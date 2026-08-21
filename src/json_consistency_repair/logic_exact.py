from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations
from typing import Any, Iterable
import hashlib
import json

from .models import Candidate
from .tree import decode_pointer


def _jkey(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def stable_rule_id(rule: dict[str, Any], prefix: str = "logic") -> str:
    payload = {k: v for k, v in rule.items() if k not in {"rule_id", "confidence", "support", "document"}}
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return f"{prefix}_{hashlib.sha256(raw).hexdigest()[:20]}"


def get_pointer(root: Any, path: str) -> tuple[bool, Any]:
    cur = root
    try:
        for token in decode_pointer(path):
            if isinstance(cur, list):
                cur = cur[int(token)]
            elif isinstance(cur, dict) and token in cur:
                cur = cur[token]
            else:
                return False, None
        return True, cur
    except (KeyError, IndexError, ValueError, TypeError):
        return False, None


def _field_get(row: dict[str, Any], field: str) -> tuple[bool, Any]:
    # Authoritative logic rules accept either a top-level field name or a JSON Pointer relative to a record.
    if field.startswith("/"):
        return get_pointer(row, field)
    return (field in row, row.get(field))


def _field_pointer(field: str) -> str:
    if field.startswith("/"):
        return field
    return "/" + str(field).replace("~", "~0").replace("/", "~1")


def predicate_value(row: dict[str, Any], pred: dict[str, Any]) -> bool | None:
    field = pred.get("field")
    if not isinstance(field, str) or not field:
        return None
    exists, value = _field_get(row, field)
    if "present" in pred:
        return exists is bool(pred["present"])
    if "equals" in pred:
        return exists and value == pred["equals"]
    if "truthy" in pred:
        if not exists:
            return False
        return bool(value) is bool(pred["truthy"])
    return None


def predicate_literal(pred: dict[str, Any]) -> tuple[str, bool] | None:
    """Translate a finite JSON predicate to a propositional SAT literal.

    Equality predicates become positive atoms (including booleans), so `x == false` is
    distinct from merely `not(x == true)`. Presence can be positive or negative. This
    preserves the important JSON distinction between false, null and absent.
    """
    field = pred.get("field")
    if not isinstance(field, str) or not field:
        return None
    if "equals" in pred:
        return f"eq:{field}:{_jkey(pred['equals'])}", True
    if "present" in pred and isinstance(pred["present"], bool):
        return f"present:{field}", bool(pred["present"])
    if "truthy" in pred and isinstance(pred["truthy"], bool):
        return f"truthy:{field}", bool(pred["truthy"])
    return None


def evaluate_rule(row: dict[str, Any], rule: dict[str, Any]) -> bool | None:
    kind = str(rule.get("kind", ""))
    if kind == "implies":
        ants = rule.get("if", [])
        if isinstance(ants, dict):
            ants = [ants]
        consequent = rule.get("then")
        if not isinstance(consequent, dict) or not isinstance(ants, list) or not ants:
            return None
        av = [predicate_value(row, p) for p in ants if isinstance(p, dict)]
        if len(av) != len(ants) or any(v is None for v in av):
            return None
        if not all(bool(v) for v in av):
            return True
        cv = predicate_value(row, consequent)
        return cv if cv is not None else None

    items = rule.get("items", [])
    if not isinstance(items, list) or not items:
        return None
    vals = [predicate_value(row, p) for p in items if isinstance(p, dict)]
    if len(vals) != len(items) or any(v is None for v in vals):
        return None
    n = sum(bool(v) for v in vals)
    if kind in {"xor", "exactly_one", "one_of"}:
        return n == 1
    if kind == "any_of":
        return n >= 1
    if kind == "not_both":
        return n <= 1
    return None


def _neg(lit: tuple[str, bool]) -> tuple[str, bool]:
    return lit[0], not lit[1]


def rule_to_cnf(rule: dict[str, Any]) -> list[list[tuple[str, bool]]] | None:
    kind = str(rule.get("kind", ""))
    if kind == "implies":
        ants = rule.get("if", [])
        if isinstance(ants, dict):
            ants = [ants]
        then = rule.get("then")
        if not isinstance(ants, list) or not ants or not isinstance(then, dict):
            return None
        alits = [predicate_literal(p) for p in ants if isinstance(p, dict)]
        tlit = predicate_literal(then)
        if len(alits) != len(ants) or any(x is None for x in alits) or tlit is None:
            return None
        return [[_neg(x) for x in alits if x is not None] + [tlit]]

    items = rule.get("items", [])
    if not isinstance(items, list) or not items:
        return None
    lits = [predicate_literal(p) for p in items if isinstance(p, dict)]
    if len(lits) != len(items) or any(x is None for x in lits):
        return None
    ls = [x for x in lits if x is not None]
    if kind in {"xor", "exactly_one", "one_of"}:
        return [ls] + [[_neg(a), _neg(b)] for a, b in combinations(ls, 2)]
    if kind == "any_of":
        return [ls]
    if kind == "not_both":
        return [[_neg(a), _neg(b)] for a, b in combinations(ls, 2)]
    return None


@dataclass
class SATResult:
    status: str
    assignment: dict[str, bool] | None
    explored_nodes: int
    unit_propagations: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "assignment": self.assignment,
            "explored_nodes": self.explored_nodes,
            "unit_propagations": self.unit_propagations,
        }


def solve_cnf(clauses: Iterable[Iterable[tuple[str, bool]]]) -> SATResult:
    """Deterministic exact finite SAT solver with unit propagation.

    False is branched before True, so the first witness is deterministic.
    The solver intentionally targets small JSON rule systems, not industrial SAT workloads.
    """
    normalized: list[tuple[tuple[str, bool], ...]] = []
    variables: set[str] = set()
    for raw_clause in clauses:
        seen: dict[str, bool] = {}
        tautology = False
        for var, pol in raw_clause:
            variables.add(var)
            if var in seen and seen[var] != bool(pol):
                tautology = True
                break
            seen[var] = bool(pol)
        if tautology:
            continue
        clause = tuple(sorted(seen.items()))
        normalized.append(clause)
    explored = 0
    unit_count = 0

    def propagate(assignment: dict[str, bool]) -> tuple[bool, dict[str, bool]]:
        nonlocal unit_count
        a = dict(assignment)
        while True:
            units: list[tuple[str, bool]] = []
            for clause in normalized:
                sat = False
                unresolved: list[tuple[str, bool]] = []
                for var, pol in clause:
                    if var in a:
                        if a[var] == pol:
                            sat = True
                            break
                    else:
                        unresolved.append((var, pol))
                if sat:
                    continue
                if not unresolved:
                    return False, a
                if len(unresolved) == 1:
                    units.append(unresolved[0])
            if not units:
                return True, a
            changed = False
            for var, pol in sorted(units):
                if var in a and a[var] != pol:
                    return False, a
                if var not in a:
                    a[var] = pol
                    unit_count += 1
                    changed = True
            if not changed:
                return True, a

    vars_sorted = sorted(variables)

    def rec(assignment: dict[str, bool]) -> dict[str, bool] | None:
        nonlocal explored
        explored += 1
        ok, a = propagate(assignment)
        if not ok:
            return None
        # If every clause is satisfied, assign remaining variables False deterministically.
        all_sat = True
        for clause in normalized:
            if not any(var in a and a[var] == pol for var, pol in clause):
                all_sat = False
                break
        if all_sat:
            for v in vars_sorted:
                a.setdefault(v, False)
            return a
        var = next((v for v in vars_sorted if v not in a), None)
        if var is None:
            return None
        for val in (False, True):
            b = dict(a); b[var] = val
            ans = rec(b)
            if ans is not None:
                return ans
        return None

    assignment = rec({})
    return SATResult("SAT" if assignment is not None else "UNSAT", assignment, explored, unit_count)


def _iter_rule_predicates(rule: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if rule.get("kind") == "implies":
        ants = rule.get("if", [])
        if isinstance(ants, dict): ants = [ants]
        out.extend(p for p in ants if isinstance(p, dict))
        if isinstance(rule.get("then"), dict): out.append(rule["then"])
    else:
        out.extend(p for p in rule.get("items", []) if isinstance(p, dict))
    return out


def rule_system_certificate(rules: list[dict[str, Any]]) -> dict[str, Any]:
    compiled: list[tuple[str, list[list[tuple[str, bool]]]]] = []
    skipped: list[str] = []
    atom_legend: dict[str, dict[str, Any]] = {}
    equality_atoms: dict[str, set[str]] = {}
    presence_atoms: dict[str, str] = {}
    for raw in rules:
        rid = str(raw.get("rule_id") or stable_rule_id(raw))
        for pred in _iter_rule_predicates(raw):
            lit = predicate_literal(pred)
            if lit is not None:
                atom, _ = lit
                atom_legend.setdefault(atom, dict(pred))
                field = pred.get("field")
                if "equals" in pred and isinstance(field, str):
                    equality_atoms.setdefault(field, set()).add(atom)
                if "present" in pred and isinstance(field, str):
                    presence_atoms[field] = f"present:{field}"
        cnf = rule_to_cnf(raw)
        if cnf is None:
            skipped.append(rid)
            continue
        compiled.append((rid, cnf))
    semantic_clauses: list[list[tuple[str, bool]]] = []
    # Distinct exact values of one JSON field cannot hold simultaneously.
    for field in sorted(equality_atoms):
        atoms = sorted(equality_atoms[field])
        for a, b in combinations(atoms, 2):
            semantic_clauses.append([(a, False), (b, False)])
        if field in presence_atoms:
            p = presence_atoms[field]
            for a in atoms:
                semantic_clauses.append([(a, False), (p, True)])
    all_clauses = [cl for _, cnf in compiled for cl in cnf] + semantic_clauses
    result = solve_cnf(all_clauses)
    cert: dict[str, Any] = {
        "contract": "json-consistency-repair.logic-sat.v1",
        "status": result.status,
        "coverage": "FULL_FINITE_PREDICATE_CORE" if not skipped else "PARTIAL_UNCOMPILED_RULES",
        "assignment": result.assignment,
        "atom_legend": {k: atom_legend[k] for k in sorted(atom_legend)},
        "explored_nodes": result.explored_nodes,
        "unit_propagations": result.unit_propagations,
        "compiled_rule_ids": [rid for rid, _ in compiled],
        "skipped_uncompiled_rule_ids": sorted(skipped),
        # Historical alias retained for PASS012 compatibility with early drafts.
        "skipped_non_boolean_rule_ids": sorted(skipped),
        "compiled_rule_count": len(compiled),
        "skipped_rule_count": len(skipped),
        "rule_clause_count": sum(len(cnf) for _, cnf in compiled),
        "semantic_clause_count": len(semantic_clauses),
        "clause_count": len(all_clauses),
    }
    if result.status == "UNSAT":
        # Deterministic irreducible-by-deletion rule core. Semantic clauses are regenerated
        # from the surviving rules on every trial, so the core respects predicate semantics.
        core_rules = [dict(r) for r in rules if str(r.get("rule_id") or stable_rule_id(r)) in {rid for rid, _ in compiled}]
        i = 0
        while i < len(core_rules):
            trial = core_rules[:i] + core_rules[i + 1:]
            # Inline non-recursive compilation for core test.
            tcompiled=[]; teq: dict[str,set[str]]={}; tpres={}
            for rr in trial:
                cnf=rule_to_cnf(rr)
                if cnf is None: continue
                tcompiled.extend(cnf)
                for pred in _iter_rule_predicates(rr):
                    lit=predicate_literal(pred)
                    if lit is None: continue
                    atom,_=lit; field=pred.get("field")
                    if "equals" in pred and isinstance(field,str): teq.setdefault(field,set()).add(atom)
                    if "present" in pred and isinstance(field,str): tpres[field]=f"present:{field}"
            tsem=[]
            for field in sorted(teq):
                atoms=sorted(teq[field])
                for a,b in combinations(atoms,2): tsem.append([(a,False),(b,False)])
                if field in tpres:
                    for a in atoms: tsem.append([(a,False),(tpres[field],True)])
            if solve_cnf(tcompiled+tsem).status == "UNSAT":
                core_rules = trial
            else:
                i += 1
        cert["unsat_core_rule_ids"] = [str(r.get("rule_id") or stable_rule_id(r)) for r in core_rules]
        cert["unsat_core_kind"] = "DELETION_IRREDUCIBLE_RULE_CORE"
    return cert


def _candidate_id(analyzer: str, path: str, old: Any, new: Any, rule_id: str) -> str:
    raw = json.dumps([analyzer, path, old, new, rule_id], sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    return hashlib.sha1(raw).hexdigest()[:16]


def candidate_to_satisfy(row: dict[str, Any], pred: dict[str, Any], base_path: str, *, analyzer: str, rule_id: str, confidence: float, evidence: tuple[str, ...]) -> Candidate | None:
    field = pred.get("field")
    if not isinstance(field, str) or not field:
        return None
    exists, old = _field_get(row, field)
    if "equals" in pred:
        new = pred["equals"]
    elif "truthy" in pred and isinstance(pred["truthy"], bool):
        new = bool(pred["truthy"])
    elif pred.get("present") is True and "value" in pred:
        new = pred["value"]
    else:
        return None
    if exists and old == new:
        return None
    rel = _field_pointer(field)
    path = (base_path.rstrip("/") + rel) if base_path else rel
    meta = {"logic_rule_id": rule_id, "relation_kind": "logic_exact", "add_if_missing": not exists}
    return Candidate(_candidate_id(analyzer, path, old if exists else None, new, rule_id), analyzer, "replace", path, old if exists else None, new,
                     "Satisfy exact logical predicate.", confidence, 1, evidence, meta)


def candidate_to_falsify(row: dict[str, Any], pred: dict[str, Any], base_path: str, *, analyzer: str, rule_id: str, confidence: float, evidence: tuple[str, ...]) -> Candidate | None:
    field = pred.get("field")
    if not isinstance(field, str) or not field:
        return None
    exists, old = _field_get(row, field)
    if not exists:
        return None
    if "equals" in pred and isinstance(pred["equals"], bool) and old == pred["equals"]:
        new = not pred["equals"]
    elif "truthy" in pred and isinstance(pred["truthy"], bool) and bool(old) is bool(pred["truthy"]) and isinstance(old, bool):
        new = not pred["truthy"]
    elif "else" in pred:
        new = pred["else"]
    else:
        return None
    rel = _field_pointer(field)
    path = (base_path.rstrip("/") + rel) if base_path else rel
    meta = {"logic_rule_id": rule_id, "relation_kind": "logic_exact"}
    return Candidate(_candidate_id(analyzer, path, old, new, rule_id), analyzer, "replace", path, old, new,
                     "Falsify one predicate to satisfy exact logical rule.", confidence, 1, evidence, meta)


def repair_candidates_for_rule(row: dict[str, Any], rule: dict[str, Any], base_path: str, *, analyzer: str = "logic_exact", confidence: float = 1.0) -> list[Candidate]:
    rid = str(rule.get("rule_id") or stable_rule_id(rule))
    evidence = (f"LOGIC:{rid}",)
    kind = str(rule.get("kind", ""))
    out: list[Candidate] = []
    if evaluate_rule(row, rule) is not False:
        return out
    if kind == "implies":
        then = rule.get("then")
        if isinstance(then, dict):
            c = candidate_to_satisfy(row, then, base_path, analyzer=analyzer, rule_id=rid, confidence=confidence, evidence=evidence)
            if c is not None:
                out.append(c)
        # Explicit repair_target=minimal also allows switching a boolean antecedent off.
        if rule.get("repair_target") == "minimal":
            ants = rule.get("if", [])
            if isinstance(ants, dict):
                ants = [ants]
            for p in ants if isinstance(ants, list) else []:
                if isinstance(p, dict):
                    c = candidate_to_falsify(row, p, base_path, analyzer=analyzer, rule_id=rid, confidence=confidence, evidence=evidence)
                    if c is not None:
                        out.append(c)
    else:
        items = rule.get("items", [])
        vals = [predicate_value(row, p) if isinstance(p, dict) else None for p in items] if isinstance(items, list) else []
        if any(v is None for v in vals):
            return out
        n = sum(bool(v) for v in vals)
        if kind in {"xor", "exactly_one", "one_of"}:
            if n == 0:
                for p, v in zip(items, vals):
                    if not v:
                        c = candidate_to_satisfy(row, p, base_path, analyzer=analyzer, rule_id=rid, confidence=confidence, evidence=evidence)
                        if c is not None: out.append(c)
            elif n > 1:
                for p, v in zip(items, vals):
                    if v:
                        c = candidate_to_falsify(row, p, base_path, analyzer=analyzer, rule_id=rid, confidence=confidence, evidence=evidence)
                        if c is not None: out.append(c)
        elif kind == "any_of" and n == 0:
            for p in items:
                if isinstance(p, dict):
                    c = candidate_to_satisfy(row, p, base_path, analyzer=analyzer, rule_id=rid, confidence=confidence, evidence=evidence)
                    if c is not None: out.append(c)
        elif kind == "not_both" and n > 1:
            for p, v in zip(items, vals):
                if v:
                    c = candidate_to_falsify(row, p, base_path, analyzer=analyzer, rule_id=rid, confidence=confidence, evidence=evidence)
                    if c is not None: out.append(c)
    uniq = {(c.path, _jkey(c.new_value)): c for c in out}
    return [uniq[k] for k in sorted(uniq)]


def public_candidate(c: Candidate) -> dict[str, Any]:
    return c.to_dict()
