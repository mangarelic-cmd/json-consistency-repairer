from __future__ import annotations

"""PASS037 — bounded active falsification / negative controls for inferred relations.

This layer does not invent observations. It attacks *claims* already inferred from the loaded
JSON by deterministic split validation, ablation, and permutation controls over the same finite
observed carrier. Authoritative rules are recorded but are not treated as empirical hypotheses.

A relation is mutation-gated only when an exact bounded attack establishes one of two strong
failures:
  * ACTIVE_REFUTED: independent deterministic folds infer incompatible mappings; or
  * NEGATIVE_CONTROL_INVARIANT: the alleged determinant contributes no information at all
    (e.g. a functional dependency with a constant target survives every target permutation /
    is exactly matched by the zero-input baseline).

The layer therefore strengthens conservative repair without confusing a deliberately corrupted
row with a refutation of a relation whose remaining support is stable.
"""

from collections import Counter, defaultdict
from copy import deepcopy
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any
import json

from .models import AnalysisResult, Candidate, Issue, digest
from .tree import get

CONTRACT = "json-consistency-repair.relation-falsification.v1"
SUMMARY_CONTRACT = "json-consistency-repair.relation-falsification-summary.v1"

_BLOCKING_STATES = {"ACTIVE_REFUTED", "NEGATIVE_CONTROL_INVARIANT"}
_AUTHORITATIVE_KINDS = {
    "authoritative_json_schema", "authoritative_boundary_contract",
    "typed_expression_exact", "graph_topological_order_authoritative",
    "graph_reciprocity_authoritative", "state_machine_authoritative",
    "migration_plan", "aggregate_sum_authoritative", "aggregate_count_authoritative",
    "balance_authoritative", "multiset_balance_authoritative",
}


def _jkey(v: Any) -> str | None:
    try:
        return json.dumps(v, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError):
        return None


def _source(rel: dict[str, Any]) -> str:
    return str(rel.get("constraint_source") or rel.get("logic_source") or rel.get("schema_source") or rel.get("source") or "").lower()


def _authoritative(rel: dict[str, Any]) -> bool:
    kind = str(rel.get("kind") or "")
    return _source(rel) == "authoritative" or kind in _AUTHORITATIVE_KINDS or kind.startswith("constraint_dsl_")


def _array(root: Any, path: str) -> list[dict[str, Any]] | None:
    try:
        value = root if path == "" else get(root, path)
    except Exception:
        return None
    if isinstance(value, list) and all(isinstance(x, dict) for x in value):
        return value
    return None


def _mode(counter: Counter[str]) -> tuple[str | None, int]:
    if not counter:
        return None, 0
    rows = sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))
    return rows[0]


def _functional_attack(root: Any, rel: dict[str, Any], config: Any) -> dict[str, Any]:
    arr = _array(root, str(rel.get("array_path") or ""))
    det = rel.get("determinant") or ((rel.get("inputs") or [None])[-1])
    target = rel.get("output")
    scope_field = rel.get("scope_field") if rel.get("kind") == "scoped_functional" else None
    scope_value = rel.get("scope_value")
    if arr is None or not isinstance(det, str) or not isinstance(target, str):
        return {"applicable": False, "reason": "CARRIER_OR_FIELDS_UNAVAILABLE"}

    rows: list[tuple[int, str, str]] = []
    mapping: dict[str, Counter[str]] = defaultdict(Counter)
    targets = Counter()
    for i, row in enumerate(arr):
        if scope_field is not None and row.get(scope_field) != scope_value:
            continue
        if det not in row or target not in row or row.get(det) is None or row.get(target) is None:
            continue
        dk, tv = _jkey(row.get(det)), _jkey(row.get(target))
        if dk is None or tv is None:
            continue
        rows.append((i, dk, tv)); mapping[dk][tv] += 1; targets[tv] += 1
    min_rows = max(2, int(getattr(config, "falsifier_min_rows", 4)))
    if len(rows) < min_rows:
        return {"applicable": False, "reason": "INSUFFICIENT_ROWS", "rows": len(rows)}

    modes = {k: _mode(v)[0] for k, v in mapping.items() if v}
    matches = sum(1 for _, dk, tv in rows if modes.get(dk) == tv)
    observed = matches / len(rows)
    baseline_key, baseline_n = _mode(targets)
    baseline = baseline_n / len(rows) if rows else 0.0

    # Deterministic 2-fold ablation: each fold must independently choose the same target mode
    # for a determinant before a disagreement is called an active refutation. Isolated corrupt
    # rows do not satisfy this criterion.
    fold_maps = []
    min_group = max(1, int(getattr(config, "min_group_support", 2)))
    for parity in (0, 1):
        fm: dict[str, Counter[str]] = defaultdict(Counter)
        for i, dk, tv in rows:
            if i % 2 == parity:
                fm[dk][tv] += 1
        fold_maps.append(fm)
    conflicts = []
    for dk in sorted(set(fold_maps[0]) & set(fold_maps[1])):
        a, b = fold_maps[0][dk], fold_maps[1][dk]
        if sum(a.values()) < min_group or sum(b.values()) < min_group:
            continue
        am, an = _mode(a); bm, bn = _mode(b)
        # Require a unique mode on both sides; equal-frequency ties are not evidence.
        au = an > sorted(a.values(), reverse=True)[1] if len(a) > 1 else True
        bu = bn > sorted(b.values(), reverse=True)[1] if len(b) > 1 else True
        if au and bu and am != bm:
            conflicts.append({"determinant_value": dk, "fold0_mode": am, "fold1_mode": bm,
                              "fold0_support": sum(a.values()), "fold1_support": sum(b.values())})

    # Deterministic target permutations are negative controls. A real non-trivial functional
    # dependency should lose predictive accuracy under at least one non-identity rotation.
    max_controls = max(0, int(getattr(config, "falsifier_max_negative_controls", 8)))
    controls = []
    vals = [tv for _, _, tv in rows]
    for shift in range(1, min(len(rows), max_controls + 1)):
        rotated = vals[shift:] + vals[:shift]
        score = sum(1 for (_, dk, _), tv in zip(rows, rotated) if modes.get(dk) == tv) / len(rows)
        controls.append({"kind": "TARGET_ROTATION", "shift": shift, "agreement": round(score, 12)})
    discriminating = any(float(c["agreement"]) < observed for c in controls)
    constant_target = len(targets) <= 1
    zero_input_equal = baseline >= observed and abs(baseline - observed) <= 1e-12

    if conflicts:
        state = "ACTIVE_REFUTED"
    elif constant_target and zero_input_equal:
        state = "NEGATIVE_CONTROL_INVARIANT"
    elif controls and discriminating:
        state = "ADVERSARIAL_SURVIVED"
    else:
        state = "OBSERVED_STABLE"
    return {
        "applicable": True, "state": state, "rows": len(rows),
        "observed_agreement": round(observed, 12), "zero_input_baseline_agreement": round(baseline, 12),
        "distinct_determinants": len(mapping), "distinct_targets": len(targets),
        "fold_mapping_conflicts": conflicts, "negative_controls": controls,
        "negative_control_discriminating": bool(discriminating),
        "ablation": {"removed_inputs": [det], "baseline_target": baseline_key,
                     "same_explanatory_accuracy": bool(zero_input_equal)},
    }


def _decimal(v: Any) -> Decimal | None:
    if isinstance(v, bool) or v is None:
        return None
    try:
        if isinstance(v, (int, float, Decimal)):
            return Decimal(str(v))
    except (InvalidOperation, ValueError):
        pass
    return None


def _arith_value(op: str, a: Decimal, b: Decimal) -> Decimal | None:
    try:
        if op == "+": return a + b
        if op == "-": return a - b
        if op == "*": return a * b
        if op == "/": return None if b == 0 else a / b
    except (InvalidOperation, ZeroDivisionError):
        return None
    return None


def _arithmetic_attack(root: Any, rel: dict[str, Any], config: Any) -> dict[str, Any]:
    arr = _array(root, str(rel.get("array_path") or ""))
    inputs = list(rel.get("inputs") or [])
    target = rel.get("output"); op = str(rel.get("operator") or "")
    if arr is None or len(inputs) != 2 or not isinstance(target, str) or op not in {"+", "-", "*", "/"}:
        return {"applicable": False, "reason": "CARRIER_OR_OPERATOR_UNAVAILABLE"}
    rows = []
    targets = Counter()
    for i, row in enumerate(arr):
        a, b, t = _decimal(row.get(inputs[0])), _decimal(row.get(inputs[1])), _decimal(row.get(target))
        if a is None or b is None or t is None: continue
        exp = _arith_value(op, a, b)
        if exp is None: continue
        rows.append((i, a, b, t)); targets[str(t)] += 1
    min_rows=max(2,int(getattr(config,"falsifier_min_rows",4)))
    if len(rows)<min_rows:
        return {"applicable":False,"reason":"INSUFFICIENT_ROWS","rows":len(rows)}
    observed=sum(1 for _,a,b,t in rows if _arith_value(op,a,b)==t)/len(rows)
    _,bn=_mode(targets); baseline=bn/len(rows)
    max_controls=max(0,int(getattr(config,"falsifier_max_negative_controls",8)))
    controls=[]
    av=[a for _,a,_,_ in rows]
    for shift in range(1,min(len(rows),max_controls+1)):
        rot=av[shift:]+av[:shift]
        valid=0; match=0
        for (_,_,b,t),a in zip(rows,rot):
            exp=_arith_value(op,a,b)
            if exp is None: continue
            valid+=1; match+=int(exp==t)
        controls.append({"kind":"INPUT0_ROTATION","shift":shift,"agreement":round(match/valid if valid else 0.0,12)})
    discriminating=any(float(c["agreement"])<observed for c in controls)
    constant_target=len(targets)<=1
    if constant_target and baseline>=observed and abs(baseline-observed)<=1e-12:
        state="NEGATIVE_CONTROL_INVARIANT"
    elif controls and discriminating:
        state="ADVERSARIAL_SURVIVED"
    else:
        state="OBSERVED_STABLE"
    return {"applicable":True,"state":state,"rows":len(rows),"observed_agreement":round(observed,12),
            "zero_input_baseline_agreement":round(baseline,12),"negative_controls":controls,
            "negative_control_discriminating":bool(discriminating),"distinct_targets":len(targets)}


def _parse_iso(v: Any) -> datetime | None:
    if not isinstance(v, str): return None
    s=v.strip()
    if s.endswith("Z"): s=s[:-1]+"+00:00"
    try: return datetime.fromisoformat(s)
    except ValueError: return None


def _temporal_attack(root: Any, rel: dict[str, Any], config: Any) -> dict[str, Any]:
    arr=_array(root,str(rel.get("array_path") or "")); inputs=list(rel.get("inputs") or []); target=rel.get("output")
    if arr is None or len(inputs)!=1 or not isinstance(target,str): return {"applicable":False,"reason":"CARRIER_OR_FIELDS_UNAVAILABLE"}
    sec=rel.get("seconds")
    if not isinstance(sec,(int,float)): return {"applicable":False,"reason":"DELTA_UNAVAILABLE"}
    rows=[]; targets=Counter()
    for i,row in enumerate(arr):
        a,b=_parse_iso(row.get(inputs[0])),_parse_iso(row.get(target))
        if a is None or b is None: continue
        try: d=(b-a).total_seconds()
        except TypeError: continue
        rows.append((i,a,b,d)); targets[str(row.get(target))]+=1
    min_rows=max(2,int(getattr(config,"falsifier_min_rows",4)))
    if len(rows)<min_rows: return {"applicable":False,"reason":"INSUFFICIENT_ROWS","rows":len(rows)}
    observed=sum(1 for *_,d in rows if d==sec)/len(rows)
    _,bn=_mode(targets); baseline=bn/len(rows)
    # Rotating start times attacks the claimed causal input while preserving observed endpoints.
    starts=[a for _,a,_,_ in rows]; controls=[]; max_controls=max(0,int(getattr(config,"falsifier_max_negative_controls",8)))
    for shift in range(1,min(len(rows),max_controls+1)):
        rot=starts[shift:]+starts[:shift]
        score=sum(1 for (_,_,b,_),a in zip(rows,rot) if (b-a).total_seconds()==sec)/len(rows)
        controls.append({"kind":"START_ROTATION","shift":shift,"agreement":round(score,12)})
    discriminating=any(float(c["agreement"])<observed for c in controls)
    state="NEGATIVE_CONTROL_INVARIANT" if len(targets)<=1 and baseline>=observed and abs(baseline-observed)<=1e-12 else ("ADVERSARIAL_SURVIVED" if controls and discriminating else "OBSERVED_STABLE")
    return {"applicable":True,"state":state,"rows":len(rows),"observed_agreement":round(observed,12),"zero_input_baseline_agreement":round(baseline,12),"negative_controls":controls,"negative_control_discriminating":bool(discriminating)}


def _attack_relation(root: Any, rel: dict[str, Any], config: Any) -> dict[str, Any]:
    rid=str(rel.get("relation_id") or "")
    kind=str(rel.get("kind") or "")
    base={"relation_id":rid,"kind":kind,"array_path":str(rel.get("array_path") or ""),"authoritative":_authoritative(rel)}
    if _authoritative(rel):
        return {**base,"state":"AUTHORITATIVE_CONTRACT","applicable":False,"reason":"DECLARED_CONSTRAINT_NOT_EMPIRICAL_HYPOTHESIS"}
    validation=str(rel.get("validation_state") or "")
    if validation=="GLOBAL_REFUTED" or int(rel.get("counterexample_count") or 0)>0:
        return {**base,"state":"ACTIVE_REFUTED","applicable":True,"reason":"INDEPENDENT_COUNTEREXAMPLE_ALREADY_MATERIALIZED","counterexample_count":int(rel.get("counterexample_count") or 0)}
    if validation in {"HELDOUT_CONFIRMED","PORTABLE"}:
        return {**base,"state":"ADVERSARIAL_SURVIVED","applicable":True,"reason":"INDEPENDENT_HELDOUT_CONFIRMED","heldout_independent_groups":deepcopy(rel.get("heldout_independent_groups") or [])}
    if kind in {"functional","scoped_functional"}:
        return {**base,**_functional_attack(root,rel,config)}
    if kind=="exact_arithmetic":
        return {**base,**_arithmetic_attack(root,rel,config)}
    if kind=="temporal_delta":
        return {**base,**_temporal_attack(root,rel,config)}
    return {**base,"state":"OBSERVED_ONLY","applicable":False,"reason":"NO_SAFE_BOUNDED_ATTACK_FOR_RELATION_FAMILY"}


def _candidate_matches(c: Candidate, rel: dict[str, Any]) -> bool:
    meta=c.metadata or {}; rid=str(rel.get("relation_id") or "")
    if str(meta.get("relation_id") or "")==rid and rid: return True
    kind=str(rel.get("kind") or "")
    mk=str(meta.get("relation_kind") or "")
    if kind=="functional" and mk=="functional":
        return meta.get("determinant")==rel.get("determinant") and meta.get("target")==rel.get("output") and c.path.startswith(str(rel.get("array_path") or ""))
    if kind=="scoped_functional" and mk=="scoped_functional":
        return meta.get("scope_field")==rel.get("scope_field") and meta.get("scope_value")==rel.get("scope_value") and meta.get("determinant")==rel.get("determinant") and meta.get("target")==rel.get("output") and c.path.startswith(str(rel.get("array_path") or ""))
    if kind=="exact_arithmetic" and mk=="exact_arithmetic":
        return meta.get("formula")==rel.get("formula") and c.path.startswith(str(rel.get("array_path") or ""))
    if kind=="temporal_delta" and mk=="temporal_delta":
        return meta.get("start")==((rel.get("inputs") or [None])[0]) and meta.get("end")==rel.get("output") and meta.get("seconds")==rel.get("seconds")
    if kind in {"cross_source_functional","cross_source_functional_relation"} and mk=="cross_source_functional":
        return str(meta.get("relation_id") or "")==rid
    return False


def apply_relation_falsification_firewall(root: Any, analysis: AnalysisResult, config: Any) -> tuple[AnalysisResult, dict[str, Any]]:
    enabled=bool(getattr(config,"enable_relation_falsifier",True))
    max_rel=max(0,int(getattr(config,"falsifier_max_relations",256)))
    all_rel=sorted(analysis.relations,key=lambda r:str(r.get("relation_id") or ""))
    targeted=bool(getattr(config,"execution_mode","full")=="fast" and
                  getattr(config,"fast_falsify_action_relations_only",True))
    if targeted:
        # SC hot path: every analyzer still observes the sovereign object, but the
        # expensive adversarial attack is opened only around a relation that can
        # currently authorize a mutation. Fast mode never promotes this targeted
        # pass to full certification.
        attack_rel=[]
        for rel in all_rel:
            if any(_candidate_matches(c,rel) for c in analysis.candidates):
                attack_rel.append(rel)
    else:
        attack_rel=all_rel
    rows=[]
    for rel in attack_rel[:max_rel]:
        row=_attack_relation(root,rel,config)
        semantic={k:deepcopy(v) for k,v in row.items() if k!="decision_sha256"}
        row["decision_sha256"]=digest(semantic); rows.append(row)
    states={str(r.get("relation_id")):str(r.get("state")) for r in rows}
    blocking={rid for rid,state in states.items() if state in _BLOCKING_STATES}

    kept_rel=[]; blocked_rel=[]
    for rel in analysis.relations:
        rid=str(rel.get("relation_id") or "")
        if enabled and rid in blocking:
            blocked_rel.append(rid); continue
        rr=deepcopy(rel)
        if rid in states:
            rr["falsification_state"]=states[rid]
            rr["falsification_decision_sha256"]=next((x["decision_sha256"] for x in rows if x.get("relation_id")==rid),None)
        kept_rel.append(rr)

    kept_c=[]; blocked_c=[]; extra_issues=[]
    for c in analysis.candidates:
        matched=[str(r.get("relation_id") or "") for r in analysis.relations if _candidate_matches(c,r)]
        matched=[rid for rid in matched if rid]
        # A candidate is gated only if it is actually relation-backed and *every* matching
        # relation is strongly falsified/non-discriminating. Independent candidates remain.
        bad=bool(matched) and all(rid in blocking for rid in matched)
        if enabled and bad:
            blocked_c.append(c.candidate_id)
            extra_issues.append(Issue("relation_falsifier","RELATION_FALSIFICATION_GATE",c.path,
                "Candidate depends only on a relation that failed an exact bounded falsification control.","warning",False,
                {"candidate_id":c.candidate_id,"relation_ids":sorted(matched),"falsification_states":sorted({states.get(rid) for rid in matched})}))
        else:
            kept_c.append(c)

    out=AnalysisResult(list(analysis.issues)+extra_issues,kept_c,kept_rel)
    counts=Counter(str(r.get("state")) for r in rows)
    cert={
        "contract":CONTRACT,"enabled":enabled,"root_digest":digest(root),
        "relation_count_examined":len(rows),"relation_count_total":len(analysis.relations),
        "targeted_action_relations_only":targeted,
        "relation_count_targeted":len(attack_rel),
        "relation_count_observed_not_deep_falsified":max(0,len(analysis.relations)-len(attack_rel)) if targeted else 0,
        "truncated":len(attack_rel)>max_rel,"max_relations":max_rel,
        "states":dict(sorted(counts.items())),"relations":rows,
        "blocked_relation_ids":sorted(blocked_rel),"blocked_candidate_ids":sorted(blocked_c),
        "blocked_relation_count":len(blocked_rel),"blocked_candidate_count":len(blocked_c),
        "policy":{
            "authoritative_contracts":"RECORDED_NOT_EMPIRICALLY_FALSIFIED",
            "synthetic_controls":"TEST_ONLY_NEVER_OBSERVATIONS",
            "active_refutation":"INCOMPATIBLE_INDEPENDENT_DETERMINISTIC_FOLDS_OR_INDEPENDENT_HELDOUT_COUNTEREXAMPLE",
            "negative_control_invariant":"ZERO_INPUT_BASELINE_EXPLAINS_RELATION_EXACTLY",
            "mutation_gate_states":sorted(_BLOCKING_STATES),
            "unhandled_family":"OBSERVED_ONLY_NOT_PROMOTED_TO_PORTABLE_BY_THIS_LAYER",
        },
    }
    cert["certificate_sha256"]=digest(cert)
    return out,cert


def verify_relation_falsification_certificate(cert: dict[str, Any]) -> bool:
    if not isinstance(cert,dict) or cert.get("contract")!=CONTRACT: return False
    supplied=cert.get("certificate_sha256"); tmp=deepcopy(cert); tmp.pop("certificate_sha256",None)
    if not supplied or digest(tmp)!=supplied: return False
    rows=cert.get("relations") or []
    if not isinstance(rows,list): return False
    for row in rows:
        if not isinstance(row,dict): return False
        ds=row.get("decision_sha256"); sem=deepcopy(row); sem.pop("decision_sha256",None)
        if not ds or digest(sem)!=ds: return False
    blocked=set(cert.get("blocked_relation_ids") or [])
    expected=({str(r.get("relation_id")) for r in rows if str(r.get("state")) in _BLOCKING_STATES} if cert.get("enabled") is not False else set())
    # When the scan is truncated, unexamined relations cannot be in expected; exact equality still holds.
    if blocked!=expected: return False
    if int(cert.get("blocked_relation_count") or 0)!=len(blocked): return False
    if int(cert.get("blocked_candidate_count") or 0)!=len(cert.get("blocked_candidate_ids") or []): return False
    return True


def relation_falsification_summary(cycles: list[dict[str, Any]], final: dict[str, Any] | None) -> dict[str, Any]:
    final=final or {}
    totals=Counter()
    for row in cycles:
        cert=(row or {}).get("certificate") if isinstance(row,dict) else None
        if isinstance(cert,dict): totals.update(cert.get("states") or {})
    return {
        "contract":SUMMARY_CONTRACT,"cycles":cycles,"final":final,
        "state_totals":dict(sorted(totals.items())),
        "final_blocked_relation_count":int(final.get("blocked_relation_count") or 0),
        "final_blocked_candidate_count":int(final.get("blocked_candidate_count") or 0),
        "portable_relation_count":sum(1 for r in (final.get("relations") or []) if r.get("state") in {"ADVERSARIAL_SURVIVED","AUTHORITATIVE_CONTRACT"}),
    }
