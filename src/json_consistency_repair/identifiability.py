from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable
import json

from .models import AnalysisResult, Candidate, Issue, digest
from .tree import decode_pointer


class ObservabilityState(str, Enum):
    OBSERVED_VALUE = "OBSERVED_VALUE"
    OBSERVED_NULL = "OBSERVED_NULL"
    UNOBSERVED = "UNOBSERVED"
    BOUNDED_UNMATERIALIZED = "BOUNDED_UNMATERIALIZED"


class IdentifiabilityState(str, Enum):
    UNIQUE = "UNIQUE"
    MULTIPLE = "MULTIPLE"
    NONE = "NONE"
    INSUFFICIENT = "INSUFFICIENT"


def _jkey(v: Any) -> str:
    return json.dumps(v, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False, default=str)


def _pointer_get(root: Any, path: str) -> tuple[bool, Any]:
    cur = root
    try:
        for token in decode_pointer(path):
            if isinstance(cur, list):
                idx = int(token)
                if idx < 0 or idx >= len(cur):
                    return False, None
                cur = cur[idx]
            elif isinstance(cur, dict):
                if token not in cur:
                    return False, None
                cur = cur[token]
            else:
                return False, None
        return True, cur
    except (KeyError, IndexError, ValueError, TypeError):
        return False, None


def observation_for_path(root: Any, path: str) -> dict[str, Any]:
    exists, value = _pointer_get(root, path)
    if not exists:
        return {"state": ObservabilityState.UNOBSERVED.value, "value_digest": None}
    if value is None:
        return {"state": ObservabilityState.OBSERVED_NULL.value, "value_digest": digest(value)}
    return {"state": ObservabilityState.OBSERVED_VALUE.value, "value_digest": digest(value)}


def _candidate_rule_key(c: Candidate) -> str:
    m = c.metadata or {}
    # Keep distinct certified laws distinct; intersecting their singleton solution sets
    # lets contradictions become NONE instead of being mislabeled as several solutions.
    identities = (
        ("formula",),
        ("scope_field", "scope_value", "determinant", "target"),
        ("determinant", "target"),
        ("start", "end", "seconds"),
        ("field", "step"),
        ("schema_key",),
        ("enum_field", "domain_id"),
        ("reference_field", "target_array_path", "target_id_field"),
        ("relation_id",),
        ("logic_rule_id",),
    )
    for keys in identities:
        if all(k in m for k in keys):
            return c.analyzer + ":" + _jkey([k for pair in ((k, m.get(k)) for k in keys) for k in pair])
    return c.analyzer + ":" + (c.evidence[0] if c.evidence else c.candidate_id)


def _candidate_direction_authorized(c: Candidate, path_candidates: list[Candidate]) -> bool:
    m = c.metadata or {}
    if not m.get("requires_cross_family"):
        return True
    # A second independent analyzer converging on exactly the same value is a legal direction witness.
    return any(
        x.candidate_id != c.candidate_id
        and x.path == c.path
        and _jkey(x.new_value) == _jkey(c.new_value)
        and x.analyzer != c.analyzer
        for x in path_candidates
    )


def _candidate_domains(path_candidates: list[Candidate]) -> tuple[list[dict[str, Any]], list[Candidate]]:
    groups: dict[str, set[str]] = defaultdict(set)
    values: dict[str, Any] = {}
    blocked: list[Candidate] = []
    for c in path_candidates:
        if not _candidate_direction_authorized(c, path_candidates):
            blocked.append(c)
            continue
        key = _jkey(c.new_value)
        values[key] = c.new_value
        groups[_candidate_rule_key(c)].add(key)
    domains = []
    for rule in sorted(groups):
        keys = sorted(groups[rule])
        domains.append({
            "source": "certified_candidate_rule",
            "rule": rule,
            "cardinality": len(keys),
            "values": [values[k] for k in keys],
            "value_digests": [digest(values[k]) for k in keys],
        })
    return domains, blocked


def _target_identifier_domain(root: Any, meta: dict[str, Any]) -> list[Any] | None:
    target = meta.get("target_array_path")
    field = meta.get("target_id_field")
    if target is None or not field:
        return None
    ok, arr = _pointer_get(root, str(target))
    if not ok or not isinstance(arr, list):
        return None
    vals = []
    seen = set()
    for row in arr:
        if not isinstance(row, dict) or row.get(field) is None:
            continue
        k = _jkey(row[field])
        if k in seen:
            continue
        seen.add(k); vals.append(row[field])
    return vals


def _issue_domains(root: Any, issues: list[Issue]) -> list[dict[str, Any]]:
    domains: list[dict[str, Any]] = []
    for issue in issues:
        m = issue.metadata or {}
        if issue.analyzer == "enum_domain" and isinstance(m.get("domain"), list):
            vals = list(m["domain"])
            domains.append({
                "source": "enum_domain",
                "rule": str(m.get("domain_id", issue.code)),
                "cardinality": len(vals),
                "values": vals,
                "value_digests": [digest(v) for v in vals],
            })
        elif issue.code in {"dangling_reference", "reference_representation_variant"}:
            vals = _target_identifier_domain(root, m)
            if vals is not None:
                domains.append({
                    "source": "foreign_reference_domain",
                    "rule": f"{m.get('target_array_path')}#{m.get('target_id_field')}",
                    "cardinality": len(vals),
                    "values": vals,
                    "value_digests": [digest(v) for v in vals],
                })
    return domains


def _intersect_domains(domains: list[dict[str, Any]]) -> tuple[list[Any] | None, list[str]]:
    if not domains:
        return None, []
    value_maps: list[dict[str, Any]] = []
    sources = []
    for d in domains:
        mp = {_jkey(v): v for v in d.get("values", [])}
        value_maps.append(mp); sources.append(str(d.get("source")))
    keys = set(value_maps[0])
    for mp in value_maps[1:]:
        keys &= set(mp)
    base = value_maps[0]
    return [base[k] for k in sorted(keys)], sources


def _minimal_witness_for(
    state: IdentifiabilityState,
    path: str,
    issues: list[Issue],
    solutions: list[Any] | None,
    blocked: list[Candidate],
    domains: list[dict[str, Any]],
) -> dict[str, Any] | None:
    if state == IdentifiabilityState.UNIQUE:
        return None
    if state == IdentifiabilityState.MULTIPLE:
        return {
            "cardinality": 1,
            "kind": "AUTHORITATIVE_SELECTOR",
            "target_path": path,
            "description": "One independent witness selecting exactly one admissible value is sufficient.",
            "candidate_value_digests": [digest(v) for v in (solutions or [])],
        }
    if state == IdentifiabilityState.NONE:
        return {
            "cardinality": 1,
            "kind": "CONSTRAINT_REVISION_OR_SOURCE_CORRECTION",
            "target_path": path,
            "description": "The certified finite domains have empty intersection; at least one governing constraint/source must be corrected or withdrawn.",
            "conflicting_domain_sources": [d.get("source") for d in domains],
        }
    if blocked:
        return {
            "cardinality": 1,
            "kind": "INDEPENDENT_DIRECTION_ANCHOR",
            "target_path": path,
            "description": "The value equation is visible, but one independent witness is still required to identify which side may legally move.",
            "blocked_candidate_ids": sorted(c.candidate_id for c in blocked),
        }
    codes = {i.code for i in issues}
    analyzers = {i.analyzer for i in issues}
    if codes & {"missing_required_key","schema_required_missing","schema_dependent_required_missing","required_missing"}:
        return {
            "cardinality": 1,
            "kind": "AUTHORITATIVE_VALUE_OR_DEFAULT",
            "target_path": path,
            "description": "Provide one authoritative value/default for the required key, or a certified relation that uniquely determines it.",
        }
    if "duplicate_identifier" in codes:
        return {
            "cardinality": 1,
            "kind": "AUTHORITATIVE_IDENTITY_ASSIGNMENT",
            "target_path": path,
            "description": "Provide one authoritative identity assignment identifying which duplicate occurrence changes and to what value.",
        }
    if "dangling_reference" in codes or "identifier_reference" in analyzers:
        return {
            "cardinality": 1,
            "kind": "REFERENCE_TARGET_WITNESS",
            "target_path": path,
            "description": "Provide the intended target identity or an independent mapping that determines it uniquely.",
        }
    if "enum_domain_outlier" in codes:
        return {
            "cardinality": 1,
            "kind": "ENUM_IDENTITY_WITNESS",
            "target_path": path,
            "description": "Provide one independent witness selecting the intended member of the certified enum domain.",
        }
    if "type_outlier" in codes:
        return {
            "cardinality": 1,
            "kind": "SEMANTIC_CONVERSION_RULE",
            "target_path": path,
            "description": "Provide a certified semantic conversion rule; dominant type alone does not determine the value.",
        }
    return {
        "cardinality": 1,
        "kind": "ADDITIONAL_INDEPENDENT_WITNESS",
        "target_path": path,
        "description": "One additional independent witness defining or selecting the reconstruction is required.",
    }


def assess_path_identifiability(root: Any, analysis: AnalysisResult, path: str) -> dict[str, Any]:
    issues = [i for i in analysis.issues if i.path == path]
    path_candidates = [c for c in analysis.candidates if c.path == path]
    cand_domains, blocked = _candidate_domains(path_candidates)
    issue_domains = _issue_domains(root, issues)
    domains = cand_domains + issue_domains
    solutions, domain_sources = _intersect_domains(domains)

    if solutions is not None:
        if len(solutions) == 0:
            state = IdentifiabilityState.NONE
        elif len(solutions) == 1:
            state = IdentifiabilityState.UNIQUE
        else:
            state = IdentifiabilityState.MULTIPLE
    elif blocked:
        state = IdentifiabilityState.INSUFFICIENT
    else:
        # No finite solution set can be derived from current certified material.
        state = IdentifiabilityState.INSUFFICIENT

    obs = observation_for_path(root, path)
    witness = _minimal_witness_for(state, path, issues, solutions, blocked, domains)
    return {
        "path": path,
        "observability": obs["state"],
        "observed_value_digest": obs["value_digest"],
        "identifiability": state.value,
        "solution_count": None if solutions is None else len(solutions),
        "solution_value_digests": [] if solutions is None else [digest(v) for v in solutions],
        "unique_solution_digest": digest(solutions[0]) if solutions is not None and len(solutions) == 1 else None,
        "finite_domains": domains,
        "domain_sources": domain_sources,
        "candidate_ids": sorted(c.candidate_id for c in path_candidates),
        "direction_blocked_candidate_ids": sorted(c.candidate_id for c in blocked),
        "terminal_issue_count": len(issues),
        "minimal_missing_witness": witness,
    }


def compile_identifiability_registry(root: Any, analysis: AnalysisResult) -> list[dict[str, Any]]:
    paths = sorted({i.path for i in analysis.issues})
    return [assess_path_identifiability(root, analysis, path) for path in paths]


def identifiability_summary(registry: Iterable[dict[str, Any]]) -> dict[str, int]:
    out = {x.value: 0 for x in IdentifiabilityState}
    for entry in registry:
        state = str(entry.get("identifiability"))
        if state in out:
            out[state] += 1
    return out


def compile_bundle_cross_identifiability(
    documents: dict[str, Any], cross_analysis: Any
) -> list[dict[str, Any]]:
    """Assess cross-document terminals while preserving qualified document identity."""
    by_key: dict[tuple[str, str], list[Any]] = defaultdict(list)
    for bi in getattr(cross_analysis, "issues", []):
        by_key[(bi.document, bi.issue.path)].append(bi)
    out = []
    for (document, path), bis in sorted(by_key.items()):
        issues = [bi.issue for bi in bis]
        candidates = [bc.candidate for bc in getattr(cross_analysis, "candidates", []) if bc.document == document and bc.candidate.path == path]
        # Build a lightweight AnalysisResult so the same finite-domain logic can be reused for candidates.
        local = AnalysisResult(issues=issues, candidates=candidates, relations=[])
        entry = assess_path_identifiability(documents[document], local, path)
        # Cross-document reference domains live in another document, so enrich/override them here.
        extra_domains = []
        for bi in bis:
            m = bi.issue.metadata or {}
            td = m.get("target_document") or getattr(bi, "target_document", None)
            ta = m.get("target_array_path")
            tf = m.get("target_id_field")
            if td in documents and ta is not None and tf:
                ok, arr = _pointer_get(documents[td], str(ta))
                if ok and isinstance(arr, list):
                    vals=[]; seen=set()
                    for row in arr:
                        if isinstance(row, dict) and row.get(tf) is not None:
                            k=_jkey(row[tf])
                            if k not in seen: seen.add(k); vals.append(row[tf])
                    extra_domains.append({"source":"cross_document_reference_domain","rule":f"{td}:{ta}#{tf}","cardinality":len(vals),"values":vals,"value_digests":[digest(v) for v in vals]})
            if bi.issue.code == "ambiguous_reference_target":
                opts=(m.get("candidate_targets") or [])
                if opts:
                    # Registry selection is itself a finite solution space, even before a value can be chosen.
                    entry["identifiability"] = IdentifiabilityState.MULTIPLE.value
                    entry["solution_count"] = len(opts)
                    entry["solution_value_digests"] = [digest(o) for o in opts]
                    entry["unique_solution_digest"] = None
                    entry["minimal_missing_witness"] = {
                        "cardinality":1,"kind":"TARGET_REGISTRY_SELECTOR","target_path":path,
                        "description":"One independent witness selecting the intended target registry is sufficient.",
                        "candidate_registry_digests":[digest(o) for o in opts],
                    }
        if extra_domains and entry["identifiability"] != IdentifiabilityState.MULTIPLE.value:
            # Recompute with cross-document domains plus any candidate domains already discovered.
            domains = list(entry.get("finite_domains", [])) + extra_domains
            sols, sources = _intersect_domains(domains)
            entry["finite_domains"] = domains; entry["domain_sources"] = sources
            if sols is not None:
                state = IdentifiabilityState.NONE if len(sols)==0 else IdentifiabilityState.UNIQUE if len(sols)==1 else IdentifiabilityState.MULTIPLE
                entry["identifiability"] = state.value
                entry["solution_count"] = len(sols)
                entry["solution_value_digests"] = [digest(v) for v in sols]
                entry["unique_solution_digest"] = digest(sols[0]) if len(sols)==1 else None
                entry["minimal_missing_witness"] = _minimal_witness_for(state,path,issues,sols,[],domains)
        entry["document"] = document
        entry["qualified_path"] = f"{document}::{path}"
        out.append(entry)
    return out


def compile_stream_identifiability(final_cycle: dict[str, Any]) -> list[dict[str, Any]]:
    out=[]
    samples=list(final_cycle.get("issue_samples", []))
    for idx, issue in enumerate(samples):
        repairable=bool(issue.get("repairable"))
        state=IdentifiabilityState.UNIQUE if repairable else IdentifiabilityState.INSUFFICIENT
        out.append({
            "stream_terminal_sample":idx,
            "record":issue.get("record"),
            "path":issue.get("path", ""),
            "observability":ObservabilityState.BOUNDED_UNMATERIALIZED.value,
            "observed_value_digest":None,
            "identifiability":state.value,
            "solution_count":1 if repairable else None,
            "solution_value_digests":[],
            "unique_solution_digest":None,
            "finite_domains":[],
            "domain_sources":[],
            "candidate_ids":[],
            "direction_blocked_candidate_ids":[],
            "terminal_issue_count":1,
            "minimal_missing_witness":None if repairable else {
                "cardinality":1,
                "kind":"MATERIALIZE_RECORD_OR_SUPPLY_WITNESS",
                "target_path":issue.get("path", ""),
                "description":"The bounded stream report does not retain the full record; materialize this record or provide one independent witness to determine the reconstruction.",
            },
        })
    return out
