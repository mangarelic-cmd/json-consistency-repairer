from __future__ import annotations

from copy import deepcopy
from collections import defaultdict
from typing import Any
import hashlib, json

from .models import AnalysisResult, Candidate, Issue, digest, pointer
from .tree import get, decode_pointer
from .identifiability import compile_identifiability_registry
from .multisource import compile_identity_registry
from .authority_scope import compile_authority_registry, evaluate_authority

CONTRACT = "json-consistency-repair.witness-materialization.v1"
SEARCH_CONTRACT = "json-consistency-repair.material-search-contract.v1"

STATUS_MATERIALIZED = "MATERIALIZED_EXACT"
STATUS_SOURCE_GATE = "SOURCE_GATE"
STATUS_MATERIAL_GATE = "MATERIAL_GATE"
STATUS_ABSENT = "ABSENT_CERTIFIED_WITHIN_SEARCH_CONTRACT"
STATUS_AMBIGUOUS = "MULTIPLE_MATERIALIZATIONS_AMBIGUOUS"
STATUS_NOT_APPLICABLE = "NO_MATERIALIZABLE_WITNESS"


def _stable(prefix: str, payload: Any, n: int = 24) -> str:
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return prefix + hashlib.sha256(raw).hexdigest()[:n]


def _exists(root: Any, path: str) -> bool:
    try:
        get(root, path)
        return True
    except (KeyError, IndexError, ValueError, TypeError):
        return False


def _parent_exists(root: Any, path: str) -> bool:
    toks = decode_pointer(path)
    if not toks:
        return False
    if len(toks) == 1:
        return isinstance(root, (dict, list))
    try:
        return isinstance(get(root, pointer(toks[:-1])), (dict, list))
    except (KeyError, IndexError, ValueError, TypeError):
        return False


def _translate_path(path: str, source_id: str, identity: dict[str, Any]) -> str:
    """Translate a primary path through canonical field identity into one source version.

    Identity bridges are field-name identities. Array indices and unbridged tokens are preserved.
    This is intentionally structural and lossless; no fuzzy-name matching occurs.
    """
    pmap = (identity.get("field_maps") or {}).get("__primary__", {})
    reverse = (identity.get("canonical_to_source_field") or {}).get(source_id, {})
    out = []
    for tok in decode_pointer(path):
        canonical = pmap.get(tok, tok)
        out.append(reverse.get(canonical, canonical))
    return pointer(out)


def _hint_rows(manifest: dict[str, Any], target_path: str) -> list[dict[str, Any]]:
    rows = []
    raw_hints=manifest.get("materialization_hints") or []
    if not isinstance(raw_hints,list) or len(raw_hints)>1024:
        raise ValueError("materialization_hints must be a bounded array of at most 1024 entries")
    for raw in raw_hints:
        if not isinstance(raw, dict):
            continue
        if str(raw.get("target_path") or "") != target_path:
            continue
        sid = str(raw.get("source_id") or "")
        sp = str(raw.get("source_path") or raw.get("path") or target_path)
        if sid and sp:
            rows.append({"source_id": sid, "source_path": sp, "mode": str(raw.get("mode") or "AUTO").upper(), "explicit": True})
    return rows


def _event_observations(context_by_id: dict[str, dict[str, Any]], manifest: dict[str, Any], target_path: str, authority_registry:dict[str,Any], operation:str) -> list[dict[str, Any]]:
    out = []
    auth_by={x.get("source_id"):x for x in authority_registry.get("sources") or []}
    ev=authority_registry.get("evaluation") or {}
    for r in manifest.get("projections") or []:
        if not isinstance(r, dict) or r.get("kind") != "last_event_value":
            continue
        target = str(r.get("target_path") or "")
        if target != target_path:
            continue
        sid = str(r.get("source_id") or "")
        src = context_by_id.get(sid)
        if not src or str(src.get("role") or "") != "event_log":
            continue
        doc = src.get("value")
        ep = str(r.get("events_path") or "")
        if ep:
            if not _exists(doc, ep):
                continue
            events = get(doc, ep)
        else:
            events = doc
        if not isinstance(events, list):
            continue
        pf = str(r.get("path_field") or "path")
        vf = str(r.get("value_field") or "value")
        vals = [e[vf] for e in events if isinstance(e, dict) and e.get(pf) == target and vf in e]
        if not vals:
            continue
        pr=evaluate_authority(authority_registry,sid,target_path=target_path,operation=operation,document=ev.get("document"),schema_version=ev.get("schema_version"),evaluation_time=ev.get("evaluation_time"))
        requested=bool(r.get("authoritative",False))
        out.append({
            "source_id": sid, "role": "event_log", "schema_version": src.get("schema_version"),
            "declared_independent_group": src.get("independent_group", sid),
            "independent_group": (auth_by.get(sid) or {}).get("effective_evidence_group",src.get("independent_group", sid)),
            "eligible": bool(src.get("eligible", True)), "source_path": ep or "",
            "value": deepcopy(vals[-1]), "value_digest": digest(vals[-1]),
            "authority_class": "AUTHORITATIVE" if requested and pr.get("authorized") else "OBSERVATION_ONLY",
            "authority_requested": requested, "authority_request_denied": bool(requested and not pr.get("authorized")),
            "authority_proof_sha256": pr.get("proof_sha256"), "discovery": "EXPLICIT_EVENT_PROJECTION", "event_count": len(vals),
        })
    return out


def _source_observations(root: Any, target_path: str, config: Any) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    context = tuple(getattr(config, "source_context", ()) or ())
    manifest = deepcopy(getattr(config, "source_manifest", None) or {})
    identity = compile_identity_registry(context, manifest)
    document=getattr(config,"logic_document",None) or getattr(config,"system_document",None) or getattr(config,"conservation_document",None) or getattr(config,"moment_document",None)
    authority_registry=compile_authority_registry(root,context,manifest,document=document)
    auth_by={x.get("source_id"):x for x in authority_registry.get("sources") or []}
    ev=authority_registry.get("evaluation") or {}
    requested_operation="replace" if _exists(root,target_path) else "add"
    ids=[str(s.get("source_id") or "") for s in context if str(s.get("source_id") or "")]
    duplicate_ids=sorted({sid for sid in ids if ids.count(sid)>1})
    byid = {str(s.get("source_id") or ""): s for s in context if str(s.get("source_id") or "") and str(s.get("source_id") or "") not in duplicate_ids}
    hints = _hint_rows(manifest, target_path)
    hinted = defaultdict(list)
    for h in hints:
        hinted[h["source_id"]].append(h)

    obs: list[dict[str, Any]] = []
    searched: list[dict[str, Any]] = []
    authority_proofs=[]
    for sid in sorted(byid):
        src = byid[sid]
        role = str(src.get("role") or "reference")
        eligible = bool(src.get("eligible", True))
        source_paths = []
        if hinted.get(sid):
            source_paths.extend((h["source_path"], h.get("mode", "AUTO"), "EXPLICIT_HINT") for h in hinted[sid])
        translated = _translate_path(target_path, sid, identity) if identity.get("valid",True) else target_path
        source_paths.append((translated, "AUTO", "IDENTITY_EQUIVALENT_PATH" if identity.get("valid",True) else "SAME_POINTER_WITH_IDENTITY_GATE"))
        if translated != target_path:
            source_paths.append((target_path, "AUTO", "SAME_POINTER_FALLBACK"))

        dedup = set()
        for sp, mode, discovery in source_paths:
            if sp in dedup:
                continue
            dedup.add(sp)
            found = _exists(src.get("value"), sp)
            searched.append({"source_id": sid, "source_path": sp, "found": found, "eligible": eligible, "role": role, "discovery": discovery})
            if not found:
                continue
            val = deepcopy(get(src.get("value"), sp))
            pr=evaluate_authority(authority_registry,sid,target_path=target_path,operation=requested_operation,document=ev.get("document"),schema_version=ev.get("schema_version"),evaluation_time=ev.get("evaluation_time"))
            authority_proofs.append(pr)
            authorized=bool(pr.get("authorized"))
            if role in {"authoritative", "manifest"}:
                authority = "AUTHORITATIVE" if authorized else "OBSERVATION_ONLY"
            elif role == "defaults":
                authority = "DEFAULT_ONLY" if authorized and requested_operation=="add" else "OBSERVATION_ONLY"
            elif role in {"reference", "heldout"}:
                authority = "INDEPENDENT_WITNESS"
            elif bool(src.get("witness_eligible", False)) or str(src.get("materialization_role") or "").upper() in {"WITNESS", "AUTHORITATIVE"}:
                requested=str(src.get("materialization_role") or "").upper()
                authority = "AUTHORITATIVE" if requested=="AUTHORITATIVE" and authorized else ("INDEPENDENT_WITNESS" if requested!="AUTHORITATIVE" else "OBSERVATION_ONLY")
            else:
                authority = "OBSERVATION_ONLY"
            authority_requested = str(mode).upper()=="AUTHORITATIVE"
            if authority_requested:
                authority = "AUTHORITATIVE" if authorized else "OBSERVATION_ONLY"
            elif str(mode).upper() in {"WITNESS", "INDEPENDENT_WITNESS"}:
                authority = "INDEPENDENT_WITNESS"
            ar=auth_by.get(sid) or {}
            obs.append({
                "source_id": sid, "role": role, "schema_version": src.get("schema_version"),
                "declared_independent_group": src.get("independent_group", sid),
                "independent_group": ar.get("effective_evidence_group",src.get("independent_group", sid)), "eligible": eligible,
                "source_path": sp, "value": val, "value_digest": digest(val),
                "authority_class": authority, "authority_requested":authority_requested,
                "authority_request_denied":bool(authority_requested and not authorized),
                "authority_proof_sha256":pr.get("proof_sha256"), "discovery": discovery,
            })

    obs.extend(_event_observations(byid, manifest, target_path, authority_registry, requested_operation))
    uniq = {}
    for row in obs:
        key = (row.get("source_id"), row.get("source_path"), row.get("value_digest"), row.get("authority_class"), row.get("discovery"))
        uniq[key] = row
    obs = [uniq[k] for k in sorted(uniq, key=lambda x: tuple(str(y) for y in x))]
    authority_proofs=list({x.get("proof_sha256"):x for x in authority_proofs if x.get("proof_sha256")}.values())
    search = {
        "contract": SEARCH_CONTRACT, "target_path": target_path, "source_count": len(context),
        "searched_locations": searched, "searched_location_count": len(searched),
        "identity_registry_digest": identity.get("registry_digest"), "identity_bridge_count": len(identity.get("bridges") or []),
        "identity_conflict_count": len(identity.get("conflicts") or []), "duplicate_source_ids": duplicate_ids,
        "source_registry_conflict_count": len(duplicate_ids) + len(authority_registry.get("conflicts") or []),
        "explicit_hint_count": len(hints), "event_projection_checked": True,
        "authority_registry_sha256":authority_registry.get("registry_sha256"),
        "evidence_poisoning_firewall_sha256":((authority_registry.get("evidence_poisoning_firewall") or {}).get("firewall_sha256")),
        "authority_proofs":sorted(authority_proofs,key=lambda x:x.get("proof_sha256","")),
        "bounded_complete_over_loaded_context": True, "no_fuzzy_matching": True,
        "authority_escalation_by_hint_forbidden":True, "effective_evidence_groups_used":True,
    }
    search["search_sha256"] = digest(search)
    return obs, search


def _solution_digests(entry: dict[str, Any]) -> set[str]:
    return set(entry.get("solution_value_digests") or [])


def _blocked_candidate_digests(analysis: AnalysisResult, entry: dict[str, Any]) -> set[str]:
    ids = set(entry.get("direction_blocked_candidate_ids") or [])
    return {digest(c.new_value) for c in analysis.candidates if c.candidate_id in ids}


def _existing_candidate_digests(analysis: AnalysisResult, path: str) -> set[str]:
    return {digest(c.new_value) for c in analysis.candidates if c.path == path}


def _qualify_observation(root: Any, analysis: AnalysisResult, entry: dict[str, Any], witness: dict[str, Any], row: dict[str, Any]) -> tuple[bool, str]:
    if not row.get("eligible"):
        return False, "SOURCE_INELIGIBLE"
    kind = str(witness.get("kind") or "")
    auth = str(row.get("authority_class") or "OBSERVATION_ONLY")
    vd = str(row.get("value_digest") or "")
    solutions = _solution_digests(entry)
    blocked = _blocked_candidate_digests(analysis, entry)
    existing = _existing_candidate_digests(analysis, str(entry.get("path") or ""))

    # If a finite solution domain is known, a material witness may only select inside it.
    if solutions and vd not in solutions:
        return False, "OUTSIDE_ADMISSIBLE_SOLUTION_DOMAIN"

    if kind == "AUTHORITATIVE_SELECTOR":
        return (auth in {"AUTHORITATIVE", "INDEPENDENT_WITNESS"}, "SELECTOR_REQUIRES_INDEPENDENT_WITNESS")
    if kind == "INDEPENDENT_DIRECTION_ANCHOR":
        if blocked and vd not in blocked:
            return False, "DOES_NOT_ANCHOR_BLOCKED_DIRECTION"
        return (auth in {"AUTHORITATIVE", "INDEPENDENT_WITNESS"}, "DIRECTION_REQUIRES_INDEPENDENT_WITNESS")
    if kind in {"AUTHORITATIVE_VALUE_OR_DEFAULT"}:
        if auth == "DEFAULT_ONLY" and _exists(root, str(entry.get("path") or "")):
            return False, "DEFAULT_CANNOT_OVERRIDE_OBSERVED_VALUE"
        return (auth in {"AUTHORITATIVE", "DEFAULT_ONLY"}, "AUTHORITATIVE_VALUE_REQUIRED")
    if kind in {"AUTHORITATIVE_IDENTITY_ASSIGNMENT", "SEMANTIC_CONVERSION_RULE"}:
        return (auth == "AUTHORITATIVE", "AUTHORITATIVE_MATERIAL_REQUIRED")
    if kind in {"REFERENCE_TARGET_WITNESS", "ENUM_IDENTITY_WITNESS"}:
        return (auth in {"AUTHORITATIVE", "INDEPENDENT_WITNESS"}, "REFERENCE_WITNESS_REQUIRED")
    if kind == "ADDITIONAL_INDEPENDENT_WITNESS":
        # Non-authoritative observations are only allowed to reinforce an already-derived candidate,
        # and a source correlated with that candidate's evidence is not an additional witness.
        if auth == "INDEPENDENT_WITNESS" and existing and vd not in existing:
            return False, "INDEPENDENT_WITNESS_DOES_NOT_MATCH_DERIVED_CANDIDATE"
        row_group=str(row.get("independent_group") or "")
        prior_groups=set()
        for c in analysis.candidates:
            if c.path != str(entry.get("path") or ""): continue
            cm=c.metadata or {}
            if cm.get("effective_evidence_group"): prior_groups.add(str(cm.get("effective_evidence_group")))
            prior_groups.update(str(x) for x in (cm.get("independent_groups") or []))
        if auth == "INDEPENDENT_WITNESS" and row_group and row_group in prior_groups:
            return False, "CORRELATED_WITH_EXISTING_EVIDENCE"
        return (auth in {"AUTHORITATIVE", "INDEPENDENT_WITNESS"}, "ADDITIONAL_INDEPENDENT_WITNESS_REQUIRED")
    # Constraint/source revision and registry-selection terminals need an explicit higher-level object;
    # copying a raw value into the target would be a category error.
    return False, "WITNESS_KIND_REQUIRES_NON_VALUE_OBJECT"


def _candidate_from_materialization(root: Any, path: str, value: Any, terminal: dict[str, Any], qualifying: list[dict[str, Any]], proof_sha: str) -> Candidate | None:
    exists = _exists(root, path)
    if not exists and not _parent_exists(root, path):
        return None
    old = deepcopy(get(root, path)) if exists else None
    if exists and old == value:
        return None
    authoritative = any(x.get("authority_class") in {"AUTHORITATIVE", "DEFAULT_ONLY"} for x in qualifying)
    meta = {
        "constraint_source": "authoritative" if authoritative else "derived_exact",
        "relation_kind": "materialized_missing_witness",
        "witness_kind": terminal.get("witness_kind"),
        "materialization_terminal_id": terminal.get("terminal_id"),
        "materialization_proof_sha256": proof_sha,
        "source_ids": sorted({str(x.get("source_id")) for x in qualifying}),
        "independent_groups": sorted({str(x.get("independent_group")) for x in qualifying}),
        "source_roles": sorted({str(x.get("role")) for x in qualifying}),
        "add_if_missing": not exists,
    }
    payload = ["witness_materializer", "add" if not exists else "replace", path, old, value, meta]
    cid = _stable("mat_", payload, 20)
    return Candidate(cid, "witness_materializer", "add" if not exists else "replace", path, old, deepcopy(value),
                     "Materialize the exact minimal missing witness from bounded admissible source evidence.",
                     1.0, 1, tuple(f"MATERIALIZED:{x.get('source_id')}" for x in qualifying), meta)


def materialize_missing_witnesses(root: Any, analysis: AnalysisResult, config: Any) -> tuple[AnalysisResult, dict[str, Any]]:
    """Compile unresolved identifiability terminals into exact source-backed candidates when possible.

    The function never treats search failure as world-level absence.  ABSENT means only that the bounded,
    explicitly loaded source/search contract was exhausted.  Ambiguous materializations abstain.
    """
    enabled = bool(getattr(config, "enable_witness_materialization", True))
    registry = compile_identifiability_registry(root, analysis)
    if not enabled:
        cert = {"contract": CONTRACT, "enabled": False, "terminals": [], "terminal_count": 0,
                "summary": {STATUS_MATERIALIZED: 0, STATUS_SOURCE_GATE: 0, STATUS_MATERIAL_GATE: 0, STATUS_ABSENT: 0, STATUS_AMBIGUOUS: 0}}
        cert["certificate_sha256"] = digest(cert)
        return AnalysisResult(), cert

    additions = AnalysisResult()
    terminals = []
    for entry in registry:
        witness = entry.get("minimal_missing_witness")
        if not isinstance(witness, dict):
            continue
        path = str(entry.get("path") or "")
        kind = str(witness.get("kind") or "")
        terminal_id = _stable("mw_", {"path": path, "kind": kind, "identifiability": entry.get("identifiability"), "witness": witness}, 20)
        observations, search = _source_observations(root, path, config)
        qualifying = []
        gates = []
        for row in observations:
            ok, reason = _qualify_observation(root, analysis, entry, witness, row)
            public = {k: deepcopy(v) for k, v in row.items() if k != "value"}
            public["qualifies"] = bool(ok)
            public["gate_reason"] = None if ok else reason
            gates.append(public)
            if ok:
                qualifying.append(row)

        value_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in qualifying:
            value_groups[str(row.get("value_digest"))].append(row)

        status = STATUS_NOT_APPLICABLE
        selected_value = None
        selected_rows: list[dict[str, Any]] = []
        candidate = None
        proof_sha = None
        if len(value_groups) > 1:
            status = STATUS_AMBIGUOUS
        elif len(value_groups) == 1:
            vd = next(iter(value_groups))
            selected_rows = value_groups[vd]
            selected_value = deepcopy(selected_rows[0]["value"])
            proof_payload = {
                "contract": CONTRACT, "terminal_id": terminal_id, "target_path": path, "witness_kind": kind,
                "identifiability": entry.get("identifiability"), "selected_value_digest": vd,
                "source_evidence": [{k: v for k, v in x.items() if k != "value"} for x in selected_rows],
                "search_sha256": search.get("search_sha256"),
            }
            proof_sha = digest(proof_payload)
            candidate = _candidate_from_materialization(root, path, selected_value,
                                                         {"terminal_id": terminal_id, "witness_kind": kind}, selected_rows, proof_sha)
            if candidate is not None:
                status = STATUS_MATERIALIZED
                additions.candidates.append(candidate)
                rel = {
                    "kind": "materialized_missing_witness", "inputs": [], "output": path,
                    "target_path": path, "witness_kind": kind, "direction_certified": True,
                    "direction_source": "bounded_source_materialization", "constraint_source": candidate.metadata.get("constraint_source"),
                    "source_ids": list(candidate.metadata.get("source_ids") or []), "independent_groups": list(candidate.metadata.get("independent_groups") or []),
                    "materialization_proof_sha256": proof_sha,
                }
                rel["relation_id"] = _stable("matrel_", rel, 20)
                additions.relations.append(rel)
            else:
                status = STATUS_MATERIAL_GATE
        else:
            if (search.get("source_registry_conflict_count") or 0)>0:
                status = STATUS_SOURCE_GATE
            elif not observations:
                status = STATUS_ABSENT
            elif any(not x.get("eligible") for x in observations):
                status = STATUS_SOURCE_GATE
            else:
                status = STATUS_MATERIAL_GATE

        terminal = {
            "terminal_id": terminal_id, "target_path": path, "observability": entry.get("observability"),
            "identifiability": entry.get("identifiability"), "witness_kind": kind,
            "witness": deepcopy(witness), "status": status,
            "search_contract": search,
            "observations": gates,
            "qualifying_observation_count": len(qualifying),
            "distinct_qualifying_value_count": len(value_groups),
            "selected_value_digest": digest(selected_value) if status == STATUS_MATERIALIZED else None,
            "materialization_proof_sha256": proof_sha if status == STATUS_MATERIALIZED else None,
            "candidate_id": candidate.candidate_id if candidate is not None else None,
            "reinjectable": bool(candidate is not None),
            "absence_scope": "LOADED_BOUNDED_SEARCH_CONTRACT_ONLY" if status == STATUS_ABSENT else None,
        }
        terminals.append(terminal)

    counts = {s: 0 for s in (STATUS_MATERIALIZED, STATUS_SOURCE_GATE, STATUS_MATERIAL_GATE, STATUS_ABSENT, STATUS_AMBIGUOUS, STATUS_NOT_APPLICABLE)}
    for row in terminals:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    cert = {
        "contract": CONTRACT, "enabled": True, "terminal_count": len(terminals), "terminals": terminals,
        "summary": counts,
        "reinjectable_candidate_count": len(additions.candidates),
        "materialized_relation_count": len(additions.relations),
        "semantic_guards": {
            "not_found_is_not_absent": True,
            "bounded_absence_only": True,
            "multiple_values_abstain": True,
            "observational_history_not_authority": True,
            "aliases_require_identity_bridge_or_explicit_hint": True,
            "event_values_require_explicit_projection": True,
        },
    }
    cert["certificate_sha256"] = digest(cert)
    return additions, cert


def materialization_summary(cycles: list[dict[str, Any]], final: dict[str, Any] | None = None) -> dict[str, Any]:
    rows = list(cycles or [])
    totals = defaultdict(int)
    materialized_candidates = 0
    for c in rows:
        cert = c.get("certificate") if isinstance(c, dict) and "certificate" in c else c
        if not isinstance(cert, dict):
            continue
        for k, v in (cert.get("summary") or {}).items():
            totals[k] += int(v or 0)
        materialized_candidates += int(cert.get("reinjectable_candidate_count", 0) or 0)
    return {
        "contract": "json-consistency-repair.witness-materialization-summary.v1",
        "cycle_count": len(rows),
        "totals": dict(sorted(totals.items())),
        "reinjectable_candidates_seen": materialized_candidates,
        "final_certificate_sha256": (final or {}).get("certificate_sha256"),
    }
