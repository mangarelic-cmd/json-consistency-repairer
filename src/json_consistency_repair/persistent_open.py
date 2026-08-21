"""PASS038 — persistent OPEN obligations and certified targeted invalidation.

This layer turns unresolved repair terminals into stable machine objects that can be
saved across runs.  New evidence wakes only obligations whose explicit wake tokens
intersect the change set.  A conservative proof-node dependency index identifies
which previously committed proof nodes are invalidated; nodes without explicit
local dependencies are treated as global and are never silently reused.

The incremental-equivalence certificate is intentionally scoped: it proves that the
targeted OPEN-obligation transition is exactly equal to the registry obtained by a
full fresh run, while publication of repaired JSON remains gated by the existing
full cold replay and proof-graph replay.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, Iterable
import json, os, tempfile

from .models import digest

REGISTRY_CONTRACT = "json-consistency-repair.open-obligation-registry.v1"
WAKE_CONTRACT = "json-consistency-repair.open-obligation-wake-plan.v1"
DEPENDENCY_CONTRACT = "json-consistency-repair.proof-dependency-index.v1"
INCREMENTAL_CONTRACT = "json-consistency-repair.incremental-recompute.v1"

_OPEN_TYPES = {
    "NEED_SOURCE",
    "NEED_SOURCE_EXTENSION",
    "NEED_DISAMBIGUATING_SOURCE",
    "NEED_MATERIAL",
    "NEED_RULE_OR_EVIDENCE",
    "NEED_PROVENANCE_PROOF",
    "NEED_AUTHORITY_GRANT",
    "NEED_SYMMETRY_BREAKER",
    "NEED_REWRITE_JOIN",
    "NEED_CONTROL_PERMISSION",
    "NEED_CONTROL_BUDGET_OR_POLICY",
    "NEED_COUNTEREXAMPLE",
    "NEED_BOUNDARY_RESOLUTION",
    "NEED_REGIME_INFORMATION",
}


def _canon_tokens(values: Iterable[str]) -> list[str]:
    return sorted({str(x) for x in values if isinstance(x, str) and x})


def _path_tokens(path: str | None) -> list[str]:
    if path is None:
        return []
    p = str(path)
    if p == "":
        return ["path:"]
    out = [f"path:{p}"]
    if p.startswith("/"):
        parts = p.split("/")[1:]
        cur = ""
        for part in parts[:-1]:
            cur += "/" + part
            out.append(f"path:{cur}/*")
    return _canon_tokens(out)


def _obligation(kind: str, *, path: str | None = None, origin: str,
                detail: Any = None, wake: Iterable[str] = (), deps: Iterable[str] = ()) -> dict[str, Any]:
    if kind not in _OPEN_TYPES:
        kind = "NEED_RULE_OR_EVIDENCE"
    target_paths = [str(path)] if path is not None else []
    wake_tokens = _canon_tokens([*wake, *_path_tokens(path)])
    dependency_tokens = _canon_tokens([*deps, *_path_tokens(path)])
    identity = {
        "kind": kind,
        "target_paths": target_paths,
        "origin": str(origin),
        "detail_sha256": digest(detail),
    }
    return {
        "obligation_id": "obl_" + digest(identity)[:24],
        "kind": kind,
        "status": "OPEN",
        "target_paths": target_paths,
        "origin": str(origin),
        "origin_sha256": digest(detail),
        "wake_tokens": wake_tokens,
        "dependency_tokens": dependency_tokens,
        "detail": deepcopy(detail),
    }


def _walk_dicts(v: Any):
    if isinstance(v, dict):
        yield v
        for x in v.values():
            yield from _walk_dicts(x)
    elif isinstance(v, list):
        for x in v:
            yield from _walk_dicts(x)


def _materialization_obligations(report: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    mat = report.get("witness_materialization") or {}
    finals = []
    if isinstance(mat.get("final"), dict):
        finals.append(mat.get("final"))
    for doc, row in (mat.get("documents") or {}).items() if isinstance(mat.get("documents"), dict) else []:
        cert = (row or {}).get("final") if isinstance(row, dict) else None
        if isinstance(cert, dict):
            finals.append(cert)
    for cert in finals:
        for t in cert.get("terminals") or []:
            if not isinstance(t, dict):
                continue
            status = str(t.get("status") or "")
            if status in {"", "MATERIALIZED_EXACT"}:
                continue
            path = t.get("target_path")
            if status == "SOURCE_GATE":
                kind = "NEED_SOURCE"
            elif status == "MATERIAL_GATE":
                kind = "NEED_MATERIAL"
            elif status == "ABSENT_CERTIFIED_WITHIN_SEARCH_CONTRACT":
                kind = "NEED_SOURCE_EXTENSION"
            elif status == "MULTIPLE_MATERIALIZATIONS_AMBIGUOUS":
                kind = "NEED_DISAMBIGUATING_SOURCE"
            else:
                kind = "NEED_RULE_OR_EVIDENCE"
            out.append(_obligation(kind, path=path, origin="witness_materialization", detail=t,
                                   wake=("source:*", "manifest:*", "identity_bridge:*", "event:*"),
                                   deps=("materialization:*",)))
    return out


def _symmetry_obligations(report: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    sym = report.get("symmetry_canonicality") or {}
    for row in _walk_dicts(sym):
        if row.get("status") != "SYMMETRY_BLOCKED_REPAIR":
            continue
        breakers = row.get("minimal_symmetry_breakers") or []
        paths = []
        for b in breakers:
            if isinstance(b, dict):
                p = b.get("path") or b.get("target_path")
                if p is not None:
                    paths.append(str(p))
        if not paths:
            for route in row.get("routes") or []:
                if isinstance(route, dict) and route.get("path") is not None:
                    paths.append(str(route.get("path")))
        if not paths:
            paths = [""]
        for p in sorted(set(paths)):
            out.append(_obligation("NEED_SYMMETRY_BREAKER", path=p, origin="symmetry_canonicality", detail=row,
                                   wake=("symmetry:*", "identity_bridge:*", "source:*", "schema:*"),
                                   deps=("symmetry:*",)))
    return out


def _algebra_obligations(report: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    alg = report.get("repair_path_algebra") or {}
    for row in _walk_dicts(alg):
        if row.get("status") == "CRITICAL_PAIR_OPEN" or row.get("confluence_status") == "CRITICAL_PAIR_OPEN":
            paths = []
            for cp in row.get("critical_pairs") or []:
                if isinstance(cp, dict) and (cp.get("status") == "CRITICAL_PAIR_OPEN" or not cp.get("joinable", True)):
                    for key in ("path", "left_path", "right_path"):
                        if cp.get(key) is not None:
                            paths.append(str(cp.get(key)))
            out.append(_obligation("NEED_REWRITE_JOIN", path=(paths[0] if paths else ""), origin="repair_path_algebra",
                                   detail=row, wake=("rule:*", "rewrite:*", "constraint:*"), deps=("repair_algebra:*",)))
    return out


def _control_obligations(report: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    control = report.get("repair_controllability") or {}
    seen = set()
    for row in _walk_dicts(control):
        if row.get("status") != "IDENTIFIABLE_BUT_UNREACHABLE" and row.get("reachability") != "UNREACHABLE":
            continue
        path = row.get("path") or row.get("target_path") or ""
        reason = str(row.get("reason") or row.get("gate") or "")
        kind = "NEED_CONTROL_BUDGET_OR_POLICY" if any(x in reason.upper() for x in ("BUDGET", "COST", "PRECEDENCE")) else "NEED_CONTROL_PERMISSION"
        marker = (kind, str(path), digest(row))
        if marker in seen:
            continue
        seen.add(marker)
        out.append(_obligation(kind, path=str(path), origin="repair_controllability", detail=row,
                               wake=("policy:*", "authority:*", "budget:*", "permission:*"), deps=("control:*",)))
    return out


def _semantic_provenance_obligations(report: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    sem = report.get("semantic_claim_provenance") or {}
    for row in _walk_dicts(sem):
        if row.get("classification") != "UNVERIFIED_ATTRIBUTION" and row.get("status") != "GATED_UNVERIFIED_ATTRIBUTION":
            continue
        path = row.get("path") or row.get("target_path") or ""
        out.append(_obligation("NEED_PROVENANCE_PROOF", path=str(path), origin="semantic_claim_provenance", detail=row,
                               wake=("source:*", "provenance:*", "claim:*", "rule:*"), deps=("semantic_provenance:*",)))
    return out


def _remaining_issue_obligations(report: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    issues = report.get("remaining_issues")
    if not isinstance(issues, list):
        # Streaming reports expose an exact count plus bounded final-cycle issue samples.
        cycles = report.get("cycles") or []
        final_cycle = cycles[-1] if cycles and isinstance(cycles[-1], dict) else {}
        issues = final_cycle.get("issue_samples") or []
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        code = str(issue.get("code") or "")
        analyzer = str(issue.get("analyzer") or "")
        path = str(issue.get("path") or "")
        u = code.upper()
        if "AUTHORITY" in u:
            kind = "NEED_AUTHORITY_GRANT"
            wake = ("authority:*", "source:*", "policy:*")
        elif "BOUND" in u or "SCHEMA" in u:
            kind = "NEED_BOUNDARY_RESOLUTION"
            wake = ("schema:*", "constraint:*", "boundary:*")
        elif "REGIME" in u or "HYSTER" in u or "CLOCK" in u:
            kind = "NEED_REGIME_INFORMATION"
            wake = ("regime:*", "time:*", "rule:*")
        elif "PROVENANCE" in u or "ATTRIBUT" in u:
            kind = "NEED_PROVENANCE_PROOF"
            wake = ("provenance:*", "source:*", "rule:*")
        elif "SYMMETRY" in u:
            kind = "NEED_SYMMETRY_BREAKER"
            wake = ("symmetry:*", "identity_bridge:*", "source:*")
        elif "UNREACHABLE" in u or analyzer == "controllability":
            kind = "NEED_CONTROL_PERMISSION"
            wake = ("permission:*", "policy:*", "budget:*")
        else:
            kind = "NEED_RULE_OR_EVIDENCE"
            wake = ("rule:*", "source:*", "schema:*", "constraint:*")
        out.append(_obligation(kind, path=path, origin=f"remaining_issue:{analyzer}:{code}", detail=issue,
                               wake=wake, deps=(f"analyzer:{analyzer}",)))
    return out


def compile_open_obligation_registry(report: dict[str, Any]) -> dict[str, Any]:
    """Compile stable unresolved terminals from a completed report."""
    obligations = []
    obligations.extend(_remaining_issue_obligations(report))
    obligations.extend(_materialization_obligations(report))
    obligations.extend(_symmetry_obligations(report))
    obligations.extend(_algebra_obligations(report))
    obligations.extend(_control_obligations(report))
    obligations.extend(_semantic_provenance_obligations(report))
    by_id = {}
    for row in obligations:
        by_id[row["obligation_id"]] = row
    rows = sorted(by_id.values(), key=lambda x: x["obligation_id"])
    obligations_sha = digest(rows)
    payload = {
        "contract": REGISTRY_CONTRACT,
        "mode": str(report.get("mode") or "single"),
        "terminal_output_digest": report.get("output_digest"),
        "status": "OPEN_OBLIGATIONS_PRESENT" if rows else "QUIESCENT",
        "obligation_count": len(rows),
        "obligations": rows,
        "obligations_sha256": obligations_sha,
        "semantics": {
            "open_is_not_absent": True,
            "not_found_is_not_impossible": True,
            "wake_requires_explicit_dependency_intersection": True,
            "unmatched_open_obligations_are_retained": True,
        },
    }
    payload["registry_sha256"] = digest({k: v for k, v in payload.items() if k != "registry_sha256"})
    return payload


def verify_open_obligation_registry(registry: dict[str, Any]) -> bool:
    if not isinstance(registry, dict) or registry.get("contract") != REGISTRY_CONTRACT:
        return False
    supplied = registry.get("registry_sha256")
    if not supplied or digest({k: v for k, v in registry.items() if k != "registry_sha256"}) != supplied:
        return False
    rows = registry.get("obligations")
    if not isinstance(rows, list) or int(registry.get("obligation_count", -1)) != len(rows):
        return False
    if digest(rows) != registry.get("obligations_sha256"):
        return False
    ids = []
    for row in rows:
        if not isinstance(row, dict) or row.get("kind") not in _OPEN_TYPES or row.get("status") != "OPEN":
            return False
        oid = row.get("obligation_id")
        if not isinstance(oid, str) or not oid.startswith("obl_"):
            return False
        ids.append(oid)
        if row.get("wake_tokens") != _canon_tokens(row.get("wake_tokens") or []):
            return False
        if row.get("dependency_tokens") != _canon_tokens(row.get("dependency_tokens") or []):
            return False
    return ids == sorted(ids) and len(ids) == len(set(ids))


def save_open_obligation_registry(path: str | Path, registry: dict[str, Any]) -> None:
    if not verify_open_obligation_registry(registry):
        raise ValueError("invalid OPEN obligation registry")
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(registry, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    fd, tmp = tempfile.mkstemp(prefix=p.name + ".", suffix=".tmp", dir=str(p.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def load_open_obligation_registry(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not verify_open_obligation_registry(value):
        raise ValueError("OPEN obligation registry integrity failure")
    return value


def _token_match(change: str, dependency: str) -> bool:
    if dependency == "global:*" or change == "global:*":
        return True
    if dependency.endswith("*"):
        return change.startswith(dependency[:-1])
    if change.endswith("*"):
        return dependency.startswith(change[:-1])
    if change == dependency:
        return True
    if change.startswith("path:") and dependency.startswith("path:"):
        a, b = change[5:].rstrip("/*"), dependency[5:].rstrip("/*")
        if a == "" or b == "":
            return a == b
        return a == b or a.startswith(b + "/") or b.startswith(a + "/")
    return False


def wake_open_obligations(registry: dict[str, Any], change_tokens: Iterable[str]) -> dict[str, Any]:
    if not verify_open_obligation_registry(registry):
        raise ValueError("invalid OPEN obligation registry")
    changes = _canon_tokens(change_tokens)
    woken, retained = [], []
    for row in registry.get("obligations") or []:
        deps = list(row.get("wake_tokens") or [])
        hit = sorted({c for c in changes for d in deps if _token_match(c, d)})
        item = {"obligation_id": row["obligation_id"], "kind": row["kind"], "matched_change_tokens": hit}
        (woken if hit else retained).append(item)
    payload = {
        "contract": WAKE_CONTRACT,
        "prior_registry_sha256": registry.get("registry_sha256"),
        "change_tokens": changes,
        "woken": woken,
        "retained": retained,
        "woken_count": len(woken),
        "retained_count": len(retained),
        "status": "TARGETED_WAKE" if woken else "NO_OBLIGATION_WAKE",
    }
    payload["wake_plan_sha256"] = digest({k: v for k, v in payload.items() if k != "wake_plan_sha256"})
    return payload


def verify_wake_plan(plan: dict[str, Any], registry: dict[str, Any]) -> bool:
    if not isinstance(plan, dict) or plan.get("contract") != WAKE_CONTRACT or not verify_open_obligation_registry(registry):
        return False
    supplied = plan.get("wake_plan_sha256")
    if not supplied or digest({k: v for k, v in plan.items() if k != "wake_plan_sha256"}) != supplied:
        return False
    expected = wake_open_obligations(registry, plan.get("change_tokens") or [])
    return expected.get("wake_plan_sha256") == supplied


def _extract_dependency_tokens(payload: Any) -> list[str]:
    tokens = []
    path_keys = {"path", "target_path", "array_path", "source_path", "from_path", "left_path", "right_path"}
    id_keys = {"relation_id": "relation", "rule_id": "rule", "source_id": "source", "document": "document", "schema_version": "schema_version"}
    for row in _walk_dicts(payload):
        for key, value in row.items():
            if key in path_keys and isinstance(value, str):
                tokens.extend(_path_tokens(value))
            elif key in id_keys and isinstance(value, (str, int)):
                tokens.append(f"{id_keys[key]}:{value}")
    return _canon_tokens(tokens)


def compile_proof_dependency_index(proof_graph: dict[str, Any] | None) -> dict[str, Any]:
    nodes = (proof_graph or {}).get("nodes") or []
    rows = []
    for node in nodes:
        if not isinstance(node, dict) or not node.get("node_id"):
            continue
        deps = _extract_dependency_tokens(node.get("payload"))
        # No explicit dependency means conservative global invalidation.  This prevents
        # accidental reuse of opaque or aggregate proof nodes.
        if not deps:
            deps = ["global:*"]
        rows.append({"node_id": node["node_id"], "kind": node.get("kind"), "dependency_tokens": deps})
    rows.sort(key=lambda x: x["node_id"])
    payload = {
        "contract": DEPENDENCY_CONTRACT,
        "proof_graph_sha256": (proof_graph or {}).get("graph_sha256"),
        "node_count": len(rows),
        "nodes": rows,
        "coverage_policy": "OPAQUE_NODE_IS_GLOBAL_AND_MUST_BE_INVALIDATED",
    }
    payload["index_sha256"] = digest({k: v for k, v in payload.items() if k != "index_sha256"})
    return payload


def verify_proof_dependency_index(index: dict[str, Any]) -> bool:
    if not isinstance(index, dict) or index.get("contract") != DEPENDENCY_CONTRACT:
        return False
    supplied = index.get("index_sha256")
    if not supplied or digest({k: v for k, v in index.items() if k != "index_sha256"}) != supplied:
        return False
    rows = index.get("nodes") or []
    if int(index.get("node_count", -1)) != len(rows):
        return False
    ids = [x.get("node_id") for x in rows if isinstance(x, dict)]
    return len(ids) == len(rows) and ids == sorted(ids) and len(ids) == len(set(ids))


def _invalidate_nodes(index: dict[str, Any], changes: list[str]) -> tuple[list[str], list[str]]:
    invalid, retained = [], []
    for row in index.get("nodes") or []:
        deps = row.get("dependency_tokens") or []
        hit = any(_token_match(c, d) for c in changes for d in deps)
        (invalid if hit else retained).append(row["node_id"])
    return sorted(invalid), sorted(retained)


def _targeted_registry_transition(prior: dict[str, Any], current: dict[str, Any], wake_plan: dict[str, Any], changes: list[str]) -> list[dict[str, Any]]:
    woken = {x.get("obligation_id") for x in wake_plan.get("woken") or []}
    retained_prior = [deepcopy(x) for x in prior.get("obligations") or [] if x.get("obligation_id") not in woken]
    affected_current = []
    for row in current.get("obligations") or []:
        deps = row.get("dependency_tokens") or []
        if row.get("obligation_id") in woken or any(_token_match(c, d) for c in changes for d in deps):
            affected_current.append(deepcopy(row))
    by_id = {x["obligation_id"]: x for x in retained_prior + affected_current}
    return sorted(by_id.values(), key=lambda x: x["obligation_id"])


def compile_incremental_recompute(current_registry: dict[str, Any], *, prior_registry: dict[str, Any] | None = None,
                                  change_tokens: Iterable[str] = (), prior_proof_graph: dict[str, Any] | None = None) -> dict[str, Any]:
    if not verify_open_obligation_registry(current_registry):
        raise ValueError("invalid current OPEN obligation registry")
    changes = _canon_tokens(change_tokens)
    if prior_registry is None:
        payload = {
            "contract": INCREMENTAL_CONTRACT,
            "status": "BASELINE_REGISTERED",
            "prior_registry_present": False,
            "current_registry_sha256": current_registry.get("registry_sha256"),
            "current_obligations_sha256": current_registry.get("obligations_sha256"),
            "change_tokens": changes,
            "wake_plan": None,
            "proof_dependency_index": compile_proof_dependency_index(prior_proof_graph),
            "invalidated_proof_nodes": [],
            "retained_proof_nodes": [],
            "incremental_equivalence": None,
            "equivalence_scope": "OPEN_OBLIGATION_STATE_AND_CONSERVATIVE_PROOF_INVALIDATION",
            "publication_gate": "JSON_PUBLICATION_REMAINS_GATED_BY_FULL_COLD_AND_PROOF_GRAPH_REPLAY",
        }
    else:
        if not verify_open_obligation_registry(prior_registry):
            raise ValueError("invalid prior OPEN obligation registry")
        wake = wake_open_obligations(prior_registry, changes)
        dep_index = compile_proof_dependency_index(prior_proof_graph)
        invalid, retained = _invalidate_nodes(dep_index, changes)
        targeted_rows = _targeted_registry_transition(prior_registry, current_registry, wake, changes)
        targeted_sha = digest(targeted_rows)
        full_sha = current_registry.get("obligations_sha256")
        eq = targeted_sha == full_sha
        payload = {
            "contract": INCREMENTAL_CONTRACT,
            "status": "INCREMENTAL_EQ_FULL" if eq else "FULL_RECOMPUTE_REQUIRED",
            "prior_registry_present": True,
            "prior_registry_sha256": prior_registry.get("registry_sha256"),
            "prior_registry_snapshot": deepcopy(prior_registry),
            "current_registry_sha256": current_registry.get("registry_sha256"),
            "current_obligations_sha256": full_sha,
            "change_tokens": changes,
            "wake_plan": wake,
            "proof_dependency_index": dep_index,
            "invalidated_proof_nodes": invalid,
            "retained_proof_nodes": retained,
            "targeted_obligation_count": len(targeted_rows),
            "targeted_obligations_sha256": targeted_sha,
            "incremental_equivalence": bool(eq),
            "equivalence_scope": "OPEN_OBLIGATION_STATE_AND_CONSERVATIVE_PROOF_INVALIDATION",
            "publication_gate": "JSON_PUBLICATION_REMAINS_GATED_BY_FULL_COLD_AND_PROOF_GRAPH_REPLAY",
            "fallback_policy": "ANY_UNEXPLAINED_NEW_OR_CHANGED_OBLIGATION_FORCES_FULL_RECOMPUTE",
        }
    payload["certificate_sha256"] = digest({k: v for k, v in payload.items() if k != "certificate_sha256"})
    return payload


def verify_incremental_recompute_certificate(cert: dict[str, Any], current_registry: dict[str, Any],
                                             prior_registry: dict[str, Any] | None = None,
                                             prior_proof_graph: dict[str, Any] | None = None) -> bool:
    if not isinstance(cert, dict) or cert.get("contract") != INCREMENTAL_CONTRACT:
        return False
    supplied = cert.get("certificate_sha256")
    if not supplied or digest({k: v for k, v in cert.items() if k != "certificate_sha256"}) != supplied:
        return False
    if prior_registry is None and cert.get("prior_registry_present"):
        prior_registry = cert.get("prior_registry_snapshot")
    try:
        # The serialized dependency index is itself integrity-checked.  If the original prior
        # proof graph is available, re-derive it; otherwise preserve the exact committed index.
        expected = compile_incremental_recompute(current_registry, prior_registry=prior_registry,
                                                 change_tokens=cert.get("change_tokens") or [],
                                                 prior_proof_graph=prior_proof_graph)
        if prior_proof_graph is None and cert.get("proof_dependency_index"):
            if not verify_proof_dependency_index(cert.get("proof_dependency_index") or {}):
                return False
            expected["proof_dependency_index"] = deepcopy(cert.get("proof_dependency_index"))
            expected["invalidated_proof_nodes"] = deepcopy(cert.get("invalidated_proof_nodes") or [])
            expected["retained_proof_nodes"] = deepcopy(cert.get("retained_proof_nodes") or [])
            expected["certificate_sha256"] = digest({k: v for k, v in expected.items() if k != "certificate_sha256"})
    except Exception:
        return False
    return expected.get("certificate_sha256") == supplied


def change_tokens_from_json_diff(old: Any, new: Any, *, max_changes: int = 1024) -> list[str]:
    """Conservative JSON-pointer diff tokens for callers resuming a persisted run."""
    out: list[str] = []
    def rec(a: Any, b: Any, parts: list[str]):
        if len(out) >= max_changes:
            return
        path = "" if not parts else "/" + "/".join(x.replace("~", "~0").replace("/", "~1") for x in parts)
        if type(a) is not type(b):
            out.extend(_path_tokens(path)); return
        if isinstance(a, dict):
            keys = sorted(set(a) | set(b))
            for k in keys:
                if k not in a or k not in b:
                    out.extend(_path_tokens(path + "/" + str(k).replace("~", "~0").replace("/", "~1")))
                else:
                    rec(a[k], b[k], parts + [str(k)])
                if len(out) >= max_changes: break
        elif isinstance(a, list):
            if len(a) != len(b):
                out.extend(_path_tokens(path)); return
            for i, (x, y) in enumerate(zip(a, b)):
                rec(x, y, parts + [str(i)])
                if len(out) >= max_changes: break
        elif a != b:
            out.extend(_path_tokens(path))
    rec(old, new, [])
    if len(out) >= max_changes:
        out.append("global:*")
    return _canon_tokens(out)

EQUIVALENCE_CONTRACT = "json-consistency-repair.incremental-equivalence.v1"


def compile_incremental_equivalence(incremental_cert: dict[str, Any], current_proof_graph: dict[str, Any],
                                    proof_graph_replay: dict[str, Any], prior_proof_graph: dict[str, Any] | None = None) -> dict[str, Any]:
    """Bind the targeted invalidation plan to the full fresh proof-graph replay.

    This is the PASS038 correctness bridge: retained prior proof nodes are reusable only if
    their exact node identity still appears in the newly reconstructed full proof graph.
    Any drift forces fallback.  The full proof-graph replay remains the publication oracle.
    """
    current_nodes={x.get("node_id"):x for x in (current_proof_graph or {}).get("nodes") or [] if isinstance(x,dict) and x.get("node_id")}
    prior_nodes={x.get("node_id"):x for x in (prior_proof_graph or {}).get("nodes") or [] if isinstance(x,dict) and x.get("node_id")}
    full_ok=bool((proof_graph_replay or {}).get("ok"))
    if not prior_proof_graph:
        payload={
            "contract":EQUIVALENCE_CONTRACT,
            "status":"BASELINE_NO_PRIOR_PROOF_GRAPH",
            "prior_proof_graph_present":False,
            "prior_proof_graph_sha256":None,
            "current_proof_graph_sha256":(current_proof_graph or {}).get("graph_sha256"),
            "full_proof_graph_replay_ok":full_ok,
            "reused_node_ids":[],"reused_node_count":0,
            "recomputed_or_new_node_ids":sorted(current_nodes),"recomputed_or_new_node_count":len(current_nodes),
            "drifted_retained_node_ids":[],
            "incremental_proof_equivalence":None,
            "publication_gate":"FULL_PROOF_GRAPH_REPLAY_REQUIRED",
        }
    else:
        retained=set(incremental_cert.get("retained_proof_nodes") or [])
        reusable=[]; drifted=[]
        for nid in sorted(retained):
            p=prior_nodes.get(nid); c=current_nodes.get(nid)
            if p is not None and c is not None and p.get("payload_sha256")==c.get("payload_sha256") and p.get("kind")==c.get("kind"):
                reusable.append(nid)
            else:
                drifted.append(nid)
        recomputed=sorted(set(current_nodes)-set(reusable))
        eq=bool(full_ok and not drifted)
        payload={
            "contract":EQUIVALENCE_CONTRACT,
            "status":"INCREMENTAL_PROOF_EQ_FULL" if eq else "FULL_RECOMPUTE_REQUIRED",
            "prior_proof_graph_present":True,
            "prior_proof_graph_sha256":prior_proof_graph.get("graph_sha256"),
            "current_proof_graph_sha256":current_proof_graph.get("graph_sha256"),
            "full_proof_graph_replay_ok":full_ok,
            "reused_node_ids":reusable,"reused_node_count":len(reusable),
            "recomputed_or_new_node_ids":recomputed,"recomputed_or_new_node_count":len(recomputed),
            "drifted_retained_node_ids":drifted,
            "incremental_proof_equivalence":eq,
            "publication_gate":"FULL_PROOF_GRAPH_REPLAY_REQUIRED",
            "safety_policy":"REUSE_ONLY_EXACT_NODE_IDENTITIES_SURVIVING_CONSERVATIVE_INVALIDATION",
        }
    payload["certificate_sha256"]=digest({k:v for k,v in payload.items() if k!="certificate_sha256"})
    return payload


def verify_incremental_equivalence_certificate(cert: dict[str, Any], current_proof_graph: dict[str, Any],
                                               proof_graph_replay: dict[str, Any]) -> bool:
    if not isinstance(cert,dict) or cert.get("contract")!=EQUIVALENCE_CONTRACT:
        return False
    supplied=cert.get("certificate_sha256")
    if not supplied or digest({k:v for k,v in cert.items() if k!="certificate_sha256"})!=supplied:
        return False
    if cert.get("current_proof_graph_sha256")!=(current_proof_graph or {}).get("graph_sha256"):
        return False
    if bool(cert.get("full_proof_graph_replay_ok"))!=bool((proof_graph_replay or {}).get("ok")):
        return False
    current_ids={x.get("node_id") for x in (current_proof_graph or {}).get("nodes") or [] if isinstance(x,dict)}
    if not set(cert.get("reused_node_ids") or []).issubset(current_ids):
        return False
    if not set(cert.get("recomputed_or_new_node_ids") or []).issubset(current_ids):
        return False
    if set(cert.get("reused_node_ids") or []) & set(cert.get("recomputed_or_new_node_ids") or []):
        return False
    if set(cert.get("reused_node_ids") or []) | set(cert.get("recomputed_or_new_node_ids") or []) != current_ids:
        return False
    if cert.get("status")=="INCREMENTAL_PROOF_EQ_FULL":
        if not cert.get("prior_proof_graph_present") or cert.get("drifted_retained_node_ids") or not cert.get("incremental_proof_equivalence"):
            return False
        if not (proof_graph_replay or {}).get("ok"):
            return False
    return True
