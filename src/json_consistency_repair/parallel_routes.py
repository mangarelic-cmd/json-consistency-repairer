from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Callable
import hashlib, json

from .models import Candidate, digest
from .jsonpatch_exact import apply_candidate
from .symmetry import semantic_quotient_digest, compile_semantic_quotient

CONTRACT = "json-consistency-repair.parallel-exact-routes.v1"
RETURN_CONTRACT = "json-consistency-repair.return-proof.v1"


def _canon(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _route_identity(route: list[Candidate]) -> str:
    rows = []
    for c in route:
        rows.append({
            "operation": c.operation,
            "path": c.path,
            "from_path": str((c.metadata or {}).get("from_path", "")),
            "new_value": c.new_value,
            "candidate_id": c.candidate_id,
        })
    return hashlib.sha256(_canon(rows)).hexdigest()


def _candidate_from_dict(row: dict[str, Any], *, suffix: str = "") -> Candidate:
    return Candidate(
        candidate_id=str(row.get("candidate_id") or ("return:" + hashlib.sha256(_canon(row)).hexdigest()[:20] + suffix)),
        analyzer=str(row.get("analyzer") or "parallel_return"),
        operation=str(row.get("operation") or "replace"),
        path=str(row.get("path") or ""),
        old_value=deepcopy(row.get("old_value")),
        new_value=deepcopy(row.get("new_value")),
        reason=str(row.get("reason") or "Continuation patch on a certified exact-minimum route."),
        confidence=float(row.get("confidence", 1.0)),
        cost=int(row.get("cost", 1)),
        evidence=tuple(row.get("evidence") or ()),
        metadata=deepcopy(row.get("metadata") or {}),
    )


def _issue_digest(report: dict[str, Any]) -> str:
    rows = report.get("remaining_issues") or []
    return hashlib.sha256(_canon(rows)).hexdigest()


def _relation_digest(report: dict[str, Any]) -> str:
    rows = report.get("relations") or []
    return hashlib.sha256(_canon(rows)).hexdigest()


def _q_digest(report: dict[str, Any]) -> str:
    q = (report.get("dynamic_q_descent") or {}).get("final") or {}
    return hashlib.sha256(_canon(q)).hexdigest()


def _unresolved_ambiguity(report: dict[str, Any]) -> int:
    bad = {
        "AMBIGUOUS_EXACT_MINIMUM",
        "PARALLEL_EXACT_MINIMUM_REQUIRED",
        "PARALLEL_ROUTE_FRONTIER_TOO_LARGE",
        "SYMMETRY_BLOCKED_REPAIR",
    }
    total = 0
    for cyc in report.get("cycles") or []:
        status = ((cyc.get("minimal_transfer") or {}).get("status"))
        if status in bad:
            total += 1
    return total


@dataclass
class ParallelRouteResolution:
    status: str
    patches: list[Candidate]
    proof: dict[str, Any]


def resolve_parallel_routes(
    root: Any,
    routes: list[list[Candidate]],
    *,
    complete_fn: Callable[[Any], tuple[Any, Any]],
    max_routes: int = 16,
    semantic_quotient_rules: tuple[dict[str, Any], ...] | list[dict[str, Any]] = (),
) -> ParallelRouteResolution:
    """Execute every exact-minimum route from one frozen snapshot.

    No branch is allowed to mutate the sovereign object.  Every route receives a deep clone,
    applies its declared exact-minimum prefix, runs the supplied full completion function, and
    returns serialized closure evidence.  MAIN may receive a route only when all admissible
    branches close to the exact same canonical terminal with the same issue/relation/Q witnesses.
    """
    frozen_digest = digest(root)
    if not routes:
        proof = {"contract": RETURN_CONTRACT, "status": "NO_ROUTES", "ok": False, "frozen_input_digest": frozen_digest}
        return ParallelRouteResolution("NO_ROUTES", [], proof)

    dedup: dict[str, list[Candidate]] = {}
    for r in routes:
        rid = _route_identity(r)
        dedup.setdefault(rid, r)
    ordered = [(rid, dedup[rid]) for rid in sorted(dedup)]
    if len(ordered) > max_routes:
        proof = {
            "contract": RETURN_CONTRACT,
            "status": "PARALLEL_ROUTE_FRONTIER_TOO_LARGE",
            "ok": False,
            "frozen_input_digest": frozen_digest,
            "route_count": len(ordered),
            "max_routes": max_routes,
        }
        return ParallelRouteResolution("PARALLEL_ROUTE_FRONTIER_TOO_LARGE", [], proof)

    route_rows: list[dict[str, Any]] = []
    route_chains: dict[str, list[Candidate]] = {}
    for rid, prefix in ordered:
        clone = deepcopy(root)
        prefix_ok = True
        for c in prefix:
            if not apply_candidate(clone, c):
                prefix_ok = False
                break
        seed_digest = digest(clone) if prefix_ok else None
        row: dict[str, Any] = {
            "route_id": rid,
            "prefix_candidate_ids": [c.candidate_id for c in prefix],
            "prefix_patch_count": len(prefix),
            "prefix_applied": prefix_ok,
            "seed_digest": seed_digest,
        }
        if not prefix_ok:
            row.update({"closed": False, "return_status": "PREFIX_PRECONDITION_FAILED"})
            route_rows.append(row)
            continue

        final_value, result = complete_fn(clone)
        report = result.report
        continuation_rows = list(report.get("committed_edits") or [])
        continuation = [_candidate_from_dict(x, suffix=f":{i}") for i, x in enumerate(continuation_rows)]
        chain = list(prefix) + continuation
        route_chains[rid] = chain
        fp = report.get("strong_fixed_point") or {}
        unresolved = _unresolved_ambiguity(report)
        closed = bool(fp.get("attained") and not fp.get("oscillation_detected") and unresolved == 0)
        row.update({
            "closed": closed,
            "return_status": "CLOSED" if closed else "OPEN_ROUTE",
            "final_status": result.final_status,
            "final_digest": digest(final_value),
            "semantic_quotient_digest": semantic_quotient_digest(final_value, semantic_quotient_rules),
            "continuation_patch_count": len(continuation),
            "total_patch_count": len(chain),
            "remaining_issue_count": int(result.remaining_issues),
            "remaining_issue_digest": _issue_digest(report),
            "relation_digest": _relation_digest(report),
            "q_digest": _q_digest(report),
            "strong_fixed_point": bool(fp.get("attained")),
            "oscillation_detected": bool(fp.get("oscillation_detected")),
            "unresolved_ambiguity_cycles": unresolved,
        })
        route_rows.append(row)

    all_prefix = all(r.get("prefix_applied") for r in route_rows)
    all_closed = bool(route_rows) and all(r.get("closed") for r in route_rows)
    finals = {r.get("final_digest") for r in route_rows if r.get("final_digest")}
    quotient_finals = {r.get("semantic_quotient_digest") for r in route_rows if r.get("semantic_quotient_digest")}
    issues = {r.get("remaining_issue_digest") for r in route_rows if r.get("remaining_issue_digest")}
    relations = {r.get("relation_digest") for r in route_rows if r.get("relation_digest")}
    qdigests = {r.get("q_digest") for r in route_rows if r.get("q_digest")}
    complete_terminals = len(route_rows) == len([r for r in route_rows if r.get("final_digest")])
    exact_terminal_equivalence = len(finals) == 1 and complete_terminals
    quotient_cert = compile_semantic_quotient(root, semantic_quotient_rules)
    quotient_terminal_equivalence = bool(quotient_cert.get("rule_count") and len(quotient_finals) == 1 and complete_terminals)
    terminal_equivalence = bool(exact_terminal_equivalence or quotient_terminal_equivalence)
    witness_equivalence = len(issues) == 1 and len(relations) == 1 and len(qdigests) == 1
    ok = bool(all_prefix and all_closed and terminal_equivalence and witness_equivalence)

    selected_route = min(route_chains) if ok and route_chains else None
    selected = list(route_chains[selected_route]) if selected_route else []
    if ok and exact_terminal_equivalence:
        return_status = "RETURN_PROOF_EQUIVALENT"
    elif ok and quotient_terminal_equivalence:
        return_status = "RETURN_PROOF_QUOTIENT_EQUIVALENT"
    else:
        return_status = "RETURN_PROOF_DIVERGENT"
    proof_body = {
        "contract": RETURN_CONTRACT,
        "parallel_contract": CONTRACT,
        "status": return_status,
        "ok": ok,
        "frozen_input_digest": frozen_digest,
        "route_count": len(route_rows),
        "route_ids": [r["route_id"] for r in route_rows],
        "routes": route_rows,
        "checks": {
            "all_prefixes_applied": all_prefix,
            "all_routes_closed": all_closed,
            "exact_terminal_equivalence": exact_terminal_equivalence,
            "semantic_quotient_terminal_equivalence": quotient_terminal_equivalence,
            "terminal_equivalence": terminal_equivalence,
            "remaining_issue_equivalence": len(issues) == 1,
            "relation_equivalence": len(relations) == 1,
            "q_return_equivalence": len(qdigests) == 1,
        },
        "terminal_digest": next(iter(finals)) if len(finals) == 1 else None,
        "semantic_quotient_terminal_digest": next(iter(quotient_finals)) if len(quotient_finals) == 1 else None,
        "semantic_quotient": quotient_cert,
        "selected_route_id": selected_route,
        "selection_rule": ("lexicographically_smallest_route_id_after_exact_return_equivalence_only" if exact_terminal_equivalence
                           else "lexicographically_smallest_route_id_after_explicit_semantic_quotient_equivalence"),
        "selected_patch_count": len(selected),
    }
    proof_body["proof_sha256"] = hashlib.sha256(_canon(proof_body)).hexdigest()
    return ParallelRouteResolution(proof_body["status"], selected, proof_body)
