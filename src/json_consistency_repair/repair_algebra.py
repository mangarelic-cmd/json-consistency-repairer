from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
from typing import Any, Iterable

from .jsonpatch_exact import apply_candidate
from .models import Candidate, digest
from .tree import decode_pointer

CONTRACT = "json-consistency-repair.repair-path-algebra.v1"
ACTION_CONTRACT = "json-consistency-repair.typed-repair-action.v1"
PAIR_CONTRACT = "json-consistency-repair.critical-pair.v1"


def _canon(v: Any) -> bytes:
    return json.dumps(v, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _path_overlap(a: str, b: str) -> bool:
    if a == "" or b == "": return True
    try:
        aa = decode_pointer(a); bb = decode_pointer(b)
    except Exception:
        return a == b or a.startswith(b.rstrip("/") + "/") or b.startswith(a.rstrip("/") + "/")
    n = min(len(aa), len(bb))
    return aa[:n] == bb[:n]


def _step_sets(step: dict[str, Any]) -> tuple[set[str], set[str]]:
    op = str(step.get("operation") or step.get("op") or "")
    path = str(step.get("path") or "")
    meta = step.get("metadata") or {}
    if op == "plan":
        reads: set[str] = set(); writes: set[str] = set()
        for s in meta.get("steps") or step.get("steps") or []:
            if isinstance(s, dict):
                r, w = _step_sets(s); reads |= r; writes |= w
        return reads, writes
    reads = {path} if path or op in {"replace", "remove", "test", "add"} else set()
    writes = {path} if op in {"replace", "add", "remove", "move", "copy"} else set()
    if op in {"move", "copy"}:
        src = str(meta.get("from_path") or step.get("from_path") or step.get("from") or "")
        if src: reads.add(src)
        if op == "move" and src: writes.add(src)
    # Explicit analyzer-supplied dependencies can only make the guard stricter.
    for p in meta.get("read_paths") or []: reads.add(str(p))
    for p in meta.get("write_paths") or []: writes.add(str(p))
    return reads, writes


def candidate_sets(c: Candidate) -> tuple[set[str], set[str]]:
    payload = {"operation": c.operation, "path": c.path, "old_value": c.old_value, "new_value": c.new_value, "metadata": c.metadata or {}}
    return _step_sets(payload)


def action_record(c: Candidate) -> dict[str, Any]:
    reads, writes = candidate_sets(c)
    payload = {
        "contract": ACTION_CONTRACT,
        "candidate_id": c.candidate_id,
        "analyzer": c.analyzer,
        "operation": c.operation,
        "path": c.path,
        "read_set": sorted(reads),
        "write_set": sorted(writes),
        "cost": c.cost,
        "evidence": sorted(c.evidence),
        "precondition_digest": digest(c.old_value),
        "postvalue_digest": digest(c.new_value),
        "one_shot_identity": True,
    }
    payload["action_sha256"] = hashlib.sha256(_canon(payload)).hexdigest()
    return payload


def _disjoint_commute(a: Candidate, b: Candidate) -> bool:
    ar, aw = candidate_sets(a); br, bw = candidate_sets(b)
    for x in aw:
        for y in br | bw:
            if _path_overlap(x, y): return False
    for x in bw:
        for y in ar | aw:
            if _path_overlap(x, y): return False
    return True


def _apply_once(root: Any, c: Candidate) -> tuple[bool, Any]:
    trial = deepcopy(root)
    ok = apply_candidate(trial, c)
    return ok, trial


def _normal_forms(seed: Any, candidates: list[Candidate], used: frozenset[int], max_states: int = 512) -> tuple[set[str], bool]:
    stack = [(deepcopy(seed), used)]
    seen: set[tuple[str, frozenset[int]]] = set()
    normals: set[str] = set(); overflow = False
    while stack:
        state, done = stack.pop(); key = (digest(state), done)
        if key in seen: continue
        seen.add(key)
        if len(seen) > max_states:
            overflow = True; break
        advanced = False
        for i, c in enumerate(candidates):
            if i in done: continue
            nxt = deepcopy(state)
            if apply_candidate(nxt, c):
                advanced = True
                stack.append((nxt, frozenset(set(done) | {i})))
        if not advanced: normals.add(digest(state))
    return normals, overflow


def critical_pair(root: Any, a: Candidate, b: Candidate, frontier: list[Candidate], *, max_states: int = 512) -> dict[str, Any]:
    if a.candidate_id == b.candidate_id:
        status = "SAME_ACTION"
        body = {"contract": PAIR_CONTRACT, "left": a.candidate_id, "right": b.candidate_id, "status": status, "joinable": True}
        body["pair_sha256"] = hashlib.sha256(_canon(body)).hexdigest(); return body
    if _disjoint_commute(a, b):
        body = {"contract": PAIR_CONTRACT, "left": a.candidate_id, "right": b.candidate_id,
                "status": "PROVEN_COMMUTE_DISJOINT", "joinable": True, "proof": "nonoverlapping read/write footprints"}
        body["pair_sha256"] = hashlib.sha256(_canon(body)).hexdigest(); return body
    ia = next((i for i, c in enumerate(frontier) if c.candidate_id == a.candidate_id), None)
    ib = next((i for i, c in enumerate(frontier) if c.candidate_id == b.candidate_id), None)
    oka, sa = _apply_once(root, a); okb, sb = _apply_once(root, b)
    if not oka or not okb:
        body = {"contract": PAIR_CONTRACT, "left": a.candidate_id, "right": b.candidate_id,
                "status": "PAIR_NOT_COAPPLICABLE_FROM_SNAPSHOT", "joinable": True,
                "left_applicable": oka, "right_applicable": okb}
        body["pair_sha256"] = hashlib.sha256(_canon(body)).hexdigest(); return body
    useda = frozenset({ia}) if ia is not None else frozenset()
    usedb = frozenset({ib}) if ib is not None else frozenset()
    na, oa = _normal_forms(sa, frontier, useda, max_states=max_states)
    nb, ob = _normal_forms(sb, frontier, usedb, max_states=max_states)
    common = sorted(na & nb)
    if oa or ob:
        status = "CRITICAL_PAIR_FRONTIER_TOO_LARGE"; joinable = False
    elif common:
        status = "JOINABLE_CRITICAL_PAIR"; joinable = True
    else:
        status = "CRITICAL_PAIR_OPEN"; joinable = False
    body = {
        "contract": PAIR_CONTRACT, "left": a.candidate_id, "right": b.candidate_id,
        "status": status, "joinable": joinable,
        "left_normal_form_count": len(na), "right_normal_form_count": len(nb),
        "common_normal_form_digest": common[0] if common else None,
        "state_frontier_overflow": bool(oa or ob),
    }
    body["pair_sha256"] = hashlib.sha256(_canon(body)).hexdigest(); return body


def compile_repair_path_algebra(root: Any, candidates: Iterable[Candidate], *, max_actions: int = 16, max_states_per_pair: int = 512) -> dict[str, Any]:
    # Candidate IDs are the finite rewrite identities. The PASS034 scheduler never reuses one
    # identity inside a frontier, so rank = remaining unused action identities strictly decreases.
    uniq = {c.candidate_id: c for c in candidates}
    ordered = [uniq[k] for k in sorted(uniq)]
    actions = [action_record(c) for c in ordered]
    overflow = len(ordered) > max_actions
    pairs: list[dict[str, Any]] = []
    if not overflow:
        for i in range(len(ordered)):
            for j in range(i + 1, len(ordered)):
                pairs.append(critical_pair(root, ordered[i], ordered[j], ordered, max_states=max_states_per_pair))
    open_pairs = [p for p in pairs if not p.get("joinable")]
    termination = {
        "status": "TERMINATION_PROVEN_FINITE_FRONTIER" if not overflow else "REWRITE_TERMINATION_FRONTIER_TOO_LARGE",
        "measure": "remaining_unused_action_identities",
        "initial_rank": len(ordered),
        "strict_decrease_per_transition": True,
        "action_reuse_forbidden": True,
        "scope": "current_finite_candidate_frontier_only",
    }
    if overflow:
        confluence = "CONFLUENCE_UNCOMPUTED_FRONTIER_TOO_LARGE"
    elif open_pairs:
        confluence = "CRITICAL_PAIR_OPEN"
    else:
        confluence = "CONFLUENT_ON_CURRENT_FINITE_FRONTIER"
    body = {
        "contract": CONTRACT,
        "action_count": len(ordered), "max_actions": max_actions, "frontier_overflow": overflow,
        "actions": actions, "critical_pair_count": len(pairs), "critical_pairs": pairs,
        "open_critical_pair_count": len(open_pairs),
        "termination": termination,
        "confluence_status": confluence,
        "newman_scope_note": "Termination plus local critical-pair joinability certifies confluence only for this finite action frontier.",
    }
    body["algebra_sha256"] = hashlib.sha256(_canon(body)).hexdigest()
    return body


def verify_repair_path_algebra(cert: dict[str, Any]) -> bool:
    if not isinstance(cert, dict) or cert.get("contract") != CONTRACT: return False
    supplied = cert.get("algebra_sha256")
    body = dict(cert); body.pop("algebra_sha256", None)
    if not supplied or hashlib.sha256(_canon(body)).hexdigest() != supplied: return False
    if int(cert.get("action_count", -1)) != len(cert.get("actions") or []): return False
    if int(cert.get("critical_pair_count", -1)) != len(cert.get("critical_pairs") or []): return False
    for action in cert.get("actions") or []:
        h = action.get("action_sha256"); tmp = dict(action); tmp.pop("action_sha256", None)
        if not h or hashlib.sha256(_canon(tmp)).hexdigest() != h: return False
    for pair in cert.get("critical_pairs") or []:
        h = pair.get("pair_sha256"); tmp = dict(pair); tmp.pop("pair_sha256", None)
        if not h or hashlib.sha256(_canon(tmp)).hexdigest() != h: return False
    return True


def candidate_set_admissibility(root: Any, candidates: list[Candidate], *, max_states: int = 256) -> dict[str, Any]:
    if len(candidates) <= 1:
        return {"admissible": True, "status": "TRIVIAL_SINGLE_ACTION", "open_pairs": []}
    cert = compile_repair_path_algebra(root, candidates, max_actions=max(2, len(candidates)), max_states_per_pair=max_states)
    open_pairs = [p for p in cert.get("critical_pairs") or [] if not p.get("joinable")]
    return {"admissible": not open_pairs and not cert.get("frontier_overflow"),
            "status": "CONFLUENT_SUBSET" if not open_pairs else "CRITICAL_PAIR_OPEN",
            "open_pairs": [{"left": p.get("left"), "right": p.get("right"), "status": p.get("status")} for p in open_pairs],
            "algebra_sha256": cert.get("algebra_sha256")}
