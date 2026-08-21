from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

from json_consistency_repair.models import AnalysisResult, Candidate, Issue, digest
from json_consistency_repair.minimal_transfer import solve_minimal_transfer
from json_consistency_repair.parallel_routes import resolve_parallel_routes
from json_consistency_repair.jsonpatch_exact import apply_candidate
from json_consistency_repair import RepairConfig, repair_object


def _candidate(cid: str, new: int) -> Candidate:
    return Candidate(cid, "synthetic", "replace", "/x", 0, new, "exact tied witness", 1.0, 1, (f"E:{cid}",), {})


def _analysis_for_tie() -> AnalysisResult:
    issue = Issue("synthetic", "bad_x", "/x", "x is inconsistent", "error", True, {"terminal": "x"})
    return AnalysisResult([issue], [_candidate("a", 1), _candidate("b", 2)], [])


def _analyze_tie(v):
    if v.get("x") in (1, 2):
        return AnalysisResult([], [], [])
    return _analysis_for_tie()


def _score(issues):
    return 10 * len(issues)


def test_exact_tie_materializes_parallel_routes_instead_of_opaque_abstention():
    d = solve_minimal_transfer({"x": 0}, _analysis_for_tie(), analyze_fn=_analyze_tie, score_fn=_score,
                               enable_parallel_routes=True, max_parallel_routes=8)
    assert d.status == "AMBIGUOUS_EXACT_MINIMUM"
    assert not d.patches
    assert len(d.parallel_routes) == 2
    assert d.certificate["parallel_route_count"] == 2


def _fake_result(seed, final, continuation):
    report = {
        "committed_edits": continuation,
        "remaining_issues": [],
        "relations": [],
        "dynamic_q_descent": {"final": {"Q_ANSWER": 0, "Q_BOUNDARY": 0, "Q_RETURN": 0}},
        "strong_fixed_point": {"attained": True, "oscillation_detected": False},
        "cycles": [{"minimal_transfer": {"status": "NO_ADMISSIBLE_CANDIDATES"}}],
    }
    return final, SimpleNamespace(report=report, final_status="PASS", remaining_issues=0)


def test_return_proof_accepts_only_exactly_reconvergent_routes():
    root = {"x": 0}
    routes = [[_candidate("a", 1)], [_candidate("b", 2)]]
    def complete(seed):
        old = seed["x"]
        final = {"x": 9}
        continuation = [{
            "candidate_id": f"close-{old}", "analyzer": "closure", "operation": "replace", "path": "/x",
            "old_value": old, "new_value": 9, "reason": "common terminal", "confidence": 1.0, "cost": 1,
            "evidence": ["RETURN"], "metadata": {},
        }]
        return _fake_result(seed, final, continuation)
    r = resolve_parallel_routes(root, routes, complete_fn=complete, max_routes=8)
    assert r.status == "RETURN_PROOF_EQUIVALENT"
    assert r.proof["ok"] is True
    assert r.proof["checks"]["exact_terminal_equivalence"] is True
    trial = deepcopy(root)
    for c in r.patches:
        assert apply_candidate(trial, c)
    assert trial == {"x": 9}
    assert digest(trial) == r.proof["terminal_digest"]


def test_return_proof_refuses_routes_that_close_to_different_terminals():
    root = {"x": 0}
    routes = [[_candidate("a", 1)], [_candidate("b", 2)]]
    def complete(seed):
        return _fake_result(seed, deepcopy(seed), [])
    r = resolve_parallel_routes(root, routes, complete_fn=complete, max_routes=8)
    assert r.status == "RETURN_PROOF_DIVERGENT"
    assert r.patches == []
    assert r.proof["checks"]["exact_terminal_equivalence"] is False


def test_return_proof_requires_every_route_to_reach_strong_closure():
    root = {"x": 0}
    routes = [[_candidate("a", 1)], [_candidate("b", 2)]]
    def complete(seed):
        final = {"x": 9}
        value, res = _fake_result(seed, final, [{"candidate_id":"z","analyzer":"closure","operation":"replace","path":"/x","old_value":seed["x"],"new_value":9,"reason":"z","confidence":1.0,"cost":1,"evidence":[],"metadata":{}}])
        if seed["x"] == 2:
            res.report["strong_fixed_point"]["attained"] = False
        return value, res
    r = resolve_parallel_routes(root, routes, complete_fn=complete, max_routes=8)
    assert not r.proof["ok"]
    assert not r.proof["checks"]["all_routes_closed"]


def test_parallel_frontier_is_bounded_before_clone_execution():
    routes = [[_candidate(str(i), i + 1)] for i in range(5)]
    called = 0
    def complete(seed):
        nonlocal called
        called += 1
        return _fake_result(seed, seed, [])
    r = resolve_parallel_routes({"x": 0}, routes, complete_fn=complete, max_routes=4)
    assert r.status == "PARALLEL_ROUTE_FRONTIER_TOO_LARGE"
    assert called == 0


def test_route_selection_is_deterministic_after_equivalence_not_before():
    root = {"x": 0}
    routes = [[_candidate("b", 2)], [_candidate("a", 1)]]
    def complete(seed):
        old=seed["x"]
        cont=[{"candidate_id":f"c{old}","analyzer":"closure","operation":"replace","path":"/x","old_value":old,"new_value":9,"reason":"return","confidence":1.0,"cost":1,"evidence":[],"metadata":{}}]
        return _fake_result(seed, {"x":9}, cont)
    r1=resolve_parallel_routes(root,routes,complete_fn=complete,max_routes=8)
    r2=resolve_parallel_routes(root,list(reversed(routes)),complete_fn=complete,max_routes=8)
    assert r1.proof["selected_route_id"] == r2.proof["selected_route_id"]
    assert r1.proof["proof_sha256"] == r2.proof["proof_sha256"]


def test_normal_engine_exposes_pass026_parallel_contract_without_regression():
    schema={"type":"object","properties":{"x":{"minimum":0}}}
    out,res=repair_object({"x":-1},RepairConfig(json_schema=schema,max_cycles=5))
    assert out=={"x":0}
    p=res.report["parallel_exact_minimum_routes"]
    assert p["contract"]=="json-consistency-repair.parallel-exact-routes.v1"
    assert p["return_proof_contract"]=="json-consistency-repair.return-proof.v1"


def test_bundle_return_proof_reconverges_tied_cross_routes_through_authoritative_schema():
    from json_consistency_repair.bundle import BundleCandidate, _bundle_return_proof, bundle_digest, apply_bundle_patch_set
    schema={"type":"object","properties":{"x":{"const":9}}}
    cfg=RepairConfig(json_schema=schema,max_cycles=5,enable_final_certification=False)
    a=BundleCandidate("a.json",Candidate("ra","synthetic","replace","/x",0,1,"route a",1.0,1,("A",),{}))
    b=BundleCandidate("a.json",Candidate("rb","synthetic","replace","/x",0,2,"route b",1.0,1,("B",),{}))
    chain,proof=_bundle_return_proof({"a.json":{"x":0}},[[a],[b]],cfg)
    assert proof["ok"] is True
    assert proof["status"]=="RETURN_PROOF_EQUIVALENT"
    final=apply_bundle_patch_set({"a.json":{"x":0}},chain)
    assert final=={"a.json":{"x":9}}
    assert bundle_digest(final)==proof["terminal_digest"]


def test_streaming_record_return_proof_reconverges_through_record_bridge():
    from json_consistency_repair.streaming import StreamingConfig, _resolve_stream_parallel_record
    cfg=StreamingConfig(json_schema={"type":"object","properties":{"x":{"const":9}}},exact_disk_registry=True,max_cycles=4,enable_final_certification=False)
    routes=[
        [{"analyzer":"synthetic","path":"/x","old_value":0,"new_value":1,"confidence":1.0,"reason":"a","evidence":[]}],
        [{"analyzer":"synthetic","path":"/x","old_value":0,"new_value":2,"confidence":1.0,"reason":"b","evidence":[]}],
    ]
    final,proof=_resolve_stream_parallel_record({"x":0},routes,{},cfg)
    assert proof["ok"] is True
    assert final=={"x":9}
