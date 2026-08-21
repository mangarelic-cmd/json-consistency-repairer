from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace
import json

from json_consistency_repair import (
    RepairConfig, StreamingConfig, repair_object, repair_bundle, repair_stream_file, parse_dsl,
    compile_semantic_quotient, semantic_quotient_normal_form, semantic_quotient_digest,
    compare_modulo_semantic_quotient, compile_symmetry_obstruction,
    verify_semantic_quotient_certificate, verify_symmetry_certificate,
)
from json_consistency_repair.models import Candidate, Issue, AnalysisResult
from json_consistency_repair.minimal_transfer import solve_minimal_transfer
from json_consistency_repair.parallel_routes import resolve_parallel_routes


def c(cid, path, old=7, new=8):
    return Candidate(cid, "test", "replace", path, old, new, "one indistinguishable member must change", 1.0, 1, (), {})


def tied_fixture():
    root={"rows":[{"x":7},{"x":7}]}
    issue=Issue("test","SUM_MISMATCH","/rows","exactly one x must become 8","error",True,{})
    rel={"relation_id":"global_rows_choice","kind":"global_choice","scope":"","inputs":["rows"],"output":"rows"}
    analysis=AnalysisResult([issue],[c("r0","/rows/0/x"),c("r1","/rows/1/x")],[rel])
    def analyze(x):
        vals=[r["x"] for r in x["rows"]]
        return AnalysisResult([] if sorted(vals)==[7,8] else [issue],[],[])
    return root,analysis,analyze


def test_pass035_semantic_quotient_is_explicit_and_idempotent():
    a={"rows":[{"x":1},{"x":2}]}
    b={"rows":[{"x":2},{"x":1}]}
    assert compare_modulo_semantic_quotient(a,b,())["semantic_quotient_equivalent"] is False
    rules=({"path":"/rows","equivalence":"unordered_array"},)
    cmp=compare_modulo_semantic_quotient(a,b,rules)
    assert cmp["semantic_quotient_equivalent"] and cmp["quotient_used"]
    cert=compile_semantic_quotient(a,rules)
    assert cert["idempotent"] and verify_semantic_quotient_certificate(cert)
    nf=semantic_quotient_normal_form(a,rules)
    assert semantic_quotient_normal_form(nf,rules)==nf


def test_pass035_unordered_array_preserves_multiplicity():
    rules=({"path":"/x","equivalence":"unordered_array"},)
    a={"x":[1,1,2]}; b={"x":[1,2]}
    assert semantic_quotient_digest(a,rules)!=semantic_quotient_digest(b,rules)


def test_pass035_unique_set_quotient_requires_explicit_duplicate_semantics():
    a={"x":[1,1,2]}; b={"x":[2,1]}
    unsafe=({"path":"/x","equivalence":"unordered_unique_array"},)
    assert semantic_quotient_digest(a,unsafe)!=semantic_quotient_digest(b,unsafe)
    safe=({"path":"/x","equivalence":"unordered_unique_array","duplicates_are_semantically_irrelevant":True},)
    assert semantic_quotient_digest(a,safe)==semantic_quotient_digest(b,safe)


def test_pass035_detects_symmetry_obstruction_and_minimal_breaker():
    root={"rows":[{"x":7},{"x":7}]}
    cert=compile_symmetry_obstruction(root,[[c("a","/rows/0/x")],[c("b","/rows/1/x")]])
    assert cert["status"]=="SYMMETRY_BLOCKED_REPAIR"
    assert cert["blocked"] is True
    assert cert["minimal_symmetry_breakers"][0]["orbit_indices"]==[0,1]
    assert cert["minimal_symmetry_breakers"][0]["minimum_selector_bits_lower_bound"]==1
    assert verify_symmetry_certificate(cert)


def test_pass035_distinguishable_records_are_not_declared_symmetric():
    root={"rows":[{"id":"A","x":7},{"id":"B","x":7}]}
    cert=compile_symmetry_obstruction(root,[[c("a","/rows/0/x")],[c("b","/rows/1/x")]])
    assert cert["status"]=="NO_SYMMETRY_OBSTRUCTION"
    assert cert["blocked"] is False


def test_pass035_solver_stops_at_symmetry_instead_of_spawning_routes():
    root,analysis,analyze=tied_fixture()
    d=solve_minimal_transfer(root,analysis,analyze_fn=analyze,score_fn=lambda xs:len(xs)*10,
        max_patch_size=2,max_exact_options=8,enable_parallel_routes=True,max_parallel_routes=8)
    assert d.status=="SYMMETRY_BLOCKED_REPAIR"
    assert d.patches==[] and d.parallel_routes==[]
    assert d.certificate["symmetry_obstruction"]["status"]=="SYMMETRY_BLOCKED_REPAIR"


def test_pass035_explicit_quotient_allows_tied_routes_to_continue():
    root,analysis,analyze=tied_fixture()
    rules=({"path":"/rows","equivalence":"unordered_array"},)
    d=solve_minimal_transfer(root,analysis,analyze_fn=analyze,score_fn=lambda xs:len(xs)*10,
        max_patch_size=2,max_exact_options=8,enable_parallel_routes=True,max_parallel_routes=8,
        semantic_quotient_rules=rules)
    assert d.status=="AMBIGUOUS_EXACT_MINIMUM"
    assert len(d.parallel_routes)==2
    assert d.certificate["symmetry_obstruction"]["status"]=="QUOTIENT_CANONICALLY_EQUIVALENT"


def test_pass035_return_proof_can_compare_modulo_explicit_quotient():
    root={"rows":[{"x":7},{"x":7}]}
    routes=[[c("a","/rows/0/x")],[c("b","/rows/1/x")]]
    rules=({"path":"/rows","equivalence":"unordered_array"},)
    def complete(seed):
        report={"remaining_issues":[],"relations":[],"dynamic_q_descent":{"final":{}},
                "strong_fixed_point":{"attained":True,"oscillation_detected":False},"cycles":[],"committed_edits":[]}
        return seed,SimpleNamespace(report=report,final_status="PASS",remaining_issues=0)
    r=resolve_parallel_routes(root,routes,complete_fn=complete,semantic_quotient_rules=rules)
    assert r.status=="RETURN_PROOF_QUOTIENT_EQUIVALENT" and r.proof["ok"]
    assert not r.proof["checks"]["exact_terminal_equivalence"]
    assert r.proof["checks"]["semantic_quotient_terminal_equivalence"]
    assert len(r.patches)==1


def test_pass035_tampered_certificate_fails_verifier():
    root={"rows":[{"x":7},{"x":7}]}
    cert=compile_symmetry_obstruction(root,[[c("a","/rows/0/x")],[c("b","/rows/1/x")]])
    bad=deepcopy(cert); bad["status"]="NO_SYMMETRY_OBSTRUCTION"
    assert not verify_symmetry_certificate(bad)


def test_pass035_report_surface_and_independent_certifier():
    value={"rows":[{"a":2,"b":3,"total":0}]}
    rule=parse_dsl("scope /rows\nexpr e: total = a + b")[0]
    out,res=repair_object(value,RepairConfig(constraint_rules=(rule,),min_support=99))
    assert out["rows"][0]["total"]==5
    sc=res.report["symmetry_canonicality"]
    assert sc["contract"]=="json-consistency-repair.symmetry-canonicality-summary.v1"
    assert sc["cycles"] and all(verify_symmetry_certificate(x["certificate"]) for x in sc["cycles"])
    assert res.report["final_certification"]["checks"]["symmetry_canonicality"] is True
    assert res.report["fifth_series_progress"]["completed_substantive_passes"]>=3
    assert res.report["fifth_series_progress"]["remaining_substantive_passes"]<=5
    assert "SYMMETRY_CANONICALITY" in res.report["proof_graph"]["section_roots"]


def test_pass035_false_external_quotient_attribution_is_gated():
    value={"rows":[{"a":1}]}
    q={"rule_id":"q_external","path":"/rows","equivalence":"unordered_array","source":"external-policy-v1"}
    _,res=repair_object(value,RepairConfig(semantic_quotient_rules=(q,),min_support=99))
    # PASS033 pre-analysis removes unverified external semantic claims before PASS035 can use them.
    assert res.report["symmetry_canonicality"]["rules"]==[]
    sem=res.report["semantic_claim_provenance"]["cycles"][0]["certificate"] or {}
    assert sem.get("gated_rule_count",0)>=1


def test_pass035_bundle_surface_certified():
    docs={"a.json":{"rows":[{"a":2,"b":3,"total":0}]},"b.json":{"rows":[{"a":1,"b":1,"total":2}]}}
    rule=parse_dsl("scope /rows\nexpr e: total = a + b")[0]
    out,res=repair_bundle(docs,RepairConfig(constraint_rules=(rule,),min_support=99))
    assert out["a.json"]["rows"][0]["total"]==5
    assert res.report["symmetry_canonicality"]["mode"]=="bundle"
    assert res.report["final_certification"]["checks"]["symmetry_canonicality"] is True
    assert res.report["fifth_series_progress"]["completed_substantive_passes"]>=3


def test_pass035_streaming_surface_certified(tmp_path):
    src=tmp_path/"in.jsonl"; dst=tmp_path/"out.jsonl"
    src.write_text(json.dumps({"a":2,"b":3,"total":0})+"\n",encoding="utf-8")
    rule=parse_dsl("scope /\nexpr e: total = a + b")[0]; rule["array_path"]=""
    cfg=StreamingConfig(constraint_rules=(rule,),exact_disk_registry=True,min_support=99,max_cycles=4,
                        semantic_quotient_rules=({"path":"/tags","equivalence":"unordered_array"},))
    res=repair_stream_file(src,dst,config=cfg,stream_format="jsonl")
    assert json.loads(dst.read_text(encoding="utf-8"))["total"]==5
    assert res.report["symmetry_canonicality"]["scope"]=="record_bridge_inherited"
    assert res.report["final_certification"]["checks"]["symmetry_canonicality"] is True
    assert res.report["fifth_series_progress"]["completed_substantive_passes"]>=3
