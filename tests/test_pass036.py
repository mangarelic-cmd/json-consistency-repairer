from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import json

from json_consistency_repair import (
    RepairConfig, repair_object, repair_bundle,
    apply_controllability_firewall, compile_control_plan,
    verify_controllability_certificate,
)
from json_consistency_repair.models import AnalysisResult, Candidate
from json_consistency_repair.streaming import StreamingConfig, repair_stream_file
from json_consistency_repair.certifier import verify_report_evidence


def _schema_const_x(value=2):
    return {"type":"object","properties":{"x":{"const":value}}}


def _cand(cid:str,path:str,new,old=0,cost=1):
    return Candidate(cid,"test","replace",path,old,new,"pass036",1.0,cost,(),{})


def _cfg(*rules, **kw):
    base=dict(json_schema=_schema_const_x(),max_cycles=4,strong_fixed_point_cycles_required=1,
              controllability_rules=tuple(rules),enable_multisource=False)
    base.update(kw)
    return RepairConfig(**base)


def test_pass036_explicit_permission_produces_controllable_certified_repair():
    rule={"control_rule_id":"allow-x","path":"/x","allowed_operations":["replace"]}
    out,res=repair_object({"x":1},_cfg(rule))
    assert out=={"x":2}
    plans=res.report["repair_controllability"]["control_plan_cycles"]
    assert any((r["certificate"]["status"]=="CONTROLLABLE") for r in plans)
    assert res.report["final_certification"]["status"]=="CERTIFIED"
    assert res.report["final_certification"]["checks"]["repair_controllability"] is True
    assert res.report["fifth_series_progress"]["completed_substantive_passes"]>=4


def test_pass036_immutable_path_is_identifiable_but_unreachable_without_mutation():
    rule={"control_rule_id":"lock-x","path":"/x","immutable":True}
    out,res=repair_object({"x":1},_cfg(rule))
    assert out=={"x":1}
    fw=res.report["repair_controllability"]["final_firewall"]
    assert fw["status"]=="IDENTIFIABLE_BUT_UNREACHABLE"
    assert fw["blocked_candidate_count"]>=1
    assert res.report["final_certification"]["status"]=="CERTIFIED"


def test_pass036_explicit_permission_required_filters_uncovered_target():
    schema={"type":"object","properties":{"x":{"const":2},"y":{"const":2}}}
    rule={"control_rule_id":"allow-x","path":"/x","allowed_operations":["replace"]}
    cfg=RepairConfig(json_schema=schema,controllability_rules=(rule,),require_explicit_mutation_permission=True,
                     max_cycles=4,strong_fixed_point_cycles_required=1,enable_multisource=False)
    out,res=repair_object({"x":1,"y":1},cfg)
    assert out["x"]==2 and out["y"]==1
    assert any(i.get("code")=="IDENTIFIABLE_BUT_UNREACHABLE" and i.get("path")=="/y" for i in res.report["remaining_issues"])


def test_pass036_denied_operation_blocks_candidate():
    rule={"control_rule_id":"deny-replace","path":"/x","denied_operations":["replace"]}
    out,res=repair_object({"x":1},_cfg(rule))
    assert out=={"x":1}
    reasons=[r for x in res.report["repair_controllability"]["final_firewall"]["checks"] for a in x["actions"] for r in a["reasons"]]
    assert any(r.startswith("OPERATION_DENIED") for r in reasons)


def test_pass036_plan_substeps_are_individually_permission_checked():
    plan=Candidate("p","test","plan","",None,None,"atomic plan",1.0,1,(),{
        "steps":[{"operation":"replace","path":"/a"},{"operation":"replace","path":"/b"}]
    })
    analysis=AnalysisResult([], [plan], [])
    cfg=RepairConfig(controllability_rules=({"control_rule_id":"lock-b","path":"/b","immutable":True},),enable_final_certification=False)
    filtered,cert=apply_controllability_firewall({"a":0,"b":0},analysis,cfg)
    assert filtered.candidates==[]
    assert cert["blocked_candidate_count"]==1 and verify_controllability_certificate(cert)


def test_pass036_budget_is_cumulative_and_can_make_known_repair_unreachable():
    cfg=RepairConfig(max_control_edits=1,enable_final_certification=False)
    c=_cand("c","/x",2,1)
    ordered,cert=compile_control_plan({"x":1},[c],cfg,used_edits=1)
    assert ordered==[]
    assert cert["status"]=="IDENTIFIABLE_BUT_UNREACHABLE"
    assert cert["checks"]["budget_ok"] is False
    assert verify_controllability_certificate(cert)


def test_pass036_precedence_is_topologically_compiled():
    a=_cand("a","/a",1,0); b=_cand("b","/b",1,0)
    cfg=RepairConfig(controllability_rules=(
        {"control_rule_id":"a-first","path":"/a","allowed_operations":["replace"],"must_precede":["/b"]},
        {"control_rule_id":"b-ok","path":"/b","allowed_operations":["replace"]},
    ),enable_final_certification=False)
    ordered,cert=compile_control_plan({"a":0,"b":0},[b,a],cfg)
    assert [c.candidate_id for c in ordered]==["a","b"]
    assert cert["status"]=="CONTROLLABLE" and cert["checks"]["precedence_ok"]


def test_pass036_precedence_cycle_is_unreachable():
    a=_cand("a","/a",1,0); b=_cand("b","/b",1,0)
    cfg=RepairConfig(controllability_rules=(
        {"control_rule_id":"a-first","path":"/a","allowed_operations":["replace"],"must_precede":["/b"]},
        {"control_rule_id":"b-first","path":"/b","allowed_operations":["replace"],"must_precede":["/a"]},
    ),enable_final_certification=False)
    ordered,cert=compile_control_plan({"a":0,"b":0},[a,b],cfg)
    assert ordered==[] and cert["status"]=="IDENTIFIABLE_BUT_UNREACHABLE"
    assert cert["precedence_cycles"] and not cert["checks"]["precedence_ok"]


def test_pass036_tampered_control_certificate_fails_verification():
    cfg=RepairConfig(controllability_rules=({"control_rule_id":"allow","path":"/x","allowed_operations":["replace"]},),enable_final_certification=False)
    _,cert=compile_control_plan({"x":1},[_cand("c","/x",2,1)],cfg)
    bad=deepcopy(cert); bad["status"]="IDENTIFIABLE_BUT_UNREACHABLE"
    assert verify_controllability_certificate(cert)
    assert not verify_controllability_certificate(bad)


def test_pass036_unverified_external_control_policy_cannot_block_repair():
    fake={"control_rule_id":"external-lock","path":"/x","immutable":True,"source":"external-policy-v1"}
    out,res=repair_object({"x":1},_cfg(fake))
    assert out=={"x":2}
    sem=res.report["semantic_claim_provenance"]["final"]
    claim=next(c for c in sem["registry"]["claims"] if c["claim_id"]=="external-lock")
    assert claim["classification"]=="UNVERIFIED_ATTRIBUTION" and not claim["verified"]


def test_pass036_bundle_document_scope_locks_only_named_document():
    rule={"control_rule_id":"lock-a","path":"/x","document":"a.json","immutable":True}
    cfg=RepairConfig(json_schema=_schema_const_x(),controllability_rules=(rule,),max_cycles=4,strong_fixed_point_cycles_required=1,enable_multisource=False)
    out,res=repair_bundle({"a.json":{"x":1},"b.json":{"x":1}},cfg)
    assert out["a.json"]=={"x":1}
    assert out["b.json"]=={"x":2}
    assert res.report["final_certification"]["status"]=="CERTIFIED"
    assert res.report["final_certification"]["checks"]["repair_controllability"]


def test_pass036_streaming_scope_and_run_budget(tmp_path:Path):
    inp=tmp_path/"in.jsonl"; out=tmp_path/"out.jsonl"
    inp.write_text('{"x":1}\n{"x":1}\n',encoding="utf-8")
    rule={"control_rule_id":"stream-x","path":"/x","document":"@stream","allowed_operations":["replace"]}
    cfg=StreamingConfig(json_schema=_schema_const_x(),controllability_rules=(rule,),max_control_edits=1,
                        max_cycles=3,strong_fixed_point_cycles_required=1,exact_disk_registry=True)
    res=repair_stream_file(inp,out,config=cfg,stream_format="jsonl")
    rows=[json.loads(x) for x in out.read_text(encoding="utf-8").splitlines() if x.strip()]
    assert sum(r["x"]==2 for r in rows)==1
    assert sum(r["x"]==1 for r in rows)==1
    assert res.report["repair_controllability"]["run_budget"]["used_edits"]==1
    assert res.report["final_certification"]["status"]=="CERTIFIED"


def test_pass036_control_surface_is_bound_into_packet_and_proof_graph():
    report=repair_object({"x":1},_cfg({"control_rule_id":"allow","path":"/x","allowed_operations":["replace"]}))[1].report
    surfaces={x["logical_name"]:x for x in report["rectification_packet"]["surfaces"]}
    assert surfaces["repair_controllability"]["state"]=="PRESENT"
    assert "REPAIR_CONTROLLABILITY" in report["proof_graph"]["section_roots"]
    assert verify_report_evidence(report)["ok"]


def test_pass036_public_control_schemas_are_draft202012_valid():
    from jsonschema import Draft202012Validator
    base=Path(__file__).resolve().parents[1]/"schemas"
    for name in ("repair-controllability-rules-v1.schema.json","repair-controllability-v1.schema.json","controllability-firewall-v1.schema.json"):
        Draft202012Validator.check_schema(json.loads((base/name).read_text(encoding="utf-8")))
