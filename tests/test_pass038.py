from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import json

from json_consistency_repair import (
    RepairConfig, repair_object, repair_bundle,
    compile_open_obligation_registry, verify_open_obligation_registry,
    save_open_obligation_registry, load_open_obligation_registry,
    wake_open_obligations, verify_wake_plan,
    compile_proof_dependency_index, verify_proof_dependency_index,
    compile_incremental_recompute, verify_incremental_recompute_certificate,
    compile_incremental_equivalence, verify_incremental_equivalence_certificate, change_tokens_from_json_diff,
)
from json_consistency_repair.streaming import StreamingConfig, repair_stream_file
from json_consistency_repair.certifier import verify_report_evidence


def _issue_report(code="IDENTIFIABLE_BUT_UNREACHABLE", analyzer="controllability", path="/x"):
    return {
        "mode":"single", "output_digest":"0"*64,
        "remaining_issues":[{"analyzer":analyzer,"code":code,"path":path,"message":"open","repairable":True,"metadata":{}}],
    }


def test_pass038_compiles_typed_open_obligation_from_remaining_terminal():
    reg=compile_open_obligation_registry(_issue_report())
    assert verify_open_obligation_registry(reg)
    assert reg["status"]=="OPEN_OBLIGATIONS_PRESENT"
    assert reg["obligation_count"]==1
    assert reg["obligations"][0]["kind"]=="NEED_CONTROL_PERMISSION"
    assert "permission:*" in reg["obligations"][0]["wake_tokens"]


def test_pass038_quiescent_registry_is_explicit_not_absence():
    reg=compile_open_obligation_registry({"mode":"single","output_digest":"1"*64,"remaining_issues":[]})
    assert verify_open_obligation_registry(reg)
    assert reg["status"]=="QUIESCENT" and reg["obligation_count"]==0
    assert reg["semantics"]["open_is_not_absent"] is True


def test_pass038_registry_persistence_is_atomic_and_tamper_detected(tmp_path:Path):
    reg=compile_open_obligation_registry(_issue_report())
    path=tmp_path/"open.json"
    save_open_obligation_registry(path,reg)
    loaded=load_open_obligation_registry(path)
    assert loaded==reg
    bad=deepcopy(reg); bad["obligations"][0]["kind"]="NEED_SOURCE"
    path.write_text(json.dumps(bad),encoding="utf-8")
    try:
        load_open_obligation_registry(path)
    except ValueError:
        pass
    else:
        raise AssertionError("tampered registry accepted")


def test_pass038_targeted_wake_retains_unrelated_open_objects():
    report=_issue_report()
    report["remaining_issues"].append({"analyzer":"boundary","code":"BOUNDARY_CONFLICT","path":"/y","message":"open","repairable":False,"metadata":{}})
    reg=compile_open_obligation_registry(report)
    plan=wake_open_obligations(reg,["permission:/x"])
    assert verify_wake_plan(plan,reg)
    assert plan["woken_count"]==1 and plan["retained_count"]==1
    assert plan["woken"][0]["kind"]=="NEED_CONTROL_PERMISSION"


def test_pass038_json_diff_emits_precise_path_tokens():
    tokens=change_tokens_from_json_diff({"a":{"x":1},"b":2},{"a":{"x":3},"b":2})
    assert "path:/a/x" in tokens
    assert "path:/a/*" in tokens
    assert all("/b" not in t for t in tokens)


def test_pass038_dependency_index_is_conservative_for_opaque_nodes():
    pg={"graph_sha256":"a"*64,"nodes":[
        {"node_id":"n1","kind":"RELATION","payload":{"path":"/x","relation_id":"r1"}},
        {"node_id":"n2","kind":"OPAQUE","payload":{"foo":"bar"}},
    ]}
    idx=compile_proof_dependency_index(pg)
    assert verify_proof_dependency_index(idx)
    d={x["node_id"]:x["dependency_tokens"] for x in idx["nodes"]}
    assert "path:/x" in d["n1"]
    assert d["n2"]==["global:*"]


def test_pass038_incremental_obligation_transition_can_equal_full_recompute():
    prior=compile_open_obligation_registry(_issue_report())
    current=compile_open_obligation_registry({"mode":"single","output_digest":"1"*64,"remaining_issues":[]})
    cert=compile_incremental_recompute(current,prior_registry=prior,change_tokens=["permission:/x"])
    assert cert["status"]=="INCREMENTAL_EQ_FULL"
    assert cert["incremental_equivalence"] is True
    assert cert["wake_plan"]["woken_count"]==1
    assert verify_incremental_recompute_certificate(cert,current)


def test_pass038_unexplained_indirect_change_forces_full_recompute():
    report=_issue_report()
    report["remaining_issues"].append({"analyzer":"boundary","code":"BOUNDARY_CONFLICT","path":"/y","message":"open","repairable":False,"metadata":{}})
    prior=compile_open_obligation_registry(report)
    # Full fresh run says both obligations disappeared, but the supplied change only wakes /x.
    current=compile_open_obligation_registry({"mode":"single","output_digest":"2"*64,"remaining_issues":[]})
    cert=compile_incremental_recompute(current,prior_registry=prior,change_tokens=["permission:/x"])
    assert cert["status"]=="FULL_RECOMPUTE_REQUIRED"
    assert cert["incremental_equivalence"] is False
    assert verify_incremental_recompute_certificate(cert,current)




def test_pass038_incremental_proof_reuse_is_bound_to_full_replay():
    pg={"graph_sha256":"a"*64,"nodes":[{"node_id":"n1","kind":"RELATION","payload_sha256":"b"*64,"payload":{"path":"/x"}}]}
    inc={"retained_proof_nodes":["n1"]}
    replay={"ok":True}
    cert=compile_incremental_equivalence(inc,pg,replay,pg)
    assert cert["status"]=="INCREMENTAL_PROOF_EQ_FULL"
    assert cert["reused_node_count"]==1
    assert verify_incremental_equivalence_certificate(cert,pg,replay)

def test_pass038_single_report_is_proof_bound_and_independently_certified():
    out,res=repair_object({"x":1},RepairConfig(max_cycles=3,strong_fixed_point_cycles_required=1,enable_multisource=False))
    assert out=={"x":1}
    assert verify_open_obligation_registry(res.report["open_obligations"])
    assert res.report["incremental_recompute"]["status"]=="BASELINE_REGISTERED"
    assert res.report["final_certification"]["checks"]["persistent_open_incremental"] is True
    surfaces={x["logical_name"]:x for x in res.report["rectification_packet"]["surfaces"]}
    assert surfaces["open_obligations"]["state"]=="PRESENT"
    assert surfaces["incremental_recompute"]["state"]=="PRESENT"
    assert res.report["fifth_series_progress"]["completed_substantive_passes"]>=6


def test_pass038_engine_can_persist_certified_registry(tmp_path:Path):
    store=tmp_path/"obligations.json"
    cfg=RepairConfig(json_schema={"type":"object","properties":{"x":{"const":2}}},require_explicit_mutation_permission=True,
                     max_cycles=4,strong_fixed_point_cycles_required=1,enable_multisource=False,open_obligation_store_path=str(store))
    out,res=repair_object({"x":1},cfg)
    assert out=={"x":1}
    assert store.exists()
    assert load_open_obligation_registry(store)["registry_sha256"]==res.report["open_obligations"]["registry_sha256"]


def test_pass038_bundle_exposes_registry_and_certifies():
    out,res=repair_bundle({"a.json":{"x":1},"b.json":{"y":2}},RepairConfig(max_cycles=3,strong_fixed_point_cycles_required=1,enable_multisource=False))
    assert out["a.json"]["x"]==1
    assert verify_open_obligation_registry(res.report["open_obligations"])
    assert res.report["final_certification"]["checks"]["persistent_open_incremental"] is True
    assert res.report["fifth_series_progress"]["completed_substantive_passes"]>=6


def test_pass038_streaming_exposes_registry_and_certifies(tmp_path:Path):
    src=tmp_path/"in.jsonl"; out=tmp_path/"out.jsonl"
    src.write_text('{"x":1}\n{"x":1}\n',encoding="utf-8")
    cfg=StreamingConfig(max_cycles=3,strong_fixed_point_cycles_required=1,exact_disk_registry=True)
    res=repair_stream_file(src,out,config=cfg,stream_format="jsonl")
    assert verify_open_obligation_registry(res.report["open_obligations"])
    assert res.report["final_certification"]["checks"]["persistent_open_incremental"] is True
    assert res.report["fifth_series_progress"]["completed_substantive_passes"]>=6


def test_pass038_public_schemas_are_draft202012_valid():
    from jsonschema import Draft202012Validator
    base=Path(__file__).resolve().parents[1]/"schemas"
    for name in ("open-obligation-registry-v1.schema.json","open-obligation-wake-plan-v1.schema.json",
                 "proof-dependency-index-v1.schema.json","incremental-recompute-v1.schema.json","incremental-equivalence-v1.schema.json"):
        Draft202012Validator.check_schema(json.loads((base/name).read_text(encoding="utf-8")))
