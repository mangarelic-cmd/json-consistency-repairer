from __future__ import annotations
from copy import deepcopy
from pathlib import Path
import json

from json_consistency_repair import (
    RepairConfig, repair_object, repair_bundle,
    compile_horizon_snapshot, verify_horizon_snapshot,
    compare_horizon_naturality, verify_horizon_naturality_certificate,
    compile_distributed_consistency, verify_distributed_consistency_certificate,
)
from json_consistency_repair.streaming import StreamingConfig, repair_stream_file


def _report(inp, out, relations=None, mode="single"):
    from json_consistency_repair.models import digest
    return {"mode":mode,"input_digest":digest(inp),"output_digest":digest(out),"relations":relations or [],"remaining_issues":[]}


def test_pass039_snapshot_is_hash_bound_and_tamper_detected():
    value={"a":1,"b":{"x":2}}
    snap=compile_horizon_snapshot(_report(value,value),value,value)
    assert verify_horizon_snapshot(snap)
    bad=deepcopy(snap); bad["output_manifest"][0]["sha256"]="0"*64
    assert not verify_horizon_snapshot(bad)


def test_pass039_pure_horizon_extension_preserves_closed_old_paths():
    old={"rows":[{"a":1,"b":2}]}; new={"rows":[{"a":1,"b":2},{"a":2,"b":4}]}
    s1=compile_horizon_snapshot(_report(old,old),old,old)
    s2=compile_horizon_snapshot(_report(new,new),new,new)
    cert=compare_horizon_naturality(s1,s2)
    assert cert["status"]=="HORIZON_NATURAL" and cert["ok"]
    assert verify_horizon_naturality_certificate(cert,s2,s1)


def test_pass039_relation_crossing_identifies_exact_new_witness():
    old={"rows":[{"a":1,"b":2}]}; old_out=deepcopy(old)
    new={"rows":[{"a":1,"b":2},{"a":2,"b":4}]}; new_out={"rows":[{"a":1,"b":3},{"a":2,"b":4}]}
    rel={"relation_id":"r_ab","array_path":"/rows","inputs":["a"],"output":"b"}
    s1=compile_horizon_snapshot(_report(old,old_out,[rel]),old,old_out)
    s2=compile_horizon_snapshot(_report(new,new_out,[rel]),new,new_out)
    cert=compare_horizon_naturality(s1,s2)
    assert cert["status"]=="HORIZON_INVALIDATED_BY_WITNESS" and cert["ok"]
    assert any(w.get("relation_id")=="r_ab" and w.get("changed_path")=="/rows/1/a" for w in cert["boundary_witnesses"])


def test_pass039_unexplained_old_scope_drift_is_rejected():
    old={"x":1}; new={"x":1,"y":2}; new_out={"x":9,"y":2}
    s1=compile_horizon_snapshot(_report(old,old),old,old)
    s2=compile_horizon_snapshot(_report(new,new_out),new,new_out)
    cert=compare_horizon_naturality(s1,s2)
    assert cert["status"]=="HORIZON_DRIFT_UNEXPLAINED"
    assert cert["full_recompute_required"] and not cert["ok"]


def test_pass039_explicit_authority_witness_can_break_horizon():
    old={"x":1}; new={"x":1,"authority":{"x":2}}; new_out={"x":2,"authority":{"x":2}}
    s1=compile_horizon_snapshot(_report(old,old),old,old)
    s2=compile_horizon_snapshot(_report(new,new_out),new,new_out)
    cert=compare_horizon_naturality(s1,s2,change_tokens=["authority:/x"],boundary_witnesses=[{"target":"/x","token":"authority:/x","origin":"verified_contract"}])
    assert cert["status"]=="HORIZON_INVALIDATED_BY_WITNESS" and cert["ok"]


def test_pass039_same_input_repartition_same_terminal_is_distributed_consistent():
    v={"x":1}
    s1=compile_horizon_snapshot(_report(v,v),v,v,distribution={"shards":1})
    s2=compile_horizon_snapshot(_report(v,v),v,v,distribution={"shards":8})
    cert=compile_distributed_consistency([s1,s2])
    assert cert["status"]=="DISTRIBUTED_CONSISTENT" and cert["ok"]
    assert verify_distributed_consistency_certificate(cert,[s1,s2])


def test_pass039_same_input_different_terminal_is_distributed_conflict():
    v={"x":1}; out2={"x":2}
    s1=compile_horizon_snapshot(_report(v,v),v,v,distribution={"shards":1})
    s2=compile_horizon_snapshot(_report(v,out2),v,out2,distribution={"shards":8})
    cert=compile_distributed_consistency([s1,s2])
    assert cert["status"]=="DISTRIBUTED_CONFLICT" and not cert["ok"] and cert["conflict_count"]>=1


def test_pass039_incomplete_stream_horizon_falls_back_on_changed_terminal():
    a={"mode":"streaming","input_digest":"a"*64,"output_digest":"b"*64}
    b={"mode":"streaming","input_digest":"c"*64,"output_digest":"d"*64}
    s1=compile_horizon_snapshot(a,None,None)
    s2=compile_horizon_snapshot(b,None,None)
    cert=compare_horizon_naturality(s1,s2)
    assert cert["status"]=="FULL_RECOMPUTE_REQUIRED" and not cert["ok"]


def test_pass039_single_engine_emits_certified_surfaces():
    out,res=repair_object({"x":1},RepairConfig(max_cycles=3,strong_fixed_point_cycles_required=1,enable_multisource=False))
    assert out=={"x":1}
    h=res.report["horizon_naturality"]
    assert h["comparison"]["status"]=="BASELINE_REGISTERED"
    assert res.report["distributed_consistency"]["status"]=="DISTRIBUTED_BASELINE"
    assert res.report["final_certification"]["checks"]["horizon_distributed"] is True
    assert res.report["fifth_series_progress"]["completed_substantive_passes"]>=7


def test_pass039_engine_prior_horizon_same_document_is_exact():
    cfg=RepairConfig(max_cycles=3,strong_fixed_point_cycles_required=1,enable_multisource=False)
    _,r1=repair_object({"x":1},cfg)
    prior=r1.report["horizon_naturality"]["snapshot"]
    _,r2=repair_object({"x":1},RepairConfig(max_cycles=3,strong_fixed_point_cycles_required=1,enable_multisource=False,prior_horizon_snapshot=prior,distribution_descriptor={"workers":4}))
    assert r2.report["horizon_naturality"]["comparison"]["status"]=="HORIZON_NATURAL"
    assert r2.report["distributed_consistency"]["status"]=="DISTRIBUTED_CONSISTENT"
    assert r2.report["final_certification"]["ok"]


def test_pass039_bundle_exposes_certified_horizon_surface():
    docs={"a.json":{"x":1},"b.json":{"y":2}}
    out,res=repair_bundle(docs,RepairConfig(max_cycles=3,strong_fixed_point_cycles_required=1,enable_multisource=False))
    assert out==docs
    assert verify_horizon_snapshot(res.report["horizon_naturality"]["snapshot"])
    assert res.report["final_certification"]["checks"]["horizon_distributed"] is True


def test_pass039_streaming_exposes_digest_naturality_surface(tmp_path:Path):
    src=tmp_path/"in.jsonl"; out=tmp_path/"out.jsonl"
    src.write_text('{"x":1}\n{"x":1}\n',encoding="utf-8")
    res=repair_stream_file(src,out,config=StreamingConfig(max_cycles=3,strong_fixed_point_cycles_required=1,exact_disk_registry=True),stream_format="jsonl")
    h=res.report["horizon_naturality"]
    assert verify_horizon_snapshot(h["snapshot"])
    assert h["comparison"]["status"]=="BASELINE_REGISTERED"
    assert res.report["final_certification"]["checks"]["horizon_distributed"] is True


def test_pass039_rectification_packet_and_proof_graph_bind_surfaces():
    _,res=repair_object({"x":1},RepairConfig(max_cycles=3,strong_fixed_point_cycles_required=1,enable_multisource=False))
    surfaces={x["logical_name"]:x for x in res.report["rectification_packet"]["surfaces"]}
    assert surfaces["horizon_naturality"]["state"]=="PRESENT"
    assert surfaces["distributed_consistency"]["state"]=="PRESENT"
    kinds={n.get("kind") for n in res.report["proof_graph"]["nodes"]}
    assert "HORIZON_NATURALITY" in kinds and "DISTRIBUTED_CONSISTENCY" in kinds


def test_pass039_public_schemas_are_draft202012_valid():
    from jsonschema import Draft202012Validator
    base=Path(__file__).resolve().parents[1]/"schemas"
    for name in ("horizon-snapshot-v1.schema.json","horizon-naturality-v1.schema.json","distributed-consistency-v1.schema.json"):
        Draft202012Validator.check_schema(json.loads((base/name).read_text(encoding="utf-8")))
