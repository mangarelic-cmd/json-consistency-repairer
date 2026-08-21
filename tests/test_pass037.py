from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import json

from json_consistency_repair import (
    RepairConfig, repair_object, repair_bundle,
    apply_relation_falsification_firewall, verify_relation_falsification_certificate,
)
from json_consistency_repair.analyzers import analyze_all
from json_consistency_repair.models import AnalysisResult, Candidate
from json_consistency_repair.streaming import StreamingConfig, repair_stream_file
from json_consistency_repair.certifier import verify_report_evidence


def _cfg(**kw):
    base=dict(min_support=4,min_group_support=2,relation_confidence=.80,max_cycles=5,strong_fixed_point_cycles_required=1,enable_multisource=False)
    base.update(kw)
    return RepairConfig(**base)


def test_pass037_nontrivial_functional_relation_survives_active_controls_and_repairs():
    data={"rows":[
        {"k":"A","v":"alpha"},{"k":"A","v":"alpha"},{"k":"A","v":"alpha"},
        {"k":"B","v":"beta"},{"k":"B","v":"beta"},{"k":"B"},
    ]}
    out,res=repair_object(data,_cfg())
    assert out["rows"][5]["v"]=="beta"
    states=res.report["relation_falsification"]["final"]["states"]
    assert states.get("ADVERSARIAL_SURVIVED",0)>=1
    assert res.report["final_certification"]["checks"]["relation_falsification"] is True


def test_pass037_constant_target_dependency_is_negative_control_invariant_and_cannot_fill_missing():
    data={"rows":[
        {"k":"A","v":"same"},{"k":"A","v":"same"},
        {"k":"B","v":"same"},{"k":"B","v":"same"},
        {"k":"A"},
    ]}
    out,res=repair_object(data,_cfg())
    assert "v" not in out["rows"][4]
    final=res.report["relation_falsification"]["final"]
    assert final["states"].get("NEGATIVE_CONTROL_INVARIANT",0)>=1
    assert final["blocked_relation_count"]>=1
    assert final["blocked_candidate_count"]>=1
    assert any(i["code"]=="RELATION_FALSIFICATION_GATE" for i in res.report["remaining_issues"])


def test_pass037_split_fold_mapping_conflict_is_active_refutation():
    # Fold 0 says A->X, fold 1 says A->Y, while the pooled mode still clears 0.70.
    rows=[
        {"k":"A","v":"X"}, # 0
        {"k":"A","v":"Y"}, # 1
        {"k":"A","v":"X"}, # 2
        {"k":"A","v":"Y"}, # 3
        {"k":"A","v":"X"}, # 4
        {"k":"B","v":"Z"}, # 5
        {"k":"B","v":"Z"}, # 6
        {"k":"B","v":"Z"}, # 7
        {"k":"B","v":"Z"}, # 8
    ]
    cfg=_cfg(relation_confidence=.70,min_group_support=2,enable_final_certification=False)
    raw=analyze_all({"rows":rows},cfg)
    filtered,cert=apply_relation_falsification_firewall({"rows":rows},raw,cfg)
    assert cert["states"].get("ACTIVE_REFUTED",0)>=1
    assert cert["blocked_relation_count"]>=1
    assert verify_relation_falsification_certificate(cert)
    assert all(r.get("falsification_state")!="ACTIVE_REFUTED" for r in filtered.relations)


def test_pass037_authoritative_contract_is_recorded_not_empirically_falsified():
    cfg=_cfg(json_schema={"type":"object","properties":{"x":{"const":2}}},enable_final_certification=False)
    raw=analyze_all({"x":1},cfg)
    _,cert=apply_relation_falsification_firewall({"x":1},raw,cfg)
    states={r["kind"]:r["state"] for r in cert["relations"]}
    assert states["authoritative_json_schema"]=="AUTHORITATIVE_CONTRACT"


def test_pass037_independent_global_refutation_gates_relation_backed_candidate():
    rel={"relation_id":"r1","kind":"cross_source_functional","array_path":"","inputs":["k"],"output":"v","validation_state":"GLOBAL_REFUTED","counterexample_count":1}
    c=Candidate("c1","multisource_lifecycle","replace","/v","bad","good","test",1.0,1,(),{"relation_id":"r1","relation_kind":"cross_source_functional"})
    a=AnalysisResult([], [c], [rel])
    out,cert=apply_relation_falsification_firewall({"v":"bad"},a,_cfg(enable_final_certification=False))
    assert not out.candidates and not out.relations
    assert cert["blocked_candidate_ids"]==["c1"]


def test_pass037_tampered_certificate_is_rejected():
    data={"rows":[{"k":"A","v":1},{"k":"A","v":1},{"k":"B","v":2},{"k":"B","v":2}]}
    a=analyze_all(data,_cfg(enable_final_certification=False))
    _,cert=apply_relation_falsification_firewall(data,a,_cfg(enable_final_certification=False))
    assert verify_relation_falsification_certificate(cert)
    bad=deepcopy(cert); bad["states"]["ADVERSARIAL_SURVIVED"]=999
    assert not verify_relation_falsification_certificate(bad)


def test_pass037_surface_is_bound_into_proof_graph_packet_and_independent_certifier():
    data={"rows":[{"k":"A","v":1},{"k":"A","v":1},{"k":"B","v":2},{"k":"B","v":2},{"k":"B"}]}
    out,res=repair_object(data,_cfg())
    assert out["rows"][4]["v"]==2
    assert "RELATION_FALSIFICATION" in res.report["proof_graph"]["section_roots"]
    surfaces={x["logical_name"]:x for x in res.report["rectification_packet"]["surfaces"]}
    assert surfaces["relation_falsification"]["state"]=="PRESENT"
    assert verify_report_evidence(res.report)["checks"]["relation_falsification"]
    assert res.report["fifth_series_progress"]["completed_substantive_passes"]>=5


def test_pass037_bundle_exposes_document_falsification_and_certifies():
    docs={
        "a.json":{"rows":[{"k":"A","v":1},{"k":"A","v":1},{"k":"B","v":2},{"k":"B","v":2},{"k":"B"}]},
        "b.json":{"x":1},
    }
    out,res=repair_bundle(docs,_cfg())
    assert out["a.json"]["rows"][4]["v"]==2
    rf=res.report["relation_falsification"]
    assert rf["mode"]=="bundle" and "a.json" in rf["documents"]
    assert res.report["final_certification"]["status"]=="CERTIFIED"
    assert res.report["final_certification"]["checks"]["relation_falsification"]


def _write_jsonl(path:Path, rows):
    path.write_text("\n".join(json.dumps(x,separators=(",",":")) for x in rows)+"\n",encoding="utf-8")


def _read_jsonl(path:Path):
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def test_pass037_stream_native_constant_dependency_is_blocked(tmp_path:Path):
    rows=[{"k":"A","v":"same"},{"k":"A","v":"same"},{"k":"B","v":"same"},{"k":"B","v":"same"},{"k":"A"}]
    src=tmp_path/"in.jsonl"; out=tmp_path/"out.jsonl"; _write_jsonl(src,rows)
    cfg=StreamingConfig(min_support=4,min_group_support=2,relation_confidence=.8,max_cycles=3,strong_fixed_point_cycles_required=1,exact_disk_registry=True)
    res=repair_stream_file(src,out,config=cfg,stream_format="jsonl")
    assert "v" not in _read_jsonl(out)[4]
    rf=res.report["relation_falsification"]["final"]
    assert rf["states"].get("NEGATIVE_CONTROL_INVARIANT",0)>=1
    assert res.report["final_certification"]["checks"]["relation_falsification"]


def test_pass037_stream_native_nontrivial_dependency_survives_and_repairs(tmp_path:Path):
    rows=[{"k":"A","v":"alpha"},{"k":"A","v":"alpha"},{"k":"A","v":"alpha"},{"k":"B","v":"beta"},{"k":"B","v":"beta"},{"k":"B"}]
    src=tmp_path/"in.jsonl"; out=tmp_path/"out.jsonl"; _write_jsonl(src,rows)
    cfg=StreamingConfig(min_support=4,min_group_support=2,relation_confidence=.8,max_cycles=4,strong_fixed_point_cycles_required=1,exact_disk_registry=True)
    res=repair_stream_file(src,out,config=cfg,stream_format="jsonl")
    assert _read_jsonl(out)[5]["v"]=="beta"
    assert res.report["relation_falsification"]["final"]["states"].get("ADVERSARIAL_SURVIVED",0)>=1
    assert res.report["final_certification"]["status"]=="CERTIFIED"


def test_pass037_public_schemas_are_draft202012_valid():
    from jsonschema import Draft202012Validator
    base=Path(__file__).resolve().parents[1]/"schemas"
    for name in ("relation-falsification-v1.schema.json","relation-falsification-summary-v1.schema.json"):
        Draft202012Validator.check_schema(json.loads((base/name).read_text(encoding="utf-8")))
