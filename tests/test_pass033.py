from copy import deepcopy
from pathlib import Path

from json_consistency_repair import (
    RepairConfig, StreamingConfig, repair_object, repair_bundle, repair_stream_file,
    compile_semantic_claim_registry, verify_semantic_claim_registry,
    merkle_root, merkle_inclusion, verify_merkle_inclusion,
)
from json_consistency_repair.certifier import verify_report_evidence


def _src(value):
    return ({"source_id":"rules","role":"reference","value":value},)


def _const_rule(v=7, prov=None, rid="r1"):
    r={"kind":"const","array_path":"","field":"x","value":v,"rule_id":rid}
    if prov is not None: r["claim_provenance"]=prov
    return r


def _cfg(rule, source_value=None, **kw):
    return RepairConfig(constraint_rules=(rule,), source_context=_src(source_value if source_value is not None else {"rules":[]}),
                        enable_multisource=False, max_cycles=4, strong_fixed_point_cycles_required=1, **kw)


def test_pass033_json_merkle_inclusion_round_trip_and_tamper():
    doc={"a":{"b":[1,{"x":7}]},"z":3}
    p=merkle_inclusion(doc,"/a/b/1/x")
    assert p and p["fragment"]==7 and p["root_merkle_sha256"]==merkle_root(doc)
    assert verify_merkle_inclusion(p)
    bad=deepcopy(p); bad["fragment"]=8
    assert not verify_merkle_inclusion(bad)


def test_pass033_source_exact_rule_reproduces_claim_and_repairs():
    core=_const_rule(7)
    rule=_const_rule(7,{"classification":"SOURCE_EXACT","source_id":"rules","source_pointer":"/rules/0"})
    out,res=repair_object([{"x":0}],_cfg(rule,{"rules":[core]}))
    assert out==[{"x":7}]
    final=res.report["semantic_claim_provenance"]["final"]
    proof=next(x for x in final["registry"]["claims"] if x["claim_id"]=="r1")
    assert proof["classification"]=="SOURCE_EXACT" and proof["verified"]
    assert verify_semantic_claim_registry(final["registry"])


def test_pass033_false_source_attribution_is_gated_before_it_can_mutate():
    claimed=_const_rule(99,{"classification":"SOURCE_EXACT","source_id":"rules","source_pointer":"/rules/0"})
    actual=_const_rule(7)
    out,res=repair_object([{"x":0}],_cfg(claimed,{"rules":[actual]}))
    assert out==[{"x":0}]
    final=res.report["semantic_claim_provenance"]["final"]
    assert final["gated_rule_count"]==1
    assert final["registry"]["blocked_claim_count"]==1
    assert any(i["code"]=="semantic_attribution_gate" for i in res.report["remaining_issues"])


def test_pass033_unverified_numeric_boundary_cannot_poison_other_repairs():
    core={"kind":"minimum","array_path":"","field":"x","value":0,"rule_id":"b1"}
    bad={"kind":"minimum","array_path":"","field":"x","value":100,"rule_id":"b1",
         "claim_provenance":{"classification":"SOURCE_EXACT","source_id":"rules","source_pointer":"/rules/0"}}
    out,res=repair_object([{"x":50}],_cfg(bad,{"rules":[core]}))
    assert out==[{"x":50}]
    assert res.committed_edits==0


def test_pass033_derived_exact_template_rederives_rule_from_source_fact():
    template={"kind":"const","array_path":"","field":"x","value":{"$source":{"source_id":"rules","pointer":"/constants/x"}},"rule_id":"r2"}
    rule=_const_rule(7,{"classification":"DERIVED_EXACT","template":template},rid="r2")
    out,res=repair_object([{"x":1}],_cfg(rule,{"constants":{"x":7}}))
    assert out==[{"x":7}]
    proof=next(x for x in res.report["semantic_claim_provenance"]["final"]["registry"]["claims"] if x["claim_id"]=="r2")
    assert proof["classification"]=="DERIVED_EXACT" and proof["verified"]
    assert proof["source_inclusions"] and verify_merkle_inclusion(proof["source_inclusions"][0])


def test_pass033_bad_derived_template_cannot_authorize_rule():
    template={"kind":"const","array_path":"","field":"x","value":{"$source":{"source_id":"rules","pointer":"/constants/x"}},"rule_id":"r2"}
    rule=_const_rule(8,{"classification":"DERIVED_EXACT","template":template},rid="r2")
    out,res=repair_object([{"x":1}],_cfg(rule,{"constants":{"x":7}}))
    assert out==[{"x":1}]
    assert res.report["semantic_claim_provenance"]["final"]["status"]=="GATED_UNVERIFIED_ATTRIBUTION"


def test_pass033_user_declared_rule_is_valid_but_not_mislabeled_source_exact():
    rule=_const_rule(5,{"classification":"USER_DECLARED"},rid="u1")
    out,res=repair_object([{"x":0}],_cfg(rule,{"anything":1}))
    assert out==[{"x":5}]
    proof=next(x for x in res.report["semantic_claim_provenance"]["final"]["registry"]["claims"] if x["claim_id"]=="u1")
    assert proof["classification"]=="USER_DECLARED" and proof["verified"] and not proof["source_inclusions"]


def test_pass033_user_declared_with_fake_external_attribution_is_rejected():
    rule=_const_rule(5,{"classification":"USER_DECLARED","source_id":"rules","source_pointer":"/x"},rid="u2")
    out,res=repair_object([{"x":0}],_cfg(rule,{"x":5}))
    assert out==[{"x":0}]
    proof=next(x for x in res.report["semantic_claim_provenance"]["final"]["registry"]["claims"] if x["claim_id"]=="u2")
    assert proof["classification"]=="UNVERIFIED_ATTRIBUTION" and not proof["verified"]


def test_pass033_provenance_claim_without_stable_rule_id_is_disabled():
    rule={"kind":"const","array_path":"","field":"x","value":5,
          "claim_provenance":{"classification":"SOURCE_EXACT","source_id":"rules","source_pointer":"/r"}}
    out,res=repair_object([{"x":0}],_cfg(rule,{"r":{"kind":"const","array_path":"","field":"x","value":5}}))
    assert out==[{"x":0}]
    assert res.report["semantic_claim_provenance"]["final"]["gated_rule_count"]==1


def test_pass033_schema_can_be_source_exact_via_manifest_claim():
    schema={"type":"object","properties":{"kind":{"const":"ok"}}}
    ctx=({"source_id":"rules","role":"reference","value":{"schemas":{"main":schema}}},)
    manifest={"claim_provenance":[{"claim_id":"__json_schema__","classification":"SOURCE_EXACT","source_id":"rules","source_pointer":"/schemas/main"}]}
    out,res=repair_object({"kind":"bad"},RepairConfig(json_schema=schema,source_context=ctx,source_manifest=manifest,enable_multisource=False,max_cycles=4,strong_fixed_point_cycles_required=1))
    assert out=={"kind":"ok"}
    proof=next(x for x in res.report["semantic_claim_provenance"]["final"]["registry"]["claims"] if x["claim_id"]=="__json_schema__")
    assert proof["verified"] and proof["classification"]=="SOURCE_EXACT"


def test_pass033_semantic_provenance_is_bound_into_packet_and_proof_graph():
    report=repair_object({"x":1},RepairConfig(max_cycles=3,strong_fixed_point_cycles_required=1))[1].report
    surfaces={x["logical_name"]:x for x in report["rectification_packet"]["surfaces"]}
    assert surfaces["semantic_claim_provenance"]["state"]=="PRESENT"
    assert "SEMANTIC_CLAIM_PROVENANCE_FINAL" in report["proof_graph"]["section_roots"]
    assert report["final_certification"]["checks"]["semantic_claim_provenance"]


def test_pass033_tampered_claim_proof_breaks_external_certification():
    report=repair_object({"x":1},RepairConfig(max_cycles=3,strong_fixed_point_cycles_required=1))[1].report
    bad=deepcopy(report)
    bad["semantic_claim_provenance"]["final"]["registry"]["registry_sha256"]="0"*64
    assert not verify_report_evidence(bad)["ok"]


def test_pass033_bundle_applies_source_exact_rule_document_locally():
    core=_const_rule(7)
    rule=_const_rule(7,{"classification":"SOURCE_EXACT","source_id":"rules","source_pointer":"/rules/0"})
    cfg=_cfg(rule,{"rules":[core]},enable_final_certification=False)
    out,res=repair_bundle({"a.json":[{"x":0}],"b.json":{"y":2}},cfg)
    assert out["a.json"]==[{"x":7}]
    assert res.report["semantic_claim_provenance"]["documents"]["a.json"]["final"]["registry"]["verified_claim_count"]>=1


def test_pass033_streaming_source_exact_rule_is_enforced(tmp_path: Path):
    core=_const_rule(7)
    rule=_const_rule(7,{"classification":"SOURCE_EXACT","source_id":"rules","source_pointer":"/rules/0"})
    inp=tmp_path/'in.jsonl'; out=tmp_path/'out.jsonl'
    inp.write_text('{"x":0}\n',encoding='utf-8')
    cfg=StreamingConfig(constraint_rules=(rule,),source_context=_src({"rules":[core]}),source_manifest={},max_cycles=3,strong_fixed_point_cycles_required=1,exact_disk_registry=True,enable_final_certification=False)
    res=repair_stream_file(inp,out,config=cfg,stream_format='jsonl')
    assert out.read_text(encoding='utf-8').strip()=='{"x":7}'
    assert res.report["semantic_claim_provenance"]["final"]["registry"]["verified_claim_count"]>=1

def test_pass033_implicit_external_source_label_without_proof_is_gated():
    rule = {"rule_id":"fake-source-label","kind":"const","array_path":"","path":"/x","value":9,"source":"external-policy-v1"}
    obj = [{"x":0}]
    out,res = repair_object(obj, RepairConfig(constraint_rules=(rule,), max_cycles=3))
    assert out == obj
    sem = res.report['semantic_claim_provenance']['final']
    assert sem['status'] == 'GATED_UNVERIFIED_ATTRIBUTION'
    claim = next(x for x in sem['registry']['claims'] if x['claim_id']=='fake-source-label')
    assert claim['classification']=='UNVERIFIED_ATTRIBUTION' and not claim['verified']

def test_pass033_public_semantic_schemas_are_draft202012_valid():
    import json
    from jsonschema import Draft202012Validator
    base=Path(__file__).resolve().parents[1]/'schemas'
    names=[
        'semantic-claim-provenance-v1.schema.json','semantic-claim-proof-v1.schema.json',
        'json-merkle-inclusion-v1.schema.json','semantic-claim-provenance-firewall-v1.schema.json',
        'fifth-series-progress-v1.schema.json','source-manifest-v1.schema.json',
    ]
    for name in names:
        Draft202012Validator.check_schema(json.loads((base/name).read_text(encoding='utf-8')))


def test_pass033_historical_progress_projection_remains_open_at_pass033():
    report=repair_object({'x':1},RepairConfig(max_cycles=3,strong_fixed_point_cycles_required=1))[1].report
    from json_consistency_repair.closure import compile_fifth_series_progress
    p=compile_fifth_series_progress(report,33)
    assert p['status']=='IN_PROGRESS' and p['closed'] is False
    assert p['completed_substantive_passes']==1 and p['remaining_substantive_passes']==7
    assert p['checks']['pass033_independent_semantic_certifier']

def test_pass033_streaming_source_exact_survives_internal_routing_adaptation(tmp_path: Path):
    core=_const_rule(11); core['document']='@stream'
    rule=deepcopy(core); rule['claim_provenance']={"classification":"SOURCE_EXACT","source_id":"rules","source_pointer":"/rules/0"}
    inp=tmp_path/'routed.jsonl'; out=tmp_path/'routed-out.jsonl'; inp.write_text('{"x":0}\n',encoding='utf-8')
    cfg=StreamingConfig(constraint_rules=(rule,),source_context=_src({"rules":[core]}),max_cycles=3,strong_fixed_point_cycles_required=1,exact_disk_registry=True,enable_final_certification=False)
    repair_stream_file(inp,out,config=cfg,stream_format='jsonl')
    assert out.read_text(encoding='utf-8').strip()=='{"x":11}'
