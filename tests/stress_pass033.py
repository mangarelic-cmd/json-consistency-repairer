from copy import deepcopy
from json_consistency_repair import RepairConfig, repair_object
from json_consistency_repair.semantic_provenance import (
    compile_semantic_claim_registry, verify_semantic_claim_registry,
    merkle_inclusion, verify_merkle_inclusion, project_verified_semantic_config,
)


def src(value):
    return ({"source_id":"rules","role":"reference","value":value},)


def const(v, rid="r", prov=None):
    r={"kind":"const","array_path":"","field":"x","value":v,"rule_id":rid}
    if prov is not None: r["claim_provenance"]=prov
    return r


def cfg(rule, value):
    return RepairConfig(constraint_rules=(rule,),source_context=src(value),enable_multisource=False,
                        max_cycles=3,strong_fixed_point_cycles_required=1,enable_final_certification=False)


def main():
    counts={}
    for i in range(100):
        core=const(i,rid=f"r{i}")
        rule=const(i,rid=f"r{i}",prov={"classification":"SOURCE_EXACT","source_id":"rules","source_pointer":"/rules/0"})
        reg=compile_semantic_claim_registry(cfg(rule,{"rules":[core]}))
        assert reg["verified_claim_count"]==1 and verify_semantic_claim_registry(reg)
    counts["source_exact_reproduction"]=100

    for i in range(100):
        core=const(i,rid=f"r{i}")
        rule=const(i+1,rid=f"r{i}",prov={"classification":"SOURCE_EXACT","source_id":"rules","source_pointer":"/rules/0"})
        projected,pre=project_verified_semantic_config(cfg(rule,{"rules":[core]}))
        assert not projected.constraint_rules and pre["gated_rule_count"]==1
    counts["false_attribution_preanalysis_gate"]=100

    for i in range(100):
        template={"kind":"const","array_path":"","field":"x","value":{"$source":{"source_id":"rules","pointer":"/v"}},"rule_id":f"d{i}"}
        rule=const(i,rid=f"d{i}",prov={"classification":"DERIVED_EXACT","template":template})
        reg=compile_semantic_claim_registry(cfg(rule,{"v":i}))
        assert reg["verified_claim_count"]==1 and verify_semantic_claim_registry(reg)
    counts["derived_exact_rederivation"]=100

    for i in range(100):
        rule=const(i,rid=f"r{i}",prov={"classification":"SOURCE_EXACT","source_id":"rules","source_pointer":"/r"})
        reg=compile_semantic_claim_registry(cfg(rule,{"r":const(i,rid=f"r{i}")}))
        bad=deepcopy(reg); bad["claims"][0]["claim_payload"]["value"]=i+1
        assert not verify_semantic_claim_registry(bad)
    counts["claim_payload_tamper_rejected"]=100

    for i in range(100):
        doc={"a":[i,{"x":i+1}],"z":i+2}; proof=merkle_inclusion(doc,"/a/1/x")
        assert proof and verify_merkle_inclusion(proof)
        bad=deepcopy(proof); bad["fragment"]=i+2
        assert not verify_merkle_inclusion(bad)
    counts["merkle_inclusion_tamper_rejected"]=100

    for i in range(100):
        bad={"kind":"minimum","array_path":"","field":"x","value":100+i,"rule_id":f"b{i}",
             "claim_provenance":{"classification":"SOURCE_EXACT","source_id":"rules","source_pointer":"/r"}}
        true={"kind":"minimum","array_path":"","field":"x","value":0,"rule_id":f"b{i}"}
        obj=[{"x":50}]
        out,res=repair_object(obj,cfg(bad,{"r":true}))
        assert out==obj and res.committed_edits==0
    counts["semantic_poison_cannot_mutate"]=100
    assert sum(counts.values())==600
    print({"PASS033":counts,"total":600})

if __name__=="__main__": main()
