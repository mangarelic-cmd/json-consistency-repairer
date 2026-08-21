from copy import deepcopy
from pathlib import Path
import json
from json_consistency_repair import RepairConfig, repair_object
from json_consistency_repair.semantic_provenance import (
    compile_semantic_claim_registry, verify_semantic_claim_registry,
    merkle_inclusion, verify_merkle_inclusion, project_verified_semantic_config,
)


def src(value): return ({"source_id":"rules","role":"reference","value":value},)
def rule(v,rid,prov=None):
    x={"kind":"const","array_path":"","field":"x","value":v,"rule_id":rid}
    if prov is not None: x["claim_provenance"]=prov
    return x
def cfg(r,v): return RepairConfig(constraint_rules=(r,),source_context=src(v),enable_multisource=False,max_cycles=3,strong_fixed_point_cycles_required=1,enable_final_certification=False)

def main():
    counts={}; false_mutations=0
    def batch(name, fn):
        nonlocal false_mutations
        ok=0
        for i in range(100):
            good,false=fn(i); ok+=int(good); false_mutations+=int(false)
        counts[name]=ok
    def source_exact(i):
        core=rule(i,f"r{i}"); claimed=rule(i,f"r{i}",{"classification":"SOURCE_EXACT","source_id":"rules","source_pointer":"/r"})
        reg=compile_semantic_claim_registry(cfg(claimed,{"r":core})); good=reg["verified_claim_count"]==1 and verify_semantic_claim_registry(reg); return good,False
    batch("source_exact_reproduction",source_exact)
    def false_attr(i):
        core=rule(i,f"r{i}"); claimed=rule(i+1,f"r{i}",{"classification":"SOURCE_EXACT","source_id":"rules","source_pointer":"/r"})
        projected,pre=project_verified_semantic_config(cfg(claimed,{"r":core})); good=not projected.constraint_rules and pre["gated_rule_count"]==1; return good,not good
    batch("false_attribution_gate",false_attr)
    def derived(i):
        template={"kind":"const","array_path":"","field":"x","value":{"$source":{"source_id":"rules","pointer":"/v"}},"rule_id":f"d{i}"}
        claimed=rule(i,f"d{i}",{"classification":"DERIVED_EXACT","template":template}); reg=compile_semantic_claim_registry(cfg(claimed,{"v":i})); good=verify_semantic_claim_registry(reg) and reg["verified_claim_count"]==1; return good,False
    batch("derived_exact_rederivation",derived)
    def payload_tamper(i):
        core=rule(i,f"r{i}"); claimed=rule(i,f"r{i}",{"classification":"SOURCE_EXACT","source_id":"rules","source_pointer":"/r"})
        reg=compile_semantic_claim_registry(cfg(claimed,{"r":core})); bad=deepcopy(reg); bad["claims"][0]["claim_payload"]["value"]=i+1; good=not verify_semantic_claim_registry(bad); return good,not good
    batch("claim_tamper_firewall",payload_tamper)
    def merkle(i):
        p=merkle_inclusion({"a":{"x":i},"z":i+1},"/a/x"); bad=deepcopy(p); bad["fragment"]=i+1; good=verify_merkle_inclusion(p) and not verify_merkle_inclusion(bad); return good,not good
    batch("merkle_inclusion_firewall",merkle)
    def poison(i):
        bad={"kind":"minimum","array_path":"","field":"x","value":100+i,"rule_id":f"b{i}","claim_provenance":{"classification":"SOURCE_EXACT","source_id":"rules","source_pointer":"/r"}}
        true={"kind":"minimum","array_path":"","field":"x","value":0,"rule_id":f"b{i}"}; obj=[{"x":50}]
        out,res=repair_object(obj,cfg(bad,{"r":true})); good=out==obj and res.committed_edits==0; return good, not good
    batch("semantic_poison_zero_mutation",poison)
    payload={"contract":"json-consistency-repair.pass033-benchmark.v1","version":"0.33.0","decisions":sum(counts.values()),"expected_decisions":600,"counts":counts,"false_mutations":false_mutations,"all_checks_pass":sum(counts.values())==600 and false_mutations==0}
    text=json.dumps(payload,sort_keys=True,separators=(',',':'))+'\n'; Path(__file__).with_name('PASS033_BENCHMARK.json').write_text(text,encoding='utf-8'); print(text,end='')

if __name__=='__main__': main()
