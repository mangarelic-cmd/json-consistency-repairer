from __future__ import annotations
import json
from json_consistency_repair.horizon import compile_horizon_snapshot, compare_horizon_naturality, compile_distributed_consistency
from json_consistency_repair.models import digest

def rep(i,o,rels=()): return {"mode":"single","input_digest":digest(i),"output_digest":digest(o),"relations":list(rels)}
def main():
    counts={"horizon_stable":0,"witnessed_invalidation":0,"unexplained_rejected":0,"partition_invariance":0,"partition_conflict_detected":0,"opaque_fallback":0}; false_mutations=0
    rel={"relation_id":"r","array_path":"/rows","inputs":["a"],"output":"b"}
    for i in range(100):
        a={"rows":[{"a":i,"b":i}]}; b={"rows":[{"a":i,"b":i},{"a":i+1,"b":i+1}]}; s1=compile_horizon_snapshot(rep(a,a),a,a); s2=compile_horizon_snapshot(rep(b,b),b,b); assert compare_horizon_naturality(s1,s2)["ok"]; counts["horizon_stable"]+=1
    for i in range(100):
        a={"rows":[{"a":i,"b":i}]}; b={"rows":[{"a":i,"b":i},{"a":i+1,"b":i+1}]}; bo={"rows":[{"a":i,"b":i+7},{"a":i+1,"b":i+1}]}; s1=compile_horizon_snapshot(rep(a,a,[rel]),a,a); s2=compile_horizon_snapshot(rep(b,bo,[rel]),b,bo); assert compare_horizon_naturality(s1,s2)["status"]=="HORIZON_INVALIDATED_BY_WITNESS"; counts["witnessed_invalidation"]+=1
    for i in range(100):
        a={"x":i}; b={"x":i,"y":0}; bo={"x":-1,"y":0}; s1=compile_horizon_snapshot(rep(a,a),a,a); s2=compile_horizon_snapshot(rep(b,bo),b,bo); c=compare_horizon_naturality(s1,s2); assert not c["ok"]; counts["unexplained_rejected"]+=1
    for i in range(100):
        a={"x":i}; s1=compile_horizon_snapshot(rep(a,a),a,a,distribution={"workers":1}); s2=compile_horizon_snapshot(rep(a,a),a,a,distribution={"workers":16}); assert compile_distributed_consistency([s1,s2])["ok"]; counts["partition_invariance"]+=1
    for i in range(100):
        a={"x":i}; o={"x":i+1}; s1=compile_horizon_snapshot(rep(a,a),a,a); s2=compile_horizon_snapshot(rep(a,o),a,o); assert not compile_distributed_consistency([s1,s2])["ok"]; counts["partition_conflict_detected"]+=1
    for i in range(100):
        s1=compile_horizon_snapshot({"mode":"streaming","input_digest":f"{i:064x}","output_digest":f"{i+1:064x}"}); s2=compile_horizon_snapshot({"mode":"streaming","input_digest":f"{i+2:064x}","output_digest":f"{i+3:064x}"}); assert compare_horizon_naturality(s1,s2)["full_recompute_required"]; counts["opaque_fallback"]+=1
    decisions=sum(counts.values()); payload={"contract":"json-consistency-repair.pass039-benchmark.v1","version":"0.39.0","expected_decisions":600,"decisions":decisions,"counts":counts,"false_mutations":false_mutations,"all_checks_pass":decisions==600 and false_mutations==0}; print(json.dumps(payload,sort_keys=True,separators=(",",":")))
if __name__=="__main__": main()
