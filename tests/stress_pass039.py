from __future__ import annotations
from json_consistency_repair.horizon import compile_horizon_snapshot, compare_horizon_naturality, compile_distributed_consistency
from json_consistency_repair.models import digest


def rep(i,o,rels=()): return {"mode":"single","input_digest":digest(i),"output_digest":digest(o),"relations":list(rels)}

def main():
    counts={"natural_extension":0,"boundary_witness":0,"unexplained_drift":0,"repartition_equal":0,"repartition_conflict":0,"conservative_fallback":0}
    for i in range(100):
        a={"rows":[{"a":i,"b":2*i}]}; b={"rows":[{"a":i,"b":2*i},{"a":i+1,"b":2*(i+1)}]}
        s1=compile_horizon_snapshot(rep(a,a),a,a); s2=compile_horizon_snapshot(rep(b,b),b,b)
        c=compare_horizon_naturality(s1,s2); assert c["status"]=="HORIZON_NATURAL" and c["ok"]; counts["natural_extension"]+=1
    rel={"relation_id":"r","array_path":"/rows","inputs":["a"],"output":"b"}
    for i in range(100):
        a={"rows":[{"a":i,"b":2*i}]}; b={"rows":[{"a":i,"b":2*i},{"a":i+1,"b":2*(i+1)}]}; bo={"rows":[{"a":i,"b":2*i+1},{"a":i+1,"b":2*(i+1)}]}
        s1=compile_horizon_snapshot(rep(a,a,[rel]),a,a); s2=compile_horizon_snapshot(rep(b,bo,[rel]),b,bo)
        c=compare_horizon_naturality(s1,s2); assert c["status"]=="HORIZON_INVALIDATED_BY_WITNESS" and c["ok"]; counts["boundary_witness"]+=1
    for i in range(100):
        a={"x":i}; b={"x":i,"z":1}; bo={"x":i+1,"z":1}
        s1=compile_horizon_snapshot(rep(a,a),a,a); s2=compile_horizon_snapshot(rep(b,bo),b,bo)
        c=compare_horizon_naturality(s1,s2); assert c["status"]=="HORIZON_DRIFT_UNEXPLAINED" and not c["ok"]; counts["unexplained_drift"]+=1
    for i in range(100):
        a={"x":i}; s1=compile_horizon_snapshot(rep(a,a),a,a,distribution={"shards":1}); s2=compile_horizon_snapshot(rep(a,a),a,a,distribution={"shards":7})
        c=compile_distributed_consistency([s1,s2]); assert c["status"]=="DISTRIBUTED_CONSISTENT" and c["ok"]; counts["repartition_equal"]+=1
    for i in range(100):
        a={"x":i}; bo={"x":i+1}; s1=compile_horizon_snapshot(rep(a,a),a,a); s2=compile_horizon_snapshot(rep(a,bo),a,bo)
        c=compile_distributed_consistency([s1,s2]); assert c["status"]=="DISTRIBUTED_CONFLICT" and not c["ok"]; counts["repartition_conflict"]+=1
    for i in range(100):
        s1=compile_horizon_snapshot({"mode":"streaming","input_digest":f"{i:064x}","output_digest":f"{i+1:064x}"},None,None)
        s2=compile_horizon_snapshot({"mode":"streaming","input_digest":f"{i+2:064x}","output_digest":f"{i+3:064x}"},None,None)
        c=compare_horizon_naturality(s1,s2); assert c["status"]=="FULL_RECOMPUTE_REQUIRED" and not c["ok"]; counts["conservative_fallback"]+=1
    total=sum(counts.values()); print("PASS039_STRESS",total,counts); assert total==600
if __name__=="__main__": main()
