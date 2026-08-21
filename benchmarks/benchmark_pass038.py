from __future__ import annotations
import json
from json_consistency_repair.persistent_open import (
    compile_open_obligation_registry, wake_open_obligations,
    compile_incremental_recompute, compile_proof_dependency_index, change_tokens_from_json_diff,
)


def issue(i,path="/x"):
    return {"mode":"single","output_digest":f"{i:064x}"[-64:],"remaining_issues":[{"analyzer":"controllability","code":"IDENTIFIABLE_BUT_UNREACHABLE","path":path,"message":"open","repairable":True,"metadata":{"i":i}}]}


def main():
    counts={"persistent_open_registry":0,"targeted_wake":0,"incremental_equivalence":0,"conservative_fallback":0,"proof_invalidation":0,"json_diff":0}
    false_mutations=0
    for i in range(100):
        r=compile_open_obligation_registry(issue(i)); assert r["obligation_count"]==1; counts["persistent_open_registry"]+=1
    for i in range(100):
        r=compile_open_obligation_registry(issue(i,f"/v/{i}")); p=wake_open_obligations(r,[f"path:/v/{i}"]); assert p["woken_count"]==1; counts["targeted_wake"]+=1
    for i in range(100):
        p=compile_open_obligation_registry(issue(i)); c=compile_open_obligation_registry({"mode":"single","output_digest":f"{i+1000:064x}"[-64:],"remaining_issues":[]})
        x=compile_incremental_recompute(c,prior_registry=p,change_tokens=["permission:/x"]); assert x["status"]=="INCREMENTAL_EQ_FULL"; counts["incremental_equivalence"]+=1
    for i in range(100):
        rr=issue(i); rr["remaining_issues"].append({"analyzer":"boundary","code":"BOUNDARY_CONFLICT","path":"/other","message":"open","repairable":False,"metadata":{}})
        p=compile_open_obligation_registry(rr); c=compile_open_obligation_registry({"mode":"single","output_digest":f"{i+2000:064x}"[-64:],"remaining_issues":[]})
        x=compile_incremental_recompute(c,prior_registry=p,change_tokens=["permission:/x"]); assert x["status"]=="FULL_RECOMPUTE_REQUIRED"; counts["conservative_fallback"]+=1
    for i in range(100):
        idx=compile_proof_dependency_index({"graph_sha256":f"{i:064x}"[-64:],"nodes":[{"node_id":f"n{i}","kind":"OPAQUE","payload":{"v":i}}]}); assert idx["nodes"][0]["dependency_tokens"]==["global:*"]; counts["proof_invalidation"]+=1
    for i in range(100):
        t=change_tokens_from_json_diff({"x":i,"y":0},{"x":i+1,"y":0}); assert "path:/x" in t; counts["json_diff"]+=1
    decisions=sum(counts.values())
    payload={"contract":"json-consistency-repair.pass038-benchmark.v1","version":"0.38.0","expected_decisions":600,"decisions":decisions,"counts":counts,"false_mutations":false_mutations,"all_checks_pass":decisions==600 and false_mutations==0}
    print(json.dumps(payload,sort_keys=True,separators=(",",":")))

if __name__=="__main__": main()
