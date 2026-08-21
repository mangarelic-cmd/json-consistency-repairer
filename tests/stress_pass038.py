from __future__ import annotations
from copy import deepcopy
from json_consistency_repair.persistent_open import (
    compile_open_obligation_registry, verify_open_obligation_registry,
    wake_open_obligations, verify_wake_plan,
    compile_incremental_recompute, verify_incremental_recompute_certificate,
    compile_proof_dependency_index, verify_proof_dependency_index,
    change_tokens_from_json_diff,
)


def issue_report(i, code="IDENTIFIABLE_BUT_UNREACHABLE", path="/x"):
    return {"mode":"single","output_digest":f"{i:064x}"[-64:],"remaining_issues":[
        {"analyzer":"controllability" if "UNREACHABLE" in code else "boundary","code":code,"path":path,"message":"open","repairable":True,"metadata":{"i":i}}
    ]}


def main():
    counts={"registry":0,"wake":0,"incremental_eq":0,"fallback":0,"dependency_index":0,"json_diff":0}
    # 100 deterministic registry integrity decisions.
    for i in range(100):
        r=compile_open_obligation_registry(issue_report(i))
        assert verify_open_obligation_registry(r) and r["obligation_count"]==1
        counts["registry"]+=1
    # 100 targeted wake decisions.
    for i in range(100):
        r=compile_open_obligation_registry(issue_report(i,path=f"/x/{i}"))
        p=wake_open_obligations(r,[f"path:/x/{i}"])
        assert verify_wake_plan(p,r) and p["woken_count"]==1
        counts["wake"]+=1
    # 100 exact targeted-registry transitions equal to a full fresh registry.
    for i in range(100):
        prior=compile_open_obligation_registry(issue_report(i))
        current=compile_open_obligation_registry({"mode":"single","output_digest":f"{i+1000:064x}"[-64:],"remaining_issues":[]})
        c=compile_incremental_recompute(current,prior_registry=prior,change_tokens=["permission:/x"])
        assert c["status"]=="INCREMENTAL_EQ_FULL" and verify_incremental_recompute_certificate(c,current)
        counts["incremental_eq"]+=1
    # 100 indirect changes must force the conservative fallback rather than silently discard OPEN state.
    for i in range(100):
        rr=issue_report(i)
        rr["remaining_issues"].append({"analyzer":"boundary","code":"BOUNDARY_CONFLICT","path":"/y","message":"open","repairable":False,"metadata":{"i":i}})
        prior=compile_open_obligation_registry(rr)
        current=compile_open_obligation_registry({"mode":"single","output_digest":f"{i+2000:064x}"[-64:],"remaining_issues":[]})
        c=compile_incremental_recompute(current,prior_registry=prior,change_tokens=["permission:/x"])
        assert c["status"]=="FULL_RECOMPUTE_REQUIRED" and not c["incremental_equivalence"] and verify_incremental_recompute_certificate(c,current)
        counts["fallback"]+=1
    # 100 conservative proof dependency indexes.
    for i in range(100):
        pg={"graph_sha256":f"{i:064x}"[-64:],"nodes":[
            {"node_id":f"a{i:03d}","kind":"RELATION","payload":{"path":f"/rows/{i}","relation_id":f"r{i}"}},
            {"node_id":f"z{i:03d}","kind":"OPAQUE","payload":{"x":i}},
        ]}
        idx=compile_proof_dependency_index(pg)
        assert verify_proof_dependency_index(idx)
        assert idx["nodes"][1]["dependency_tokens"]==["global:*"]
        counts["dependency_index"]+=1
    # 100 bounded JSON diffs identify the changed path and not untouched siblings.
    for i in range(100):
        t=change_tokens_from_json_diff({"a":{"x":i},"b":0},{"a":{"x":i+1},"b":0})
        assert "path:/a/x" in t and all("/b" not in x for x in t)
        counts["json_diff"]+=1
    total=sum(counts.values())
    print("PASS038_STRESS",total,counts)
    assert total==600

if __name__=="__main__": main()
