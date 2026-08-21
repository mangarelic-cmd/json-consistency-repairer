from __future__ import annotations
from copy import deepcopy
from types import SimpleNamespace

from json_consistency_repair import (
    RepairConfig, repair_object,
    compile_symmetry_obstruction, verify_symmetry_certificate,
    semantic_quotient_digest, compare_modulo_semantic_quotient,
)
from json_consistency_repair.models import Candidate
from json_consistency_repair.parallel_routes import resolve_parallel_routes


def c(cid,path,old,new):
    return Candidate(cid,"stress","replace",path,old,new,"stress",1.0,1,(),{})


def main():
    counts={}
    for i in range(100):
        root={"rows":[{"x":i},{"x":i}]}
        cert=compile_symmetry_obstruction(root,[[c(f"a{i}","/rows/0/x",i,i+1)],[c(f"b{i}","/rows/1/x",i,i+1)]])
        assert cert["status"]=="SYMMETRY_BLOCKED_REPAIR" and cert["blocked"] and verify_symmetry_certificate(cert)
    counts["symmetry_obstruction"]=100

    rules=({"path":"/rows","equivalence":"unordered_array"},)
    for i in range(100):
        a={"rows":[{"x":i},{"x":i+1}]}; b={"rows":[{"x":i+1},{"x":i}]}
        cmp=compare_modulo_semantic_quotient(a,b,rules)
        assert cmp["semantic_quotient_equivalent"] and cmp["quotient_used"]
    counts["explicit_quotient_equivalence"]=100

    for i in range(100):
        root={"rows":[{"id":"A","x":i},{"id":"B","x":i}]}
        cert=compile_symmetry_obstruction(root,[[c(f"a{i}","/rows/0/x",i,i+1)],[c(f"b{i}","/rows/1/x",i,i+1)]])
        assert cert["status"]=="NO_SYMMETRY_OBSTRUCTION" and not cert["blocked"]
    counts["identity_breaks_symmetry"]=100

    for i in range(100):
        r=({"path":"/x","equivalence":"unordered_array"},)
        assert semantic_quotient_digest({"x":[i,i,i+1]},r)!=semantic_quotient_digest({"x":[i,i+1]},r)
    counts["multiplicity_preserved"]=100

    def complete(seed):
        report={"remaining_issues":[],"relations":[],"dynamic_q_descent":{"final":{}},
                "strong_fixed_point":{"attained":True,"oscillation_detected":False},"cycles":[],"committed_edits":[]}
        return seed,SimpleNamespace(report=report,final_status="PASS",remaining_issues=0)
    for i in range(100):
        root={"rows":[{"x":i},{"x":i}]}
        routes=[[c(f"a{i}","/rows/0/x",i,i+1)],[c(f"b{i}","/rows/1/x",i,i+1)]]
        res=resolve_parallel_routes(root,routes,complete_fn=complete,semantic_quotient_rules=rules)
        assert res.status=="RETURN_PROOF_QUOTIENT_EQUIVALENT" and res.proof["ok"] and len(res.patches)==1
    counts["quotient_return_proof"]=100

    for i in range(100):
        root={"rows":[{"x":i},{"x":i}]}
        cert=compile_symmetry_obstruction(root,[[c(f"a{i}","/rows/0/x",i,i+1)],[c(f"b{i}","/rows/1/x",i,i+1)]])
        bad=deepcopy(cert); bad["blocked"]=False
        assert not verify_symmetry_certificate(bad)
    counts["tamper_firewall"]=100

    assert sum(counts.values())==600
    print({"PASS035":counts,"total":600})

if __name__=="__main__": main()
