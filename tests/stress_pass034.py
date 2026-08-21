from copy import deepcopy
from json_consistency_repair import (
    RepairConfig, repair_object, parse_dsl, parse_expression, solve_equation,
    compile_repair_path_algebra, verify_repair_path_algebra, candidate_set_admissibility,
)
from json_consistency_repair.models import Candidate


def c(cid, path, old, new, meta=None):
    return Candidate(cid, "stress", "replace", path, old, new, "stress", 1.0, 1, (), meta or {})


def main():
    counts={}
    for i in range(100):
        obj={"rows":[{"a":i,"b":i+1,"total":0}]}
        r=parse_dsl("scope /rows\nexpr e: total = a + b")[0]
        out,res=repair_object(obj,RepairConfig(constraint_rules=(r,),min_support=999,enable_final_certification=False))
        assert out["rows"][0]["total"]==2*i+1
    counts["exact_expression_projection"]=100

    for i in range(100):
        st,v,_=solve_equation(parse_expression("x ** 2"),parse_expression(str((i+1)**2)),"x",{})
        assert st=="MULTIPLE" and v is None
    counts["nonunique_inverse_abstention"]=100

    for i in range(100):
        obj={"rows":[{}]}; r=parse_dsl(f"scope /rows\nexpr e: x = {3*i+1} / 3")[0]
        out,res=repair_object(obj,RepairConfig(constraint_rules=(r,),min_support=999,enable_final_certification=False))
        assert out==obj and res.committed_edits==0
    counts["nonfinite_json_rational_abstention"]=100

    for i in range(100):
        root={"a":i,"b":i}; xs=[c(f"a{i}","/a",i,i+1),c(f"b{i}","/b",i,i+2)]
        cert=compile_repair_path_algebra(root,xs)
        assert cert["confluence_status"]=="CONFLUENT_ON_CURRENT_FINITE_FRONTIER" and verify_repair_path_algebra(cert)
    counts["disjoint_commutation_proof"]=100

    for i in range(100):
        root={"x":i}; xs=[c(f"a{i}","/x",i,i+1),c(f"b{i}","/x",i,i+2),c(f"c{i}","/x",i+1,i+3),c(f"d{i}","/x",i+2,i+3)]
        cert=compile_repair_path_algebra(root,xs)
        p=next(p for p in cert["critical_pairs"] if {p["left"],p["right"]}=={f"a{i}",f"b{i}"})
        assert p["joinable"] and p["status"]=="JOINABLE_CRITICAL_PAIR"
    counts["critical_pair_joinability"]=100

    for i in range(100):
        root={"x":i}; xs=[c(f"a{i}","/x",i,i+1),c(f"b{i}","/x",i,i+2)]
        cert=compile_repair_path_algebra(root,xs)
        assert cert["confluence_status"]=="CRITICAL_PAIR_OPEN" and not candidate_set_admissibility(root,xs)["admissible"]
        bad=deepcopy(cert); bad["confluence_status"]="CONFLUENT_ON_CURRENT_FINITE_FRONTIER"
        assert not verify_repair_path_algebra(bad)
    counts["open_pair_and_tamper_firewall"]=100
    assert sum(counts.values())==600
    print({"PASS034":counts,"total":600})

if __name__=="__main__": main()
