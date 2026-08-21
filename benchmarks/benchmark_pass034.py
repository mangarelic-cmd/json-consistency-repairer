from copy import deepcopy
from pathlib import Path
import json
from json_consistency_repair import (
    RepairConfig, repair_object, parse_dsl, parse_expression, solve_equation,
    compile_repair_path_algebra, verify_repair_path_algebra, candidate_set_admissibility,
)
from json_consistency_repair.models import Candidate

def c(cid,path,old,new,meta=None): return Candidate(cid,"bench","replace",path,old,new,"bench",1.0,1,(),meta or {})

def main():
    counts={}; false_mutations=0
    def batch(name,fn):
        nonlocal false_mutations
        ok=0
        for i in range(100):
            good,false=fn(i); ok+=int(good); false_mutations+=int(false)
        counts[name]=ok
    def exact(i):
        obj={"rows":[{"a":i,"b":i+1,"total":0}]}; r=parse_dsl("scope /rows\nexpr e: total = a + b")[0]
        out,_=repair_object(obj,RepairConfig(constraint_rules=(r,),min_support=999,enable_final_certification=False)); good=out["rows"][0]["total"]==2*i+1
        return good,not good
    batch("exact_expression_projection",exact)
    def symmetry(i):
        st,v,_=solve_equation(parse_expression("x ** 2"),parse_expression(str((i+1)**2)),"x",{}); good=st=="MULTIPLE" and v is None; return good,not good
    batch("nonunique_inverse_abstention",symmetry)
    def rational(i):
        obj={"rows":[{}]}; r=parse_dsl(f"scope /rows\nexpr e: x = {3*i+1} / 3")[0]
        out,res=repair_object(obj,RepairConfig(constraint_rules=(r,),min_support=999,enable_final_certification=False)); good=out==obj and res.committed_edits==0; return good,not good
    batch("nonfinite_rational_zero_mutation",rational)
    def commute(i):
        root={"a":i,"b":i}; xs=[c(f"a{i}","/a",i,i+1),c(f"b{i}","/b",i,i+2)]; cert=compile_repair_path_algebra(root,xs); good=cert["confluence_status"]=="CONFLUENT_ON_CURRENT_FINITE_FRONTIER" and verify_repair_path_algebra(cert); return good,False
    batch("disjoint_commutation",commute)
    def join(i):
        root={"x":i}; xs=[c(f"a{i}","/x",i,i+1),c(f"b{i}","/x",i,i+2),c(f"c{i}","/x",i+1,i+3),c(f"d{i}","/x",i+2,i+3)]; cert=compile_repair_path_algebra(root,xs); p=next(p for p in cert["critical_pairs"] if {p["left"],p["right"]}=={f"a{i}",f"b{i}"}); good=p["joinable"]; return good,False
    batch("critical_pair_joinability",join)
    def open_pair(i):
        root={"x":i}; xs=[c(f"a{i}","/x",i,i+1),c(f"b{i}","/x",i,i+2)]; cert=compile_repair_path_algebra(root,xs); bad=deepcopy(cert); bad["confluence_status"]="CONFLUENT_ON_CURRENT_FINITE_FRONTIER"; good=not candidate_set_admissibility(root,xs)["admissible"] and not verify_repair_path_algebra(bad); return good,not good
    batch("open_pair_abstention_tamper_firewall",open_pair)
    payload={"contract":"json-consistency-repair.pass034-benchmark.v1","version":"0.34.0","decisions":sum(counts.values()),"expected_decisions":600,"counts":counts,"false_mutations":false_mutations,"all_checks_pass":sum(counts.values())==600 and false_mutations==0}
    text=json.dumps(payload,sort_keys=True,separators=(',',':'))+'\n'; Path(__file__).with_name('PASS034_BENCHMARK.json').write_text(text,encoding='utf-8'); print(text,end='')
if __name__=='__main__': main()
