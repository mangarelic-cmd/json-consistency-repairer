from __future__ import annotations
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import json

from json_consistency_repair import (
    compile_symmetry_obstruction, verify_symmetry_certificate,
    semantic_quotient_digest, compare_modulo_semantic_quotient,
)
from json_consistency_repair.models import Candidate
from json_consistency_repair.parallel_routes import resolve_parallel_routes


def c(cid,path,old,new): return Candidate(cid,"bench","replace",path,old,new,"bench",1.0,1,(),{})

def main():
    counts={}; false_mutations=0
    def batch(name, fn):
        nonlocal false_mutations
        ok=0
        for i in range(100):
            good,false=fn(i); ok+=int(good); false_mutations+=int(false)
        counts[name]=ok

    def blocked(i):
        root={"rows":[{"x":i},{"x":i}]}
        cert=compile_symmetry_obstruction(root,[[c(f"a{i}","/rows/0/x",i,i+1)],[c(f"b{i}","/rows/1/x",i,i+1)]])
        good=cert["status"]=="SYMMETRY_BLOCKED_REPAIR" and cert["blocked"]
        return good,not good
    batch("symmetry_blocked_zero_tiebreak",blocked)

    rules=({"path":"/rows","equivalence":"unordered_array"},)
    def quotient(i):
        a={"rows":[{"x":i},{"x":i+1}]}; b={"rows":[{"x":i+1},{"x":i}]}
        good=compare_modulo_semantic_quotient(a,b,rules)["semantic_quotient_equivalent"]
        return good,False
    batch("explicit_quotient_equivalence",quotient)

    def identity(i):
        root={"rows":[{"id":"A","x":i},{"id":"B","x":i}]}
        cert=compile_symmetry_obstruction(root,[[c(f"a{i}","/rows/0/x",i,i+1)],[c(f"b{i}","/rows/1/x",i,i+1)]])
        good=cert["status"]=="NO_SYMMETRY_OBSTRUCTION"
        return good,False
    batch("identity_breaker",identity)

    def multiplicity(i):
        r=({"path":"/x","equivalence":"unordered_array"},)
        good=semantic_quotient_digest({"x":[i,i,i+1]},r)!=semantic_quotient_digest({"x":[i,i+1]},r)
        return good,not good
    batch("multiplicity_not_erased",multiplicity)

    def complete(seed):
        report={"remaining_issues":[],"relations":[],"dynamic_q_descent":{"final":{}},
                "strong_fixed_point":{"attained":True,"oscillation_detected":False},"cycles":[],"committed_edits":[]}
        return seed,SimpleNamespace(report=report,final_status="PASS",remaining_issues=0)
    def return_proof(i):
        root={"rows":[{"x":i},{"x":i}]}; routes=[[c(f"a{i}","/rows/0/x",i,i+1)],[c(f"b{i}","/rows/1/x",i,i+1)]]
        res=resolve_parallel_routes(root,routes,complete_fn=complete,semantic_quotient_rules=rules)
        good=res.status=="RETURN_PROOF_QUOTIENT_EQUIVALENT" and res.proof["ok"] and len(res.patches)==1
        return good,not good
    batch("quotient_return_proof",return_proof)

    def tamper(i):
        root={"rows":[{"x":i},{"x":i}]}
        cert=compile_symmetry_obstruction(root,[[c(f"a{i}","/rows/0/x",i,i+1)],[c(f"b{i}","/rows/1/x",i,i+1)]])
        bad=deepcopy(cert); bad["status"]="NO_SYMMETRY_OBSTRUCTION"
        good=not verify_symmetry_certificate(bad)
        return good,not good
    batch("symmetry_certificate_tamper_firewall",tamper)

    payload={"contract":"json-consistency-repair.pass035-benchmark.v1","version":"0.35.0","decisions":sum(counts.values()),"expected_decisions":600,
             "counts":counts,"false_mutations":false_mutations,"all_checks_pass":sum(counts.values())==600 and false_mutations==0}
    text=json.dumps(payload,sort_keys=True,separators=(',',':'))+'\n'
    Path(__file__).with_name('PASS035_BENCHMARK.json').write_text(text,encoding='utf-8')
    print(text,end='')

if __name__=='__main__': main()
