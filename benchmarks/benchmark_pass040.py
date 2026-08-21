from __future__ import annotations
from copy import deepcopy
import json
from json_consistency_repair.information_bounds import compile_residual_information_bound, compile_blind_carrier_reconstruction, verify_blind_reconstruction_trial
from json_consistency_repair.models import digest

def rel(): return {"relation_id":"r","kind":"functional","array_path":"/rows","inputs":["k"],"output":"v","determinant":"k","confidence":1.0,"support":4}

def main():
    counts={"finite_bound_exact":0,"blind_exact":0,"ambiguity_abstained":0,"insufficient_abstained":0,"tamper_detected":0,"reorder_stable":0}; false_mutations=0
    for i in range(100):
        c=compile_residual_information_bound([i,i+1,i+2],target_path="/x"); assert c["minimum_fixed_width_selector_bits"]==2; counts["finite_bound_exact"]+=1
    for i in range(100):
        root={"rows":[{"k":"a","v":i},{"k":"a","v":i},{"k":"b","v":i+1},{"k":"b","v":i+1}]}; before=digest(root)
        c=compile_blind_carrier_reconstruction(root,[rel()],max_trials=4); assert c["exact_reconstruction_count"]==4 and c["mismatch_count"]==0; assert digest(root)==before; counts["blind_exact"]+=1
    for i in range(100):
        root={"rows":[{"k":"a","v":i+j} for j in range(4)]}; before=digest(root); t=compile_blind_carrier_reconstruction(root,[rel()],max_trials=1)["trials"][0]; assert t["status"]=="RESIDUAL_INFORMATION_REQUIRED" and t["predicted_value"] is None; assert digest(root)==before; counts["ambiguity_abstained"]+=1
    for i in range(100):
        root={"rows":[{"k":str(j),"v":i+j} for j in range(4)]}; before=digest(root); t=compile_blind_carrier_reconstruction(root,[rel()],max_trials=1)["trials"][0]; assert t["status"]=="CARRIER_INSUFFICIENT"; assert digest(root)==before; counts["insufficient_abstained"]+=1
    for i in range(100):
        root={"rows":[{"k":"a","v":i},{"k":"a","v":i},{"k":"b","v":i+1},{"k":"b","v":i+1}]}; t=deepcopy(compile_blind_carrier_reconstruction(root,[rel()],max_trials=1)["trials"][0]); t["sealed_target_sha256"]="0"*64; body=deepcopy(t); body.pop("trial_sha256",None); t["trial_sha256"]=digest(body); assert not verify_blind_reconstruction_trial(t); counts["tamper_detected"]+=1
    for i in range(100):
        a={"rows":[{"k":"a","v":i},{"k":"a","v":i},{"k":"b","v":i+1},{"k":"b","v":i+1}]}; b={"rows":list(reversed(a["rows"]))}; ca=compile_blind_carrier_reconstruction(a,[rel()],max_trials=4); cb=compile_blind_carrier_reconstruction(b,[rel()],max_trials=4); assert ca["exact_reconstruction_count"]==cb["exact_reconstruction_count"]==4; counts["reorder_stable"]+=1
    decisions=sum(counts.values()); payload={"contract":"json-consistency-repair.pass040-benchmark.v1","version":"0.40.0","expected_decisions":600,"decisions":decisions,"counts":counts,"false_mutations":false_mutations,"all_checks_pass":decisions==600 and false_mutations==0}; print(json.dumps(payload,sort_keys=True,separators=(",",":")))
if __name__=="__main__": main()
