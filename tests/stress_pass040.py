from __future__ import annotations
from copy import deepcopy
from json_consistency_repair.information_bounds import (
    compile_residual_information_bound, verify_residual_information_bound,
    compile_blind_carrier_reconstruction, verify_blind_carrier_reconstruction,
    verify_blind_reconstruction_trial,
)
from json_consistency_repair.models import digest


def rel():
    return {"relation_id":"r","kind":"functional","array_path":"/rows","inputs":["k"],"output":"v","determinant":"k","confidence":1.0,"support":4}


def main():
    counts={"finite_lower_bound":0,"blind_exact":0,"residual_debt":0,"carrier_insufficient":0,"tamper_rejected":0,"permutation_invariant":0}
    for i in range(100):
        c=compile_residual_information_bound([i,i+1,i+2],target_path=f"/x/{i}")
        assert c["candidate_count"]==3 and c["minimum_fixed_width_selector_bits"]==2 and verify_residual_information_bound(c)
        counts["finite_lower_bound"]+=1
    for i in range(100):
        root={"rows":[{"k":"a","v":i},{"k":"a","v":i},{"k":"b","v":i+1},{"k":"b","v":i+1}]}
        c=compile_blind_carrier_reconstruction(root,[rel()],max_trials=4)
        assert c["exact_reconstruction_count"]==4 and c["mismatch_count"]==0 and verify_blind_carrier_reconstruction(c)
        counts["blind_exact"]+=1
    for i in range(100):
        root={"rows":[{"k":"a","v":i+j} for j in range(4)]}
        c=compile_blind_carrier_reconstruction(root,[rel()],max_trials=1); t=c["trials"][0]
        assert t["status"]=="RESIDUAL_INFORMATION_REQUIRED" and t["predicted_value"] is None
        assert t["residual_information_bound"]["candidate_count"]==3 and t["residual_information_bound"]["minimum_fixed_width_selector_bits"]==2
        counts["residual_debt"]+=1
    for i in range(100):
        root={"rows":[{"k":f"k{j}","v":i+j} for j in range(4)]}
        c=compile_blind_carrier_reconstruction(root,[rel()],max_trials=1); t=c["trials"][0]
        assert t["status"]=="CARRIER_INSUFFICIENT" and t["residual_information_bound"]["minimum_fixed_width_selector_bits"] is None
        counts["carrier_insufficient"]+=1
    for i in range(100):
        root={"rows":[{"k":"a","v":i},{"k":"a","v":i},{"k":"b","v":i+1},{"k":"b","v":i+1}]}
        c=compile_blind_carrier_reconstruction(root,[rel()],max_trials=1); t=deepcopy(c["trials"][0]); t["sealed_target_sha256"]="0"*64
        body=deepcopy(t); body.pop("trial_sha256",None); t["trial_sha256"]=digest(body)
        assert not verify_blind_reconstruction_trial(t); counts["tamper_rejected"]+=1
    for i in range(100):
        a={"rows":[{"k":"a","v":i},{"k":"a","v":i},{"k":"b","v":i+1},{"k":"b","v":i+1}]}
        b={"rows":list(reversed(a["rows"]))}
        ca=compile_blind_carrier_reconstruction(a,[rel()],max_trials=4); cb=compile_blind_carrier_reconstruction(b,[rel()],max_trials=4)
        assert ca["exact_reconstruction_count"]==cb["exact_reconstruction_count"]==4 and ca["mismatch_count"]==cb["mismatch_count"]==0
        counts["permutation_invariant"]+=1
    total=sum(counts.values()); print("PASS040_STRESS",total,counts); assert total==600

if __name__=="__main__": main()
