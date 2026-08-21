from copy import deepcopy
from json_consistency_repair.rectification_packet import (
    compile_rectification_packet, verify_rectification_packet, verify_rectification_packet_final, seal_rectification_packet
)
from json_consistency_repair.models import digest


def base_report(i):
    pg={"contract":"json-consistency-repair.proof-graph.v1","graph_sha256":digest(["pg",i])}
    return {
        "engine":"json-consistency-repair","version":"0.32.0","report_contract":{"status":"PASS"},
        "mode":"single","input_digest":digest(["in",i]),"output_digest":digest(["out",i]),
        "boundary_calculus":{"contract":"json-consistency-repair.boundary-calculus.v1","i":i},
        "parallel_exact_minimum_routes":{"contract":"json-consistency-repair.parallel-exact-routes.v1","cycles":[]},
        "primary_factorization":{"contract":"json-consistency-repair.primary-factorization-summary.v1","cycles":[]},
        "witness_materialization":{"contract":"json-consistency-repair.witness-materialization.v1","cycles":[]},
        "scoped_authority":{"contract":"json-consistency-repair.scoped-authority.v1","i":i},
        "evidence_poisoning_firewall":{"contract":"json-consistency-repair.evidence-poisoning-firewall.v1","i":i},
        "robust_envelope":{"contract":"json-consistency-repair.robust-envelope.v1","i":i},
        "dynamic_q_descent":{"contract":"json-consistency-repair.dynamic-q-descent.v1","i":i},
        "proof_graph":pg,"proof_graph_replay":{"contract":"json-consistency-repair.proof-graph-replay.v1","status":"PROOF_GRAPH_REPLAY_EXACT","ok":True},
        "provenance_chain":{"contract":"x","root_hash":digest(["prov",i])},
        "strong_fixed_point":{"attained":True,"oscillation_detected":False},
        "cold_replay":{"performed":True,"would_commit_edits":0,"same_output":True},
        "remaining_issues":[],"committed_edits":[],"cycles":[],"replay":{"inverse_restores_input":True},
    }


def main():
    counts={}
    for i in range(100):
        r=base_report(i); a=compile_rectification_packet(r); b=compile_rectification_packet(deepcopy(r))
        assert a["packet_sha256"]==b["packet_sha256"] and verify_rectification_packet(a,r)
    counts["deterministic_packet"]=100
    for i in range(100):
        r=base_report(i); p=compile_rectification_packet(r); r["boundary_calculus"]["x"]="tamper"
        assert not verify_rectification_packet(p,r)
    counts["section_tamper_rejected"]=100
    for i in range(100):
        r=base_report(i); p=compile_rectification_packet(r); bad=deepcopy(p); bad["remaining"]["state"]="FAKE"
        assert not verify_rectification_packet(bad,r)
    counts["packet_tamper_rejected"]=100
    for i in range(100):
        r=base_report(i); p=compile_rectification_packet(r)
        cert={"status":"CERTIFIED","ok":True,"certifier_code_sha256":digest(["cert",i]),"provenance_root":r["provenance_chain"]["root_hash"]}
        r["final_certification"]=cert; p=seal_rectification_packet(p,cert,r); r["rectification_packet"]=p
        assert verify_rectification_packet_final(p,r)
    counts["sealed_packet_verified"]=100
    for i in range(100):
        r=base_report(i); p=compile_rectification_packet(r)
        cert={"status":"CERTIFIED","ok":True,"certifier_code_sha256":digest(["cert",i]),"provenance_root":r["provenance_chain"]["root_hash"]}
        r["final_certification"]=cert; p=seal_rectification_packet(p,cert,r); bad=deepcopy(p); bad["certifier_seal"]["seal_sha256"]="0"*64
        assert not verify_rectification_packet_final(bad,r)
    counts["seal_tamper_rejected"]=100
    for i in range(100):
        p=compile_rectification_packet({"engine":"x","version":"v","report_contract":{"status":"OPEN"},"remaining_issues":[]})
        row={x["logical_name"]:x for x in p["surfaces"]}["boundaries"]
        assert row["state"]=="NOT_EMITTED" and row["sha256"] is None and row["shape"] is None
    counts["absence_semantics_preserved"]=100
    assert sum(counts.values())==600
    print({"PASS032":counts,"total":600})

if __name__=="__main__": main()
