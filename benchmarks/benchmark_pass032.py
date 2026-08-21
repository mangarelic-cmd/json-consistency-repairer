from pathlib import Path
from copy import deepcopy
import json
from json_consistency_repair.rectification_packet import compile_rectification_packet, verify_rectification_packet, verify_rectification_packet_final, seal_rectification_packet
from json_consistency_repair.models import digest


def base(i):
    return {
        "engine":"json-consistency-repair","version":"0.32.0","report_contract":{"status":"PASS"},"mode":"single",
        "input_digest":digest(["i",i]),"output_digest":digest(["o",i]),"remaining_issues":[],"committed_edits":[],"cycles":[],
        "boundary_calculus":{"contract":"json-consistency-repair.boundary-calculus.v1","n":i},
        "parallel_exact_minimum_routes":{"contract":"json-consistency-repair.parallel-exact-routes.v1"},
        "primary_factorization":{"contract":"json-consistency-repair.primary-factorization-summary.v1"},
        "witness_materialization":{"contract":"json-consistency-repair.witness-materialization.v1"},
        "scoped_authority":{"contract":"json-consistency-repair.scoped-authority.v1"},
        "evidence_poisoning_firewall":{"contract":"json-consistency-repair.evidence-poisoning-firewall.v1"},
        "robust_envelope":{"contract":"json-consistency-repair.robust-envelope.v1"},
        "dynamic_q_descent":{"contract":"json-consistency-repair.dynamic-q-descent.v1"},
        "proof_graph":{"graph_sha256":digest(["pg",i])},"proof_graph_replay":{"status":"PROOF_GRAPH_REPLAY_EXACT","ok":True},
        "provenance_chain":{"root_hash":digest(["p",i])},"strong_fixed_point":{"attained":True},
        "cold_replay":{"performed":True,"would_commit_edits":0,"same_output":True},"replay":{"inverse_restores_input":True}
    }


def main():
    counts={}; false_mutations=0
    def batch(name,fn):
        nonlocal false_mutations
        ok=0
        for i in range(100):
            good,false=fn(i); ok+=int(good); false_mutations+=int(false)
        counts[name]=ok
    def deterministic(i):
        r=base(i); a=compile_rectification_packet(r); b=compile_rectification_packet(deepcopy(r)); return a["packet_sha256"]==b["packet_sha256"],False
    batch("deterministic_packet",deterministic)
    def section_tamper(i):
        r=base(i); p=compile_rectification_packet(r); r["boundary_calculus"]["bad"]=True; good=not verify_rectification_packet(p,r); return good,not good
    batch("section_tamper_firewall",section_tamper)
    def packet_tamper(i):
        r=base(i); p=compile_rectification_packet(r); p["surface_count"]+=1; good=not verify_rectification_packet(p,r); return good,not good
    batch("packet_tamper_firewall",packet_tamper)
    def sealed(i):
        r=base(i); p=compile_rectification_packet(r); cert={"status":"CERTIFIED","ok":True,"certifier_code_sha256":digest(["c",i]),"provenance_root":r["provenance_chain"]["root_hash"]}; r["final_certification"]=cert; p=seal_rectification_packet(p,cert,r); r["rectification_packet"]=p; good=verify_rectification_packet_final(p,r); return good,False
    batch("certifier_seal",sealed)
    def seal_tamper(i):
        r=base(i); p=compile_rectification_packet(r); cert={"status":"CERTIFIED","ok":True,"certifier_code_sha256":digest(["c",i]),"provenance_root":r["provenance_chain"]["root_hash"]}; r["final_certification"]=cert; p=seal_rectification_packet(p,cert,r); p["certifier_seal"]["proof_graph_replay_ok"]=False; good=not verify_rectification_packet_final(p,r); return good,not good
    batch("seal_tamper_firewall",seal_tamper)
    def absence(i):
        p=compile_rectification_packet({"engine":"x","version":"v","report_contract":{"status":"OPEN"}}); row={x["logical_name"]:x for x in p["surfaces"]}["boundaries"]; good=row["state"]=="NOT_EMITTED" and row["sha256"] is None; return good,False
    batch("absence_not_false_zero",absence)
    payload={"contract":"json-consistency-repair.pass032-benchmark.v1","version":"0.32.0","decisions":sum(counts.values()),"expected_decisions":600,"counts":counts,"false_mutations":false_mutations,"all_checks_pass":sum(counts.values())==600 and false_mutations==0}
    text=json.dumps(payload,sort_keys=True,separators=(',',':'))+'\n'; Path(__file__).with_name('PASS032_BENCHMARK.json').write_text(text,encoding='utf-8'); print(text,end='')

if __name__=='__main__': main()
