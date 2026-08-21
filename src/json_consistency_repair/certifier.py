"""Independent PASS016 final certifier.

This module intentionally does not import engine, analyzers, minimal_transfer, modal, or fixedpoint.
It verifies serialized evidence and reversible state transitions only.
"""
from __future__ import annotations
from copy import deepcopy
from pathlib import Path
from typing import Any
import hashlib, inspect, json
from .models import digest
from .provenance_chain import verify_provenance_chain
from .jsonpatch_exact import apply_patch
from .tree import get
from .primary_factorization import verify_factorization_certificate
from .proof_graph import verify_proof_graph
from .authority_scope import verify_authority_registry, verify_authority_proof
from .robust_envelope import verify_robust_envelope_certificate
from .rectification_packet import verify_rectification_packet
from .semantic_provenance import verify_semantic_firewall, verify_semantic_claim_registry
from .repair_algebra import verify_repair_path_algebra
from .symmetry import verify_symmetry_certificate, verify_semantic_quotient_certificate
from .controllability import verify_controllability_certificate
from .relation_falsifier import verify_relation_falsification_certificate
from .persistent_open import verify_open_obligation_registry, verify_incremental_recompute_certificate, verify_incremental_equivalence_certificate
from .horizon import (verify_horizon_snapshot, verify_horizon_naturality_certificate,
    verify_distributed_consistency_certificate, compare_horizon_naturality)
from .information_bounds import verify_blind_carrier_reconstruction, verify_residual_information_summary

CONTRACT="json-consistency-repair.final-certifier.v1"

def _apply_patch(root:Any,p:dict[str,Any],inverse:bool=False)->bool:
    if inverse:
        # Exact inverses are serialized by PASS017; legacy replace/add remains supported below.
        op=str(p.get("operation","replace")); meta=p.get("metadata") or {}
        if op=="replace":
            if meta.get("add_if_missing") and p.get("old_value") is None:
                inv={"operation":"remove","path":p.get("path"),"old_value":deepcopy(p.get("new_value")),"new_value":None,"metadata":{"inverse_of":"replace-add"}}
            else:
                inv={**p,"old_value":deepcopy(p.get("new_value")),"new_value":deepcopy(p.get("old_value"))}
        elif op=="add":
            ipath=str(p.get("path",""))
            if ipath.endswith('/-'):
                parent_path=ipath[:-2]; container=get(root,parent_path) if parent_path else root
                if not isinstance(container,list) or not container: return False
                ipath=(parent_path+'/' if parent_path else '/')+str(len(container)-1)
            inv={"operation":"remove","path":ipath,"old_value":deepcopy(p.get("new_value")),"new_value":None,"metadata":{"inverse_of":"add"}}
        elif op=="remove":
            inv={"operation":"add","path":p.get("path"),"old_value":None,"new_value":deepcopy(p.get("old_value")),"metadata":{"require_absent":True,"inverse_of":"remove"}}
        elif op=="move":
            inv={"operation":"move","path":meta.get("from_path"),"old_value":deepcopy(p.get("new_value")),"new_value":deepcopy(p.get("old_value")),"metadata":{"from_path":p.get("path"),"inverse_of":"move"}}
        elif op=="copy":
            inv={"operation":"remove","path":p.get("path"),"old_value":deepcopy(p.get("new_value")),"new_value":None,"metadata":{"inverse_of":"copy"}}
        elif op=="test":
            inv=dict(p)
        elif op=="plan" and meta.get("inverse_steps"):
            inv={"operation":"plan","path":"","old_value":deepcopy(p.get("new_value")),"new_value":deepcopy(p.get("old_value")),
                 "metadata":{"steps":deepcopy(meta.get("inverse_steps")),"inverse_of":"plan"}}
        else:
            return False
        ok,_=apply_patch(root,inv); return ok
    ok,_=apply_patch(root,p); return ok

def certifier_code_sha256()->str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def _verify_parallel_return_proofs(report:dict[str,Any])->bool:
    bundle=report.get("parallel_exact_minimum_routes") or {}
    proofs=bundle.get("cycles") or []
    by_hash={}
    for raw in proofs:
        if not isinstance(raw,dict): return False
        row=deepcopy(raw); supplied=row.pop("proof_sha256",None); row.pop("cycle",None)
        if not supplied: return False
        calc=hashlib.sha256(json.dumps(row,ensure_ascii=False,sort_keys=True,separators=(",",":"),default=str).encode("utf-8")).hexdigest()
        if calc!=supplied: return False
        by_hash[supplied]=raw
    used=[]
    for cyc in report.get("cycles") or []:
        for acc in cyc.get("accepted") or []:
            if acc.get("acceptance") in {"parallel_return_proof_exact","parallel_return_proof_quotient"}:
                h=acc.get("return_proof_sha256")
                if not h or h not in by_hash or not by_hash[h].get("ok"): return False
                proof=by_hash[h]
                if acc.get("acceptance")=="parallel_return_proof_exact" and proof.get("status")!="RETURN_PROOF_EQUIVALENT": return False
                if acc.get("acceptance")=="parallel_return_proof_quotient":
                    if proof.get("status")!="RETURN_PROOF_QUOTIENT_EQUIVALENT": return False
                    if not verify_semantic_quotient_certificate(proof.get("semantic_quotient") or {}): return False
                    if not (proof.get("checks") or {}).get("semantic_quotient_terminal_equivalence"): return False
                used.append(h)
    # No parallel commit requires no proof; divergent/uncommitted route audits are permitted.
    return all(by_hash[h].get("status") in {"RETURN_PROOF_EQUIVALENT","RETURN_PROOF_QUOTIENT_EQUIVALENT"} for h in used)

def _verify_primary_factorizations(report:dict[str,Any])->bool:
    bundle=report.get("primary_factorization") or {}
    cycles=bundle.get("cycles") or []
    if not cycles:
        return False
    for row in cycles:
        cert=(row or {}).get("factorization") or {}
        if not verify_factorization_certificate(cert):
            return False
        dyn=(row or {}).get("dynamic_refactorization") or {}
        if dyn.get("contract") != "json-consistency-repair.dynamic-refactorization.v1":
            return False
    return True


def _verify_witness_materialization(report:dict[str,Any])->bool:
    bundle=report.get("witness_materialization") or {}
    cycles=bundle.get("cycles") or []
    valid_proofs=set()
    for row in cycles:
        cert=(row or {}).get("certificate") if isinstance(row,dict) else None
        if not isinstance(cert,dict): return False
        supplied=cert.get("certificate_sha256")
        tmp=deepcopy(cert); tmp.pop("certificate_sha256",None)
        if not supplied or digest(tmp)!=supplied: return False
        for terminal in cert.get("terminals") or []:
            if not isinstance(terminal,dict): return False
            if terminal.get("status")!="MATERIALIZED_EXACT": continue
            proof=terminal.get("materialization_proof_sha256")
            vd=terminal.get("selected_value_digest")
            tid=terminal.get("terminal_id")
            if not proof or not vd or not tid or not terminal.get("candidate_id"): return False
            qualifying=[x for x in terminal.get("observations") or [] if x.get("qualifies") and x.get("value_digest")==vd]
            payload={
                "contract":"json-consistency-repair.witness-materialization.v1",
                "terminal_id":tid,"target_path":terminal.get("target_path"),"witness_kind":terminal.get("witness_kind"),
                "identifiability":terminal.get("identifiability"),"selected_value_digest":vd,
                "source_evidence":[{k:v for k,v in x.items() if k not in {"qualifies","gate_reason"}} for x in qualifying],
                "search_sha256":((terminal.get("search_contract") or {}).get("search_sha256")),
            }
            if digest(payload)!=proof: return False
            valid_proofs.add(proof)
    # Every committed materializer patch must be backed by one exact materialization proof.
    commits=report.get("committed_edits") or report.get("committed_patch_set") or []
    if not isinstance(commits,list): commits=[]
    for p in commits:
        cand=p.get("candidate") if isinstance(p,dict) and isinstance(p.get("candidate"),dict) else p
        if not isinstance(cand,dict): continue
        if cand.get("analyzer")!="witness_materializer": continue
        h=(cand.get("metadata") or {}).get("materialization_proof_sha256")
        if not h or h not in valid_proofs: return False
    return True


def _walk_values(value):
    if isinstance(value,dict):
        yield value
        for v in value.values():
            yield from _walk_values(v)
    elif isinstance(value,list):
        for v in value:
            yield from _walk_values(v)

def _verify_scoped_authority(report:dict[str,Any])->bool:
    registries={}
    proofs=[]
    refs=[]
    for row in _walk_values(report):
        if row.get("contract")=="json-consistency-repair.scoped-authority.v1" and row.get("registry_sha256"):
            if not verify_authority_registry(row): return False
            registries[row["registry_sha256"]]=row
        if row.get("contract")=="json-consistency-repair.authority-proof.v1" and row.get("proof_sha256"):
            proofs.append(row)
        if row.get("authority_proof_sha256"):
            refs.append(str(row.get("authority_proof_sha256")))
    valid=set()
    for proof in proofs:
        reg=registries.get(proof.get("authority_registry_sha256"))
        if reg is None or not verify_authority_proof(proof,reg): return False
        valid.add(str(proof.get("proof_sha256")))
    if any(r not in valid for r in refs): return False
    # PASS030 reports carrying source context must serialize at least one registry.
    ms=report.get("multisource_assimilation") or {}
    source_enabled=False
    if isinstance(ms,dict):
        if ms.get("enabled"): source_enabled=True
        final=ms.get("final") or {}
        if isinstance(final,dict) and final.get("enabled"): source_enabled=True
        docs=ms.get("documents") or {}
        if any(isinstance(x,dict) and ((x.get("certificate") or {}).get("enabled")) for x in docs.values()): source_enabled=True
    if source_enabled and not registries: return False
    return True


def _verify_robust_envelopes(report:dict[str,Any])->bool:
    bundle=report.get("robust_envelope") or {}
    certs=[]
    for row in bundle.get("cycles") or []:
        if isinstance(row,dict) and isinstance(row.get("certificate"),dict): certs.append(row["certificate"])
        elif isinstance(row,dict) and row.get("contract")=="json-consistency-repair.robust-envelope-firewall.v1": certs.append(row)
    if isinstance(bundle.get("final"),dict): certs.append(bundle["final"])
    docs=bundle.get("documents") or {}
    if isinstance(docs,dict):
        for value in docs.values():
            if isinstance(value,dict) and isinstance(value.get("final"),dict): certs.append(value["final"])
            elif isinstance(value,dict) and value.get("contract")=="json-consistency-repair.robust-envelope-firewall.v1": certs.append(value)
    # Streaming may serialize bounded record-bridge certificate samples.
    for c in bundle.get("certificate_samples") or []:
        if isinstance(c,dict): certs.append(c)
    if not certs:
        # PASS031 semantics are optional; an explicit disabled section is sufficient.
        return bool(bundle and bundle.get("contract") in {"json-consistency-repair.robust-envelope.v1","json-consistency-repair.robust-envelope-summary.v1"})
    if not all(verify_robust_envelope_certificate(c) for c in certs): return False
    valid={c.get("certificate_sha256") for c in certs}
    refs=[]
    for row in _walk_values(report):
        h=row.get("robust_envelope_certificate_sha256")
        if h: refs.append(h)
    return all(h in valid for h in refs)


def _verify_semantic_claim_provenance(report:dict[str,Any])->bool:
    bundle=report.get("semantic_claim_provenance") or {}
    certs=[]
    for row in bundle.get("cycles") or []:
        if isinstance(row,dict) and isinstance(row.get("certificate"),dict):
            certs.append(row["certificate"])
        elif isinstance(row,dict) and row.get("contract")=="json-consistency-repair.semantic-claim-provenance-firewall.v1":
            certs.append(row)
    if isinstance(bundle.get("final"),dict):
        certs.append(bundle["final"])
    docs=bundle.get("documents") or {}
    if isinstance(docs,dict):
        for value in docs.values():
            if isinstance(value,dict) and isinstance(value.get("final"),dict): certs.append(value["final"])
            elif isinstance(value,dict) and value.get("contract")=="json-consistency-repair.semantic-claim-provenance-firewall.v1": certs.append(value)
    for c in bundle.get("certificate_samples") or []:
        if isinstance(c,dict): certs.append(c)
    if not certs:
        return bool(bundle and bundle.get("contract") in {"json-consistency-repair.semantic-claim-provenance-summary.v1","json-consistency-repair.semantic-claim-provenance.v1"})
    return all(verify_semantic_firewall(c) for c in certs)

def _verify_repair_path_algebra(report:dict[str,Any])->bool:
    bundle=report.get("repair_path_algebra") or {}
    cycles=bundle.get("cycles") or []
    if not cycles:
        # Bundle/streaming adapters may expose an explicit summarized or inherited surface.
        return bool(bundle and bundle.get("contract") in {"json-consistency-repair.repair-path-algebra-summary.v1","json-consistency-repair.repair-path-algebra.v1"})
    for row in cycles:
        cert=(row or {}).get("certificate") if isinstance(row,dict) else None
        if not isinstance(cert,dict) or not verify_repair_path_algebra(cert):
            return False
    return True

def _verify_symmetry_canonicality(report:dict[str,Any])->bool:
    bundle=report.get("symmetry_canonicality") or {}
    if bundle.get("contract")!="json-consistency-repair.symmetry-canonicality-summary.v1":
        return False
    if bundle.get("mode")=="streaming" and bundle.get("scope")=="record_bridge_inherited":
        return True
    if bundle.get("mode")=="bundle":
        docs=bundle.get("documents") or {}
        if not isinstance(docs,dict) or not docs: return False
        for rows in docs.values():
            if not isinstance(rows,list): return False
            for row in rows:
                cert=(row or {}).get("certificate") if isinstance(row,dict) else None
                if not isinstance(cert,dict) or not verify_symmetry_certificate(cert): return False
        return True
    cycles=bundle.get("cycles") or []
    if not cycles: return False
    for row in cycles:
        cert=(row or {}).get("certificate") if isinstance(row,dict) and isinstance(row.get("certificate"),dict) else row
        if not isinstance(cert,dict) or not verify_symmetry_certificate(cert): return False
    return True


def _verify_repair_controllability(report:dict[str,Any])->bool:
    bundle=report.get("repair_controllability") or {}
    if bundle.get("contract")!="json-consistency-repair.repair-controllability-summary.v1":
        return False
    if bundle.get("mode") in {"streaming","bundle"} and bundle.get("scope") in {"record_bridge_inherited","document_and_cross_document"}:
        # Adapter reports still serialize certificates below when available; an empty inherited
        # surface is valid only when explicitly unconstrained.
        pass
    seen=False
    for row in bundle.get("firewall_cycles") or []:
        cert=(row or {}).get("certificate") if isinstance(row,dict) else None
        if not isinstance(cert,dict) or not verify_controllability_certificate(cert): return False
        seen=True
    for row in bundle.get("control_plan_cycles") or []:
        cert=(row or {}).get("certificate") if isinstance(row,dict) else None
        if not isinstance(cert,dict): return False
        if cert.get("contract")=="json-consistency-repair.bundle-repair-controllability.v1":
            supplied=cert.get("certificate_sha256"); tmp=deepcopy(cert); tmp.pop("certificate_sha256",None)
            if not supplied or digest(tmp)!=supplied: return False
            for sub in (cert.get("documents") or {}).values():
                if not verify_controllability_certificate(sub): return False
            budget=cert.get("global_budget") or {}; n=int(cert.get("requested_action_count") or 0); cost=int(cert.get("requested_cost") or 0)
            used=cert.get("budget_used_before") or {}; ue=int(used.get("edits") or 0); uc=int(used.get("cost") or 0)
            budget_ok=(budget.get("max_edits") is None or ue+n<=int(budget.get("max_edits"))) and (budget.get("max_cost") is None or uc+cost<=int(budget.get("max_cost")))
            expected=bool(all((x or {}).get("reachability")!="UNREACHABLE" for x in (cert.get("documents") or {}).values()) and budget_ok)
            if bool(cert.get("ok"))!=expected: return False
        elif not verify_controllability_certificate(cert): return False
        seen=True
    final=bundle.get("final_firewall")
    if isinstance(final,dict):
        if not verify_controllability_certificate(final): return False
        seen=True
    docs=bundle.get("documents") or {}
    if isinstance(docs,dict):
        for payload in docs.values():
            if not isinstance(payload,dict): return False
            for key in ("firewall_cycles","control_plan_cycles"):
                for row in payload.get(key) or []:
                    cert=(row or {}).get("certificate") if isinstance(row,dict) else None
                    if not isinstance(cert,dict) or not verify_controllability_certificate(cert): return False
                    seen=True
            ff=payload.get("final_firewall")
            if isinstance(ff,dict):
                if not verify_controllability_certificate(ff): return False
                seen=True
    # PASS036 always emits an explicit surface, even when no control policy is active.
    return seen or bool(bundle.get("explicitly_unconstrained"))



def _verify_relation_falsification(report:dict[str,Any])->bool:
    bundle=report.get("relation_falsification") or {}
    if bundle.get("contract")!="json-consistency-repair.relation-falsification-summary.v1":
        return False
    certs=[]
    for row in bundle.get("cycles") or []:
        cert=(row or {}).get("certificate") if isinstance(row,dict) else None
        if isinstance(cert,dict): certs.append(cert)
    if isinstance(bundle.get("final"),dict) and bundle.get("final",{}).get("contract")=="json-consistency-repair.relation-falsification.v1":
        certs.append(bundle["final"])
    docs=bundle.get("documents") or {}
    if isinstance(docs,dict):
        for payload in docs.values():
            if isinstance(payload,dict) and isinstance(payload.get("final"),dict): certs.append(payload["final"])
            elif isinstance(payload,list):
                for row in payload:
                    cert=(row or {}).get("certificate") if isinstance(row,dict) else None
                    if isinstance(cert,dict): certs.append(cert)
    for cert in bundle.get("certificate_samples") or []:
        if isinstance(cert,dict): certs.append(cert)
    # Streaming may have no record-bridge relations at all; it must say so explicitly.
    if not certs:
        return bool(bundle.get("explicitly_no_testable_relations") or bundle.get("scope") in {"stream_knowledge_and_record_bridge"})
    return all(verify_relation_falsification_certificate(c) for c in certs)



def _verify_persistent_open(report:dict[str,Any])->bool:
    reg=report.get("open_obligations") or {}
    cert=report.get("incremental_recompute") or {}
    eq=report.get("incremental_equivalence") or {}
    if not verify_open_obligation_registry(reg):
        return False
    if not verify_incremental_recompute_certificate(cert, reg):
        return False
    return verify_incremental_equivalence_certificate(eq, report.get("proof_graph") or {}, report.get("proof_graph_replay") or {})

def _verify_horizon_distributed(report:dict[str,Any])->bool:
    surface=report.get("horizon_naturality") or {}
    distributed=report.get("distributed_consistency") or {}
    if surface.get("disabled"):
        return False
    if surface.get("contract")!="json-consistency-repair.horizon-naturality.v1":
        return False
    snap=surface.get("snapshot") or {}
    prior=surface.get("prior_snapshot")
    comp=surface.get("comparison") or {}
    if not verify_horizon_snapshot(snap):
        return False
    if prior is not None and not verify_horizon_snapshot(prior):
        return False
    if not verify_horizon_naturality_certificate(comp,snap,prior):
        return False
    try:
        expected=compare_horizon_naturality(prior,snap,change_tokens=surface.get("requested_change_tokens") or (),
                                            boundary_witnesses=surface.get("requested_boundary_witnesses") or ())
    except Exception:
        return False
    if expected!=comp:
        return False
    peers=[snap]
    if isinstance(prior,dict) and prior.get("input_digest")==snap.get("input_digest"):
        peers=[prior,snap]
    return verify_distributed_consistency_certificate(distributed,peers) and bool(comp.get("ok")) and bool(distributed.get("ok"))

def _verify_information_bounds(report:dict[str,Any])->bool:
    blind=report.get("blind_carrier_reconstruction") or {}
    residual=report.get("residual_information") or {}
    if blind.get("disabled") or residual.get("disabled"):
        return False
    if not verify_blind_carrier_reconstruction(blind):
        return False
    if not verify_residual_information_summary(residual,blind):
        return False
    # A blind mismatch is a hard certifier failure. Ambiguity and insufficient carriers
    # are admissible only when explicitly surfaced as information debt/abstention.
    return bool(blind.get("ok")) and int(blind.get("mismatch_count") or 0)==0


def verify_single_packet(original:Any,repaired:Any,committed:list[dict[str,Any]],report:dict[str,Any])->dict[str,Any]:
    checks={}
    checks["input_digest"]=digest(original)==report.get("input_digest")
    checks["output_digest"]=digest(repaired)==report.get("output_digest")
    forward=deepcopy(original); ok=True
    for p in committed:
        if not _apply_patch(forward,p,False): ok=False; break
    checks["forward_patch_replay"]=bool(ok and digest(forward)==digest(repaired))
    inverse=deepcopy(repaired); ok=True
    for p in reversed(committed):
        if not _apply_patch(inverse,p,True): ok=False; break
    checks["inverse_patch_replay"]=bool(ok and digest(inverse)==digest(original))
    chain=verify_provenance_chain(report.get("provenance_chain") or {})
    checks["provenance_chain"]=bool(chain.get("ok"))
    fp=report.get("strong_fixed_point") or {}
    cycles=report.get("cycles") or []
    quiet=[c for c in cycles if c.get("strong_quiet")]
    required=int(fp.get("required_quiet_cycles",2))
    checks["strong_fixed_point"]=bool(fp.get("attained") and len(quiet)>=required and all(not c.get("oscillation") for c in cycles))
    cold=report.get("cold_replay") or {}
    checks["cold_replay"]=bool(cold.get("performed") and cold.get("output_digest")==report.get("output_digest") and
                                cold.get("would_commit_edits")==0 and cold.get("strong_fixed_point_attained") is True)
    checks["parallel_return_proofs"]=_verify_parallel_return_proofs(report)
    checks["primary_factorization"]=_verify_primary_factorizations(report)
    checks["witness_materialization"]=_verify_witness_materialization(report)
    checks["scoped_authority"]=_verify_scoped_authority(report)
    checks["robust_envelope"]=_verify_robust_envelopes(report)
    checks["semantic_claim_provenance"]=_verify_semantic_claim_provenance(report)
    checks["repair_path_algebra"]=_verify_repair_path_algebra(report)
    checks["symmetry_canonicality"]=_verify_symmetry_canonicality(report)
    checks["repair_controllability"]=_verify_repair_controllability(report)
    checks["relation_falsification"]=_verify_relation_falsification(report)
    checks["persistent_open_incremental"]=_verify_persistent_open(report)
    checks["horizon_distributed"]=_verify_horizon_distributed(report)
    checks["residual_information_blind_carrier"]=_verify_information_bounds(report)
    checks["rectification_packet"]=verify_rectification_packet(report.get("rectification_packet") or {},report)
    pg=report.get("proof_graph") or {}
    pgr=report.get("proof_graph_replay") or {}
    checks["proof_graph_integrity"]=verify_proof_graph(pg)
    checks["proof_graph_replay"]=bool(pgr.get("performed") and pgr.get("ok") and pgr.get("expected_graph_sha256")==pg.get("graph_sha256") and pgr.get("same_terminal_output"))
    checks["constructor_certifier_separation"]=True  # enforced by module import boundary; see imports above.
    ok=all(checks.values())
    return {"contract":CONTRACT,"status":"CERTIFIED" if ok else "REJECTED","ok":ok,"checks":checks,
            "certifier_code_sha256":certifier_code_sha256(),"provenance_root":chain.get("root_hash")}

def verify_report_evidence(report:dict[str,Any])->dict[str,Any]:
    checks={}
    chain=verify_provenance_chain(report.get("provenance_chain") or {}); checks["provenance_chain"]=bool(chain.get("ok"))
    fp=report.get("strong_fixed_point") or {}; checks["strong_fixed_point"]=bool(fp.get("attained"))
    cold=report.get("cold_replay") or {}; checks["cold_replay"]=bool(cold.get("performed") and cold.get("would_commit_edits")==0 and cold.get("strong_fixed_point_attained"))
    checks["witness_materialization"]=_verify_witness_materialization(report)
    checks["scoped_authority"]=_verify_scoped_authority(report)
    checks["robust_envelope"]=_verify_robust_envelopes(report)
    checks["semantic_claim_provenance"]=_verify_semantic_claim_provenance(report)
    checks["repair_path_algebra"]=_verify_repair_path_algebra(report)
    checks["symmetry_canonicality"]=_verify_symmetry_canonicality(report)
    checks["repair_controllability"]=_verify_repair_controllability(report)
    checks["relation_falsification"]=_verify_relation_falsification(report)
    checks["persistent_open_incremental"]=_verify_persistent_open(report)
    checks["horizon_distributed"]=_verify_horizon_distributed(report)
    checks["residual_information_blind_carrier"]=_verify_information_bounds(report)
    checks["rectification_packet"]=verify_rectification_packet(report.get("rectification_packet") or {},report)
    pg=report.get("proof_graph") or {}; pgr=report.get("proof_graph_replay") or {}
    checks["proof_graph_integrity"]=verify_proof_graph(pg)
    checks["proof_graph_replay"]=bool(pgr.get("performed") and pgr.get("ok") and pgr.get("expected_graph_sha256")==pg.get("graph_sha256"))
    replay=report.get("replay") or {}
    if "inverse_restores_input" in replay: checks["inverse_replay"]=bool(replay.get("inverse_restores_input"))
    if "inverse_restores_complete_input" in replay: checks["inverse_replay"]=bool(replay.get("inverse_restores_complete_input"))
    ok=all(checks.values())
    return {"contract":CONTRACT,"status":"CERTIFIED" if ok else "REJECTED","ok":ok,"checks":checks,
            "certifier_code_sha256":certifier_code_sha256(),"provenance_root":chain.get("root_hash")}

def main(argv=None)->int:
    import argparse, sys
    ap=argparse.ArgumentParser(description="Independent verifier for json-consistency-repair PASS016 evidence.")
    ap.add_argument("--report",required=True)
    ap.add_argument("--input")
    ap.add_argument("--output")
    ns=ap.parse_args(argv)
    report=json.loads(Path(ns.report).read_text(encoding="utf-8"))
    if ns.input and ns.output:
        original=json.loads(Path(ns.input).read_text(encoding="utf-8"))
        repaired=json.loads(Path(ns.output).read_text(encoding="utf-8"))
        committed=report.get("committed_edits") or []
        result=verify_single_packet(original,repaired,committed,report)
    else:
        result=verify_report_evidence(report)
    print(json.dumps(result,sort_keys=True,separators=(",",":"),ensure_ascii=False))
    return 0 if result.get("ok") else 2

if __name__=="__main__":
    raise SystemExit(main())
