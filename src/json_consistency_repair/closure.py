from __future__ import annotations
from typing import Any
from .provenance_chain import verify_provenance_chain
from .models import digest

CONTRACT="json-consistency-repair.third-series-closure.v1"
FOURTH_CONTRACT="json-consistency-repair.fourth-series-closure.v1"


def _federation_fixed(report:dict[str,Any])->bool:
    fed=report.get("federation_summary") or {}
    mode=fed.get("mode")
    if mode=="streaming":
        final=fed.get("final") or {}
        m2=final.get("mode_ii") or {}
        return bool(m2.get("fixed_point_attained",True))
    if mode=="bundle":
        docs=fed.get("documents") or {}
        return all(bool(((v.get("mode_ii") or {}).get("fixed_point_attained",True))) for v in docs.values())
    final=fed.get("final") or {}
    return bool(((final.get("mode_ii") or {}).get("fixed_point_attained",True)))


def compile_third_series_closure(report:dict[str,Any])->dict[str,Any]:
    """Reconcile the independent closure evidence already materialized by the engine."""
    cold=report.get("cold_replay") or {}
    fp=report.get("strong_fixed_point") or {}
    cert=report.get("final_certification") or {}
    chain=verify_provenance_chain(report.get("provenance_chain") or {})
    checks={
        "strong_fixed_point": bool(fp.get("attained") and not fp.get("oscillation_detected")),
        "cold_zero_edit": bool(cold.get("performed") and int(cold.get("would_commit_edits",-1))==0 and cold.get("same_output",True)),
        "independent_certifier": bool(cert.get("ok")),
        "provenance_chain": bool(chain.get("ok")),
        "federation_fixed_point": _federation_fixed(report),
        "proof_graph_exact": bool((report.get("proof_graph_replay") or {}).get("ok")),
    }
    mode=report.get("mode","single")
    if mode=="streaming":
        reg=report.get("disk_backed_registry") or {}
        bridge=report.get("record_bridge_summary") or {}
        checks["disk_registry_exact"]=bool(reg.get("exact") or reg.get("backend")=="disabled")
        checks["record_bridge_terminal_quiet"]=not bridge.get("enabled") or int(bridge.get("remaining_inner_issues",0))==0
    elif mode=="bundle":
        checks["multisource_reconciled"]="multisource_assimilation" in report
        checks["inverse_transaction"]=bool((report.get("transaction") or {}).get("inverse_restores_bundle"))
    else:
        checks["multisource_reconciled"]="multisource_assimilation" in report
        checks["inverse_transaction"]=bool((report.get("replay") or {}).get("inverse_restores_input"))
    ok=all(checks.values())
    return {"contract":CONTRACT,"status":"CLOSED" if ok else "OPEN","ok":ok,"checks":checks,
            "provenance_root":chain.get("root_hash")}


def _has_contract(report:dict[str,Any], key:str, prefixes:tuple[str,...])->bool:
    value=report.get(key)
    if not isinstance(value,dict): return False
    contract=str(value.get("contract") or "")
    return any(contract.startswith(p) for p in prefixes)


def compile_fourth_series_closure(report:dict[str,Any])->dict[str,Any]:
    """PASS032 reconciliation gate for PASS025..PASS032.

    It does not infer missing evidence.  Every fourth-series layer is checked through the
    serialized evidence or the independent certifier verdict already present in the report.
    """
    from .rectification_packet import verify_rectification_packet_final
    cert=report.get("final_certification") or {}
    cert_checks=cert.get("checks") or {}
    third=report.get("third_series_closure") or {}
    packet=report.get("rectification_packet") or {}
    checks={
        "third_series_closed": bool(third.get("ok")),
        "pass025_boundary_calculus": _has_contract(report,"boundary_calculus",("json-consistency-repair.boundary-calculus",)),
        "pass026_parallel_exact_routes": (
            _has_contract(report,"parallel_exact_minimum_routes",("json-consistency-repair.parallel-exact-routes",))
            or report.get("mode")=="streaming" and isinstance(((report.get("record_bridge_summary") or {}).get("parallel_exact_minimum_routes")),dict)
        ),
        "pass027_primary_factorization": (
            _has_contract(report,"primary_factorization",("json-consistency-repair.primary-factorization",))
            or bool((((report.get("cross_document_minimal_transfer") or {}).get("primary_factorization") or {}).get("lossless")))
            or report.get("mode")=="streaming" and isinstance(report.get("record_bridge_summary"),dict)
        ),
        "pass028_proof_graph_replay": bool((report.get("proof_graph_replay") or {}).get("ok") and cert_checks.get("proof_graph_integrity",True)),
        "pass029_witness_materialization": _has_contract(report,"witness_materialization",("json-consistency-repair.witness-materialization",)),
        "pass030_scoped_authority": bool(cert_checks.get("scoped_authority")),
        "pass030_evidence_poisoning_surface": "evidence_poisoning_firewall" in report,
        "pass031_robust_envelope": bool(cert_checks.get("robust_envelope")),
        "pass032_rectification_packet": verify_rectification_packet_final(packet,report),
        "independent_certifier": bool(cert.get("ok") and cert_checks.get("rectification_packet")),
        "zero_edit_cold_replay": bool((report.get("cold_replay") or {}).get("performed") and int((report.get("cold_replay") or {}).get("would_commit_edits",-1))==0),
        "no_oscillation": not bool((report.get("strong_fixed_point") or {}).get("oscillation_detected")),
    }
    ok=all(checks.values())
    return {
        "contract":FOURTH_CONTRACT,
        "status":"CLOSED" if ok else "OPEN",
        "ok":ok,
        "series":"PASS025-PASS032",
        "checks":checks,
        "rectification_packet_sha256":packet.get("packet_sha256"),
        "proof_graph_sha256":(report.get("proof_graph") or {}).get("graph_sha256"),
        "provenance_root":(report.get("provenance_chain") or {}).get("root_hash"),
        "remaining_substantive_passes":0 if ok else 1,
    }

FIFTH_PROGRESS_CONTRACT="json-consistency-repair.fifth-series-progress.v1"


def compile_fifth_series_progress(report:dict[str,Any], current_pass:int=40)->dict[str,Any]:
    """Progress ledger for the PASS033..PASS040 fifth series.

    The object is intentionally non-closing before PASS040. Each completed pass requires its
    serialized surface and, where applicable, an independent certifier check; passing a later
    current_pass number alone never increments progress.
    """
    sem=report.get("semantic_claim_provenance") or {}
    cert=report.get("final_certification") or {}
    cert_checks=cert.get("checks") or {}
    mode=report.get("mode","single")
    if mode=="bundle":
        docs=sem.get("documents") or {}
        semantic_present=isinstance(docs,dict) and bool(docs) and all(isinstance((v or {}).get("final"),dict) for v in docs.values())
    elif mode=="streaming":
        semantic_present=isinstance(sem.get("final"),dict)
    else:
        semantic_present=isinstance(sem.get("final"),dict)
    expression=report.get("typed_expression_ir") or {}
    algebra=report.get("repair_path_algebra") or {}
    pass033_checks={
        "fourth_series_remains_closed": bool((report.get("fourth_series_closure") or {}).get("ok")),
        "pass033_semantic_claim_provenance_surface": bool(semantic_present),
        "pass033_independent_semantic_certifier": bool(cert.get("ok") and cert_checks.get("semantic_claim_provenance")),
    }
    pass033=all(pass033_checks.values())
    pass034_checks={
        "pass034_typed_expression_ir_surface": bool(str(expression.get("contract") or "").startswith("json-consistency-repair.typed-expression-ir")),
        "pass034_repair_path_algebra_surface": bool(str(algebra.get("contract") or "").startswith("json-consistency-repair.repair-path-algebra")),
        "pass034_independent_algebra_certifier": bool(cert.get("ok") and cert_checks.get("repair_path_algebra")),
    }
    pass034=bool(pass033 and current_pass>=34 and all(pass034_checks.values()))
    symmetry=report.get("symmetry_canonicality") or {}
    pass035_checks={
        "pass035_symmetry_canonicality_surface": bool(str(symmetry.get("contract") or "").startswith("json-consistency-repair.symmetry-canonicality-summary")),
        "pass035_independent_symmetry_certifier": bool(cert.get("ok") and cert_checks.get("symmetry_canonicality")),
    }
    pass035=bool(pass034 and current_pass>=35 and all(pass035_checks.values()))
    control=report.get("repair_controllability") or {}
    pass036_checks={
        "pass036_repair_controllability_surface": bool(str(control.get("contract") or "").startswith("json-consistency-repair.repair-controllability-summary")),
        "pass036_independent_controllability_certifier": bool(cert.get("ok") and cert_checks.get("repair_controllability")),
    }
    pass036=bool(pass035 and current_pass>=36 and all(pass036_checks.values()))
    falsification=report.get("relation_falsification") or {}
    pass037_checks={
        "pass037_relation_falsification_surface": bool(str(falsification.get("contract") or "").startswith("json-consistency-repair.relation-falsification-summary")),
        "pass037_independent_falsification_certifier": bool(cert.get("ok") and cert_checks.get("relation_falsification")),
    }
    pass037=bool(pass036 and current_pass>=37 and all(pass037_checks.values()))
    open_reg=report.get("open_obligations") or {}
    incremental=report.get("incremental_recompute") or {}
    incremental_equivalence=report.get("incremental_equivalence") or {}
    pass038_checks={
        "pass038_open_obligation_registry_surface": bool(str(open_reg.get("contract") or "").startswith("json-consistency-repair.open-obligation-registry")),
        "pass038_incremental_recompute_surface": bool(str(incremental.get("contract") or "").startswith("json-consistency-repair.incremental-recompute")),
        "pass038_incremental_equivalence_surface": bool(str(incremental_equivalence.get("contract") or "").startswith("json-consistency-repair.incremental-equivalence")),
        "pass038_independent_incremental_certifier": bool(cert.get("ok") and cert_checks.get("persistent_open_incremental")),
    }
    pass038=bool(pass037 and current_pass>=38 and all(pass038_checks.values()))
    horizon=report.get("horizon_naturality") or {}
    distributed=report.get("distributed_consistency") or {}
    hcomp=horizon.get("comparison") or {}
    pass039_checks={
        "pass039_horizon_naturality_surface": bool(str(horizon.get("contract") or "").startswith("json-consistency-repair.horizon-naturality") and hcomp.get("ok") is True),
        "pass039_distributed_consistency_surface": bool(str(distributed.get("contract") or "").startswith("json-consistency-repair.distributed-consistency") and distributed.get("ok") is True),
        "pass039_independent_horizon_distributed_certifier": bool(cert.get("ok") and cert_checks.get("horizon_distributed")),
    }
    pass039=bool(pass038 and current_pass>=39 and all(pass039_checks.values()))
    residual=report.get("residual_information") or {}
    blind=report.get("blind_carrier_reconstruction") or {}
    packet=report.get("rectification_packet") or {}
    surfaces={x.get("logical_name"):x for x in (packet.get("surfaces") or []) if isinstance(x,dict)}
    graph_kinds={str(x.get("kind")) for x in ((report.get("proof_graph") or {}).get("nodes") or []) if isinstance(x,dict)}
    pass040_checks={
        "pass040_residual_information_surface": bool(str(residual.get("contract") or "").startswith("json-consistency-repair.residual-information-summary") and not residual.get("disabled")),
        "pass040_blind_carrier_surface": bool(str(blind.get("contract") or "").startswith("json-consistency-repair.blind-carrier-reconstruction") and blind.get("ok") is True and not blind.get("disabled")),
        "pass040_independent_information_certifier": bool(cert.get("ok") and cert_checks.get("residual_information_blind_carrier")),
        "pass040_packet_reconciliation": bool((surfaces.get("residual_information") or {}).get("state")=="PRESENT" and (surfaces.get("blind_carrier_reconstruction") or {}).get("state")=="PRESENT"),
        "pass040_proof_graph_reconciliation": bool({"RESIDUAL_INFORMATION_BOUND","BLIND_CARRIER_RECONSTRUCTION"}.issubset(graph_kinds)),
    }
    pass040=bool(pass039 and current_pass>=40 and all(pass040_checks.values()))
    checks={**pass033_checks,**pass034_checks,**pass035_checks,**pass036_checks,**pass037_checks,**pass038_checks,**pass039_checks,**pass040_checks}
    completed=(1 if current_pass>=33 and pass033 else 0)+(1 if pass034 else 0)+(1 if pass035 else 0)+(1 if pass036 else 0)+(1 if pass037 else 0)+(1 if pass038 else 0)+(1 if pass039 else 0)+(1 if pass040 else 0)
    closed=bool(current_pass>=40 and completed==8)
    return {
        "contract":FIFTH_PROGRESS_CONTRACT,
        "series":"PASS033-PASS040",
        "current_pass":int(current_pass),
        "status":"CLOSED" if closed else ("IN_PROGRESS" if completed else "OPEN"),
        "checks":checks,
        "completed_substantive_passes":completed,
        "remaining_substantive_passes":8-completed,
        "closed":closed,
    }

FIFTH_CLOSURE_CONTRACT="json-consistency-repair.fifth-series-closure.v1"

def compile_fifth_series_closure(report:dict[str,Any])->dict[str,Any]:
    """PASS040 reconciliation/closure gate for PASS033..PASS040.

    Closure is not inferred from the release number. It consumes the serialized progress
    ledger, independent certifier, proof-graph replay, rectification packet and the new
    information surfaces.
    """
    progress=report.get("fifth_series_progress") or compile_fifth_series_progress(report,40)
    cert=report.get("final_certification") or {}; cc=cert.get("checks") or {}
    cold=report.get("cold_replay") or {}; pgr=report.get("proof_graph_replay") or {}
    horizon=((report.get("horizon_naturality") or {}).get("comparison") or {})
    distributed=report.get("distributed_consistency") or {}
    blind=report.get("blind_carrier_reconstruction") or {}
    packet=report.get("rectification_packet") or {}
    surfaces={x.get("logical_name"):x for x in (packet.get("surfaces") or []) if isinstance(x,dict)}
    required_certifier_checks=(
        "semantic_claim_provenance","repair_path_algebra","symmetry_canonicality",
        "repair_controllability","relation_falsification","persistent_open_incremental",
        "horizon_distributed","residual_information_blind_carrier",
        "rectification_packet","proof_graph_integrity","proof_graph_replay",
    )
    checks={
        "fourth_series_closed": bool((report.get("fourth_series_closure") or {}).get("ok")),
        "progress_8_of_8": bool(progress.get("closed") and progress.get("completed_substantive_passes")==8 and progress.get("remaining_substantive_passes")==0),
        "all_progress_checks": bool(progress.get("checks")) and all(bool(v) for v in (progress.get("checks") or {}).values()),
        "independent_final_certifier": bool(cert.get("ok")),
        "all_fifth_series_certifier_checks": all(bool(cc.get(k)) for k in required_certifier_checks),
        "zero_edit_cold_replay": bool(cold.get("performed") and int(cold.get("would_commit_edits",-1))==0 and cold.get("same_output") is not False),
        "proof_graph_replay_exact": bool(pgr.get("ok") and pgr.get("same_terminal_output") is not False),
        "horizon_has_no_unexplained_drift": bool(horizon.get("ok") and horizon.get("status")!="HORIZON_DRIFT_UNEXPLAINED"),
        "distributed_has_no_conflict": bool(distributed.get("ok") and distributed.get("status")!="DISTRIBUTED_CONFLICT"),
        "blind_reconstruction_has_no_mismatch": bool(blind.get("ok") and int(blind.get("mismatch_count") or 0)==0),
        "pass040_packet_surfaces_present": bool((surfaces.get("residual_information") or {}).get("state")=="PRESENT" and (surfaces.get("blind_carrier_reconstruction") or {}).get("state")=="PRESENT"),
        "strong_fixed_point": bool((report.get("strong_fixed_point") or {}).get("attained") and not (report.get("strong_fixed_point") or {}).get("oscillation_detected")),
    }
    ok=all(checks.values())
    out={
        "contract":FIFTH_CLOSURE_CONTRACT,
        "series":"PASS033-PASS040",
        "status":"CLOSED" if ok else "OPEN",
        "ok":ok,
        "checks":checks,
        "completed_substantive_passes":8 if ok else int(progress.get("completed_substantive_passes") or 0),
        "remaining_substantive_passes":0 if ok else max(0,8-int(progress.get("completed_substantive_passes") or 0)),
        "proof_graph_sha256":(report.get("proof_graph") or {}).get("graph_sha256"),
        "rectification_packet_sha256":packet.get("packet_sha256"),
        "provenance_root":(report.get("provenance_chain") or {}).get("root_hash"),
        "residual_information_sha256":(report.get("residual_information") or {}).get("certificate_sha256"),
        "blind_carrier_sha256":blind.get("certificate_sha256"),
    }
    out["closure_sha256"]=digest(out)
    return out
