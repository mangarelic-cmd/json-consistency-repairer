from __future__ import annotations
from copy import deepcopy
from typing import Any
from .models import digest

CONTRACT = "json-consistency-repair.rectification-packet.v1"
SEAL_CONTRACT = "json-consistency-repair.rectification-packet-seal.v1"

# Stable logical surface names.  Each surface points to a serialized report section;
# large evidence stays in one place while this packet provides a complete canonical index.
SURFACE_PATHS = (
    ("typed_constraints", ("typed_constraint_ir",)),
    ("terminal_registry", ("terminal_registry",)),
    ("constraint_graph", ("constraint_graph",)),
    ("logic", ("logic_summary",)),
    ("conservation", ("conservation_summary",)),
    ("moments", ("moment_distribution_summary",)),
    ("system_graph", ("system_graph_summary",)),
    ("causal_root", ("causal_root_analysis",)),
    ("federation", ("federation_summary",)),
    ("sources", ("multisource_assimilation",)),
    ("boundaries", ("boundary_calculus",)),
    ("parallel_routes", ("parallel_exact_minimum_routes",)),
    ("primary_factorization", ("primary_factorization", "cross_document_minimal_transfer", "record_bridge_summary")),
    ("materialization", ("witness_materialization",)),
    ("scoped_authority", ("scoped_authority",)),
    ("evidence_poisoning", ("evidence_poisoning_firewall",)),
    ("robust_envelope", ("robust_envelope",)),
    ("semantic_claim_provenance", ("semantic_claim_provenance",)),
    ("typed_expression_ir", ("typed_expression_ir",)),
    ("repair_path_algebra", ("repair_path_algebra",)),
    ("symmetry_canonicality", ("symmetry_canonicality",)),
    ("repair_controllability", ("repair_controllability",)),
    ("relation_falsification", ("relation_falsification",)),
    ("open_obligations", ("open_obligations",)),
    ("incremental_recompute", ("incremental_recompute",)),
    ("incremental_equivalence", ("incremental_equivalence",)),
    ("horizon_naturality", ("horizon_naturality",)),
    ("distributed_consistency", ("distributed_consistency",)),
    ("residual_information", ("residual_information",)),
    ("blind_carrier_reconstruction", ("blind_carrier_reconstruction",)),
    ("q_descent", ("dynamic_q_descent",)),
    ("knowledge", ("knowledge_ledger",)),
    ("relations", ("relations", "cross_document_relations", "knowledge_ledger")),
    ("provenance", ("provenance_chain",)),
    ("proof_graph", ("proof_graph",)),
    ("proof_graph_replay", ("proof_graph_replay",)),
    ("replay", ("replay", "transaction")),
    ("cold_replay", ("cold_replay",)),
    ("strong_fixed_point", ("strong_fixed_point",)),
)


def _shape(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return {"kind": "object", "members": len(value)}
    if isinstance(value, list):
        return {"kind": "array", "items": len(value)}
    if value is None:
        return {"kind": "null"}
    return {"kind": type(value).__name__}


def _commit(report: dict[str, Any], logical_name: str, candidates: tuple[str, ...]) -> dict[str, Any]:
    selected = next((k for k in candidates if k in report), None)
    if selected is None:
        return {
            "logical_name": logical_name,
            "state": "NOT_EMITTED",
            "report_path": None,
            "sha256": None,
            "shape": None,
        }
    value = report.get(selected)
    if value is None:
        return {
            "logical_name": logical_name,
            "state": "EXPLICIT_NULL",
            "report_path": selected,
            "sha256": digest(None),
            "shape": _shape(None),
        }
    return {
        "logical_name": logical_name,
        "state": "PRESENT",
        "report_path": selected,
        "sha256": digest(value),
        "shape": _shape(value),
    }


def _candidate_event(candidate: Any) -> dict[str, Any] | None:
    if not isinstance(candidate, dict):
        return None
    c = candidate.get("candidate") if isinstance(candidate.get("candidate"), dict) else candidate
    if not isinstance(c, dict):
        return None
    return {
        "candidate_id": c.get("candidate_id"),
        "analyzer": c.get("analyzer"),
        "operation": c.get("operation"),
        "path": c.get("path"),
        "new_value_sha256": digest(c.get("new_value")) if "new_value" in c else None,
        "acceptance": candidate.get("acceptance") if candidate is not c else None,
        "solver_status": candidate.get("solver_status") if candidate is not c else None,
        "return_proof_sha256": candidate.get("return_proof_sha256") if candidate is not c else None,
    }


def _cycle_ledger(report: dict[str, Any]) -> dict[str, Any]:
    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    for cyc in report.get("cycles") or []:
        if not isinstance(cyc, dict):
            continue
        cycle = cyc.get("cycle")
        for row in cyc.get("accepted") or []:
            event = _candidate_event(row)
            if event is not None:
                event["cycle"] = cycle
                accepted.append(event)
        for row in cyc.get("rejected") or []:
            if not isinstance(row, dict):
                continue
            rejected.append({
                "cycle": cycle,
                "reason": row.get("reason"),
                "solver_status": row.get("solver_status"),
                "candidate_digest": row.get("candidate_digest"),
                "return_terminal_digest": row.get("return_terminal_digest"),
                "event_sha256": digest(row),
            })
    return {
        "accepted": accepted,
        "rejected": rejected,
        "accepted_count": len(accepted),
        "rejected_count": len(rejected),
    }


def _applied_chain(report: dict[str, Any]) -> dict[str, Any]:
    if isinstance(report.get("committed_edits"), list):
        chain = report.get("committed_edits") or []
        return {"kind": "single_patch_chain", "count": len(chain), "sha256": digest(chain)}
    if isinstance(report.get("committed_patch_set"), list):
        chain = report.get("committed_patch_set") or []
        return {"kind": "bundle_patch_chain", "count": len(chain), "sha256": digest(chain)}
    # Streaming deliberately does not retain an unbounded in-memory patch list.
    if "committed_edits" in report:
        return {
            "kind": "streaming_disk_journal",
            "count": int(report.get("committed_edits") or 0),
            "sha256": digest(report.get("record_bridge_execution") or {}),
            "memory_bounded": True,
        }
    return {"kind": "NOT_EMITTED", "count": None, "sha256": None}


def _remaining(report: dict[str, Any]) -> dict[str, Any]:
    rows = report.get("remaining_issues")
    if isinstance(rows, list):
        compact = []
        for row in rows:
            if isinstance(row, dict):
                compact.append({
                    "analyzer": row.get("analyzer"), "code": row.get("code"),
                    "path": row.get("path"), "severity": row.get("severity"),
                    "repairable": row.get("repairable"), "issue_sha256": digest(row),
                })
            else:
                compact.append({"issue_sha256": digest(row)})
        return {"state": "NONE_AFTER_FIXED_POINT" if not rows else "REMAINING_VISIBLE",
                "count": len(rows), "issues": compact, "sha256": digest(rows)}
    if isinstance(rows, int):
        # Streaming reports only the bounded aggregate count.
        return {"state": "NONE_AFTER_FIXED_POINT" if rows == 0 else "REMAINING_VISIBLE_BOUNDED_AGGREGATE",
                "count": rows, "issues": None, "sha256": digest(rows)}
    return {"state": "NOT_EMITTED", "count": None, "issues": None, "sha256": None}


def _next_objects(report: dict[str, Any], remaining: dict[str, Any]) -> dict[str, Any]:
    if remaining.get("state") == "NONE_AFTER_FIXED_POINT":
        return {"state": "NONE_AFTER_FIXED_POINT", "objects": []}
    objects = []
    for issue in remaining.get("issues") or []:
        objects.append({
            "kind": "REMAINING_ISSUE_TERMINAL",
            "path": issue.get("path"), "analyzer": issue.get("analyzer"), "code": issue.get("code"),
            "repairable": issue.get("repairable"), "source_issue_sha256": issue.get("issue_sha256"),
        })
    mat = report.get("witness_materialization") or {}
    final = mat.get("final") if isinstance(mat, dict) else None
    for terminal in ((final or {}).get("terminals") or []) if isinstance(final, dict) else []:
        if isinstance(terminal, dict) and terminal.get("status") not in {None, "MATERIALIZED_EXACT"}:
            objects.append({
                "kind": "MATERIALIZATION_GATE",
                "terminal_id": terminal.get("terminal_id"), "path": terminal.get("target_path"),
                "status": terminal.get("status"),
            })
    return {"state": "EXECUTABLE_OBJECTS_PRESENT" if objects else "VISIBLE_BUT_NO_EXECUTABLE_OBJECT",
            "objects": objects, "count": len(objects)}


def _packet_payload(packet: dict[str, Any]) -> dict[str, Any]:
    return {k: deepcopy(v) for k, v in packet.items() if k not in {"packet_sha256", "certifier_seal"}}


def compile_rectification_packet(report: dict[str, Any]) -> dict[str, Any]:
    surfaces = [_commit(report, name, paths) for name, paths in SURFACE_PATHS]
    surfaces.sort(key=lambda x: x["logical_name"])
    section_root = digest({x["logical_name"]: {k: x[k] for k in ("state", "report_path", "sha256", "shape")} for x in surfaces})
    cycle_ledger = _cycle_ledger(report)
    remaining = _remaining(report)
    report_contract = report.get("report_contract") or {}
    packet = {
        "contract": CONTRACT,
        "schema_version": "1.0",
        "engine": report.get("engine"),
        "version": report.get("version"),
        "mode": report.get("mode", "single"),
        "terminal": {
            "status": report_contract.get("status"),
            "input_digest": report.get("input_digest"),
            "output_digest": report.get("output_digest"),
            "strong_fixed_point_attained": bool((report.get("strong_fixed_point") or {}).get("attained")),
            "proof_graph_sha256": (report.get("proof_graph") or {}).get("graph_sha256"),
            "proof_graph_replay_status": (report.get("proof_graph_replay") or {}).get("status"),
        },
        "applied_chain": _applied_chain(report),
        "decision_ledger": cycle_ledger,
        "remaining": remaining,
        "next_executable_objects": _next_objects(report, remaining),
        "surfaces": surfaces,
        "section_root_sha256": section_root,
        "surface_count": len(surfaces),
        "present_surface_count": sum(1 for x in surfaces if x["state"] == "PRESENT"),
        "absence_semantics": "NOT_EMITTED_IS_NOT_FALSE_ZERO_OR_IMPOSSIBLE",
        "hash_exclusions": ["packet_sha256", "certifier_seal"],
        "certification_state": "PENDING_INDEPENDENT_VERIFICATION",
    }
    packet["packet_sha256"] = digest(_packet_payload(packet))
    return packet


def verify_rectification_packet(packet: dict[str, Any], report: dict[str, Any] | None = None) -> bool:
    if not isinstance(packet, dict) or packet.get("contract") != CONTRACT:
        return False
    supplied = packet.get("packet_sha256")
    hash_payload = _packet_for_hash_with_poststate(packet) if packet.get("certifier_seal") else _packet_payload(packet)
    if not supplied or digest(hash_payload) != supplied:
        return False
    surfaces = packet.get("surfaces")
    if not isinstance(surfaces, list):
        return False
    names = [x.get("logical_name") for x in surfaces if isinstance(x, dict)]
    expected_names = sorted(name for name, _ in SURFACE_PATHS)
    if sorted(names) != expected_names or len(names) != len(set(names)):
        return False
    normalized = {}
    for row in surfaces:
        if not isinstance(row, dict) or row.get("state") not in {"PRESENT", "EXPLICIT_NULL", "NOT_EMITTED"}:
            return False
        normalized[row["logical_name"]] = {k: row.get(k) for k in ("state", "report_path", "sha256", "shape")}
    if digest(normalized) != packet.get("section_root_sha256"):
        return False
    if report is not None:
        expected = compile_rectification_packet(report)
        # Compare all pre-seal semantics, not merely the packet hash copied into the report.
        if expected.get("packet_sha256") != supplied:
            return False
        if expected.get("section_root_sha256") != packet.get("section_root_sha256"):
            return False
    return True


def seal_rectification_packet(packet: dict[str, Any], final_certification: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
    out = deepcopy(packet)
    cert_payload = {
        "contract": SEAL_CONTRACT,
        "packet_sha256": out.get("packet_sha256"),
        "certifier_status": final_certification.get("status"),
        "certifier_ok": final_certification.get("ok"),
        "certifier_code_sha256": final_certification.get("certifier_code_sha256"),
        "provenance_root": final_certification.get("provenance_root"),
        "proof_graph_sha256": (report.get("proof_graph") or {}).get("graph_sha256"),
        "proof_graph_replay_ok": bool((report.get("proof_graph_replay") or {}).get("ok")),
    }
    cert_payload["seal_sha256"] = digest({k: v for k, v in cert_payload.items() if k != "seal_sha256"})
    out["certifier_seal"] = cert_payload
    out["certification_state"] = "INDEPENDENTLY_CERTIFIED" if final_certification.get("ok") else "CERTIFICATION_REJECTED"
    # certification_state is intentionally post-hash state and therefore excluded from semantic packet hash
    # by reverting it for hash verification via a stable rule below.
    return out


def _packet_for_hash_with_poststate(packet: dict[str, Any]) -> dict[str, Any]:
    tmp = deepcopy(packet)
    tmp.pop("packet_sha256", None); tmp.pop("certifier_seal", None)
    if tmp.get("certification_state") in {"INDEPENDENTLY_CERTIFIED", "CERTIFICATION_REJECTED"}:
        tmp["certification_state"] = "PENDING_INDEPENDENT_VERIFICATION"
    return tmp


def verify_rectification_packet_final(packet: dict[str, Any], report: dict[str, Any] | None = None) -> bool:
    if not isinstance(packet, dict) or packet.get("contract") != CONTRACT:
        return False
    if digest(_packet_for_hash_with_poststate(packet)) != packet.get("packet_sha256"):
        return False
    # Verify surface binding directly against the report without recompiling post-certification fields.
    if report is not None:
        for row in packet.get("surfaces") or []:
            if not isinstance(row, dict): return False
            path = row.get("report_path")
            if row.get("state") == "NOT_EMITTED":
                if path is not None: return False
                continue
            if path not in report: return False
            value = report.get(path)
            if row.get("state") == "EXPLICIT_NULL" and value is not None: return False
            if row.get("state") == "PRESENT" and value is None: return False
            if digest(value) != row.get("sha256"): return False
    seal = packet.get("certifier_seal")
    if not isinstance(seal, dict) or seal.get("contract") != SEAL_CONTRACT:
        return False
    if seal.get("packet_sha256") != packet.get("packet_sha256"):
        return False
    supplied = seal.get("seal_sha256")
    expected = digest({k: v for k, v in seal.items() if k != "seal_sha256"})
    if not supplied or supplied != expected:
        return False
    if report is not None:
        cert = report.get("final_certification") or {}
        if seal.get("certifier_status") != cert.get("status") or bool(seal.get("certifier_ok")) != bool(cert.get("ok")):
            return False
        if seal.get("certifier_code_sha256") != cert.get("certifier_code_sha256"):
            return False
        if seal.get("proof_graph_sha256") != (report.get("proof_graph") or {}).get("graph_sha256"):
            return False
        if bool(seal.get("proof_graph_replay_ok")) != bool((report.get("proof_graph_replay") or {}).get("ok")):
            return False
    return True
