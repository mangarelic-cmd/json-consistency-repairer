"""PASS028 — canonical full proof-graph commitment and replay comparison.

The graph is a cryptographic, path-addressed commitment to the complete decision
trace that is relevant to a repair.  It deliberately excludes the final
certifier and the replay verdict itself, preventing recursive/self-referential
certification.
"""
from __future__ import annotations
from copy import deepcopy
from typing import Any
import hashlib, json

CONTRACT = "json-consistency-repair.proof-graph.v1"
REPLAY_CONTRACT = "json-consistency-repair.proof-graph-replay.v1"


def _bytes(v: Any) -> bytes:
    return json.dumps(v, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _sha(v: Any) -> str:
    return hashlib.sha256(_bytes(v)).hexdigest()


def _clean(v: Any) -> Any:
    """Remove fields whose identity is environmental rather than causal."""
    if isinstance(v, dict):
        return {k: _clean(x) for k, x in sorted(v.items())
                if k not in {"input", "output", "report_path", "input_path", "output_path",
                             "certifier_code_sha256"}}
    if isinstance(v, list):
        return [_clean(x) for x in v]
    return v


def _node(nodes: list[dict[str, Any]], *, kind: str, scope: str, identity: str, payload: Any,
          cycle: int | None = None, phase: str | None = None) -> str:
    payload = _clean(payload)
    pd = _sha(payload)
    key = {"kind": kind, "scope": scope, "identity": identity, "cycle": cycle, "phase": phase, "payload_sha256": pd}
    nid = "pg_" + _sha(key)[:24]
    nodes.append({"node_id": nid, **key, "payload": payload})
    return nid


def _edge(edges: list[dict[str, Any]], kind: str, source: str, target: str, *, cycle: int | None = None,
          phase: str | None = None, payload: Any | None = None) -> None:
    row = {"kind": kind, "source": source, "target": target, "cycle": cycle, "phase": phase,
           "payload_sha256": _sha(_clean(payload or {}))}
    row["edge_id"] = "pge_" + _sha(row)[:24]
    edges.append(row)


def _extract_federation(report: dict[str, Any], nodes: list[dict[str, Any]], edges: list[dict[str, Any]], root_id: str) -> None:
    fed = report.get("federation_summary") or {}
    snapshots = list(fed.get("cycles") or [])
    if fed.get("final"):
        snapshots.append({"cycle": "final", "phase": "final", **(fed.get("final") or {})})
    # bundle final may be a document map rather than one federation certificate.
    documents = fed.get("documents") or {}
    for doc, cert in sorted(documents.items()):
        snapshots.append({"cycle": "final", "phase": "final", "document": doc, **(cert or {})})
    for idx, snap in enumerate(snapshots):
        cyc = snap.get("cycle") if isinstance(snap.get("cycle"), int) else None
        phase = str(snap.get("phase") or "") or None
        scope = str(snap.get("document") or report.get("mode") or "single")
        mi = snap.get("mode_i") or {}
        for p in mi.get("packets") or []:
            aid = str(p.get("actor_id", "unknown"))
            nid = _node(nodes, kind="ANALYZER_RESPONSE", scope=scope, identity=aid, payload=p, cycle=cyc, phase=phase)
            _edge(edges, "OBSERVES", root_id, nid, cycle=cyc, phase=phase)
        mii = snap.get("mode_ii") or {}
        for key, kind, ident_key in (("pairwise_objects", "PAIRWISE_OBJECT", "pair_id"),
                                     ("hyperobjects", "HYPEROBJECT", "hyperobject_id"),
                                     ("relations", "FEDERATED_RELATION", "relation_id"),
                                     ("composites", "FEDERATED_COMPOSITE", "relation_id")):
            for obj in mii.get(key) or []:
                ident = str(obj.get(ident_key) or _sha(obj)[:20])
                nid = _node(nodes, kind=kind, scope=scope, identity=ident, payload=obj, cycle=cyc, phase=phase)
                _edge(edges, "FEDERATES", root_id, nid, cycle=cyc, phase=phase)


def compile_proof_graph(report: dict[str, Any]) -> dict[str, Any]:
    """Compile a deterministic proof graph from already-serialized evidence."""
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    mode = str(report.get("mode") or "single")
    inp = str(report.get("input_digest") or "")
    out = str(report.get("output_digest") or "")
    root = _node(nodes, kind="TERMINAL_INPUT", scope=mode, identity=inp, payload={"digest": inp})
    final = _node(nodes, kind="TERMINAL_OUTPUT", scope=mode, identity=out, payload={"digest": out})
    _edge(edges, "TRAJECTORY", root, final)

    # Final relations / cross-document identities / stream knowledge.
    rels = list(report.get("relations") or [])
    if mode == "streaming":
        kr=(report.get("knowledge_ledger") or {}).get("relations") or []
        if isinstance(kr,dict): rels.extend(kr.values())
        else: rels.extend(kr)
    for r in rels:
        ident = str((r.get("relation_id") if isinstance(r, dict) else None) or _sha(r)[:20])
        nid = _node(nodes, kind="RELATION", scope=mode, identity=ident, payload=r)
        _edge(edges, "CONSTRAINS", nid, final)

    # Source authority and identity layers.
    ms = report.get("multisource_assimilation") or {}
    for label, payload in (("multisource_final", ms.get("final")), ("multisource_summary", ms.get("summary")),
                           ("identity_registry", report.get("identity_registry")),
                           ("authority_firewall", report.get("authority_firewall")),
                           ("scoped_authority", report.get("scoped_authority")),
                           ("evidence_poisoning_firewall", report.get("evidence_poisoning_firewall"))):
        if payload not in (None, {}, []):
            nid = _node(nodes, kind="SOURCE_AUTHORITY", scope=mode, identity=label, payload=payload)
            _edge(edges, "AUTHORIZES", nid, final)

    # PASS038 persistent OPEN obligations and targeted invalidation contract.
    for label, payload, kind, edge_kind in (
        ("open_obligations", report.get("open_obligations"), "OPEN_OBLIGATION_REGISTRY", "PERSISTS_OPEN"),
        ("incremental_recompute", report.get("incremental_recompute"), "INCREMENTAL_RECOMPUTE", "INVALIDATES_TARGETED"),
    ):
        if payload not in (None, {}, []):
            nid = _node(nodes, kind=kind, scope=mode, identity=label, payload=payload)
            _edge(edges, edge_kind, root, nid)
            _edge(edges, "CONSTRAINS", nid, final)

    # PASS039 horizon naturality and distributed consistency.
    for label, payload, kind, edge_kind in (
        ("horizon_naturality", report.get("horizon_naturality"), "HORIZON_NATURALITY", "EXTENDS_HORIZON"),
        ("distributed_consistency", report.get("distributed_consistency"), "DISTRIBUTED_CONSISTENCY", "RECONCILES_PARTITIONS"),
    ):
        if payload not in (None, {}, []):
            nid = _node(nodes, kind=kind, scope=mode, identity=label, payload=payload)
            _edge(edges, edge_kind, root, nid)
            _edge(edges, "CONSTRAINS", nid, final)

    # PASS040 residual-information lower bounds and blind-carrier reconstruction.
    for label, payload, kind, edge_kind in (
        ("residual_information", report.get("residual_information"), "RESIDUAL_INFORMATION_BOUND", "BOUNDS_RESIDUAL_INFORMATION"),
        ("blind_carrier_reconstruction", report.get("blind_carrier_reconstruction"), "BLIND_CARRIER_RECONSTRUCTION", "TESTS_BLIND_RECONSTRUCTION"),
    ):
        if payload not in (None, {}, []):
            nid = _node(nodes, kind=kind, scope=mode, identity=label, payload=payload)
            _edge(edges, edge_kind, root, nid)
            _edge(edges, "CONSTRAINS", nid, final)

    # PASS029 minimal-witness materialization: unresolved terminal objects, bounded
    # source searches, gates, exact materializations and provenance digests.
    wm = report.get("witness_materialization") or {}
    for i, row in enumerate(wm.get("cycles") or []):
        cyc = row.get("cycle") if isinstance(row, dict) and isinstance(row.get("cycle"), int) else None
        cert = row.get("certificate") if isinstance(row, dict) else None
        if not isinstance(cert, dict):
            continue
        mscope = str(row.get("document") or mode) if isinstance(row, dict) else mode
        cid = _node(nodes, kind="MATERIALIZATION_CYCLE", scope=mscope, identity=f"materialization:{i}", payload=cert, cycle=cyc)
        _edge(edges, "SEARCHES_WITNESS", root, cid, cycle=cyc)
        for terminal in cert.get("terminals") or []:
            if not isinstance(terminal, dict):
                continue
            tid = _node(nodes, kind="MISSING_WITNESS_TERMINAL", scope=mscope,
                        identity=str(terminal.get("terminal_id") or _sha(terminal)[:20]), payload=terminal, cycle=cyc)
            _edge(edges, "MATERIALIZES", cid, tid, cycle=cyc)
            if terminal.get("status") == "MATERIALIZED_EXACT":
                _edge(edges, "REINJECTS", tid, final, cycle=cyc)
    if wm.get("final") not in (None, {}, []):
        fid = _node(nodes, kind="MATERIALIZATION_FINAL", scope=mode, identity="materialization:final", payload=wm.get("final"))
        _edge(edges, "MATERIALIZATION_GATE", fid, final)

    # Boundary registry/firewall history.
    bc = report.get("boundary_calculus") or {}
    for i, row in enumerate(bc.get("cycles") or []):
        cyc = row.get("cycle") if isinstance(row, dict) and isinstance(row.get("cycle"), int) else None
        phase = str(row.get("phase")) if isinstance(row, dict) and row.get("phase") is not None else None
        nid = _node(nodes, kind="BOUNDARY_STATE", scope=mode, identity=f"boundary:{i}", payload=row, cycle=cyc, phase=phase)
        _edge(edges, "BOUNDS", nid, final, cycle=cyc, phase=phase)
    if bc.get("final") or bc.get("registry"):
        payload = bc.get("final") or bc.get("registry")
        nid = _node(nodes, kind="BOUNDARY_FINAL", scope=mode, identity="boundary:final", payload=payload)
        _edge(edges, "BOUNDS", nid, final)

    # Cycle-level solver, accepted/rejected chain and frontier identities.
    previous = root
    for c in report.get("cycles") or []:
        cyc = c.get("cycle") if isinstance(c.get("cycle"), int) else None
        summary = {k: deepcopy(c.get(k)) for k in (
            "cycle", "digest", "bundle_digest", "input_digest", "output_digest", "issue_count", "issues_observed",
            "score", "relation_count", "relation_delta", "candidate_frontier_signature", "frontier_changed",
            "strong_quiet", "strong_fixed_point_streak", "oscillation", "order_audit", "minimal_transfer",
            "cross_document_minimal_transfer", "record_bridge") if k in c}
        cid = _node(nodes, kind="CYCLE", scope=mode, identity=f"cycle:{c.get('cycle')}", payload=summary, cycle=cyc)
        _edge(edges, "NEXT", previous, cid, cycle=cyc)
        previous = cid
        for status_key, nkind in (("accepted", "APPLIED_CORRECTION"), ("rejected", "REJECTED_CORRECTION")):
            for j, a in enumerate(c.get(status_key) or []):
                ident = str((a.get("candidate_id") if isinstance(a, dict) else None) or f"{status_key}:{j}")
                aid = _node(nodes, kind=nkind, scope=mode, identity=ident, payload=a, cycle=cyc)
                _edge(edges, "DECIDES", cid, aid, cycle=cyc)

    # Primary factorization and dynamic refactorization history.
    pf = report.get("primary_factorization") or {}
    for row in pf.get("cycles") or []:
        cyc = row.get("cycle") if isinstance(row.get("cycle"), int) else None
        fact = row.get("factorization") or {}
        fid = _node(nodes, kind="PRIMARY_FACTORIZATION", scope=mode,
                    identity=str(fact.get("factorization_sha256") or f"cycle:{cyc}"), payload=fact, cycle=cyc)
        _edge(edges, "FACTORIZES", root, fid, cycle=cyc)
        dyn = row.get("dynamic_refactorization") or {}
        did = _node(nodes, kind="DYNAMIC_REFACTORIZATION", scope=mode,
                    identity=f"refactor:{cyc}", payload=dyn, cycle=cyc)
        _edge(edges, "REFACTORS", fid, did, cycle=cyc)

    # PASS033 semantic claim/source provenance firewall.  This binds not only byte integrity
    # but the reproducible attribution class and exact source-inclusion/derivation evidence.
    sp = report.get("semantic_claim_provenance") or {}
    for i, row in enumerate(sp.get("cycles") or []):
        cert = (row or {}).get("certificate") if isinstance(row, dict) else None
        if not isinstance(cert, dict):
            continue
        cyc = row.get("cycle") if isinstance(row.get("cycle"), int) else None
        phase = str(row.get("phase")) if row.get("phase") is not None else None
        sid = _node(nodes, kind="SEMANTIC_CLAIM_PROVENANCE", scope=mode,
                    identity=str(cert.get("certificate_sha256") or f"semantic-claim:{i}"), payload=cert, cycle=cyc, phase=phase)
        _edge(edges, "VERIFIES_ATTRIBUTION", sid, final, cycle=cyc, phase=phase)
    if sp.get("final") not in (None, {}, []):
        cert = sp.get("final") or {}
        sid = _node(nodes, kind="SEMANTIC_CLAIM_PROVENANCE_FINAL", scope=mode,
                    identity=str(cert.get("certificate_sha256") or "semantic-claim:final"), payload=cert)
        _edge(edges, "VERIFIES_ATTRIBUTION", sid, final)

    # PASS035 symmetry obstruction and explicit semantic quotient/canonicality.
    sc = report.get("symmetry_canonicality") or {}
    if sc not in (None, {}, []):
        sid = _node(nodes, kind="SYMMETRY_CANONICALITY", scope=mode, identity="symmetry:summary", payload=sc)
        _edge(edges, "CANONICALLY_BOUNDS", sid, final)

    # PASS036 repair controllability / reachability under the actual mutation surface.
    rc = report.get("repair_controllability") or {}
    if rc not in (None, {}, []):
        cid = _node(nodes, kind="REPAIR_CONTROLLABILITY", scope=mode, identity="controllability:summary", payload=rc)
        _edge(edges, "CONTROLS_REACHABILITY", cid, final)

    # PASS037 active relation falsification / negative controls / ablations.
    rf = report.get("relation_falsification") or {}
    if rf not in (None, {}, []):
        fid = _node(nodes, kind="RELATION_FALSIFICATION", scope=mode, identity="falsification:summary", payload=rf)
        _edge(edges, "ATTACKS_RELATIONS", fid, final)

    # PASS031 robust uncertainty / clock / regime / hysteresis envelopes.
    re = report.get("robust_envelope") or {}
    for i, row in enumerate(re.get("cycles") or []):
        cert = (row or {}).get("certificate") if isinstance(row, dict) else None
        if not isinstance(cert, dict):
            continue
        cyc = row.get("cycle") if isinstance(row.get("cycle"), int) else None
        phase = str(row.get("phase")) if row.get("phase") is not None else None
        rid = _node(nodes, kind="ROBUST_ENVELOPE", scope=mode, identity=str(cert.get("certificate_sha256") or f"robust:{i}"), payload=cert, cycle=cyc, phase=phase)
        _edge(edges, "ROBUSTLY_BOUNDS", rid, final, cycle=cyc, phase=phase)
    if re.get("final") not in (None, {}, []):
        cert = re.get("final") or {}
        rid = _node(nodes, kind="ROBUST_ENVELOPE_FINAL", scope=mode, identity=str(cert.get("certificate_sha256") or "robust:final"), payload=cert)
        _edge(edges, "ROBUSTLY_BOUNDS", rid, final)

    # PASS026 routes and return proofs.
    pr = report.get("parallel_exact_minimum_routes") or {}
    for i, proof in enumerate(pr.get("cycles") or []):
        pid = _node(nodes, kind="RETURN_PROOF", scope=mode,
                    identity=str((proof or {}).get("proof_sha256") or f"route:{i}"), payload=proof)
        _edge(edges, "RETURNS", pid, final)

    # Q trajectory.
    q = report.get("dynamic_q_descent") or {}
    for i, row in enumerate(q.get("cycles") or []):
        qid = _node(nodes, kind="Q_STATE", scope=mode, identity=f"q:{i}", payload=row,
                    cycle=row.get("cycle") if isinstance(row, dict) and isinstance(row.get("cycle"), int) else None)
        _edge(edges, "DESCENDS", root, qid)
    if q.get("final") not in (None, {}, []):
        qid = _node(nodes, kind="Q_FINAL", scope=mode, identity="q:final", payload=q.get("final"))
        _edge(edges, "CERTIFIES_TERMINAL", qid, final)

    _extract_federation(report, nodes, edges, root)

    # Exact public commit chain and provenance commitment.
    commits = report.get("committed_edits") or report.get("committed_patch_set") or []
    if not isinstance(commits, list): commits = []
    for i, patch in enumerate(commits):
        pid = _node(nodes, kind="COMMITTED_PATCH", scope=mode, identity=f"commit:{i}", payload=patch)
        _edge(edges, "APPLIES", root if i == 0 else nodes[-2]["node_id"], pid)
    prov = report.get("provenance_chain") or {}
    if prov:
        pid = _node(nodes, kind="PROVENANCE", scope=mode, identity=str(prov.get("root_hash") or "provenance"), payload=prov)
        _edge(edges, "PROVES", pid, final)

    # Stable sorting makes graph identity independent of insertion ordering.
    nodes = sorted(nodes, key=lambda x: (x["kind"], x["scope"], str(x.get("cycle")), str(x.get("phase")), x["identity"], x["node_id"]))
    edges = sorted(edges, key=lambda x: (x["kind"], x["source"], x["target"], str(x.get("cycle")), str(x.get("phase")), x["edge_id"]))
    roots: dict[str, str] = {}
    for kind in sorted({n["kind"] for n in nodes}):
        roots[kind] = _sha([{"node_id": n["node_id"], "payload_sha256": n["payload_sha256"]} for n in nodes if n["kind"] == kind])
    edge_root = _sha(edges)
    graph = {"contract": CONTRACT, "mode": mode, "input_digest": inp, "output_digest": out,
             "node_count": len(nodes), "edge_count": len(edges), "section_roots": roots,
             "edge_root_sha256": edge_root, "nodes": nodes, "edges": edges}
    graph["graph_sha256"] = _sha(graph)
    return graph


def verify_proof_graph(graph: dict[str, Any]) -> bool:
    if not isinstance(graph, dict) or graph.get("contract") != CONTRACT: return False
    supplied = graph.get("graph_sha256")
    if not supplied: return False
    row = deepcopy(graph); row.pop("graph_sha256", None)
    if _sha(row) != supplied: return False
    nodes = graph.get("nodes") or []; edges = graph.get("edges") or []
    node_ids = {n.get("node_id") for n in nodes}
    if len(node_ids) != len(nodes) or None in node_ids: return False
    if any(e.get("source") not in node_ids or e.get("target") not in node_ids for e in edges): return False
    for n in nodes:
        if _sha(_clean(n.get("payload"))) != n.get("payload_sha256"): return False
    return True


def compare_proof_graphs(expected: dict[str, Any], replayed: dict[str, Any]) -> dict[str, Any]:
    expected_ok = verify_proof_graph(expected); replay_ok = verify_proof_graph(replayed)
    er = expected.get("section_roots") or {}; rr = replayed.get("section_roots") or {}
    kinds = sorted(set(er) | set(rr))
    section_matches = {k: er.get(k) == rr.get(k) for k in kinds}
    graph_match = bool(expected_ok and replay_ok and expected.get("graph_sha256") == replayed.get("graph_sha256"))
    return {"contract": REPLAY_CONTRACT, "performed": True, "ok": graph_match,
            "status": "PROOF_GRAPH_REPLAY_EXACT" if graph_match else "PROOF_GRAPH_REPLAY_MISMATCH",
            "expected_graph_sha256": expected.get("graph_sha256"), "replayed_graph_sha256": replayed.get("graph_sha256"),
            "expected_node_count": expected.get("node_count"), "replayed_node_count": replayed.get("node_count"),
            "expected_edge_count": expected.get("edge_count"), "replayed_edge_count": replayed.get("edge_count"),
            "section_matches": section_matches, "edge_root_match": expected.get("edge_root_sha256") == replayed.get("edge_root_sha256"),
            "expected_graph_valid": expected_ok, "replayed_graph_valid": replay_ok}
