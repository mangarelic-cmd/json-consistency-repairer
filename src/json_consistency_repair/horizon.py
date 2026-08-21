"""PASS039 — horizon naturality and distributed consistency.

A closed local result must remain stable when its information horizon is enlarged or
when the same logical input is repartitioned.  A changed old conclusion is accepted
only when a newly introduced dependency can be named as a boundary-crossing witness.
Opaque/incomplete locality never becomes a silent permission: it falls back to full
recomputation.
"""
from __future__ import annotations

from copy import deepcopy
from fnmatch import fnmatchcase
from typing import Any, Iterable

from .models import digest

SNAPSHOT_CONTRACT = "json-consistency-repair.horizon-snapshot.v1"
NATURALITY_CONTRACT = "json-consistency-repair.horizon-naturality.v1"
DISTRIBUTED_CONTRACT = "json-consistency-repair.distributed-consistency.v1"


def _escape(part: str) -> str:
    return str(part).replace("~", "~0").replace("/", "~1")


def _canon_tokens(values: Iterable[str]) -> list[str]:
    return sorted({str(v) for v in values if isinstance(v, str) and v})


def _path_tokens(path: str) -> list[str]:
    p = str(path)
    out = [f"path:{p}"]
    if p.startswith("/"):
        parts = p.split("/")[1:]
        cur = ""
        for part in parts[:-1]:
            cur += "/" + part
            out.append(f"path:{cur}/*")
    return _canon_tokens(out)


def _manifest(value: Any, *, prefix: str = "", max_entries: int = 4096) -> tuple[list[dict[str, Any]], bool]:
    """Hash every visited JSON node up to a deterministic hard bound."""
    rows: list[dict[str, Any]] = []
    complete = True

    def visit(v: Any, path: str) -> None:
        nonlocal complete
        if len(rows) >= max_entries:
            complete = False
            return
        kind = "object" if isinstance(v, dict) else "array" if isinstance(v, list) else "scalar"
        rows.append({"path": path, "kind": kind, "sha256": digest(v)})
        if isinstance(v, dict):
            for k in sorted(v, key=lambda x: str(x)):
                if not complete:
                    break
                visit(v[k], path + "/" + _escape(str(k)))
        elif isinstance(v, list):
            for i, item in enumerate(v):
                if not complete:
                    break
                visit(item, path + f"/{i}")

    visit(value, prefix)
    return rows, complete


def _relation_dependency_rows(report: dict[str, Any], *, mode: str) -> list[dict[str, Any]]:
    """Compile only dependencies that can be localized from serialized relation data."""
    rels: list[dict[str, Any]] = []
    for key in ("relations", "cross_document_relations"):
        raw = report.get(key) or []
        if isinstance(raw, list):
            rels.extend(x for x in raw if isinstance(x, dict))
    ledger = report.get("knowledge_ledger") or {}
    if isinstance(ledger, dict) and isinstance(ledger.get("relations"), list):
        rels.extend(x for x in ledger["relations"] if isinstance(x, dict))

    rows: list[dict[str, Any]] = []
    seen = set()
    for rel in rels:
        rid = str(rel.get("relation_id") or rel.get("id") or digest(rel)[:20])
        base = str(rel.get("array_path") or rel.get("scope_path") or "")
        document = rel.get("document") or rel.get("source_document")
        if mode == "bundle" and document:
            base = "/@doc/" + _escape(str(document)) + base
        target_patterns: list[str] = []
        dependency_patterns: list[str] = []
        for key in ("output_path", "target_path", "path"):
            if isinstance(rel.get(key), str):
                target_patterns.append(str(rel[key]))
        output = rel.get("output") or rel.get("target")
        if isinstance(output, str):
            target_patterns.append((base.rstrip("/") + "/*/" + _escape(output)) if base else "/*/" + _escape(output))
        for key in ("input_paths", "source_paths", "dependency_paths"):
            if isinstance(rel.get(key), list):
                dependency_patterns.extend(str(x) for x in rel[key] if isinstance(x, str))
        for field in rel.get("inputs") or []:
            if isinstance(field, str):
                dependency_patterns.append((base.rstrip("/") + "/*/" + _escape(field)) if base else "/*/" + _escape(field))
        target_patterns = sorted(set(target_patterns))
        dependency_patterns = sorted(set(dependency_patterns))
        if not target_patterns or not dependency_patterns:
            continue
        row = {
            "relation_id": rid,
            "target_patterns": target_patterns,
            "dependency_patterns": dependency_patterns,
            "relation_sha256": digest(rel),
        }
        key = digest(row)
        if key not in seen:
            seen.add(key); rows.append(row)
    return sorted(rows, key=lambda x: (x["relation_id"], digest(x)))


def _seal(obj: dict[str, Any], field: str) -> dict[str, Any]:
    out = deepcopy(obj)
    out.pop(field, None)
    obj[field] = digest(out)
    return obj


def compile_horizon_snapshot(report: dict[str, Any], input_value: Any = None, output_value: Any = None,
                             *, namespace: str = "root", distribution: dict[str, Any] | None = None,
                             max_manifest_entries: int = 4096) -> dict[str, Any]:
    mode = str(report.get("mode") or "single")
    if input_value is None:
        in_manifest, in_complete = [], False
    else:
        in_manifest, in_complete = _manifest(input_value, max_entries=max_manifest_entries)
    if output_value is None:
        out_manifest, out_complete = [], False
    else:
        out_manifest, out_complete = _manifest(output_value, max_entries=max_manifest_entries)
    snap = {
        "contract": SNAPSHOT_CONTRACT,
        "mode": mode,
        "namespace": str(namespace),
        "input_digest": str(report.get("input_digest") or (digest(input_value) if input_value is not None else "")),
        "output_digest": str(report.get("output_digest") or (digest(output_value) if output_value is not None else "")),
        "input_manifest": in_manifest,
        "output_manifest": out_manifest,
        "input_manifest_complete": bool(in_complete),
        "output_manifest_complete": bool(out_complete),
        "manifest_limit": int(max_manifest_entries),
        "localized_relation_dependencies": _relation_dependency_rows(report, mode=mode),
        "distribution": deepcopy(distribution or {"mode": mode}),
        "proof_surface_sha256": digest({
            "relations": report.get("relations"),
            "cross_document_relations": report.get("cross_document_relations"),
            "knowledge_ledger": report.get("knowledge_ledger"),
            "open_obligations": report.get("open_obligations"),
        }),
    }
    return _seal(snap, "snapshot_sha256")


def verify_horizon_snapshot(snapshot: dict[str, Any]) -> bool:
    if not isinstance(snapshot, dict) or snapshot.get("contract") != SNAPSHOT_CONTRACT:
        return False
    if not isinstance(snapshot.get("namespace"), str) or not snapshot.get("namespace"):
        return False
    for key in ("input_manifest", "output_manifest", "localized_relation_dependencies"):
        if not isinstance(snapshot.get(key), list):
            return False
    for key in ("input_manifest", "output_manifest"):
        seen = set()
        for row in snapshot.get(key) or []:
            if not isinstance(row, dict) or not isinstance(row.get("path"), str) or not isinstance(row.get("sha256"), str):
                return False
            if row["path"] in seen:
                return False
            seen.add(row["path"])
    supplied = snapshot.get("snapshot_sha256")
    raw = deepcopy(snapshot); raw.pop("snapshot_sha256", None)
    return isinstance(supplied, str) and supplied == digest(raw)


def _map_manifest(rows: list[dict[str, Any]]) -> dict[str, str]:
    return {str(r["path"]): str(r["sha256"]) for r in rows if isinstance(r, dict) and isinstance(r.get("path"), str)}


def _path_pattern_matches(pattern: str, path: str) -> bool:
    # JSON pointer patterns use '*' for one-or-more wildcard characters here; escaping is already canonical.
    return fnmatchcase(path, pattern)


def _changed_paths(prior: dict[str, Any], current: dict[str, Any]) -> list[str]:
    a = _map_manifest(prior.get("input_manifest") or [])
    b = _map_manifest(current.get("input_manifest") or [])
    return sorted(p for p in set(a) | set(b) if a.get(p) != b.get(p))


def _drift_paths(prior: dict[str, Any], current: dict[str, Any]) -> list[str]:
    pin = _map_manifest(prior.get("input_manifest") or [])
    cin = _map_manifest(current.get("input_manifest") or [])
    prow = {str(r.get("path")): r for r in (prior.get("output_manifest") or []) if isinstance(r, dict)}
    crow = {str(r.get("path")): r for r in (current.get("output_manifest") or []) if isinstance(r, dict)}
    drift = []
    # Container hashes change whenever a descendant changes; counting both would duplicate one
    # semantic drift.  Compare scalar terminals (including added/removed scalar terminals).
    scalar_paths = {p for p,r in prow.items() if r.get("kind")=="scalar"} | {p for p,r in crow.items() if r.get("kind")=="scalar"}
    for path in sorted(scalar_paths):
        ph = (prow.get(path) or {}).get("sha256")
        ch = (crow.get(path) or {}).get("sha256")
        if ph == ch:
            continue
        # Exact unchanged input location is the strongest locality witness.  If the path is
        # output-only, walk to the nearest common unchanged input ancestor.
        stable_input = path in pin and path in cin and pin[path] == cin[path]
        if not stable_input:
            cur = path
            while "/" in cur.strip("/"):
                cur = cur.rsplit("/",1)[0]
                if cur in pin and cur in cin:
                    stable_input = pin[cur] == cin[cur]
                    break
        if stable_input:
            drift.append(path)
    return drift


def _explicit_witnesses(boundary_witnesses: Iterable[dict[str, Any]], drift: str, changed_tokens: set[str]) -> list[dict[str, Any]]:
    out = []
    for raw in boundary_witnesses:
        if not isinstance(raw, dict):
            continue
        target = str(raw.get("target") or raw.get("target_pattern") or "")
        token = str(raw.get("token") or "")
        if not target or not token or token not in changed_tokens:
            continue
        if target == drift or _path_pattern_matches(target, drift):
            row = {"kind": "EXPLICIT_BOUNDARY_WITNESS", "target": drift, "token": token,
                   "origin": raw.get("origin"), "evidence_sha256": raw.get("evidence_sha256") or digest(raw)}
            out.append(row)
    return out


def _relation_witnesses(current: dict[str, Any], drift: str, changed_paths: list[str]) -> list[dict[str, Any]]:
    out = []
    for row in current.get("localized_relation_dependencies") or []:
        if not any(_path_pattern_matches(str(tp), drift) for tp in row.get("target_patterns") or []):
            continue
        hits = sorted({p for p in changed_paths if any(_path_pattern_matches(str(dp), p) for dp in row.get("dependency_patterns") or [])})
        for hit in hits:
            out.append({"kind": "RELATION_BOUNDARY_WITNESS", "target": drift, "changed_path": hit,
                        "relation_id": row.get("relation_id"), "relation_sha256": row.get("relation_sha256")})
    return out


def compare_horizon_naturality(prior_snapshot: dict[str, Any] | None, current_snapshot: dict[str, Any],
                               *, change_tokens: Iterable[str] = (),
                               boundary_witnesses: Iterable[dict[str, Any]] = ()) -> dict[str, Any]:
    if not verify_horizon_snapshot(current_snapshot):
        raise ValueError("invalid current horizon snapshot")
    if prior_snapshot is None:
        cert = {
            "contract": NATURALITY_CONTRACT, "status": "BASELINE_REGISTERED", "ok": True,
            "prior_snapshot_sha256": None, "current_snapshot_sha256": current_snapshot["snapshot_sha256"],
            "changed_input_paths": [], "change_tokens": _canon_tokens(change_tokens),
            "stable_old_paths_checked": 0, "drifted_old_paths": [], "boundary_witnesses": [],
            "full_recompute_required": False,
        }
        return _seal(cert, "certificate_sha256")
    if not verify_horizon_snapshot(prior_snapshot):
        raise ValueError("invalid prior horizon snapshot")
    if prior_snapshot.get("namespace") != current_snapshot.get("namespace"):
        cert = {
            "contract": NATURALITY_CONTRACT, "status": "NONCOMPARABLE_NAMESPACE", "ok": True,
            "prior_snapshot_sha256": prior_snapshot["snapshot_sha256"], "current_snapshot_sha256": current_snapshot["snapshot_sha256"],
            "changed_input_paths": [], "change_tokens": _canon_tokens(change_tokens),
            "stable_old_paths_checked": 0, "drifted_old_paths": [], "boundary_witnesses": [],
            "full_recompute_required": False,
        }
        return _seal(cert, "certificate_sha256")

    changed_paths = _changed_paths(prior_snapshot, current_snapshot) if prior_snapshot.get("input_manifest_complete") and current_snapshot.get("input_manifest_complete") else []
    auto_tokens = []
    for p in changed_paths:
        auto_tokens.extend(_path_tokens(p))
    all_tokens = set(_canon_tokens([*change_tokens, *auto_tokens]))

    manifests_complete = bool(prior_snapshot.get("input_manifest_complete") and current_snapshot.get("input_manifest_complete") and
                              prior_snapshot.get("output_manifest_complete") and current_snapshot.get("output_manifest_complete"))
    if not manifests_complete:
        if prior_snapshot.get("input_digest") == current_snapshot.get("input_digest"):
            if prior_snapshot.get("output_digest") == current_snapshot.get("output_digest"):
                status, ok, full = "HORIZON_NATURAL_DIGEST_EXACT", True, False
            else:
                status, ok, full = "DISTRIBUTED_OR_HORIZON_DRIFT_UNEXPLAINED", False, True
        elif prior_snapshot.get("output_digest") == current_snapshot.get("output_digest"):
            status, ok, full = "HORIZON_NATURAL_OUTPUT_UNCHANGED", True, False
        else:
            status, ok, full = "FULL_RECOMPUTE_REQUIRED", False, True
        cert = {
            "contract": NATURALITY_CONTRACT, "status": status, "ok": ok,
            "prior_snapshot_sha256": prior_snapshot["snapshot_sha256"], "current_snapshot_sha256": current_snapshot["snapshot_sha256"],
            "changed_input_paths": changed_paths, "change_tokens": sorted(all_tokens),
            "stable_old_paths_checked": 0, "drifted_old_paths": [], "boundary_witnesses": [],
            "full_recompute_required": full, "reason": "INCOMPLETE_LOCAL_MANIFEST" if full else None,
        }
        return _seal(cert, "certificate_sha256")

    drift = _drift_paths(prior_snapshot, current_snapshot)
    pin = _map_manifest(prior_snapshot.get("input_manifest") or [])
    cin = _map_manifest(current_snapshot.get("input_manifest") or [])
    stable_checked = sum(1 for p in set(pin) & set(cin) if pin[p] == cin[p])
    witnesses: list[dict[str, Any]] = []
    unexplained = []
    for target in drift:
        ws = _relation_witnesses(current_snapshot, target, changed_paths)
        ws.extend(_explicit_witnesses(boundary_witnesses, target, all_tokens))
        if ws:
            witnesses.extend(ws)
        else:
            unexplained.append(target)
    if unexplained:
        status, ok, full = "HORIZON_DRIFT_UNEXPLAINED", False, True
    elif drift:
        status, ok, full = "HORIZON_INVALIDATED_BY_WITNESS", True, False
    else:
        status, ok, full = "HORIZON_NATURAL", True, False
    cert = {
        "contract": NATURALITY_CONTRACT, "status": status, "ok": ok,
        "prior_snapshot_sha256": prior_snapshot["snapshot_sha256"], "current_snapshot_sha256": current_snapshot["snapshot_sha256"],
        "changed_input_paths": changed_paths, "change_tokens": sorted(all_tokens),
        "stable_old_paths_checked": stable_checked, "drifted_old_paths": drift,
        "unexplained_drift_paths": unexplained, "boundary_witnesses": sorted(witnesses, key=lambda x: digest(x)),
        "full_recompute_required": full,
    }
    return _seal(cert, "certificate_sha256")


def verify_horizon_naturality_certificate(cert: dict[str, Any], current_snapshot: dict[str, Any],
                                           prior_snapshot: dict[str, Any] | None = None) -> bool:
    if not isinstance(cert, dict) or cert.get("contract") != NATURALITY_CONTRACT or not verify_horizon_snapshot(current_snapshot):
        return False
    supplied = cert.get("certificate_sha256"); raw = deepcopy(cert); raw.pop("certificate_sha256", None)
    if not isinstance(supplied, str) or supplied != digest(raw):
        return False
    if cert.get("current_snapshot_sha256") != current_snapshot.get("snapshot_sha256"):
        return False
    if prior_snapshot is None:
        return cert.get("status") == "BASELINE_REGISTERED" and cert.get("prior_snapshot_sha256") is None and cert.get("ok") is True
    if not verify_horizon_snapshot(prior_snapshot) or cert.get("prior_snapshot_sha256") != prior_snapshot.get("snapshot_sha256"):
        return False
    if cert.get("ok") is True:
        return cert.get("status") in {"HORIZON_NATURAL", "HORIZON_NATURAL_DIGEST_EXACT", "HORIZON_NATURAL_OUTPUT_UNCHANGED", "HORIZON_INVALIDATED_BY_WITNESS", "NONCOMPARABLE_NAMESPACE"} and not cert.get("full_recompute_required")
    return cert.get("status") in {"HORIZON_DRIFT_UNEXPLAINED", "FULL_RECOMPUTE_REQUIRED", "DISTRIBUTED_OR_HORIZON_DRIFT_UNEXPLAINED"} and bool(cert.get("full_recompute_required"))


def compile_distributed_consistency(snapshots: Iterable[dict[str, Any]]) -> dict[str, Any]:
    snaps = [deepcopy(s) for s in snapshots]
    if not snaps or not all(verify_horizon_snapshot(s) for s in snaps):
        raise ValueError("distributed consistency requires valid horizon snapshots")
    conflicts: list[dict[str, Any]] = []
    comparisons = 0
    for i in range(len(snaps)):
        for j in range(i + 1, len(snaps)):
            a, b = snaps[i], snaps[j]
            if a.get("namespace") != b.get("namespace"):
                continue
            if a.get("input_digest") == b.get("input_digest"):
                comparisons += 1
                if a.get("output_digest") != b.get("output_digest"):
                    conflicts.append({"kind": "SAME_INPUT_DIFFERENT_TERMINAL", "left": a["snapshot_sha256"], "right": b["snapshot_sha256"],
                                      "input_digest": a.get("input_digest"), "left_output": a.get("output_digest"), "right_output": b.get("output_digest")})
                continue
            if not (a.get("input_manifest_complete") and b.get("input_manifest_complete") and a.get("output_manifest_complete") and b.get("output_manifest_complete")):
                continue
            ain, bin = _map_manifest(a["input_manifest"]), _map_manifest(b["input_manifest"])
            aout, bout = _map_manifest(a["output_manifest"]), _map_manifest(b["output_manifest"])
            for path in sorted(set(ain) & set(bin) & set(aout) & set(bout)):
                if ain[path] == bin[path]:
                    comparisons += 1
                    if aout[path] != bout[path]:
                        conflicts.append({"kind": "OVERLAP_TERMINAL_CONFLICT", "path": path,
                                          "left": a["snapshot_sha256"], "right": b["snapshot_sha256"],
                                          "input_sha256": ain[path], "left_output_sha256": aout[path], "right_output_sha256": bout[path]})
    if conflicts:
        status, ok = "DISTRIBUTED_CONFLICT", False
    elif len(snaps) == 1:
        status, ok = "DISTRIBUTED_BASELINE", True
    elif comparisons:
        status, ok = "DISTRIBUTED_CONSISTENT", True
    else:
        status, ok = "DISTRIBUTED_NONOVERLAPPING", True
    cert = {
        "contract": DISTRIBUTED_CONTRACT, "status": status, "ok": ok,
        "snapshot_sha256s": [s["snapshot_sha256"] for s in snaps],
        "snapshot_count": len(snaps), "comparisons": comparisons,
        "conflicts": conflicts, "conflict_count": len(conflicts),
    }
    return _seal(cert, "certificate_sha256")


def verify_distributed_consistency_certificate(cert: dict[str, Any], snapshots: Iterable[dict[str, Any]]) -> bool:
    snaps = list(snapshots)
    if not isinstance(cert, dict) or cert.get("contract") != DISTRIBUTED_CONTRACT or not snaps or not all(verify_horizon_snapshot(s) for s in snaps):
        return False
    supplied = cert.get("certificate_sha256"); raw = deepcopy(cert); raw.pop("certificate_sha256", None)
    if supplied != digest(raw):
        return False
    if cert.get("snapshot_sha256s") != [s.get("snapshot_sha256") for s in snaps]:
        return False
    expected = compile_distributed_consistency(snaps)
    return expected == cert


def compile_horizon_surface(report: dict[str, Any], input_value: Any = None, output_value: Any = None, *,
                            prior_snapshot: dict[str, Any] | None = None,
                            change_tokens: Iterable[str] = (), boundary_witnesses: Iterable[dict[str, Any]] = (),
                            distribution: dict[str, Any] | None = None, namespace: str = "root",
                            max_manifest_entries: int = 4096) -> tuple[dict[str, Any], dict[str, Any]]:
    snapshot = compile_horizon_snapshot(report, input_value, output_value, namespace=namespace,
                                        distribution=distribution, max_manifest_entries=max_manifest_entries)
    naturality = compare_horizon_naturality(prior_snapshot, snapshot, change_tokens=change_tokens,
                                            boundary_witnesses=boundary_witnesses)
    peers = [snapshot]
    if prior_snapshot is not None and verify_horizon_snapshot(prior_snapshot) and prior_snapshot.get("input_digest") == snapshot.get("input_digest"):
        peers = [prior_snapshot, snapshot]
    distributed = compile_distributed_consistency(peers)
    surface = {
        "contract": NATURALITY_CONTRACT,
        "snapshot": snapshot,
        "prior_snapshot": deepcopy(prior_snapshot) if prior_snapshot is not None else None,
        "requested_change_tokens": _canon_tokens(change_tokens),
        "requested_boundary_witnesses": [deepcopy(x) for x in boundary_witnesses if isinstance(x, dict)],
        "comparison": naturality,
    }
    return surface, distributed
