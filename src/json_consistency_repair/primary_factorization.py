from __future__ import annotations

from copy import deepcopy
from typing import Any
import hashlib, json

from .tree import decode_pointer

CONTRACT = "json-consistency-repair.primary-factorization.v1"
REGISTRY_CONTRACT = "json-consistency-repair.primary-block-registry.v1"
RELATION_CONTRACT = "json-consistency-repair.primary-relation-registry.v1"
REFACTOR_CONTRACT = "json-consistency-repair.dynamic-refactorization.v1"


def _stable(prefix: str, payload: Any) -> str:
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return prefix + hashlib.sha256(raw).hexdigest()[:20]


def _escape(token: Any) -> str:
    return str(token).replace("~", "~0").replace("/", "~1")


def _ptr(tokens: list[Any]) -> str:
    return "" if not tokens else "/" + "/".join(_escape(x) for x in tokens)


def _is_index(x: Any) -> bool:
    try:
        s = str(x)
        return s == "0" or (s.isdigit() and not s.startswith("0"))
    except Exception:
        return False


def _candidate_paths(candidate: Any) -> list[str]:
    """Return every path whose state is touched/read structurally by one candidate.

    A plan is atomic and therefore exposes every step path.  A move exposes source and
    destination.  This is used only for dependency factorization; patch application remains
    delegated to jsonpatch_exact.
    """
    out: list[str] = []
    op = str(getattr(candidate, "operation", "") or "")
    path = str(getattr(candidate, "path", "") or "")
    meta = getattr(candidate, "metadata", None) or {}
    if op == "plan":
        for step in meta.get("steps") or []:
            if isinstance(step, dict):
                p = str(step.get("path", "") or "")
                if p not in out: out.append(p)
                fp = str((step.get("metadata") or {}).get("from_path", "") or "")
                if fp and fp not in out: out.append(fp)
    else:
        if path not in out: out.append(path)
        fp = str(meta.get("from_path", "") or "")
        if fp and fp not in out: out.append(fp)
    return out or [path]


def _path_overlap(a: str, b: str) -> bool:
    ta, tb = decode_pointer(a), decode_pointer(b)
    n = min(len(ta), len(tb))
    return ta[:n] == tb[:n]


def _relation_fields(rel: dict[str, Any]) -> set[str]:
    fields: set[str] = set()
    for x in rel.get("inputs") or []:
        if isinstance(x, str) and x and not x.startswith("__"): fields.add(x)
    out = rel.get("output")
    if isinstance(out, str) and out and not out.startswith("__"): fields.add(out)
    # Some system rules serialize the concrete field names outside inputs/output.
    for k in ("node_id", "source_field", "target_field", "value_field", "unit_field", "weight_field", "items_field", "target"):
        x = rel.get(k)
        if isinstance(x, str) and x and not x.startswith("/") and not x.startswith("__"): fields.add(x)
    return fields


def _relation_scopes(rel: dict[str, Any]) -> list[str]:
    scopes: list[str] = []
    for k in ("array_path", "scope", "object_path", "nodes_path", "edges_path"):
        x = rel.get(k)
        if isinstance(x, str) and (x == "" or x.startswith("/")) and x not in scopes:
            scopes.append(x)
    if not scopes: scopes.append("")
    return scopes


def _relation_bindings(rel: dict[str, Any], path: str) -> list[tuple[str, str | None]]:
    """Map one concrete JSON pointer to zero or more relation instances.

    For repeated object arrays the row index is part of the instance key.  Consequently a
    relation learned on /orders does not accidentally couple repairs in /orders/3 and
    /orders/91.  Top-level/record-carrier relations bind to their concrete object instance.
    """
    pt = decode_pointer(path)
    fields = _relation_fields(rel)
    out: list[tuple[str, str | None]] = []
    rid = str(rel.get("relation_id") or _stable("rel_", rel))
    for scope in _relation_scopes(rel):
        st = decode_pointer(scope)
        if len(pt) < len(st) or pt[:len(st)] != st:
            continue
        tail = pt[len(st):]
        if not tail:
            # Relation touches the carrier itself only when it has no field-level signature.
            if not fields: out.append((rid + "@" + _ptr(st), None))
            continue
        if _is_index(tail[0]):
            instance = st + [tail[0]]
            field = str(tail[1]) if len(tail) > 1 else None
        else:
            instance = st
            field = str(tail[0]) if tail else None
        if fields and field not in fields:
            continue
        out.append((rid + "@" + _ptr(instance), field))
    return out


def _option_identity(option: Any) -> str:
    c = option.candidate
    meta = getattr(c, "metadata", None) or {}
    payload = [str(c.operation), str(c.path), str(meta.get("from_path", "")), c.new_value]
    return _stable("opt_", payload)


def _legacy_parent(path: str) -> str:
    toks = decode_pointer(path)
    if not toks or len(toks) == 1: return ""
    return _ptr(toks[:-1])


class _UF:
    def __init__(self, n: int): self.p = list(range(n)); self.r = [0] * n
    def find(self, x: int) -> int:
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]; x = self.p[x]
        return x
    def union(self, a: int, b: int) -> None:
        a, b = self.find(a), self.find(b)
        if a == b: return
        if self.r[a] < self.r[b]: a, b = b, a
        self.p[b] = a
        if self.r[a] == self.r[b]: self.r[a] += 1


def factorize_options(root: Any, analysis: Any, options: list[Any]) -> tuple[dict[str, list[Any]], dict[str, Any]]:
    """Factor the exact repair frontier into dependency-primary blocks.

    Blocks are connected components of the *known concrete dependency graph*, not JSON
    containers.  Two options are coupled only by overlapping touched paths or by a relation
    instance that actually touches both options.  The resulting partition is therefore lossless
    with respect to the serialized frontier and irreducible under the known coupling edges.
    """
    n = len(options)
    uf = _UF(n)
    opt_ids = [_option_identity(o) for o in options]
    paths = [_candidate_paths(o.candidate) for o in options]
    coupling_edges: list[dict[str, Any]] = []

    def connect(i: int, j: int, kind: str, witness: str) -> None:
        if i == j: return
        a, b = sorted((i, j))
        row = {"a": opt_ids[a], "b": opt_ids[b], "kind": kind, "witness": witness}
        if row not in coupling_edges: coupling_edges.append(row)
        uf.union(a, b)

    # Structural overlap is an unavoidable dependency, including ancestor/descendant edits.
    for i in range(n):
        for j in range(i + 1, n):
            hits = [(a, b) for a in paths[i] for b in paths[j] if _path_overlap(a, b)]
            if hits:
                a, b = sorted(hits[0])
                connect(i, j, "PATH_OVERLAP", a + "|" + b)

    # Relation registry is instance-addressed.  This is the main replacement for the legacy
    # parent_json_container heuristic.
    binding_to_options: dict[str, set[int]] = {}
    relation_registry: dict[str, dict[str, Any]] = {}
    for rel in analysis.relations:
        rid = str(rel.get("relation_id") or _stable("rel_", rel))
        for i, pset in enumerate(paths):
            for p in pset:
                for binding, field in _relation_bindings(rel, p):
                    binding_to_options.setdefault(binding, set()).add(i)
                    row = relation_registry.setdefault(binding, {
                        "binding_id": binding,
                        "relation_id": rid,
                        "relation_kind": rel.get("kind"),
                        "scope": binding.split("@", 1)[1] if "@" in binding else "",
                        "option_ids": [],
                        "fields": [],
                    })
                    if opt_ids[i] not in row["option_ids"]: row["option_ids"].append(opt_ids[i])
                    if field is not None and field not in row["fields"]: row["fields"].append(field)
    for binding, members in sorted(binding_to_options.items()):
        mm = sorted(members)
        for k in range(1, len(mm)):
            connect(mm[0], mm[k], "RELATION_INSTANCE", binding)

    # Candidate metadata can point directly to a relation.  Use it only within the same
    # concrete carrier so a global learned relation does not couple every row in an array.
    evidence_groups: dict[tuple[str, str], list[int]] = {}
    known_rids = {str(r.get("relation_id")) for r in analysis.relations if r.get("relation_id")}
    for i, o in enumerate(options):
        c = o.candidate; meta = getattr(c, "metadata", None) or {}
        refs = set(str(x) for x in getattr(c, "evidence", ()) if str(x) in known_rids)
        for k in ("relation_id", "linear_system_id"):
            if meta.get(k) is not None and str(meta.get(k)) in known_rids: refs.add(str(meta.get(k)))
        carrier = _legacy_parent(paths[i][0] if paths[i] else str(c.path))
        for rid in refs: evidence_groups.setdefault((rid, carrier), []).append(i)
    for (rid, carrier), mm in sorted(evidence_groups.items()):
        mm = sorted(set(mm))
        for k in range(1, len(mm)):
            connect(mm[0], mm[k], "RELATION_EVIDENCE_SAME_CARRIER", rid + "@" + carrier)

    # Lossless-refinement guard.  Absence of a discovered relation is not itself proof of
    # independence.  A legacy local carrier may be split only when every option in that
    # carrier is attached to at least one explicit relation instance/evidence witness.
    # Otherwise the carrier stays atomic and exact joint repairs remain discoverable.
    bound_options = {i for members in binding_to_options.values() for i in members}
    for mm in evidence_groups.values():
        bound_options.update(mm)
    legacy_members: dict[str, list[int]] = {}
    for i, pset in enumerate(paths):
        key = _legacy_parent(pset[0] if pset else str(options[i].candidate.path))
        legacy_members.setdefault(key, []).append(i)
    for carrier, mm in sorted(legacy_members.items()):
        if len(mm) > 1 and not all(i in bound_options for i in mm):
            base = sorted(mm)[0]
            for j in sorted(mm)[1:]:
                connect(base, j, "UNRESOLVED_DEPENDENCY_GUARD", carrier)

    components: dict[int, list[int]] = {}
    for i in range(n): components.setdefault(uf.find(i), []).append(i)

    blocks: list[dict[str, Any]] = []
    clusters: dict[str, list[Any]] = {}
    index_to_block: dict[int, str] = {}
    for members in sorted(components.values(), key=lambda xs: tuple(opt_ids[i] for i in sorted(xs))):
        mids = sorted(opt_ids[i] for i in members)
        mpaths = sorted({p for i in members for p in paths[i]})
        relbinds = sorted({e["witness"] for e in coupling_edges if e["kind"].startswith("RELATION") and (e["a"] in mids or e["b"] in mids)})
        bid = _stable("pb_", {"options": mids, "paths": mpaths, "relations": relbinds})
        clusters[bid] = [options[i] for i in sorted(members, key=lambda j: opt_ids[j])]
        for i in members: index_to_block[i] = bid
        blocks.append({
            "block_id": bid,
            "option_ids": mids,
            "candidate_ids": sorted({cid for i in members for cid in getattr(options[i], "candidate_ids", ())}),
            "paths": mpaths,
            "relation_bindings": relbinds,
            "option_count": len(members),
            "primary": True,
            "primary_reason": "CONNECTED_COMPONENT_OF_KNOWN_CONCRETE_DEPENDENCIES",
        })

    # Independent recomposition proof over the frontier partition.
    covered = [oid for b in blocks for oid in b["option_ids"]]
    cross_edges = [e for e in coupling_edges if index_to_block[opt_ids.index(e["a"])] != index_to_block[opt_ids.index(e["b"])]] if opt_ids else []
    unique_covered = len(set(covered)) == len(covered) == n
    lossless = bool(unique_covered and not cross_edges and set(covered) == set(opt_ids))

    # Compare with the old parent-container partition to make refinement/merger effects visible.
    legacy: dict[str, set[str]] = {}
    for i, oid in enumerate(opt_ids):
        carriers = {_legacy_parent(p) for p in paths[i]}
        key = sorted(carriers)[0] if carriers else ""
        legacy.setdefault(key, set()).add(oid)
    primary_sets = [set(b["option_ids"]) for b in blocks]
    strict_refinement = len(primary_sets) > len(legacy) and all(any(ps <= old for old in legacy.values()) for ps in primary_sets)
    cross_parent_merge = any(len({_legacy_parent(p) for p in b["paths"]}) > 1 for b in blocks)

    cert = {
        "contract": CONTRACT,
        "block_registry_contract": REGISTRY_CONTRACT,
        "relation_registry_contract": RELATION_CONTRACT,
        "partition_rule": "CONCRETE_RELATION_CONNECTED_COMPONENTS",
        "option_count": n,
        "primary_block_count": len(blocks),
        "legacy_parent_block_count": len(legacy),
        "strict_refinement_of_legacy_parent_partition": strict_refinement,
        "cross_parent_relation_merge_present": cross_parent_merge,
        "lossless_refinement_guard":"SPLIT_LEGACY_CARRIER_ONLY_IF_EVERY_OPTION_HAS_EXPLICIT_RELATION_WITNESS",
        "guarded_legacy_carriers":sorted([carrier for carrier,mm in legacy_members.items() if len(mm)>1 and not all(i in bound_options for i in mm)]),
        "blocks": blocks,
        "primary_relation_registry": [
            {**deepcopy(v), "option_ids": sorted(v["option_ids"]), "fields": sorted(v["fields"])}
            for _, v in sorted(relation_registry.items())
        ],
        "coupling_edges": sorted(coupling_edges, key=lambda e: (e["a"], e["b"], e["kind"], e["witness"])),
        "recomposition_proof": {
            "frontier_option_count": n,
            "covered_option_count": len(covered),
            "unique_coverage": unique_covered,
            "cross_block_dependency_edge_count": len(cross_edges),
            "information_loss": 0 if lossless else None,
            "lossless": lossless,
        },
        "primary_definition": "NO_BLOCK_CAN_BE_SPLIT_WITHOUT_CUTTING_A_KNOWN_CONCRETE_DEPENDENCY_EDGE",
    }
    digest_payload = deepcopy(cert)
    cert["factorization_sha256"] = hashlib.sha256(json.dumps(digest_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")).hexdigest()
    return clusters, cert


def compare_factorizations(previous: dict[str, Any] | None, current: dict[str, Any]) -> dict[str, Any]:
    """Compile dynamic split/merge/invalidation events between two frontier factorizations."""
    if not previous:
        return {"contract": REFACTOR_CONTRACT, "status": "INITIAL_FACTORIZATION", "events": [], "invalidated_block_ids": []}
    old = {b["block_id"]: set(b.get("paths") or []) for b in previous.get("blocks") or []}
    new = {b["block_id"]: set(b.get("paths") or []) for b in current.get("blocks") or []}
    events: list[dict[str, Any]] = []
    invalidated: set[str] = set()
    for oid, ops in old.items():
        hits = [nid for nid, nps in new.items() if ops & nps]
        if len(hits) > 1:
            events.append({"kind": "PRIMARY_BLOCK_SPLIT", "old_block_id": oid, "new_block_ids": sorted(hits)})
            invalidated.add(oid)
        elif len(hits) == 1 and hits[0] != oid:
            events.append({"kind": "PRIMARY_BLOCK_REPLACED", "old_block_id": oid, "new_block_ids": hits})
            invalidated.add(oid)
        elif not hits:
            events.append({"kind": "PRIMARY_BLOCK_DROPPED", "old_block_id": oid, "new_block_ids": []})
            invalidated.add(oid)
    for nid, nps in new.items():
        hits = [oid for oid, ops in old.items() if ops & nps]
        if len(hits) > 1:
            events.append({"kind": "PRIMARY_BLOCK_MERGE", "old_block_ids": sorted(hits), "new_block_id": nid})
            invalidated.update(hits)
        elif not hits:
            events.append({"kind": "PRIMARY_BLOCK_NEW", "new_block_id": nid})
    status = "REFACTORIZED" if events else "STABLE_FACTORIZATION"
    return {"contract": REFACTOR_CONTRACT, "status": status, "events": events, "invalidated_block_ids": sorted(invalidated),
            "rule": "RECOMPUTE_FROM_CURRENT_RELATIONS; INVALIDATE_STALE_PRIMARY_BLOCKS; REQUIRE_LOSSLESS_RECOMPOSITION"}


def verify_factorization_certificate(cert: dict[str, Any]) -> bool:
    """Independent structural check usable by the final certifier without analyzer imports."""
    if not isinstance(cert, dict) or cert.get("contract") != CONTRACT: return False
    rp = cert.get("recomposition_proof") or {}
    if not (rp.get("lossless") is True and rp.get("information_loss") == 0 and rp.get("cross_block_dependency_edge_count") == 0): return False
    blocks = cert.get("blocks") or []
    seen: set[str] = set()
    for b in blocks:
        ids = b.get("option_ids") or []
        if not b.get("primary") or any(x in seen for x in ids): return False
        seen.update(ids)
    if len(seen) != int(cert.get("option_count", -1)): return False
    supplied = cert.get("factorization_sha256")
    if not supplied: return False
    row = deepcopy(cert); row.pop("factorization_sha256", None)
    calc = hashlib.sha256(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")).hexdigest()
    return calc == supplied
