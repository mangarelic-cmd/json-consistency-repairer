from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any
import hashlib, json

from .models import digest

CONTRACT = "json-consistency-repair.scoped-authority.v1"
PROOF_CONTRACT = "json-consistency-repair.authority-proof.v1"
POISON_CONTRACT = "json-consistency-repair.evidence-poisoning-firewall.v1"

_AUTHORITATIVE_ROLES = {"authoritative", "manifest"}
_DEFAULT_ROLE = "defaults"
_DEFAULT_AUTH_OPS = ("add", "replace", "witness", "project")
_DEFAULT_DEFAULT_OPS = ("add", "default", "witness")


def _stable(prefix: str, payload: Any, n: int = 20) -> str:
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return prefix + hashlib.sha256(raw).hexdigest()[:n]


def _norm_path(path: Any) -> str:
    p = str(path if path is not None else "")
    if p in {"", "*"}:
        return "*"
    return p if p.startswith("/") else "/" + p


def _path_match(scope_path: str, target_path: str) -> bool:
    s = _norm_path(scope_path)
    t = _norm_path(target_path)
    if s == "*":
        return True
    if t == "*":
        return s == "*"
    if s.endswith("/*"):
        base = s[:-2]
        return t == base or t.startswith(base + "/")
    # A plain JSON pointer scope authorizes the node and descendants.
    return t == s or t.startswith(s + "/")


def _as_list(v: Any, default: list[Any] | None = None) -> list[Any]:
    if v is None:
        return list(default or [])
    if isinstance(v, list):
        return list(v)
    if isinstance(v, tuple):
        return list(v)
    return [v]


def _parse_time(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    s = str(value).strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _scope_rows(raw: Any, *, fallback_ops: tuple[str, ...] = ()) -> list[dict[str, Any]]:
    if raw is None:
        return [{"paths": ["*"], "documents": ["*"], "schema_versions": ["*"], "operations": list(fallback_ops),
                 "valid_from": None, "valid_until": None}]
    rows = raw if isinstance(raw, list) else [raw]
    out = []
    for x in rows[:256]:
        if not isinstance(x, dict):
            continue
        out.append({
            "paths": sorted({_norm_path(p) for p in _as_list(x.get("paths") if "paths" in x else x.get("path"), ["*"])}) or ["*"],
            "documents": sorted({str(d) for d in _as_list(x.get("documents") if "documents" in x else x.get("document"), ["*"])}) or ["*"],
            "schema_versions": sorted({str(v) for v in _as_list(x.get("schema_versions") if "schema_versions" in x else x.get("schema_version"), ["*"])}) or ["*"],
            "operations": sorted({str(o).lower() for o in _as_list(x.get("operations"), list(fallback_ops))}) or list(fallback_ops),
            "valid_from": x.get("valid_from"),
            "valid_until": x.get("valid_until"),
        })
    return out


def _scope_matches(scope: dict[str, Any], *, target_path: str, operation: str, document: str | None,
                   schema_version: Any, evaluation_time: Any) -> tuple[bool, str]:
    if not any(_path_match(p, target_path) for p in scope.get("paths") or []):
        return False, "PATH_OUT_OF_SCOPE"
    op = str(operation or "witness").lower()
    ops = {str(x).lower() for x in scope.get("operations") or []}
    if op not in ops and "*" not in ops:
        return False, "OPERATION_OUT_OF_SCOPE"
    docs = {str(x) for x in scope.get("documents") or ["*"]}
    doc = "" if document is None else str(document)
    if "*" not in docs and doc not in docs:
        return False, "DOCUMENT_OUT_OF_SCOPE"
    vers = {str(x) for x in scope.get("schema_versions") or ["*"]}
    ver = "" if schema_version is None else str(schema_version)
    if "*" not in vers and ver not in vers:
        return False, "SCHEMA_VERSION_OUT_OF_SCOPE"
    vf, vu = _parse_time(scope.get("valid_from")), _parse_time(scope.get("valid_until"))
    if vf is not None or vu is not None:
        now = _parse_time(evaluation_time)
        if now is None:
            return False, "TEMPORAL_SCOPE_REQUIRES_EVALUATION_TIME"
        if vf is not None and now < vf:
            return False, "AUTHORITY_NOT_YET_VALID"
        if vu is not None and now > vu:
            return False, "AUTHORITY_EXPIRED"
    return True, "SCOPE_MATCH"


class _UF:
    def __init__(self, items: list[str]):
        self.p = {x: x for x in items}
    def find(self, x: str) -> str:
        self.p.setdefault(x, x)
        if self.p[x] != x:
            self.p[x] = self.find(self.p[x])
        return self.p[x]
    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[rb] = ra if ra < rb else rb
            self.p[ra] = ra if ra < rb else rb


def _provenance_parents(src: dict[str, Any]) -> list[str]:
    out: list[str] = []
    p = src.get("provenance")
    if isinstance(p, dict):
        out.extend(str(x) for x in _as_list(p.get("parents") or p.get("derived_from")) if str(x))
    out.extend(str(x) for x in _as_list(src.get("derived_from")) if str(x))
    return sorted(set(out))


def _compile_evidence_groups(context: tuple[dict[str, Any], ...], manifest: dict[str, Any]) -> tuple[dict[str, str], dict[str, Any]]:
    ids = sorted({str(s.get("source_id") or "") for s in context if str(s.get("source_id") or "")})
    uf = _UF(ids)
    byid = {str(s.get("source_id")): s for s in context if str(s.get("source_id") or "")}
    findings: list[dict[str, Any]] = []
    edge_rows: list[dict[str, Any]] = []

    # Declared independence groups are correlation groups, not proof of independence.
    groups: dict[str, list[str]] = {}
    for sid, s in byid.items():
        g = str(s.get("independent_group") or sid)
        groups.setdefault(g, []).append(sid)
    for g, members in groups.items():
        for x in members[1:]:
            uf.union(members[0], x)
            edge_rows.append({"kind": "DECLARED_GROUP", "a": members[0], "b": x, "group": g})

    # Byte/semantic-identical loaded values cannot be counted as independent replicas.
    digests: dict[str, list[str]] = {}
    for sid, s in byid.items():
        try:
            d = digest(s.get("value"))
        except Exception:
            d = _stable("unhash_", repr(s.get("value")), 24)
        digests.setdefault(d, []).append(sid)
    strict_content_dedup = bool(manifest.get("evidence_policy",{}).get("identical_content_is_correlated", False)) if isinstance(manifest.get("evidence_policy"),dict) else False
    for d, members in digests.items():
        if len(members) < 2:
            continue
        declared = {str(byid[x].get("independent_group") or x) for x in members}
        findings.append({"code": "IDENTICAL_CONTENT_POTENTIAL_CORRELATION", "source_ids": sorted(members), "declared_groups": sorted(declared), "content_digest": d,
                         "collapsed": strict_content_dedup})
        if strict_content_dedup:
            for x in members[1:]:
                uf.union(members[0], x)
                edge_rows.append({"kind": "IDENTICAL_CONTENT", "a": members[0], "b": x, "content_digest": d})
            if len(declared) > 1:
                findings.append({"code": "IDENTICAL_CONTENT_FALSE_INDEPENDENCE", "source_ids": sorted(members), "declared_groups": sorted(declared), "content_digest": d})

    # Explicit derivation lineage collapses source copies with their ancestors.
    for sid, s in byid.items():
        for parent in _provenance_parents(s):
            if parent not in byid:
                findings.append({"code": "UNKNOWN_PROVENANCE_PARENT", "source_id": sid, "parent_source_id": parent})
                continue
            uf.union(sid, parent)
            edge_rows.append({"kind": "DERIVATION_LINEAGE", "a": sid, "b": parent})
            if str(s.get("independent_group") or sid) != str(byid[parent].get("independent_group") or parent):
                findings.append({"code": "DERIVATION_FALSE_INDEPENDENCE", "source_id": sid, "parent_source_id": parent})

    # Manifest-declared correlation edges/groups are authoritative evidence topology.
    raw_corr = manifest.get("source_correlations") or []
    if isinstance(raw_corr, list):
        for i, row in enumerate(raw_corr[:1024]):
            if not isinstance(row, dict):
                continue
            members = [str(x) for x in _as_list(row.get("source_ids")) if str(x) in byid]
            if len(members) < 2:
                continue
            for x in members[1:]:
                uf.union(members[0], x)
                edge_rows.append({"kind": "MANIFEST_CORRELATION", "a": members[0], "b": x, "correlation_id": str(row.get("correlation_id") or i)})

    components: dict[str, list[str]] = {}
    for sid in ids:
        components.setdefault(uf.find(sid), []).append(sid)
    effective: dict[str, str] = {}
    comp_rows = []
    for members in sorted((sorted(v) for v in components.values()), key=lambda x: x):
        gid = _stable("eg_", members, 20)
        roles = sorted({str(byid[x].get("role") or "reference") for x in members})
        for sid in members:
            effective[sid] = gid
        comp_rows.append({"effective_group": gid, "source_ids": members, "roles": roles})
        if "development" in roles and "heldout" in roles:
            findings.append({"code": "HELDOUT_CORRELATED_WITH_DEVELOPMENT", "effective_group": gid, "source_ids": members})

    poison = {
        "contract": POISON_CONTRACT,
        "effective_groups": comp_rows,
        "correlation_edges": sorted(edge_rows, key=lambda x: (x["kind"], x["a"], x["b"])),
        "findings": sorted(findings, key=lambda x: (x.get("code", ""), json.dumps(x, sort_keys=True, default=str))),
        "finding_count": len(findings),
        "same_effective_group_is_not_independent": True,
        "identical_content_is_not_independent_when_strict_policy_enabled": strict_content_dedup,
        "identical_content_is_always_flagged": True,
        "derivation_lineage_is_not_independent": True,
    }
    poison["firewall_sha256"] = digest(poison)
    return effective, poison


def _source_schema_version(primary: Any, manifest: dict[str, Any]) -> Any:
    if "current_schema_version" in manifest:
        return manifest.get("current_schema_version")
    if isinstance(primary, dict) and "schema_version" in primary and not isinstance(primary.get("schema_version"), (dict, list)):
        return primary.get("schema_version")
    return None


def compile_authority_registry(primary: Any, context: tuple[dict[str, Any], ...], manifest: dict[str, Any] | None = None,
                               *, document: str | None = None) -> dict[str, Any]:
    manifest = deepcopy(manifest or {})
    context = tuple(context or ())
    effective, poison = _compile_evidence_groups(context, manifest)
    sources = []
    byid = {}
    conflicts: list[dict[str, Any]] = []
    seen = set()
    for s in context:
        sid = str(s.get("source_id") or "").strip()
        if not sid or sid in seen:
            conflicts.append({"code": "DUPLICATE_OR_EMPTY_SOURCE_ID", "source_id": sid})
            continue
        seen.add(sid)
        role = str(s.get("role") or "reference")
        manifest_grants=[]
        for h in manifest.get("materialization_hints") or []:
            if isinstance(h,dict) and str(h.get("source_id") or "")==sid and str(h.get("mode") or "").upper()=="AUTHORITATIVE":
                tp=str(h.get("target_path") or "")
                if tp: manifest_grants.append({"paths":[tp],"documents":["*"],"schema_versions":["*"],"operations":["add","replace","witness"],"valid_from":None,"valid_until":None})
        for pr in manifest.get("projections") or []:
            if isinstance(pr,dict) and str(pr.get("source_id") or "")==sid and bool(pr.get("authoritative",False)):
                tp=str(pr.get("target_path") or "")
                if tp: manifest_grants.append({"paths":[tp],"documents":["*"],"schema_versions":["*"],"operations":["add","replace","project","witness"],"valid_from":None,"valid_until":None})
        if role in _AUTHORITATIVE_ROLES:
            fallback = _DEFAULT_AUTH_OPS
            base = "DIRECT_AUTHORITATIVE"
            scopes = _scope_rows(s.get("authority_scope"), fallback_ops=fallback)
        elif role == _DEFAULT_ROLE:
            fallback = _DEFAULT_DEFAULT_OPS
            base = "DEFAULT_AUTHORITY"
            scopes = _scope_rows(s.get("authority_scope"), fallback_ops=fallback)
        elif manifest_grants:
            base = "MANIFEST_SCOPED_GRANT"
            scopes = manifest_grants
        else:
            fallback = ()
            base = "CONTEXT_ONLY"
            scopes = []
        row = {
            "source_id": sid, "role": role, "eligible": bool(s.get("eligible", True)),
            "declared_independent_group": s.get("independent_group", sid),
            "effective_evidence_group": effective.get(sid, _stable("eg_", [sid], 20)),
            "schema_version": s.get("schema_version"), "document": s.get("document"),
            "base_authority": base, "authority_scopes": scopes,
            "content_digest": digest(s.get("value")), "provenance_parents": _provenance_parents(s),
        }
        sources.append(row); byid[sid] = row

    revocations = set(str(x) for x in _as_list(manifest.get("revocations")) if str(x))
    delegations = []
    raw_delegations = manifest.get("delegations") or []
    if not isinstance(raw_delegations, list) or len(raw_delegations) > 1024:
        conflicts.append({"code": "DELEGATION_SET_OUT_OF_BOUNDS"})
        raw_delegations = []
    for i, d in enumerate(raw_delegations):
        if not isinstance(d, dict):
            continue
        did = str(d.get("delegation_id") or _stable("del_", d, 20))
        grantor = str(d.get("grantor_source_id") or "")
        delegate = str(d.get("delegate_source_id") or "")
        if grantor not in byid or delegate not in byid:
            conflicts.append({"code": "UNKNOWN_DELEGATION_ENDPOINT", "delegation_id": did, "grantor_source_id": grantor, "delegate_source_id": delegate})
            continue
        scopes = _scope_rows(d.get("scope") if "scope" in d else d.get("authority_scope"), fallback_ops=_DEFAULT_AUTH_OPS)
        delegations.append({"delegation_id": did, "grantor_source_id": grantor, "delegate_source_id": delegate,
                            "scopes": scopes, "revoked": did in revocations or bool(d.get("revoked", False))})

    reg = {
        "contract": CONTRACT,
        "evaluation": {"document": document, "schema_version": _source_schema_version(primary, manifest), "evaluation_time": manifest.get("evaluation_time")},
        "sources": sorted(sources, key=lambda x: x["source_id"]),
        "delegations": sorted(delegations, key=lambda x: x["delegation_id"]),
        "revocations": sorted(revocations),
        "evidence_poisoning_firewall": poison,
        "conflicts": sorted(conflicts, key=lambda x: (x.get("code", ""), json.dumps(x, sort_keys=True, default=str))),
        "valid": not conflicts,
    }
    reg["registry_sha256"] = digest(reg)
    return reg


def _direct_scope_match(src: dict[str, Any], *, target_path: str, operation: str, document: str | None,
                        schema_version: Any, evaluation_time: Any) -> tuple[bool, dict[str, Any] | None, str]:
    if not src.get("eligible", True):
        return False, None, "SOURCE_INELIGIBLE"
    if src.get("base_authority") == "CONTEXT_ONLY":
        return False, None, "NO_DIRECT_AUTHORITY"
    last = "NO_SCOPE_MATCH"
    for scope in src.get("authority_scopes") or []:
        ok, reason = _scope_matches(scope, target_path=target_path, operation=operation, document=document,
                                    schema_version=schema_version, evaluation_time=evaluation_time)
        if ok:
            return True, scope, "DIRECT_SCOPE_MATCH"
        last = reason
    return False, None, last


def evaluate_authority(registry: dict[str, Any], source_id: str, *, target_path: str, operation: str,
                       document: str | None = None, schema_version: Any = None, evaluation_time: Any = None) -> dict[str, Any]:
    sources = {str(x.get("source_id")): x for x in registry.get("sources") or [] if isinstance(x, dict)}
    sid = str(source_id or "")
    ev = registry.get("evaluation") or {}
    if document is None: document = ev.get("document")
    if schema_version is None: schema_version = ev.get("schema_version")
    if evaluation_time is None: evaluation_time = ev.get("evaluation_time")
    src = sources.get(sid)
    chain: list[dict[str, Any]] = []
    authorized = False; reason = "UNKNOWN_SOURCE"; matched_scope = None

    if src is not None:
        ok, scope, why = _direct_scope_match(src, target_path=target_path, operation=operation, document=document,
                                             schema_version=schema_version, evaluation_time=evaluation_time)
        if ok:
            authorized = True; reason = why; matched_scope = scope
            chain = [{"kind": "DIRECT", "source_id": sid, "scope": deepcopy(scope)}]
        else:
            reason = why
            # Bounded BFS from every direct-authority root through matching, non-revoked delegations.
            edges = registry.get("delegations") or []
            roots = []
            for rid, rsrc in sources.items():
                rok, rscope, _ = _direct_scope_match(rsrc, target_path=target_path, operation=operation, document=document,
                                                      schema_version=schema_version, evaluation_time=evaluation_time)
                if rok:
                    roots.append((rid, rscope))
            queue: list[tuple[str, list[dict[str, Any]]]] = [(rid, [{"kind": "DIRECT", "source_id": rid, "scope": deepcopy(rscope)}]) for rid, rscope in roots]
            visited = set()
            while queue:
                cur, cchain = queue.pop(0)
                state = (cur, tuple(x.get("delegation_id") for x in cchain if x.get("delegation_id")))
                if state in visited or len(cchain) > 17:
                    continue
                visited.add(state)
                if cur == sid:
                    authorized = True; reason = "DELEGATED_SCOPE_MATCH"; chain = cchain; matched_scope = cchain[-1].get("scope"); break
                for d in edges:
                    if d.get("grantor_source_id") != cur or d.get("revoked"):
                        continue
                    for sc in d.get("scopes") or []:
                        sok, _ = _scope_matches(sc, target_path=target_path, operation=operation, document=document,
                                                schema_version=schema_version, evaluation_time=evaluation_time)
                        if sok:
                            queue.append((str(d.get("delegate_source_id")), cchain + [{"kind": "DELEGATION", "delegation_id": d.get("delegation_id"),
                                                                                     "grantor_source_id": cur, "delegate_source_id": d.get("delegate_source_id"), "scope": deepcopy(sc)}]))
                            break

    proof = {
        "contract": PROOF_CONTRACT, "source_id": sid, "target_path": str(target_path), "operation": str(operation).lower(),
        "document": document, "schema_version": schema_version, "evaluation_time": evaluation_time,
        "authorized": bool(authorized), "reason": reason, "matched_scope": deepcopy(matched_scope),
        "delegation_chain": chain,
        "effective_evidence_group": (src or {}).get("effective_evidence_group"),
        "authority_registry_sha256": registry.get("registry_sha256"),
    }
    proof["proof_sha256"] = digest(proof)
    return proof


def verify_authority_registry(registry: dict[str, Any]) -> bool:
    if not isinstance(registry, dict) or registry.get("contract") != CONTRACT:
        return False
    supplied = registry.get("registry_sha256")
    if not supplied:
        return False
    tmp = deepcopy(registry); tmp.pop("registry_sha256", None)
    if digest(tmp) != supplied:
        return False
    poison = registry.get("evidence_poisoning_firewall") or {}
    ps = poison.get("firewall_sha256")
    ptmp = deepcopy(poison); ptmp.pop("firewall_sha256", None)
    if not ps or digest(ptmp) != ps:
        return False
    return True


def verify_authority_proof(proof: dict[str, Any], registry: dict[str, Any] | None = None) -> bool:
    if not isinstance(proof, dict) or proof.get("contract") != PROOF_CONTRACT:
        return False
    supplied = proof.get("proof_sha256")
    if not supplied:
        return False
    tmp = deepcopy(proof); tmp.pop("proof_sha256", None)
    if digest(tmp) != supplied:
        return False
    if registry is not None:
        if proof.get("authority_registry_sha256") != registry.get("registry_sha256"):
            return False
        # Re-evaluate to prevent a forged internally-hashed authorization result.
        actual = evaluate_authority(registry, str(proof.get("source_id") or ""), target_path=str(proof.get("target_path") or ""),
                                    operation=str(proof.get("operation") or "witness"), document=proof.get("document"),
                                    schema_version=proof.get("schema_version"), evaluation_time=proof.get("evaluation_time"))
        return actual.get("proof_sha256") == supplied
    return True
