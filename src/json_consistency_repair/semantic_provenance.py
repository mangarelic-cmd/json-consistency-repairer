from __future__ import annotations

from copy import deepcopy
from typing import Any
import hashlib, json

from .models import AnalysisResult, Candidate, Issue, digest
from .tree import decode_pointer, get

CONTRACT = "json-consistency-repair.semantic-claim-provenance.v1"
PROOF_CONTRACT = "json-consistency-repair.semantic-claim-proof.v1"
FIREWALL_CONTRACT = "json-consistency-repair.semantic-claim-provenance-firewall.v1"
MERKLE_CONTRACT = "json-consistency-repair.json-merkle-inclusion.v1"

_ALLOWED = {"SOURCE_EXACT", "DERIVED_EXACT", "USER_DECLARED", "INFERRED", "UNVERIFIED_ATTRIBUTION"}
_GENERIC_SOURCE_LABELS = {"", "authoritative", "user", "user_declared", "json_schema", "inferred", "derived_exact"}
_RULE_ID_KEYS = ("rule_id", "logic_rule_id", "conservation_rule_id", "moment_rule_id", "robust_rule_id", "control_rule_id")


def _canon(v: Any) -> bytes:
    return json.dumps(v, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False, default=str).encode("utf-8")


def _sha(v: Any) -> str:
    return hashlib.sha256(_canon(v)).hexdigest()


def _clean_rule(rule: dict[str, Any]) -> dict[str, Any]:
    return {k: deepcopy(v) for k, v in rule.items() if k not in {"claim_provenance", "semantic_provenance", "provenance"}}


def _leaf(v: Any) -> str:
    return _sha(["json-leaf-v1", v])


def merkle_root(v: Any) -> str:
    if isinstance(v, dict):
        return _sha(["json-object-v1", [[k, merkle_root(v[k])] for k in sorted(v)]])
    if isinstance(v, list):
        return _sha(["json-array-v1", [merkle_root(x) for x in v]])
    return _leaf(v)


def merkle_inclusion(root: Any, pointer: str) -> dict[str, Any] | None:
    try:
        toks = decode_pointer(pointer)
    except Exception:
        return None
    cur = root
    frames: list[dict[str, Any]] = []
    for tok in toks:
        if isinstance(cur, dict):
            if tok not in cur:
                return None
            siblings = [[k, merkle_root(cur[k])] for k in sorted(cur) if k != tok]
            frames.append({"container": "object", "key": tok, "siblings": siblings})
            cur = cur[tok]
        elif isinstance(cur, list):
            try:
                idx = int(tok)
            except Exception:
                return None
            if idx < 0 or idx >= len(cur):
                return None
            frames.append({"container": "array", "index": idx, "length": len(cur),
                           "siblings": [[i, merkle_root(x)] for i, x in enumerate(cur) if i != idx]})
            cur = cur[idx]
        else:
            return None
    proof = {"contract": MERKLE_CONTRACT, "pointer": pointer, "fragment": deepcopy(cur),
             "fragment_sha256": digest(cur), "frames": frames, "root_merkle_sha256": merkle_root(root)}
    proof["proof_sha256"] = _sha({k: v for k, v in proof.items() if k != "proof_sha256"})
    return proof


def verify_merkle_inclusion(proof: dict[str, Any]) -> bool:
    if not isinstance(proof, dict) or proof.get("contract") != MERKLE_CONTRACT:
        return False
    supplied = proof.get("proof_sha256")
    if not supplied or _sha({k: v for k, v in proof.items() if k != "proof_sha256"}) != supplied:
        return False
    if digest(proof.get("fragment")) != proof.get("fragment_sha256"):
        return False
    h = merkle_root(proof.get("fragment"))
    for frame in reversed(proof.get("frames") or []):
        if frame.get("container") == "object":
            key = frame.get("key")
            rows = list(frame.get("siblings") or []) + [[key, h]]
            try:
                rows = sorted(rows, key=lambda x: x[0])
            except Exception:
                return False
            if len({x[0] for x in rows}) != len(rows):
                return False
            h = _sha(["json-object-v1", rows])
        elif frame.get("container") == "array":
            idx = frame.get("index"); length = frame.get("length")
            if not isinstance(idx, int) or not isinstance(length, int) or length < 1 or idx < 0 or idx >= length:
                return False
            mp = {i: x for i, x in (frame.get("siblings") or [])}
            if idx in mp or len(mp) != length - 1:
                return False
            mp[idx] = h
            if sorted(mp) != list(range(length)):
                return False
            h = _sha(["json-array-v1", [mp[i] for i in range(length)]])
        else:
            return False
    return h == proof.get("root_merkle_sha256")


def _source_index(config) -> dict[str, dict[str, Any]]:
    out = {}
    for row in getattr(config, "source_context", ()) or ():
        if not isinstance(row, dict):
            continue
        sid = str(row.get("source_id") or "")
        if not sid or "value" not in row:
            continue
        value = row.get("value")
        out[sid] = {"source_id": sid, "role": row.get("role"), "source_path": row.get("source_path"),
                    "canonical_sha256": digest(value), "merkle_sha256": merkle_root(value), "value": value}
    return out


def _implicit_external_attribution(rule: dict[str, Any]) -> dict[str, Any] | None:
    """Detect source-label claims that would otherwise bypass PASS033 provenance declarations."""
    raw = rule.get("source")
    if raw is None:
        return None
    label = str(raw).strip()
    if label.lower() in _GENERIC_SOURCE_LABELS:
        return None
    return {"classification": "UNVERIFIED_ATTRIBUTION", "claimed_source_label": label}


def _rule_inventory(config) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    attrs = ("constraint_rules", "logic_rules", "conservation_rules", "system_rules", "moment_rules", "robust_envelope_rules", "semantic_quotient_rules", "controllability_rules")
    for attr in attrs:
        for i, rule in enumerate(getattr(config, attr, ()) or ()):
            if not isinstance(rule, dict):
                continue
            rid = next((rule.get(k) for k in _RULE_ID_KEYS if rule.get(k) is not None), None)
            prov = rule.get("claim_provenance") or rule.get("semantic_provenance") or rule.get("provenance") or _implicit_external_attribution(rule)
            if rid is not None:
                out[str(rid)] = {"rule_id": str(rid), "rule_family": attr, "rule": _clean_rule(rule), "provenance": deepcopy(prov)}
            elif prov:
                # Provenance-bearing external claims must be addressable by a stable public identity.
                auto = "unaddressed_" + hashlib.sha256(_canon([attr, i, _clean_rule(rule)])).hexdigest()[:20]
                out[auto] = {"rule_id": auto, "rule_family": attr, "rule": _clean_rule(rule), "provenance": deepcopy(prov), "unaddressed": True}
    schema = getattr(config, "json_schema", None)
    if isinstance(schema, (dict, bool)) and schema not in ({}, None):
        out["__json_schema__"] = {"rule_id": "__json_schema__", "rule_family": "json_schema", "rule": deepcopy(schema),
                                    "provenance": deepcopy(getattr(config, "schema_claim_provenance", None))}
    manifest = getattr(config, "source_manifest", None) or {}
    decls = manifest.get("claim_provenance") or manifest.get("semantic_claims") or []
    if isinstance(decls, dict):
        decls = [decls]
    if isinstance(decls, list):
        for d in decls[:1024]:
            if not isinstance(d, dict):
                continue
            rid = str(d.get("rule_id") or d.get("claim_id") or "")
            if rid in out:
                out[rid]["provenance"] = deepcopy(d)
            elif rid:
                out[rid] = {"rule_id": rid, "rule_family": "manifest_claim", "rule": deepcopy(d.get("claim_value")),
                            "provenance": deepcopy(d), "manifest_only": True}
    return out


def _resolve_source_ref(ref: dict[str, Any], sources: dict[str, dict[str, Any]]) -> tuple[Any, dict[str, Any] | None, str | None]:
    sid = str(ref.get("source_id") or "")
    ptr = str(ref.get("source_pointer") if ref.get("source_pointer") is not None else ref.get("pointer") or "")
    src = sources.get(sid)
    if src is None:
        return None, None, "SOURCE_ID_NOT_LOADED"
    proof = merkle_inclusion(src["value"], ptr)
    if proof is None:
        return None, None, "SOURCE_POINTER_NOT_FOUND"
    proof["source_id"] = sid
    proof["source_canonical_sha256"] = src["canonical_sha256"]
    proof["source_path"] = src.get("source_path")
    # Re-hash after source metadata is bound to the inclusion proof.
    proof["proof_sha256"] = _sha({k: v for k, v in proof.items() if k != "proof_sha256"})
    return deepcopy(proof["fragment"]), proof, None


def _render_template(v: Any, sources: dict[str, dict[str, Any]], inclusions: list[dict[str, Any]]) -> tuple[Any, str | None]:
    if isinstance(v, dict) and set(v) == {"$source"} and isinstance(v["$source"], dict):
        value, proof, err = _resolve_source_ref(v["$source"], sources)
        if err:
            return None, err
        inclusions.append(proof)
        return value, None
    if isinstance(v, dict):
        out = {}
        for k in sorted(v):
            x, err = _render_template(v[k], sources, inclusions)
            if err:
                return None, err
            out[k] = x
        return out, None
    if isinstance(v, list):
        out = []
        for item in v:
            x, err = _render_template(item, sources, inclusions)
            if err:
                return None, err
            out.append(x)
        return out, None
    return deepcopy(v), None


def _render_template_from_inclusions(v: Any, inclusions: list[dict[str, Any]]) -> tuple[Any, str | None]:
    """Re-evaluate a DERIVED_EXACT template using only proof-carried source fragments."""
    by_ref = {}
    for inc in inclusions or []:
        if not isinstance(inc, dict):
            continue
        key = (str(inc.get("source_id") or ""), str(inc.get("pointer") or ""))
        if key in by_ref and by_ref[key] != inc.get("fragment"):
            return None, "DUPLICATE_SOURCE_REFERENCE_CONFLICT"
        by_ref[key] = deepcopy(inc.get("fragment"))
    def walk(x):
        if isinstance(x, dict) and set(x) == {"$source"} and isinstance(x["$source"], dict):
            ref = x["$source"]
            key = (str(ref.get("source_id") or ""), str(ref.get("source_pointer") if ref.get("source_pointer") is not None else ref.get("pointer") or ""))
            if key not in by_ref:
                raise KeyError(key)
            return deepcopy(by_ref[key])
        if isinstance(x, dict):
            return {k: walk(x[k]) for k in sorted(x)}
        if isinstance(x, list):
            return [walk(y) for y in x]
        return deepcopy(x)
    try:
        return walk(v), None
    except KeyError:
        return None, "DERIVATION_REFERENCE_NOT_PROVED"


def _proof(rule_id: str, family: str, claim: Any, provenance: Any, sources: dict[str, dict[str, Any]], *, unaddressed: bool = False) -> dict[str, Any]:
    p = provenance if isinstance(provenance, dict) else None
    classification = str((p or {}).get("classification") or ("USER_DECLARED" if p is None else "UNVERIFIED_ATTRIBUTION")).upper()
    if classification not in _ALLOWED:
        classification = "UNVERIFIED_ATTRIBUTION"
    verified = False; reason = None; inclusions: list[dict[str, Any]] = []; derived = None
    if unaddressed:
        classification = "UNVERIFIED_ATTRIBUTION"; reason = "PROVENANCE_CLAIM_REQUIRES_STABLE_RULE_ID"
    elif classification == "USER_DECLARED":
        # USER_DECLARED is valid only when it does not pretend to be extracted from an external source.
        if p and any(k in p for k in ("source_id", "source_pointer", "pointer", "template", "derived_from")):
            classification = "UNVERIFIED_ATTRIBUTION"; reason = "USER_DECLARED_CANNOT_CARRY_EXTERNAL_ATTRIBUTION"
        else:
            verified = True; reason = "EXPLICIT_USER_RULE_NO_EXTERNAL_ATTRIBUTION"
    elif classification == "SOURCE_EXACT":
        value, inc, err = _resolve_source_ref(p or {}, sources)
        if err:
            reason = err
        else:
            inclusions.append(inc)
            verified = value == claim
            reason = "EXACT_SOURCE_FRAGMENT_MATCH" if verified else "SOURCE_FRAGMENT_DOES_NOT_REPRODUCE_CLAIM"
    elif classification == "DERIVED_EXACT":
        template = (p or {}).get("template")
        if template is None:
            reason = "DERIVED_EXACT_TEMPLATE_MISSING"
        else:
            derived, err = _render_template(template, sources, inclusions)
            if err:
                reason = err
            else:
                verified = derived == claim and all(verify_merkle_inclusion(x) for x in inclusions)
                reason = "DETERMINISTIC_TEMPLATE_REDERIVATION_MATCH" if verified else "DERIVATION_DOES_NOT_REPRODUCE_CLAIM"
    elif classification == "INFERRED":
        # External rules may not self-label as inferred. Inferred claims are emitted only for internal discovered relations.
        reason = "EXTERNAL_RULE_CANNOT_SELF_PROMOTE_AS_INFERRED"
    else:
        reason = "UNVERIFIED_EXTERNAL_ATTRIBUTION"
    row = {"contract": PROOF_CONTRACT, "claim_id": rule_id, "claim_family": family,
           "classification": classification, "verified": bool(verified), "reason": reason,
           # The payload is deliberately carried by the proof: a hash alone proves integrity,
           # not that SOURCE_EXACT/DERIVED_EXACT semantically reproduces the law being used.
           "claim_payload": deepcopy(claim), "claim_sha256": digest(claim),
           "provenance_descriptor": deepcopy(p), "source_inclusions": inclusions,
           "derivation_template": deepcopy((p or {}).get("template")) if classification == "DERIVED_EXACT" else None,
           "derived_value_sha256": digest(derived) if derived is not None else None}
    row["proof_sha256"] = _sha({k: v for k, v in row.items() if k != "proof_sha256"})
    return row


def compile_semantic_claim_registry(config) -> dict[str, Any]:
    sources = _source_index(config); inv = _rule_inventory(config)
    proofs = []
    for rid in sorted(inv):
        row = inv[rid]
        proofs.append(_proof(rid, row.get("rule_family") or "rule", row.get("rule"), row.get("provenance"), sources,
                             unaddressed=bool(row.get("unaddressed"))))
    reg = {"contract": CONTRACT,
           "source_commitments": [{k: v for k, v in sources[s].items() if k != "value"} for s in sorted(sources)],
           "claims": proofs, "claim_count": len(proofs),
           "verified_claim_count": sum(1 for p in proofs if p.get("verified")),
           "blocked_claim_count": sum(1 for p in proofs if not p.get("verified")),
           "policy": {"hash_integrity_is_not_semantic_attribution": True,
                      "unverified_attribution_can_authorize_mutation": False,
                      "user_declared_is_not_source_exact": True,
                      "source_exact_requires_merkle_inclusion": True,
                      "derived_exact_requires_deterministic_rederivation": True}}
    reg["registry_sha256"] = _sha({k: v for k, v in reg.items() if k != "registry_sha256"})
    return reg


def verify_semantic_claim_proof(proof: dict[str, Any]) -> bool:
    if not isinstance(proof, dict) or proof.get("contract") != PROOF_CONTRACT:
        return False
    supplied = proof.get("proof_sha256")
    if not supplied or _sha({k: v for k, v in proof.items() if k != "proof_sha256"}) != supplied:
        return False
    if digest(proof.get("claim_payload")) != proof.get("claim_sha256"):
        return False
    inclusions = proof.get("source_inclusions") or []
    for inc in inclusions:
        if not verify_merkle_inclusion(inc):
            return False
    cls = proof.get("classification")
    if cls not in _ALLOWED or not isinstance(proof.get("verified"), bool):
        return False
    p = proof.get("provenance_descriptor")
    if cls == "SOURCE_EXACT" and proof.get("verified"):
        if len(inclusions) != 1:
            return False
        inc = inclusions[0]
        if digest(inc.get("fragment")) != proof.get("claim_sha256") or inc.get("fragment") != proof.get("claim_payload"):
            return False
        if not isinstance(p, dict):
            return False
        sid = str(p.get("source_id") or "")
        ptr = str(p.get("source_pointer") if p.get("source_pointer") is not None else p.get("pointer") or "")
        if sid != str(inc.get("source_id") or "") or ptr != str(inc.get("pointer") or ""):
            return False
    if cls == "DERIVED_EXACT" and proof.get("verified"):
        template = proof.get("derivation_template")
        if template is None or not inclusions:
            return False
        rendered, err = _render_template_from_inclusions(template, inclusions)
        if err or rendered != proof.get("claim_payload"):
            return False
        if digest(rendered) != proof.get("derived_value_sha256") or digest(rendered) != proof.get("claim_sha256"):
            return False
    if cls == "USER_DECLARED" and proof.get("verified"):
        if inclusions or proof.get("derivation_template") is not None:
            return False
        if isinstance(p, dict) and any(k in p for k in ("source_id", "source_pointer", "pointer", "template", "derived_from")):
            return False
    if cls in {"INFERRED", "UNVERIFIED_ATTRIBUTION"} and proof.get("verified"):
        return False
    return True


def verify_semantic_claim_registry(reg: dict[str, Any]) -> bool:
    if not isinstance(reg, dict) or reg.get("contract") != CONTRACT:
        return False
    supplied = reg.get("registry_sha256")
    if not supplied or _sha({k: v for k, v in reg.items() if k != "registry_sha256"}) != supplied:
        return False
    commitments = reg.get("source_commitments") or []
    if not isinstance(commitments, list):
        return False
    by_source = {}
    for row in commitments:
        if not isinstance(row, dict):
            return False
        sid = str(row.get("source_id") or "")
        if not sid or sid in by_source or not row.get("canonical_sha256") or not row.get("merkle_sha256"):
            return False
        by_source[sid] = row
    claims = reg.get("claims") or []
    if any(not verify_semantic_claim_proof(p) for p in claims):
        return False
    for proof in claims:
        for inc in proof.get("source_inclusions") or []:
            src = by_source.get(str(inc.get("source_id") or ""))
            if src is None:
                return False
            if inc.get("root_merkle_sha256") != src.get("merkle_sha256"):
                return False
            if inc.get("source_canonical_sha256") != src.get("canonical_sha256"):
                return False
    ids = [p.get("claim_id") for p in claims]
    return (len(ids) == len(set(ids)) and reg.get("claim_count") == len(claims)
            and reg.get("verified_claim_count") == sum(1 for p in claims if p.get("verified"))
            and reg.get("blocked_claim_count") == sum(1 for p in claims if not p.get("verified")))


def _ids_from(meta: dict[str, Any] | None) -> set[str]:
    m = meta or {}; out = set()
    for k in _RULE_ID_KEYS:
        if m.get(k) is not None:
            out.add(str(m[k]))
    for k in ("rule_ids",):
        for x in m.get(k) or []:
            out.add(str(x))
    return out


def _relation_ids(rel: dict[str, Any]) -> set[str]:
    out = _ids_from(rel)
    # Schema relation/candidates share schema_id rather than a rule_id. The loaded schema is one claim.
    if rel.get("kind") in {"authoritative_json_schema", "authoritative_boundary_contract"}:
        out.add("__json_schema__")
    return out


def _candidate_ids(c: Candidate) -> set[str]:
    ids = _ids_from(c.metadata)
    if c.analyzer == "schema_bridge":
        ids.add("__json_schema__")
    return ids


def apply_semantic_claim_provenance_firewall(root: Any, analysis: AnalysisResult, config, *, preanalysis: dict[str, Any] | None = None) -> tuple[AnalysisResult, dict[str, Any]]:
    if not bool(getattr(config, "enable_semantic_claim_provenance", True)):
        return analysis, {"contract": FIREWALL_CONTRACT, "enabled": False, "blocked_candidates": [], "blocked_relations": []}
    registry = deepcopy((preanalysis or {}).get("registry")) if isinstance(preanalysis, dict) and (preanalysis or {}).get("registry") else compile_semantic_claim_registry(config)
    by = {p.get("claim_id"): p for p in registry.get("claims") or []}
    blocked_claims = {rid for rid, p in by.items() if not p.get("verified")}
    kept_rel = []; blocked_rel = []
    for rel in analysis.relations:
        ids = _relation_ids(rel)
        bad = sorted(ids & blocked_claims)
        if bad:
            blocked_rel.append({"relation_id": rel.get("relation_id"), "claim_ids": bad, "reason": "SEMANTIC_ATTRIBUTION_NOT_VERIFIED"})
        else:
            kept_rel.append(rel)
    kept_c = []; blocked_c = []
    for c in analysis.candidates:
        ids = _candidate_ids(c)
        bad = sorted(ids & blocked_claims)
        if bad:
            blocked_c.append({"candidate_id": c.candidate_id, "path": c.path, "claim_ids": bad, "reason": "SEMANTIC_ATTRIBUTION_NOT_VERIFIED"})
        else:
            kept_c.append(c)
    issues = list(analysis.issues)
    # Configuration-level provenance failures are terminal objects in their own right.
    # They remain visible even when the unverified rule was removed before analysis.
    _pre_for_issues = preanalysis if isinstance(preanalysis, dict) else project_verified_semantic_config(config)[1]
    for gate in _pre_for_issues.get("configuration_gates") or []:
        issues.append(Issue("semantic_claim_provenance", "semantic_attribution_gate", "",
                            "An externally attributed repair law was disabled because its claimed lineage could not be reproduced exactly.",
                            "error", False, deepcopy(gate)))
    for row in blocked_c:
        issues.append(Issue("semantic_claim_provenance", "unverified_attribution_blocks_mutation", row["path"],
                            "A repair candidate depends on a claim whose source attribution cannot be reproduced exactly.",
                            "error", False, {"candidate_id": row["candidate_id"], "claim_ids": row["claim_ids"], "reason": row["reason"]}))
    inferred = [r for r in kept_rel if not _relation_ids(r) and str(r.get("constraint_source") or r.get("logic_source") or r.get("schema_source") or r.get("source") or "").lower() not in {"authoritative"}]
    # Pre-analysis gates are recomputed from the requested configuration so the certificate
    # exposes claims removed before any analyzer could let them influence another repair.
    pre = preanalysis if isinstance(preanalysis, dict) else project_verified_semantic_config(config)[1]
    config_gates = deepcopy(pre.get("configuration_gates") or [])
    cert = {"contract": FIREWALL_CONTRACT, "enabled": True, "registry": registry,
            "configuration_gates": config_gates, "gated_rule_count": len(config_gates),
            "blocked_candidates": blocked_c, "blocked_relations": blocked_rel,
            "blocked_candidate_count": len(blocked_c), "blocked_relation_count": len(blocked_rel),
            "inferred_relation_count": len(inferred),
            "status": "PASS" if not blocked_c and not blocked_rel and not config_gates else "GATED_UNVERIFIED_ATTRIBUTION"}
    cert["certificate_sha256"] = _sha({k: v for k, v in cert.items() if k != "certificate_sha256"})
    return AnalysisResult(issues, kept_c, kept_rel), cert


def verify_semantic_firewall(cert: dict[str, Any]) -> bool:
    if not isinstance(cert, dict) or cert.get("contract") != FIREWALL_CONTRACT:
        return False
    if cert.get("enabled") is False:
        return True
    supplied = cert.get("certificate_sha256")
    if not supplied or _sha({k: v for k, v in cert.items() if k != "certificate_sha256"}) != supplied:
        return False
    return verify_semantic_claim_registry(cert.get("registry") or {})


def semantic_claim_summary(cycles: list[dict[str, Any]], final: dict[str, Any]) -> dict[str, Any]:
    return {"contract": "json-consistency-repair.semantic-claim-provenance-summary.v1",
            "cycle_certificate_count": len(cycles),
            "final_status": final.get("status"),
            "claim_count": ((final.get("registry") or {}).get("claim_count", 0)),
            "verified_claim_count": ((final.get("registry") or {}).get("verified_claim_count", 0)),
            "blocked_claim_count": ((final.get("registry") or {}).get("blocked_claim_count", 0)),
            "blocked_candidate_count": final.get("blocked_candidate_count", 0),
            "blocked_relation_count": final.get("blocked_relation_count", 0)}


def project_verified_semantic_config(config):
    """Return a deep-copied config with semantically unverified external claims disabled.

    This pre-analysis gate is what prevents a false attribution from influencing another
    analyzer indirectly (for example by becoming a boundary that vetoes an unrelated patch).
    The returned preflight certificate retains the original registry and exact gate reasons.
    """
    cfg = deepcopy(config)
    if not bool(getattr(config, "enable_semantic_claim_provenance", True)):
        pre={"contract":"json-consistency-repair.semantic-claim-preanalysis-gate.v1","enabled":False,
             "registry":{},"configuration_gates":[],"gated_rule_count":0,"status":"DISABLED"}
        pre["certificate_sha256"]=_sha({k:v for k,v in pre.items() if k!="certificate_sha256"})
        return cfg,pre
    reg = compile_semantic_claim_registry(config)
    by = {p.get("claim_id"): p for p in reg.get("claims") or []}
    gates = []
    for attr in ("constraint_rules", "logic_rules", "conservation_rules", "system_rules", "moment_rules", "robust_envelope_rules", "semantic_quotient_rules", "controllability_rules"):
        kept = []
        for i, rule in enumerate(getattr(config, attr, ()) or ()):
            if not isinstance(rule, dict):
                continue
            prov = rule.get("claim_provenance") or rule.get("semantic_provenance") or rule.get("provenance") or _implicit_external_attribution(rule)
            rid = str(rule.get("rule_id") or "")
            proof = by.get(rid) if rid else None
            # A provenance-bearing rule without a stable ID cannot be rebound safely to analyzer output.
            deny = bool(prov and not rid) or bool(proof is not None and not proof.get("verified"))
            if deny:
                gates.append({"rule_family": attr, "rule_id": rid or None, "index": i,
                              "reason": (proof or {}).get("reason") or "PROVENANCE_CLAIM_REQUIRES_STABLE_RULE_ID"})
            else:
                kept.append(deepcopy(rule))
        try:
            setattr(cfg, attr, tuple(kept))
        except Exception:
            pass
    schema_proof = by.get("__json_schema__")
    if schema_proof is not None and not schema_proof.get("verified"):
        try:
            cfg.json_schema = None
            cfg.schema_source = None
        except Exception:
            pass
        gates.append({"rule_family": "json_schema", "rule_id": "__json_schema__", "index": None, "reason": schema_proof.get("reason")})
    pre = {"contract": "json-consistency-repair.semantic-claim-preanalysis-gate.v1", "registry": reg,
           "configuration_gates": gates, "gated_rule_count": len(gates),
           "status": "PASS" if not gates else "GATED_UNVERIFIED_ATTRIBUTION"}
    pre["certificate_sha256"] = _sha({k: v for k, v in pre.items() if k != "certificate_sha256"})
    return cfg, pre


def preanalysis_as_firewall(pre: dict[str, Any]) -> dict[str, Any]:
    if pre.get("enabled") is False:
        return {"contract":FIREWALL_CONTRACT,"enabled":False,"blocked_candidates":[],"blocked_relations":[]}
    reg = deepcopy(pre.get("registry") or {})
    gates = deepcopy(pre.get("configuration_gates") or [])
    cert = {"contract": FIREWALL_CONTRACT, "enabled": True, "registry": reg,
            "configuration_gates": gates, "gated_rule_count": len(gates),
            "blocked_candidates": [], "blocked_relations": [],
            "blocked_candidate_count": 0, "blocked_relation_count": 0,
            "inferred_relation_count": 0,
            "status": "PASS" if not gates else "GATED_UNVERIFIED_ATTRIBUTION"}
    cert["certificate_sha256"] = _sha({k: v for k, v in cert.items() if k != "certificate_sha256"})
    return cert
