from __future__ import annotations

from copy import deepcopy
from math import ceil, log2
from typing import Any, Iterable
import hashlib, json

from .models import Candidate, digest
from .tree import decode_pointer, get
from .jsonpatch_exact import apply_candidate

QUOTIENT_CONTRACT = "json-consistency-repair.semantic-quotient.v1"
SYMMETRY_CONTRACT = "json-consistency-repair.symmetry-obstruction.v1"
CANONICALITY_CONTRACT = "json-consistency-repair.canonicality-certificate.v1"


def _canon(v: Any) -> bytes:
    return json.dumps(v, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _sha(v: Any) -> str:
    return hashlib.sha256(_canon(v)).hexdigest()


def _encode_token(s: str) -> str:
    return s.replace("~", "~0").replace("/", "~1")


def _pointer(tokens: list[str]) -> str:
    return "" if not tokens else "/" + "/".join(_encode_token(x) for x in tokens)


def _normalized_rules(rules: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for i, raw in enumerate(rules or ()):
        if not isinstance(raw, dict):
            continue
        path = str(raw.get("path", ""))
        mode = str(raw.get("equivalence") or raw.get("mode") or "")
        if mode not in {"unordered_array", "unordered_unique_array"}:
            continue
        if path and not path.startswith("/"):
            continue
        row = {
            "rule_id": str(raw.get("rule_id") or f"quotient:{i}:{_sha([path, mode])[:16]}"),
            "path": path,
            "equivalence": mode,
            "explicit": True,
        }
        if mode == "unordered_unique_array":
            # Deduplication is a stronger semantic declaration and is never inferred.
            row["duplicates_are_semantically_irrelevant"] = bool(raw.get("duplicates_are_semantically_irrelevant", False))
            if not row["duplicates_are_semantically_irrelevant"]:
                continue
        out.append(row)
    return sorted(out, key=lambda x: (x["path"], x["equivalence"], x["rule_id"]))


def _path_matches(rule_tokens: list[str], actual: list[str]) -> bool:
    if len(rule_tokens) != len(actual):
        return False
    return all(r == "*" or r == a for r, a in zip(rule_tokens, actual))


def _normalize_node(value: Any, tokens: list[str], rules: list[dict[str, Any]]) -> Any:
    if isinstance(value, dict):
        node = {k: _normalize_node(v, tokens + [str(k)], rules) for k, v in sorted(value.items())}
    elif isinstance(value, list):
        node = [_normalize_node(v, tokens + [str(i)], rules) for i, v in enumerate(value)]
    else:
        node = deepcopy(value)

    matching = [r for r in rules if _path_matches(decode_pointer(r["path"]), tokens)]
    for rule in matching:
        if not isinstance(node, list):
            continue
        ordered = sorted(node, key=_canon)
        if rule["equivalence"] == "unordered_unique_array":
            dedup: list[Any] = []
            seen: set[bytes] = set()
            for x in ordered:
                b = _canon(x)
                if b not in seen:
                    dedup.append(x); seen.add(b)
            node = dedup
        else:
            node = ordered
    return node


def semantic_quotient_normal_form(value: Any, rules: Iterable[dict[str, Any]] | None) -> Any:
    nr = _normalized_rules(rules)
    return _normalize_node(deepcopy(value), [], nr)


def semantic_quotient_digest(value: Any, rules: Iterable[dict[str, Any]] | None) -> str:
    return digest(semantic_quotient_normal_form(value, rules))


def compile_semantic_quotient(value: Any, rules: Iterable[dict[str, Any]] | None) -> dict[str, Any]:
    nr = _normalized_rules(rules)
    normal = semantic_quotient_normal_form(value, nr)
    second = semantic_quotient_normal_form(normal, nr)
    cert = {
        "contract": QUOTIENT_CONTRACT,
        "rules": nr,
        "rule_count": len(nr),
        "rules_sha256": _sha(nr),
        "input_digest": digest(value),
        "normal_form_digest": digest(normal),
        "idempotent": digest(normal) == digest(second),
        "scope": "explicit_rules_only",
        "inferred_representation_freedoms": 0,
    }
    body = dict(cert)
    cert["certificate_sha256"] = _sha(body)
    return cert


def compare_modulo_semantic_quotient(a: Any, b: Any, rules: Iterable[dict[str, Any]] | None) -> dict[str, Any]:
    nr = _normalized_rules(rules)
    da, db = digest(a), digest(b)
    qa, qb = semantic_quotient_digest(a, nr), semantic_quotient_digest(b, nr)
    exact = da == db
    equivalent = exact or (bool(nr) and qa == qb)
    row = {
        "contract": CANONICALITY_CONTRACT,
        "exact_equal": exact,
        "semantic_quotient_equivalent": equivalent,
        "quotient_used": bool(not exact and equivalent and nr),
        "left_digest": da,
        "right_digest": db,
        "left_quotient_digest": qa,
        "right_quotient_digest": qb,
        "rules_sha256": _sha(nr),
    }
    row["certificate_sha256"] = _sha(row)
    return row


def _deepest_numeric_context(root: Any, path: str) -> dict[str, Any] | None:
    toks = decode_pointer(path)
    cur = root
    last_ctx = None
    prefix: list[str] = []
    for pos, tok in enumerate(toks):
        if isinstance(cur, list):
            try:
                idx = int(tok)
            except Exception:
                return last_ctx
            if idx < 0 or idx >= len(cur):
                return last_ctx
            item = cur[idx]
            sig = digest(item)
            orbit = [j for j, x in enumerate(cur) if digest(x) == sig]
            if len(orbit) > 1:
                last_ctx = {
                    "array_path": _pointer(prefix),
                    "index_position": pos,
                    "selected_index": idx,
                    "orbit_indices": orbit,
                    "orbit_size": len(orbit),
                    "member_digest": sig,
                    "suffix_tokens": toks[pos + 1 :],
                }
            cur = item
        elif isinstance(cur, dict):
            if tok not in cur:
                return last_ctx
            cur = cur[tok]
        else:
            return last_ctx
        prefix.append(tok)
    return last_ctx


def _candidate_orbit_signature(root: Any, c: Candidate) -> tuple[str | None, dict[str, Any] | None]:
    ctx = _deepest_numeric_context(root, c.path)
    if not ctx:
        return None, None
    toks = decode_pointer(c.path)
    generalized = list(toks)
    generalized[ctx["index_position"]] = "*"
    meta = c.metadata or {}
    sig = {
        "operation": c.operation,
        "generalized_path": _pointer(generalized),
        "new_value_sha256": digest(c.new_value),
        "analyzer": c.analyzer,
        "from_path": str(meta.get("from_path", "")),
        "array_path": ctx["array_path"],
        "member_digest": ctx["member_digest"],
    }
    return _sha(sig), ctx


def _route_orbit_signature(root: Any, route: list[Candidate]) -> tuple[str | None, list[dict[str, Any]]]:
    rows = []
    contexts = []
    for c in route:
        sig, ctx = _candidate_orbit_signature(root, c)
        if sig is None:
            rows.append({"literal": [c.operation, c.path, digest(c.new_value)]})
        else:
            rows.append({"orbit": sig})
            contexts.append(ctx or {})
    if not contexts:
        return None, []
    return _sha(sorted(rows, key=_canon)), contexts


def _minimal_breakers(contexts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    uniq: dict[tuple[str, tuple[int, ...]], dict[str, Any]] = {}
    for c in contexts:
        if not c:
            continue
        key = (str(c.get("array_path", "")), tuple(c.get("orbit_indices") or ()))
        n = int(c.get("orbit_size") or len(key[1]) or 0)
        uniq[key] = {
            "array_path": key[0],
            "orbit_indices": list(key[1]),
            "orbit_size": n,
            "breaker_requirement": "one stable selector/identity value distinguishing the chosen orbit member",
            "minimum_selector_bits_lower_bound": int(ceil(log2(n))) if n > 1 else 0,
            "examples": ["stable id field", "authoritative source selector", "explicit ordered-position semantics"],
        }
    return [uniq[k] for k in sorted(uniq)]


def compile_symmetry_obstruction(
    root: Any,
    routes: list[list[Candidate]] | None,
    *,
    quotient_rules: Iterable[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    routes = list(routes or [])
    nr = _normalized_rules(quotient_rules)
    route_rows: list[dict[str, Any]] = []
    orbit_sigs: list[str] = []
    contexts: list[dict[str, Any]] = []
    for i, route in enumerate(routes):
        clone = deepcopy(root)
        ok = True
        for c in route:
            if not apply_candidate(clone, c):
                ok = False; break
        osig, ctxs = _route_orbit_signature(root, route)
        contexts.extend(ctxs)
        if osig:
            orbit_sigs.append(osig)
        route_rows.append({
            "route_index": i,
            "candidate_ids": [c.candidate_id for c in route],
            "prefix_applied": ok,
            "raw_terminal_digest": digest(clone) if ok else None,
            "quotient_terminal_digest": semantic_quotient_digest(clone, nr) if ok else None,
            "orbit_signature": osig,
        })
    raws = {r["raw_terminal_digest"] for r in route_rows if r.get("raw_terminal_digest")}
    qds = {r["quotient_terminal_digest"] for r in route_rows if r.get("quotient_terminal_digest")}
    structural_orbit = bool(len(routes) > 1 and orbit_sigs and len(set(orbit_sigs)) == 1)
    quotient_equivalent = bool(len(raws) > 1 and len(qds) == 1 and nr and len(qds) == 1)
    if quotient_equivalent:
        status = "QUOTIENT_CANONICALLY_EQUIVALENT"
        blocked = False
    elif structural_orbit:
        status = "SYMMETRY_BLOCKED_REPAIR"
        blocked = True
    else:
        status = "NO_SYMMETRY_OBSTRUCTION"
        blocked = False
    cert = {
        "contract": SYMMETRY_CONTRACT,
        "status": status,
        "blocked": blocked,
        "route_count": len(routes),
        "routes": route_rows,
        "structural_orbit_detected": structural_orbit,
        "semantic_quotient_equivalent": quotient_equivalent,
        "quotient": compile_semantic_quotient(root, nr),
        "minimal_symmetry_breakers": _minimal_breakers(contexts) if blocked else [],
        "policy": {
            "automatic_symmetry_detection_may_only_block": True,
            "semantic_quotient_may_enable_return_only_when_explicitly_declared": True,
            "array_order_is_never_assumed_irrelevant": True,
        },
    }
    body = dict(cert)
    cert["certificate_sha256"] = _sha(body)
    return cert


def verify_semantic_quotient_certificate(cert: dict[str, Any]) -> bool:
    if not isinstance(cert, dict) or cert.get("contract") != QUOTIENT_CONTRACT:
        return False
    body = {k: deepcopy(v) for k, v in cert.items() if k != "certificate_sha256"}
    if cert.get("certificate_sha256") != _sha(body):
        return False
    rules = _normalized_rules(cert.get("rules") or [])
    if rules != cert.get("rules"):
        return False
    if cert.get("rules_sha256") != _sha(rules):
        return False
    return bool(cert.get("idempotent"))


def verify_symmetry_certificate(cert: dict[str, Any]) -> bool:
    if not isinstance(cert, dict) or cert.get("contract") != SYMMETRY_CONTRACT:
        return False
    body = {k: deepcopy(v) for k, v in cert.items() if k != "certificate_sha256"}
    if cert.get("certificate_sha256") != _sha(body):
        return False
    if not verify_semantic_quotient_certificate(cert.get("quotient") or {}):
        return False
    status = cert.get("status")
    if status not in {"QUOTIENT_CANONICALLY_EQUIVALENT", "SYMMETRY_BLOCKED_REPAIR", "NO_SYMMETRY_OBSTRUCTION"}:
        return False
    if bool(cert.get("blocked")) != (status == "SYMMETRY_BLOCKED_REPAIR"):
        return False
    if status == "QUOTIENT_CANONICALLY_EQUIVALENT" and not cert.get("semantic_quotient_equivalent"):
        return False
    if status == "SYMMETRY_BLOCKED_REPAIR" and not cert.get("structural_orbit_detected"):
        return False
    return True


def symmetry_summary(certificates: Iterable[dict[str, Any]], rules: Iterable[dict[str, Any]] | None = None) -> dict[str, Any]:
    rows = [x for x in certificates if isinstance(x, dict)]
    def cert_of(x: dict[str, Any]) -> dict[str, Any]:
        c=x.get("certificate")
        return c if isinstance(c,dict) else x
    return {
        "contract": "json-consistency-repair.symmetry-canonicality-summary.v1",
        "semantic_quotient_contract": QUOTIENT_CONTRACT,
        "symmetry_obstruction_contract": SYMMETRY_CONTRACT,
        "rules": _normalized_rules(rules),
        "cycles": rows,
        "blocked_cycles": sum(1 for x in rows if cert_of(x).get("status") == "SYMMETRY_BLOCKED_REPAIR"),
        "quotient_equivalent_cycles": sum(1 for x in rows if cert_of(x).get("status") == "QUOTIENT_CANONICALLY_EQUIVALENT"),
    }
