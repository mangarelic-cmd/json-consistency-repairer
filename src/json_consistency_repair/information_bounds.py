"""PASS040 — residual-information bounds and blind-carrier reconstruction.

The engine must not confuse "a value is missing" with "the remaining carrier contains
sufficient information to recover it".  PASS040 adds two conservative proof surfaces:

* exact finite lower bounds for residual selector information when several admissible
  completions remain; and
* blind reconstruction trials in which the target cell is physically removed from a
  cloned carrier before the reconstructor is invoked.

The hidden target is used only *after* reconstruction, as a SHA-256 commitment checked
by the verifier.  No target value is supplied to the reconstructor.  When the finite
carrier does not determine a unique value, the result is an explicit information debt,
never an invented tie-break.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
from typing import Any, Iterable

from .models import canonical_bytes, digest
from .tree import get

BOUND_CONTRACT = "json-consistency-repair.residual-information-bound.v1"
SUMMARY_CONTRACT = "json-consistency-repair.residual-information-summary.v1"
BLIND_CONTRACT = "json-consistency-repair.blind-carrier-reconstruction.v1"


def _seal(obj: dict[str, Any], field: str = "certificate_sha256") -> dict[str, Any]:
    body = deepcopy(obj)
    body.pop(field, None)
    obj[field] = digest(body)
    return obj


def _unique_values(values: Iterable[Any]) -> list[Any]:
    by: dict[bytes, Any] = {}
    for value in values:
        try:
            key = canonical_bytes(value)
        except (TypeError, ValueError):
            continue
        by.setdefault(key, deepcopy(value))
    return [by[k] for k in sorted(by)]


def minimum_fixed_width_selector_bits(candidate_count: int) -> int | None:
    """Exact worst-case fixed-width binary selector lower bound.

    For n finite admissible states, a fixed-width selector needs ceil(log2(n)) bits.
    The integer identity ``(n-1).bit_length()`` avoids floating point entirely.
    ``None`` means no finite candidate set was established.
    """
    n = int(candidate_count)
    if n < 0:
        raise ValueError("candidate_count must be non-negative")
    if n == 0:
        return None
    return (n - 1).bit_length()


def compile_residual_information_bound(
    candidate_values: Iterable[Any] | None,
    *,
    target_path: str = "",
    namespace: str = "root",
    source_kind: str = "FINITE_DECLARED_CANDIDATE_SET",
    source_sha256: str | None = None,
) -> dict[str, Any]:
    """Compile a proof-carrying finite residual-information bound.

    A finite candidate set of size n>1 requires a selector able to distinguish n states.
    PASS040 records the exact finite cardinality and the exact fixed-width binary lower
    bound.  If no finite candidate set is established, the certificate deliberately does
    not emit a numeric bit claim.
    """
    finite = candidate_values is not None
    values = _unique_values(candidate_values or ()) if finite else []
    n = len(values)
    bits = minimum_fixed_width_selector_bits(n) if finite else None
    if not finite:
        status = "FINITE_BOUND_NOT_ESTABLISHED"
    elif n == 0:
        status = "NO_ADMISSIBLE_FINITE_COMPLETION_MATERIALIZED"
    elif n == 1:
        status = "UNIQUE_ON_DECLARED_CARRIER"
    else:
        status = "RESIDUAL_INFORMATION_REQUIRED"
    cert = {
        "contract": BOUND_CONTRACT,
        "status": status,
        "namespace": str(namespace),
        "target_path": str(target_path),
        "source_kind": str(source_kind),
        "source_sha256": source_sha256,
        "finite_candidate_set_established": bool(finite),
        "candidate_count": n if finite else None,
        "candidate_values": values if finite else [],
        "candidate_commitments": [digest(v) for v in values] if finite else [],
        "minimum_fixed_width_selector_bits": bits,
        "unique_on_declared_carrier": bool(finite and n == 1),
        "external_information_required": bool(finite and n > 1),
        "policy": {
            "unknown_candidate_space_never_receives_numeric_bound": True,
            "finite_ambiguity_never_selects_by_index_or_iteration_order": True,
            "bound_semantics": "ceil(log2(candidate_count)) fixed-width binary selector bits",
        },
    }
    return _seal(cert)


def verify_residual_information_bound(cert: dict[str, Any]) -> bool:
    if not isinstance(cert, dict) or cert.get("contract") != BOUND_CONTRACT:
        return False
    supplied = cert.get("certificate_sha256")
    body = deepcopy(cert); body.pop("certificate_sha256", None)
    if not isinstance(supplied, str) or supplied != digest(body):
        return False
    finite = bool(cert.get("finite_candidate_set_established"))
    values = cert.get("candidate_values")
    commitments = cert.get("candidate_commitments")
    if not isinstance(values, list) or not isinstance(commitments, list):
        return False
    if finite:
        uniq = _unique_values(values)
        if uniq != values:
            return False
        if commitments != [digest(v) for v in values]:
            return False
        n = len(values)
        if cert.get("candidate_count") != n:
            return False
        bits = minimum_fixed_width_selector_bits(n)
        if cert.get("minimum_fixed_width_selector_bits") != bits:
            return False
        expected = ("NO_ADMISSIBLE_FINITE_COMPLETION_MATERIALIZED" if n == 0 else
                    "UNIQUE_ON_DECLARED_CARRIER" if n == 1 else
                    "RESIDUAL_INFORMATION_REQUIRED")
        if cert.get("status") != expected:
            return False
        if bool(cert.get("unique_on_declared_carrier")) != (n == 1):
            return False
        if bool(cert.get("external_information_required")) != (n > 1):
            return False
    else:
        if cert.get("status") != "FINITE_BOUND_NOT_ESTABLISHED":
            return False
        if cert.get("candidate_count") is not None or cert.get("minimum_fixed_width_selector_bits") is not None:
            return False
        if values or commitments or cert.get("unique_on_declared_carrier") or cert.get("external_information_required"):
            return False
    return True


def _array_at(root: Any, path: str) -> list[Any] | None:
    try:
        value = get(root, path)
    except Exception:
        return None
    return value if isinstance(value, list) else None


def _redact_target(root: Any, array_path: str, row_index: int, target: str) -> Any | None:
    redacted = deepcopy(root)
    arr = _array_at(redacted, array_path)
    if arr is None or row_index < 0 or row_index >= len(arr) or not isinstance(arr[row_index], dict):
        return None
    arr[row_index].pop(target, None)
    return redacted


def _functional_candidates(redacted_root: Any, relation: dict[str, Any], row_index: int) -> tuple[list[Any], int, dict[str, Any]]:
    arr_path = str(relation.get("array_path") or "")
    arr = _array_at(redacted_root, arr_path)
    det = relation.get("determinant") or ((relation.get("inputs") or [None])[-1])
    target = relation.get("output")
    scope_field = relation.get("scope_field") if relation.get("kind") == "scoped_functional" else None
    if arr is None or not isinstance(det, str) or not isinstance(target, str) or row_index >= len(arr) or not isinstance(arr[row_index], dict):
        return [], 0, {"reason": "CARRIER_OR_RELATION_NOT_MATERIALIZED"}
    row = arr[row_index]
    if det not in row:
        return [], 0, {"reason": "DETERMINANT_NOT_VISIBLE"}
    determinant = row.get(det)
    scope_value = row.get(scope_field) if isinstance(scope_field, str) else None
    values = []
    peers = 0
    for j, other in enumerate(arr):
        if j == row_index or not isinstance(other, dict):
            continue
        if other.get(det) != determinant:
            continue
        if isinstance(scope_field, str) and other.get(scope_field) != scope_value:
            continue
        if target not in other or other.get(target) is None:
            continue
        peers += 1
        values.append(other.get(target))
    return _unique_values(values), peers, {
        "determinant_field": det,
        "determinant_value": deepcopy(determinant),
        "scope_field": scope_field,
        "scope_value": deepcopy(scope_value) if isinstance(scope_field, str) else None,
    }


def _compile_blind_trial(root: Any, relation: dict[str, Any], row_index: int, *, namespace: str) -> dict[str, Any] | None:
    arr_path = str(relation.get("array_path") or "")
    arr = _array_at(root, arr_path)
    target = relation.get("output")
    if arr is None or not isinstance(target, str) or row_index < 0 or row_index >= len(arr) or not isinstance(arr[row_index], dict):
        return None
    row = arr[row_index]
    if target not in row or row.get(target) is None:
        return None

    hidden = deepcopy(row[target])
    redacted = _redact_target(root, arr_path, row_index, target)
    if redacted is None:
        return None
    values, peer_count, ctx = _functional_candidates(redacted, relation, row_index)
    target_path = (arr_path.rstrip("/") + f"/{row_index}/" + target.replace("~", "~0").replace("/", "~1")) if arr_path else f"/{row_index}/" + target.replace("~", "~0").replace("/", "~1")
    bound = compile_residual_information_bound(
        values if peer_count else None,
        target_path=target_path,
        namespace=namespace,
        source_kind="BLIND_VISIBLE_PEER_CARRIER" if peer_count else "BLIND_CARRIER_NO_MATCHING_PEER",
        source_sha256=digest({"relation_id": relation.get("relation_id"), "redacted_carrier_digest": digest(redacted)}),
    )
    if peer_count == 0:
        status = "CARRIER_INSUFFICIENT"
        predicted = None
        exact = False
    elif len(values) == 1:
        predicted = deepcopy(values[0])
        exact = digest(predicted) == digest(hidden)
        status = "BLIND_RECONSTRUCTED_EXACT" if exact else "BLIND_RECONSTRUCTION_MISMATCH"
    else:
        predicted = None
        exact = False
        status = "RESIDUAL_INFORMATION_REQUIRED"

    trial = {
        "contract": BLIND_CONTRACT,
        "status": status,
        "namespace": str(namespace),
        "relation_id": str(relation.get("relation_id") or ""),
        "relation_kind": str(relation.get("kind") or ""),
        "relation_sha256": digest(relation),
        "array_path": arr_path,
        "row_index": int(row_index),
        "target_field": target,
        "target_path": target_path,
        "redacted_carrier_digest": digest(redacted),
        "sealed_target_sha256": digest(hidden),
        "target_value_exposed_to_reconstructor": False,
        "matching_visible_peer_count": int(peer_count),
        "visible_candidate_values": values,
        "visible_candidate_commitments": [digest(v) for v in values],
        "reconstruction_context": ctx,
        "predicted_value": predicted,
        "predicted_value_sha256": digest(predicted) if predicted is not None else None,
        "reconstruction_matches_sealed_target": bool(exact),
        "residual_information_bound": bound,
        "blindness_policy": {
            "target_removed_before_reconstructor_call": True,
            "hidden_target_used_only_after_prediction_for_commitment_comparison": True,
            "no_index_or_route_order_tiebreak": True,
        },
    }
    return _seal(trial, "trial_sha256")


def verify_blind_reconstruction_trial(trial: dict[str, Any]) -> bool:
    if not isinstance(trial, dict) or trial.get("contract") != BLIND_CONTRACT:
        return False
    supplied = trial.get("trial_sha256")
    body = deepcopy(trial); body.pop("trial_sha256", None)
    if not isinstance(supplied, str) or supplied != digest(body):
        return False
    if trial.get("target_value_exposed_to_reconstructor") is not False:
        return False
    policy = trial.get("blindness_policy") or {}
    if not (policy.get("target_removed_before_reconstructor_call") and policy.get("hidden_target_used_only_after_prediction_for_commitment_comparison")):
        return False
    values = trial.get("visible_candidate_values")
    commits = trial.get("visible_candidate_commitments")
    if not isinstance(values, list) or commits != [digest(v) for v in values]:
        return False
    if values != _unique_values(values):
        return False
    if not verify_residual_information_bound(trial.get("residual_information_bound") or {}):
        return False
    status = trial.get("status")
    peers = int(trial.get("matching_visible_peer_count") or 0)
    if peers == 0:
        return status == "CARRIER_INSUFFICIENT" and trial.get("predicted_value") is None and not trial.get("reconstruction_matches_sealed_target")
    if len(values) == 1:
        pred = trial.get("predicted_value")
        if pred != values[0] or trial.get("predicted_value_sha256") != digest(pred):
            return False
        match = digest(pred) == trial.get("sealed_target_sha256")
        if bool(trial.get("reconstruction_matches_sealed_target")) != match:
            return False
        return status == ("BLIND_RECONSTRUCTED_EXACT" if match else "BLIND_RECONSTRUCTION_MISMATCH")
    if len(values) > 1:
        return status == "RESIDUAL_INFORMATION_REQUIRED" and trial.get("predicted_value") is None and not trial.get("reconstruction_matches_sealed_target")
    return False


def compile_blind_carrier_reconstruction(
    root: Any | None,
    relations: Iterable[dict[str, Any]] | None,
    *,
    namespace: str = "root",
    mode: str = "single",
    max_trials: int = 64,
    max_relations: int = 128,
) -> dict[str, Any]:
    """Run bounded deterministic blind trials against supported functional relations."""
    trials: list[dict[str, Any]] = []
    examined = 0
    applicable = 0
    if root is not None:
        rels = [r for r in (relations or ()) if isinstance(r, dict) and r.get("kind") in {"functional", "scoped_functional"}]
        rels = sorted(rels, key=lambda r: (str(r.get("relation_id") or ""), digest(r)))[:max(0, int(max_relations))]
        for relation in rels:
            examined += 1
            arr = _array_at(root, str(relation.get("array_path") or ""))
            if arr is None:
                continue
            applicable += 1
            for i in range(len(arr)):
                if len(trials) >= max(0, int(max_trials)):
                    break
                trial = _compile_blind_trial(root, relation, i, namespace=namespace)
                if trial is not None:
                    trials.append(trial)
            if len(trials) >= max(0, int(max_trials)):
                break
    counts = Counter(str(t.get("status")) for t in trials)
    mismatch = int(counts.get("BLIND_RECONSTRUCTION_MISMATCH", 0))
    if root is None:
        status = "CARRIER_NOT_MATERIALIZED"
    elif mismatch:
        status = "BLIND_RECONSTRUCTION_REJECTED"
    elif trials:
        status = "BLIND_CARRIER_CHECKED"
    else:
        status = "NO_APPLICABLE_BLIND_TRIAL"
    cert = {
        "contract": BLIND_CONTRACT,
        "scope": "summary",
        "mode": str(mode),
        "namespace": str(namespace),
        "status": status,
        "carrier_digest": digest(root) if root is not None else None,
        "carrier_materialized": root is not None,
        "supported_relation_families": ["functional", "scoped_functional"],
        "relations_examined": int(examined),
        "relations_applicable": int(applicable),
        "max_trials": int(max_trials),
        "trial_count": len(trials),
        "trials": trials,
        "state_counts": dict(sorted(counts.items())),
        "exact_reconstruction_count": int(counts.get("BLIND_RECONSTRUCTED_EXACT", 0)),
        "residual_information_required_count": int(counts.get("RESIDUAL_INFORMATION_REQUIRED", 0)),
        "carrier_insufficient_count": int(counts.get("CARRIER_INSUFFICIENT", 0)),
        "mismatch_count": mismatch,
        "ok": mismatch == 0,
        "policy": {
            "successful_trial_requires_target_redaction_before_reconstruction": True,
            "ambiguous_visible_carrier_emits_information_debt_not_guess": True,
            "no_applicable_trial_is_not_a_claim_of_reconstructability": True,
        },
    }
    return _seal(cert)


def verify_blind_carrier_reconstruction(cert: dict[str, Any]) -> bool:
    if not isinstance(cert, dict) or cert.get("contract") != BLIND_CONTRACT:
        return False
    if cert.get("scope") == "bundle_summary":
        supplied = cert.get("certificate_sha256"); body = deepcopy(cert); body.pop("certificate_sha256", None)
        if not isinstance(supplied, str) or supplied != digest(body): return False
        docs = cert.get("documents")
        if not isinstance(docs, dict) or not all(verify_blind_carrier_reconstruction(v) for v in docs.values()): return False
        trials = sum(int(v.get("trial_count") or 0) for v in docs.values())
        mismatch = sum(int(v.get("mismatch_count") or 0) for v in docs.values())
        if int(cert.get("trial_count") or 0) != trials or int(cert.get("mismatch_count") or 0) != mismatch: return False
        if bool(cert.get("ok")) != (mismatch == 0): return False
        expected = "BLIND_RECONSTRUCTION_REJECTED" if mismatch else ("BLIND_CARRIER_CHECKED" if trials else "NO_APPLICABLE_BLIND_TRIAL")
        return cert.get("status") == expected
    if cert.get("scope") != "summary":
        return False
    supplied = cert.get("certificate_sha256")
    body = deepcopy(cert); body.pop("certificate_sha256", None)
    if not isinstance(supplied, str) or supplied != digest(body):
        return False
    trials = cert.get("trials")
    if not isinstance(trials, list) or not all(verify_blind_reconstruction_trial(t) for t in trials):
        return False
    counts = Counter(str(t.get("status")) for t in trials)
    if cert.get("state_counts") != dict(sorted(counts.items())):
        return False
    if int(cert.get("trial_count") or 0) != len(trials):
        return False
    mismatch = int(counts.get("BLIND_RECONSTRUCTION_MISMATCH", 0))
    if int(cert.get("mismatch_count") or 0) != mismatch or bool(cert.get("ok")) != (mismatch == 0):
        return False
    expected = ("CARRIER_NOT_MATERIALIZED" if not cert.get("carrier_materialized") else
                "BLIND_RECONSTRUCTION_REJECTED" if mismatch else
                "BLIND_CARRIER_CHECKED" if trials else "NO_APPLICABLE_BLIND_TRIAL")
    return cert.get("status") == expected


def _bounds_from_symmetry(symmetry_surface: dict[str, Any] | None, *, namespace: str) -> list[dict[str, Any]]:
    bounds: list[dict[str, Any]] = []
    surface = symmetry_surface or {}
    # Single mode stores per-cycle certificates under ``cycles[*].certificate``.
    candidates = []
    for row in surface.get("cycles") or []:
        if isinstance(row, dict):
            c = row.get("certificate") or row
            if isinstance(c, dict): candidates.append(c)
    # Bundle may expose per-document/cross-document certificates.
    for payload in (surface.get("documents") or {}).values() if isinstance(surface.get("documents"), dict) else []:
        if isinstance(payload, dict):
            for row in payload.get("cycles") or []:
                c = (row or {}).get("certificate") if isinstance(row, dict) else None
                if isinstance(c, dict): candidates.append(c)
    cross = surface.get("cross_document")
    if isinstance(cross, dict): candidates.append(cross)
    for cert in candidates:
        for b in cert.get("minimal_symmetry_breakers") or []:
            if not isinstance(b, dict): continue
            n = int(b.get("orbit_size") or 0)
            if n <= 1: continue
            vals = [f"orbit-member:{i}" for i in range(n)]
            bounds.append(compile_residual_information_bound(
                vals,
                target_path=str(b.get("array_path") or ""),
                namespace=namespace,
                source_kind="SYMMETRY_ORBIT_CARDINALITY",
                source_sha256=digest(b),
            ))
    return bounds


def compile_residual_information_summary(
    blind_surface: dict[str, Any],
    *,
    symmetry_surface: dict[str, Any] | None = None,
    namespace: str = "root",
    mode: str = "single",
) -> dict[str, Any]:
    bounds: list[dict[str, Any]] = []
    for trial in blind_surface.get("trials") or []:
        bound = (trial or {}).get("residual_information_bound") if isinstance(trial, dict) else None
        if isinstance(bound, dict) and bound.get("status") in {"RESIDUAL_INFORMATION_REQUIRED", "FINITE_BOUND_NOT_ESTABLISHED"}:
            bounds.append(deepcopy(bound))
    bounds.extend(_bounds_from_symmetry(symmetry_surface, namespace=namespace))
    # Exact de-duplication by full bound commitment.
    uniq = {str(b.get("certificate_sha256") or digest(b)): b for b in bounds if isinstance(b, dict)}
    bounds = [uniq[k] for k in sorted(uniq)]
    finite = [b for b in bounds if b.get("finite_candidate_set_established")]
    unknown = [b for b in bounds if not b.get("finite_candidate_set_established")]
    max_bits = max((int(b.get("minimum_fixed_width_selector_bits") or 0) for b in finite), default=0)
    summary = {
        "contract": SUMMARY_CONTRACT,
        "mode": str(mode),
        "namespace": str(namespace),
        "status": "RESIDUAL_INFORMATION_DEBTS_VISIBLE" if bounds else "NO_FINITE_RESIDUAL_DEBT_MATERIALIZED",
        "bounds": bounds,
        "bound_count": len(bounds),
        "finite_bound_count": len(finite),
        "unknown_bound_count": len(unknown),
        "maximum_fixed_width_selector_bits_lower_bound": max_bits if finite else None,
        "blind_surface_sha256": blind_surface.get("certificate_sha256"),
        "policy": {
            "open_or_unknown_space_is_never_treated_as_zero_information": True,
            "finite_candidate_cardinality_is_the_only_numeric_bound_source": True,
        },
    }
    return _seal(summary)


def verify_residual_information_summary(summary: dict[str, Any], blind_surface: dict[str, Any] | None = None) -> bool:
    if not isinstance(summary, dict) or summary.get("contract") != SUMMARY_CONTRACT:
        return False
    if summary.get("mode") == "bundle" and isinstance(summary.get("documents"), dict):
        supplied = summary.get("certificate_sha256"); body = deepcopy(summary); body.pop("certificate_sha256", None)
        if not isinstance(supplied, str) or supplied != digest(body): return False
        docs = summary.get("documents") or {}
        if not all(verify_residual_information_summary(v) for v in docs.values()): return False
        total = sum(int(v.get("bound_count") or 0) for v in docs.values())
        if int(summary.get("bound_count") or 0) != total: return False
        expected = "RESIDUAL_INFORMATION_DEBTS_VISIBLE" if total else "NO_FINITE_RESIDUAL_DEBT_MATERIALIZED"
        if summary.get("status") != expected: return False
        if blind_surface is not None and summary.get("blind_surface_sha256") != blind_surface.get("certificate_sha256"): return False
        return True
    supplied = summary.get("certificate_sha256")
    body = deepcopy(summary); body.pop("certificate_sha256", None)
    if not isinstance(supplied, str) or supplied != digest(body):
        return False
    bounds = summary.get("bounds")
    if not isinstance(bounds, list) or not all(verify_residual_information_bound(b) for b in bounds):
        return False
    if int(summary.get("bound_count") or 0) != len(bounds):
        return False
    finite = [b for b in bounds if b.get("finite_candidate_set_established")]
    unknown = [b for b in bounds if not b.get("finite_candidate_set_established")]
    if int(summary.get("finite_bound_count") or 0) != len(finite) or int(summary.get("unknown_bound_count") or 0) != len(unknown):
        return False
    expected_max = max((int(b.get("minimum_fixed_width_selector_bits") or 0) for b in finite), default=None)
    if summary.get("maximum_fixed_width_selector_bits_lower_bound") != expected_max:
        return False
    expected_status = "RESIDUAL_INFORMATION_DEBTS_VISIBLE" if bounds else "NO_FINITE_RESIDUAL_DEBT_MATERIALIZED"
    if summary.get("status") != expected_status:
        return False
    if blind_surface is not None and summary.get("blind_surface_sha256") != blind_surface.get("certificate_sha256"):
        return False
    return True


def compile_information_surface(
    root: Any | None,
    relations: Iterable[dict[str, Any]] | None,
    *,
    symmetry_surface: dict[str, Any] | None = None,
    namespace: str = "root",
    mode: str = "single",
    max_trials: int = 64,
) -> tuple[dict[str, Any], dict[str, Any]]:
    blind = compile_blind_carrier_reconstruction(root, relations, namespace=namespace, mode=mode, max_trials=max_trials)
    residual = compile_residual_information_summary(blind, symmetry_surface=symmetry_surface, namespace=namespace, mode=mode)
    return residual, blind


def compile_information_bundle_surface(
    documents: dict[str, Any],
    relations_by_document: dict[str, Iterable[dict[str, Any]]],
    *,
    symmetry_surface: dict[str, Any] | None = None,
    max_trials: int = 64,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Compile bounded per-document PASS040 surfaces for a bundle."""
    blind_docs: dict[str, Any] = {}
    residual_docs: dict[str, Any] = {}
    remaining = max(0, int(max_trials))
    for doc in sorted(documents):
        quota = remaining
        residual, blind = compile_information_surface(
            documents[doc], relations_by_document.get(doc) or (),
            symmetry_surface=None, namespace=f"document:{doc}", mode="bundle_document",
            max_trials=quota,
        )
        blind_docs[doc] = blind
        residual_docs[doc] = residual
        remaining = max(0, remaining - int(blind.get("trial_count") or 0))
    # Symmetry debts may live at the bundle/cross-document layer. Add them as a dedicated
    # reconciliation summary without pretending that a cross-document blind carrier was
    # materialized by the per-document trials.
    extra_blind = compile_blind_carrier_reconstruction(None, (), namespace="bundle", mode="bundle_cross_document", max_trials=0)
    bundle_symmetry = compile_residual_information_summary(extra_blind, symmetry_surface=symmetry_surface, namespace="bundle", mode="bundle")
    residual_docs["@bundle"] = bundle_symmetry

    trial_count = sum(int(v.get("trial_count") or 0) for v in blind_docs.values())
    mismatch = sum(int(v.get("mismatch_count") or 0) for v in blind_docs.values())
    blind_bundle = {
        "contract": BLIND_CONTRACT,
        "scope": "bundle_summary",
        "mode": "bundle",
        "status": "BLIND_RECONSTRUCTION_REJECTED" if mismatch else ("BLIND_CARRIER_CHECKED" if trial_count else "NO_APPLICABLE_BLIND_TRIAL"),
        "documents": blind_docs,
        "trial_count": trial_count,
        "mismatch_count": mismatch,
        "ok": mismatch == 0,
        "global_trial_limit": int(max_trials),
    }
    _seal(blind_bundle)
    bounds = sum(int(v.get("bound_count") or 0) for v in residual_docs.values())
    residual_bundle = {
        "contract": SUMMARY_CONTRACT,
        "mode": "bundle",
        "namespace": "bundle",
        "status": "RESIDUAL_INFORMATION_DEBTS_VISIBLE" if bounds else "NO_FINITE_RESIDUAL_DEBT_MATERIALIZED",
        "documents": residual_docs,
        "bound_count": bounds,
        "blind_surface_sha256": blind_bundle.get("certificate_sha256"),
    }
    _seal(residual_bundle)
    return residual_bundle, blind_bundle
