from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import json

from json_consistency_repair import (
    RepairConfig, StreamingConfig, repair_object, repair_bundle,
    minimum_fixed_width_selector_bits,
    compile_residual_information_bound, verify_residual_information_bound,
    compile_blind_carrier_reconstruction, verify_blind_carrier_reconstruction,
    verify_blind_reconstruction_trial,
)
from json_consistency_repair.streaming import repair_stream_file


def _functional_relation():
    return {
        "relation_id": "r-k-v",
        "kind": "functional",
        "array_path": "/rows",
        "inputs": ["k"],
        "output": "v",
        "determinant": "k",
        "confidence": 1.0,
        "support": 4,
    }


def test_pass040_exact_integer_selector_bound():
    assert minimum_fixed_width_selector_bits(1) == 0
    assert minimum_fixed_width_selector_bits(2) == 1
    assert minimum_fixed_width_selector_bits(3) == 2
    assert minimum_fixed_width_selector_bits(4) == 2
    assert minimum_fixed_width_selector_bits(5) == 3
    cert = compile_residual_information_bound(["a", "b", "c"], target_path="/x")
    assert cert["status"] == "RESIDUAL_INFORMATION_REQUIRED"
    assert cert["candidate_count"] == 3
    assert cert["minimum_fixed_width_selector_bits"] == 2
    assert verify_residual_information_bound(cert)


def test_pass040_unknown_candidate_space_never_claims_zero_bits():
    cert = compile_residual_information_bound(None, target_path="/missing")
    assert cert["status"] == "FINITE_BOUND_NOT_ESTABLISHED"
    assert cert["candidate_count"] is None
    assert cert["minimum_fixed_width_selector_bits"] is None
    assert verify_residual_information_bound(cert)


def test_pass040_blind_reconstruction_uses_only_redacted_carrier():
    root = {"rows": [
        {"k": "a", "v": 11}, {"k": "a", "v": 11},
        {"k": "b", "v": 22}, {"k": "b", "v": 22},
    ]}
    cert = compile_blind_carrier_reconstruction(root, [_functional_relation()], max_trials=16)
    assert cert["status"] == "BLIND_CARRIER_CHECKED"
    assert cert["exact_reconstruction_count"] == 4
    assert cert["mismatch_count"] == 0
    assert verify_blind_carrier_reconstruction(cert)
    for trial in cert["trials"]:
        assert trial["status"] == "BLIND_RECONSTRUCTED_EXACT"
        assert trial["target_value_exposed_to_reconstructor"] is False
        assert "hidden_target_value" not in trial
        assert trial["predicted_value_sha256"] == trial["sealed_target_sha256"]
        assert verify_blind_reconstruction_trial(trial)


def test_pass040_ambiguous_blind_carrier_emits_information_debt_not_tiebreak():
    root = {"rows": [
        {"k": "a", "v": 0}, {"k": "a", "v": 1},
        {"k": "a", "v": 2}, {"k": "a", "v": 3},
    ]}
    cert = compile_blind_carrier_reconstruction(root, [_functional_relation()], max_trials=1)
    trial = cert["trials"][0]
    assert trial["status"] == "RESIDUAL_INFORMATION_REQUIRED"
    assert trial["predicted_value"] is None
    bound = trial["residual_information_bound"]
    assert bound["candidate_count"] == 3
    assert bound["minimum_fixed_width_selector_bits"] == 2
    assert cert["ok"] and cert["mismatch_count"] == 0


def test_pass040_tampered_target_commitment_is_rejected():
    root = {"rows": [
        {"k": "a", "v": 11}, {"k": "a", "v": 11},
        {"k": "b", "v": 22}, {"k": "b", "v": 22},
    ]}
    cert = compile_blind_carrier_reconstruction(root, [_functional_relation()], max_trials=1)
    bad = deepcopy(cert["trials"][0])
    bad["sealed_target_sha256"] = "0" * 64
    # Even resealing the outer trial cannot make the false reconstruction match the sealed target.
    from json_consistency_repair.models import digest
    body = deepcopy(bad); body.pop("trial_sha256", None); bad["trial_sha256"] = digest(body)
    assert not verify_blind_reconstruction_trial(bad)


def test_pass040_single_engine_closes_fifth_series_and_binds_surfaces():
    out, res = repair_object({"x": 1}, RepairConfig(max_cycles=3, strong_fixed_point_cycles_required=1, enable_multisource=False))
    assert out == {"x": 1}
    report = res.report
    assert report["final_certification"]["checks"]["residual_information_blind_carrier"] is True
    assert report["fifth_series_progress"]["status"] == "CLOSED"
    assert report["fifth_series_progress"]["completed_substantive_passes"] == 8
    assert report["fifth_series_progress"]["remaining_substantive_passes"] == 0
    assert report["fifth_series_closure"]["status"] == "CLOSED"
    assert report["fifth_series_closure"]["ok"] is True
    surfaces = {x["logical_name"]: x for x in report["rectification_packet"]["surfaces"]}
    assert surfaces["residual_information"]["state"] == "PRESENT"
    assert surfaces["blind_carrier_reconstruction"]["state"] == "PRESENT"
    kinds = {n.get("kind") for n in report["proof_graph"]["nodes"]}
    assert "RESIDUAL_INFORMATION_BOUND" in kinds
    assert "BLIND_CARRIER_RECONSTRUCTION" in kinds


def test_pass040_engine_performs_real_blind_functional_trials():
    root = {"rows": [
        {"k": "a", "v": 11}, {"k": "a", "v": 11},
        {"k": "b", "v": 22}, {"k": "b", "v": 22},
        {"k": "c", "v": 33}, {"k": "c", "v": 33},
    ]}
    cfg = RepairConfig(max_cycles=3, strong_fixed_point_cycles_required=1, enable_multisource=False,
                       min_support=4, min_group_support=2, relation_confidence=1.0)
    out, res = repair_object(root, cfg)
    assert out == root
    blind = res.report["blind_carrier_reconstruction"]
    assert blind["trial_count"] >= 6
    assert blind["exact_reconstruction_count"] >= 6
    assert blind["mismatch_count"] == 0
    assert res.report["fifth_series_closure"]["ok"]


def test_pass040_bundle_closes_with_per_document_information_surface():
    docs = {"a.json": {"x": 1}, "b.json": {"y": 2}}
    out, res = repair_bundle(docs, RepairConfig(max_cycles=3, strong_fixed_point_cycles_required=1, enable_multisource=False))
    assert out == docs
    assert res.report["blind_carrier_reconstruction"]["scope"] == "bundle_summary"
    assert res.report["final_certification"]["checks"]["residual_information_blind_carrier"] is True
    assert res.report["fifth_series_closure"]["ok"]


def test_pass040_streaming_conservatively_declares_unmaterialized_blind_carrier(tmp_path: Path):
    src = tmp_path / "in.jsonl"; out = tmp_path / "out.jsonl"
    src.write_text('{"x":1}\n{"x":1}\n', encoding="utf-8")
    res = repair_stream_file(src, out, config=StreamingConfig(max_cycles=3, strong_fixed_point_cycles_required=1), stream_format="jsonl")
    blind = res.report["blind_carrier_reconstruction"]
    assert blind["status"] == "CARRIER_NOT_MATERIALIZED"
    assert blind["ok"] is True
    assert res.report["final_certification"]["checks"]["residual_information_blind_carrier"] is True
    assert res.report["fifth_series_closure"]["ok"]


def test_pass040_public_schemas_are_draft202012_valid():
    from jsonschema import Draft202012Validator
    base = Path(__file__).resolve().parents[1] / "schemas"
    names = [
        "residual-information-bound-v1.schema.json",
        "residual-information-summary-v1.schema.json",
        "blind-carrier-reconstruction-v1.schema.json",
        "fifth-series-closure-v1.schema.json",
        "fifth-series-progress-v1.schema.json",
    ]
    for name in names:
        Draft202012Validator.check_schema(json.loads((base / name).read_text(encoding="utf-8")))
