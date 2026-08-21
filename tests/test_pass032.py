from copy import deepcopy
from pathlib import Path
import json

from json_consistency_repair import (
    RepairConfig, StreamingConfig, repair_object, repair_bundle, repair_stream_file,
    compile_rectification_packet, verify_rectification_packet, verify_rectification_packet_final,
)
from json_consistency_repair.rectification_packet import seal_rectification_packet
from json_consistency_repair.certifier import verify_report_evidence


def _single():
    return repair_object({"x": 1, "nested": {"y": 2}}, RepairConfig(max_cycles=3))[1].report


def test_pass032_single_packet_and_fourth_series_closed():
    report = _single()
    assert report["rectification_packet"]["contract"] == "json-consistency-repair.rectification-packet.v1"
    assert report["rectification_packet"]["certification_state"] == "INDEPENDENTLY_CERTIFIED"
    assert verify_rectification_packet(report["rectification_packet"], report)
    assert verify_rectification_packet_final(report["rectification_packet"], report)
    assert report["fourth_series_closure"]["status"] == "CLOSED"
    assert report["fourth_series_closure"]["remaining_substantive_passes"] == 0


def test_pass032_packet_is_deterministic_for_same_sovereign_input():
    a = _single()["rectification_packet"]
    b = _single()["rectification_packet"]
    assert a["packet_sha256"] == b["packet_sha256"]
    assert a["section_root_sha256"] == b["section_root_sha256"]


def test_pass032_surface_catalog_contains_fourth_series_layers():
    packet = _single()["rectification_packet"]
    by = {x["logical_name"]: x for x in packet["surfaces"]}
    for name in ["boundaries", "parallel_routes", "primary_factorization", "proof_graph", "materialization", "scoped_authority", "robust_envelope", "q_descent"]:
        assert name in by
    assert by["boundaries"]["state"] == "PRESENT"
    assert by["proof_graph"]["state"] == "PRESENT"


def test_pass032_section_tamper_breaks_packet_binding_and_certifier():
    report = _single()
    bad = deepcopy(report)
    bad["boundary_calculus"]["tampered"] = True
    assert not verify_rectification_packet_final(bad["rectification_packet"], bad)
    assert not verify_report_evidence(bad)["ok"]


def test_pass032_packet_tamper_is_rejected():
    report = _single()
    bad = deepcopy(report["rectification_packet"])
    bad["remaining"]["state"] = "FAKE"
    assert not verify_rectification_packet(bad, report)
    assert not verify_rectification_packet_final(bad, report)


def test_pass032_seal_tamper_is_rejected():
    report = _single()
    bad = deepcopy(report["rectification_packet"])
    bad["certifier_seal"]["certifier_ok"] = False
    assert not verify_rectification_packet_final(bad, report)


def test_pass032_absence_is_not_encoded_as_false_or_zero():
    packet = compile_rectification_packet({"engine": "x", "version": "v", "report_contract": {"status": "OPEN"}})
    rows = {x["logical_name"]: x for x in packet["surfaces"]}
    assert rows["boundaries"]["state"] == "NOT_EMITTED"
    assert rows["boundaries"]["sha256"] is None
    assert rows["boundaries"]["shape"] is None
    assert packet["absence_semantics"] == "NOT_EMITTED_IS_NOT_FALSE_ZERO_OR_IMPOSSIBLE"


def test_pass032_remaining_issues_become_next_terminal_objects():
    report = {
        "engine": "x", "version": "v", "report_contract": {"status": "STABLE_WITH_REPORTED_ISSUES"},
        "remaining_issues": [{"analyzer": "a", "code": "missing", "path": "/x", "severity": "warning", "repairable": False}],
    }
    packet = compile_rectification_packet(report)
    assert packet["remaining"]["state"] == "REMAINING_VISIBLE"
    assert packet["next_executable_objects"]["objects"][0]["kind"] == "REMAINING_ISSUE_TERMINAL"


def test_pass032_bundle_packet_and_closure():
    _, res = repair_bundle({"a.json": {"x": 1}, "b.json": {"y": 2}}, RepairConfig(max_cycles=3))
    report = res.report
    assert report["mode"] == "bundle"
    assert report["final_certification"]["ok"]
    assert verify_rectification_packet_final(report["rectification_packet"], report)
    assert report["fourth_series_closure"]["ok"]


def test_pass032_streaming_packet_and_closure(tmp_path: Path):
    src = tmp_path / "in.jsonl"; out = tmp_path / "out.jsonl"
    src.write_text('{"x":1}\n{"x":2}\n', encoding="utf-8")
    res = repair_stream_file(src, out, None, StreamingConfig(max_cycles=3), stream_format="jsonl")
    report = res.report
    assert report["mode"] == "streaming"
    assert report["final_certification"]["ok"]
    assert report["parallel_exact_minimum_routes"]["mode"] == "streaming"
    assert verify_rectification_packet_final(report["rectification_packet"], report)
    assert report["fourth_series_closure"]["status"] == "CLOSED"


def test_pass032_external_certifier_rechecks_final_sealed_packet():
    report = _single()
    cert = verify_report_evidence(report)
    assert cert["ok"] and cert["checks"]["rectification_packet"]


def test_pass032_disabled_certification_does_not_fake_closure():
    _, res = repair_object({"x": 1}, RepairConfig(max_cycles=3, enable_final_certification=False))
    report = res.report
    assert report["rectification_packet"]["certification_state"] == "PENDING_INDEPENDENT_VERIFICATION"
    assert report["fourth_series_closure"]["status"] == "OPEN"
    assert report["fourth_series_closure"]["remaining_substantive_passes"] == 1
