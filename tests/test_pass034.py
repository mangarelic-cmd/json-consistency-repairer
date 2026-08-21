from copy import deepcopy

from json_consistency_repair import (
    RepairConfig, repair_object, parse_dsl,
    parse_expression, evaluate_expression, solve_equation,
    compile_repair_path_algebra, verify_repair_path_algebra, candidate_set_admissibility,
)
from json_consistency_repair.models import Candidate


def c(cid, op, path, old, new, meta=None):
    return Candidate(cid, "test", op, path, old, new, "test", 1.0, 1, (), meta or {})


def test_pass034_expression_parser_and_exact_evaluator():
    expr = parse_expression("(subtotal + tax) / 2")
    r = evaluate_expression(expr, {"subtotal": "7/2", "tax": "1/2"})
    assert r.status == "VALUE"
    assert str(r.value) == "2"


def test_pass034_dsl_compiles_expression_rule():
    rules = parse_dsl("scope /rows\nexpr total_rule: total = subtotal + tax")
    assert len(rules) == 1
    assert rules[0]["kind"] == "expression"
    assert rules[0]["name"] == "total_rule"
    assert rules[0]["rule_id"].startswith("dsl_")


def test_pass034_expression_repairs_unique_target():
    value = {"rows": [{"subtotal": 7, "tax": 3, "total": 9}]}
    rule = parse_dsl("scope /rows\nexpr total_rule: total = subtotal + tax")[0]
    out, res = repair_object(value, RepairConfig(constraint_rules=(rule,), min_support=99))
    assert out["rows"][0]["total"] == 10
    assert res.final_status == "PASS"
    assert res.report["typed_expression_ir"]["rule_count"] == 1
    assert "add" in res.report["typed_expression_ir"]["operator_set"]
    assert res.report["final_certification"]["status"] == "CERTIFIED"


def test_pass034_expression_materializes_missing_target():
    value = {"rows": [{"a": 4, "b": 6}]}
    rule = parse_dsl("scope /rows\nexpr sum_rule: total = a + b")[0]
    out, res = repair_object(value, RepairConfig(constraint_rules=(rule,), min_support=99))
    assert out["rows"][0]["total"] == 10
    assert res.committed_edits == 1


def test_pass034_inverse_solver_handles_division_and_sqrt_exactly():
    lhs = parse_expression("x / 3")
    rhs = parse_expression("2")
    st, v, _ = solve_equation(lhs, rhs, "x", {})
    assert st == "UNIQUE" and str(v) == "6"
    lhs = parse_expression("sqrt(x)")
    rhs = parse_expression("3")
    st, v, _ = solve_equation(lhs, rhs, "x", {})
    assert st == "UNIQUE" and str(v) == "9"


def test_pass034_even_power_sign_symmetry_abstains():
    lhs = parse_expression("x ** 2")
    rhs = parse_expression("9")
    st, v, reason = solve_equation(lhs, rhs, "x", {})
    assert st == "MULTIPLE" and v is None
    assert "sign symmetry" in reason


def test_pass034_noninvertible_mod_is_visible_not_guessed():
    lhs = parse_expression("mod(x, 5)")
    rhs = parse_expression("2")
    st, v, _ = solve_equation(lhs, rhs, "x", {})
    assert st == "MULTIPLE" and v is None


def test_pass034_disjoint_actions_are_proven_confluent():
    root = {"a": 0, "b": 0}
    xs = [c("a", "replace", "/a", 0, 1), c("b", "replace", "/b", 0, 2)]
    cert = compile_repair_path_algebra(root, xs)
    assert cert["termination"]["status"] == "TERMINATION_PROVEN_FINITE_FRONTIER"
    assert cert["confluence_status"] == "CONFLUENT_ON_CURRENT_FINITE_FRONTIER"
    assert cert["critical_pairs"][0]["status"] == "PROVEN_COMMUTE_DISJOINT"
    assert verify_repair_path_algebra(cert)


def test_pass034_open_critical_pair_detected():
    root = {"x": 0}
    xs = [c("a", "replace", "/x", 0, 1), c("b", "replace", "/x", 0, 2)]
    cert = compile_repair_path_algebra(root, xs)
    assert cert["confluence_status"] == "CRITICAL_PAIR_OPEN"
    assert cert["open_critical_pair_count"] == 1
    assert not candidate_set_admissibility(root, xs)["admissible"]


def test_pass034_critical_pair_can_join_through_later_actions():
    root = {"x": 0}
    xs = [
        c("a", "replace", "/x", 0, 1),
        c("b", "replace", "/x", 0, 2),
        c("c", "replace", "/x", 1, 3),
        c("d", "replace", "/x", 2, 3),
    ]
    cert = compile_repair_path_algebra(root, xs)
    pair = next(p for p in cert["critical_pairs"] if {p["left"], p["right"]} == {"a", "b"})
    assert pair["status"] == "JOINABLE_CRITICAL_PAIR"
    assert pair["joinable"] is True
    assert pair["common_normal_form_digest"]


def test_pass034_report_algebra_is_independently_verifiable():
    value = {"rows": [{"a": 1, "b": 2, "total": 0}]}
    rule = parse_dsl("scope /rows\nexpr e: total = a + b")[0]
    out, res = repair_object(value, RepairConfig(constraint_rules=(rule,), min_support=99))
    rows = res.report["repair_path_algebra"]["cycles"]
    assert rows
    assert all(verify_repair_path_algebra(x["certificate"]) for x in rows)
    assert res.report["final_certification"]["checks"]["repair_path_algebra"] is True


def test_pass034_tampered_algebra_fails_independent_certifier_evidence():
    from json_consistency_repair.certifier import verify_report_evidence
    value = {"rows": [{"a": 1, "b": 2, "total": 0}]}
    rule = parse_dsl("scope /rows\nexpr e: total = a + b")[0]
    _, res = repair_object(value, RepairConfig(constraint_rules=(rule,), min_support=99))
    report = deepcopy(res.report)
    report["repair_path_algebra"]["cycles"][0]["certificate"]["confluence_status"] = "FORGED"
    chk = verify_report_evidence(report)
    assert chk["ok"] is False
    assert chk["checks"]["repair_path_algebra"] is False


def test_pass034_nonfinite_rational_is_open_not_approximated():
    value = {"rows": [{}]}
    rule = parse_dsl("scope /rows\nexpr third: x = 1 / 3")[0]
    out, res = repair_object(value, RepairConfig(constraint_rules=(rule,), min_support=99))
    assert out == value
    expr_issues = [x for x in res.report.get("remaining_issues", []) if x.get("analyzer") == "expression_exact"]
    assert expr_issues
    attempts = expr_issues[0]["metadata"]["solve_attempts"]
    assert attempts[0]["status"] == "OPEN_NONFINITE_JSON_NUMBER"


def test_pass034_finite_rational_can_be_materialized_exactly():
    value = {"rows": [{}]}
    rule = parse_dsl("scope /rows\nexpr eighth: x = 1 / 8")[0]
    out, res = repair_object(value, RepairConfig(constraint_rules=(rule,), min_support=99))
    assert out["rows"][0]["x"] == 0.125
    assert res.report["final_certification"]["status"] == "CERTIFIED"


def test_pass034_bundle_expression_and_algebra_certified():
    from json_consistency_repair import repair_bundle
    docs = {"a.json": {"rows": [{"a": 2, "b": 3, "total": 0}]}, "b.json": {"rows": [{"a": 1, "b": 1, "total": 2}]}}
    rule = parse_dsl("scope /rows\nexpr total_rule: total = a + b")[0]
    out, res = repair_bundle(docs, RepairConfig(constraint_rules=(rule,), min_support=99))
    assert out["a.json"]["rows"][0]["total"] == 5
    assert res.report["final_certification"]["status"] == "CERTIFIED"
    assert res.report["typed_expression_ir"]["documents"]["a.json"]["rule_count"] == 1
    assert res.report["repair_path_algebra"]["cycles"]


def test_pass034_streaming_expression_and_algebra_certified(tmp_path):
    import json
    from json_consistency_repair import StreamingConfig, repair_stream_file
    src = tmp_path / "in.jsonl"; dst = tmp_path / "out.jsonl"
    src.write_text(json.dumps({"a": 2, "b": 3, "total": 0}) + "\n", encoding="utf-8")
    rule = parse_dsl("scope /\nexpr total_rule: total = a + b")[0]
    rule["array_path"] = ""
    cfg = StreamingConfig(constraint_rules=(rule,), exact_disk_registry=True, min_support=99, max_cycles=4)
    res = repair_stream_file(src, dst, config=cfg, stream_format="jsonl")
    row = json.loads(dst.read_text(encoding="utf-8"))
    assert row["total"] == 5
    assert res.report["final_certification"]["status"] == "CERTIFIED"
    assert res.report["typed_expression_ir"]["rule_count"] == 1
    assert res.report["repair_path_algebra"]["scope"] == "record_bridge_inherited"
