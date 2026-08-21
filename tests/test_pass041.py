from __future__ import annotations

from copy import deepcopy
import random

from json_consistency_repair import RepairConfig, repair_object
from json_consistency_repair.analyzers import analyze_all
from json_consistency_repair.grammar_repair import minimal_grammar_repair
from json_consistency_repair.security import SecurityLimits


def _cfg(**kw):
    base = dict(max_cycles=8, strong_fixed_point_cycles_required=2, enable_multisource=False)
    base.update(kw)
    return RepairConfig(**base)


def test_pass041_three_missing_nonmonotonic_terminal_is_closed():
    rows = [{"k": f"K{i%5}", "v": i % 5} for i in range(40)]
    truth = deepcopy(rows)
    # Historical PASS040 witness: this three-hole pattern could return
    # NO_IMPROVING_TRANSFER because one correct edit exposed new diagnostics.
    for i in (3, 11, 30):
        rows[i].pop("v")
    out, res = repair_object({"rows": rows}, _cfg())
    assert out == {"rows": truth}
    assert res.committed_edits == 3
    assert res.final_status == "PASS"


def test_pass041_sparse_functional_outliers_recover_below_safe_floor_boundary():
    rows = [{"k": f"K{i%5}", "v": i % 5} for i in range(40)]
    truth = deepcopy(rows)
    inds = random.Random(1).sample(range(40), 12)  # 30% corruption
    for q, i in enumerate(inds):
        rows[i]["v"] = 100 + (q % 13)
    out, res = repair_object({"rows": rows}, _cfg())
    assert out == {"rows": truth}
    assert res.committed_edits == 12
    assert res.final_status == "PASS"


def test_pass041_sparse_arithmetic_outliers_recover_when_residuals_are_noncoherent():
    rows = [{"a": i + 1, "b": 2 * (i + 1), "total": 3 * (i + 1)} for i in range(40)]
    truth = deepcopy(rows)
    inds = random.Random(1).sample(range(40), 16)  # 40% corruption, heterogeneous residuals
    for q, i in enumerate(inds):
        rows[i]["total"] = -1000 - q
    out, res = repair_object({"rows": rows}, _cfg())
    assert out == {"rows": truth}
    assert res.committed_edits == 16
    assert res.final_status == "PASS"


def test_pass041_sparse_route_refuses_coherent_competing_functional_mode():
    rows = []
    # For each determinant there are 5 observations of A and 3 observations of B.
    # A 5:3 mode is not enough to prove that B is corruption rather than a second regime.
    for k in range(5):
        rows.extend([{"k": f"K{k}", "v": k} for _ in range(5)])
        rows.extend([{"k": f"K{k}", "v": 100 + k} for _ in range(3)])
    analysis = analyze_all({"rows": rows}, _cfg())
    sparse = [r for r in analysis.relations if r.get("recovery_route") == "SPARSE_OUTLIER_RECOVERY"]
    assert not sparse
    out, res = repair_object({"rows": rows}, _cfg())
    assert out == {"rows": rows}
    assert res.committed_edits == 0


def test_pass041_sparse_route_requires_active_falsifier():
    rows = [{"k": f"K{i%5}", "v": i % 5} for i in range(40)]
    for q, i in enumerate(random.Random(1).sample(range(40), 8)):
        rows[i]["v"] = 100 + q
    analysis = analyze_all({"rows": rows}, _cfg(enable_relation_falsifier=False))
    assert not [r for r in analysis.relations if r.get("recovery_route") == "SPARSE_OUTLIER_RECOVERY"]


def test_pass041_pass_semantics_are_explicitly_relative_not_ground_truth():
    _, res = repair_object({"x": 1}, _cfg(max_cycles=3, strong_fixed_point_cycles_required=1))
    contract = res.report["report_contract"]
    assert contract["truth_scope"] == "EVIDENCE_AND_DECLARED_CONTRACT_RELATIVE"
    assert "NOT_EXTERNAL_GROUND_TRUTH_PROOF" in contract["pass_semantics"]


def test_pass041_grammar_closes_unterminated_scalar_string_when_unique():
    value, report = minimal_grammar_repair('{"a":"x}', SecurityLimits(), max_edit_distance=2)
    assert value == {"a": "x"}
    assert report and report[0]["canonical_parse_unique"]
    assert any(step["operation"] == "close_unterminated_string" for step in report[0]["route"])


def test_pass041_grammar_composes_two_minimal_structural_edits():
    value, report = minimal_grammar_repair('{"a" 1 "b":2}', SecurityLimits(), max_edit_distance=2)
    assert value == {"a": 1, "b": 2}
    assert report and report[0]["canonical_parse_unique"]
    assert report[0]["edit_distance"] == 2


def test_pass041_grammar_still_refuses_duplicate_key_ambiguity():
    value, report = minimal_grammar_repair('{"a":1,"a":2}', SecurityLimits(), max_edit_distance=2)
    assert value is None
    assert report == []


def test_pass041_random_structured_corpora_do_not_activate_sparse_route():
    rng = random.Random(41041)
    for _ in range(100):
        rows = []
        for i in range(30):
            rows.append({"k": f"K{i%5}", "v": rng.randrange(1000000), "a": rng.randrange(1, 500), "b": rng.randrange(1, 500)})
        analysis = analyze_all({"rows": rows}, _cfg())
        assert not [r for r in analysis.relations if r.get("recovery_route") == "SPARSE_OUTLIER_RECOVERY"]


def test_pass041_dirty_json_adapters_repair_three_deterministic_dialects():
    lim=SecurityLimits()
    cases=[
        ("{'a':1, 'b':'x'}", {'a':1,'b':'x'}, 'normalize_single_quoted_strings'),
        ('{a:1, b:"x"}', {'a':1,'b':'x'}, 'quote_unquoted_identifier_keys'),
        ('{"a":1/*note*/,"b":2//line\n}', {'a':1,'b':2}, 'strip_js_comments'),
    ]
    for text,expected,op in cases:
        value,report=minimal_grammar_repair(text,lim,max_edit_distance=2)
        assert value==expected
        assert report and any(step['operation']==op for route in report[0]['convergent_routes'] for step in route)


def test_pass041_dirty_json_adapters_do_not_touch_comment_markers_inside_strings():
    lim=SecurityLimits()
    text='{"url":"https://x/y//z","note":"/*not comment*/"}'
    value,report=minimal_grammar_repair(text,lim,max_edit_distance=2)
    assert value=={'url':'https://x/y//z','note':'/*not comment*/'}
    assert report==[]


def test_pass041_fast_mode_scans_all_but_repairs_only_local_unique_cones():
    n=100
    rows=[{'k':f'K{i%5}','v':i%5,'a':i+1,'b':2*(i+1),'total':3*(i+1)} for i in range(n)]
    rows[n//3]['v']=99991
    rows[(2*n)//3]['total']=-99991
    out,res=repair_object({'rows':rows},_cfg(execution_mode='fast'))
    assert out['rows'][n//3]['v']==(n//3)%5
    assert out['rows'][(2*n)//3]['total']==3*((2*n)//3+1)
    assert res.committed_edits==2
    assert res.final_status=='PASS'
    assert res.report['execution_profile']['scan_scope']=='ALL_ANALYZERS'
    assert res.report['certification_gate']=='FAST_SCAN_ONLY'
    assert res.report['final_certification']['status']=='NOT_RUN_FAST_MODE'


def test_pass041_fast_mode_does_not_claim_full_certification():
    _,res=repair_object({'rows':[{'k':'A','v':1},{'k':'A','v':1},{'k':'A','v':1},{'k':'A','v':1}]},_cfg(execution_mode='fast'))
    assert res.report['report_contract']['assurance']=='FAST_SCAN_ONLY'
    assert res.report['report_contract']['full_certification'] is False
    assert res.report['certification_gate']=='FAST_SCAN_ONLY'


def test_pass041_fast_mode_defers_true_multifield_ambiguity():
    # Two independent local candidate targets in the same carrier without a unique
    # direction witness are scanned and exposed, not silently mutated in fast mode.
    rows=[]
    for i in range(20):
        rows.append({'x':i%2,'y':i%2,'z':i%2})
    rows[7]['y']=9
    rows[7]['z']=8
    out,res=repair_object({'rows':rows},_cfg(execution_mode='fast'))
    # The key contract is that fast mode remains a bounded action surface. Whether
    # one independently directed repair survives is allowed, but it cannot claim
    # full certification and must expose anything it defers.
    assert res.report['certification_gate']=='FAST_SCAN_ONLY'
    if res.remaining_issues:
        skipped=[x for cyc in res.report['cycles'] for x in cyc.get('skipped',[])]
        assert skipped
