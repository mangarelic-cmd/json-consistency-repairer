from __future__ import annotations

from pathlib import Path
import tomllib

from json_consistency_repair._version import __version__
from json_consistency_repair.engine import RepairConfig, repair_object, score
from json_consistency_repair.minimal_transfer import solve_minimal_transfer
from json_consistency_repair.models import AnalysisResult, Candidate, Issue


def _c(cid,path,old,new):
    return Candidate(cid,"synthetic","replace",path,old,new,"synthetic",1.0,1,("independent",),{})


def test_coupled_transfer_closes_when_no_single_edit_improves():
    c1=_c("a","/a",0,1); c2=_c("b","/b",0,1)
    issue=Issue("synthetic","coupled","/a","both values must move","warning",True,{})
    baseline=AnalysisResult([issue],[c1,c2],[])
    def analyze(x):
        if x["a"]==1 and x["b"]==1:
            return AnalysisResult([],[],[])
        return AnalysisResult([issue],[c1,c2],[])
    d=solve_minimal_transfer({"a":0,"b":0},baseline,analyze_fn=analyze,score_fn=score,max_patch_size=2,max_exact_options=4)
    assert d.status.startswith("UNIQUE_EXACT_MINIMUM")
    assert {c.path for c in d.patches}=={"/a","/b"}
    assert d.certificate["selected_patch_count"]==2


def test_equal_exact_minima_abstain():
    c1=_c("x1","/x",0,1); c2=_c("x2","/x",0,2)
    issue=Issue("synthetic","either","/x","either value closes","warning",True,{})
    baseline=AnalysisResult([issue],[c1,c2],[])
    def analyze(x):
        if x["x"] in (1,2): return AnalysisResult([],[],[])
        return baseline
    d=solve_minimal_transfer({"x":0},baseline,analyze_fn=analyze,score_fn=score,max_patch_size=1,max_exact_options=4)
    assert d.status=="AMBIGUOUS_EXACT_MINIMUM"
    assert d.patches==[]
    assert d.certificate["clusters"][0]["tie_count"]==2


def test_two_enum_representation_repairs_in_same_record_commit_together():
    rows=[]
    for i in range(12):
        rows.append({"id":i,"status":"Ready","currency":"USD"})
    rows[-1]["status"]="ready"
    rows[-1]["currency"]="usd"
    cfg=RepairConfig(min_support=4,enum_confidence=.75,enum_min_value_support=2,enum_normalization_confidence=.70)
    repaired,res=repair_object({"rows":rows},cfg)
    assert repaired["rows"][-1]["status"]=="Ready"
    assert repaired["rows"][-1]["currency"]=="USD"
    first=res.report["cycles"][0]
    assert len(first["accepted"])==2
    assert first["minimal_transfer"]["selected_patch_count"]==2
    assert first["minimal_transfer"]["status"].startswith("UNIQUE_EXACT_MINIMUM")


def test_independent_records_are_partitioned_then_union_revalidated():
    rows=[]
    for i in range(12): rows.append({"id":i,"status":"Ready"})
    rows[10]["status"]="ready"; rows[11]["status"]="ready"
    cfg=RepairConfig(min_support=4,enum_confidence=.75,enum_min_value_support=3,enum_normalization_confidence=.70)
    repaired,res=repair_object({"rows":rows},cfg)
    assert repaired["rows"][10]["status"]==repaired["rows"][11]["status"]=="Ready"
    cert=res.report["cycles"][0]["minimal_transfer"]
    assert cert["status"]=="UNIQUE_EXACT_MINIMUM_PARTITIONED"
    assert cert["selected_patch_count"]==2
    assert cert["union_objective"] < cert["baseline_objective"]


def test_metric_is_exact_rational_not_float():
    rows=[{"id":i,"status":"Ready"} for i in range(12)]
    rows[-1]["status"]="ready"
    cfg=RepairConfig(min_support=4,enum_confidence=.75,enum_min_value_support=2,enum_normalization_confidence=.70)
    _,res=repair_object({"rows":rows},cfg)
    cert=res.report["cycles"][0]["minimal_transfer"]
    m=cert["union_metric"]
    assert m["cost"]=={"numerator":1,"denominator":1}
    assert isinstance(m["canonical_new_value_bytes"],int)


def test_large_exact_frontier_abstains_instead_of_claiming_minimality():
    issue=Issue("synthetic","many","/x0","many choices","warning",True,{})
    cands=[_c(f"c{i}",f"/x{i}",0,1) for i in range(9)]
    baseline=AnalysisResult([issue],cands,[])
    def analyze(x):
        # any individual edit would improve, but exact frontier is intentionally capped
        if any(v==1 for v in x.values()): return AnalysisResult([],[],[])
        return baseline
    root={f"x{i}":0 for i in range(9)}
    d=solve_minimal_transfer(root,baseline,analyze_fn=analyze,score_fn=score,max_patch_size=2,max_exact_options=8)
    # parent scope is root, so nine options exceed the exact declared frontier
    assert d.status=="FRONTIER_TOO_LARGE"
    assert d.patches==[]


def test_pass011_version_reconciled():
    root=Path(__file__).resolve().parents[1]
    project=tomllib.loads((root/'pyproject.toml').read_text(encoding='utf-8'))
    assert __version__==project['project']['version']
