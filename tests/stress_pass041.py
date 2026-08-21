from __future__ import annotations

import random

from json_consistency_repair import RepairConfig
from json_consistency_repair.analyzers import analyze_all
from json_consistency_repair.engine import score
from json_consistency_repair.grammar_repair import minimal_grammar_repair
from json_consistency_repair.minimal_transfer import solve_minimal_transfer
from json_consistency_repair.models import AnalysisResult, Candidate, Issue
from json_consistency_repair.security import SecurityLimits


def cfg(**kw):
    d=dict(max_cycles=8,strong_fixed_point_cycles_required=2,enable_multisource=False)
    d.update(kw)
    return RepairConfig(**d)


def main():
    counts={
        "frozen_terminal_descent":0,
        "functional_sparse_surface":0,
        "arithmetic_sparse_surface":0,
        "random_no_sparse_promotion":0,
        "coherent_alternative_refused":0,
        "grammar_bounded_safe":0,
    }

    # Exact synthetic version of the PASS040 non-monotonicity defect: closing
    # the frozen pre-existing terminal reveals two new warning diagnostics.
    # The move must still count as descent on the same terminal.
    for i in range(100):
        c=Candidate(f"c{i}","synthetic","replace","/x",0,1,"close frozen terminal",1.0,1,("independent",),{})
        old=Issue("synthetic","frozen_terminal","/x","old terminal","warning",True,{})
        baseline=AnalysisResult([old],[c],[])
        n1=Issue("synthetic","newly_exposed_1","/y","new diagnostic","warning",False,{})
        n2=Issue("synthetic","newly_exposed_2","/z","new diagnostic","warning",False,{})
        def analyze(x):
            return AnalysisResult([n1,n2],[],[]) if x["x"]==1 else baseline
        d=solve_minimal_transfer({"x":0},baseline,analyze_fn=analyze,score_fn=score,max_patch_size=1,max_exact_options=4)
        assert d.status.startswith("UNIQUE_EXACT_MINIMUM") and len(d.patches)==1
        assert d.certificate["objective_order"][1]=="surviving_preexisting_terminals"
        counts["frozen_terminal_descent"]+=1

    # Sparse corruption surfaces: eight unique/non-coherent outliers on 40 rows.
    for seed in range(100):
        rows=[{"k":f"K{i%5}","v":i%5} for i in range(40)]
        for q,i in enumerate(random.Random(seed+42000).sample(range(40),8)):
            rows[i]["v"]=100000+seed*100+q
        a=analyze_all({"rows":rows},cfg())
        rel=[r for r in a.relations if r.get("kind")=="functional" and r.get("recovery_route")=="SPARSE_OUTLIER_RECOVERY"]
        assert rel and len([c for c in a.candidates if c.metadata.get("recovery_route")=="SPARSE_OUTLIER_RECOVERY"])>=8
        counts["functional_sparse_surface"]+=1

    for seed in range(100):
        rows=[{"a":i+1,"b":2*(i+1),"total":3*(i+1)} for i in range(40)]
        for q,i in enumerate(random.Random(seed+43000).sample(range(40),8)):
            rows[i]["total"]=3*(i+1)+1000000+seed*100+q
        a=analyze_all({"rows":rows},cfg())
        rel=[r for r in a.relations if r.get("kind")=="exact_arithmetic" and r.get("output")=="total" and r.get("recovery_route")=="SPARSE_OUTLIER_RECOVERY"]
        assert rel and len([c for c in a.candidates if c.metadata.get("recovery_route")=="SPARSE_OUTLIER_RECOVERY" and c.path.endswith("/total")])>=8
        counts["arithmetic_sparse_surface"]+=1

    # Random unrelated values must not be promoted by the fallback.
    for seed in range(100):
        rng=random.Random(seed+44000)
        rows=[{"k":f"K{i%5}","v":rng.randrange(10**9),"a":rng.randrange(1,10**6),"b":rng.randrange(1,10**6)} for i in range(30)]
        a=analyze_all({"rows":rows},cfg())
        assert not [r for r in a.relations if r.get("recovery_route")=="SPARSE_OUTLIER_RECOVERY"]
        counts["random_no_sparse_promotion"]+=1

    # A coherent second mode is evidence of a possible second regime, not a
    # sparse corruption cloud; keep it untouched.
    for seed in range(100):
        rows=[]; shift=1000+seed*10
        for k in range(5):
            rows.extend([{"k":f"K{k}","v":k} for _ in range(5)])
            rows.extend([{"k":f"K{k}","v":shift+k} for _ in range(3)])
        a=analyze_all({"rows":rows},cfg())
        assert not [r for r in a.relations if r.get("recovery_route")=="SPARSE_OUTLIER_RECOVERY"]
        counts["coherent_alternative_refused"]+=1

    # The grammar extension is bounded JSON-native composition.  Duplicate-key
    # ambiguity remains outside the automatic repair algebra.
    lim=SecurityLimits()
    for _ in range(100):
        v,rep=minimal_grammar_repair('{"a" 1 "b":2}',lim,max_edit_distance=2)
        assert v=={"a":1,"b":2} and rep and rep[0]["edit_distance"]==2
        v2,rep2=minimal_grammar_repair('{"a":1,"a":2}',lim,max_edit_distance=2)
        assert v2 is None and rep2==[]
        counts["grammar_bounded_safe"]+=1

    total=sum(counts.values())
    print("PASS041_STRESS",total,counts)
    assert total==600


if __name__=="__main__":
    main()
