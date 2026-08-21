from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
"""Deterministic PASS002 stress campaign. Run directly; exits non-zero on first failure."""
from datetime import datetime, timedelta
import random
from json_consistency_repair.engine import repair_object, RepairConfig

R=random.Random(20260819)


def cfg(**kw):
    d=dict(min_support=4,min_group_support=2,min_scope_support=3,min_scope_group_support=2,
           relation_confidence=.80,scoped_relation_confidence=.80,arithmetic_confidence=.80,
           arithmetic_direction_confidence=.90,temporal_confidence=.80,sequential_confidence=.70)
    d.update(kw); return RepairConfig(**d)

counts={"functional":0,"sum":0,"product":0,"sequence":0,"temporal":0,"ambiguous_abstain":0,"idempotence":0}

for case in range(75):
    rows=[]
    for i in range(10):
        x="A" if i%2==0 else "B"; y="alpha" if x=="A" else "beta"
        rows.append({"id":i,"x":x,"y":y})
    j=R.randrange(10); expected=rows[j]["y"]; rows[j]["y"]="BROKEN"
    out,res=repair_object({"rows":rows},cfg())
    assert out["rows"][j]["y"]==expected, (case,j,out["rows"][j])
    counts["functional"]+=1

for op in ("sum","product"):
    for case in range(75):
        rows=[]
        for i in range(8):
            a=R.randint(2,40); b=R.randint(2,12)
            target=a+b if op=="sum" else a*b
            key="total" if op=="sum" else "product"
            rows.append({"a":a,"b":b,key:target})
        j=R.randrange(1,7); key="total" if op=="sum" else "product"; expected=rows[j][key]; rows[j][key]+=R.randint(1000,2000)
        out,res=repair_object({"rows":rows},cfg())
        assert out["rows"][j][key]==expected, (op,case,j,out["rows"][j],expected)
        assert res.report["replay"]["inverse_restores_input"] is True
        counts[op]+=1

for case in range(75):
    start=R.randint(-50,50); step=R.choice([1,2,3,5,10])
    rows=[{"seq":start+i*step} for i in range(9)]
    j=R.randrange(1,8); expected=rows[j]["seq"]; rows[j]["seq"]+=R.randint(100,500)
    out,res=repair_object({"rows":rows},cfg(min_support=3))
    assert out["rows"][j]["seq"]==expected, (case,j,step,out["rows"][j],expected)
    counts["sequence"]+=1

for case in range(50):
    base=datetime(2026,1,1)+timedelta(days=case); delta=timedelta(minutes=R.choice([15,30,45,60,90]))
    rows=[]
    for i in range(7):
        a=base+timedelta(days=i); b=a+delta
        rows.append({"start":a.isoformat(),"end":b.isoformat()})
    j=R.randrange(7); expected=rows[j]["end"]; rows[j]["end"]=(base+timedelta(days=j,hours=9)).isoformat()
    out,res=repair_object({"events":rows},cfg())
    assert out["events"][j]["end"]==expected, (case,j,out["events"][j],expected)
    counts["temporal"]+=1

for case in range(50):
    rows=[]
    # Deliberately non-sequential values: only the invertible arithmetic equation is available.
    pairs=[(11,2),(23,5),(37,4),(52,9),(68,7),(83,11),(101,13)]
    for i,(a,b) in enumerate(pairs):
        a += case*17; b += (case%3); d=a-b
        o={"a":a,"b":b,"d":d} if i%2==0 else {"d":d,"b":b,"a":a}
        rows.append(o)
    rows[3]["d"]+=999
    original={"rows":rows}
    out,res=repair_object(original,cfg(arithmetic_direction_confidence=.90))
    assert out==original, (case,out)
    counts["ambiguous_abstain"]+=1

# Three consecutive idempotence replays after one repair.
for case in range(25):
    rows=[{"a":i,"b":2,"total":i+2} for i in range(1,9)]
    rows[4]["total"]=999
    cur,res=repair_object({"rows":rows},cfg())
    for _ in range(3):
        nxt,r=repair_object(cur,cfg())
        assert nxt==cur and r.committed_edits==0 and r.report["replay"]["inverse_restores_input"] is True
        cur=nxt
    counts["idempotence"]+=1

print(counts)
print("TOTAL",sum(counts.values()),"PASS")
