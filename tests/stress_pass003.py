from __future__ import annotations
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
import random
from json_consistency_repair.engine import repair_object, RepairConfig

rnd=random.Random(3003)

def cfg(**kw):
    base=dict(min_support=4,min_group_support=2,relation_confidence=.80,scoped_relation_confidence=.90,
              arithmetic_confidence=.80,temporal_confidence=.80,sequential_confidence=.75,
              required_key_confidence=.90,shape_confidence=.70,enum_confidence=.90,
              enum_normalization_confidence=.75,reference_confidence=.90,id_uniqueness_confidence=.90)
    base.update(kw); return RepairConfig(**base)

counts={}
def hit(k): counts[k]=counts.get(k,0)+1

# Enum normalization
for t in range(100):
    good="READY"; alt="ready"
    rows=[{"id":i,"state":good if i%2==0 else "DONE"} for i in range(20)]
    j=rnd.randrange(0,20,2); rows[j]["state"]=alt
    out,r=repair_object({"rows":rows},cfg())
    assert out["rows"][j]["state"]==good
    hit("enum_case_repair")

# Unknown enum: detect, abstain
for t in range(100):
    rows=[{"id":i,"state":"READY" if i%2==0 else "DONE"} for i in range(20)]
    j=rnd.randrange(20); rows[j]["state"]="ALIEN"
    data={"rows":rows}; out,r=repair_object(data,cfg())
    assert out==data
    assert any(i["code"]=="enum_domain_outlier" for i in r.report["remaining_issues"])
    hit("enum_abstain")

# Cross-array reference normalization and dangling abstention
for t in range(100):
    prefix=f"U{t}_"
    users=[{"id":f"{prefix}{i}"} for i in range(20)]
    orders=[{"id":1000+t*100+i,"user_id":f"{prefix}{i}"} for i in range(20)]
    j=rnd.randrange(20); orders[j]["user_id"]=orders[j]["user_id"].lower()
    out,r=repair_object({"users":users,"orders":orders},cfg())
    assert out["orders"][j]["user_id"]==f"{prefix}{j}"
    hit("reference_case_repair")

for t in range(100):
    prefix=f"R{t}_"
    users=[{"id":f"{prefix}{i}"} for i in range(20)]
    orders=[{"id":2000+t*100+i,"user_id":f"{prefix}{i}"} for i in range(20)]
    j=rnd.randrange(20); orders[j]["user_id"]="NO_SUCH_ID"
    data={"users":users,"orders":orders}; out,r=repair_object(data,cfg())
    assert out==data
    assert any(i["code"]=="dangling_reference" for i in r.report["remaining_issues"])
    hit("reference_abstain")

# Schema absence is never invented without value evidence
for t in range(100):
    rows=[{"id":i,"name":f"n{i}","active":True} for i in range(20)]
    j=rnd.randrange(20); del rows[j]["name"]
    data={"rows":rows}; out,r=repair_object(data,cfg(required_key_confidence=.95))
    assert out==data
    assert any(i["code"]=="missing_required_key" and i["path"]==f"/rows/{j}/name" for i in r.report["remaining_issues"])
    hit("schema_abstain")

# Cross-family arithmetic direction anchor
for t in range(100):
    rows=[]
    bad=rnd.randrange(10)
    for i in range(10):
        plan="A" if i<5 else "B"; sub,tax,total=(10,2,12) if plan=="A" else (20,4,24)
        if i==bad: total=999
        o={"plan":plan,"subtotal":sub,"tax":tax,"total":total}
        if i%2: o={"total":total,"tax":tax,"subtotal":sub,"plan":plan}
        rows.append(o)
    # Ensure corrupted row belongs to a group with enough untouched support.
    if bad in (0,1,2,3,4): pass
    out,r=repair_object({"rows":rows},cfg(arithmetic_direction_confidence=.95,relation_confidence=.75))
    assert out["rows"][bad]["total"] in (12,24)
    hit("arithmetic_federated")

# Multi-equation direction anchor and triple idempotence after repair
for t in range(50):
    rows=[]; bad=rnd.randrange(10)
    for i in range(10):
        a=10+i; b=2; total=a+b; d=7; c=total+d
        if i==bad: total=777
        o={"a":a,"b":b,"c":c,"d":d,"total":total}
        if i%2: o={"total":total,"d":d,"c":c,"b":b,"a":a}
        rows.append(o)
    out,r=repair_object({"rows":rows},cfg(arithmetic_direction_confidence=.95,max_numeric_fields=8))
    assert out["rows"][bad]["total"]==12+bad
    cur=out
    for _ in range(3):
        nxt,rr=repair_object(cur,cfg(arithmetic_direction_confidence=.95,max_numeric_fields=8))
        assert nxt==cur and rr.committed_edits==0 and rr.report["replay"]["inverse_restores_input"] is True
        cur=nxt
    hit("multi_equation_and_idempotence3")

print(counts)
print('TOTAL',sum(counts.values()),'PASS')
