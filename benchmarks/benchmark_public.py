from __future__ import annotations
import json, random, sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from json_consistency_repair.engine import RepairConfig, repair_object
from json_consistency_repair.provenance import package_code_sha256
from json_consistency_repair import __version__

rnd=random.Random(7007)

def cfg(**kw):
    base=dict(min_support=4,min_group_support=2,relation_confidence=.80,scoped_relation_confidence=.90,
              arithmetic_confidence=.80,temporal_confidence=.80,sequential_confidence=.75,
              required_key_confidence=.90,shape_confidence=.70,enum_confidence=.90,
              enum_normalization_confidence=.75,reference_confidence=.90,id_uniqueness_confidence=.90)
    base.update(kw); return RepairConfig(**base)

stats={"repair_cases":0,"correct_repairs":0,"abstention_cases":0,"correct_abstentions":0,"false_mutations":0,"replay_failures":0,"idempotence_failures":0}

# 100 enum representation repairs
for _ in range(100):
    rows=[{"id":i,"state":"READY" if i%2==0 else "DONE"} for i in range(20)]
    j=2*rnd.randrange(10); rows[j]["state"]="ready"; data={"rows":rows}
    out,r=repair_object(data,cfg()); stats["repair_cases"]+=1
    stats["correct_repairs"] += out["rows"][j]["state"]=="READY"
    stats["replay_failures"] += not r.report["replay"]["inverse_restores_input"]

# 100 canonical reference repairs
for t in range(100):
    pref=f"B{t}_"; users=[{"id":f"{pref}{i}"} for i in range(20)]; orders=[{"id":1000+i,"user_id":f"{pref}{i}"} for i in range(20)]
    j=rnd.randrange(20); orders[j]["user_id"]=orders[j]["user_id"].lower(); data={"users":users,"orders":orders}
    out,r=repair_object(data,cfg()); stats["repair_cases"]+=1
    stats["correct_repairs"] += out["orders"][j]["user_id"]==f"{pref}{j}"
    stats["replay_failures"] += not r.report["replay"]["inverse_restores_input"]

# 100 arithmetic repairs with independent directional evidence
for _ in range(100):
    rows=[]; bad=rnd.randrange(10)
    for i in range(10):
        plan="A" if i<5 else "B"; sub,tax,total=(10,2,12) if plan=="A" else (20,4,24)
        if i==bad: total=999
        rows.append({"plan":plan,"subtotal":sub,"tax":tax,"total":total})
    data={"rows":rows}; out,r=repair_object(data,cfg(arithmetic_direction_confidence=.95,relation_confidence=.75)); stats["repair_cases"]+=1
    stats["correct_repairs"] += out["rows"][bad]["total"] in (12,24)
    stats["replay_failures"] += not r.report["replay"]["inverse_restores_input"]

# 100 unknown enums: report, do not guess
for _ in range(100):
    rows=[{"id":i,"state":"READY" if i%2==0 else "DONE"} for i in range(20)]; rows[rnd.randrange(20)]["state"]="ALIEN"; data={"rows":rows}
    out,r=repair_object(data,cfg()); stats["abstention_cases"]+=1
    ok=out==data and any(i["code"]=="enum_domain_outlier" for i in r.report["remaining_issues"])
    stats["correct_abstentions"]+=ok; stats["false_mutations"]+=out!=data

# 100 dangling references: report, do not guess
for t in range(100):
    pref=f"D{t}_"; users=[{"id":f"{pref}{i}"} for i in range(20)]; orders=[{"id":2000+i,"user_id":f"{pref}{i}"} for i in range(20)]
    j=rnd.randrange(20); orders[j]["user_id"]="NO_SUCH_ID"; data={"users":users,"orders":orders}
    out,r=repair_object(data,cfg()); stats["abstention_cases"]+=1
    ok=out==data and any(i["code"]=="dangling_reference" for i in r.report["remaining_issues"])
    stats["correct_abstentions"]+=ok; stats["false_mutations"]+=out!=data

# 100 missing-required-key cases: anomaly is known, value is not invented
for _ in range(100):
    rows=[{"id":i,"name":f"n{i}","active":True} for i in range(20)]; j=rnd.randrange(20); del rows[j]["name"]; data={"rows":rows}
    out,r=repair_object(data,cfg(required_key_confidence=.95)); stats["abstention_cases"]+=1
    ok=out==data and any(i["code"]=="missing_required_key" for i in r.report["remaining_issues"])
    stats["correct_abstentions"]+=ok; stats["false_mutations"]+=out!=data

# Idempotence check over a fixed repaired corpus
for t in range(50):
    pref=f"I{t}_"; users=[{"id":f"{pref}{i}"} for i in range(20)]; orders=[{"id":3000+i,"user_id":f"{pref}{i}"} for i in range(20)]
    j=rnd.randrange(20); orders[j]["user_id"]=orders[j]["user_id"].lower(); out,_=repair_object({"users":users,"orders":orders},cfg())
    again,r2=repair_object(out,cfg()); stats["idempotence_failures"] += not (again==out and r2.committed_edits==0)

result={
 "benchmark":"JCR_PUBLIC_SYNTHETIC_V1","seed":7007,"engine_version":__version__,"package_code_sha256":package_code_sha256(),
 "scope":"synthetic in-distribution capability benchmark; not an external comparative benchmark",
 **stats,
 "repair_accuracy":stats["correct_repairs"]/stats["repair_cases"],
 "abstention_accuracy":stats["correct_abstentions"]/stats["abstention_cases"]
}
print(json.dumps(result,sort_keys=True,indent=2))
if not (stats["correct_repairs"]==stats["repair_cases"] and stats["correct_abstentions"]==stats["abstention_cases"] and stats["false_mutations"]==0 and stats["replay_failures"]==0 and stats["idempotence_failures"]==0):
    raise SystemExit(1)
