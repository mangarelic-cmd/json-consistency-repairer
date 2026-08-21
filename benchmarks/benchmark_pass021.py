from __future__ import annotations
import json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'src'))
from json_consistency_repair import RepairConfig, repair_object, __version__

def cfg(rule): return RepairConfig(moment_rules=(rule,),enable_final_certification=False,max_cycles=5,min_support=1)
counts={}; false_mutations=0
def hit(k): counts[k]=counts.get(k,0)+1
for n in range(100):
    o={'rows':[{'items':[{'v':n+1,'w':1},{'v':n+3,'w':3}],'mean':-1}]}; r={'kind':'weighted_mean','array_path':'/rows','items_field':'items','value_field':'v','weight_field':'w','target':'mean'}; out,_=repair_object(o,cfg(r)); assert out['rows'][0]['mean']==n+2.5; hit('weighted_mean')
for n in range(100):
    o={'rows':[{'items':[{'x':n+1},{'x':n+3}],'variance':99}]}; r={'kind':'variance','array_path':'/rows','items_field':'items','value_field':'x','target':'variance'}; out,_=repair_object(o,cfg(r)); assert out['rows'][0]['variance']==1; hit('variance')
for n in range(100):
    o={'rows':[{'items':[{'x':n+1,'y':2*(n+1)},{'x':n+3,'y':2*(n+3)}],'cov':99}]}; r={'kind':'covariance','array_path':'/rows','items_field':'items','x_field':'x','y_field':'y','target':'cov'}; out,_=repair_object(o,cfg(r)); assert out['rows'][0]['cov']==2; hit('covariance')
for n in range(100):
    o={'rows':[{'items':[{'p':0.1},{'p':0.2},{'p':0.7}],'p_total':9}]}; r={'kind':'probability_total','array_path':'/rows','items_field':'items','probability_field':'p','target':'p_total'}; out,_=repair_object(o,cfg(r)); assert out['rows'][0]['p_total']==1.0; hit('probability_total')
for n in range(100):
    o={'rows':[{'items':[{'v':1,'w':1},{'v':2,'w':2}],'mean':0}]}; r={'kind':'weighted_mean','array_path':'/rows','items_field':'items','value_field':'v','weight_field':'w','target':'mean'}; out,res=repair_object(o,cfg(r)); false_mutations+=int(out!=o); hit('nonterminating_abstain')
for n in range(100):
    o={'rows':[{'value':250+n,'unit':'cm'}]}; r={'kind':'unit_normalize','array_path':'/rows','value_field':'value','unit_field':'unit','canonical_unit':'m','conversions':{'cm':'0.01'}}; out,res=repair_object(o,cfg(r)); assert out['rows'][0]['unit']=='m' and res.committed_edits==1; hit('unit_atomic_plan')
result={'contract':'json-consistency-repair.pass021-benchmark.v1','version':__version__,'expected_decisions':600,'decisions':sum(counts.values()),'false_mutations':false_mutations,'counts':dict(sorted(counts.items())),'all_checks_pass':sum(counts.values())==600 and false_mutations==0}
print(json.dumps(result,sort_keys=True,separators=(',',':')))
