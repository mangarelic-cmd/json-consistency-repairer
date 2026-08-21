from __future__ import annotations
from json_consistency_repair import RepairConfig, repair_object
from json_consistency_repair.bundle import repair_bundle
from json_consistency_repair.streaming import StreamingConfig, repair_stream_file
import json, tempfile
from pathlib import Path

counts={}
def cfg(rule=None,**kw): return RepairConfig(enable_final_certification=False,max_cycles=5,moment_rules=((rule,) if rule else ()),**kw)

def wm(**kw):
    d={'kind':'weighted_mean','array_path':'/rows','items_field':'items','value_field':'v','weight_field':'w','target':'mean'}; d.update(kw); return d

for n in range(100):
    obj={'rows':[{'items':[{'v':n+1,'w':1},{'v':n+3,'w':3}],'mean':-1}]}; out,res=repair_object(obj,cfg(wm(),min_support=1)); assert out['rows'][0]['mean']==n+2.5 and res.committed_edits==1
counts['weighted_mean']=100
for n in range(80):
    obj={'rows':[{'items':[{'x':n+1},{'x':n+3}],'variance':99}]}; rule={'kind':'variance','array_path':'/rows','items_field':'items','value_field':'x','target':'variance'}; out,res=repair_object(obj,cfg(rule,min_support=1)); assert out['rows'][0]['variance']==1
counts['variance']=80
for n in range(80):
    obj={'rows':[{'items':[{'x':n+1,'y':2*(n+1)},{'x':n+3,'y':2*(n+3)}],'cov':99}]}; rule={'kind':'covariance','array_path':'/rows','items_field':'items','x_field':'x','y_field':'y','target':'cov'}; out,res=repair_object(obj,cfg(rule,min_support=1)); assert out['rows'][0]['cov']==2
counts['covariance']=80
for n in range(80):
    obj={'rows':[{'items':[{'p':0.1},{'p':0.2},{'p':0.7}],'p_total':n+2}]}; rule={'kind':'probability_total','array_path':'/rows','items_field':'items','probability_field':'p','target':'p_total'}; out,res=repair_object(obj,cfg(rule,min_support=1)); assert out['rows'][0]['p_total']==1.0
counts['probability_total']=80
for n in range(60):
    obj={'rows':[{'items':[{'u':1,'w':1},{'u':1,'w':1}],'uvar':9}]}; rule={'kind':'uncertainty_variance','array_path':'/rows','items_field':'items','uncertainty_field':'u','weight_field':'w','target':'uvar','mode':'weighted_mean'}; out,res=repair_object(obj,cfg(rule,min_support=1)); assert out['rows'][0]['uvar']==0.5
counts['uncertainty_sidecar']=60
for n in range(60):
    obj={'rows':[{'value':250+n,'unit':'cm'}]}; rule={'kind':'unit_normalize','array_path':'/rows','value_field':'value','unit_field':'unit','canonical_unit':'m','conversions':{'cm':'0.01'}}; out,res=repair_object(obj,cfg(rule,min_support=1)); assert out['rows'][0]['unit']=='m' and out['rows'][0]['value']==(250+n)/100 and res.committed_edits==1 and res.report['replay']['inverse_restores_input']
counts['unit_atomic_plan']=60
for n in range(60):
    rows=[]
    for i in range(20): rows.append({'items':[{'v':i+n+1,'w':1},{'v':i+n+3,'w':1}],'weighted_mean':i+n+2})
    rows[-1]['weighted_mean']=999999
    out,res=repair_object({'rows':rows},RepairConfig(enable_final_certification=False,max_cycles=5,min_support=4,moment_min_support=4)); assert out['rows'][-1]['weighted_mean']==n+21
counts['inferred_weighted_mean']=60
for n in range(40):
    # exact mean 5/3 cannot be represented as a finite JSON decimal; abstain instead of rounding.
    obj={'rows':[{'items':[{'v':1,'w':1},{'v':2,'w':2}],'mean':0}]}; out,res=repair_object(obj,cfg(wm(),min_support=1)); assert out==obj and res.committed_edits==0
counts['nonterminating_abstain']=40
for n in range(20):
    docs={'a.json':{'rows':[{'items':[{'v':1,'w':1},{'v':3,'w':1}],'mean':0}]},'b.json':{'rows':[{'items':[{'v':10,'w':1}],'mean':0}]}}; rule=wm(document='a.json'); out,res=repair_bundle(docs,cfg(rule,min_support=1)); assert out['a.json']['rows'][0]['mean']==2 and out['b.json']==docs['b.json']
counts['bundle_scoped']=20
with tempfile.TemporaryDirectory() as td:
    td=Path(td)
    for n in range(20):
        inp=td/f'i{n}.jsonl'; outp=td/f'o{n}.jsonl'; inp.write_text(json.dumps({'items':[{'v':1,'w':1},{'v':3,'w':1}],'mean':0})+'\n')
        rule={'kind':'weighted_mean','document':'@stream','items_field':'items','value_field':'v','weight_field':'w','target':'mean'}
        res=repair_stream_file(inp,outp,config=StreamingConfig(moment_rules=(rule,),min_support=1,enable_final_certification=False,max_cycles=4)); assert json.loads(outp.read_text().strip())['mean']==2
counts['stream_scalar']=20
assert sum(counts.values())==600
print({'pass':True,'total':sum(counts.values()),'counts':counts})
