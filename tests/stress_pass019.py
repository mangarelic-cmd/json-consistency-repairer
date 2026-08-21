from __future__ import annotations
import json,tempfile
from pathlib import Path
from json_consistency_repair.engine import RepairConfig,repair_object
from json_consistency_repair.models import AnalysisResult,Candidate,Issue
from json_consistency_repair.causal_cone import apply_authority_firewall,causal_dominance
from json_consistency_repair.bundle import repair_bundle
from json_consistency_repair.streaming import StreamingConfig,repair_stream_file
counts={}
def cascade(seed=0):
    rows=[{'a':a+seed,'one':1,'b':a+seed+1,'c':a+seed+2} for a in range(1,7)]; rows[-1]['b']=9000+seed; return {'rows':rows}
for n in range(120):
    out,res=repair_object(cascade(n),RepairConfig(min_support=4,arithmetic_confidence=.8,enable_final_certification=False)); assert out['rows'][-1]['b']==n+7 and res.report['causal_root_analysis']['cycles'][0]['root_cause_dominance']['dominated_candidate_ids']
counts['root_cause_cascade']=120
for n in range(80):
    dsl=({'kind':'const','array_path':'/rows','field':'flag','value':False,'rule_id':'dsl_false'},); logic=({'kind':'implies','array_path':'/rows','if':{'field':'trigger','equals':True},'then':{'field':'flag','equals':True}},); obj={'rows':[{'trigger':False,'flag':False} for _ in range(4)]}; obj['rows'][-1]={'trigger':True,'flag':None}; out,res=repair_object(obj,RepairConfig(constraint_rules=dsl,logic_rules=logic,enable_final_certification=False,max_cycles=3)); assert out==obj and any(i['code']=='authority_conflict' for i in res.report['remaining_issues'])
counts['authority_conflict']=80
for n in range(80):
    low=Candidate(f'low{n}','exact_arithmetic','replace','/x',0,n+1,'low',1,1,(),{'relation_kind':'exact_arithmetic'}); high=Candidate(f'high{n}','schema_bridge','replace','/x',0,999,'high',1,1,(),{'schema_keyword':'const'}); out,cert=apply_authority_firewall(AnalysisResult([], [low,high], [])); assert [c.candidate_id for c in out.candidates]==[f'high{n}']
counts['lower_authority_block']=80
for n in range(80):
    _,r1=repair_object(cascade(n),RepairConfig(min_support=4,arithmetic_confidence=.8,enable_final_certification=False)); _,r2=repair_object(cascade(n),RepairConfig(min_support=4,arithmetic_confidence=.8,enable_final_certification=False)); assert json.dumps(r1.report['causal_root_analysis']['cycles'][0]['double_cone'],sort_keys=True)==json.dumps(r2.report['causal_root_analysis']['cycles'][0]['double_cone'],sort_keys=True)
counts['deterministic_double_cone']=80
for n in range(60):
    out,res=repair_bundle({'a.json':cascade(n),'b.json':{'rows':[{'id':i} for i in range(6)]}},RepairConfig(min_support=4,arithmetic_confidence=.8,enable_final_certification=False,max_cycles=5)); assert out['a.json']['rows'][-1]['b']==n+7
counts['bundle_double_cone']=60
with tempfile.TemporaryDirectory() as td:
    td=Path(td)
    for n in range(60):
        src=td/f'{n}.jsonl'; out=td/f'{n}.out'; rows=[{'a':i+n,'one':1,'b':i+n+1} for i in range(1,9)]; rows[-1]['b']=9999; src.write_text('\n'.join(json.dumps(x) for x in rows)+'\n'); res=repair_stream_file(src,out,None,StreamingConfig(min_support=4,arithmetic_confidence=.8,enable_final_certification=False),stream_format='jsonl'); assert res.report['causal_root_analysis']['double_cone']['mode']=='BOUNDED_STREAM'
counts['stream_double_cone']=60
for n in range(60):
    out,res=repair_object(cascade(n),RepairConfig(min_support=4,arithmetic_confidence=.8,enable_final_certification=True)); assert out['rows'][-1]['b']==n+7 and res.report['final_certification']['ok']
counts['certified_root_cause']=60
for n in range(60):
    root={'left':0,'right':0}; c1=Candidate('c1','unit','replace','/left',0,1,'left'); c2=Candidate('c2','unit','replace','/right',0,1,'right')
    def analyze(v):
        issues=[]
        if v['left']==0: issues.append(Issue('unit','left','/left','left','warning',True,{}))
        if v['right']==0: issues.append(Issue('unit','right','/right','right','warning',True,{}))
        return AnalysisResult(issues,[c1,c2],[])
    out,cert=causal_dominance(root,analyze(root),analyze); assert not cert['dominated_candidate_ids']
counts['independent_non_dominance']=60
assert sum(counts.values())==600
print(json.dumps({'pass':600,'total':600,'categories':counts,'all_checks_pass':True},sort_keys=True))
