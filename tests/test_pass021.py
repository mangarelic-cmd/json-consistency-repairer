from __future__ import annotations
import json
from pathlib import Path
from json_consistency_repair.engine import RepairConfig, repair_object
from json_consistency_repair.moments import evaluate_moment_rule
from json_consistency_repair.streaming import StreamingConfig, repair_stream_file


def cfg(rule, **kw):
    return RepairConfig(moment_rules=(rule,), enable_final_certification=False, **kw)

def test_weighted_mean_exact_repair():
    doc={'rows':[{'items':[{'v':10,'w':1},{'v':20,'w':3}],'mean':0}]}
    rule={'kind':'weighted_mean','array_path':'/rows','items_field':'items','value_field':'v','weight_field':'w','target':'mean'}
    out,res=repair_object(doc,cfg(rule,min_support=1))
    assert out['rows'][0]['mean']==17.5 and res.committed_edits==1
    assert res.report['moment_distribution_summary']['weighted_mean_relations']==1

def test_weighted_sum_exact_repair():
    doc={'rows':[{'items':[{'v':2,'w':3},{'v':4,'w':5}],'weighted_total':0}]}
    rule={'kind':'weighted_sum','array_path':'/rows','items_field':'items','value_field':'v','weight_field':'w','target':'weighted_total'}
    out,_=repair_object(doc,cfg(rule,min_support=1)); assert out['rows'][0]['weighted_total']==26

def test_variance_population():
    doc={'rows':[{'items':[{'x':1},{'x':3}],'variance':0}]}
    rule={'kind':'variance','array_path':'/rows','items_field':'items','value_field':'x','target':'variance','ddof':0}
    out,_=repair_object(doc,cfg(rule,min_support=1)); assert out['rows'][0]['variance']==1

def test_covariance_population():
    doc={'rows':[{'items':[{'x':1,'y':2},{'x':3,'y':6}],'cov':0}]}
    rule={'kind':'covariance','array_path':'/rows','items_field':'items','x_field':'x','y_field':'y','target':'cov'}
    out,_=repair_object(doc,cfg(rule,min_support=1)); assert out['rows'][0]['cov']==2

def test_probability_total_repairs_summary_not_members():
    doc={'rows':[{'items':[{'p':0.1},{'p':0.2},{'p':0.7}],'p_total':9}]}
    rule={'kind':'probability_total','array_path':'/rows','items_field':'items','probability_field':'p','target':'p_total'}
    out,res=repair_object(doc,cfg(rule,min_support=1)); assert out['rows'][0]['p_total']==1.0
    assert [x['p'] for x in out['rows'][0]['items']]==[0.1,0.2,0.7]

def test_uncertainty_variance_weighted_mean():
    doc={'rows':[{'items':[{'u':1,'w':1},{'u':1,'w':1}],'uvar':0}]}
    rule={'kind':'uncertainty_variance','array_path':'/rows','items_field':'items','uncertainty_field':'u','weight_field':'w','target':'uvar','mode':'weighted_mean'}
    out,_=repair_object(doc,cfg(rule,min_support=1)); assert out['rows'][0]['uvar']==0.5

def test_unit_normalization_is_atomic_plan_and_replayable():
    doc={'rows':[{'value':250,'unit':'cm'}]}
    rule={'kind':'unit_normalize','array_path':'/rows','value_field':'value','unit_field':'unit','canonical_unit':'m','conversions':{'cm':'0.01'}}
    out,res=repair_object(doc,cfg(rule,min_support=1))
    assert out=={'rows':[{'value':2.5,'unit':'m'}]}
    assert res.committed_edits==1 and res.report['committed_edits'][0]['operation']=='plan'
    assert res.report['replay']['inverse_restores_input']

def test_nonterminating_rational_abstains():
    doc={'rows':[{'items':[{'v':1,'w':1},{'v':2,'w':1},{'v':2,'w':1}],'mean':0}]}
    rule={'kind':'weighted_mean','array_path':'/rows','items_field':'items','value_field':'v','weight_field':'w','target':'mean'}
    out,res=repair_object(doc,cfg(rule,min_support=1))
    assert out==doc and any(i['code']=='weighted_mean_violation' and not i['repairable'] for i in res.report['remaining_issues'])

def test_bundle_document_scope(tmp_path):
    from json_consistency_repair.bundle import repair_bundle
    docs={'a.json':{'rows':[{'items':[{'v':1,'w':1},{'v':3,'w':1}],'mean':0}]},'b.json':{'rows':[{'items':[{'v':10,'w':1}],'mean':0}]}}
    rule={'kind':'weighted_mean','document':'a.json','array_path':'/rows','items_field':'items','value_field':'v','weight_field':'w','target':'mean'}
    out,res=repair_bundle(docs,RepairConfig(moment_rules=(rule,),min_support=1,enable_final_certification=False))
    assert out['a.json']['rows'][0]['mean']==2 and out['b.json']['rows'][0]['mean']==0

def test_stream_scalar_moment_rule(tmp_path):
    inp=tmp_path/'x.jsonl'; out=tmp_path/'o.jsonl'
    inp.write_text(json.dumps({'items':[{'v':1,'w':1},{'v':3,'w':1}],'mean':0})+'\n',encoding='utf-8')
    rule={'kind':'weighted_mean','document':'@stream','items_field':'items','value_field':'v','weight_field':'w','target':'mean'}
    res=repair_stream_file(inp,out,config=StreamingConfig(moment_rules=(rule,),min_support=1,enable_final_certification=False))
    row=json.loads(out.read_text().strip()); assert row['mean']==2 and res.committed_edits>=1

def test_stream_unit_plan_abstains(tmp_path):
    inp=tmp_path/'x.jsonl'; out=tmp_path/'o.jsonl'
    inp.write_text(json.dumps({'value':250,'unit':'cm'})+'\n',encoding='utf-8')
    rule={'kind':'unit_normalize','document':'@stream','value_field':'value','unit_field':'unit','canonical_unit':'m','conversions':{'cm':'0.01'}}
    res=repair_stream_file(inp,out,config=StreamingConfig(moment_rules=(rule,),min_support=1,enable_final_certification=False))
    assert json.loads(out.read_text().strip())=={'value':250,'unit':'cm'}
    assert any(x.get('code')=='bounded_stream_unit_plan_requires_materialization' for c in res.report['cycles'] for x in c.get('issue_samples',[]))

def test_exact_evaluator_exposes_fraction():
    r={'items':[{'v':1,'w':1},{'v':2,'w':2}], 'm':0}
    rule={'kind':'weighted_mean','items_field':'items','value_field':'v','weight_field':'w','target':'m'}
    ev=evaluate_moment_rule(r,rule); assert str(ev['expected'])=='5/3'

def test_inferred_weighted_mean_repairs_one_outlier():
    rows=[]
    for i in range(20):
        rows.append({'items':[{'v':i+1,'w':1},{'v':i+3,'w':1}],'weighted_mean':i+2})
    rows[-1]['weighted_mean']=999
    out,res=repair_object({'rows':rows},RepairConfig(enable_final_certification=False,min_support=3,moment_min_support=3))
    assert out['rows'][-1]['weighted_mean']==21
    assert any(r.get('kind')=='weighted_mean' for r in res.report['relations'])

def test_probability_member_out_of_range_blocks_summary_repair():
    doc={'rows':[{'items':[{'p':-0.1},{'p':1.1}],'p_total':9}]}
    rule={'kind':'probability_total','array_path':'/rows','items_field':'items','probability_field':'p','target':'p_total'}
    out,res=repair_object(doc,cfg(rule,min_support=1))
    assert out==doc
    assert any(i['code']=='probability_out_of_range' for i in res.report['remaining_issues'])


def test_unit_plan_commutes_with_disjoint_moment_patch():
    doc={'rows':[{'items':[{'value':10,'weight':1},{'value':20,'weight':3}],'weighted_mean':0}], 'measurements':[{'value':250,'unit':'cm'}]}
    rules=(
      {'kind':'weighted_mean','array_path':'/rows','items_field':'items','value_field':'value','weight_field':'weight','target':'weighted_mean'},
      {'kind':'unit_normalize','array_path':'/measurements','value_field':'value','unit_field':'unit','canonical_unit':'m','conversions':{'cm':'0.01'}},
    )
    out,res=repair_object(doc,RepairConfig(moment_rules=rules,min_support=1,enable_final_certification=False))
    assert out['rows'][0]['weighted_mean']==17.5
    assert out['measurements'][0]=={'value':2.5,'unit':'m'}
    assert res.committed_edits==2 and res.report['replay']['inverse_restores_input']
