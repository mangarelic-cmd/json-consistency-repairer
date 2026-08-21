from __future__ import annotations
from json_consistency_repair import repair_object, RepairConfig


def test_modal_regime_prevents_shape_false_positive():
    rows=[]
    for i in range(8): rows.append({'type':'sale','id':i,'amount':10+i,'tax':2+i})
    for i in range(4): rows.append({'type':'refund','id':100+i,'amount':10+i,'reason':'x'})
    original={'rows':rows}
    repaired,res=repair_object(original,RepairConfig(enable_final_certification=False,max_cycles=4))
    assert repaired==original
    rels=[r for r in res.report['relations'] if r.get('kind')=='modal_regime']
    assert {r.get('regime_value') for r in rels}=={'sale','refund'}
    assert not any(i['code']=='missing_required_key' for i in res.report['remaining_issues'])


def test_modal_regime_allows_different_arithmetic_laws():
    rows=[]
    for i in range(8): rows.append({'type':'sale','a':i+2,'b':i+3,'total':2*i+5})
    for i in range(8): rows.append({'type':'refund','a':i+2,'b':i+3,'total':-1})
    # Refund law is a-b=-1; sale law is a+b.
    repaired,res=repair_object({'rows':rows},RepairConfig(enable_final_certification=False,max_cycles=4))
    assert repaired=={'rows':rows}
    arithmetic=[r for r in res.report['relations'] if r.get('modalized') and str(r.get('kind',''))=='exact_arithmetic']
    assert arithmetic


def test_schema_version_emits_schema_evolution():
    rows=[]
    for i in range(5): rows.append({'schema_version':'1','id':i,'name':'n'})
    for i in range(5): rows.append({'schema_version':'2','id':10+i,'name':'n','active':True})
    _,res=repair_object({'rows':rows},RepairConfig(enable_final_certification=False,max_cycles=4))
    assert any(r.get('kind')=='schema_evolution' for r in res.report['relations'])


def test_status_outlier_is_not_hidden_as_regime():
    rows=[{'id':i,'status':'OPEN'} for i in range(20)]
    rows[-1]['status']='open'
    repaired,res=repair_object({'rows':rows},RepairConfig(enable_final_certification=False,max_cycles=4))
    assert repaired['rows'][-1]['status']=='OPEN'
    assert not any(r.get('kind')=='modal_regime' and r.get('regime_field')=='status' for r in res.report['relations'])


def test_recursive_morphology_diagnoses_missing_structure_without_invention():
    tree={'children':[{'name':str(i),'kind':'leaf'} for i in range(20)]}; tree['children'][-1].pop('kind')
    repaired,res=repair_object(tree,RepairConfig(enable_final_certification=False,max_cycles=4))
    assert repaired==tree
    assert any(i['code']=='recursive_morphology_missing_key' and not i['repairable'] for i in res.report['remaining_issues'])
