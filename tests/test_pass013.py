from __future__ import annotations

import json
from pathlib import Path
import tomllib

from json_consistency_repair import __version__
from json_consistency_repair.engine import RepairConfig, repair_object
from json_consistency_repair.bundle import repair_bundle
from json_consistency_repair.streaming import StreamingConfig, discover_stream_knowledge, repair_stream_file
from json_consistency_repair.cli import main


def _orders(n=21):
    rows=[]
    for i in range(n):
        items=[{'sku':'A','amount':i+1},{'sku':'B','amount':2*(i+1)}]
        rows.append({'id':i,'items':items,'total':3*(i+1),'item_count':2})
    return rows


def test_inferred_local_to_aggregate_sum_repairs_parent_total():
    rows=_orders(); rows[-1]['total']=999
    repaired,res=repair_object({'orders':rows},RepairConfig(max_cycles=4))
    assert repaired['orders'][-1]['total']==63
    assert any(r['kind']=='aggregate_sum' for r in res.report['relations'])
    assert res.report['replay']['inverse_restores_input'] is True


def test_inferred_constant_child_count_repairs_named_count_field():
    rows=_orders(); rows[-1]['item_count']=9
    repaired,res=repair_object({'orders':rows},RepairConfig(max_cycles=4))
    assert repaired['orders'][-1]['item_count']==2
    assert any(r['kind']=='aggregate_count' for r in res.report['relations'])


def test_unoriented_aggregate_abstains_without_direction_witness():
    rows=[]
    for i in range(21):
        parts=[{'v':i+1},{'v':2*(i+1)}]
        rows.append({'x':3*(i+1),'parts':parts})  # target precedes source; x is not an aggregate name
    rows[-1]['x']=999
    repaired,res=repair_object({'rows':rows},RepairConfig(max_cycles=3))
    assert repaired['rows'][-1]['x']==999
    rel=next(r for r in res.report['relations'] if r['kind']=='aggregate_sum' and r['output']=='x')
    assert rel['direction_certified'] is False
    assert res.committed_edits==0


def test_inferred_scalar_balance_diagnoses_but_does_not_pick_a_side():
    rows=[]
    for i in range(21):
        rows.append({'a':i+1,'b':2*i+3,'c':i,'d':2*i+4})
    rows[-1]['d']=999
    repaired,res=repair_object({'rows':rows},RepairConfig(max_cycles=3))
    assert repaired=={'rows':rows}
    issue=next(i for i in res.report['remaining_issues'] if i['code']=='scalar_conservation_violation')
    assert issue['repairable'] is False
    assert issue['metadata']['direction_source']=='symmetric_conservation'


def test_authoritative_balance_repairs_declared_target():
    rows=[]
    for i in range(6):
        opening=100+i*10; received=20; sold=15
        rows.append({'opening':opening,'received':received,'sold':sold,'closing':opening+received-sold})
    rows[-1]['closing']=999
    rule={'kind':'balance','array_path':'/rows','terms':[{'field':'opening','coefficient':1},{'field':'received','coefficient':1},{'field':'sold','coefficient':-1},{'field':'closing','coefficient':-1}],'target':'closing'}
    repaired,res=repair_object({'rows':rows},RepairConfig(conservation_rules=(rule,),max_cycles=4))
    assert repaired['rows'][-1]['closing']==155
    assert res.final_status=='PASS'
    assert any(r['kind']=='balance_authoritative' for r in res.report['relations'])


def test_inferred_multiset_conservation_emits_exact_residue_and_abstains():
    rows=[]
    for i in range(21):
        rows.append({'before':[{'sku':'A','qty':i+1},{'sku':'B','qty':2}], 'after':[{'sku':'A','qty':i+1},{'sku':'B','qty':2}]})
    rows[-1]['after'][0]['qty']=999
    repaired,res=repair_object({'rows':rows},RepairConfig(max_cycles=3))
    assert repaired=={'rows':rows}
    issue=next(i for i in res.report['remaining_issues'] if i['code']=='multiset_conservation_violation')
    assert issue['repairable'] is False
    assert issue['metadata']['residue']
    rels=[r for r in res.report['relations'] if r['kind']=='multiset_conservation']
    assert len(rels)==1 and rels[0]['key_field']=='sku' and rels[0]['quantity_field']=='qty'


def test_authoritative_multiset_target_side_repairs_single_quantity():
    rows=[]
    for i in range(6):
        rows.append({'before':[{'sku':'A','qty':i+1},{'sku':'B','qty':2}], 'after':[{'sku':'A','qty':i+1},{'sku':'B','qty':2}]})
    rows[-1]['after'][0]['qty']=99
    rule={'kind':'multiset_balance','array_path':'/rows','left_field':'before','right_field':'after','key_field':'sku','quantity_field':'qty','target_side':'right'}
    repaired,res=repair_object({'rows':rows},RepairConfig(conservation_rules=(rule,),max_cycles=4))
    assert repaired['rows'][-1]['after'][0]['qty']==6
    assert res.report['replay']['inverse_restores_input'] is True
    assert any(r['kind']=='multiset_balance_authoritative' for r in res.report['relations'])


def test_authoritative_scope_missing_is_hard_nonrepairable_error():
    data={'rows':[{'a':1} for _ in range(4)]}
    rule={'kind':'balance','array_path':'/missing','terms':[{'field':'a','coefficient':1}],'target':'a'}
    repaired,res=repair_object(data,RepairConfig(conservation_rules=(rule,),max_cycles=3))
    assert repaired==data
    issue=next(i for i in res.report['remaining_issues'] if i['code']=='conservation_rule_scope_missing')
    assert issue['severity']=='error' and issue['repairable'] is False


def test_bundle_document_scoping_for_conservation_rules():
    rule={'document':'orders.json','kind':'balance','array_path':'/rows','terms':[{'field':'a','coefficient':1},{'field':'b','coefficient':1},{'field':'total','coefficient':-1}],'target':'total'}
    docs={
        'orders.json':{'rows':[{'a':i,'b':2*i,'total':3*i} for i in range(1,7)]},
        'other.json':{'rows':[{'a':i,'b':2*i,'total':999} for i in range(1,7)]},
    }
    docs['orders.json']['rows'][-1]['total']=999
    repaired,res=repair_bundle(docs,RepairConfig(conservation_rules=(rule,),max_cycles=4))
    assert repaired['orders.json']['rows'][-1]['total']==18
    assert all(x['total']==999 for x in repaired['other.json']['rows'])
    assert res.report['replay']['inverse_restores_input'] is True


def test_stream_infers_aggregate_sum_and_count(tmp_path):
    src=tmp_path/'x.jsonl'; out=tmp_path/'o.jsonl'
    rows=_orders(); rows[-1]['total']=999; rows[-1]['item_count']=9
    src.write_text('\n'.join(json.dumps(x) for x in rows)+'\n',encoding='utf-8')
    cfg=StreamingConfig(max_cycles=5,stable_cycles_required=2)
    knowledge=discover_stream_knowledge(src,cfg)
    kinds={r['kind'] for r in knowledge['relations']}
    assert {'aggregate_sum_stream','aggregate_count_stream'} <= kinds
    result=repair_stream_file(src,out,None,cfg)
    repaired=[json.loads(x) for x in out.read_text(encoding='utf-8').splitlines() if x.strip()]
    assert repaired[-1]['total']==63 and repaired[-1]['item_count']==2
    assert result.report['replay']['inverse_restores_complete_input'] is True


def test_stream_authoritative_balance_rule(tmp_path):
    src=tmp_path/'x.jsonl'; out=tmp_path/'o.jsonl'
    rows=[{'a':i,'b':2*i,'total':3*i} for i in range(1,9)]; rows[-1]['total']=999
    src.write_text('\n'.join(json.dumps(x) for x in rows)+'\n',encoding='utf-8')
    rule={'document':'@stream','kind':'balance','terms':[{'field':'a','coefficient':1},{'field':'b','coefficient':1},{'field':'total','coefficient':-1}],'target':'total'}
    result=repair_stream_file(src,out,None,StreamingConfig(conservation_rules=(rule,),max_cycles=4,stable_cycles_required=2))
    repaired=[json.loads(x) for x in out.read_text(encoding='utf-8').splitlines() if x.strip()]
    assert repaired[-1]['total']==24
    assert result.report['conservation_summary']['rule_count']==1


def test_cli_conservation_rules_file(tmp_path,capsys):
    src=tmp_path/'x.json'; out=tmp_path/'o.json'; rules=tmp_path/'rules.json'
    rows=[{'a':i,'b':2*i,'total':3*i} for i in range(1,7)]; rows[-1]['total']=999
    src.write_text(json.dumps({'rows':rows}),encoding='utf-8')
    rules.write_text(json.dumps({'rules':[{'kind':'balance','array_path':'/rows','terms':[{'field':'a','coefficient':1},{'field':'b','coefficient':1},{'field':'total','coefficient':-1}],'target':'total'}]}),encoding='utf-8')
    rc=main(['--machine','--conservation-rules',str(rules),str(src),'-o',str(out)])
    obj=json.loads(capsys.readouterr().out)
    assert rc==0 and obj['status']=='PASS'
    assert json.loads(out.read_text(encoding='utf-8'))['rows'][-1]['total']==18


def test_constraint_ir_contains_conservation_terminal_and_relation():
    rows=[]
    for i in range(21): rows.append({'a':i+1,'b':2*i+3,'c':i,'d':2*i+4})
    rows[-1]['d']=999
    _,res=repair_object({'rows':rows},RepairConfig(max_cycles=3))
    ir=res.report['typed_constraint_ir']
    assert any(c['kind']=='scalar_conservation_balance' for c in ir['constraints'])
    assert any(t['analyzer']=='conservation' and t['code']=='scalar_conservation_violation' for t in ir['terminal_registry'])


def test_pass013_version_reconciled():
    root=Path(__file__).resolve().parents[1]
    project=tomllib.loads((root/'pyproject.toml').read_text(encoding='utf-8'))
    assert __version__==project['project']['version']
    assert f'version: "{__version__}"' in (root/'CITATION.cff').read_text(encoding='utf-8')
    assert __version__ in (root/'GUIDE_LLM.md').read_text(encoding='utf-8')
