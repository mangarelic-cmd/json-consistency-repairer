from __future__ import annotations

import json
from pathlib import Path
import tomllib

from json_consistency_repair import __version__
from json_consistency_repair.cli import main
from json_consistency_repair.engine import RepairConfig, repair_object
from json_consistency_repair.bundle import repair_bundle
from json_consistency_repair.streaming import StreamingConfig, discover_stream_knowledge, repair_stream_file
from json_consistency_repair.logic_exact import evaluate_rule, rule_system_certificate, solve_cnf


def test_exact_sat_solver_returns_deterministic_witness():
    # (a or b) and (not a or b) is SAT; False is branched first, so a=False,b=True.
    r=solve_cnf([[('a',True),('b',True)],[('a',False),('b',True)]])
    assert r.status=='SAT'
    assert r.assignment=={'a':False,'b':True}
    assert r.explored_nodes>=1


def test_authoritative_rule_system_unsat_has_irreducible_core():
    rules=[
        {'kind':'any_of','items':[{'field':'a','equals':True}]},
        {'kind':'any_of','items':[{'field':'b','equals':True}]},
        {'kind':'not_both','items':[{'field':'a','equals':True},{'field':'b','equals':True}]},
    ]
    cert=rule_system_certificate(rules)
    assert cert['status']=='UNSAT'
    assert cert['assignment'] is None
    assert cert['unsat_core_kind']=='DELETION_IRREDUCIBLE_RULE_CORE'
    assert len(cert['unsat_core_rule_ids'])==3


def test_inferred_multivariate_implication_repairs_unique_consequent():
    rows=[]
    for i in range(20): rows.append({'a':True,'b':True,'c':True})
    rows[-1]['c']=False
    for i in range(5): rows.append({'a':False,'b':True,'c':False})
    for i in range(5): rows.append({'a':True,'b':False,'c':False})
    repaired,res=repair_object({'rows':rows},RepairConfig(logic_confidence=.95,logic_min_support=4,max_cycles=4))
    assert repaired['rows'][19]['c'] is True
    assert res.committed_edits>=1
    rels=[x for x in res.report['relations'] if x.get('kind')=='logic_exact' and x.get('logic_kind')=='implies']
    assert rels and all(x['sat_status']=='SAT' for x in rels)


def test_inferred_exactly_one_equal_minima_abstains():
    rows=[{'a':i%2==0,'b':i%2==1} for i in range(20)] + [{'a':False,'b':False}]
    repaired,res=repair_object({'rows':rows},RepairConfig(logic_confidence=.95,max_cycles=3))
    assert repaired['rows'][-1]=={'a':False,'b':False}
    assert res.committed_edits==0
    assert res.report['cycles'][0]['minimal_transfer']['status']=='AMBIGUOUS_EXACT_MINIMUM'
    assert any(i['analyzer']=='logic_exact' for i in res.report['remaining_issues'])


def test_authoritative_implication_is_sat_but_current_row_can_be_false():
    rule={'kind':'implies','array_path':'/rows','if':{'field':'paid','equals':True},'then':{'field':'archived','equals':True}}
    data={'rows':[{'id':i,'paid':False,'archived':False} for i in range(5)]}
    data['rows'][4]={'id':4,'paid':True,'archived':False}
    repaired,res=repair_object(data,RepairConfig(logic_rules=(rule,),max_cycles=4))
    assert repaired['rows'][4]['archived'] is True
    assert res.report['logic_summary']['sat_systems']==1
    # SAT certifies consistency of the rule system, not truth of the pre-repair record.
    first_logic=[r for r in res.report['cycles'][0]['minimal_transfer']['clusters'] if r['scope']=='/rows/4']
    assert first_logic


def test_authoritative_unsat_blocks_data_mutation():
    rules=(
        {'kind':'any_of','array_path':'/rows','items':[{'field':'a','equals':True}]},
        {'kind':'any_of','array_path':'/rows','items':[{'field':'b','equals':True}]},
        {'kind':'not_both','array_path':'/rows','items':[{'field':'a','equals':True},{'field':'b','equals':True}]},
    )
    data={'rows':[{'a':False,'b':False} for _ in range(4)]}
    repaired,res=repair_object(data,RepairConfig(logic_rules=rules,max_cycles=3))
    assert repaired==data
    assert res.committed_edits==0
    issue=next(i for i in res.report['remaining_issues'] if i['code']=='logical_rule_system_unsat')
    assert issue['severity']=='error'
    assert issue['metadata']['sat_certificate']['status']=='UNSAT'


def test_one_of_any_of_xor_and_not_both_semantics():
    row={'a':True,'b':False,'c':False}
    assert evaluate_rule(row,{'kind':'one_of','items':[{'field':'a','equals':True},{'field':'b','equals':True}]}) is True
    assert evaluate_rule(row,{'kind':'any_of','items':[{'field':'a','equals':True},{'field':'b','equals':True}]}) is True
    assert evaluate_rule(row,{'kind':'xor','items':[{'field':'a','equals':True},{'field':'b','equals':True}]}) is True
    assert evaluate_rule(row,{'kind':'not_both','items':[{'field':'a','equals':True},{'field':'b','equals':True}]}) is True
    row['b']=True
    assert evaluate_rule(row,{'kind':'one_of','items':[{'field':'a','equals':True},{'field':'b','equals':True}]}) is False
    assert evaluate_rule(row,{'kind':'not_both','items':[{'field':'a','equals':True},{'field':'b','equals':True}]}) is False


def test_bundle_document_scoping_of_authoritative_logic():
    rules=({'document':'orders.json','kind':'implies','array_path':'/rows','if':{'field':'paid','equals':True},'then':{'field':'archived','equals':True}},)
    docs={
        'orders.json':{'rows':[{'id':i,'paid':False,'archived':False} for i in range(5)]},
        'other.json':{'rows':[{'id':i,'paid':True,'archived':False} for i in range(5)]},
    }
    docs['orders.json']['rows'][4]['paid']=True
    repaired,res=repair_bundle(docs,RepairConfig(logic_rules=rules,max_cycles=4))
    assert repaired['orders.json']['rows'][4]['archived'] is True
    assert all(r['archived'] is False for r in repaired['other.json']['rows'])
    assert res.report['replay']['inverse_restores_input'] is True


def test_stream_authoritative_implication_and_sat_certificate(tmp_path):
    src=tmp_path/'x.jsonl'; out=tmp_path/'o.jsonl'; rep=tmp_path/'r.json'
    rows=[{'id':i,'a':False,'b':False} for i in range(8)]
    rows[7]={'id':7,'a':True,'b':False}
    src.write_text('\n'.join(json.dumps(x) for x in rows)+'\n',encoding='utf-8')
    rule={'document':'@stream','kind':'implies','if':{'field':'a','equals':True},'then':{'field':'b','equals':True}}
    cfg=StreamingConfig(logic_rules=(rule,),max_cycles=4,stable_cycles_required=2)
    result=repair_stream_file(src,out,rep,cfg)
    repaired=[json.loads(x) for x in out.read_text(encoding='utf-8').splitlines() if x.strip()]
    assert repaired[7]['b'] is True
    assert result.report['replay']['inverse_restores_complete_input'] is True
    k=discover_stream_knowledge(src,cfg)
    assert k['logic_system_certificate']['status']=='SAT'


def test_stream_ambiguous_exactly_one_does_not_apply_both_alternatives(tmp_path):
    src=tmp_path/'x.jsonl'; out=tmp_path/'o.jsonl'
    rows=[{'id':i,'a':True,'b':False} for i in range(6)]
    rows[-1]={'id':5,'a':False,'b':False}
    src.write_text('\n'.join(json.dumps(x) for x in rows)+'\n',encoding='utf-8')
    rule={'document':'@stream','kind':'exactly_one','items':[{'field':'a','equals':True},{'field':'b','equals':True}]}
    result=repair_stream_file(src,out,None,StreamingConfig(logic_rules=(rule,),max_cycles=3,stable_cycles_required=2))
    repaired=[json.loads(x) for x in out.read_text(encoding='utf-8').splitlines() if x.strip()]
    assert repaired[-1]==rows[-1]
    assert result.final_status=='STABLE_WITH_REPORTED_ISSUES'


def test_cli_logic_rules_file(tmp_path,capsys):
    src=tmp_path/'x.json'; out=tmp_path/'o.json'; rules=tmp_path/'rules.json'
    rows=[{'id':i,'paid':False,'archived':False} for i in range(5)]
    rows[4]['paid']=True
    src.write_text(json.dumps({'rows':rows}),encoding='utf-8')
    rules.write_text(json.dumps({'rules':[{'kind':'implies','array_path':'/rows','if':{'field':'paid','equals':True},'then':{'field':'archived','equals':True}}]}),encoding='utf-8')
    rc=main(['--machine','--logic-rules',str(rules),str(src),'-o',str(out)])
    obj=json.loads(capsys.readouterr().out)
    assert rc==0 and obj['status']=='PASS'
    assert json.loads(out.read_text(encoding='utf-8'))['rows'][4]['archived'] is True


def test_pass012_version_reconciled():
    root=Path(__file__).resolve().parents[1]
    project=tomllib.loads((root/'pyproject.toml').read_text(encoding='utf-8'))
    assert __version__==project['project']['version']
