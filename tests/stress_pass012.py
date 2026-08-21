from __future__ import annotations
import json, sys, tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))

from json_consistency_repair.engine import RepairConfig, repair_object
from json_consistency_repair.bundle import repair_bundle
from json_consistency_repair.streaming import StreamingConfig, repair_stream_file
from json_consistency_repair.logic_exact import rule_system_certificate, solve_cnf

counts={}
def hit(k): counts[k]=counts.get(k,0)+1

# 100 inferred multivariate implications: unique consequent repair.
for t in range(100):
    rows=[]
    for i in range(20): rows.append({'a':True,'b':True,'c':True,'seed':t})
    rows[-1]['c']=False
    for i in range(5): rows.append({'a':False,'b':True,'c':False,'seed':t})
    for i in range(5): rows.append({'a':True,'b':False,'c':False,'seed':t})
    repaired,res=repair_object({'rows':rows},RepairConfig(logic_confidence=.95,logic_min_support=4,max_cycles=4))
    assert repaired['rows'][19]['c'] is True and res.report['replay']['inverse_restores_input']
    hit('inferred_multivariate')

# 100 inferred exactly-one violations: two equal minima, no mutation.
for t in range(100):
    rows=[{'a':i%2==0,'b':i%2==1,'seed':t} for i in range(20)] + [{'a':False,'b':False,'seed':t}]
    repaired,res=repair_object({'rows':rows},RepairConfig(logic_confidence=.95,max_cycles=3))
    assert repaired['rows'][-1]['a'] is False and repaired['rows'][-1]['b'] is False
    assert res.committed_edits==0 and res.report['cycles'][0]['minimal_transfer']['status']=='AMBIGUOUS_EXACT_MINIMUM'
    hit('exactly_one_tie')

# 100 authoritative implications, exact SAT gate + unique repair.
rule={'kind':'implies','array_path':'/rows','if':{'field':'paid','equals':True},'then':{'field':'archived','equals':True}}
for t in range(100):
    rows=[{'id':i,'paid':False,'archived':False,'seed':t} for i in range(6)]
    rows[-1]['paid']=True
    repaired,res=repair_object({'rows':rows},RepairConfig(logic_rules=(rule,),max_cycles=4))
    assert repaired['rows'][-1]['archived'] is True and res.report['logic_summary']['sat_systems']==1
    hit('authoritative_implication')

# 100 contradictory rule systems, exact UNSAT certificate and zero mutation.
unsat_rules=(
 {'kind':'any_of','array_path':'/rows','items':[{'field':'a','equals':True}]},
 {'kind':'any_of','array_path':'/rows','items':[{'field':'b','equals':True}]},
 {'kind':'not_both','array_path':'/rows','items':[{'field':'a','equals':True},{'field':'b','equals':True}]},
)
for t in range(100):
    data={'rows':[{'a':False,'b':False,'seed':t} for _ in range(4)]}
    repaired,res=repair_object(data,RepairConfig(logic_rules=unsat_rules,max_cycles=2))
    assert repaired==data and res.committed_edits==0
    issue=next(i for i in res.report['remaining_issues'] if i['code']=='logical_rule_system_unsat')
    assert issue['metadata']['sat_certificate']['status']=='UNSAT' and len(issue['metadata']['unsat_core_rule_ids'])==3
    hit('unsat_abstain')

# 50 direct deterministic SAT witnesses.
for t in range(50):
    r=solve_cnf([[('a',True),('b',True)],[('a',False),('b',True)]])
    assert r.status=='SAT' and r.assignment=={'a':False,'b':True}
    hit('sat_witness')

# 50 exact one/any-of rule certificates remain SAT.
for t in range(50):
    rules=[{'kind':'one_of','items':[{'field':'a','equals':True},{'field':'b','equals':True}]},
           {'kind':'any_of','items':[{'field':'a','equals':True},{'field':'b','equals':True}]}]
    cert=rule_system_certificate(rules)
    assert cert['status']=='SAT' and cert['assignment'] is not None
    hit('oneof_anyof_sat')

# 25 bundle document-scoped rules.
for t in range(25):
    brule={'document':'orders.json','kind':'implies','array_path':'/rows','if':{'field':'paid','equals':True},'then':{'field':'archived','equals':True}}
    docs={'orders.json':{'rows':[{'id':i,'paid':False,'archived':False} for i in range(5)]},
          'other.json':{'rows':[{'id':i,'paid':True,'archived':False} for i in range(5)]}}
    docs['orders.json']['rows'][-1]['paid']=True
    repaired,res=repair_bundle(docs,RepairConfig(logic_rules=(brule,),max_cycles=4))
    assert repaired['orders.json']['rows'][-1]['archived'] is True
    assert all(not r['archived'] for r in repaired['other.json']['rows']) and res.report['replay']['inverse_restores_input']
    hit('bundle_scope')

# 25 unique streaming logic repairs + 25 ambiguous streaming exact-one abstentions.
with tempfile.TemporaryDirectory() as td:
    td=Path(td)
    for t in range(25):
        src=td/f'u{t}.jsonl'; out=td/f'uo{t}.jsonl'
        rows=[{'id':i,'a':False,'b':False} for i in range(8)]; rows[-1]['a']=True
        src.write_text('\n'.join(json.dumps(x) for x in rows)+'\n',encoding='utf-8')
        srule={'document':'@stream','kind':'implies','if':{'field':'a','equals':True},'then':{'field':'b','equals':True}}
        res=repair_stream_file(src,out,None,StreamingConfig(logic_rules=(srule,),max_cycles=4,stable_cycles_required=2))
        rr=[json.loads(x) for x in out.read_text().splitlines() if x.strip()]
        assert rr[-1]['b'] is True and res.report['replay']['inverse_restores_complete_input']
        hit('stream_unique')
    for t in range(25):
        src=td/f'a{t}.jsonl'; out=td/f'ao{t}.jsonl'
        rows=[{'id':i,'a':True,'b':False} for i in range(6)]; rows[-1]={'id':5,'a':False,'b':False}
        src.write_text('\n'.join(json.dumps(x) for x in rows)+'\n',encoding='utf-8')
        srule={'document':'@stream','kind':'exactly_one','items':[{'field':'a','equals':True},{'field':'b','equals':True}]}
        res=repair_stream_file(src,out,None,StreamingConfig(logic_rules=(srule,),max_cycles=3,stable_cycles_required=2))
        rr=[json.loads(x) for x in out.read_text().splitlines() if x.strip()]
        assert rr[-1]==rows[-1] and res.final_status=='STABLE_WITH_REPORTED_ISSUES'
        hit('stream_ambiguous')

# 25 authoritative any-of single-literal closures.
for t in range(25):
    arule={'kind':'any_of','array_path':'/rows','items':[{'field':'ready','equals':True}]}
    data={'rows':[{'id':i,'ready':True} for i in range(5)]}
    data['rows'][-1]['ready']=False
    repaired,res=repair_object(data,RepairConfig(logic_rules=(arule,),max_cycles=4))
    assert repaired['rows'][-1]['ready'] is True and res.report['replay']['inverse_restores_input']
    hit('anyof_unique')

assert sum(counts.values())==600,counts
print(counts)
print('TOTAL',sum(counts.values()),'PASS')
