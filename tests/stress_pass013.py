from __future__ import annotations
import json, random, tempfile
from pathlib import Path

from json_consistency_repair.engine import RepairConfig, repair_object
from json_consistency_repair.bundle import repair_bundle
from json_consistency_repair.streaming import StreamingConfig, repair_stream_file

R=random.Random(130013)
checks=0

def ck(cond,msg):
    global checks
    if not cond: raise AssertionError(msg)
    checks+=1

# 100 inferred aggregate sums
for case in range(100):
    rows=[]
    for i in range(21):
        x=R.randint(1,100); y=R.randint(1,100)
        rows.append({'id':i,'items':[{'amount':x},{'amount':y}],'total':x+y})
    idx=R.randrange(21); expected=sum(x['amount'] for x in rows[idx]['items']); rows[idx]['total']=expected+R.randint(1,50)
    repaired,res=repair_object({'rows':rows},RepairConfig(max_cycles=4))
    ck(repaired['rows'][idx]['total']==expected and res.report['replay']['inverse_restores_input'],'aggregate sum')

# 100 inferred aggregate counts, constant and varying mixed
for case in range(100):
    rows=[]
    for i in range(21):
        n=2 if case<50 else 1+(i%4)
        rows.append({'id':i,'items':[{'v':j} for j in range(n)],'item_count':n})
    idx=R.randrange(21); expected=len(rows[idx]['items']); rows[idx]['item_count']=99
    repaired,res=repair_object({'rows':rows},RepairConfig(max_cycles=4))
    ck(repaired['rows'][idx]['item_count']==expected and res.committed_edits>=1,'aggregate count')

# 100 symmetric four-field balances: diagnose, do not mutate.
for case in range(100):
    rows=[]
    for i in range(21):
        a=R.randint(1,100); b=R.randint(1,100); c=R.randint(1,a+b-1); d=a+b-c
        rows.append({'a':a,'b':b,'c':c,'d':d})
    idx=R.randrange(21); rows[idx]['d']+=R.randint(1,20)
    before=json.loads(json.dumps({'rows':rows}))
    repaired,res=repair_object(before,RepairConfig(max_cycles=3))
    issues=[x for x in res.report['remaining_issues'] if x['analyzer']=='conservation' and x['code']=='scalar_conservation_violation']
    ck(repaired==before and issues and all(not x['repairable'] for x in issues),'symmetric balance abstention')

# 100 inferred multisets: exact residue, no invented target side.
for case in range(100):
    rows=[]
    for i in range(21):
        q=R.randint(1,50)
        rows.append({'before':[{'sku':'A','qty':q},{'sku':'B','qty':2}], 'after':[{'sku':'A','qty':q},{'sku':'B','qty':2}]})
    idx=R.randrange(21); rows[idx]['after'][0]['qty']+=R.randint(1,20)
    before=json.loads(json.dumps({'rows':rows}))
    repaired,res=repair_object(before,RepairConfig(max_cycles=3))
    issues=[x for x in res.report['remaining_issues'] if x['code']=='multiset_conservation_violation']
    ck(repaired==before and issues and issues[0]['metadata']['residue'],'multiset abstention')

# 50 authoritative scalar balances.
balance_rule={'kind':'balance','array_path':'/rows','terms':[{'field':'opening','coefficient':1},{'field':'received','coefficient':1},{'field':'sold','coefficient':-1},{'field':'closing','coefficient':-1}],'target':'closing'}
for case in range(50):
    rows=[]
    for i in range(8):
        opening=R.randint(20,500); rec=R.randint(1,80); sold=R.randint(1,20); rows.append({'opening':opening,'received':rec,'sold':sold,'closing':opening+rec-sold})
    idx=R.randrange(8); expected=rows[idx]['opening']+rows[idx]['received']-rows[idx]['sold']; rows[idx]['closing']=99999
    repaired,res=repair_object({'rows':rows},RepairConfig(conservation_rules=(balance_rule,),max_cycles=4))
    ck(repaired['rows'][idx]['closing']==expected and res.final_status=='PASS','authoritative balance')

# 50 authoritative multisets.
multiset_rule={'kind':'multiset_balance','array_path':'/rows','left_field':'before','right_field':'after','key_field':'sku','quantity_field':'qty','target_side':'right'}
for case in range(50):
    rows=[]
    for i in range(8):
        q=R.randint(1,50); rows.append({'before':[{'sku':'A','qty':q},{'sku':'B','qty':3}], 'after':[{'sku':'A','qty':q},{'sku':'B','qty':3}]})
    idx=R.randrange(8); expected=rows[idx]['before'][0]['qty']; rows[idx]['after'][0]['qty']=expected+11
    repaired,res=repair_object({'rows':rows},RepairConfig(conservation_rules=(multiset_rule,),max_cycles=4))
    ck(repaired['rows'][idx]['after'][0]['qty']==expected and res.report['replay']['inverse_restores_input'],'authoritative multiset')

# 50 bundle document-scoped rules.
bundle_rule={'document':'a.json','kind':'balance','array_path':'/rows','terms':[{'field':'x','coefficient':1},{'field':'y','coefficient':1},{'field':'total','coefficient':-1}],'target':'total'}
for case in range(50):
    rows=[{'x':i+1,'y':2*(i+1),'total':3*(i+1)} for i in range(8)]; rows[-1]['total']=999
    docs={'a.json':{'rows':rows},'b.json':{'rows':[{'x':i+1,'y':2*(i+1),'total':777} for i in range(8)]}}
    repaired,res=repair_bundle(docs,RepairConfig(conservation_rules=(bundle_rule,),max_cycles=4))
    ck(repaired['a.json']['rows'][-1]['total']==24 and all(r['total']==777 for r in repaired['b.json']['rows']),'bundle scope')

# 50 streaming inferred aggregate sum/count under bounded-memory execution.
with tempfile.TemporaryDirectory(prefix='pass013-stress-') as td:
    td=Path(td)
    for case in range(50):
        src=td/f'i{case}.jsonl'; out=td/f'o{case}.jsonl'
        rows=[]
        for i in range(21):
            a=R.randint(1,100); b=R.randint(1,100); rows.append({'id':i,'items':[{'amount':a},{'amount':b}],'total':a+b,'item_count':2})
        expected=sum(x['amount'] for x in rows[-1]['items']); rows[-1]['total']=99999; rows[-1]['item_count']=9
        src.write_text('\n'.join(json.dumps(x) for x in rows)+'\n',encoding='utf-8')
        res=repair_stream_file(src,out,None,StreamingConfig(max_cycles=4,stable_cycles_required=2))
        last=json.loads(out.read_text(encoding='utf-8').splitlines()[-1])
        ck(last['total']==expected and last['item_count']==2 and res.report['replay']['inverse_restores_complete_input'],'stream aggregate')

print(json.dumps({'pass':checks,'expected':600,'categories':{'aggregate_sum':100,'aggregate_count':100,'symmetric_balance':100,'multiset_abstention':100,'authoritative_balance':50,'authoritative_multiset':50,'bundle':50,'stream':50}},sort_keys=True))
