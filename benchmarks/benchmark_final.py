from __future__ import annotations

import json, random, sys, tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))

from json_consistency_repair import __version__
from json_consistency_repair.bundle import repair_bundle
from json_consistency_repair.engine import RepairConfig, repair_object
from json_consistency_repair.io import loads_strict, DuplicateKeyError
from json_consistency_repair.provenance import package_code_sha256
from json_consistency_repair.security import SecurityLimits, SecurityLimitError
from json_consistency_repair.streaming import repair_stream_file

rnd=random.Random(8008)

def cfg(**kw):
    base=dict(min_support=4,min_group_support=2,relation_confidence=.80,scoped_relation_confidence=.90,
              arithmetic_confidence=.80,temporal_confidence=.80,sequential_confidence=.75,
              required_key_confidence=.90,shape_confidence=.70,enum_confidence=.90,
              enum_normalization_confidence=.75,reference_confidence=.90,id_uniqueness_confidence=.90)
    base.update(kw); return RepairConfig(**base)

def write_jsonl(path, rows):
    path.write_text('\n'.join(json.dumps(x,ensure_ascii=False,separators=(',',':')) for x in rows)+'\n',encoding='utf-8')

def read_jsonl(path):
    return [json.loads(x) for x in path.read_text(encoding='utf-8').splitlines() if x.strip()]

s={
 'single_exact':0,'single_exact_ok':0,'single_abstain':0,'single_abstain_ok':0,
 'bundle_exact':0,'bundle_exact_ok':0,'bundle_abstain':0,'bundle_abstain_ok':0,
 'stream_second_pass':0,'stream_second_pass_ok':0,'security_refusal':0,'security_refusal_ok':0,
 'false_mutations':0,'replay_failures':0,'idempotence_failures':0,
}

# Single JSON: exact enum/reference/arithmetic repairs.
for t in range(150):
    mode=t%3
    if mode==0:
        rows=[{'id':i,'state':'READY' if i%2==0 else 'DONE'} for i in range(20)]
        j=2*rnd.randrange(10); rows[j]['state']='ready'; data={'rows':rows}; expected=('rows',j,'state','READY')
    elif mode==1:
        pref=f'S{t}_'; users=[{'id':f'{pref}{i}'} for i in range(20)]; orders=[{'id':1000+i,'user_id':f'{pref}{i}'} for i in range(20)]
        j=rnd.randrange(20); orders[j]['user_id']=orders[j]['user_id'].lower(); data={'users':users,'orders':orders}; expected=('orders',j,'user_id',f'{pref}{j}')
    else:
        rows=[]; j=rnd.randrange(10)
        for i in range(10):
            plan='A' if i<5 else 'B'; sub,tax,total=(10,2,12) if plan=='A' else (20,4,24)
            if i==j: total=999
            rows.append({'plan':plan,'subtotal':sub,'tax':tax,'total':total})
        data={'rows':rows}; expected=('rows',j,'total',12 if j<5 else 24)
    out,r=repair_object(data,cfg(arithmetic_direction_confidence=.95,relation_confidence=.75))
    s['single_exact']+=1; s['single_exact_ok']+=out[expected[0]][expected[1]][expected[2]]==expected[3]
    s['replay_failures']+=not r.report['replay']['inverse_restores_input']
    again,r2=repair_object(out,cfg(arithmetic_direction_confidence=.95,relation_confidence=.75))
    s['idempotence_failures']+=not (again==out and r2.committed_edits==0)

# Single JSON abstention: unknown enum / dangling ref / missing required value.
for t in range(150):
    mode=t%3
    if mode==0:
        rows=[{'id':i,'state':'READY' if i%2==0 else 'DONE'} for i in range(20)]; rows[rnd.randrange(20)]['state']='ALIEN'; data={'rows':rows}; code='enum_domain_outlier'
    elif mode==1:
        pref=f'D{t}_'; users=[{'id':f'{pref}{i}'} for i in range(20)]; orders=[{'id':2000+i,'user_id':f'{pref}{i}'} for i in range(20)]
        orders[rnd.randrange(20)]['user_id']='NO_SUCH_ID'; data={'users':users,'orders':orders}; code='dangling_reference'
    else:
        rows=[{'id':i,'name':f'n{i}','active':True} for i in range(20)]; del rows[rnd.randrange(20)]['name']; data={'rows':rows}; code='missing_required_key'
    out,r=repair_object(data,cfg(required_key_confidence=.95))
    ok=out==data and any(i['code']==code for i in r.report['remaining_issues'])
    s['single_abstain']+=1; s['single_abstain_ok']+=ok; s['false_mutations']+=out!=data

# Cross-document exact repair.
for t in range(100):
    pref=f'B{t}_'; users={'users':[{'id':f'{pref}{i}'} for i in range(20)]}; orders={'orders':[{'id':3000+i,'user_id':f'{pref}{i}'} for i in range(20)]}
    j=rnd.randrange(20); orders['orders'][j]['user_id']=orders['orders'][j]['user_id'].lower(); docs={'users.json':users,'orders.json':orders}
    out,r=repair_bundle(docs,cfg())
    s['bundle_exact']+=1; s['bundle_exact_ok']+=out['orders.json']['orders'][j]['user_id']==f'{pref}{j}'
    s['replay_failures']+=not r.report['replay']['inverse_restores_input']

# Cross-document ambiguity must abstain.
for t in range(50):
    ids=[{'id':f'X{t}_{i}'} for i in range(10)]; refs={'rows':[{'id':4000+i,'ref_id':f'X{t}_{i}'} for i in range(10)]}; docs={'a.json':{'a':ids},'b.json':{'b':ids},'refs.json':refs}
    out,r=repair_bundle(docs,cfg(reference_confidence=1.0))
    ok=out==docs and any(i['code']=='ambiguous_reference_target' for i in r.report['remaining_issues'])
    s['bundle_abstain']+=1; s['bundle_abstain_ok']+=ok; s['false_mutations']+=out!=docs

# Streaming: first correction reveals functional relation used in later cycle.
with tempfile.TemporaryDirectory() as td:
    td=Path(td)
    for t in range(50):
        rows=[]
        for i in range(10): rows.append({'code':'A','country':'US','x':i+1,'y':2*i+3})
        for i in range(10): rows.append({'code':'B','country':'CA','x':100+i,'y':500+i})
        rows[8]['code']='a'; rows[9]['code']='a'; rows[9]['country']='XX'
        src=td/f'{t}.jsonl'; out=td/f'{t}.out.jsonl'; write_jsonl(src,rows)
        r=repair_stream_file(src,out)
        fixed=read_jsonl(out)
        ok=(fixed[8]['code']=='A' and fixed[9]['code']=='A' and fixed[9]['country']=='US' and
            len(r.report['cycles'])>=4 and r.report['cycles'][1]['new_relations'] and r.report['replay']['inverse_restores_complete_input'])
        s['stream_second_pass']+=1; s['stream_second_pass_ok']+=ok
        again=td/f'{t}.again.jsonl'; r2=repair_stream_file(out,again)
        s['idempotence_failures']+=not (r2.committed_edits==0 and again.read_bytes()==out.read_bytes())

# Security/refusal surfaces are deterministic and non-mutating.
for t in range(100):
    mode=t%2; s['security_refusal']+=1
    try:
        if mode==0:
            loads_strict('{"x":1,"x":2}')
        else:
            loads_strict('[[[[0]]]]',SecurityLimits(max_depth=2))
    except (DuplicateKeyError, SecurityLimitError):
        s['security_refusal_ok']+=1

result={
 'benchmark':'JCR_FINAL_CANDIDATE_SYNTHETIC_V2','seed':8008,'engine_version':__version__,
 'package_code_sha256':package_code_sha256(),
 'scope':'synthetic in-distribution multi-mode closure benchmark; not an external comparative dominance benchmark',
 **s,
}
checks=[
 s['single_exact']==s['single_exact_ok'],s['single_abstain']==s['single_abstain_ok'],
 s['bundle_exact']==s['bundle_exact_ok'],s['bundle_abstain']==s['bundle_abstain_ok'],
 s['stream_second_pass']==s['stream_second_pass_ok'],s['security_refusal']==s['security_refusal_ok'],
 s['false_mutations']==0,s['replay_failures']==0,s['idempotence_failures']==0,
]
result['all_checks_pass']=all(checks)
print(json.dumps(result,sort_keys=True,indent=2))
if not result['all_checks_pass']:
    raise SystemExit(1)
