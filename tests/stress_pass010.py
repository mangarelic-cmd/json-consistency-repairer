from __future__ import annotations
import json, tempfile
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from json_consistency_repair.analyzers import analyze_all
from json_consistency_repair.constraint_ir import compile_typed_constraint_ir
from json_consistency_repair.engine import RepairConfig
from json_consistency_repair.bundle import repair_bundle
from json_consistency_repair.streaming import StreamingConfig, repair_stream_file


def cfg(**kw):
    d=dict(min_support=4,min_group_support=2,relation_confidence=.75,arithmetic_confidence=.75,
           arithmetic_direction_confidence=.90,required_key_confidence=.85,enum_confidence=.80,
           enum_min_value_support=2,enum_normalization_confidence=.75,reference_confidence=.75,id_uniqueness_confidence=.75)
    d.update(kw); return RepairConfig(**d)

counts={}
def hit(k): counts[k]=counts.get(k,0)+1

def ent(ir,path):
    xs=[x for x in ir['identifiability_registry'] if x['path']==path]
    assert xs
    return xs[0]

# 100 UNIQUE finite-domain reconstructions.
for t in range(100):
    rows=[{'id':i,'status':'ready'} for i in range(10)] + [{'id':10,'status':f'unknown-{t}'}]
    data={'rows':rows}; ir=compile_typed_constraint_ir(data,analyze_all(data,cfg()))
    e=ent(ir,'/rows/10/status')
    assert e['identifiability']=='UNIQUE' and e['solution_count']==1 and e['minimal_missing_witness'] is None
    hit('unique')

# 100 MULTIPLE finite domains.
for t in range(100):
    rows=[{'id':i,'status':'ready' if i%2==0 else 'done'} for i in range(12)]
    rows.append({'id':12,'status':f'unknown-{t}'})
    data={'rows':rows}; ir=compile_typed_constraint_ir(data,analyze_all(data,cfg()))
    e=ent(ir,'/rows/12/status')
    assert e['identifiability']=='MULTIPLE' and e['solution_count']==2
    assert e['minimal_missing_witness']['cardinality']==1
    hit('multiple')

# 100 NONE: two independently certified finite singleton laws with empty intersection.
for t in range(100):
    rows=[]
    for i in range(6): rows.append({'d1':'A','d2':'X','label':'x'})
    for i in range(6): rows.append({'d1':'B','d2':'Y','label':'y'})
    rows.append({'d1':'A','d2':'Y','label':f'bad-{t}'})
    data={'rows':rows}; ir=compile_typed_constraint_ir(data,analyze_all(data,cfg()))
    e=ent(ir,'/rows/12/label')
    assert e['identifiability']=='NONE' and e['solution_count']==0
    assert e['minimal_missing_witness']['kind']=='CONSTRAINT_REVISION_OR_SOURCE_CORRECTION'
    hit('none')

# 100 INSUFFICIENT free required values.
for t in range(100):
    rows=[{'id':i,'name':f'{t}-{i}'} for i in range(10)]; del rows[9]['name']
    data={'rows':rows}; ir=compile_typed_constraint_ir(data,analyze_all(data,cfg()))
    e=ent(ir,'/rows/9/name')
    assert e['identifiability']=='INSUFFICIENT' and e['solution_count'] is None
    assert e['minimal_missing_witness']['kind']=='AUTHORITATIVE_VALUE_OR_DEFAULT'
    hit('insufficient')

# 100 algebraic value candidates whose mutation direction is not identified.
for t in range(100):
    rows=[{'total':i+2+t,'a':i+t,'b':2} for i in range(12)]
    rows[11]['total']=999999+t
    data={'rows':rows}; ir=compile_typed_constraint_ir(data,analyze_all(data,cfg()))
    e=ent(ir,'/rows/11/total')
    assert e['identifiability']=='INSUFFICIENT' and e['direction_blocked_candidate_ids']
    assert e['minimal_missing_witness']['kind']=='INDEPENDENT_DIRECTION_ANCHOR'
    hit('direction_blocked')

# 50 cross-document finite multiple target domains.
for t in range(50):
    users={'users':[{'id':f'U{t}-{i}'} for i in range(8)]}
    orders={'orders':[{'id':100+i,'user_id':f'U{t}-{i}'} for i in range(8)]}
    orders['orders'][7]['user_id']=f'MISSING-{t}'
    _,res=repair_bundle({'users.json':users,'orders.json':orders},cfg())
    xs=[x for x in res.report['cross_document_identifiability_registry'] if x['document']=='orders.json' and x['path']=='/orders/7/user_id']
    assert xs and xs[0]['identifiability']=='MULTIPLE' and xs[0]['solution_count']==8
    hit('bundle_multiple')

# 50 bounded stream insufficient witnesses.
with tempfile.TemporaryDirectory() as td:
    td=Path(td)
    for t in range(50):
        rows=[{'kind':'A','name':'x'} for _ in range(12)]; rows[-1].pop('name')
        p=td/f'{t}.jsonl'; o=td/f'{t}.out.jsonl'
        p.write_text('\n'.join(json.dumps(x,separators=(',',':')) for x in rows)+'\n',encoding='utf-8')
        res=repair_stream_file(p,o,config=StreamingConfig(min_support=4,required_key_confidence=.80,issue_sample_limit=4))
        bad=[x for x in res.report['identifiability_registry'] if x['identifiability']=='INSUFFICIENT']
        assert bad and bad[0]['observability']=='BOUNDED_UNMATERIALIZED'
        hit('stream_insufficient')

assert sum(counts.values())==600
print(counts)
print('TOTAL',sum(counts.values()),'PASS')
