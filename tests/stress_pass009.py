from __future__ import annotations
import json, tempfile
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from json_consistency_repair.analyzers import analyze_all
from json_consistency_repair.constraint_ir import compile_typed_constraint_ir
from json_consistency_repair.engine import RepairConfig, repair_object
from json_consistency_repair.bundle import repair_bundle
from json_consistency_repair.streaming import StreamingConfig, repair_stream_file


def cfg(**kw):
    d=dict(min_support=4,min_group_support=2,relation_confidence=.80,arithmetic_confidence=.80,
           required_key_confidence=.90,enum_confidence=.85,reference_confidence=.80,id_uniqueness_confidence=.80)
    d.update(kw); return RepairConfig(**d)

counts={}
def hit(k): counts[k]=counts.get(k,0)+1

# 100 certain structural defects whose missing value is not identifiable yet.
for t in range(100):
    rows=[{'id':i,'name':f'n{t}-{i}'} for i in range(10)]; del rows[9]['name']
    a=analyze_all({'rows':rows},cfg()); ir=compile_typed_constraint_ir({'rows':rows},a)
    terms=[x for x in ir['terminal_registry'] if x['path']=='/rows/9/name']
    assert terms and all(x['satisfaction_truth']=='FALSE' for x in terms)
    assert any(x['reconstruction_truth']=='UNKNOWN' for x in terms)
    hit('false_vs_unknown')

# 100 exact repairs: terminal exists before repair and disappears from the final IR.
for t in range(100):
    rows=[]
    for i in range(12):
        k='A' if i<6 else 'B'; rows.append({'id':i,'kind':k,'label':'x' if k=='A' else 'y'})
    rows[5]['label']='bad'
    before=compile_typed_constraint_ir({'rows':rows},analyze_all({'rows':rows},cfg()))
    assert any(x['path']=='/rows/5/label' and x['reconstruction_truth']=='TRUE' for x in before['terminal_registry'])
    out,res=repair_object({'rows':rows},cfg())
    assert out['rows'][5]['label']=='x'
    assert not any(x['path']=='/rows/5/label' and x['analyzer']=='functional_relation' for x in res.report['terminal_registry'])
    hit('terminal_closure')

# 100 deterministic compilations under key-order permutations.
for t in range(100):
    rows=[{'a':i+t,'b':2,'sum':i+t+2} for i in range(8)]
    d={'meta':{'z':1,'a':2},'rows':rows}
    a=analyze_all(d,cfg()); ir1=compile_typed_constraint_ir(d,a); ir2=compile_typed_constraint_ir(d,a)
    assert ir1==ir2 and ir1['root_digest']==ir2['root_digest']
    hit('deterministic_ir')

# 100 bundle terminals retain document provenance and UNKNOWN reconstruction for dangling references.
for t in range(100):
    users={'users':[{'id':f'U{t}-{i}'} for i in range(8)]}
    orders={'orders':[{'id':100+i,'user_id':f'U{t}-{i}'} for i in range(8)]}
    orders['orders'][7]['user_id']=f'MISSING-{t}'
    _,res=repair_bundle({'users.json':users,'orders.json':orders},cfg(reference_confidence=.75))
    terms=[x for x in res.report['terminal_registry'] if x.get('document')=='orders.json' and x.get('code')=='cross_document_dangling_reference']
    assert terms and all(x['reconstruction_truth']=='UNKNOWN' for x in terms)
    hit('bundle_qualified_unknown')

# 100 streaming runs: bounded IR never claims the full terminal set materialized.
with tempfile.TemporaryDirectory() as td:
    td=Path(td)
    for t in range(100):
        rows=[{'kind':'A' if i<10 else 'B','label':'x' if i<10 else 'y'} for i in range(20)]
        rows[18].pop('label'); rows[19].pop('label')
        p=td/f'{t}.jsonl'; o=td/f'{t}.out.jsonl'
        p.write_text('\n'.join(json.dumps(x,separators=(',',':')) for x in rows)+'\n',encoding='utf-8')
        res=repair_stream_file(p,o,config=StreamingConfig(min_support=4,required_key_confidence=.80,issue_sample_limit=1))
        ir=res.report['typed_constraint_ir']
        assert ir['materialization_scope']=='BOUNDED_STREAM'
        assert ir['observed_terminal_count']>=ir['materialized_terminal_sample_count']
        if ir['unmaterialized_terminal_count']:
            assert ir['truth_summary']['UNKNOWN']>=ir['unmaterialized_terminal_count']
        hit('stream_bounded_truth')

print(counts)
print('TOTAL',sum(counts.values()),'PASS')
