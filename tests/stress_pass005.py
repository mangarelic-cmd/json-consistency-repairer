from __future__ import annotations
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
import json, random, tempfile
from pathlib import Path
from json_consistency_repair.streaming import StreamingConfig, discover_stream_knowledge, iter_records, repair_stream_file

rnd=random.Random(5005)
counts={}
def hit(k): counts[k]=counts.get(k,0)+1

def write_jsonl(path,rows):
    path.write_text('\n'.join(json.dumps(x,separators=(',',':')) for x in rows)+'\n',encoding='utf-8')

def read_jsonl(path):
    return [json.loads(x) for x in path.read_text(encoding='utf-8').splitlines() if x]

with tempfile.TemporaryDirectory(prefix='jcr-pass005-stress-') as td:
    td=Path(td)
    # 150 cases: correction A creates new certified relation B on next cycle.
    for t in range(150):
        rows=[]
        for i in range(10): rows.append({'code':'A','country':'US','x':i+t*100+1,'z':f'a{i}_{t}'})
        for i in range(10): rows.append({'code':'B','country':'CA','x':1000+i+t*100,'z':f'b{i}_{t}'})
        b1,b2=rnd.sample(range(10),2); rows[b1]['code']='a'; rows[b2]['code']='a'; rows[b2]['country']='XX'
        src=td/f'second-{t}.jsonl'; out=td/f'second-{t}.out.jsonl'; write_jsonl(src,rows)
        r=repair_stream_file(src,out,config=StreamingConfig(max_numeric_fields=2))
        fixed=read_jsonl(out)
        assert fixed[b1]['code']=='A' and fixed[b2]['code']=='A' and fixed[b2]['country']=='US'
        assert r.report['cycles'][0]['committed_edits']==2 and r.report['cycles'][1]['committed_edits']==1
        assert r.report['cycles'][1]['new_relations']
        assert r.report['replay']['inverse_restores_complete_input'] is True
        hit('second_pass_new_relation')

    # 150 exact arithmetic repairs with structural direction.
    for t in range(150):
        rows=[]
        for i in range(24):
            a=t*100+i+2; b=3+(i%7); rows.append({'a':a,'b':b,'total':a+b,'tag':f'T{t}_{i}'})
        bad=rnd.randrange(24); expected=rows[bad]['total']; rows[bad]['total']+=7777
        src=td/f'arith-{t}.jsonl'; out=td/f'arith-{t}.out.jsonl'; write_jsonl(src,rows)
        r=repair_stream_file(src,out,config=StreamingConfig(max_numeric_fields=3,max_relation_fields=4))
        assert read_jsonl(out)[bad]['total']==expected and r.final_status=='PASS'
        hit('arithmetic')

    # 100 top-level arrays with records split across tiny input chunks.
    for t in range(100):
        rows=[{'id':i,'payload':'x'*(9+((i+t)%31)),'nested':{'v':i+t}} for i in range(80)]
        src=td/f'arr-{t}.json'; src.write_text(json.dumps(rows,separators=(',',':')),encoding='utf-8')
        got=[e.value for e in iter_records(src,stream_format='array',chunk_bytes=17+(t%11))]
        assert got==rows
        hit('array_chunk_boundary')

    # 100 high-cardinality functional maps exceed memory budget and must not be certified by truncation.
    for t in range(100):
        rows=[]
        for i in range(40):
            for j in range(3): rows.append({'key':f'K{t}_{i}','value':f'V{t}_{i}','group':'A' if i%2==0 else 'B'})
        src=td/f'overflow-{t}.jsonl'; write_jsonl(src,rows)
        cfg=StreamingConfig(max_functional_groups=12,max_relation_fields=3,max_tracked_fields=6,max_numeric_fields=1)
        k=discover_stream_knowledge(src,cfg)
        assert k['bounded_state']['overflowed_functional_pairs']>0
        assert not any(r['kind']=='functional_stream' and r['determinant']=='/key' and r['output']=='/value' for r in k['relations'])
        hit('overflow_abstain')

    # 100 repaired streams rerun three times with zero additional semantic edits.
    for t in range(100):
        rows=[{'kind':'A' if i<15 else 'B','label':'x' if i<15 else 'y','a':i+t+1,'b':2+(i%3),'sum':i+t+3+(i%3)} for i in range(30)]
        rows[3]['label']='bad'; rows[7]['sum']+=9000
        p=td/f'idem-{t}-0.jsonl'; write_jsonl(p,rows)
        first=td/f'idem-{t}-1.jsonl'; r=repair_stream_file(p,first,config=StreamingConfig(max_relation_fields=5,max_numeric_fields=3))
        assert r.committed_edits>=2
        cur=first
        for n in range(3):
            nxt=td/f'idem-{t}-{n+2}.jsonl'; rr=repair_stream_file(cur,nxt,config=StreamingConfig(max_relation_fields=5,max_numeric_fields=3))
            assert rr.committed_edits==0 and rr.report['replay']['inverse_restores_complete_input'] is True
            cur=nxt
        hit('idempotence3')

    # 50 larger streams: retained inference state stays at configured caps as record count grows.
    for t in range(50):
        src=td/f'large-{t}.jsonl'
        with src.open('w',encoding='utf-8') as f:
            for i in range(2000):
                row={f'f{j}':i+j+t for j in range(24)}
                f.write(json.dumps(row,separators=(',',':'))+'\n')
        cfg=StreamingConfig(max_tracked_fields=7,max_relation_fields=4,max_numeric_fields=2,max_functional_groups=8)
        k=discover_stream_knowledge(src,cfg)
        assert k['records']==2000
        assert k['bounded_state']['tracked_fields']<=7 and k['bounded_state']['relation_fields']<=4
        hit('bounded_large_stream')

print(counts)
print('TOTAL',sum(counts.values()),'PASS')
