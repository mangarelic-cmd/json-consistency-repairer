from __future__ import annotations
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
import json, random, tempfile
from pathlib import Path

from json_consistency_repair import RepairConfig, StreamingConfig, SecurityLimits, SecurityLimitError
from json_consistency_repair.engine import repair_file
from json_consistency_repair.io import DuplicateKeyError, loads_strict
from json_consistency_repair.streaming import StreamingParseError, discover_stream_knowledge, iter_records, repair_stream_file
from json_consistency_repair.bundle import repair_bundle_dir

rnd=random.Random(6006)
counts={}
def hit(k): counts[k]=counts.get(k,0)+1

def lim(**kw):
    b=SecurityLimits(); return SecurityLimits(**{**b.__dict__,**kw})

def expect_code(fn, code):
    try: fn()
    except SecurityLimitError as e:
        assert e.code==code, (e.code,code); return
    raise AssertionError(f'expected {code}')

with tempfile.TemporaryDirectory(prefix='jcr-pass006-stress-') as td:
    td=Path(td)
    # 150 duplicate-key attacks distributed over all three parser surfaces.
    for t in range(50):
        raw='{"id":%d,"x":1,"x":2}'%t
        try: loads_strict(raw); raise AssertionError('duplicate accepted')
        except DuplicateKeyError: pass
        hit('duplicate_single')
        p=td/f'dup-{t}.jsonl'; p.write_text(raw+'\n',encoding='utf-8')
        try: discover_stream_knowledge(p); raise AssertionError('stream duplicate accepted')
        except StreamingParseError: pass
        hit('duplicate_jsonl')
        p=td/f'dup-{t}.json'; p.write_text('['+raw+']',encoding='utf-8')
        try: list(iter_records(p,stream_format='array',chunk_bytes=7)); raise AssertionError('array duplicate accepted')
        except StreamingParseError: pass
        hit('duplicate_array')

    # 100 non-finite / exponent-overflow attacks across single and streaming.
    badnums=['NaN','Infinity','-Infinity','1e999999']
    for t in range(100):
        token=badnums[t%len(badnums)]; raw='{"x":'+token+'}'
        try: loads_strict(raw); raise AssertionError('non-finite accepted')
        except ValueError: pass
        p=td/f'num-{t}.jsonl'; p.write_text(raw+'\n',encoding='utf-8')
        try: discover_stream_knowledge(p); raise AssertionError('non-finite stream accepted')
        except StreamingParseError: pass
        hit('nonfinite')

    # 100 depth attacks: deterministic boundary at configured limit+1.
    for t in range(100):
        limit=4+(t%20); depth=limit+1+rnd.randrange(8)
        raw='['*depth+'0'+']'*depth
        try: loads_strict(raw,lim(max_depth=limit)); raise AssertionError('deep accepted')
        except SecurityLimitError as e: assert e.code=='max_depth' and e.observed==limit+1
        hit('depth')

    # 100 over-sized JSONL records: no output publication, stable error code over two runs.
    for t in range(100):
        limit=64+(t%32); p=td/f'big-{t}.jsonl'; out=td/f'big-{t}.out.jsonl'
        p.write_text(json.dumps({'id':t,'payload':'z'*(limit+40)})+'\n',encoding='utf-8'); out.write_text('UNCHANGED\n',encoding='utf-8')
        cfg=StreamingConfig(security_limits=lim(max_record_bytes=limit))
        got=[]
        for _ in range(2):
            try: repair_stream_file(p,out,config=cfg); raise AssertionError('oversize accepted')
            except SecurityLimitError as e: got.append(e.code)
        assert got==['max_record_bytes','max_record_bytes'] and out.read_text(encoding='utf-8')=='UNCHANGED\n'
        hit('record_bytes_atomic')

    # 100 node / width exhaustion attempts.
    for t in range(50):
        n=20+(t%20); raw=json.dumps(list(range(n)))
        expect_code(lambda raw=raw: loads_strict(raw,lim(max_nodes=10,max_array_items=1000)),'max_nodes')
        hit('node_budget')
    for t in range(50):
        raw=json.dumps({f'k{i}':i for i in range(20)})
        expect_code(lambda raw=raw: loads_strict(raw,lim(max_object_keys=8)),'max_object_keys')
        hit('object_width')

    # 100 malformed Unicode scalars; escaped surrogate must not reach writers/hashers.
    for t in range(100):
        code=0xD800+(t%0x800); raw='{"s":"\\u%04x"}'%code
        expect_code(lambda raw=raw: loads_strict(raw),'invalid_unicode_scalar')
        hit('invalid_unicode')

    # 100 valid but awkward Unicode samples must survive (do not confuse unusual text with malformed Unicode).
    samples=['é','e\u0301','😀','עברית','العربية','漢字','\u202eRTL','a\u200db','𝄞']
    for t in range(100):
        value={'id':t,'s':samples[t%len(samples)]*3}
        raw=json.dumps(value,ensure_ascii=False)
        assert loads_strict(raw)==value
        hit('valid_unicode_survives')

    # 50 bundle resource-envelope attacks: file count and total bytes.
    for t in range(25):
        d=td/f'bundle-count-{t}'; d.mkdir()
        for i in range(4): (d/f'{i}.json').write_text('{"x":1}',encoding='utf-8')
        expect_code(lambda d=d: repair_bundle_dir(d,config=RepairConfig(security_limits=lim(max_bundle_documents=3))),'max_bundle_documents')
        hit('bundle_count')
    for t in range(25):
        d=td/f'bundle-bytes-{t}'; d.mkdir()
        for i in range(3): (d/f'{i}.json').write_text(json.dumps({'x':'a'*20}),encoding='utf-8')
        expect_code(lambda d=d: repair_bundle_dir(d,config=RepairConfig(security_limits=lim(max_bundle_bytes=30))),'max_bundle_bytes')
        hit('bundle_bytes')

print(counts)
print('TOTAL',sum(counts.values()),'PASS')
