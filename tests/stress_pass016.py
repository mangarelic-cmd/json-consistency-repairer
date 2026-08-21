from __future__ import annotations
import copy, inspect, json, tempfile, ast
from pathlib import Path
from json_consistency_repair import repair_object, repair_bundle, RepairConfig
from json_consistency_repair.streaming import repair_stream_file, StreamingConfig
from json_consistency_repair.certifier import verify_single_packet, verify_report_evidence
from json_consistency_repair.provenance_chain import build_provenance_chain, verify_provenance_chain
from json_consistency_repair.provenance import package_code_sha256
import json_consistency_repair.certifier as certmod

checks=0
def ck(x,m):
    global checks
    if not x: raise AssertionError(m)
    checks+=1

def dirty():
    rows=[{'id':i,'items':[{'v':1},{'v':2}],'item_count':2} for i in range(21)]; rows[-1]['item_count']=9; return {'rows':rows}
def clean(): return {'rows':[{'id':i,'v':i} for i in range(8)]}

cached=[]
for i in range(100):
    original=dirty(); out,r=repair_object(original,RepairConfig(max_cycles=7)); cached.append((original,out,r.report)); ck(r.report['final_certification']['ok'],'single cert')
for i in range(100):
    original,out,report=cached[i]; chain=copy.deepcopy(report['provenance_chain']); chain['events'][0]['hash']='0'*64; ck(not verify_provenance_chain(chain)['ok'],'tampered chain')
for i in range(100):
    original,out,report=cached[i]; bad=copy.deepcopy(out); bad['rows'][0]['item_count']=999; ck(not verify_single_packet(original,bad,report['committed_edits'],report)['ok'],'tampered output')
for i in range(50):
    bad=copy.deepcopy(cached[i][2]); bad['cold_replay']['would_commit_edits']=1; ck(not verify_report_evidence(bad)['ok'],'cold tamper')
for i in range(50):
    docs={'a.json':dirty(),'b.json':clean()}; out,r=repair_bundle(docs,RepairConfig(max_cycles=7)); ck(r.report['final_certification']['ok'],'bundle cert')
with tempfile.TemporaryDirectory(prefix='pass016-stress-') as td:
    td=Path(td)
    for i in range(50):
        src=td/f'i{i}.jsonl'; out=td/f'o{i}.jsonl'; src.write_text('\n'.join(json.dumps(x) for x in clean()['rows'])+'\n')
        r=repair_stream_file(src,out,None,StreamingConfig(max_cycles=7)); ck(r.report['final_certification']['ok'],'stream cert')
for i in range(50):
    a=build_provenance_chain(input_digest='a'*64,output_digest='b'*64,committed=[{'x':i}],cycles=[{'cycle':1,'digest':'b'*64,'strong_quiet':True,'strong_fixed_point_streak':1}],code_digest='c'*64)
    b=build_provenance_chain(input_digest='a'*64,output_digest='b'*64,committed=[{'x':i}],cycles=[{'cycle':1,'digest':'b'*64,'strong_quiet':True,'strong_fixed_point_streak':1}],code_digest='c'*64)
    ck(a==b and verify_provenance_chain(a)['ok'],'deterministic chain')
source=Path(certmod.__file__).read_text(); tree=ast.parse(source); imports=[]
for node in ast.walk(tree):
    if isinstance(node,ast.ImportFrom): imports.append(node.module or '')
    elif isinstance(node,ast.Import): imports.extend(a.name for a in node.names)
for i in range(50): ck(not any(x.endswith('engine') or x.endswith('analyzers') or x.endswith('minimal_transfer') for x in imports),'import boundary')
for i in range(50):
    _,r=repair_object(clean(),RepairConfig(max_cycles=7)); ck(r.report['cold_replay']['would_commit_edits']==0 and r.report['cold_replay']['same_output'],'cold zero')
print(json.dumps({'pass':checks,'expected':600},sort_keys=True))
