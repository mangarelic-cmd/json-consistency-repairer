from __future__ import annotations
from json_consistency_repair.models import AnalysisResult, Issue, Candidate
from json_consistency_repair.federation import federation_fixed_point, compile_q_descent
from json_consistency_repair.engine import RepairConfig, repair_object
from json_consistency_repair.bundle import repair_bundle
from json_consistency_repair.streaming import StreamingConfig, repair_stream_file
from pathlib import Path
import tempfile, json

def c(cid,a,path,old,new): return Candidate(cid,a,'replace',path,old,new,'stress',1.0,1,(),{})
cfg=RepairConfig(enable_final_certification=False,max_cycles=5)
counts={}
for n in range(80):
    _,x=federation_fixed_point(AnalysisResult([Issue('logic_exact','x','/x','x')],[],[]),cfg)
    _,y=federation_fixed_point(AnalysisResult([Issue('logic_exact','x','/x','x')],[],[]),cfg)
    assert x['federation_digest']==y['federation_digest'] and x['mode_i']['independence_barrier']
counts['mode_i_deterministic']=80
for n in range(80):
    a=AnalysisResult([], [c(f'a{n}','logic_exact','/x',0,1),c(f'b{n}','constraint_bridge','/x',0,1)], [])
    out,cert=federation_fixed_point(a,cfg); f=[x for x in out.candidates if x.analyzer=='federation_consensus']
    assert len(f)==1 and len(f[0].evidence)>=2
counts['consensus']=80
for n in range(80):
    a=AnalysisResult([], [c(f'a{n}','logic_exact','/x',0,1),c(f'b{n}','constraint_bridge','/x',0,2)], [])
    out,cert=federation_fixed_point(a,cfg)
    assert not [x for x in out.candidates if x.analyzer=='federation_consensus']
    assert any(h['hyperobject_kind']=='CANDIDATE_CONFLICT' for h in cert['mode_ii']['hyperobjects'])
counts['conflict_debt']=80
for n in range(100):
    r1={'relation_id':f'r1{n}','kind':'exact_arithmetic','array_path':'/rows','inputs':['a'],'output':'b','direction_certified':True,'confidence':1.0,'support':10}
    r2={'relation_id':f'r2{n}','kind':'functional','array_path':'/rows','inputs':['b'],'output':'c','direction_certified':True,'confidence':1.0,'support':10}
    out,cert=federation_fixed_point(AnalysisResult([],[],[r1,r2]),cfg)
    assert any(r.get('kind')=='federated_composite' and r.get('inputs')==['a'] and r.get('output')=='c' for r in out.relations)
counts['pairwise_composition']=100
for n in range(60):
    rs=[
      {'relation_id':f'r1{n}','kind':'exact_arithmetic','array_path':'','inputs':['a'],'output':'b','direction_certified':True,'confidence':1.0,'support':5},
      {'relation_id':f'r2{n}','kind':'functional','array_path':'','inputs':['b'],'output':'c','direction_certified':True,'confidence':1.0,'support':5},
      {'relation_id':f'r3{n}','kind':'sequence_step','array_path':'','inputs':['c'],'output':'d','direction_certified':True,'confidence':1.0,'support':5},]
    out,cert=federation_fixed_point(AnalysisResult([],[],rs),RepairConfig(enable_final_certification=False,federation_max_cycles=6))
    assert any(r.get('kind')=='federated_composite' and r.get('output')=='d' and 'a' in r.get('inputs',[]) for r in out.relations)
counts['recursive_rebroadcast']=60
for n in range(80):
    a=AnalysisResult([Issue('logic_exact','bad','/x','bad','warning',True)],[c(f'a{n}','logic_exact','/x',0,1),c(f'b{n}','constraint_bridge','/x',0,2)],[])
    fed,cert=federation_fixed_point(a,cfg); q=compile_q_descent({'x':0},fed,cert)
    assert q['global_q']['q_answer']>0 and q['global_q']['q_boundary']>0 and q['global_q']['q_return']==0
counts['q_ledger']=80
for n in range(60):
    doc={'rows':[{'x':1,'y':2},{'x':2,'y':3},{'x':3,'y':4},{'x':4,'y':5}]}
    out,res=repair_object(doc,RepairConfig(enable_final_certification=False,max_cycles=5,min_support=3))
    assert res.report['federation_summary']['final']['mode_ii']['fixed_point_attained']
    assert res.report['dynamic_q_descent']['final']['global_q']['lexicographic_vector']==[0,0,0]
counts['engine_integration']=60
for n in range(30):
    docs={'a.json':{'rows':[{'x':1},{'x':2},{'x':3}]},'b.json':{'rows':[{'y':1},{'y':2},{'y':3}]}}
    out,res=repair_bundle(docs,RepairConfig(enable_final_certification=False,max_cycles=4,min_support=3))
    assert res.report['federation_summary']['mode']=='bundle' and set(res.report['federation_summary']['documents'])=={'a.json','b.json'}
counts['bundle']=30
with tempfile.TemporaryDirectory() as td:
    td=Path(td)
    for n in range(30):
        inp=td/f'i{n}.jsonl'; outp=td/f'o{n}.jsonl'; inp.write_text(json.dumps({'x':n})+'\n',encoding='utf-8')
        res=repair_stream_file(inp,outp,config=StreamingConfig(enable_final_certification=False,max_cycles=4,min_support=1))
        assert res.report['federation_summary']['mode']=='streaming' and res.report['dynamic_q_descent']['materialization_scope']=='BOUNDED_STREAM'
counts['streaming']=30
assert sum(counts.values())==600
print({'pass':True,'total':sum(counts.values()),'counts':counts})
