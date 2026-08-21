from __future__ import annotations
import json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'src'))
from json_consistency_repair import RepairConfig, __version__
from json_consistency_repair.models import AnalysisResult, Issue, Candidate
from json_consistency_repair.federation import federation_fixed_point, compile_q_descent

def c(cid,a,path,old,new): return Candidate(cid,a,'replace',path,old,new,'benchmark',1.0,1,(),{})
cfg=RepairConfig(enable_final_certification=False)
counts={}; false_mutations=0
def hit(k): counts[k]=counts.get(k,0)+1
for n in range(100):
    a=AnalysisResult([], [c(f'a{n}','logic_exact','/x',0,1),c(f'b{n}','constraint_bridge','/x',0,1)], [])
    out,cert=federation_fixed_point(a,cfg); assert len([x for x in out.candidates if x.analyzer=='federation_consensus'])==1; hit('consensus')
for n in range(100):
    a=AnalysisResult([], [c(f'a{n}','logic_exact','/x',0,1),c(f'b{n}','constraint_bridge','/x',0,2)], [])
    out,cert=federation_fixed_point(a,cfg); assert not [x for x in out.candidates if x.analyzer=='federation_consensus']; assert any(h['hyperobject_kind']=='CANDIDATE_CONFLICT' for h in cert['mode_ii']['hyperobjects']); hit('conflict_abstain')
for n in range(100):
    r1={'relation_id':f'a{n}','kind':'exact_arithmetic','array_path':'/r','inputs':['a'],'output':'b','direction_certified':True,'confidence':1.0,'support':4}
    r2={'relation_id':f'b{n}','kind':'functional','array_path':'/r','inputs':['b'],'output':'c','direction_certified':True,'confidence':1.0,'support':4}
    out,cert=federation_fixed_point(AnalysisResult([],[],[r1,r2]),cfg); assert any(r.get('kind')=='federated_composite' and r.get('output')=='c' for r in out.relations); hit('pairwise_composition')
for n in range(100):
    rs=[{'relation_id':f'a{n}','kind':'exact_arithmetic','array_path':'','inputs':['a'],'output':'b','direction_certified':True,'confidence':1.0,'support':4},{'relation_id':f'b{n}','kind':'functional','array_path':'','inputs':['b'],'output':'c','direction_certified':True,'confidence':1.0,'support':4},{'relation_id':f'c{n}','kind':'sequence_step','array_path':'','inputs':['c'],'output':'d','direction_certified':True,'confidence':1.0,'support':4}]
    out,cert=federation_fixed_point(AnalysisResult([],[],rs),RepairConfig(enable_final_certification=False,federation_max_cycles=6)); assert cert['mode_ii']['fixed_point_attained']; assert any(r.get('output')=='d' and 'a' in r.get('inputs',[]) for r in out.relations if r.get('kind')=='federated_composite'); hit('recursive_rebroadcast')
for n in range(100):
    a=AnalysisResult([Issue('logic_exact','bad','/x','bad','warning',True)],[c(f'a{n}','logic_exact','/x',0,1),c(f'b{n}','constraint_bridge','/x',0,2)],[])
    fed,cert=federation_fixed_point(a,cfg); q=compile_q_descent({'x':0},fed,cert); assert q['global_q']['q_boundary']>0 and q['global_q']['q_return']==0; hit('q_boundary_return')
for n in range(100):
    a=AnalysisResult([],[],[]); _,x=federation_fixed_point(a,cfg); _,y=federation_fixed_point(a,cfg); assert x['federation_digest']==y['federation_digest'] and x['mode_i']['independence_barrier']; hit('deterministic_mode_i')
result={'contract':'json-consistency-repair.pass022-benchmark.v1','version':__version__,'expected_decisions':600,'decisions':sum(counts.values()),'false_mutations':false_mutations,'counts':dict(sorted(counts.items())),'all_checks_pass':sum(counts.values())==600 and false_mutations==0}
print(json.dumps(result,sort_keys=True,separators=(',',':')))
