from __future__ import annotations
from copy import deepcopy
from types import SimpleNamespace

from json_consistency_repair import RepairConfig, repair_object
from json_consistency_repair.models import AnalysisResult, Candidate, Issue
from json_consistency_repair.minimal_transfer import solve_minimal_transfer
from json_consistency_repair.parallel_routes import resolve_parallel_routes
from json_consistency_repair.bundle import BundleCandidate, _bundle_return_proof, apply_bundle_patch_set
from json_consistency_repair.streaming import StreamingConfig, _resolve_stream_parallel_record


def cand(cid,new):
    return Candidate(cid,'synthetic','replace','/x',0,new,'tied exact route',1.0,1,(cid,),{})

def tie_analysis():
    i=Issue('synthetic','bad','/x','bad','error',True,{})
    return AnalysisResult([i],[cand('a',1),cand('b',2)],[])

def analyze(v):
    return AnalysisResult([],[],[]) if v.get('x') in (1,2) else tie_analysis()

def score(xs): return 10*len(xs)

def fake_result(final, continuation, strong=True, ambiguous=False):
    report={'committed_edits':continuation,'remaining_issues':[],'relations':[],
            'dynamic_q_descent':{'final':{'Q_ANSWER':0,'Q_BOUNDARY':0,'Q_RETURN':0}},
            'strong_fixed_point':{'attained':strong,'oscillation_detected':False},
            'cycles':[{'minimal_transfer':{'status':'AMBIGUOUS_EXACT_MINIMUM' if ambiguous else 'NO_ADMISSIBLE_CANDIDATES'}}]}
    return final,SimpleNamespace(report=report,final_status='PASS' if strong else 'OPEN_REPAIRABLE',remaining_issues=0)

def run():
    counts={k:0 for k in ('route_materialization','return_equivalence','return_divergence','closure_gate','engine_abstention','mode_bridges')}
    total=0
    for i in range(100):
        d=solve_minimal_transfer({'x':0},tie_analysis(),analyze_fn=analyze,score_fn=score,max_patch_size=1,max_exact_options=4,enable_parallel_routes=True,max_parallel_routes=8)
        assert d.status=='AMBIGUOUS_EXACT_MINIMUM' and len(d.parallel_routes)==2 and not d.patches
        counts['route_materialization']+=1; total+=1
    routes=[[cand('a',1)],[cand('b',2)]]
    for i in range(100):
        def complete(seed):
            old=seed['x']; cont=[{'candidate_id':f'c{old}','analyzer':'closure','operation':'replace','path':'/x','old_value':old,'new_value':9,'reason':'return','confidence':1.0,'cost':1,'evidence':[],'metadata':{}}]
            return fake_result({'x':9},cont)
        r=resolve_parallel_routes({'x':0},routes,complete_fn=complete,max_routes=8)
        assert r.proof['ok'] and r.status=='RETURN_PROOF_EQUIVALENT' and len(r.patches)==2
        counts['return_equivalence']+=1; total+=1
    for i in range(100):
        r=resolve_parallel_routes({'x':0},routes,complete_fn=lambda seed:fake_result(deepcopy(seed),[]),max_routes=8)
        assert not r.proof['ok'] and r.status=='RETURN_PROOF_DIVERGENT' and not r.patches
        counts['return_divergence']+=1; total+=1
    for i in range(100):
        def complete(seed):
            old=seed['x']; cont=[{'candidate_id':f'c{old}','analyzer':'closure','operation':'replace','path':'/x','old_value':old,'new_value':9,'reason':'return','confidence':1.0,'cost':1,'evidence':[],'metadata':{}}]
            return fake_result({'x':9},cont,strong=(old==1))
        r=resolve_parallel_routes({'x':0},routes,complete_fn=complete,max_routes=8)
        assert not r.proof['ok'] and not r.proof['checks']['all_routes_closed']
        counts['closure_gate']+=1; total+=1
    for i in range(100):
        rows=[{'a':j%2==0,'b':j%2==1} for j in range(20)] + [{'a':False,'b':False}]
        out,res=repair_object({'rows':rows},RepairConfig(logic_confidence=.95,max_cycles=3,enable_final_certification=False))
        assert out['rows'][-1]=={'a':False,'b':False} and res.committed_edits==0
        pr=res.report['parallel_exact_minimum_routes']['cycles']
        assert pr and pr[0]['status']=='RETURN_PROOF_DIVERGENT'
        counts['engine_abstention']+=1; total+=1
    schema={'type':'object','properties':{'x':{'const':9}}}
    for i in range(50):
        a=BundleCandidate('a.json',Candidate(f'a{i}','synthetic','replace','/x',0,1,'a',1.0,1,('A',),{}))
        b=BundleCandidate('a.json',Candidate(f'b{i}','synthetic','replace','/x',0,2,'b',1.0,1,('B',),{}))
        cfg=RepairConfig(json_schema=schema,max_cycles=4,enable_final_certification=False)
        chain,proof=_bundle_return_proof({'a.json':{'x':0}},[[a],[b]],cfg)
        assert proof['ok'] and apply_bundle_patch_set({'a.json':{'x':0}},chain)=={'a.json':{'x':9}}
        counts['mode_bridges']+=1; total+=1
    for i in range(50):
        cfg=StreamingConfig(json_schema=schema,exact_disk_registry=True,max_cycles=4,enable_final_certification=False)
        rr=[[{'analyzer':'synthetic','path':'/x','old_value':0,'new_value':1,'confidence':1.0,'reason':'a','evidence':[]}],
            [{'analyzer':'synthetic','path':'/x','old_value':0,'new_value':2,'confidence':1.0,'reason':'b','evidence':[]}]]
        final,proof=_resolve_stream_parallel_record({'x':0},rr,{},cfg)
        assert proof['ok'] and final=={'x':9}
        counts['mode_bridges']+=1; total+=1
    assert total==600
    print('PASS026_STRESS',total,counts)

if __name__=='__main__': run()
