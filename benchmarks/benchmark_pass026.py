from __future__ import annotations
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import json

from json_consistency_repair import RepairConfig, repair_object
from json_consistency_repair.models import AnalysisResult, Candidate, Issue
from json_consistency_repair.minimal_transfer import solve_minimal_transfer
from json_consistency_repair.parallel_routes import resolve_parallel_routes
from json_consistency_repair.bundle import BundleCandidate, _bundle_return_proof, apply_bundle_patch_set
from json_consistency_repair.streaming import StreamingConfig, _resolve_stream_parallel_record


def cand(cid,new):
    return Candidate(cid,'synthetic','replace','/x',0,new,'tied exact route',1.0,1,(cid,),{})

def tie_analysis():
    return AnalysisResult([Issue('synthetic','bad','/x','bad','error',True,{})],[cand('a',1),cand('b',2)],[])

def analyze(v): return AnalysisResult([],[],[]) if v.get('x') in (1,2) else tie_analysis()
def score(xs): return 10*len(xs)

def fake(final,cont,strong=True):
    return final,SimpleNamespace(report={'committed_edits':cont,'remaining_issues':[],'relations':[],
        'dynamic_q_descent':{'final':{'Q_ANSWER':0,'Q_BOUNDARY':0,'Q_RETURN':0}},
        'strong_fixed_point':{'attained':strong,'oscillation_detected':False},
        'cycles':[{'minimal_transfer':{'status':'NO_ADMISSIBLE_CANDIDATES'}}]},final_status='PASS' if strong else 'OPEN_REPAIRABLE',remaining_issues=0)

def main():
    counts={}; false=0
    def batch(name,fn,n=100):
        nonlocal false
        ok=0
        for i in range(n):
            good,mut=fn(i); ok+=int(good); false+=int(mut)
        counts[name]=ok

    def mat(i):
        d=solve_minimal_transfer({'x':0},tie_analysis(),analyze_fn=analyze,score_fn=score,max_patch_size=1,max_exact_options=4,enable_parallel_routes=True,max_parallel_routes=8)
        return d.status=='AMBIGUOUS_EXACT_MINIMUM' and len(d.parallel_routes)==2 and not d.patches, bool(d.patches)
    batch('materialized_ties',mat)

    routes=[[cand('a',1)],[cand('b',2)]]
    def conv(i):
        def complete(seed):
            old=seed['x']; cont=[{'candidate_id':f'c{old}','analyzer':'closure','operation':'replace','path':'/x','old_value':old,'new_value':9,'reason':'return','confidence':1.0,'cost':1,'evidence':[],'metadata':{}}]
            return fake({'x':9},cont)
        r=resolve_parallel_routes({'x':0},routes,complete_fn=complete,max_routes=8)
        return r.proof.get('ok') and r.proof.get('terminal_digest') is not None, False
    batch('convergent_return',conv)

    def div(i):
        r=resolve_parallel_routes({'x':0},routes,complete_fn=lambda seed:fake(deepcopy(seed),[]),max_routes=8)
        return (not r.proof.get('ok')) and not r.patches, bool(r.patches)
    batch('divergent_abstention',div)

    def gate(i):
        def complete(seed):
            old=seed['x']; cont=[{'candidate_id':f'c{old}','analyzer':'closure','operation':'replace','path':'/x','old_value':old,'new_value':9,'reason':'return','confidence':1.0,'cost':1,'evidence':[],'metadata':{}}]
            return fake({'x':9},cont,strong=(old==1))
        r=resolve_parallel_routes({'x':0},routes,complete_fn=complete,max_routes=8)
        return (not r.proof.get('ok')) and not r.proof['checks']['all_routes_closed'], bool(r.patches)
    batch('closure_gate',gate)

    def frontier(i):
        rs=[[cand(str(j),j+1)] for j in range(5)]
        called=[0]
        def complete(seed):
            called[0]+=1
            return fake(seed,[])
        r=resolve_parallel_routes({'x':0},rs,complete_fn=complete,max_routes=4)
        return r.status=='PARALLEL_ROUTE_FRONTIER_TOO_LARGE' and called[0]==0 and not r.patches, bool(r.patches)
    batch('bounded_frontier',frontier)

    def modes(i):
        schema={'type':'object','properties':{'x':{'const':9}}}
        if i<50:
            a=BundleCandidate('a.json',Candidate(f'a{i}','synthetic','replace','/x',0,1,'a',1.0,1,('A',),{}))
            b=BundleCandidate('a.json',Candidate(f'b{i}','synthetic','replace','/x',0,2,'b',1.0,1,('B',),{}))
            chain,proof=_bundle_return_proof({'a.json':{'x':0}},[[a],[b]],RepairConfig(json_schema=schema,max_cycles=4,enable_final_certification=False))
            final=apply_bundle_patch_set({'a.json':{'x':0}},chain) if chain else None
            return proof.get('ok') and final=={'a.json':{'x':9}}, False
        cfg=StreamingConfig(json_schema=schema,exact_disk_registry=True,max_cycles=4,enable_final_certification=False)
        rr=[[{'analyzer':'synthetic','path':'/x','old_value':0,'new_value':1,'confidence':1.0,'reason':'a','evidence':[]}],
            [{'analyzer':'synthetic','path':'/x','old_value':0,'new_value':2,'confidence':1.0,'reason':'b','evidence':[]}]]
        final,proof=_resolve_stream_parallel_record({'x':0},rr,{},cfg)
        return proof.get('ok') and final=={'x':9}, False
    batch('bundle_stream_return_bridge',modes)

    payload={'contract':'json-consistency-repair.pass026-benchmark.v1','version':'0.26.0','decisions':sum(counts.values()),'expected_decisions':600,'counts':counts,'false_mutations':false,'all_checks_pass':sum(counts.values())==600 and false==0}
    text=json.dumps(payload,sort_keys=True,separators=(',',':'))+'\n'
    Path(__file__).with_name('PASS026_BENCHMARK.json').write_text(text,encoding='utf-8')
    print(text,end='')

if __name__=='__main__': main()
