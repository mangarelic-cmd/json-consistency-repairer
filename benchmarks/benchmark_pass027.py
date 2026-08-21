from __future__ import annotations
from pathlib import Path
from types import SimpleNamespace
import json

from json_consistency_repair.engine import score
from json_consistency_repair.models import AnalysisResult, Candidate, Issue
from json_consistency_repair.minimal_transfer import solve_minimal_transfer
from json_consistency_repair.primary_factorization import factorize_options, compare_factorizations, verify_factorization_certificate


def c(cid,path,new,rel=None):
    meta={} if rel is None else {'relation_id':rel}; ev=() if rel is None else (rel,)
    return Candidate(cid,'synthetic','replace',path,0,new,'repair',1.0,1,ev,meta)
def o(x): return SimpleNamespace(candidate=x,candidate_ids=(x.candidate_id,))
def r(rid,inputs,output): return {'relation_id':rid,'kind':'synthetic_exact','array_path':'','inputs':list(inputs),'output':output,'confidence':1.0,'support':1}

def main():
    counts={}; false_mutations=0
    def batch(name,fn,n=100):
        nonlocal false_mutations
        ok=0
        for i in range(n):
            good,false=fn(i); ok+=int(good); false_mutations+=int(false)
        counts[name]=ok

    def refine(i):
        a,b=c(f'a{i}','/a',1,'ra'),c(f'b{i}','/b',1,'rb')
        _,x=factorize_options({'a':0,'b':0},AnalysisResult([], [a,b], [r('ra',[],'a'),r('rb',[],'b')]),[o(a),o(b)])
        return x['primary_block_count']==2 and x['strict_refinement_of_legacy_parent_partition'] and verify_factorization_certificate(x),False
    batch('strict_refinement',refine)

    def coupled(i):
        a,b=c(f'a{i}','/a',1,'rab'),c(f'b{i}','/b',1,'rab')
        _,x=factorize_options({'a':0,'b':0},AnalysisResult([], [a,b], [r('rab',['a'],'b')]),[o(a),o(b)])
        return x['primary_block_count']==1 and any(e['kind']=='RELATION_INSTANCE' for e in x['coupling_edges']),False
    batch('coupling_preserved',coupled)

    def guarded(i):
        a,b=c(f'a{i}','/a',1),c(f'b{i}','/b',1)
        _,x=factorize_options({'a':0,'b':0},AnalysisResult([], [a,b], []),[o(a),o(b)])
        # A false split here would be a false structural mutation opportunity.
        bad=x['primary_block_count']!=1
        return (not bad) and verify_factorization_certificate(x),bad
    batch('unknown_dependency_guard',guarded)

    def split(i):
        a,b=c(f'a{i}','/a',1,'rab'),c(f'b{i}','/b',1,'rab')
        _,old=factorize_options({},AnalysisResult([], [a,b], [r('rab',['a'],'b')]),[o(a),o(b)])
        a2,b2=c(f'a2{i}','/a',1,'ra'),c(f'b2{i}','/b',1,'rb')
        _,new=factorize_options({},AnalysisResult([], [a2,b2], [r('ra',[],'a'),r('rb',[],'b')]),[o(a2),o(b2)])
        d=compare_factorizations(old,new)
        return any(e['kind']=='PRIMARY_BLOCK_SPLIT' for e in d['events']) and bool(d['invalidated_block_ids']),False
    batch('dynamic_split',split)

    def merge(i):
        a,b=c(f'a{i}','/a',1,'ra'),c(f'b{i}','/b',1,'rb')
        _,old=factorize_options({},AnalysisResult([], [a,b], [r('ra',[],'a'),r('rb',[],'b')]),[o(a),o(b)])
        a2,b2=c(f'a2{i}','/a',1,'rab'),c(f'b2{i}','/b',1,'rab')
        _,new=factorize_options({},AnalysisResult([], [a2,b2], [r('rab',['a'],'b')]),[o(a2),o(b2)])
        d=compare_factorizations(old,new)
        return any(e['kind']=='PRIMARY_BLOCK_MERGE' for e in d['events']),False
    batch('dynamic_merge',merge)

    def solve(i):
        ia=Issue('synthetic','bad_a','/a','a bad','warning',True,{})
        ib=Issue('synthetic','bad_b','/b','b bad','warning',True,{})
        a,b=c(f'a{i}','/a',1,'ra'),c(f'b{i}','/b',1,'rb')
        def analyze(x):
            issues=[]; cands=[]
            if x['a']!=1: issues.append(ia); cands.append(a)
            if x['b']!=1: issues.append(ib); cands.append(b)
            return AnalysisResult(issues,cands,[r('ra',[],'a'),r('rb',[],'b')])
        d=solve_minimal_transfer({'a':0,'b':0},analyze({'a':0,'b':0}),analyze_fn=analyze,score_fn=score,max_patch_size=2,max_exact_options=8)
        good=d.status=='UNIQUE_EXACT_MINIMUM_PARTITIONED' and {p.path for p in d.patches}=={'/a','/b'}
        return good,False
    batch('solver_recomposition',solve)

    payload={'contract':'json-consistency-repair.pass027-benchmark.v1','version':'0.27.0','decisions':sum(counts.values()),'expected_decisions':600,'counts':counts,'false_mutations':false_mutations,'all_checks_pass':sum(counts.values())==600 and false_mutations==0}
    text=json.dumps(payload,sort_keys=True,separators=(',',':'))+'\n'
    Path(__file__).with_name('PASS027_BENCHMARK.json').write_text(text,encoding='utf-8')
    print(text,end='')

if __name__=='__main__': main()
