from __future__ import annotations
from types import SimpleNamespace

from json_consistency_repair.engine import score
from json_consistency_repair.models import AnalysisResult, Candidate, Issue
from json_consistency_repair.minimal_transfer import solve_minimal_transfer
from json_consistency_repair.primary_factorization import factorize_options, compare_factorizations, verify_factorization_certificate


def c(cid,path,new,rel=None):
    meta={} if rel is None else {'relation_id':rel}
    ev=() if rel is None else (rel,)
    return Candidate(cid,'synthetic','replace',path,0,new,'repair',1.0,1,ev,meta)

def o(x): return SimpleNamespace(candidate=x,candidate_ids=(x.candidate_id,))
def r(rid,inputs,output): return {'relation_id':rid,'kind':'synthetic_exact','array_path':'','inputs':list(inputs),'output':output,'confidence':1.0,'support':1}

def run():
    counts={k:0 for k in ('strict_refinement','coupling_preserved','unknown_dependency_guard','dynamic_split','dynamic_merge','solver_recomposition')}
    total=0
    for i in range(100):
        a,b=c(f'a{i}','/a',1,'ra'),c(f'b{i}','/b',1,'rb')
        _,cert=factorize_options({'a':0,'b':0},AnalysisResult([], [a,b], [r('ra',[],'a'),r('rb',[],'b')]),[o(a),o(b)])
        assert cert['primary_block_count']==2 and cert['strict_refinement_of_legacy_parent_partition'] and verify_factorization_certificate(cert)
        counts['strict_refinement']+=1; total+=1
    for i in range(100):
        a,b=c(f'a{i}','/a',1,'rab'),c(f'b{i}','/b',1,'rab')
        _,cert=factorize_options({'a':0,'b':0},AnalysisResult([], [a,b], [r('rab',['a'],'b')]),[o(a),o(b)])
        assert cert['primary_block_count']==1 and any(e['kind']=='RELATION_INSTANCE' for e in cert['coupling_edges'])
        counts['coupling_preserved']+=1; total+=1
    for i in range(100):
        a,b=c(f'a{i}','/a',1),c(f'b{i}','/b',1)
        _,cert=factorize_options({'a':0,'b':0},AnalysisResult([], [a,b], []),[o(a),o(b)])
        assert cert['primary_block_count']==1 and cert['guarded_legacy_carriers']==[''] and verify_factorization_certificate(cert)
        counts['unknown_dependency_guard']+=1; total+=1
    for i in range(100):
        a,b=c(f'a{i}','/a',1,'rab'),c(f'b{i}','/b',1,'rab')
        _,old=factorize_options({'a':0,'b':0},AnalysisResult([], [a,b], [r('rab',['a'],'b')]),[o(a),o(b)])
        a2,b2=c(f'a2{i}','/a',1,'ra'),c(f'b2{i}','/b',1,'rb')
        _,new=factorize_options({'a':0,'b':0},AnalysisResult([], [a2,b2], [r('ra',[],'a'),r('rb',[],'b')]),[o(a2),o(b2)])
        d=compare_factorizations(old,new)
        assert any(e['kind']=='PRIMARY_BLOCK_SPLIT' for e in d['events']) and d['invalidated_block_ids']
        counts['dynamic_split']+=1; total+=1
    for i in range(100):
        a,b=c(f'a{i}','/a',1,'ra'),c(f'b{i}','/b',1,'rb')
        _,old=factorize_options({'a':0,'b':0},AnalysisResult([], [a,b], [r('ra',[],'a'),r('rb',[],'b')]),[o(a),o(b)])
        a2,b2=c(f'a2{i}','/a',1,'rab'),c(f'b2{i}','/b',1,'rab')
        _,new=factorize_options({'a':0,'b':0},AnalysisResult([], [a2,b2], [r('rab',['a'],'b')]),[o(a2),o(b2)])
        d=compare_factorizations(old,new)
        assert any(e['kind']=='PRIMARY_BLOCK_MERGE' for e in d['events'])
        counts['dynamic_merge']+=1; total+=1
    for i in range(100):
        ia=Issue('synthetic','bad_a','/a','a bad','warning',True,{})
        ib=Issue('synthetic','bad_b','/b','b bad','warning',True,{})
        a,b=c(f'a{i}','/a',1,'ra'),c(f'b{i}','/b',1,'rb')
        def analyze(x):
            issues=[]; cands=[]
            if x['a']!=1: issues.append(ia); cands.append(a)
            if x['b']!=1: issues.append(ib); cands.append(b)
            return AnalysisResult(issues,cands,[r('ra',[],'a'),r('rb',[],'b')])
        d=solve_minimal_transfer({'a':0,'b':0},analyze({'a':0,'b':0}),analyze_fn=analyze,score_fn=score,max_patch_size=2,max_exact_options=8)
        assert d.status=='UNIQUE_EXACT_MINIMUM_PARTITIONED' and len(d.patches)==2 and d.certificate['primary_factorization']['recomposition_proof']['lossless']
        counts['solver_recomposition']+=1; total+=1
    assert total==600
    print('PASS027_STRESS',total,counts)

if __name__=='__main__': run()
