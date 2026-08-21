from __future__ import annotations

from types import SimpleNamespace

from json_consistency_repair import RepairConfig, repair_object
from json_consistency_repair.engine import score
from json_consistency_repair.models import AnalysisResult, Candidate, Issue
from json_consistency_repair.minimal_transfer import solve_minimal_transfer
from json_consistency_repair.primary_factorization import factorize_options, compare_factorizations, verify_factorization_certificate
from json_consistency_repair.bundle import analyze_bundle, _solve_cross_minimal_transfer


def c(cid,path,new,rel=None):
    meta={}
    ev=()
    if rel:
        meta['relation_id']=rel; ev=(rel,)
    return Candidate(cid,'synthetic','replace',path,0,new,'repair',1.0,1,ev,meta)


def opt(cand):
    return SimpleNamespace(candidate=cand,candidate_ids=(cand.candidate_id,))


def rel(rid,inputs,output):
    return {'relation_id':rid,'kind':'synthetic_exact','array_path':'','inputs':list(inputs),'output':output,'confidence':1.0,'support':1}


def test_primary_factorization_strictly_refines_legacy_parent_when_independence_is_witnessed():
    a,b=c('a','/a',1,'ra'),c('b','/b',1,'rb')
    analysis=AnalysisResult([], [a,b], [rel('ra',[],'a'),rel('rb',[],'b')])
    clusters,cert=factorize_options({'a':0,'b':0},analysis,[opt(a),opt(b)])
    assert len(clusters)==2
    assert cert['legacy_parent_block_count']==1
    assert cert['strict_refinement_of_legacy_parent_partition'] is True
    assert cert['recomposition_proof']=={'frontier_option_count':2,'covered_option_count':2,'unique_coverage':True,'cross_block_dependency_edge_count':0,'information_loss':0,'lossless':True}
    assert verify_factorization_certificate(cert)


def test_explicit_relation_keeps_coupled_fields_in_one_primary_block():
    a,b=c('a','/a',1,'rab'),c('b','/b',1,'rab')
    analysis=AnalysisResult([], [a,b], [rel('rab',['a'],'b')])
    clusters,cert=factorize_options({'a':0,'b':0},analysis,[opt(a),opt(b)])
    assert len(clusters)==1
    assert any(e['kind']=='RELATION_INSTANCE' for e in cert['coupling_edges'])
    assert cert['recomposition_proof']['lossless']


def test_absence_of_relation_never_falsely_proves_independence():
    a,b=c('a','/a',1),c('b','/b',1)
    analysis=AnalysisResult([], [a,b], [])
    clusters,cert=factorize_options({'a':0,'b':0},analysis,[opt(a),opt(b)])
    assert len(clusters)==1
    assert cert['guarded_legacy_carriers']==['']
    assert any(e['kind']=='UNRESOLVED_DEPENDENCY_GUARD' for e in cert['coupling_edges'])


def test_solver_uses_primary_blocks_and_recomposes_independent_repairs():
    ia=Issue('synthetic','bad_a','/a','a bad','warning',True,{})
    ib=Issue('synthetic','bad_b','/b','b bad','warning',True,{})
    a,b=c('a','/a',1,'ra'),c('b','/b',1,'rb')
    def analyze(x):
        issues=[]; cands=[]
        if x['a']!=1: issues.append(ia); cands.append(a)
        if x['b']!=1: issues.append(ib); cands.append(b)
        return AnalysisResult(issues,cands,[rel('ra',[],'a'),rel('rb',[],'b')])
    baseline=analyze({'a':0,'b':0})
    d=solve_minimal_transfer({'a':0,'b':0},baseline,analyze_fn=analyze,score_fn=score,max_patch_size=2,max_exact_options=8)
    assert d.status=='UNIQUE_EXACT_MINIMUM_PARTITIONED'
    assert {x.path for x in d.patches}=={'/a','/b'}
    f=d.certificate['primary_factorization']
    assert f['primary_block_count']==2 and f['strict_refinement_of_legacy_parent_partition']


def test_joint_only_repair_is_preserved_by_lossless_guard():
    issue=Issue('synthetic','joint','/a','both must change','warning',True,{})
    a,b=c('a','/a',1),c('b','/b',1)
    baseline=AnalysisResult([issue],[a,b],[])
    def analyze(x):
        return AnalysisResult([],[],[]) if x=={'a':1,'b':1} else baseline
    d=solve_minimal_transfer({'a':0,'b':0},baseline,analyze_fn=analyze,score_fn=score,max_patch_size=2,max_exact_options=8)
    assert d.status.startswith('UNIQUE_EXACT_MINIMUM')
    assert len(d.patches)==2
    assert d.certificate['primary_factorization']['primary_block_count']==1


def test_dynamic_refactorization_invalidates_old_primary_block_on_split():
    a,b=c('a','/a',1,'rab'),c('b','/b',1,'rab')
    _,old=factorize_options({'a':0,'b':0},AnalysisResult([], [a,b], [rel('rab',['a'],'b')]),[opt(a),opt(b)])
    a2,b2=c('a2','/a',1,'ra'),c('b2','/b',1,'rb')
    _,new=factorize_options({'a':0,'b':0},AnalysisResult([], [a2,b2], [rel('ra',[],'a'),rel('rb',[],'b')]),[opt(a2),opt(b2)])
    d=compare_factorizations(old,new)
    assert d['status']=='REFACTORIZED'
    assert any(e['kind']=='PRIMARY_BLOCK_SPLIT' for e in d['events'])
    assert d['invalidated_block_ids']


def test_dynamic_refactorization_detects_relation_merge():
    a,b=c('a','/a',1,'ra'),c('b','/b',1,'rb')
    _,old=factorize_options({'a':0,'b':0},AnalysisResult([], [a,b], [rel('ra',[],'a'),rel('rb',[],'b')]),[opt(a),opt(b)])
    a2,b2=c('a2','/a',1,'rab'),c('b2','/b',1,'rab')
    _,new=factorize_options({'a':0,'b':0},AnalysisResult([], [a2,b2], [rel('rab',['a'],'b')]),[opt(a2),opt(b2)])
    d=compare_factorizations(old,new)
    assert any(e['kind']=='PRIMARY_BLOCK_MERGE' for e in d['events'])


def test_atomic_plan_paths_are_never_split():
    steps=[{'operation':'replace','path':'/value','old_value':250,'new_value':2.5,'metadata':{}},
           {'operation':'replace','path':'/unit','old_value':'cm','new_value':'m','metadata':{}}]
    p=Candidate('plan','synthetic','plan','',None,None,'atomic',1.0,2,('unitrel',),{'steps':steps,'relation_id':'unitrel'})
    q=Candidate('q','synthetic','replace','/unit','cm','m','same unit',1.0,1,('unitrel',),{'relation_id':'unitrel'})
    analysis=AnalysisResult([], [p,q], [rel('unitrel',['value'],'unit')])
    clusters,cert=factorize_options({'value':250,'unit':'cm'},analysis,[opt(p),opt(q)])
    assert len(clusters)==1
    assert any(e['kind']=='PATH_OVERLAP' for e in cert['coupling_edges'])


def test_engine_serializes_primary_factorization_and_final_certifier_checks_it():
    schema={'type':'object','properties':{'x':{'const':1}}}
    repaired,res=repair_object({'x':0},RepairConfig(json_schema=schema,max_cycles=4))
    assert repaired=={'x':1}
    pf=res.report['primary_factorization']
    assert pf['cycles']
    assert all(verify_factorization_certificate(x['factorization']) for x in pf['cycles'])
    assert res.report['final_certification']['checks']['primary_factorization'] is True
    assert res.report['final_certification']['status']=='CERTIFIED'


def test_bundle_cross_solver_uses_document_scoped_primary_factorization():
    users=[{'id':chr(ord('A')+i)} for i in range(10)]
    orders=[{'user_id':chr(ord('A')+i)} for i in range(9)]+[{'user_id':'j'}]
    docs={'users.json':users,'orders.json':orders}
    cfg=RepairConfig(min_support=4,reference_confidence=.9,max_cycles=3,enable_final_certification=False)
    cross=analyze_bundle(docs,cfg)
    assert len(cross.candidates)==1
    patches,cert,_=_solve_cross_minimal_transfer(docs,cross,cfg)
    assert patches
    assert cert['partition_rule']=='document_scoped_primary_relation_connected_components'
    assert cert['primary_factorization']['lossless'] is True
