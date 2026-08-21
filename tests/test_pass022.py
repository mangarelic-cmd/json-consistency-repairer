from __future__ import annotations
from json_consistency_repair.models import AnalysisResult, Issue, Candidate
from json_consistency_repair.federation import federation_fixed_point, federate_analysis, compile_q_descent, q_compare
from json_consistency_repair.engine import RepairConfig, repair_object


def c(cid, analyzer, path, old, new):
    return Candidate(cid,analyzer,'replace',path,old,new,'test',1.0,1,(),{})


def test_mode_i_has_independence_barrier_and_actor_roster():
    a=AnalysisResult([Issue('logic_exact','x','/x','x',repairable=True)],[c('c1','logic_exact','/x',0,1)],[])
    _,cert=federation_fixed_point(a,RepairConfig(enable_final_certification=False))
    assert cert['mode_i']['independence_barrier'] is True
    assert cert['mode_i']['mode_ii_visible_during_mode_i'] is False
    assert cert['mode_i']['snapshot_actor_count']>=17


def test_consensus_hyperobject_adds_independent_evidence():
    a=AnalysisResult([], [c('c1','logic_exact','/x',0,1),c('c2','constraint_bridge','/x',0,1)], [])
    out,cert=federation_fixed_point(a,RepairConfig(enable_final_certification=False))
    fed=[x for x in out.candidates if x.analyzer=='federation_consensus']
    assert len(fed)==1 and len(fed[0].evidence)>=2
    assert any(h['hyperobject_kind']=='CONSENSUS_PATCH' for h in cert['mode_ii']['hyperobjects'])


def test_conflicting_cross_actor_candidates_create_debt_not_winner():
    a=AnalysisResult([], [c('c1','logic_exact','/x',0,1),c('c2','constraint_bridge','/x',0,2)], [])
    out,cert=federation_fixed_point(a,RepairConfig(enable_final_certification=False))
    assert not [x for x in out.candidates if x.analyzer=='federation_consensus']
    hs=[h for h in cert['mode_ii']['hyperobjects'] if h['hyperobject_kind']=='CANDIDATE_CONFLICT']
    assert len(hs)==1 and hs[0]['alternative_count']==2


def test_cross_actor_directed_relations_compose_and_rebroadcast_to_fixed_point():
    r1={'relation_id':'r1','kind':'exact_arithmetic','array_path':'/rows','inputs':['a'],'output':'b','direction_certified':True,'confidence':1.0,'support':10}
    r2={'relation_id':'r2','kind':'functional','array_path':'/rows','inputs':['b'],'output':'c','direction_certified':True,'confidence':1.0,'support':10}
    a=AnalysisResult([],[],[r1,r2])
    out,cert=federation_fixed_point(a,RepairConfig(enable_final_certification=False,federation_max_cycles=5))
    comp=[r for r in out.relations if r.get('kind')=='federated_composite']
    assert any(r['inputs']==['a'] and r['output']=='c' for r in comp)
    assert cert['mode_ii']['fixed_point_attained'] is True
    assert len(cert['mode_ii']['cycle_receipts'])>=2


def test_rebroadcast_can_build_depth_two_composite_without_exhaustive_hyperobjects():
    rs=[
      {'relation_id':'r1','kind':'exact_arithmetic','array_path':'','inputs':['a'],'output':'b','direction_certified':True,'confidence':1.0,'support':5},
      {'relation_id':'r2','kind':'functional','array_path':'','inputs':['b'],'output':'c','direction_certified':True,'confidence':1.0,'support':5},
      {'relation_id':'r3','kind':'sequence_step','array_path':'','inputs':['c'],'output':'d','direction_certified':True,'confidence':1.0,'support':5},
    ]
    out,cert=federation_fixed_point(AnalysisResult([],[],rs),RepairConfig(enable_final_certification=False,federation_max_cycles=6))
    assert any(r.get('kind')=='federated_composite' and r.get('output')=='d' and 'a' in r.get('inputs',[]) for r in out.relations)
    assert cert['mode_ii']['composite_relation_count']<=128


def test_q_boundary_counts_federated_conflict_and_return_route():
    root={'x':0}
    a=AnalysisResult([Issue('logic_exact','bad','/x','bad','warning',True)], [c('c1','logic_exact','/x',0,1),c('c2','constraint_bridge','/x',0,2)], [])
    fed,cert=federation_fixed_point(a,RepairConfig(enable_final_certification=False))
    q=compile_q_descent(root,fed,cert)
    assert q['global_q']['q_answer']>0 and q['global_q']['q_boundary']>0
    assert q['global_q']['q_return']==0


def test_q_compare_only_credits_strict_descent():
    b={'global_q':{'lexicographic_vector':[3,1,0]}}
    a={'global_q':{'lexicographic_vector':[0,0,0]}}
    eq={'global_q':{'lexicographic_vector':[3,1,0]}}
    assert q_compare(b,a)['sovereign_credit'] is True
    assert q_compare(b,eq)['sovereign_credit'] is False


def test_engine_exposes_federation_and_dynamic_q_contracts():
    doc={'rows':[{'x':1,'y':2},{'x':2,'y':3},{'x':3,'y':4},{'x':4,'y':999}]}
    out,res=repair_object(doc,RepairConfig(enable_final_certification=False,min_support=3,max_cycles=6))
    assert res.report['federation_summary']['contract']=='json-consistency-repair.c189-federation-summary.v1'
    assert res.report['dynamic_q_descent']['contract']=='json-consistency-repair.dynamic-q-descent.v1'
    assert res.report['federation_summary']['final']['mode_ii']['fixed_point_attained'] is True


def test_federation_can_be_disabled_without_removing_q_ledger():
    doc={'x':1}
    out,res=repair_object(doc,RepairConfig(enable_federation=False,enable_final_certification=False,max_cycles=3))
    assert res.report['federation_summary']['final']['enabled'] is False
    assert res.report['dynamic_q_descent']['final']['global_q']['lexicographic_vector']==[0,0,0]


def test_federation_is_deterministic():
    r1={'relation_id':'r1','kind':'exact_arithmetic','array_path':'','inputs':['a'],'output':'b','direction_certified':True,'confidence':1.0,'support':5}
    r2={'relation_id':'r2','kind':'functional','array_path':'','inputs':['b'],'output':'c','direction_certified':True,'confidence':1.0,'support':5}
    cfg=RepairConfig(enable_final_certification=False)
    _,a=federation_fixed_point(AnalysisResult([],[],[r1,r2]),cfg)
    _,b=federation_fixed_point(AnalysisResult([],[],[r1,r2]),cfg)
    assert a['federation_digest']==b['federation_digest']
