from __future__ import annotations
from copy import deepcopy
import json

from json_consistency_repair import RepairConfig, repair_object
from json_consistency_repair.models import AnalysisResult, Candidate, Issue
from json_consistency_repair.materialization import materialize_missing_witnesses
from json_consistency_repair.bundle import repair_bundle
from json_consistency_repair.streaming import StreamingConfig, repair_stream_file
from json_consistency_repair.certifier import verify_single_packet


def _required_schema():
    return {'type':'object','required':['x'],'properties':{'x':{'type':'integer'}}}


def test_authoritative_source_is_materialized_and_reinjected():
    cfg=RepairConfig(json_schema=_required_schema(),
                     source_context=({'source_id':'auth','role':'authoritative','value':{'x':7},'schema_version':'v1'},),
                     source_manifest={'identity_bridges':[]},max_cycles=5,strong_fixed_point_cycles_required=1)
    repaired,res=repair_object({},cfg)
    assert repaired=={'x':7}
    assert res.report['final_certification']['status']=='CERTIFIED'
    exact=[t for c in res.report['witness_materialization']['cycles'] for t in c['certificate']['terminals'] if t['status']=='MATERIALIZED_EXACT']
    assert exact and exact[0]['target_path']=='/x'
    assert exact[0]['selected_value_digest']
    assert res.report['committed_edits'][0]['analyzer']=='witness_materializer'
    assert 'MISSING_WITNESS_TERMINAL' in res.report['proof_graph']['section_roots']


def test_identity_bridge_materializes_across_schema_versions():
    manifest={'identity_bridges':[{
        'logical_id':'status-field','canonical_field':'status',
        'members':[{'source_id':'__primary__','field':'status'},{'source_id':'old','field':'state'}]
    }]}
    cfg=RepairConfig(json_schema={'type':'object','required':['status']},
                     source_context=({'source_id':'old','role':'authoritative','value':{'state':'READY'},'schema_version':1},),
                     source_manifest=manifest,max_cycles=5,strong_fixed_point_cycles_required=1)
    repaired,res=repair_object({},cfg)
    assert repaired=={'status':'READY'}
    terminals=[t for c in res.report['witness_materialization']['cycles'] for t in c['certificate']['terminals']]
    exact=next(t for t in terminals if t['status']=='MATERIALIZED_EXACT')
    obs=next(o for o in exact['observations'] if o['qualifies'])
    assert obs['source_path']=='/state'
    assert obs['schema_version']==1


def test_two_distinct_authoritative_materializations_abstain():
    cfg=RepairConfig(json_schema=_required_schema(),source_context=(
        {'source_id':'a','role':'authoritative','value':{'x':1}},
        {'source_id':'b','role':'authoritative','value':{'x':2}},
    ),max_cycles=3,strong_fixed_point_cycles_required=1)
    repaired,res=repair_object({},cfg)
    assert repaired=={}
    statuses=[t['status'] for c in res.report['witness_materialization']['cycles'] for t in c['certificate']['terminals']]
    assert 'MULTIPLE_MATERIALIZATIONS_AMBIGUOUS' in statuses
    assert not res.report['committed_edits']


def test_ineligible_source_is_source_gate_not_absence():
    cfg=RepairConfig(json_schema=_required_schema(),
                     source_context=({'source_id':'a','role':'authoritative','eligible':False,'value':{'x':1}},),
                     max_cycles=2,strong_fixed_point_cycles_required=1)
    _,res=repair_object({},cfg)
    statuses=[t['status'] for c in res.report['witness_materialization']['cycles'] for t in c['certificate']['terminals']]
    assert 'SOURCE_GATE' in statuses
    assert 'ABSENT_CERTIFIED_WITHIN_SEARCH_CONTRACT' not in statuses


def test_loaded_search_exhaustion_is_bounded_absence_only():
    cfg=RepairConfig(json_schema=_required_schema(),source_context=(),max_cycles=2,strong_fixed_point_cycles_required=1)
    _,res=repair_object({},cfg)
    terms=[t for c in res.report['witness_materialization']['cycles'] for t in c['certificate']['terminals']]
    assert terms
    assert terms[0]['status']=='ABSENT_CERTIFIED_WITHIN_SEARCH_CONTRACT'
    assert terms[0]['absence_scope']=='LOADED_BOUNDED_SEARCH_CONTRACT_ONLY'
    assert res.report['witness_materialization']['cycles'][0]['certificate']['semantic_guards']['not_found_is_not_absent'] is True


def test_reference_source_can_select_inside_already_certified_finite_domain():
    root={'x':'WRONG'}
    issue=Issue('enum_domain','enum_domain_outlier','/x','outside domain','warning',False,{'domain':['A','B'],'domain_id':'d'})
    c1=Candidate('c1','enum_domain','replace','/x','WRONG','A','choice',1.0,1,('RULE',),{'formula':'enum-choice'})
    c2=Candidate('c2','enum_domain','replace','/x','WRONG','B','choice',1.0,1,('RULE',),{'formula':'enum-choice'})
    analysis=AnalysisResult([issue],[c1,c2],[])
    cfg=RepairConfig(source_context=({'source_id':'ref','role':'reference','value':{'x':'B'},'independent_group':'ref-g'},))
    additions,cert=materialize_missing_witnesses(root,analysis,cfg)
    term=cert['terminals'][0]
    assert term['witness_kind']=='AUTHORITATIVE_SELECTOR'
    assert term['status']=='MATERIALIZED_EXACT'
    assert additions.candidates and additions.candidates[0].new_value=='B'
    assert additions.candidates[0].metadata['constraint_source']=='derived_exact'


def test_previous_source_remains_observer_without_explicit_witness_authorization():
    cfg=RepairConfig(json_schema=_required_schema(),
                     source_context=({'source_id':'prev','role':'previous','value':{'x':9}},),max_cycles=2,strong_fixed_point_cycles_required=1)
    repaired,res=repair_object({},cfg)
    assert repaired=={}
    statuses=[t['status'] for c in res.report['witness_materialization']['cycles'] for t in c['certificate']['terminals']]
    assert 'MATERIAL_GATE' in statuses


def test_explicit_materialization_hint_can_bridge_nonidentical_path():
    manifest={'materialization_hints':[{'target_path':'/x','source_id':'auth','source_path':'/legacy/value','mode':'AUTHORITATIVE'}]}
    cfg=RepairConfig(json_schema=_required_schema(),
                     source_context=({'source_id':'auth','role':'reference','value':{'legacy':{'value':13}}},),
                     source_manifest=manifest,max_cycles=5,strong_fixed_point_cycles_required=1)
    repaired,res=repair_object({},cfg)
    assert repaired=={'x':13}
    exact=next(t for c in res.report['witness_materialization']['cycles'] for t in c['certificate']['terminals'] if t['status']=='MATERIALIZED_EXACT')
    assert any(o['source_path']=='/legacy/value' and o['qualifies'] for o in exact['observations'])


def test_materialization_tamper_is_rejected_by_independent_certifier():
    cfg=RepairConfig(json_schema=_required_schema(),source_context=({'source_id':'auth','role':'authoritative','value':{'x':7}},),
                     max_cycles=5,strong_fixed_point_cycles_required=1)
    repaired,res=repair_object({},cfg)
    report=deepcopy(res.report)
    report['witness_materialization']['cycles'][0]['certificate']['terminals'][0]['selected_value_digest']='0'*64
    verdict=verify_single_packet({},repaired,report['committed_edits'],report)
    assert verdict['status']=='REJECTED'
    assert verdict['checks']['witness_materialization'] is False


def test_bundle_local_materialization_is_committed_and_proof_replayed():
    cfg=RepairConfig(json_schema=_required_schema(),
                     source_context=({'source_id':'auth','role':'authoritative','document':'a.json','value':{'x':5}},),
                     max_cycles=4,strong_fixed_point_cycles_required=1)
    repaired,res=repair_bundle({'a.json':{}},cfg)
    assert repaired['a.json']=={'x':5}
    assert res.report['witness_materialization']['cycles']
    assert res.report['proof_graph_replay']['status']=='PROOF_GRAPH_REPLAY_EXACT'
    assert res.report['final_certification']['status']=='CERTIFIED'


def test_streaming_record_bridge_materializes_missing_witness(tmp_path):
    src=tmp_path/'in.jsonl'; out=tmp_path/'out.jsonl'
    src.write_text(json.dumps({'y':1})+'\n'+json.dumps({'y':2})+'\n',encoding='utf-8')
    cfg=StreamingConfig(exact_disk_registry=True,json_schema=_required_schema(),
                        source_context=({'source_id':'auth','role':'authoritative','value':{'x':11}},),
                        max_cycles=3,strong_fixed_point_cycles_required=1)
    res=repair_stream_file(src,out,None,cfg,stream_format='jsonl')
    rows=[json.loads(x) for x in out.read_text(encoding='utf-8').splitlines()]
    assert rows==[{'x':11,'y':1},{'x':11,'y':2}]
    wm=res.report['witness_materialization']
    assert wm['final']['totals'].get('MATERIALIZED_EXACT',0)>0
    assert wm['final']['proof_samples']
    assert res.report['proof_graph_replay']['status']=='PROOF_GRAPH_REPLAY_EXACT'
    assert res.report['final_certification']['status']=='CERTIFIED'
