from __future__ import annotations
from copy import deepcopy
from pathlib import Path
import json

from json_consistency_repair import (
    RepairConfig, StreamingConfig, analyze_multisource, repair_bundle, repair_stream_file,
    compile_authority_registry, evaluate_authority, verify_authority_registry, verify_authority_proof,
)


def _rows():
    return [
        {'code':'A','name':'alpha'},{'code':'A','name':'alpha'},
        {'code':'B','name':'beta'},{'code':'B','name':'beta'},
        {'code':'C','name':'gamma'},{'code':'C','name':'gamma'},
    ]


def test_direct_authority_is_path_scoped_before_candidate_creation():
    src={'source_id':'auth','role':'authoritative','value':{'pricing':{'tax':0.2},'identity':{'name':'CANON'}},
         'authority_scope':{'paths':['/pricing'],'operations':['replace','add','witness']}}
    manifest={'authoritative_values':[
        {'source_id':'auth','source_path':'/pricing/tax','target_path':'/pricing/tax'},
        {'source_id':'auth','source_path':'/identity/name','target_path':'/identity/name'},
    ]}
    analysis,cert=analyze_multisource({'pricing':{'tax':0.1},'identity':{'name':'local'}},RepairConfig(source_context=(src,),source_manifest=manifest))
    assert [(c.path,c.new_value) for c in analysis.candidates]==[('/pricing/tax',0.2)]
    assert any(x['kind']=='AUTHORITATIVE_VALUE_SCOPE_GATE' and x['path']=='/identity/name' for x in cert['assimilation']['gated_actions'])
    assert cert['authority_scope_registry']['contract']=='json-consistency-repair.scoped-authority.v1'


def test_operation_scope_blocks_replace_but_allows_add():
    src={'source_id':'a','role':'authoritative','value':{'x':7},'authority_scope':{'paths':['/x'],'operations':['add']}}
    reg=compile_authority_registry({},(src,),{})
    assert evaluate_authority(reg,'a',target_path='/x',operation='add')['authorized']
    denied=evaluate_authority(reg,'a',target_path='/x',operation='replace')
    assert not denied['authorized'] and denied['reason']=='OPERATION_OUT_OF_SCOPE'


def test_schema_version_scope_is_exact():
    src={'source_id':'a','role':'authoritative','value':{'x':7},'authority_scope':{'paths':['/x'],'schema_versions':['1'],'operations':['replace']}}
    reg=compile_authority_registry({'schema_version':2,'x':0},(src,),{})
    pr=evaluate_authority(reg,'a',target_path='/x',operation='replace')
    assert not pr['authorized'] and pr['reason']=='SCHEMA_VERSION_OUT_OF_SCOPE'


def test_temporal_authority_needs_explicit_evaluation_time_and_window():
    src={'source_id':'a','role':'authoritative','value':{'x':7},'authority_scope':{'paths':['/x'],'operations':['replace'],
         'valid_from':'2026-01-01T00:00:00Z','valid_until':'2026-06-01T00:00:00Z'}}
    no_clock=compile_authority_registry({'x':0},(src,),{})
    assert evaluate_authority(no_clock,'a',target_path='/x',operation='replace')['reason']=='TEMPORAL_SCOPE_REQUIRES_EVALUATION_TIME'
    inside=compile_authority_registry({'x':0},(src,),{'evaluation_time':'2026-03-01T00:00:00Z'})
    assert evaluate_authority(inside,'a',target_path='/x',operation='replace')['authorized']
    expired=compile_authority_registry({'x':0},(src,),{'evaluation_time':'2026-08-01T00:00:00Z'})
    assert evaluate_authority(expired,'a',target_path='/x',operation='replace')['reason']=='AUTHORITY_EXPIRED'


def test_delegated_authority_can_be_narrower_than_grantor():
    ctx=(
        {'source_id':'root','role':'authoritative','value':{},'authority_scope':{'paths':['/pricing'],'operations':['replace','add','witness']}},
        {'source_id':'delegate','role':'reference','value':{'v':7}},
    )
    manifest={'delegations':[{'delegation_id':'d1','grantor_source_id':'root','delegate_source_id':'delegate',
                              'scope':{'paths':['/pricing/tax'],'operations':['replace','add','witness']}}],
              'authoritative_values':[{'source_id':'delegate','source_path':'/v','target_path':'/pricing/tax'}]}
    analysis,cert=analyze_multisource({'pricing':{'tax':0}},RepairConfig(source_context=ctx,source_manifest=manifest))
    assert len(analysis.candidates)==1 and analysis.candidates[0].new_value==7
    proof=analysis.candidates[0].metadata['authority_proof']
    assert proof['reason']=='DELEGATED_SCOPE_MATCH'
    assert [x['kind'] for x in proof['delegation_chain']]==['DIRECT','DELEGATION']
    assert verify_authority_proof(proof,cert['authority_scope_registry'])


def test_revoked_delegation_cannot_mutate():
    ctx=(
        {'source_id':'root','role':'authoritative','value':{},'authority_scope':{'paths':['/x'],'operations':['replace']}},
        {'source_id':'delegate','role':'reference','value':{'v':7}},
    )
    manifest={'delegations':[{'delegation_id':'d1','grantor_source_id':'root','delegate_source_id':'delegate','scope':{'paths':['/x'],'operations':['replace']}}],
              'revocations':['d1'],'authoritative_values':[{'source_id':'delegate','source_path':'/v','target_path':'/x'}]}
    analysis,cert=analyze_multisource({'x':0},RepairConfig(source_context=ctx,source_manifest=manifest))
    assert not analysis.candidates
    assert any(x['reason']=='NO_DIRECT_AUTHORITY' for x in cert['assimilation']['gated_actions'])


def test_chained_delegation_is_bounded_and_exact():
    ctx=(
        {'source_id':'root','role':'authoritative','value':{},'authority_scope':{'paths':['/x'],'operations':['replace']}},
        {'source_id':'mid','role':'reference','value':{}},
        {'source_id':'leaf','role':'reference','value':{'x':3}},
    )
    manifest={'delegations':[
        {'delegation_id':'d1','grantor_source_id':'root','delegate_source_id':'mid','scope':{'paths':['/x'],'operations':['replace']}},
        {'delegation_id':'d2','grantor_source_id':'mid','delegate_source_id':'leaf','scope':{'paths':['/x'],'operations':['replace']}},
    ]}
    reg=compile_authority_registry({'x':0},ctx,manifest)
    proof=evaluate_authority(reg,'leaf',target_path='/x',operation='replace')
    assert proof['authorized'] and [x.get('delegation_id') for x in proof['delegation_chain'][1:]]==['d1','d2']


def test_provenance_lineage_prevents_false_heldout_promotion():
    ctx=(
        {'source_id':'dev','role':'development','value':{'rows':_rows()},'independent_group':'train'},
        {'source_id':'hold','role':'heldout','value':{'rows':_rows()},'independent_group':'hold','provenance':{'parents':['dev']}},
    )
    _,cert=analyze_multisource({'rows':[{'code':'B','name':'WRONG'}]},RepairConfig(source_context=ctx,source_min_support=4,source_min_group_support=1))
    life=cert['relation_lifecycle']
    assert life['dependent_only']>=1 and life['heldout_confirmed']==0
    findings=cert['evidence_poisoning_firewall']['findings']
    assert any(x['code']=='DERIVATION_FALSE_INDEPENDENCE' for x in findings)


def test_identical_content_strict_policy_collapses_false_independence():
    ctx=(
        {'source_id':'dev','role':'development','value':{'rows':_rows()},'independent_group':'train'},
        {'source_id':'hold','role':'heldout','value':{'rows':_rows()},'independent_group':'hold'},
    )
    manifest={'evidence_policy':{'identical_content_is_correlated':True}}
    _,cert=analyze_multisource({'rows':[{'code':'B','name':'WRONG'}]},RepairConfig(source_context=ctx,source_manifest=manifest,source_min_support=4,source_min_group_support=1))
    assert cert['relation_lifecycle']['dependent_only']>=1
    assert any(x['code']=='IDENTICAL_CONTENT_FALSE_INDEPENDENCE' for x in cert['evidence_poisoning_firewall']['findings'])


def test_identical_content_is_flagged_but_not_silently_collapsed_by_default():
    ctx=(
        {'source_id':'dev','role':'development','value':{'rows':_rows()},'independent_group':'train'},
        {'source_id':'hold','role':'heldout','value':{'rows':_rows()},'independent_group':'hold'},
    )
    _,cert=analyze_multisource({'rows':[{'code':'B','name':'WRONG'}]},RepairConfig(source_context=ctx,source_min_support=4,source_min_group_support=1))
    assert cert['relation_lifecycle']['heldout_confirmed']>=1
    assert any(x['code']=='IDENTICAL_CONTENT_POTENTIAL_CORRELATION' and not x['collapsed'] for x in cert['evidence_poisoning_firewall']['findings'])


def test_reference_authority_scope_cannot_self_escalate_without_delegation():
    src={'source_id':'r','role':'reference','value':{'x':9},'authority_scope':{'paths':['/x'],'operations':['replace']}}
    manifest={'authoritative_values':[{'source_id':'r','source_path':'/x','target_path':'/x'}]}
    analysis,cert=analyze_multisource({'x':0},RepairConfig(source_context=(src,),source_manifest=manifest))
    assert not analysis.candidates
    assert cert['assimilation']['gated_actions'][0]['reason']=='NO_DIRECT_AUTHORITY'


def test_manifest_authoritative_hint_is_a_narrow_scoped_grant_not_global_escalation():
    src={'source_id':'r','role':'reference','value':{'legacy':7,'other':8}}
    manifest={'materialization_hints':[{'target_path':'/x','source_id':'r','source_path':'/legacy','mode':'AUTHORITATIVE'}]}
    reg=compile_authority_registry({},(src,),manifest)
    assert evaluate_authority(reg,'r',target_path='/x',operation='add')['authorized']
    assert not evaluate_authority(reg,'r',target_path='/y',operation='add')['authorized']


def test_bundle_document_scope_applies_only_to_named_document():
    docs={'a.json':{'x':0},'b.json':{'x':0}}
    src={'source_id':'a','role':'authoritative','value':{'x':7},
         'authority_scope':{'paths':['/x'],'documents':['a.json'],'operations':['replace']}}
    manifest={'authoritative_values':[{'source_id':'a','source_path':'/x','target_path':'/x'}]}
    out,res=repair_bundle(docs,RepairConfig(source_context=(src,),source_manifest=manifest,max_cycles=4,strong_fixed_point_cycles_required=1,enable_final_certification=False))
    assert out['a.json']['x']==7 and out['b.json']['x']==0
    assert res.report['scoped_authority']['mode']=='bundle'


def test_stream_record_bridge_respects_scoped_authority(tmp_path:Path):
    inp=tmp_path/'in.jsonl'; out=tmp_path/'out.jsonl'
    inp.write_text(json.dumps({'status':'OLD'})+'\n',encoding='utf-8')
    src={'source_id':'a','role':'authoritative','value':{'status':'NEW'},
         'authority_scope':{'paths':['/status'],'operations':['replace','add']}}
    manifest={'authoritative_values':[{'source_id':'a','source_path':'/status','target_path':'/status'}]}
    res=repair_stream_file(inp,out,config=StreamingConfig(source_context=(src,),source_manifest=manifest,max_cycles=3,enable_final_certification=False))
    assert json.loads(out.read_text(encoding='utf-8'))['status']=='NEW'
    assert res.report['scoped_authority']['mode']=='streaming'
    assert res.report['record_bridge_execution']['authority_registry_samples']


def test_registry_and_proof_hash_tampering_is_rejected():
    src={'source_id':'a','role':'authoritative','value':{'x':1},'authority_scope':{'paths':['/x'],'operations':['replace']}}
    reg=compile_authority_registry({'x':0},(src,),{})
    proof=evaluate_authority(reg,'a',target_path='/x',operation='replace')
    assert verify_authority_registry(reg) and verify_authority_proof(proof,reg)
    bad=deepcopy(reg); bad['sources'][0]['authority_scopes'][0]['paths']=['/other']
    assert not verify_authority_registry(bad)
    badp=deepcopy(proof); badp['authorized']=False
    assert not verify_authority_proof(badp,reg)
