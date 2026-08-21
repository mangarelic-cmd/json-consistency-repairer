from __future__ import annotations
import json, subprocess, sys
from copy import deepcopy
from pathlib import Path

from json_consistency_repair import RepairConfig, repair_object
from json_consistency_repair.multisource import analyze_multisource, source_registry, compile_identity_registry


def cfg(context, manifest=None, **kw):
    base=dict(max_cycles=5,strong_fixed_point_cycles_required=2,source_context=tuple(context),source_manifest=manifest or {},source_min_support=4,source_min_group_support=1)
    base.update(kw); return RepairConfig(**base)


def rows(field='code', target='name'):
    return [{field:'A',target:'alpha'},{field:'A',target:'alpha'},{field:'B',target:'beta'},{field:'B',target:'beta'},{field:'C',target:'gamma'},{field:'C',target:'gamma'}]


def test_defaults_fill_missing_only_and_cold_replay():
    c=[{'source_id':'d','role':'defaults','value':{'country':'CA'}}]
    out,res=repair_object({'name':'Alice'},cfg(c))
    assert out=={'name':'Alice','country':'CA'}
    assert res.report['final_certification']['ok'] is True
    assert res.report['cold_replay']['would_commit_edits']==0
    ms=res.report['multisource_assimilation']['final']
    assert ms['source_registry']['source_count']==2


def test_defaults_never_override_observed_current():
    c=[{'source_id':'d','role':'defaults','value':{'country':'CA'}}]
    out,res=repair_object({'country':'US'},cfg(c))
    assert out['country']=='US' and res.committed_edits==0


def test_explicit_authoritative_source_can_override_frozen_path():
    c=[{'source_id':'master','role':'authoritative','value':{'region':'CA'}}]
    m={'authoritative_values':[{'source_id':'master','source_path':'/region','target_path':'/region'}]}
    out,res=repair_object({'region':'US'},cfg(c,m))
    assert out['region']=='CA'
    assert any(x['candidate']['analyzer']=='multisource_authority' for cy in res.report['cycles'] for x in cy['accepted'])


def test_equal_authoritative_sources_conflict_and_abstain():
    c=[{'source_id':'a','role':'authoritative','value':{'x':1}},{'source_id':'b','role':'authoritative','value':{'x':2}}]
    m={'authoritative_values':[{'source_id':'a','path':'/x'},{'source_id':'b','path':'/x'}]}
    out,res=repair_object({'x':0},cfg(c,m))
    assert out['x']==0
    assert any(i['code']=='authority_conflict' for i in res.report['remaining_issues'])


def test_previous_is_observer_only():
    c=[{'source_id':'prev','role':'previous','value':{'x':9,'legacy':3}}]
    out,res=repair_object({'x':1},cfg(c))
    assert out=={'x':1}
    a=res.report['multisource_assimilation']['final']['assimilation']
    assert a['historical_observation_count']==2


def test_independent_heldout_promotes_functional_relation_and_repairs_primary():
    dev={'source_id':'dev','role':'development','value':{'rows':rows()},'independent_group':'train'}
    hold={'source_id':'hold','role':'heldout','value':{'rows':rows()},'independent_group':'hold1'}
    primary={'rows':[{'code':'A','name':'alpha'},{'code':'B','name':'WRONG'},{'code':'C','name':'gamma'}]}
    out,res=repair_object(primary,cfg([dev,hold],min_support=10))
    assert out['rows'][1]['name']=='beta'
    life=res.report['multisource_assimilation']['final']['relation_lifecycle']
    assert life['heldout_confirmed']>=1


def test_independent_counterexample_refutes_global_relation():
    dev={'source_id':'dev','role':'development','value':{'rows':rows()},'independent_group':'train'}
    bad=rows(); bad[-1]['name']='NOT_GAMMA'
    hold={'source_id':'hold','role':'heldout','value':{'rows':bad},'independent_group':'hold1'}
    primary={'rows':[{'code':'A','name':'alpha'},{'code':'B','name':'WRONG'},{'code':'C','name':'gamma'}]}
    out,res=repair_object(primary,cfg([dev,hold],min_support=10))
    assert out['rows'][1]['name']=='WRONG'
    life=res.report['multisource_assimilation']['final']['relation_lifecycle']
    assert life['global_refuted']>=1
    assert any(i['code']=='global_relation_refuted' for i in res.report['remaining_issues'])


def test_same_independence_group_does_not_count_as_heldout():
    dev={'source_id':'dev','role':'development','value':{'rows':rows()},'independent_group':'same'}
    hold={'source_id':'hold','role':'heldout','value':{'rows':rows()},'independent_group':'same'}
    primary={'rows':[{'code':'A','name':'alpha'},{'code':'B','name':'WRONG'},{'code':'C','name':'gamma'}]}
    out,res=repair_object(primary,cfg([dev,hold],min_support=10))
    assert out['rows'][1]['name']=='WRONG'
    life=res.report['multisource_assimilation']['final']['relation_lifecycle']
    assert life['dependent_only']>=1


def test_two_independent_heldouts_make_relation_portable():
    dev={'source_id':'dev','role':'development','value':{'rows':rows()},'independent_group':'train'}
    h1={'source_id':'h1','role':'heldout','value':{'rows':rows()},'independent_group':'h1'}
    h2={'source_id':'h2','role':'heldout','value':{'rows':rows()},'independent_group':'h2'}
    _,cert=analyze_multisource({'rows':[{'code':'A','name':'alpha'},{'code':'B','name':'beta'},{'code':'C','name':'gamma'}]},cfg([dev,h1,h2],min_support=10))
    assert cert['relation_lifecycle']['portable']>=1


def test_identity_bridge_allows_cross_version_heldout_validation():
    devrows=rows('state','label_old')
    holdrows=rows('status','label')
    dev={'source_id':'dev','role':'development','value':{'rows':devrows},'independent_group':'train'}
    hold={'source_id':'hold','role':'heldout','value':{'rows':holdrows},'independent_group':'h1'}
    manifest={'identity_bridges':[
        {'logical_id':'status','canonical_field':'status','members':[{'source_id':'dev','field':'state'},{'source_id':'hold','field':'status'},{'source_id':'__primary__','field':'status'}]},
        {'logical_id':'label','canonical_field':'label','members':[{'source_id':'dev','field':'label_old'},{'source_id':'hold','field':'label'},{'source_id':'__primary__','field':'label'}]},
    ]}
    primary={'rows':[{'status':'A','label':'alpha'},{'status':'B','label':'WRONG'},{'status':'C','label':'gamma'}]}
    out,res=repair_object(primary,cfg([dev,hold],manifest,min_support=10))
    assert out['rows'][1]['label']=='beta'
    assert res.report['multisource_assimilation']['final']['identity_registry']['valid']


def test_event_log_projection_requires_explicit_authority():
    ev={'source_id':'events','role':'event_log','value':{'events':[{'path':'/status','value':'NEW'},{'path':'/status','value':'PAID'}]}}
    manifest={'projections':[{'kind':'last_event_value','source_id':'events','events_path':'/events','target_path':'/status','authoritative':True}]}
    out,res=repair_object({'status':'NEW'},cfg([ev],manifest))
    assert out['status']=='PAID'


def test_source_registry_and_identity_registry_are_deterministic():
    context=({'source_id':'x','role':'reference','value':{'a':1}},)
    m={'identity_bridges':[{'logical_id':'a','canonical_field':'a','members':[{'source_id':'x','field':'old_a'}]}]}
    a=source_registry({'z':1},context,m); b=source_registry({'z':1},context,m)
    assert a==b and a['registry_digest']==b['registry_digest']
    ia=compile_identity_registry(context,m); ib=compile_identity_registry(context,m)
    assert ia==ib


def test_cli_sources_manifest_relative_files(tmp_path:Path):
    inp=tmp_path/'current.json'; defaults=tmp_path/'defaults.json'; man=tmp_path/'sources.json'; out=tmp_path/'out.json'
    inp.write_text('{"name":"Alice"}',encoding='utf-8'); defaults.write_text('{"country":"CA"}',encoding='utf-8')
    man.write_text(json.dumps({'sources':[{'source_id':'d','role':'defaults','path':'defaults.json'}]}),encoding='utf-8')
    cp=subprocess.run([sys.executable,'-m','json_consistency_repair.cli',str(inp),'--sources-manifest',str(man),'-o',str(out),'--machine'],capture_output=True,text=True)
    assert cp.returncode==0,cp.stderr
    assert json.loads(out.read_text())['country']=='CA'

