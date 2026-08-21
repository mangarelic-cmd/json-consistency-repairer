from __future__ import annotations
import json
from pathlib import Path

from json_consistency_repair import RepairConfig, repair_object, parse_dsl
from json_consistency_repair.boundary import compile_boundary_registry
from json_consistency_repair.bundle import repair_bundle
from json_consistency_repair.streaming import StreamingConfig, repair_stream_file


def test_schema_inclusive_minimum_projects_to_unique_nearest_boundary():
    schema={'type':'object','properties':{'x':{'type':'number','minimum':0}}}
    out,res=repair_object({'x':-7},RepairConfig(json_schema=schema,schema_source='json_schema',max_cycles=5))
    assert out=={'x':0}
    assert res.report['boundary_calculus']['final']['registry']['boundary_count']>=1
    assert res.report['cold_replay']['would_commit_edits']==0


def test_schema_exclusive_boundary_abstains_no_fake_epsilon():
    schema={'type':'object','properties':{'x':{'type':'number','exclusiveMinimum':0}}}
    out,res=repair_object({'x':0},RepairConfig(json_schema=schema,max_cycles=4))
    assert out=={'x':0}
    assert any(i['code']=='schema_exclusive_minimum_violation' for i in res.report['remaining_issues'])


def test_schema_multipleof_unique_nearest_repairs_but_tie_abstains():
    schema={'type':'object','properties':{'x':{'type':'number','multipleOf':2}}}
    out,_=repair_object({'x':3.2},RepairConfig(json_schema=schema,max_cycles=5))
    assert out['x']==4
    tied,res=repair_object({'x':3},RepairConfig(json_schema=schema,max_cycles=4))
    assert tied['x']==3
    assert any(i['code']=='schema_multiple_of_violation' and not i['repairable'] for i in res.report['remaining_issues'])


def test_bounds_of_bounds_empty_interval_blocks_all_mutation():
    schema={'type':'object','properties':{'x':{'minimum':10,'maximum':2},'status':{'const':'ok'}}}
    out,res=repair_object({'x':5,'status':'bad'},RepairConfig(json_schema=schema,max_cycles=4))
    assert out=={'x':5,'status':'bad'}
    reg=res.report['boundary_calculus']['final']['registry']
    assert reg['bounds_of_bounds']['status']=='CONFLICT'
    assert reg['bounds_of_bounds']['conflict_count']>=1
    assert any(i['code']=='bounds_of_bounds_conflict' for i in res.report['remaining_issues'])


def test_boundary_firewall_blocks_other_authority_crossing_schema_maximum():
    schema={'type':'array','items':{'type':'object','properties':{'x':{'type':'number','maximum':10}}}}
    rules=({'kind':'const','array_path':'','field':'x','value':20,'rule_id':'dsl_x20'},)
    out,res=repair_object([{'x':5}],RepairConfig(json_schema=schema,constraint_rules=rules,record_carrier_mode=True,max_cycles=4))
    assert out==[{'x':5}]
    cycles=res.report['boundary_calculus']['cycles']
    assert any(x.get('rejected',0)>=1 for x in cycles)


def test_dependentrequired_uses_explicit_default_only():
    schema={'type':'object','properties':{'credit_card':{'type':'string'},'billing':{'type':'string','default':'UNKNOWN'}},
            'dependentRequired':{'credit_card':['billing']}}
    out,res=repair_object({'credit_card':'123'},RepairConfig(json_schema=schema,max_cycles=5))
    assert out['billing']=='UNKNOWN'
    assert res.final_status=='PASS'


def test_if_then_selects_only_active_branch():
    schema={'type':'object','properties':{'country':{'type':'string'},'postal':{'type':'string','default':'H0H0H0'}},
            'if':{'properties':{'country':{'const':'CA'}},'required':['country']},
            'then':{'required':['postal'],'properties':{'postal':{'type':'string','default':'H0H0H0'}}},
            'else':{'properties':{'postal':{'type':'string'}}}}
    out,_=repair_object({'country':'CA'},RepairConfig(json_schema=schema,max_cycles=5))
    assert out=={'country':'CA','postal':'H0H0H0'}


def test_anyof_and_oneof_are_diagnostic_when_branch_direction_not_unique():
    schema={'anyOf':[{'type':'string','pattern':'^A+$'},{'type':'integer','minimum':0}]}
    out,res=repair_object(False,RepairConfig(json_schema=schema,max_cycles=3))
    assert out is False
    assert any(i['code']=='schema_anyof_violation' for i in res.report['remaining_issues'])
    schema2={'oneOf':[{'type':'number'},{'minimum':0}]}
    out2,res2=repair_object(3,RepairConfig(json_schema=schema2,max_cycles=3))
    assert out2==3
    assert any(i['code']=='schema_oneof_violation' for i in res2.report['remaining_issues'])


def test_structural_boundaries_diagnose_without_destructive_guess():
    schema={'type':'object','properties':{
        's':{'type':'string','minLength':3,'maxLength':4,'pattern':'^[A-Z]+$'},
        'a':{'type':'array','minItems':2,'maxItems':3,'uniqueItems':True,'contains':{'const':9},'minContains':1},
    },'minProperties':2,'maxProperties':2}
    out,res=repair_object({'s':'ab','a':[1,1]},RepairConfig(json_schema=schema,max_cycles=3))
    assert out=={'s':'ab','a':[1,1]}
    codes={i['code'] for i in res.report['remaining_issues']}
    assert {'schema_min_length_violation','schema_pattern_violation','schema_unique_items_violation','schema_min_contains_violation'}<=codes


def test_prefixitems_propertynames_patternproperties_and_additionalproperties():
    schema={'type':'object','propertyNames':{'pattern':'^[a-z]+$'},'patternProperties':{'^v':{'type':'integer','minimum':0}},'additionalProperties':False}
    out,res=repair_object({'Value':1,'vbad':-1},RepairConfig(json_schema=schema,max_cycles=5))
    assert out['vbad']==0
    codes={i['code'] for i in res.report['remaining_issues']}
    assert 'schema_property_name_violation' in codes and 'schema_additional_property' in codes
    arr_schema={'type':'array','prefixItems':[{'const':'head'},{'type':'integer','minimum':0}],'items':False}
    arr,arrres=repair_object(['bad',-2,'extra'],RepairConfig(json_schema=arr_schema,max_cycles=5))
    # const/minimum are repaired, but forbidden tail remains an explicit non-destructive issue.
    assert arr[:2]==['head',0]
    assert any(i['code']=='schema_false_violation' for i in arrres.report['remaining_issues'])


def test_dsl_boundary_language_parses_and_repairs_numeric_projection():
    rules=parse_dsl('scope /rows\nminimum score 0\nmaximum score 100\nmultipleOf score 5\nmaxLength name 8\npattern code "^[A-Z]+$"\n')
    kinds={r['kind'] for r in rules}
    assert {'minimum','maximum','multipleOf','maxLength','pattern'}<=kinds
    out,_=repair_object({'rows':[{'score':-2,'name':'Alice','code':'ABC'}]},RepairConfig(constraint_rules=rules,max_cycles=5))
    assert out['rows'][0]['score']==0


def test_boundary_registry_detects_cardinality_bounds_of_bounds():
    schema={'type':'array','minItems':5,'maxItems':2}
    reg=compile_boundary_registry(schema,())
    assert reg['bounds_of_bounds']['conflict_count']==1
    assert reg['bounds_of_bounds']['conflicts'][0]['conflict']['kind']=='EMPTY_CARDINALITY_INTERVAL'


def test_bundle_emits_per_document_boundary_registry_and_enforces_projection():
    schema={'type':'object','properties':{'x':{'minimum':0}}}
    out,res=repair_bundle({'a.json':{'x':-1},'b.json':{'x':2}},RepairConfig(json_schema=schema,max_cycles=5))
    assert out['a.json']['x']==0 and out['b.json']['x']==2
    assert set(res.report['boundary_calculus']['documents'])=={'a.json','b.json'}


def test_stream_record_carrier_enforces_boundary_projection(tmp_path:Path):
    inp=tmp_path/'in.jsonl'; out=tmp_path/'out.jsonl'
    inp.write_text('{"x":-2}\n{"x":3}\n',encoding='utf-8')
    schema={'type':'object','properties':{'x':{'minimum':0}}}
    res=repair_stream_file(inp,out,config=StreamingConfig(json_schema=schema,exact_disk_registry=True,max_cycles=5))
    rows=[json.loads(x) for x in out.read_text().splitlines()]
    assert rows==[{'x':0},{'x':3}]
    assert res.report['boundary_calculus']['registry']['boundary_count']>=1
    assert res.report['cold_replay']['would_commit_edits']==0
