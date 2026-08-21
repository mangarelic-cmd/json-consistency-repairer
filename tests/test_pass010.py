from __future__ import annotations
import json
from pathlib import Path
import tomllib

from json_consistency_repair import (
    __version__, IdentifiabilityState, ObservabilityState,
    compile_typed_constraint_ir,
)
from json_consistency_repair.analyzers import analyze_all
from json_consistency_repair.engine import RepairConfig


def cfg(**kw):
    d=dict(min_support=4,min_group_support=2,relation_confidence=.80,
           arithmetic_confidence=.80,arithmetic_direction_confidence=.90,
           required_key_confidence=.85,enum_confidence=.80,enum_min_value_support=2,
           enum_normalization_confidence=.75,reference_confidence=.75,
           id_uniqueness_confidence=.75)
    d.update(kw); return RepairConfig(**d)


def entry(ir,path):
    xs=[x for x in ir['identifiability_registry'] if x['path']==path]
    assert xs, path
    return xs[0]


def test_contract_enums_are_exact():
    assert {x.value for x in IdentifiabilityState} == {'UNIQUE','MULTIPLE','NONE','INSUFFICIENT'}
    assert {x.value for x in ObservabilityState} == {'OBSERVED_VALUE','OBSERVED_NULL','UNOBSERVED','BOUNDED_UNMATERIALIZED'}


def test_singleton_enum_domain_makes_outlier_unique_without_inventing_new_domain():
    rows=[{'id':i,'status':'ready'} for i in range(10)] + [{'id':10,'status':'mystery'}]
    data={'rows':rows}; a=analyze_all(data,cfg())
    ir=compile_typed_constraint_ir(data,a)
    e=entry(ir,'/rows/10/status')
    assert e['identifiability']=='UNIQUE'
    assert e['solution_count']==1
    assert e['unique_solution_digest']
    assert e['minimal_missing_witness'] is None


def test_multi_member_enum_domain_is_multiple_and_requests_one_selector():
    rows=[]
    for i in range(12): rows.append({'id':i,'status':'ready' if i%2==0 else 'done'})
    rows.append({'id':12,'status':'mystery'})
    data={'rows':rows}; ir=compile_typed_constraint_ir(data,analyze_all(data,cfg()))
    e=entry(ir,'/rows/12/status')
    assert e['identifiability']=='MULTIPLE'
    assert e['solution_count']==2
    assert e['minimal_missing_witness']['cardinality']==1
    assert e['minimal_missing_witness']['kind']=='AUTHORITATIVE_SELECTOR'


def test_two_certified_functional_constraints_with_empty_intersection_are_none():
    rows=[]
    # det1=A -> x, det2=X -> x ; det1=B -> y, det2=Y -> y
    for i in range(6): rows.append({'d1':'A','d2':'X','label':'x'})
    for i in range(6): rows.append({'d1':'B','d2':'Y','label':'y'})
    # Cross-combination contradicts both certified FDs in opposite ways.
    rows.append({'d1':'A','d2':'Y','label':'bad'})
    data={'rows':rows}; ir=compile_typed_constraint_ir(data,analyze_all(data,cfg(relation_confidence=.75)))
    e=entry(ir,'/rows/12/label')
    assert e['identifiability']=='NONE'
    assert e['solution_count']==0
    assert e['minimal_missing_witness']['kind']=='CONSTRAINT_REVISION_OR_SOURCE_CORRECTION'


def test_required_free_value_is_insufficient_and_names_minimal_witness():
    rows=[{'id':i,'name':f'n{i}'} for i in range(10)]
    del rows[9]['name']
    data={'rows':rows}; ir=compile_typed_constraint_ir(data,analyze_all(data,cfg()))
    e=entry(ir,'/rows/9/name')
    assert e['observability']=='UNOBSERVED'
    assert e['identifiability']=='INSUFFICIENT'
    assert e['solution_count'] is None
    assert e['minimal_missing_witness']['kind']=='AUTHORITATIVE_VALUE_OR_DEFAULT'
    assert e['minimal_missing_witness']['cardinality']==1


def test_arithmetic_unique_value_without_direction_anchor_is_still_insufficient():
    rows=[]
    for i in range(12):
        # Put total before sources so JSON key order cannot act as the weak direction witness.
        rows.append({'total':i+2,'a':i,'b':2})
    rows[11]['total']=999
    data={'rows':rows}; ir=compile_typed_constraint_ir(data,analyze_all(data,cfg(arithmetic_confidence=.75)))
    e=entry(ir,'/rows/11/total')
    assert e['identifiability']=='INSUFFICIENT'
    assert e['direction_blocked_candidate_ids']
    assert e['minimal_missing_witness']['kind']=='INDEPENDENT_DIRECTION_ANCHOR'


def test_null_and_missing_are_observationally_distinct():
    rows=[]
    for i in range(12):
        kind='A' if i<6 else 'B'
        rows.append({'id':i,'kind':kind,'name':'x' if kind=='A' else 'y'})
    rows[4]['name']=None
    del rows[10]['name']
    data={'rows':rows}; ir=compile_typed_constraint_ir(data,analyze_all(data,cfg()))
    e4=entry(ir,'/rows/4/name'); e10=entry(ir,'/rows/10/name')
    assert e4['observability']=='OBSERVED_NULL'
    assert e10['observability']=='UNOBSERVED'


def test_bundle_dangling_reference_has_finite_multiple_target_domain():
    from json_consistency_repair.bundle import repair_bundle
    users={'users':[{'id':f'U{i}'} for i in range(8)]}
    orders={'orders':[{'id':100+i,'user_id':f'U{i}'} for i in range(8)]}
    orders['orders'][7]['user_id']='MISSING'
    _,res=repair_bundle({'users.json':users,'orders.json':orders},cfg())
    xs=[x for x in res.report['typed_constraint_ir']['cross_document_identifiability_registry']
        if x['document']=='orders.json' and x['path']=='/orders/7/user_id']
    assert xs
    e=xs[0]
    assert e['identifiability']=='MULTIPLE'
    assert e['solution_count']==8
    assert e['minimal_missing_witness']['kind']=='AUTHORITATIVE_SELECTOR'


def test_stream_bounded_unknown_names_materialization_witness(tmp_path):
    from json_consistency_repair.streaming import StreamingConfig, repair_stream_file
    p=tmp_path/'x.jsonl'; o=tmp_path/'o.jsonl'
    rows=[{'kind':'A','name':'x'} for _ in range(12)]
    rows[-1].pop('name')
    p.write_text('\n'.join(json.dumps(x) for x in rows)+'\n',encoding='utf-8')
    res=repair_stream_file(p,o,config=StreamingConfig(min_support=4,required_key_confidence=.80,issue_sample_limit=4))
    reg=res.report['typed_constraint_ir']['identifiability_registry']
    assert reg
    bad=[x for x in reg if x['identifiability']=='INSUFFICIENT']
    assert bad
    assert bad[0]['observability']=='BOUNDED_UNMATERIALIZED'
    assert bad[0]['minimal_missing_witness']['kind']=='MATERIALIZE_RECORD_OR_SUPPLY_WITNESS'


def test_pass010_version_reconciled_and_v2_schema_exists():
    root=Path(__file__).resolve().parents[1]
    project=tomllib.loads((root/'pyproject.toml').read_text(encoding='utf-8'))
    assert __version__==project['project']['version']
    schema=json.loads((root/'schemas'/'typed-constraint-ir-v2.schema.json').read_text(encoding='utf-8'))
    assert schema['$id']=='json-consistency-repair.typed-constraint-ir.v2'
