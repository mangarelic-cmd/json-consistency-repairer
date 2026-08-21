from __future__ import annotations
import json
from pathlib import Path
import tomllib

from json_consistency_repair import Truth3, __version__, compile_typed_constraint_ir
from json_consistency_repair.analyzers import analyze_all
from json_consistency_repair.engine import RepairConfig, repair_object


def cfg(**kw):
    base=dict(min_support=4,min_group_support=2,relation_confidence=.80,
              arithmetic_confidence=.80,required_key_confidence=.90,
              enum_confidence=.85,enum_normalization_confidence=.75,
              reference_confidence=.80,id_uniqueness_confidence=.80)
    base.update(kw); return RepairConfig(**base)


def test_truth3_is_exact_three_state_contract():
    assert {x.value for x in Truth3} == {'TRUE','FALSE','UNKNOWN'}


def test_typed_ir_distinguishes_false_defect_from_unknown_reconstruction():
    rows=[{'id':i,'name':f'n{i}'} for i in range(10)]
    del rows[9]['name']
    data={'rows':rows}
    a=analyze_all(data,cfg())
    ir=compile_typed_constraint_ir(data,a)
    ts=[t for t in ir['terminal_registry'] if t['path']=='/rows/9/name']
    assert ts
    t=ts[0]
    assert t['satisfaction_truth']=='FALSE'
    assert t['reconstruction_truth']=='UNKNOWN'
    assert t['repairable'] is False
    assert t['terminal_id'] in ir['unresolved_terminal_ids']


def test_typed_ir_marks_exact_reconstruction_true_when_candidate_exists():
    rows=[]
    for i in range(12):
        kind='A' if i<6 else 'B'
        rows.append({'id':i,'kind':kind,'label':'x' if kind=='A' else 'y'})
    rows[5]['label']='bad'
    data={'rows':rows}
    a=analyze_all(data,cfg())
    ir=compile_typed_constraint_ir(data,a)
    ts=[t for t in ir['terminal_registry'] if t['path']=='/rows/5/label' and t['analyzer']=='functional_relation']
    assert ts and ts[0]['reconstruction_truth']=='TRUE'
    assert ts[0]['candidate_ids']


def test_typed_ir_nodes_are_deterministic_and_cover_root():
    data={'b':[1,2], 'a':{'x':True}}
    a=analyze_all(data,cfg())
    ir1=compile_typed_constraint_ir(data,a); ir2=compile_typed_constraint_ir(data,a)
    assert ir1==ir2
    paths={n['path'] for n in ir1['object_nodes']}
    assert {'','/a','/a/x','/b','/b/0','/b/1'} <= paths
    assert ir1['root_digest']==ir2['root_digest']


def test_repair_report_embeds_terminal_registry_for_final_state():
    rows=[]
    for i in range(12):
        kind='A' if i<6 else 'B'
        rows.append({'id':i,'kind':kind,'label':'x' if kind=='A' else 'y'})
    rows[5]['label']='bad'
    out,res=repair_object({'rows':rows},cfg())
    assert out['rows'][5]['label']=='x'
    ir=res.report['typed_constraint_ir']
    assert ir['root_digest']==res.output_digest
    assert res.report['terminal_registry']==ir['terminal_registry']
    assert res.report['truth_summary']==ir['truth_summary']
    # final repaired state must no longer expose that terminal
    assert not any(t['path']=='/rows/5/label' and t['analyzer']=='functional_relation' for t in ir['terminal_registry'])


def test_pass009_version_reconciled():
    root=Path(__file__).resolve().parents[1]
    project=tomllib.loads((root/'pyproject.toml').read_text(encoding='utf-8'))
    assert __version__==project['project']['version']


def test_bundle_ir_qualifies_local_and_cross_document_terminals():
    from json_consistency_repair.bundle import repair_bundle
    users={'users':[{'id':f'U{i}'} for i in range(10)]}
    orders={'orders':[{'id':100+i,'user_id':f'U{i}'} for i in range(10)]}
    orders['orders'][9]['user_id']='NO_SUCH_USER'
    out,res=repair_bundle({'users.json':users,'orders.json':orders},cfg())
    ir=res.report['typed_constraint_ir']
    assert ir['mode']=='bundle' and ir['materialization_scope']=='FULL'
    assert any(t.get('document')=='orders.json' for t in ir['terminal_registry'])
    assert res.report['terminal_registry']==ir['terminal_registry']
    assert any(c['kind']=='foreign_reference_cross_document' for c in ir['cross_document_constraints'])


def test_stream_ir_is_bounded_and_does_not_claim_unseen_terminals_materialized(tmp_path):
    from json_consistency_repair.streaming import StreamingConfig, repair_stream_file
    p=tmp_path/'x.jsonl'; o=tmp_path/'o.jsonl'
    rows=[{'kind':'A' if i<10 else 'B','label':'x' if i<10 else 'y'} for i in range(20)]
    # irreparable required-field absence samples create UNKNOWN reconstruction terminals.
    for i in range(18,20): rows[i].pop('label')
    p.write_text('\n'.join(json.dumps(x) for x in rows)+'\n',encoding='utf-8')
    res=repair_stream_file(p,o,config=StreamingConfig(min_support=4,required_key_confidence=.80,issue_sample_limit=1))
    ir=res.report['typed_constraint_ir']
    assert ir['mode']=='streaming' and ir['materialization_scope']=='BOUNDED_STREAM'
    assert ir['observed_terminal_count']>=ir['materialized_terminal_sample_count']
    assert ir['unmaterialized_terminal_count']>=0
    if ir['unmaterialized_terminal_count']:
        assert ir['truth_summary']['UNKNOWN']>=ir['unmaterialized_terminal_count']


def test_typed_ir_schema_file_is_valid_json_and_names_contract():
    root=Path(__file__).resolve().parents[1]
    obj=json.loads((root/'schemas'/'typed-constraint-ir-v1.schema.json').read_text(encoding='utf-8'))
    assert obj['$id']=='json-consistency-repair.typed-constraint-ir.v1'
    assert obj['type']=='object'
