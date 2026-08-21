from __future__ import annotations
import json
from pathlib import Path

from json_consistency_repair import RepairConfig, repair_object, compile_third_series_closure
from json_consistency_repair.bundle import repair_bundle
from json_consistency_repair.streaming import StreamingConfig, discover_stream_knowledge, repair_stream_file


def _write_jsonl(path:Path, rows:list[dict]):
    path.write_text(''.join(json.dumps(x,separators=(',',':'))+'\n' for x in rows),encoding='utf-8')


def _mapping_rows(groups:int=10):
    rows=[]
    for i in range(groups):
        rows.extend([{'code':f'K{i}','name':f'N{i}'},{'code':f'K{i}','name':f'N{i}'}])
    return rows


def test_disk_registry_recovers_functional_relation_after_memory_overflow(tmp_path:Path):
    rows=_mapping_rows(); rows.append({'code':'K9','name':'BAD'})
    inp=tmp_path/'in.jsonl'; _write_jsonl(inp,rows)
    cfg=StreamingConfig(exact_disk_registry=True,max_functional_groups=3,min_functional_groups=2,
                        min_group_support=2,min_support=4,relation_confidence=.95,enable_final_certification=False)
    k=discover_stream_knowledge(inp,cfg,registry_dir=tmp_path/'registry')
    try:
        rel=next(r for r in k['relations'] if r['kind']=='functional_stream' and r['determinant']=='/code' and r['output']=='/name')
        assert k['bounded_state']['overflowed_functional_pairs']>0
        assert k['disk_registry_summary']['exact'] is True
        assert k['disk_registry_summary']['recovered_functional_pairs']>0
        assert rel['groups']==10 and rel['registry_storage']=='disk_exact'
    finally:
        if k.get('_disk_registry') is not None: k['_disk_registry'].close()


def test_disk_registry_repairs_overflowed_group_and_exact_inverse(tmp_path:Path):
    rows=_mapping_rows(); rows.append({'code':'K9','name':'BAD'})
    inp=tmp_path/'in.jsonl'; out=tmp_path/'out.jsonl'; _write_jsonl(inp,rows)
    cfg=StreamingConfig(exact_disk_registry=True,max_functional_groups=3,min_functional_groups=2,
                        min_group_support=2,min_support=4,relation_confidence=.95,enable_final_certification=False,max_cycles=5)
    res=repair_stream_file(inp,out,config=cfg)
    repaired=[json.loads(x) for x in out.read_text(encoding='utf-8').splitlines()]
    assert repaired[-1]=={'code':'K9','name':'N9'}
    assert res.report['replay']['inverse_restores_complete_input'] is True
    assert res.report['disk_backed_registry']['exact'] is True


def test_stream_schema_and_ordered_migration_compose_as_atomic_record_transaction(tmp_path:Path):
    inp=tmp_path/'in.jsonl'; out=tmp_path/'out.jsonl'; _write_jsonl(inp,[{'kind':'bad','schema_version':1,'user_name':'Alice'}])
    schema={'type':'object','properties':{'kind':{'const':'ok'}}}
    migration={'kind':'migration','document':'@stream','steps':[
        {'id':'move_name','operation':'move','from':'/user_name','path':'/name','old_value':'Alice'},
        {'id':'version','operation':'replace','path':'/schema_version','old_value':1,'new_value':2,'after':['move_name']},
    ],'target_tests':[{'path':'/schema_version','equals':2},{'path':'/name','equals':'Alice'}]}
    cfg=StreamingConfig(exact_disk_registry=True,json_schema=schema,schema_source='json_schema',system_rules=(migration,),max_cycles=5)
    res=repair_stream_file(inp,out,config=cfg)
    assert json.loads(out.read_text())=={'kind':'ok','schema_version':2,'name':'Alice'}
    assert res.report['record_bridge_execution']['atomic_record_transactions']==1
    assert res.report['cold_replay']['would_commit_edits']==0
    assert res.report['third_series_closure']['status']=='CLOSED'


def test_stream_constraint_dsl_record_scope_is_materialized(tmp_path:Path):
    inp=tmp_path/'in.jsonl'; out=tmp_path/'out.jsonl'; _write_jsonl(inp,[{'status':'bad'}])
    rule={'kind':'const','array_path':'','field':'status','value':'ok','rule_id':'dsl_status'}
    cfg=StreamingConfig(exact_disk_registry=True,constraint_rules=(rule,),max_cycles=4,enable_final_certification=False)
    res=repair_stream_file(inp,out,config=cfg)
    assert json.loads(out.read_text())['status']=='ok'
    assert res.report['record_bridge_execution']['atomic_record_transactions']==1


def test_stream_unit_plan_is_now_exact_and_reversible_in_pass024_mode(tmp_path:Path):
    inp=tmp_path/'in.jsonl'; out=tmp_path/'out.jsonl'; _write_jsonl(inp,[{'value':250,'unit':'cm'}])
    rule={'kind':'unit_normalize','document':'@stream','value_field':'value','unit_field':'unit','canonical_unit':'m','conversions':{'cm':'0.01'}}
    res=repair_stream_file(inp,out,config=StreamingConfig(moment_rules=(rule,),exact_disk_registry=True,min_support=1,max_cycles=5))
    assert json.loads(out.read_text())=={'value':2.5,'unit':'m'}
    assert res.report['record_bridge_execution']['atomic_record_transactions']==1
    assert res.report['replay']['inverse_restores_complete_input'] is True
    assert res.report['third_series_closure']['status']=='CLOSED'


def test_stream_development_heldout_lifecycle_repairs_primary_record(tmp_path:Path):
    evidence=[{'code':'A','name':'alpha'},{'code':'A','name':'alpha'},{'code':'B','name':'beta'},
              {'code':'B','name':'beta'},{'code':'C','name':'gamma'},{'code':'C','name':'gamma'}]
    ctx=(
      {'source_id':'dev','role':'development','value':evidence,'independent_group':'train'},
      {'source_id':'hold','role':'heldout','value':evidence,'independent_group':'hold1'},
    )
    inp=tmp_path/'in.jsonl'; out=tmp_path/'out.jsonl'; _write_jsonl(inp,[{'code':'B','name':'WRONG'}])
    cfg=StreamingConfig(source_context=ctx,source_min_support=4,source_min_group_support=1,
                        exact_disk_registry=True,min_support=2,max_cycles=5)
    res=repair_stream_file(inp,out,config=cfg)
    assert json.loads(out.read_text())['name']=='beta'
    life=res.report['record_bridge_execution']['final_lifecycle']
    assert life['heldout_confirmed']>=1
    assert res.report['third_series_closure']['status']=='CLOSED'


def test_bundle_multisource_document_scope_repairs_only_target_document():
    docs={'a.json':{'name':'Alice'},'b.json':{'name':'Bob'}}
    ctx=({'source_id':'defs','role':'defaults','document':'a.json','value':{'country':'CA'}},)
    out,res=repair_bundle(docs,RepairConfig(source_context=ctx,max_cycles=5))
    assert out['a.json']=={'name':'Alice','country':'CA'}
    assert out['b.json']=={'name':'Bob'}
    assert res.report['multisource_assimilation']['mode']=='bundle'
    assert res.report['third_series_closure']['status']=='CLOSED'


def test_single_bundle_stream_all_emit_third_series_closure(tmp_path:Path):
    _,single=repair_object({'x':1},RepairConfig(max_cycles=3))
    _,bundle=repair_bundle({'a.json':{'x':1}},RepairConfig(max_cycles=3))
    inp=tmp_path/'in.jsonl'; out=tmp_path/'out.jsonl'; _write_jsonl(inp,[{'x':1},{'x':2}])
    stream=repair_stream_file(inp,out,config=StreamingConfig(exact_disk_registry=True,min_support=1,max_cycles=3))
    for report in (single.report,bundle.report,stream.report):
        assert report['third_series_closure']['contract']=='json-consistency-repair.third-series-closure.v1'
        assert report['third_series_closure']['status']=='CLOSED'
        assert compile_third_series_closure(report)['ok'] is True


def test_pass024_public_export_and_schema_contracts():
    import json_consistency_repair as jcr
    assert hasattr(jcr,'compile_third_series_closure')
    root=Path(__file__).resolve().parents[1]
    # Files are introduced by PASS024 and must stay Draft 2020-12 machine contracts.
    for name in ('disk-registry-v1.schema.json','streaming-record-bridge-v1.schema.json','third-series-closure-v1.schema.json'):
        data=json.loads((root/'schemas'/name).read_text(encoding='utf-8'))
        assert data['$schema']=='https://json-schema.org/draft/2020-12/schema'
