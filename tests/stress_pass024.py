from __future__ import annotations
import json, tempfile
from pathlib import Path
from json_consistency_repair import RepairConfig
from json_consistency_repair.bundle import repair_bundle
from json_consistency_repair.streaming import StreamingConfig, discover_stream_knowledge, _repair_record_with_pass024_bridges

counts={}
def ok(name,cond):
    if not cond: raise AssertionError(name)
    counts[name]=counts.get(name,0)+1

def mapping_rows(suffix=''):
    rows=[]
    for j in range(8):
        rows += [{'code':f'K{j}{suffix}','name':f'N{j}'},{'code':f'K{j}{suffix}','name':f'N{j}'}]
    rows += [{'code':f'K7{suffix}','name':'BAD'}]
    return rows

with tempfile.TemporaryDirectory(prefix='jcr-pass024-stress-') as td0:
    root=Path(td0)
    for i in range(100):
        p=root/f'disk-{i}.jsonl'; p.write_text(''.join(json.dumps(x)+'\n' for x in mapping_rows(str(i))),encoding='utf-8')
        cfg=StreamingConfig(exact_disk_registry=True,max_functional_groups=2,min_functional_groups=2,min_group_support=2,
                            min_support=4,relation_confidence=.94,enable_final_certification=False)
        k=discover_stream_knowledge(p,cfg,registry_dir=root/f'reg-{i}')
        try:
            rel=next(r for r in k['relations'] if r['kind']=='functional_stream' and r['determinant']=='/code' and r['output']=='/name')
            ok('disk_exact_overflow',k['disk_registry_summary']['exact'] and rel['registry_storage']=='disk_exact' and rel['groups']==8)
        finally:
            if k.get('_disk_registry') is not None: k['_disk_registry'].close()

for i in range(100):
    rule={'kind':'const','array_path':'','field':'status','value':f'OK{i}','rule_id':f'dsl{i}'}
    out,meta=_repair_record_with_pass024_bridges({'status':'bad'},StreamingConfig(exact_disk_registry=True,constraint_rules=(rule,),enable_final_certification=False))
    ok('constraint_record_carrier',out['status']==f'OK{i}' and meta['committed_edits']==1 and meta['remaining_inner_issues']==0)

for i in range(100):
    schema={'type':'object','properties':{'kind':{'const':'ok'}}}
    migration={'kind':'migration','document':'@stream','steps':[
        {'id':'move','operation':'move','from':'/old','path':'/name','old_value':f'N{i}'},
        {'id':'ver','operation':'replace','path':'/version','old_value':1,'new_value':2,'after':['move']}],
        'target_tests':[{'path':'/version','equals':2},{'path':'/name','equals':f'N{i}'}]}
    out,meta=_repair_record_with_pass024_bridges({'kind':'bad','version':1,'old':f'N{i}'},StreamingConfig(exact_disk_registry=True,json_schema=schema,schema_source='json_schema',system_rules=(migration,),enable_final_certification=False))
    ok('schema_migration_composition',out=={'kind':'ok','version':2,'name':f'N{i}'} and meta['committed_edits']==2)

for i in range(100):
    rule={'kind':'unit_normalize','document':'@stream','value_field':'value','unit_field':'unit','canonical_unit':'m','conversions':{'cm':'0.01'}}
    out,meta=_repair_record_with_pass024_bridges({'value':100+i,'unit':'cm'},StreamingConfig(exact_disk_registry=True,moment_rules=(rule,),enable_final_certification=False))
    ok('unit_atomic_materialization',out['unit']=='m' and abs(out['value']-(1+i/100))<1e-12 and meta['committed_edits']==1)

for i in range(100):
    rows=[{'code':'A','name':'alpha'},{'code':'A','name':'alpha'},{'code':'B','name':'beta'},{'code':'B','name':'beta'},{'code':'C','name':'gamma'},{'code':'C','name':'gamma'}]
    ctx=({'source_id':'dev','role':'development','value':rows,'independent_group':'train'}, {'source_id':'hold','role':'heldout','value':rows,'independent_group':'hold'})
    out,meta=_repair_record_with_pass024_bridges({'code':'B','name':'bad'},StreamingConfig(exact_disk_registry=True,source_context=ctx,source_min_support=4,source_min_group_support=1,min_support=10,enable_final_certification=False))
    ok('stream_multisource_lifecycle',out['name']=='beta' and (meta.get('lifecycle') or {}).get('heldout_confirmed',0)>=1)

for i in range(100):
    docs={'a.json':{'id':i},'b.json':{'id':i}}
    ctx=({'source_id':'defaults','role':'defaults','document':'a.json','value':{'country':'CA'}},)
    out,res=repair_bundle(docs,RepairConfig(source_context=ctx,max_cycles=4,enable_final_certification=False))
    ok('bundle_source_scope',out['a.json'].get('country')=='CA' and 'country' not in out['b.json'] and res.report['transaction']['inverse_restores_bundle'])

assert sum(counts.values())==600,counts
print('PASS024_STRESS',sum(counts.values()),counts)
