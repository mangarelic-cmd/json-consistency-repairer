from __future__ import annotations
import json,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'src'))
from json_consistency_repair import RepairConfig,repair_object,__version__
from json_consistency_repair.streaming import StreamingConfig,discover_stream_knowledge,_repair_record_with_pass024_bridges

counts={}; false_mutations=0
def hit(k): counts[k]=counts.get(k,0)+1

def rows(): return [{'code':'A','name':'alpha'},{'code':'A','name':'alpha'},{'code':'B','name':'beta'},{'code':'B','name':'beta'},{'code':'C','name':'gamma'},{'code':'C','name':'gamma'}]

with tempfile.TemporaryDirectory(prefix='jcr-pass024-bench-') as td0:
    td=Path(td0)
    for n in range(100):
        data=[]
        for j in range(8): data.extend([{'code':f'K{j}-{n}','name':f'N{j}'},{'code':f'K{j}-{n}','name':f'N{j}'}])
        data.append({'code':f'K7-{n}','name':'BAD'})
        p=td/f'{n}.jsonl'; p.write_text(''.join(json.dumps(x)+'\n' for x in data),encoding='utf-8')
        cfg=StreamingConfig(exact_disk_registry=True,max_functional_groups=2,min_functional_groups=2,min_group_support=2,min_support=4,relation_confidence=.94,enable_final_certification=False)
        k=discover_stream_knowledge(p,cfg,registry_dir=td/f'r{n}')
        try:
            rel=next(r for r in k['relations'] if r['kind']=='functional_stream' and r['determinant']=='/code' and r['output']=='/name')
            assert rel['registry_storage']=='disk_exact' and rel['groups']==8 and k['disk_registry_summary']['recovered_functional_pairs']>0
            hit('disk_registry_exact_overflow')
        finally:
            if k.get('_disk_registry') is not None: k['_disk_registry'].close()

for n in range(100):
    rule={'kind':'const','array_path':'','field':'state','value':f'OK{n}','rule_id':f'c{n}'}
    out,meta=_repair_record_with_pass024_bridges({'state':'bad'},StreamingConfig(exact_disk_registry=True,constraint_rules=(rule,),enable_final_certification=False))
    assert out['state']==f'OK{n}' and meta['remaining_inner_issues']==0; hit('dsl_record_bridge')

for n in range(100):
    schema={'type':'object','properties':{'kind':{'const':'ok'}}}
    mig={'kind':'migration','document':'@stream','steps':[{'id':'m','operation':'move','from':'/old','path':'/name','old_value':f'user{n}'},{'id':'v','operation':'replace','path':'/version','old_value':1,'new_value':2,'after':['m']}], 'target_tests':[{'path':'/version','equals':2},{'path':'/name','equals':f'user{n}'}]}
    out,meta=_repair_record_with_pass024_bridges({'kind':'bad','version':1,'old':f'user{n}'},StreamingConfig(exact_disk_registry=True,json_schema=schema,schema_source='json_schema',system_rules=(mig,),enable_final_certification=False))
    assert out=={'kind':'ok','version':2,'name':f'user{n}'} and meta['committed_edits']==2; hit('schema_migration_atomic_composition')

for n in range(100):
    rule={'kind':'unit_normalize','document':'@stream','value_field':'value','unit_field':'unit','canonical_unit':'m','conversions':{'cm':'0.01'}}
    out,meta=_repair_record_with_pass024_bridges({'value':200+n,'unit':'cm'},StreamingConfig(exact_disk_registry=True,moment_rules=(rule,),enable_final_certification=False))
    assert out['unit']=='m' and abs(out['value']-(2+n/100))<1e-12; hit('moment_unit_plan_stream')

for n in range(100):
    ctx=({'source_id':'dev','role':'development','value':rows(),'independent_group':'train'}, {'source_id':'held','role':'heldout','value':rows(),'independent_group':'held'})
    out,meta=_repair_record_with_pass024_bridges({'code':'B','name':'WRONG'},StreamingConfig(exact_disk_registry=True,source_context=ctx,source_min_support=4,source_min_group_support=1,min_support=10,enable_final_certification=False))
    assert out['name']=='beta' and meta['lifecycle']['heldout_confirmed']>=1; hit('stream_heldout_lifecycle')

for n in range(100):
    c=[{'source_id':'a','role':'authoritative','value':{'x':1}},{'source_id':'b','role':'authoritative','value':{'x':2}}]
    m={'authoritative_values':[{'source_id':'a','path':'/x'},{'source_id':'b','path':'/x'}]}
    inp={'x':n+10}; out,res=repair_object(inp,RepairConfig(source_context=tuple(c),source_manifest=m,enable_final_certification=False,max_cycles=4))
    if out!=inp: false_mutations+=1
    assert out==inp and any(i['code']=='authority_conflict' for i in res.report['remaining_issues']); hit('authority_conflict_abstention')

result={'contract':'json-consistency-repair.pass024-benchmark.v1','version':__version__,'expected_decisions':600,'decisions':sum(counts.values()),'false_mutations':false_mutations,'counts':dict(sorted(counts.items())),'all_checks_pass':sum(counts.values())==600 and false_mutations==0}
print(json.dumps(result,sort_keys=True,separators=(',',':')))
