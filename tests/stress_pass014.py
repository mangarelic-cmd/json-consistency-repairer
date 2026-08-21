from __future__ import annotations
import json, tempfile
from pathlib import Path
from json_consistency_repair import repair_object, repair_bundle, RepairConfig
from json_consistency_repair.streaming import StreamingConfig, repair_stream_file, discover_stream_knowledge

checks=0
def ck(x,m):
    global checks
    if not x: raise AssertionError(m)
    checks+=1

# 100 legitimate shape regimes
for c in range(100):
    rows=[{'type':'sale','id':i,'tax':i} for i in range(8)]+[{'type':'refund','id':20+i,'reason':'r'} for i in range(4)]
    data={'rows':rows}; repaired,res=repair_object(data,RepairConfig(enable_final_certification=False,max_cycles=4))
    ck(repaired==data and len([r for r in res.report['relations'] if r.get('kind')=='modal_regime'])==2,'shape regimes')

# 100 schema evolution objects
for c in range(100):
    rows=[{'schema_version':'1','id':i,'name':'n'} for i in range(4)]+[{'schema_version':'2','id':10+i,'name':'n','active':True} for i in range(4)]
    _,res=repair_object({'rows':rows},RepairConfig(enable_final_certification=False,max_cycles=4))
    ck(any(r.get('kind')=='schema_evolution' for r in res.report['relations']),'schema evolution')

# 100 status outliers remain anomalies, not modal escape hatches
for c in range(100):
    rows=[{'id':i,'status':'OPEN'} for i in range(20)]; rows[-1]['status']='open'
    repaired,res=repair_object({'rows':rows},RepairConfig(enable_final_certification=False,max_cycles=4))
    ck(repaired['rows'][-1]['status']=='OPEN' and not any(r.get('regime_field')=='status' for r in res.report['relations'] if r.get('kind')=='modal_regime'),'status outlier')

# 100 different arithmetic laws by type remain legal together
for c in range(100):
    rows=[]
    for i in range(8): rows.append({'type':'sale','a':i+2,'b':i+3,'total':2*i+5})
    for i in range(8): rows.append({'type':'refund','a':i+2,'b':i+3,'total':-1})
    data={'rows':rows}; repaired,res=repair_object(data,RepairConfig(enable_final_certification=False,max_cycles=4))
    ck(repaired==data and any(r.get('modalized') and r.get('kind')=='exact_arithmetic' for r in res.report['relations']),'modal arithmetic')

# 50 recursive morphology diagnoses without invention
for c in range(50):
    tree={'children':[{'name':str(i),'kind':'leaf'} for i in range(20)]}; tree['children'][-1].pop('kind')
    repaired,res=repair_object(tree,RepairConfig(enable_final_certification=False,max_cycles=4))
    ck(repaired==tree and any(i['code']=='recursive_morphology_missing_key' for i in res.report['remaining_issues']),'morphology')

# 50 bundles preserve local regimes
for c in range(50):
    rows=[{'type':'sale','id':i,'tax':i} for i in range(8)]+[{'type':'refund','id':20+i,'reason':'r'} for i in range(4)]
    docs={'a.json':{'rows':rows},'b.json':{'rows':[{'id':i,'v':i} for i in range(4)]}}
    repaired,res=repair_bundle(docs,RepairConfig(enable_final_certification=False,max_cycles=5))
    ck(repaired==docs and res.report['strong_fixed_point']['attained'],'bundle regimes')

# 50 bounded streams use regime-specific required fields
with tempfile.TemporaryDirectory(prefix='pass014-stress-') as td:
    td=Path(td)
    for c in range(50):
        src=td/f'i{c}.jsonl'; out=td/f'o{c}.jsonl'
        rows=[{'type':'sale','id':i,'tax':i} for i in range(20)]+[{'type':'refund','id':30+i,'reason':'r'} for i in range(5)]
        src.write_text('\n'.join(json.dumps(x) for x in rows)+'\n',encoding='utf-8')
        cfg=StreamingConfig(required_key_confidence=.80,enable_final_certification=False,max_cycles=5)
        knowledge=discover_stream_knowledge(src,cfg)
        res=repair_stream_file(src,out,None,cfg)
        ck(knowledge['modal_discriminator']=='/type' and res.remaining_issues==0,'stream regimes')


# 50 bounded streams expose schema evolution by version
with tempfile.TemporaryDirectory(prefix='pass014-schema-stream-') as td:
    td=Path(td)
    for c in range(50):
        src=td/f'v{c}.jsonl'
        rows=[{'schema_version':'1','id':i,'name':'n'} for i in range(5)]+[{'schema_version':'2','id':10+i,'name':'n','active':True} for i in range(5)]
        src.write_text('\n'.join(json.dumps(x) for x in rows)+'\n',encoding='utf-8')
        k=discover_stream_knowledge(src,StreamingConfig(enable_final_certification=False))
        ck(any(r.get('kind')=='schema_evolution_stream' for r in k['relations']),'stream schema evolution')

print(json.dumps({'pass':checks,'expected':600},sort_keys=True))
