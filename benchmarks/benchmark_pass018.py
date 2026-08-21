from __future__ import annotations
import json,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'src'))
from json_consistency_repair import __version__
from json_consistency_repair.engine import RepairConfig,repair_object
from json_consistency_repair.constraint_dsl import parse_dsl
from json_consistency_repair.cli import _load_schema,_load_openapi_schema
from json_consistency_repair.security import SecurityLimits
from json_consistency_repair.provenance import package_code_sha256

def cfg(**kw): return RepairConfig(enable_final_certification=False,**kw)
cat={k:0 for k in ('linear_unique','linear_ambiguous_abstain','linear_joint_missing','schema_exact','dsl_exact','ref_bridge')}
false_mutations=0
for n in range(100):
    a=n+2;b=3;d=4;c=a+b;e=c+d
    rules=({'kind':'linear','array_path':'/rows','coefficients':{'a':'1','b':'1','c':'-1'},'constant':'0','rule_id':'r1'}, {'kind':'linear','array_path':'/rows','coefficients':{'c':'1','d':'1','e':'-1'},'constant':'0','rule_id':'r2'})
    data={'rows':[{'a':1,'b':2,'c':3,'d':4,'e':7},{'a':2,'b':3,'c':5,'d':4,'e':9},{'a':4,'b':5,'c':9,'d':1,'e':10},{'a':a,'b':b,'c':c+91,'d':d,'e':e}]}
    out,r=repair_object(data,cfg(constraint_rules=rules)); cat['linear_unique']+=int(out['rows'][3]['c']==c and r.committed_edits==1)
for n in range(100):
    rules=({'kind':'linear','array_path':'/rows','coefficients':{'a':'1','b':'1','c':'-1'},'constant':'0','rule_id':'r'},)
    data={'rows':[{'a':1,'b':2,'c':3},{'a':2,'b':3,'c':5},{'a':n+1,'b':2,'c':999}]}
    out,r=repair_object(data,cfg(constraint_rules=rules)); ok=(out==data and r.committed_edits==0); cat['linear_ambiguous_abstain']+=int(ok); false_mutations+=int(out!=data)
for n in range(100):
    total=40+2*n; delta=6; x=(total+delta)//2; y=(total-delta)//2
    rules=({'kind':'linear','array_path':'/rows','coefficients':{'x':'1','y':'1'},'constant':str(total),'rule_id':'r1'}, {'kind':'linear','array_path':'/rows','coefficients':{'x':'1','y':'-1'},'constant':str(delta),'rule_id':'r2'})
    data={'rows':[{'x':x,'y':y},{'x':x,'y':y},{'x':x,'y':y},{}]}
    out,r=repair_object(data,cfg(constraint_rules=rules)); cat['linear_joint_missing']+=int(out['rows'][3]=={'x':x,'y':y} and r.committed_edits==2)
for n in range(100):
    schema={'type':'object','properties':{'kind':{'const':'invoice'},'currency':{'default':'CAD'},'n':{'type':'integer'}},'required':['kind','currency','n']}
    out,r=repair_object({'kind':'wrong','n':n},cfg(json_schema=schema,schema_source='json_schema')); cat['schema_exact']+=int(out=={'kind':'invoice','currency':'CAD','n':n})
rules=parse_dsl('scope /rows\nrequire country default "CA"\nenum status ["OPEN","CLOSED"]')
for n in range(100):
    data={'rows':[{'country':'CA','status':'OPEN'},{'country':'CA','status':'CLOSED'},{'country':'CA','status':'OPEN'},{'status':'open'}]}
    out,r=repair_object(data,cfg(constraint_rules=rules)); cat['dsl_exact']+=int(out['rows'][3]=={'status':'OPEN','country':'CA'})
for n in range(100):
    doc={'openapi':'3.1.0','components':{'schemas':{'ID':{'type':'integer'},'Thing':{'type':'object','properties':{'id':{'$ref':'#/components/schemas/ID'}}}}}}
    with tempfile.TemporaryDirectory() as td:
        p=Path(td)/'o.json'; p.write_text(json.dumps(doc)); s=_load_openapi_schema(str(p),'Thing',SecurityLimits()); cat['ref_bridge']+=int(s['properties']['id']['type']=='integer')
result={'benchmark':'JCR_PASS018_CONSTRAINT_BRIDGE_SYNTHETIC_V1','engine_version':__version__,'package_code_sha256':package_code_sha256(),'scope':'synthetic in-distribution PASS018 DSL/schema/exact-linear benchmark; not an external comparative dominance benchmark','categories':cat,'expected_per_category':100,'total_checks':600,'false_mutations':false_mutations}
result['all_checks_pass']=all(v==100 for v in cat.values()) and false_mutations==0
print(json.dumps(result,sort_keys=True,indent=2))
if not result['all_checks_pass']: raise SystemExit(1)
