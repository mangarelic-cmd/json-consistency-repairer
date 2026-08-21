from __future__ import annotations
import json,tempfile
from pathlib import Path
from json_consistency_repair.engine import RepairConfig,repair_object
from json_consistency_repair.constraint_dsl import parse_dsl
from json_consistency_repair.cli import _load_schema,_load_openapi_schema
from json_consistency_repair.security import SecurityLimits

def base(**kw): return RepairConfig(enable_final_certification=False,**kw)
checks=0
# 100: two independent equations identify the only globally repairing field.
for n in range(100):
    a=n+2;b=3;d=4;c=a+b;e=c+d
    rules=({'kind':'linear','array_path':'/rows','coefficients':{'a':'1','b':'1','c':'-1'},'constant':'0','rule_id':'r1'},
           {'kind':'linear','array_path':'/rows','coefficients':{'c':'1','d':'1','e':'-1'},'constant':'0','rule_id':'r2'})
    obj={'rows':[{'a':1,'b':2,'c':3,'d':4,'e':7},{'a':2,'b':3,'c':5,'d':4,'e':9},{'a':4,'b':5,'c':9,'d':1,'e':10},{'a':a,'b':b,'c':c+99,'d':d,'e':e}]}
    repaired,res=repair_object(obj,base(constraint_rules=rules)); assert repaired['rows'][3]['c']==c and res.committed_edits==1; checks+=1
# 100: symmetric single equation cannot identify culprit.
for n in range(100):
    rules=({'kind':'linear','array_path':'/rows','coefficients':{'a':'1','b':'1','c':'-1'},'constant':'0','rule_id':'r'},)
    obj={'rows':[{'a':1,'b':2,'c':3},{'a':2,'b':3,'c':5},{'a':n+1,'b':2,'c':999}]}
    repaired,res=repair_object(obj,base(constraint_rules=rules)); assert repaired==obj and res.committed_edits==0; checks+=1
# 100: rank-2 system reconstructs two missing variables jointly.
for n in range(100):
    total=10+n; delta=2+n
    x=(total+delta)//2 if (total+delta)%2==0 else None
    # choose parity-compatible total/delta
    total=20+2*n; delta=4; x=(total+delta)//2; y=(total-delta)//2
    rules=({'kind':'linear','array_path':'/rows','coefficients':{'x':'1','y':'1'},'constant':str(total),'rule_id':'r1'},
           {'kind':'linear','array_path':'/rows','coefficients':{'x':'1','y':'-1'},'constant':str(delta),'rule_id':'r2'})
    obj={'rows':[{'x':x,'y':y},{'x':x,'y':y},{'x':x,'y':y},{}]}
    repaired,res=repair_object(obj,base(constraint_rules=rules)); assert repaired['rows'][3]=={'x':x,'y':y} and res.committed_edits==2; checks+=1
# 100: authoritative JSON Schema const+default.
for n in range(100):
    schema={'type':'object','properties':{'kind':{'const':'invoice'},'currency':{'type':'string','default':'CAD'},'n':{'type':'integer'}},'required':['kind','currency','n']}
    obj={'kind':'bad','n':n}; repaired,res=repair_object(obj,base(json_schema=schema,schema_source='json_schema')); assert repaired['kind']=='invoice' and repaired['currency']=='CAD' and repaired['n']==n; checks+=1
# 50: compact DSL enum canonicalization / defaults.
rules=parse_dsl('scope /rows\nrequire country default "CA"\nenum status ["OPEN","CLOSED"]')
for n in range(50):
    obj={'rows':[{'country':'CA','status':'OPEN'},{'country':'CA','status':'CLOSED'},{'country':'CA','status':'OPEN'},{'status':'open'}]}
    repaired,res=repair_object(obj,base(constraint_rules=rules)); assert repaired['rows'][3]=={'status':'OPEN','country':'CA'}; checks+=1
# 25: JSON Schema local $ref expansion.
for n in range(25):
    doc={'$defs':{'ID':{'type':'integer'}},'type':'object','properties':{'id':{'$ref':'#/$defs/ID'}}}
    with tempfile.TemporaryDirectory() as td:
        p=Path(td)/'s.json'; p.write_text(json.dumps(doc)); s=_load_schema(str(p),SecurityLimits()); assert s['properties']['id']['type']=='integer'; checks+=1
# 25: OpenAPI local component $ref expansion.
for n in range(25):
    doc={'openapi':'3.1.0','components':{'schemas':{'ID':{'type':'integer'},'Thing':{'type':'object','properties':{'id':{'$ref':'#/components/schemas/ID'}}}}}}
    with tempfile.TemporaryDirectory() as td:
        p=Path(td)/'o.json'; p.write_text(json.dumps(doc)); s=_load_openapi_schema(str(p),'Thing',SecurityLimits()); assert s['properties']['id']['type']=='integer'; checks+=1
# 50: nested schema bridge stays exact and conservative.
for n in range(50):
    schema={'type':'object','properties':{'meta':{'type':'object','properties':{'state':{'const':'ok'},'tag':{'default':'v1'}},'required':['state','tag']}}}
    repaired,res=repair_object({'meta':{'state':'bad'}},base(json_schema=schema)); assert repaired=={'meta':{'state':'ok','tag':'v1'}}; checks+=1
# 50: full final-certification path on a DSL default repair.
rules=parse_dsl('scope /rows\nrequire country default "CA"')
for n in range(50):
    obj={'rows':[{'country':'CA'},{'country':'CA'},{'country':'CA'},{}]}
    repaired,res=repair_object(obj,RepairConfig(constraint_rules=rules,enable_final_certification=True)); assert repaired['rows'][3]['country']=='CA' and res.report['final_certification']['ok']; checks+=1
assert checks==600,checks
print(json.dumps({'contract':'json-consistency-repair.pass018-stress.v1','checks':checks,'all_checks_pass':True},sort_keys=True))
