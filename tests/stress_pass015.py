from __future__ import annotations
import json, tempfile
from pathlib import Path
from json_consistency_repair import repair_object, repair_bundle, RepairConfig
from json_consistency_repair.streaming import repair_stream_file, StreamingConfig
from json_consistency_repair.fixedpoint import update_lifecycle, audit_patch_order, relation_delta
from json_consistency_repair.models import Candidate
from json_consistency_repair.engine import _apply

checks=0
def ck(x,m):
    global checks
    if not x: raise AssertionError(m)
    checks+=1

def clean(): return {'rows':[{'id':i,'v':i} for i in range(8)]}
def dirty():
    rows=[{'id':i,'items':[{'v':1},{'v':2}],'item_count':2} for i in range(21)]; rows[-1]['item_count']=9; return {'rows':rows}

for i in range(100):
    _,r=repair_object(clean(),RepairConfig(enable_final_certification=False,max_cycles=5)); ck(r.report['strong_fixed_point']['attained'] and r.cycles>=3,'clean strong')
for i in range(100):
    out,r=repair_object(dirty(),RepairConfig(enable_final_certification=False,max_cycles=6)); ck(out['rows'][-1]['item_count']==2 and r.report['strong_fixed_point']['attained'],'repair strong')
for i in range(100):
    _,r=repair_object(clean(),RepairConfig(enable_final_certification=False,max_cycles=5)); ck(any(v.get('state')=='STABLE' for v in r.report['knowledge_ledger']['lifecycle'].values()),'lifecycle stable')
for i in range(50):
    ledger={}; rel={'relation_id':'r','confidence':1.0,'support':4}; update_lifecycle(ledger,[rel],1); update_lifecycle(ledger,[],2); ck(ledger['r']['state']=='RETIRED','retired')
for i in range(100):
    if i%2:
        root={'a':1,'b':2}; p1=Candidate('1','t','replace','/a',1,3,'',1,1,(),{}); p2=Candidate('2','t','replace','/b',2,4,'',1,1,(),{})
        ck(audit_patch_order(root,[p1,p2],_apply)['order_independent'],'commuting')
    else:
        root={'a':{'b':1}}; p1=Candidate('1','t','replace','/a',{'b':1},{'b':2},'',1,1,(),{}); p2=Candidate('2','t','replace','/a/b',1,3,'',1,1,(),{})
        ck(not audit_patch_order(root,[p1,p2],_apply)['order_independent'],'noncommuting')
for i in range(50):
    docs={'a.json':dirty(),'b.json':clean()}; out,r=repair_bundle(docs,RepairConfig(enable_final_certification=False,max_cycles=6)); ck(r.report['strong_fixed_point']['attained'],'bundle strong')
with tempfile.TemporaryDirectory(prefix='pass015-stress-') as td:
    td=Path(td)
    for i in range(50):
        src=td/f'i{i}.jsonl'; out=td/f'o{i}.jsonl'; src.write_text('\n'.join(json.dumps(x) for x in clean()['rows'])+'\n')
        r=repair_stream_file(src,out,None,StreamingConfig(enable_final_certification=False,max_cycles=5)); ck(r.report['strong_fixed_point']['attained'],'stream strong')
for i in range(50):
    prev={'r':('1','4')}; cur={'r':('1','5')}; d=relation_delta(prev,cur); ck(not d['quiet'] and d['strength_changed'],'frontier/lifecycle blocker')
print(json.dumps({'pass':checks,'expected':600},sort_keys=True))
