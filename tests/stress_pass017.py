from __future__ import annotations
import json, tempfile
from pathlib import Path
from json_consistency_repair import RepairConfig, repair_object
from json_consistency_repair.engine import repair_file
from json_consistency_repair.grammar_repair import minimal_grammar_repair
from json_consistency_repair.jsonpatch_exact import apply_patch
from json_consistency_repair.security import SecurityLimits

checks=0
def ck(x,msg):
    global checks
    if not x: raise AssertionError(msg)
    checks+=1

# 100 uniquely forced structural renames.
for t in range(100):
    rows=[{'name':f'u{t}-{i}','age':i} for i in range(19)]
    rows.append({'user_name':f'u{t}-19','age':19})
    out,r=repair_object({'rows':rows},RepairConfig(max_cycles=6))
    ck(out['rows'][19].get('name')==f'u{t}-19' and 'user_name' not in out['rows'][19] and r.report['final_certification']['ok'],'structural move')

# 100 ambiguous structural records must abstain.
for t in range(100):
    rows=[{'name':f'u{t}-{i}','city':'M','age':i} for i in range(19)]
    rows.append({'user_name':f'u{t}-19','town':'M','age':19})
    out,r=repair_object({'rows':rows},RepairConfig(enable_final_certification=False,max_cycles=5))
    ck('name' not in out['rows'][19] and 'user_name' in out['rows'][19] and not any(x['operation']=='move' for x in r.report['committed_edits']),'ambiguous abstain')

# 100 missing-comma grammar repairs.
for t in range(100):
    text='{"a":%d "b":%d}'%(t,t+1)
    v,rep=minimal_grammar_repair(text,SecurityLimits(),max_edit_distance=1)
    ck(v=={'a':t,'b':t+1} and bool(rep),'comma grammar')

# 100 two-token truncation repairs.
for t in range(100):
    text='{"a":[%d,%d'%(t,t+1)
    v,rep=minimal_grammar_repair(text,SecurityLimits(),max_edit_distance=2)
    ck(v=={'a':[t,t+1]} and rep[0]['edit_distance']==2,'trunc grammar')

# 100 exact move roundtrips.
for t in range(100):
    root={'old':{'x':t},'keep':1}; before=json.loads(json.dumps(root))
    ok,inv=apply_patch(root,{'operation':'move','path':'/new','old_value':{'x':t},'new_value':{'x':t},'metadata':{'from_path':'/old'}})
    ok2,_=apply_patch(root,inv or {})
    ck(ok and ok2 and root==before,'move roundtrip')

# 100 file-level grammar + independent final certification.
with tempfile.TemporaryDirectory(prefix='pass017-') as td:
    td=Path(td)
    for t in range(100):
        src=td/f'i{t}.json'; out=td/f'o{t}.json'; rpt=td/f'r{t}.json'
        src.write_text('{"x":%d "y":%d}'%(t,t+1),encoding='utf-8')
        r=repair_file(src,out,rpt,RepairConfig(max_cycles=5))
        rr=json.loads(rpt.read_text())
        ck(json.loads(out.read_text())=={'x':t,'y':t+1} and rr['syntax_repairs'][0]['canonical_parse_unique'] and rr['final_certification']['ok'],'file grammar cert')

print(json.dumps({'pass':checks,'expected':600},sort_keys=True))
