from copy import deepcopy
import json
from pathlib import Path

from json_consistency_repair import RepairConfig, repair_object, repair_file
from json_consistency_repair.jsonpatch_exact import apply_patch, replay_with_inverses
from json_consistency_repair.grammar_repair import minimal_grammar_repair
from json_consistency_repair.security import SecurityLimits


def _roundtrip(root, patch):
    before=deepcopy(root); cur=deepcopy(root)
    ok,inv=apply_patch(cur,patch)
    assert ok and inv
    ok2,_=apply_patch(cur,inv)
    assert ok2 and cur==before


def test_exact_patch_algebra_roundtrips():
    _roundtrip({'a':1},{'operation':'replace','path':'/a','old_value':1,'new_value':2})
    _roundtrip({'a':1},{'operation':'add','path':'/b','new_value':2,'metadata':{'require_absent':True}})
    _roundtrip({'a':1,'b':2},{'operation':'remove','path':'/b','old_value':2})
    _roundtrip({'old':{'x':1}},{'operation':'move','path':'/new','old_value':{'x':1},'new_value':{'x':1},'metadata':{'from_path':'/old'}})
    _roundtrip({'a':{'x':1}},{'operation':'copy','path':'/b','new_value':{'x':1},'metadata':{'from_path':'/a'}})
    _roundtrip({'a':1},{'operation':'test','path':'/a','new_value':1})


def test_move_rejects_descendant_and_occupied_destination():
    x={'a':{'b':1},'c':0}
    ok,_=apply_patch(x,{'operation':'move','path':'/a/b/c','metadata':{'from_path':'/a'}})
    assert not ok
    x={'a':1,'b':2}
    ok,_=apply_patch(x,{'operation':'move','path':'/b','old_value':1,'new_value':1,'metadata':{'from_path':'/a'}})
    assert not ok and x=={'a':1,'b':2}


def test_unique_structural_rename_is_repaired_atomically():
    rows=[{'name':f'user-{i}','age':20+i} for i in range(19)]
    rows.append({'user_name':'user-19','age':39})
    value={'rows':rows}
    cfg=RepairConfig(enable_final_certification=True,max_cycles=6,required_key_confidence=.95,shape_confidence=.8)
    out,res=repair_object(value,cfg)
    assert out['rows'][19]=={'name':'user-19','age':39}
    moves=[x for x in res.report['committed_edits'] if x['operation']=='move']
    assert len(moves)==1
    assert moves[0]['metadata']['from_path']=='/rows/19/user_name'
    assert res.report['replay']['inverse_restores_input'] is True
    assert res.report['final_certification']['ok'] is True


def test_structural_rename_abstains_when_mapping_is_not_unique():
    rows=[{'name':f'u{i}','age':i,'city':'M'} for i in range(19)]
    rows.append({'user_name':'u19','town':'M','age':19})
    out,res=repair_object({'rows':rows},RepairConfig(enable_final_certification=False,required_key_confidence=.95))
    assert 'name' not in out['rows'][19] and 'user_name' in out['rows'][19]
    assert not any(x['operation']=='move' for x in res.report['committed_edits'])


def test_grammar_missing_comma_unique():
    v,rep=minimal_grammar_repair('{"a":1 "b":2}',SecurityLimits(),max_edit_distance=1)
    assert v=={'a':1,'b':2}
    assert rep and rep[0]['canonical_parse_unique']


def test_grammar_missing_colon_unique():
    v,rep=minimal_grammar_repair('{"a" 1}',SecurityLimits(),max_edit_distance=1)
    assert v=={'a':1}
    assert rep


def test_grammar_two_token_truncation():
    v,rep=minimal_grammar_repair('{"a":[1,2',SecurityLimits(),max_edit_distance=2)
    assert v=={'a':[1,2]}
    assert rep[0]['edit_distance']==2


def test_repair_file_uses_bounded_grammar_frontier(tmp_path):
    src=tmp_path/'dirty.json'; out=tmp_path/'fixed.json'; rpt=tmp_path/'report.json'
    src.write_text('{"a":1 "b":2}',encoding='utf-8')
    r=repair_file(src,out,rpt,RepairConfig(enable_final_certification=True))
    assert json.loads(out.read_text())=={'a':1,'b':2}
    rr=json.loads(rpt.read_text())
    assert rr['syntax_repairs'][0]['grammar_frontier']=='bounded-minimal'
    assert rr['final_certification']['ok'] is True


def test_replay_with_inverses_mixed_patch_plan():
    root={'a':1,'old':{'x':2}}
    patches=[
        {'operation':'replace','path':'/a','old_value':1,'new_value':3},
        {'operation':'move','path':'/new','old_value':{'x':2},'new_value':{'x':2},'metadata':{'from_path':'/old'}},
        {'operation':'add','path':'/flag','new_value':True,'metadata':{'require_absent':True}},
    ]
    ok,out,inverses=replay_with_inverses(root,patches)
    assert ok and out=={'a':3,'new':{'x':2},'flag':True}
    for inv in inverses:
        ok,_=apply_patch(out,inv); assert ok
    assert out==root
