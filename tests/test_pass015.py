from __future__ import annotations
from json_consistency_repair import repair_object, RepairConfig
from json_consistency_repair.fixedpoint import audit_patch_order, update_lifecycle
from json_consistency_repair.models import Candidate
from json_consistency_repair.engine import _apply


def test_clean_object_requires_two_strong_quiet_cycles_after_baseline():
    data={'rows':[{'id':i,'v':i} for i in range(8)]}
    _,res=repair_object(data,RepairConfig(enable_final_certification=False,max_cycles=5))
    fp=res.report['strong_fixed_point']
    assert fp['attained'] is True and fp['quiet_streak']>=2
    assert res.cycles>=3
    assert res.report['cycles'][-1]['strong_fixed_point_streak']>=2


def test_repair_resets_strong_streak_then_closes():
    rows=[{'id':i,'items':[{'v':1},{'v':2}],'item_count':2} for i in range(21)]
    rows[-1]['item_count']=9
    repaired,res=repair_object({'rows':rows},RepairConfig(enable_final_certification=False,max_cycles=6))
    assert repaired['rows'][-1]['item_count']==2
    assert res.report['cycles'][0]['strong_fixed_point_streak']==0
    assert res.report['strong_fixed_point']['attained'] is True


def test_relation_lifecycle_reaches_stable_with_cold_gate():
    data={'rows':[{'id':i,'state':'A' if i%2 else 'B'} for i in range(8)]}
    _,res=repair_object(data,RepairConfig(enable_final_certification=False,max_cycles=5))
    states=[v for v in res.report['knowledge_ledger']['lifecycle'].values() if v.get('state')=='STABLE']
    assert states and all(x.get('promotion_gate')=='COLD_REPLAY_REQUIRED' for x in states)


def test_noncommuting_parent_child_patch_set_is_rejected_by_order_audit():
    root={'a':{'b':1}}
    p1=Candidate('1','t','replace','/a',{'b':1},{'b':2},'x',1.0,1,(),{})
    p2=Candidate('2','t','replace','/a/b',1,3,'y',1.0,1,(),{})
    audit=audit_patch_order(root,[p1,p2],_apply)
    assert audit['order_independent'] is False


def test_lifecycle_marks_retired_relations():
    ledger={}
    r={'relation_id':'r','confidence':1.0,'support':4}
    update_lifecycle(ledger,[r],1)
    update_lifecycle(ledger,[],2)
    assert ledger['r']['state']=='RETIRED'
