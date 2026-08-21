from __future__ import annotations
import json
from copy import deepcopy
from pathlib import Path
from json_consistency_repair import RepairConfig, repair_object
from json_consistency_repair.bundle import repair_bundle
from json_consistency_repair.jsonpatch_exact import apply_patch
from json_consistency_repair.system_graph import analyze_graph_rule, analyze_state_machine_rule, analyze_migration_rule, discover_graph_rules


def cfg(**kw): return RepairConfig(enable_final_certification=False, **kw)

def dag():
    return {'nodes':[{'id':'A'},{'id':'B'},{'id':'C'}], 'edges':[{'source':'A','target':'B'},{'source':'B','target':'C'}], 'order':['C','A','B']}

def graph_rule(**kw):
    d={'kind':'graph','nodes_path':'/nodes','edges_path':'/edges','node_id':'id','source_field':'source','target_field':'target','require_acyclic':True,'order_path':'/order'}; d.update(kw); return d

def state_rule(**kw):
    d={'kind':'state_machine','sequence_path':'/events','state_field':'state','transitions':[['NEW','PAID'],['PAID','SHIPPED'],['SHIPPED','DELIVERED']], 'initial':'NEW','terminal':['DELIVERED']}; d.update(kw); return d

def migration_rule():
    return {'kind':'migration','steps':[{'id':'move_name','operation':'move','from':'/user_name','path':'/name','old_value':'Alice'}, {'id':'version','operation':'replace','path':'/schema_version','old_value':1,'new_value':2,'after':['move_name']}], 'target_tests':[{'path':'/schema_version','equals':2},{'path':'/name','equals':'Alice'}]}

def test_unique_topological_order_is_repaired_exactly():
    out,res=repair_object(dag(),cfg(system_rules=(graph_rule(),),max_cycles=5)); assert out['order']==['A','B','C'] and res.committed_edits==1; assert res.report['system_graph_summary']['graph_relations']==1

def test_nonunique_topological_order_abstains_when_observed_order_invalid():
    obj={'nodes':[{'id':'A'},{'id':'B'},{'id':'C'}], 'edges':[{'source':'A','target':'C'},{'source':'B','target':'C'}], 'order':['C','A','B']}
    out,res=repair_object(obj,cfg(system_rules=(graph_rule(),),max_cycles=4)); assert out==obj and res.committed_edits==0; assert any(i['code']=='topological_order_ambiguous' for i in res.report['remaining_issues'])

def test_auto_graph_discovery_diagnoses_dangling_edge_without_inventing_node():
    obj={'nodes':[{'id':'A'},{'id':'B'}], 'edges':[{'source':'A','target':'Z'}]}; out,res=repair_object(obj,cfg(max_cycles=4)); assert out==obj and res.committed_edits==0; assert any(i['code']=='dangling_edge' for i in res.report['remaining_issues']); assert discover_graph_rules(obj)

def test_single_missing_reciprocal_edge_can_be_appended_and_replayed():
    obj={'nodes':[{'id':'A'},{'id':'B'}], 'edges':[{'source':'A','target':'B'}]}; rule=graph_rule(require_acyclic=False,order_path=None,require_reciprocal=True)
    out,res=repair_object(obj,RepairConfig(system_rules=(rule,),max_cycles=5)); assert {'source':'B','target':'A'} in out['edges']; assert res.committed_edits==1; assert res.report['replay']['inverse_restores_input']; assert res.report['final_certification']['status']=='CERTIFIED'

def test_state_machine_repairs_unique_interior_state_only():
    obj={'events':[{'state':'NEW'},{'state':'BROKEN'},{'state':'SHIPPED'},{'state':'DELIVERED'}]}; out,res=repair_object(obj,cfg(system_rules=(state_rule(),),max_cycles=5)); assert out['events'][1]['state']=='PAID' and res.committed_edits==1

def test_state_machine_ambiguous_bridge_abstains():
    rule={'kind':'state_machine','sequence_path':'/events','state_field':'state','transitions':[['A','X'],['A','Y'],['X','B'],['Y','B']]}
    obj={'events':[{'state':'A'},{'state':'BAD'},{'state':'B'}]}; out,res=repair_object(obj,cfg(system_rules=(rule,),max_cycles=4)); assert out==obj and res.committed_edits==0; term=next(i for i in res.report['remaining_issues'] if i['code']=='invalid_transition_state'); assert set(term['metadata']['possible_states'])=={'X','Y'}

def test_reachability_is_materialized_as_plan_not_history_mutation():
    rule=state_rule(target_state='DELIVERED',terminal=None); obj={'events':[{'state':'NEW'},{'state':'PAID'}]}; out,res=repair_object(obj,cfg(system_rules=(rule,),max_cycles=4)); assert out==obj; rel=next(r for r in res.report['relations'] if r['kind']=='state_reachability'); assert rel['shortest_state_path']==['PAID','SHIPPED','DELIVERED'] and rel['reachable'] is True

def test_ordered_migration_is_one_atomic_plan_with_exact_inverse_and_certifier():
    obj={'schema_version':1,'user_name':'Alice'}; out,res=repair_object(obj,RepairConfig(system_rules=(migration_rule(),),max_cycles=5)); assert out=={'schema_version':2,'name':'Alice'}; assert res.committed_edits==1; edit=res.report['committed_edits'][0]; assert edit['operation']=='plan' and edit['metadata']['ordered_step_ids']==['move_name','version']; assert res.report['replay']['inverse_restores_input'] and res.report['final_certification']['status']=='CERTIFIED' and res.report['cold_replay']['would_commit_edits']==0

def test_unordered_noncommuting_migration_is_rejected():
    obj={'a':{'x':1}}; rule={'kind':'migration','steps':[{'id':'move','operation':'move','from':'/a','path':'/b','old_value':{'x':1}}, {'id':'edit','operation':'replace','path':'/a/x','old_value':1,'new_value':2}]}
    out,res=repair_object(obj,cfg(system_rules=(rule,),max_cycles=3)); assert out==obj and res.committed_edits==0; assert any(i['code']=='migration_order_underspecified' for i in res.report['remaining_issues'])

def test_plan_primitive_rolls_back_if_an_inner_step_fails():
    obj={'x':1}; before=deepcopy(obj); patch={'operation':'plan','path':'','old_value':None,'new_value':None,'metadata':{'steps':[{'operation':'replace','path':'/x','old_value':1,'new_value':2},{'operation':'replace','path':'/missing','old_value':0,'new_value':1}]}}
    ok,inv=apply_patch(obj,patch); assert not ok and inv is None and obj==before

def test_bundle_document_scoped_system_rule_repairs_only_target_document():
    docs={'workflow.json':{'events':[{'state':'NEW'},{'state':'BAD'},{'state':'SHIPPED'},{'state':'DELIVERED'}]}, 'other.json':{'events':[{'state':'BAD'}]}}
    rule={**state_rule(),'document':'workflow.json'}; out,res=repair_bundle(docs,cfg(system_rules=(rule,),max_cycles=5)); assert out['workflow.json']['events'][1]['state']=='PAID'; assert out['other.json']==docs['other.json']; assert res.report['transaction']['inverse_restores_bundle']

def test_pass020_public_exports_and_contracts():
    import json_consistency_repair as jcr
    for name in ('analyze_system_rules','analyze_graph_rule','analyze_state_machine_rule','analyze_migration_rule','discover_graph_rules','system_summary'):
        assert hasattr(jcr,name)
    _,res=repair_object(dag(),cfg(system_rules=(graph_rule(),),max_cycles=5)); assert res.report['system_graph_summary']['contract']=='json-consistency-repair.system-graph-state.v1'
    root=Path(__file__).resolve().parents[1]
    for schema in ('system-rules-v1.schema.json','system-graph-state-v1.schema.json'):
        data=json.loads((root/'schemas'/schema).read_text()); assert data['$schema']=='https://json-schema.org/draft/2020-12/schema'
