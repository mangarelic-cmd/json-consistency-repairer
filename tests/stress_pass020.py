from __future__ import annotations
from json_consistency_repair import RepairConfig, repair_object
from json_consistency_repair.bundle import repair_bundle

counts={}
def cfg(**kw): return RepairConfig(enable_final_certification=False,max_cycles=5,**kw)
def gr(**kw):
    d={'kind':'graph','nodes_path':'/nodes','edges_path':'/edges','node_id':'id','source_field':'source','target_field':'target','require_acyclic':True,'order_path':'/order'}; d.update(kw); return d
def sr(**kw):
    d={'kind':'state_machine','sequence_path':'/events','state_field':'state','transitions':[['NEW','PAID'],['PAID','SHIPPED'],['SHIPPED','DELIVERED']],'initial':'NEW','terminal':['DELIVERED']}; d.update(kw); return d

for n in range(90):
    obj={'nodes':[{'id':f'A{n}'},{'id':f'B{n}'},{'id':f'C{n}'}],'edges':[{'source':f'A{n}','target':f'B{n}'},{'source':f'B{n}','target':f'C{n}'}],'order':[f'C{n}',f'A{n}',f'B{n}']}
    out,res=repair_object(obj,cfg(system_rules=(gr(),))); assert out['order']==[f'A{n}',f'B{n}',f'C{n}'] and res.committed_edits==1
counts['unique_topological_order']=90
for n in range(70):
    obj={'nodes':[{'id':f'A{n}'},{'id':f'B{n}'},{'id':f'C{n}'}],'edges':[{'source':f'A{n}','target':f'C{n}'},{'source':f'B{n}','target':f'C{n}'}],'order':[f'C{n}',f'A{n}',f'B{n}']}
    out,res=repair_object(obj,cfg(system_rules=(gr(),))); assert out==obj and res.committed_edits==0 and any(i['code']=='topological_order_ambiguous' for i in res.report['remaining_issues'])
counts['ambiguous_topological_order']=70
for n in range(70):
    obj={'nodes':[{'id':f'A{n}'},{'id':f'B{n}'}],'edges':[{'source':f'A{n}','target':f'Z{n}'}]}; out,res=repair_object(obj,cfg()); assert out==obj and any(i['code']=='dangling_edge' for i in res.report['remaining_issues'])
counts['dangling_no_invention']=70
for n in range(90):
    obj={'events':[{'state':'NEW'},{'state':f'BAD{n}'},{'state':'SHIPPED'},{'state':'DELIVERED'}]}; out,res=repair_object(obj,cfg(system_rules=(sr(),))); assert out['events'][1]['state']=='PAID' and res.committed_edits==1
counts['unique_state_bridge']=90
for n in range(60):
    rule={'kind':'state_machine','sequence_path':'/events','state_field':'state','transitions':[['A','X'],['A','Y'],['X','B'],['Y','B']]}; obj={'events':[{'state':'A'},{'state':f'BAD{n}'},{'state':'B'}]}; out,res=repair_object(obj,cfg(system_rules=(rule,))); assert out==obj and res.committed_edits==0
counts['ambiguous_state_bridge']=60
for n in range(50):
    obj={'events':[{'state':'NEW'},{'state':'PAID'}]}; out,res=repair_object(obj,cfg(system_rules=(sr(target_state='DELIVERED',terminal=None),))); rel=next(x for x in res.report['relations'] if x['kind']=='state_reachability'); assert rel['shortest_state_path']==['PAID','SHIPPED','DELIVERED'] and out==obj
counts['reachability_plan']=50
for n in range(60):
    obj={'schema_version':1,'user_name':f'U{n}'}; rule={'kind':'migration','steps':[{'id':'move','operation':'move','from':'/user_name','path':'/name','old_value':f'U{n}'},{'id':'ver','operation':'replace','path':'/schema_version','old_value':1,'new_value':2,'after':['move']}], 'target_tests':[{'path':'/schema_version','equals':2},{'path':'/name','equals':f'U{n}'}]}; out,res=repair_object(obj,cfg(system_rules=(rule,))); assert out=={'schema_version':2,'name':f'U{n}'} and res.committed_edits==1 and res.report['replay']['inverse_restores_input']
counts['atomic_migration_plan']=60
for n in range(40):
    obj={'a':{'x':n}}; rule={'kind':'migration','steps':[{'id':'move','operation':'move','from':'/a','path':'/b','old_value':{'x':n}},{'id':'edit','operation':'replace','path':'/a/x','old_value':n,'new_value':n+1}]}; out,res=repair_object(obj,cfg(system_rules=(rule,))); assert out==obj and any(i['code']=='migration_order_underspecified' for i in res.report['remaining_issues'])
counts['noncommuting_order_refusal']=40
for n in range(40):
    obj={'nodes':[{'id':f'A{n}'},{'id':f'B{n}'}],'edges':[{'source':f'A{n}','target':f'B{n}'}]}; out,res=repair_object(obj,cfg(system_rules=(gr(require_acyclic=False,order_path=None,require_reciprocal=True),))); assert {'source':f'B{n}','target':f'A{n}'} in out['edges'] and res.report['replay']['inverse_restores_input']
counts['reciprocal_append_inverse']=40
for n in range(30):
    docs={'wf.json':{'events':[{'state':'NEW'},{'state':f'BAD{n}'},{'state':'SHIPPED'},{'state':'DELIVERED'}]},'other.json':{'events':[{'state':'BAD'}]}}; rule={**sr(),'document':'wf.json'}; out,res=repair_bundle(docs,cfg(system_rules=(rule,))); assert out['wf.json']['events'][1]['state']=='PAID' and out['other.json']==docs['other.json'] and res.report['transaction']['inverse_restores_bundle']
counts['bundle_scoped_system_rule']=30
assert sum(counts.values())==600
print({'pass':True,'total':sum(counts.values()),'counts':counts})
