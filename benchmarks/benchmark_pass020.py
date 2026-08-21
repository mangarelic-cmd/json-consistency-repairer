from __future__ import annotations
import json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'src'))
from json_consistency_repair import RepairConfig, repair_object, __version__

def cfg(**kw): return RepairConfig(enable_final_certification=False,max_cycles=5,**kw)
def gr(**kw):
    d={'kind':'graph','nodes_path':'/nodes','edges_path':'/edges','node_id':'id','source_field':'source','target_field':'target','require_acyclic':True,'order_path':'/order'}; d.update(kw); return d
def sr(): return {'kind':'state_machine','sequence_path':'/events','state_field':'state','transitions':[['NEW','PAID'],['PAID','SHIPPED'],['SHIPPED','DELIVERED']],'initial':'NEW','terminal':['DELIVERED']}
counts={}; false_mutations=0
for n in range(100):
    o={'nodes':[{'id':f'A{n}'},{'id':f'B{n}'},{'id':f'C{n}'}],'edges':[{'source':f'A{n}','target':f'B{n}'},{'source':f'B{n}','target':f'C{n}'}],'order':[f'C{n}',f'A{n}',f'B{n}']}; out,r=repair_object(o,cfg(system_rules=(gr(),))); assert out['order']==[f'A{n}',f'B{n}',f'C{n}']; counts['graph_unique']=counts.get('graph_unique',0)+1
for n in range(100):
    o={'nodes':[{'id':f'A{n}'},{'id':f'B{n}'},{'id':f'C{n}'}],'edges':[{'source':f'A{n}','target':f'C{n}'},{'source':f'B{n}','target':f'C{n}'}],'order':[f'C{n}',f'A{n}',f'B{n}']}; out,r=repair_object(o,cfg(system_rules=(gr(),))); false_mutations+=int(out!=o); counts['graph_ambiguous_abstain']=counts.get('graph_ambiguous_abstain',0)+1
for n in range(100):
    o={'events':[{'state':'NEW'},{'state':f'BAD{n}'},{'state':'SHIPPED'},{'state':'DELIVERED'}]}; out,r=repair_object(o,cfg(system_rules=(sr(),))); assert out['events'][1]['state']=='PAID'; counts['state_unique']=counts.get('state_unique',0)+1
for n in range(100):
    rule={'kind':'state_machine','sequence_path':'/events','state_field':'state','transitions':[['A','X'],['A','Y'],['X','B'],['Y','B']]}; o={'events':[{'state':'A'},{'state':f'BAD{n}'},{'state':'B'}]}; out,r=repair_object(o,cfg(system_rules=(rule,))); false_mutations+=int(out!=o); counts['state_ambiguous_abstain']=counts.get('state_ambiguous_abstain',0)+1
for n in range(100):
    o={'schema_version':1,'user_name':f'U{n}'}; rule={'kind':'migration','steps':[{'id':'m','operation':'move','from':'/user_name','path':'/name','old_value':f'U{n}'},{'id':'v','operation':'replace','path':'/schema_version','old_value':1,'new_value':2,'after':['m']}],'target_tests':[{'path':'/schema_version','equals':2},{'path':'/name','equals':f'U{n}'}]}; out,r=repair_object(o,cfg(system_rules=(rule,))); assert out=={'schema_version':2,'name':f'U{n}'}; counts['migration_atomic']=counts.get('migration_atomic',0)+1
for n in range(100):
    o={'nodes':[{'id':f'A{n}'},{'id':f'B{n}'}],'edges':[{'source':f'A{n}','target':f'Z{n}'}]}; out,r=repair_object(o,cfg()); false_mutations+=int(out!=o); counts['dangling_abstain']=counts.get('dangling_abstain',0)+1
result={'contract':'json-consistency-repair.pass020-benchmark.v1','version':__version__,'expected_decisions':600,'decisions':sum(counts.values()),'false_mutations':false_mutations,'counts':dict(sorted(counts.items())),'all_checks_pass':sum(counts.values())==600 and false_mutations==0}
print(json.dumps(result,sort_keys=True,separators=(',',':')))
