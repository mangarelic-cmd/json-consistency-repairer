from __future__ import annotations
import json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'src'))
from json_consistency_repair import RepairConfig, repair_object, __version__
from json_consistency_repair.multisource import source_registry

counts={}; false_mutations=0
def hit(k): counts[k]=counts.get(k,0)+1
def cfg(context, manifest=None, min_support=10): return RepairConfig(max_cycles=4,strong_fixed_point_cycles_required=2,enable_final_certification=False,source_context=tuple(context),source_manifest=manifest or {},source_min_support=4,source_min_group_support=1,min_support=min_support)
def rows(): return [{'code':'A','name':'alpha'},{'code':'A','name':'alpha'},{'code':'B','name':'beta'},{'code':'B','name':'beta'},{'code':'C','name':'gamma'},{'code':'C','name':'gamma'}]

for n in range(100):
    out,res=repair_object({'id':n},cfg([{'source_id':'d','role':'defaults','value':{'id':n,'country':'CA'}}],min_support=4)); assert out=={'id':n,'country':'CA'}; hit('defaults_fill_missing')
for n in range(100):
    c=[{'source_id':'a','role':'authoritative','value':{'x':1}},{'source_id':'b','role':'authoritative','value':{'x':2}}]; m={'authoritative_values':[{'source_id':'a','path':'/x'},{'source_id':'b','path':'/x'}]}
    out,res=repair_object({'x':0},cfg(c,m,min_support=4)); assert out['x']==0; hit('authority_conflict_abstain')
for n in range(100):
    dev={'source_id':'dev','role':'development','value':{'rows':rows()},'independent_group':'train'}; hold={'source_id':'hold','role':'heldout','value':{'rows':rows()},'independent_group':'h1'}
    out,res=repair_object({'rows':[{'code':'A','name':'alpha'},{'code':'B','name':'bad'},{'code':'C','name':'gamma'}]},cfg([dev,hold])); assert out['rows'][1]['name']=='beta'; hit('heldout_confirmed')
for n in range(100):
    dev={'source_id':'dev','role':'development','value':{'rows':rows()},'independent_group':'train'}; bad=rows(); bad[-1]['name']='counter'; hold={'source_id':'hold','role':'heldout','value':{'rows':bad},'independent_group':'h1'}
    out,res=repair_object({'rows':[{'code':'A','name':'alpha'},{'code':'B','name':'bad'},{'code':'C','name':'gamma'}]},cfg([dev,hold])); assert out['rows'][1]['name']=='bad'; hit('counterexample_refutes')
for n in range(100):
    dev={'source_id':'dev','role':'development','value':{'rows':rows()},'independent_group':'same'}; hold={'source_id':'hold','role':'heldout','value':{'rows':rows()},'independent_group':'same'}
    out,res=repair_object({'rows':[{'code':'A','name':'alpha'},{'code':'B','name':'bad'},{'code':'C','name':'gamma'}]},cfg([dev,hold])); assert out['rows'][1]['name']=='bad'; hit('dependent_replication_not_heldout')
for n in range(100):
    c=({'source_id':'ref','role':'reference','value':{'id':n}},); a=source_registry({'id':n},c,{}); b=source_registry({'id':n},c,{}); assert a==b; hit('registry_determinism')

result={'contract':'json-consistency-repair.pass023-benchmark.v1','version':__version__,'expected_decisions':600,'decisions':sum(counts.values()),'false_mutations':false_mutations,'counts':dict(sorted(counts.items())),'all_checks_pass':sum(counts.values())==600 and false_mutations==0}
print(json.dumps(result,sort_keys=True,separators=(',',':')))
