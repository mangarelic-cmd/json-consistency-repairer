from __future__ import annotations
from copy import deepcopy
from json_consistency_repair import RepairConfig, repair_object
from json_consistency_repair.multisource import analyze_multisource, source_registry


def cfg(context, manifest=None, *, cert=False, min_support=10):
    return RepairConfig(max_cycles=5,strong_fixed_point_cycles_required=2,source_context=tuple(context),source_manifest=manifest or {},source_min_support=4,source_min_group_support=1,min_support=min_support,enable_final_certification=cert)

def rows():
    return [{'code':'A','name':'alpha'},{'code':'A','name':'alpha'},{'code':'B','name':'beta'},{'code':'B','name':'beta'},{'code':'C','name':'gamma'},{'code':'C','name':'gamma'}]

counts={}
def ok(name,cond):
    if not cond: raise AssertionError(name)
    counts[name]=counts.get(name,0)+1

for i in range(80):
    c=[{'source_id':'d','role':'defaults','value':{'x':i,'country':'CA'}}]
    out,res=repair_object({'x':i},cfg(c,min_support=4))
    ok('defaults',out=={'x':i,'country':'CA'} and res.committed_edits==1)

for i in range(80):
    c=[{'source_id':'a','role':'authoritative','value':{'x':1}},{'source_id':'b','role':'authoritative','value':{'x':2}}]
    m={'authoritative_values':[{'source_id':'a','path':'/x'},{'source_id':'b','path':'/x'}]}
    out,res=repair_object({'x':0},cfg(c,m,min_support=4))
    ok('authority_conflict',out['x']==0 and any(x['code']=='authority_conflict' for x in res.report['remaining_issues']))

for i in range(100):
    dev={'source_id':'dev','role':'development','value':{'rows':rows()},'independent_group':'train'}
    hold={'source_id':'hold','role':'heldout','value':{'rows':rows()},'independent_group':'hold'}
    p={'rows':[{'code':'A','name':'alpha'},{'code':'B','name':'bad'},{'code':'C','name':'gamma'}]}
    out,res=repair_object(p,cfg([dev,hold]))
    ok('heldout_repair',out['rows'][1]['name']=='beta')

for i in range(80):
    dev={'source_id':'dev','role':'development','value':{'rows':rows()},'independent_group':'train'}
    bad=rows(); bad[-1]['name']='counterexample'
    hold={'source_id':'hold','role':'heldout','value':{'rows':bad},'independent_group':'hold'}
    p={'rows':[{'code':'A','name':'alpha'},{'code':'B','name':'bad'},{'code':'C','name':'gamma'}]}
    out,res=repair_object(p,cfg([dev,hold]))
    ok('counterexample_refute',out['rows'][1]['name']=='bad' and res.report['multisource_assimilation']['final']['relation_lifecycle']['global_refuted']>=1)

for i in range(60):
    dev={'source_id':'dev','role':'development','value':{'rows':rows()},'independent_group':'same'}
    hold={'source_id':'hold','role':'heldout','value':{'rows':rows()},'independent_group':'same'}
    p={'rows':[{'code':'A','name':'alpha'},{'code':'B','name':'bad'},{'code':'C','name':'gamma'}]}
    out,res=repair_object(p,cfg([dev,hold]))
    ok('dependent_abstain',out['rows'][1]['name']=='bad')

for i in range(60):
    devrows=[{'state':r['code'],'label_old':r['name']} for r in rows()]
    holdrows=[{'status':r['code'],'label':r['name']} for r in rows()]
    dev={'source_id':'dev','role':'development','value':{'rows':devrows},'independent_group':'train'}
    hold={'source_id':'hold','role':'heldout','value':{'rows':holdrows},'independent_group':'hold'}
    m={'identity_bridges':[{'logical_id':'status','canonical_field':'status','members':[{'source_id':'dev','field':'state'},{'source_id':'hold','field':'status'},{'source_id':'__primary__','field':'status'}]},{'logical_id':'label','canonical_field':'label','members':[{'source_id':'dev','field':'label_old'},{'source_id':'hold','field':'label'},{'source_id':'__primary__','field':'label'}]}]}
    p={'rows':[{'status':'A','label':'alpha'},{'status':'B','label':'bad'},{'status':'C','label':'gamma'}]}
    out,res=repair_object(p,cfg([dev,hold],m))
    ok('identity_bridge',out['rows'][1]['label']=='beta')

for i in range(60):
    ev={'source_id':'events','role':'event_log','value':{'events':[{'path':'/status','value':'NEW'},{'path':'/status','value':'PAID'}]}}
    m={'projections':[{'kind':'last_event_value','source_id':'events','events_path':'/events','target_path':'/status','authoritative':True}]}
    out,res=repair_object({'status':'NEW'},cfg([ev],m,min_support=4,cert=(i<10)))
    ok('event_projection',out['status']=='PAID' and (not i<10 or res.report['final_certification']['ok']))

for i in range(80):
    c=({'source_id':'ref','role':'reference','value':{'id':i}},)
    a=source_registry({'id':i},c,{}); b=source_registry({'id':i},c,{})
    ok('registry_determinism',a==b and a['registry_digest']==b['registry_digest'])

assert sum(counts.values())==600,counts
print('PASS023_STRESS',sum(counts.values()),counts)
