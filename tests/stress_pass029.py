from __future__ import annotations
from copy import deepcopy
from json_consistency_repair import RepairConfig, repair_object
from json_consistency_repair.models import AnalysisResult, Candidate, Issue
from json_consistency_repair.materialization import materialize_missing_witnesses
from json_consistency_repair.certifier import _verify_witness_materialization

SCHEMA={'type':'object','required':['x'],'properties':{'x':{'type':'integer'}}}

def enum_analysis(i:int):
    root={'x':'WRONG'}
    issue=Issue('enum_domain','enum_domain_outlier','/x','outside','warning',False,{'domain':[i,i+1],'domain_id':f'd{i}'})
    c1=Candidate(f'a{i}','enum_domain','replace','/x','WRONG',i,'choice',1.0,1,('RULE',),{'formula':f'enum-{i}'})
    c2=Candidate(f'b{i}','enum_domain','replace','/x','WRONG',i+1,'choice',1.0,1,('RULE',),{'formula':f'enum-{i}'})
    return root,AnalysisResult([issue],[c1,c2],[])

def run():
    counts={k:0 for k in ('authoritative','identity_alias','finite_selector','ambiguous','gates','reinject_reask')}
    total=0
    # Exact authoritative materialization.
    for i in range(100):
        cfg=RepairConfig(json_schema=SCHEMA,source_context=({'source_id':'a','role':'authoritative','value':{'x':i}},),enable_final_certification=False)
        root,analysis={'seed':i},AnalysisResult([Issue('schema_bridge','schema_required_missing','/x','missing','error',False,{})],[],[])
        add,cert=materialize_missing_witnesses(root,analysis,cfg)
        assert cert['terminals'][0]['status']=='MATERIALIZED_EXACT' and add.candidates[0].new_value==i
        assert _verify_witness_materialization({'witness_materialization':{'cycles':[{'certificate':cert}]},'committed_edits':[]})
        counts['authoritative']+=1; total+=1
    # Alias/version bridge.
    for i in range(100):
        manifest={'identity_bridges':[{'logical_id':'x','canonical_field':'x','members':[{'source_id':'__primary__','field':'x'},{'source_id':'old','field':'legacy_x'}]}]}
        cfg=RepairConfig(source_context=({'source_id':'old','role':'authoritative','schema_version':i,'value':{'legacy_x':i}},),source_manifest=manifest)
        root,analysis={},AnalysisResult([Issue('schema_bridge','schema_required_missing','/x','missing','error',False,{})],[],[])
        add,cert=materialize_missing_witnesses(root,analysis,cfg)
        t=cert['terminals'][0]; assert t['status']=='MATERIALIZED_EXACT' and add.candidates[0].new_value==i
        assert any(o['source_path']=='/legacy_x' for o in t['observations'])
        counts['identity_alias']+=1; total+=1
    # Independent reference selects one member of an already-certified finite solution set.
    for i in range(100):
        root,analysis=enum_analysis(i)
        cfg=RepairConfig(source_context=({'source_id':'ref','role':'reference','independent_group':f'g{i}','value':{'x':i+1}},))
        add,cert=materialize_missing_witnesses(root,analysis,cfg)
        assert cert['terminals'][0]['status']=='MATERIALIZED_EXACT' and add.candidates[0].new_value==i+1
        counts['finite_selector']+=1; total+=1
    # Conflicting materializations are never mutated by majority/tiebreak.
    for i in range(100):
        cfg=RepairConfig(source_context=(
            {'source_id':'a','role':'authoritative','value':{'x':i}},
            {'source_id':'b','role':'authoritative','value':{'x':i+1}},))
        root,analysis={},AnalysisResult([Issue('schema_bridge','schema_required_missing','/x','missing','error',False,{})],[],[])
        add,cert=materialize_missing_witnesses(root,analysis,cfg)
        assert cert['terminals'][0]['status']=='MULTIPLE_MATERIALIZATIONS_AMBIGUOUS' and not add.candidates
        counts['ambiguous']+=1; total+=1
    # Not-found, ineligible and observer-only remain distinct gates and never fabricate absence/value.
    for i in range(100):
        mode=i%3
        if mode==0: ctx=()
        elif mode==1: ctx=({'source_id':'a','role':'authoritative','eligible':False,'value':{'x':i}},)
        else: ctx=({'source_id':'p','role':'previous','value':{'x':i}},)
        cfg=RepairConfig(source_context=ctx)
        root,analysis={},AnalysisResult([Issue('schema_bridge','schema_required_missing','/x','missing','error',False,{})],[],[])
        add,cert=materialize_missing_witnesses(root,analysis,cfg)
        st=cert['terminals'][0]['status']
        assert st in {'ABSENT_CERTIFIED_WITHIN_SEARCH_CONTRACT','SOURCE_GATE','MATERIAL_GATE'} and not add.candidates
        counts['gates']+=1; total+=1
    # Reinjection into the real engine must close the original terminal and disappear on re-analysis.
    for i in range(100):
        cfg=RepairConfig(json_schema=SCHEMA,source_context=({'source_id':'a','role':'authoritative','value':{'x':i}},),
                         max_cycles=4,strong_fixed_point_cycles_required=1,enable_final_certification=False)
        out,res=repair_object({},cfg)
        assert out=={'x':i} and res.committed_edits==1
        assert any(t['status']=='MATERIALIZED_EXACT' for c in res.report['witness_materialization']['cycles'] for t in c['certificate']['terminals'])
        assert res.report['witness_materialization']['final']['terminal_count']==0
        counts['reinject_reask']+=1; total+=1
    assert total==600
    print('PASS029_STRESS',total,counts)

if __name__=='__main__': run()
