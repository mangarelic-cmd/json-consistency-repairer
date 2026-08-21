from __future__ import annotations
from copy import deepcopy
from json_consistency_repair import RepairConfig, analyze_multisource
from json_consistency_repair.authority_scope import compile_authority_registry,evaluate_authority,verify_authority_registry,verify_authority_proof


def run():
    counts={k:0 for k in ('direct_scope','scope_gate','delegation','revocation','poison_lineage','proof_integrity')}; total=0
    for i in range(100):
        src={'source_id':'a','role':'authoritative','value':{'v':i},'authority_scope':{'paths':['/x'],'operations':['replace']}}
        reg=compile_authority_registry({'x':-1},(src,),{})
        pr=evaluate_authority(reg,'a',target_path='/x',operation='replace')
        assert pr['authorized'] and verify_authority_proof(pr,reg); counts['direct_scope']+=1; total+=1
    for i in range(100):
        src={'source_id':'a','role':'authoritative','value':{'v':i},'authority_scope':{'paths':['/safe'],'operations':['replace']}}
        reg=compile_authority_registry({'x':-1},(src,),{})
        pr=evaluate_authority(reg,'a',target_path='/x',operation='replace')
        assert not pr['authorized']; counts['scope_gate']+=1; total+=1
    for i in range(100):
        ctx=({'source_id':'root','role':'authoritative','value':{},'authority_scope':{'paths':['/x'],'operations':['replace']}},
             {'source_id':'d','role':'reference','value':{'v':i}})
        m={'delegations':[{'delegation_id':f'd{i}','grantor_source_id':'root','delegate_source_id':'d','scope':{'paths':['/x'],'operations':['replace']}}]}
        reg=compile_authority_registry({'x':0},ctx,m); pr=evaluate_authority(reg,'d',target_path='/x',operation='replace')
        assert pr['authorized'] and pr['reason']=='DELEGATED_SCOPE_MATCH'; counts['delegation']+=1; total+=1
    for i in range(100):
        ctx=({'source_id':'root','role':'authoritative','value':{},'authority_scope':{'paths':['/x'],'operations':['replace']}},
             {'source_id':'d','role':'reference','value':{'v':i}})
        did=f'd{i}'; m={'delegations':[{'delegation_id':did,'grantor_source_id':'root','delegate_source_id':'d','scope':{'paths':['/x'],'operations':['replace']}}],'revocations':[did]}
        reg=compile_authority_registry({'x':0},ctx,m); pr=evaluate_authority(reg,'d',target_path='/x',operation='replace')
        assert not pr['authorized']; counts['revocation']+=1; total+=1
    rows=[{'k':'A','v':1},{'k':'A','v':1},{'k':'B','v':2},{'k':'B','v':2}]
    for i in range(100):
        ctx=({'source_id':f'dev{i}','role':'development','value':{'rows':rows},'independent_group':f'gdev{i}'},
             {'source_id':f'h{i}','role':'heldout','value':{'rows':rows},'independent_group':f'gh{i}','provenance':{'parents':[f'dev{i}']}})
        _,cert=analyze_multisource({'rows':[{'k':'A','v':1}]},RepairConfig(source_context=ctx,source_min_support=4,source_min_group_support=1))
        assert cert['relation_lifecycle']['dependent_only']>=1 and cert['relation_lifecycle']['heldout_confirmed']==0
        counts['poison_lineage']+=1; total+=1
    for i in range(100):
        src={'source_id':'a','role':'authoritative','value':{'x':i},'authority_scope':{'paths':['/x'],'operations':['replace']}}
        reg=compile_authority_registry({'x':0},(src,),{}); pr=evaluate_authority(reg,'a',target_path='/x',operation='replace')
        assert verify_authority_registry(reg) and verify_authority_proof(pr,reg)
        bad=deepcopy(pr); bad['target_path']='/y'; assert not verify_authority_proof(bad,reg)
        counts['proof_integrity']+=1; total+=1
    assert total==600 and all(v==100 for v in counts.values())
    print('PASS030_STRESS',total,counts)

if __name__=='__main__': run()
