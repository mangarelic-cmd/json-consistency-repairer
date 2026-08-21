from __future__ import annotations
from pathlib import Path
from copy import deepcopy
import json
from json_consistency_repair.authority_scope import compile_authority_registry,evaluate_authority,verify_authority_registry,verify_authority_proof


def main():
    counts={}; false_mutations=0
    def batch(name,fn):
        nonlocal false_mutations
        ok=0
        for i in range(100):
            good,false=fn(i); ok+=int(good); false_mutations+=int(false)
        counts[name]=ok
    def direct(i):
        src={'source_id':'a','role':'authoritative','value':{'x':i},'authority_scope':{'paths':['/x'],'operations':['replace']}}
        reg=compile_authority_registry({'x':0},(src,),{}); p=evaluate_authority(reg,'a',target_path='/x',operation='replace')
        good=p['authorized'] and verify_authority_proof(p,reg); return good,not good
    batch('direct_scoped_authority',direct)
    def gate(i):
        src={'source_id':'a','role':'authoritative','value':{'x':i},'authority_scope':{'paths':['/safe'],'operations':['replace']}}
        reg=compile_authority_registry({'x':0},(src,),{}); p=evaluate_authority(reg,'a',target_path='/x',operation='replace')
        return (not p['authorized'],p['authorized'])
    batch('out_of_scope_abstention',gate)
    def delegate(i):
        ctx=({'source_id':'root','role':'authoritative','value':{},'authority_scope':{'paths':['/x'],'operations':['replace']}},{'source_id':'d','role':'reference','value':{'x':i}})
        m={'delegations':[{'delegation_id':f'd{i}','grantor_source_id':'root','delegate_source_id':'d','scope':{'paths':['/x'],'operations':['replace']}}]}
        reg=compile_authority_registry({'x':0},ctx,m); p=evaluate_authority(reg,'d',target_path='/x',operation='replace')
        return (p['authorized'] and p['reason']=='DELEGATED_SCOPE_MATCH',False)
    batch('delegated_authority',delegate)
    def revoked(i):
        ctx=({'source_id':'root','role':'authoritative','value':{},'authority_scope':{'paths':['/x'],'operations':['replace']}},{'source_id':'d','role':'reference','value':{'x':i}})
        did=f'd{i}'; m={'delegations':[{'delegation_id':did,'grantor_source_id':'root','delegate_source_id':'d','scope':{'paths':['/x'],'operations':['replace']}}],'revocations':[did]}
        reg=compile_authority_registry({'x':0},ctx,m); p=evaluate_authority(reg,'d',target_path='/x',operation='replace')
        return (not p['authorized'],p['authorized'])
    batch('revocation_firewall',revoked)
    def schema(i):
        src={'source_id':'a','role':'authoritative','value':{'x':i},'authority_scope':{'paths':['/x'],'schema_versions':['1'],'operations':['replace']}}
        reg=compile_authority_registry({'schema_version':2,'x':0},(src,),{}); p=evaluate_authority(reg,'a',target_path='/x',operation='replace')
        return (not p['authorized'] and p['reason']=='SCHEMA_VERSION_OUT_OF_SCOPE',p['authorized'])
    batch('schema_version_gate',schema)
    def tamper(i):
        src={'source_id':'a','role':'authoritative','value':{'x':i},'authority_scope':{'paths':['/x'],'operations':['replace']}}
        reg=compile_authority_registry({'x':0},(src,),{}); p=evaluate_authority(reg,'a',target_path='/x',operation='replace')
        bad=deepcopy(p); bad['authorized']=False
        good=verify_authority_registry(reg) and verify_authority_proof(p,reg) and not verify_authority_proof(bad,reg)
        return good,not good
    batch('proof_tamper_rejection',tamper)
    payload={'contract':'json-consistency-repair.pass030-benchmark.v1','version':'0.30.0','decisions':sum(counts.values()),'expected_decisions':600,
             'counts':counts,'false_mutations':false_mutations,'all_checks_pass':sum(counts.values())==600 and false_mutations==0}
    text=json.dumps(payload,sort_keys=True,separators=(',',':'))+'\n'
    Path(__file__).with_name('PASS030_BENCHMARK.json').write_text(text,encoding='utf-8'); print(text,end='')
if __name__=='__main__': main()
