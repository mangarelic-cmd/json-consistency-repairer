from __future__ import annotations
from copy import deepcopy
from json_consistency_repair import RepairConfig, apply_relation_falsification_firewall, verify_relation_falsification_certificate
from json_consistency_repair.analyzers import analyze_all
from json_consistency_repair.models import AnalysisResult, Candidate

counts={}
def run(name,n,fn):
    ok=0
    for i in range(n): ok+=bool(fn(i))
    if ok!=n: raise AssertionError(f'{name}: {ok}/{n}')
    counts[name]=ok

def cfg(**kw):
    d=dict(min_support=4,min_group_support=2,relation_confidence=.8,arithmetic_confidence=.8,enable_final_certification=False,enable_multisource=False)
    d.update(kw); return RepairConfig(**d)

def survive(i):
    rows=[{'k':'A','v':1},{'k':'A','v':1},{'k':'B','v':2},{'k':'B','v':2},{'k':'B','v':2}]
    a=analyze_all({'rows':rows},cfg()); _,c=apply_relation_falsification_firewall({'rows':rows},a,cfg())
    return c['states'].get('ADVERSARIAL_SURVIVED',0)>=1 and verify_relation_falsification_certificate(c)
run('functional_adversarial_survival',100,survive)

def constant_gate(i):
    rows=[{'k':'A','v':'same'},{'k':'A','v':'same'},{'k':'B','v':'same'},{'k':'B','v':'same'},{'k':'A'}]
    a=analyze_all({'rows':rows},cfg()); f,c=apply_relation_falsification_firewall({'rows':rows},a,cfg())
    return c['states'].get('NEGATIVE_CONTROL_INVARIANT',0)>=1 and c['blocked_candidate_count']>=1 and verify_relation_falsification_certificate(c)
run('negative_control_invariance_gate',100,constant_gate)

def split_refute(i):
    rows=[{'k':'A','v':'X'},{'k':'A','v':'Y'},{'k':'A','v':'X'},{'k':'A','v':'Y'},{'k':'A','v':'X'},
          {'k':'B','v':'Z'},{'k':'B','v':'Z'},{'k':'B','v':'Z'},{'k':'B','v':'Z'}]
    cc=cfg(relation_confidence=.7); a=analyze_all({'rows':rows},cc); _,c=apply_relation_falsification_firewall({'rows':rows},a,cc)
    return c['states'].get('ACTIVE_REFUTED',0)>=1 and c['blocked_relation_count']>=1
run('split_fold_refutation',100,split_refute)

def heldout_refute(i):
    rel={'relation_id':f'r{i}','kind':'cross_source_functional','array_path':'','inputs':['k'],'output':'v','validation_state':'GLOBAL_REFUTED','counterexample_count':1}
    cand=Candidate(f'c{i}','multisource_lifecycle','replace','/v','bad','good','stress',1.0,1,(),{'relation_id':f'r{i}','relation_kind':'cross_source_functional'})
    f,c=apply_relation_falsification_firewall({'v':'bad'},AnalysisResult([], [cand], [rel]),cfg())
    return not f.candidates and c['blocked_candidate_count']==1 and verify_relation_falsification_certificate(c)
run('independent_counterexample_gate',100,heldout_refute)

def authoritative(i):
    cc=cfg(json_schema={'type':'object','properties':{'x':{'const':2}}}); a=analyze_all({'x':i},cc); _,c=apply_relation_falsification_firewall({'x':i},a,cc)
    return any(r['state']=='AUTHORITATIVE_CONTRACT' for r in c['relations']) and verify_relation_falsification_certificate(c)
run('authoritative_contract_separation',100,authoritative)

def tamper(i):
    rows=[{'k':'A','v':1},{'k':'A','v':1},{'k':'B','v':2},{'k':'B','v':2}]; cc=cfg(); a=analyze_all({'rows':rows},cc); _,c=apply_relation_falsification_firewall({'rows':rows},a,cc)
    b=deepcopy(c); b['relation_count_examined']+=1
    return verify_relation_falsification_certificate(c) and not verify_relation_falsification_certificate(b)
run('certificate_tamper_rejection',100,tamper)

print('PASS037_STRESS',sum(counts.values()),counts)
