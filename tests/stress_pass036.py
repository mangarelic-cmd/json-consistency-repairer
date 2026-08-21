from __future__ import annotations

from json_consistency_repair import RepairConfig, apply_controllability_firewall, compile_control_plan, verify_controllability_certificate
from json_consistency_repair.models import AnalysisResult, Candidate
from json_consistency_repair.semantic_provenance import project_verified_semantic_config


def cand(i,path,new=1,old=0,cost=1):
    return Candidate(f'c{i}','stress','replace',path,old,new,'pass036-stress',1.0,cost,(),{})

counts={}

def run(name,n,fn):
    ok=0
    for i in range(n):
        if fn(i): ok+=1
    if ok!=n: raise AssertionError(f'{name}: {ok}/{n}')
    counts[name]=ok

run('explicit_permission_allow',100,lambda i: (lambda r: bool(r[0]) and r[1]['status']=='CONTROLLABLE' and verify_controllability_certificate(r[1]))(
    compile_control_plan({'x':0},[cand(i,'/x')],RepairConfig(controllability_rules=({'control_rule_id':f'a{i}','path':'/x','allowed_operations':['replace']},),enable_final_certification=False))))

run('immutable_block',100,lambda i: (lambda r: len(r[0].candidates)==0 and r[1]['status']=='IDENTIFIABLE_BUT_UNREACHABLE' and verify_controllability_certificate(r[1]))(
    apply_controllability_firewall({'x':0},AnalysisResult([], [cand(i,'/x')], []),RepairConfig(controllability_rules=({'control_rule_id':f'l{i}','path':'/x','immutable':True},),enable_final_certification=False))))

run('cumulative_budget_gate',100,lambda i: (lambda r: not r[0] and r[1]['status']=='IDENTIFIABLE_BUT_UNREACHABLE' and not r[1]['checks']['budget_ok'])(
    compile_control_plan({'x':0},[cand(i,'/x')],RepairConfig(max_control_edits=1,enable_final_certification=False),used_edits=1)))

def precedence(i):
    a=cand(i*2,'/a'); b=cand(i*2+1,'/b')
    cfg=RepairConfig(controllability_rules=(
      {'control_rule_id':f'p{i}','path':'/a','allowed_operations':['replace'],'must_precede':['/b']},
      {'control_rule_id':f'q{i}','path':'/b','allowed_operations':['replace']},),enable_final_certification=False)
    ordered,cert=compile_control_plan({'a':0,'b':0},[b,a],cfg)
    return [x.path for x in ordered]==['/a','/b'] and cert['checks']['precedence_ok']
run('precedence_compilation',100,precedence)

def cycle(i):
    a=cand(i*2,'/a'); b=cand(i*2+1,'/b')
    cfg=RepairConfig(controllability_rules=(
      {'control_rule_id':f'p{i}','path':'/a','allowed_operations':['replace'],'must_precede':['/b']},
      {'control_rule_id':f'q{i}','path':'/b','allowed_operations':['replace'],'must_precede':['/a']},),enable_final_certification=False)
    ordered,cert=compile_control_plan({'a':0,'b':0},[a,b],cfg)
    return not ordered and cert['reachability']=='UNREACHABLE' and bool(cert['precedence_cycles'])
run('precedence_cycle_gate',100,cycle)

def poisoned(i):
    rule={'control_rule_id':f'external-{i}','path':'/x','immutable':True,'source':'external-policy-v1'}
    cfg,pre=project_verified_semantic_config(RepairConfig(controllability_rules=(rule,),enable_final_certification=False))
    return not cfg.controllability_rules and pre['gated_rule_count']==1 and pre['registry']['blocked_claim_count']==1
run('semantic_policy_poison_gate',100,poisoned)

print('PASS036_STRESS',sum(counts.values()),counts)
