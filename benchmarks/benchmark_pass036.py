from __future__ import annotations
import json
from pathlib import Path
from json_consistency_repair import RepairConfig, apply_controllability_firewall, compile_control_plan
from json_consistency_repair.models import AnalysisResult, Candidate
from json_consistency_repair.semantic_provenance import project_verified_semantic_config

counts={}; false_mutations=0

def c(i,p='/x'):
    return Candidate(f'c{i}','bench','replace',p,0,1,'pass036',1.0,1,(),{})
def add(name,fn):
    global false_mutations
    ok=0
    for i in range(100):
        good,mut=fn(i); ok+=bool(good); false_mutations+=int(bool(mut))
    counts[name]=ok

def allow(i):
    o,cert=compile_control_plan({'x':0},[c(i)],RepairConfig(controllability_rules=({'control_rule_id':f'a{i}','path':'/x','allowed_operations':['replace']},),enable_final_certification=False))
    return bool(o) and cert['status']=='CONTROLLABLE', False
add('explicit_permission',allow)

def lock(i):
    f,cert=apply_controllability_firewall({'x':0},AnalysisResult([], [c(i)], []),RepairConfig(controllability_rules=({'control_rule_id':f'l{i}','path':'/x','immutable':True},),enable_final_certification=False))
    return not f.candidates and cert['blocked_candidate_count']==1, bool(f.candidates)
add('immutable_rejection',lock)

def budget(i):
    o,cert=compile_control_plan({'x':0},[c(i)],RepairConfig(max_control_edits=1,enable_final_certification=False),used_edits=1)
    return not o and not cert['checks']['budget_ok'], bool(o)
add('run_budget_exhaustion',budget)

def order(i):
    a=c(i*2,'/a'); b=c(i*2+1,'/b')
    cfg=RepairConfig(controllability_rules=({'control_rule_id':f'p{i}','path':'/a','must_precede':['/b']},{'control_rule_id':f'q{i}','path':'/b'}),enable_final_certification=False)
    o,cert=compile_control_plan({'a':0,'b':0},[b,a],cfg)
    return [x.path for x in o]==['/a','/b'] and cert['checks']['precedence_ok'], False
add('precedence_compilation',order)

def cyc(i):
    a=c(i*2,'/a'); b=c(i*2+1,'/b')
    cfg=RepairConfig(controllability_rules=({'control_rule_id':f'p{i}','path':'/a','must_precede':['/b']},{'control_rule_id':f'q{i}','path':'/b','must_precede':['/a']}),enable_final_certification=False)
    o,cert=compile_control_plan({'a':0,'b':0},[a,b],cfg)
    return not o and cert['reachability']=='UNREACHABLE', bool(o)
add('precedence_cycle_rejection',cyc)

def poison(i):
    rule={'control_rule_id':f'e{i}','path':'/x','immutable':True,'source':'external-policy-v1'}
    cfg,pre=project_verified_semantic_config(RepairConfig(controllability_rules=(rule,),enable_final_certification=False))
    return not cfg.controllability_rules and pre['gated_rule_count']==1, bool(cfg.controllability_rules)
add('unverified_policy_attribution',poison)

payload={'contract':'json-consistency-repair.pass036-benchmark.v1','version':'0.36.0','decisions':sum(counts.values()),'expected_decisions':600,'counts':counts,'false_mutations':false_mutations,'all_checks_pass':all(v==100 for v in counts.values()) and false_mutations==0}
print(json.dumps(payload,sort_keys=True,separators=(',',':')))
