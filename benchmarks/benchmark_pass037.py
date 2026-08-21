from __future__ import annotations
import json
from copy import deepcopy
from json_consistency_repair import RepairConfig, apply_relation_falsification_firewall, verify_relation_falsification_certificate
from json_consistency_repair.analyzers import analyze_all
from json_consistency_repair.models import AnalysisResult, Candidate

counts={}; false_mutations=0
def cfg(**kw):
    d=dict(min_support=4,min_group_support=2,relation_confidence=.8,arithmetic_confidence=.8,enable_final_certification=False,enable_multisource=False); d.update(kw); return RepairConfig(**d)
def add(name,fn):
    global false_mutations
    ok=0
    for i in range(100):
        good,mut=fn(i); ok+=int(bool(good)); false_mutations+=int(bool(mut))
    counts[name]=ok

def survive(i):
    x={'rows':[{'k':'A','v':1},{'k':'A','v':1},{'k':'B','v':2},{'k':'B','v':2},{'k':'B','v':2}]}; cc=cfg(); a=analyze_all(x,cc); _,c=apply_relation_falsification_firewall(x,a,cc)
    return c['states'].get('ADVERSARIAL_SURVIVED',0)>=1 and verify_relation_falsification_certificate(c),False
add('functional_survival',survive)

def constant(i):
    x={'rows':[{'k':'A','v':'same'},{'k':'A','v':'same'},{'k':'B','v':'same'},{'k':'B','v':'same'},{'k':'A'}]}; cc=cfg(); a=analyze_all(x,cc); f,c=apply_relation_falsification_firewall(x,a,cc)
    bad=bool(f.candidates)
    return c['states'].get('NEGATIVE_CONTROL_INVARIANT',0)>=1 and not f.candidates,bad
add('negative_control_gate',constant)

def split(i):
    rows=[{'k':'A','v':'X'},{'k':'A','v':'Y'},{'k':'A','v':'X'},{'k':'A','v':'Y'},{'k':'A','v':'X'},{'k':'B','v':'Z'},{'k':'B','v':'Z'},{'k':'B','v':'Z'},{'k':'B','v':'Z'}]; x={'rows':rows}; cc=cfg(relation_confidence=.7); a=analyze_all(x,cc); f,c=apply_relation_falsification_firewall(x,a,cc)
    bad=any(r.get('falsification_state')=='ACTIVE_REFUTED' for r in f.relations)
    return c['states'].get('ACTIVE_REFUTED',0)>=1 and not bad,bad
add('split_refutation',split)

def heldout(i):
    rel={'relation_id':f'r{i}','kind':'cross_source_functional','array_path':'','inputs':['k'],'output':'v','validation_state':'GLOBAL_REFUTED','counterexample_count':1}; cand=Candidate(f'c{i}','multisource_lifecycle','replace','/v','bad','good','bench',1.0,1,(),{'relation_id':f'r{i}','relation_kind':'cross_source_functional'}); f,c=apply_relation_falsification_firewall({'v':'bad'},AnalysisResult([], [cand], [rel]),cfg())
    return not f.candidates and c['blocked_candidate_count']==1,bool(f.candidates)
add('independent_counterexample',heldout)

def auth(i):
    cc=cfg(json_schema={'type':'object','properties':{'x':{'const':2}}}); a=analyze_all({'x':i},cc); f,c=apply_relation_falsification_firewall({'x':i},a,cc)
    return any(r['state']=='AUTHORITATIVE_CONTRACT' for r in c['relations']),False
add('authoritative_separation',auth)

def verify(i):
    x={'rows':[{'k':'A','v':1},{'k':'A','v':1},{'k':'B','v':2},{'k':'B','v':2}]}; cc=cfg(); a=analyze_all(x,cc); _,c=apply_relation_falsification_firewall(x,a,cc); b=deepcopy(c); b['blocked_relation_count']+=1
    return verify_relation_falsification_certificate(c) and not verify_relation_falsification_certificate(b),False
add('certificate_integrity',verify)

payload={'contract':'json-consistency-repair.pass037-benchmark.v1','version':'0.37.0','decisions':sum(counts.values()),'expected_decisions':600,'counts':counts,'false_mutations':false_mutations,'all_checks_pass':all(v==100 for v in counts.values()) and false_mutations==0}
print(json.dumps(payload,sort_keys=True,separators=(',',':')))
