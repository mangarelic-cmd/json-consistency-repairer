from pathlib import Path
from copy import deepcopy
import json
from json_consistency_repair.models import AnalysisResult, Candidate, Issue
from json_consistency_repair.robust_envelope import apply_robust_envelope_firewall, verify_robust_envelope_certificate

class C:
    logic_document=None; system_document=None; moment_document=None
    def __init__(self,*rules): self.robust_envelope_rules=tuple(rules)

def eval_one(root,c,rule):
    a=AnalysisResult([Issue(c.analyzer,'v',c.path,'v',repairable=True)],[c],[])
    return apply_robust_envelope_firewall(root,a,C(rule))

def main():
    counts={}; false_mutations=0
    def batch(name,fn):
        nonlocal false_mutations
        ok=0
        for i in range(100):
            good,false=fn(i); ok+=int(good); false_mutations+=int(false)
        counts[name]=ok
    def uncertainty_gate(i):
        root={'x':i,'u':2}; c=Candidate(f'a{i}','t','replace','/x',i,i+1,'x')
        out,cert=eval_one(root,c,{'kind':'uncertainty_interval','path':'/x','radius_path':'/u'})
        good=(not out.candidates and cert['gated_count']==1 and verify_robust_envelope_certificate(cert)); return good,bool(out.candidates)
    batch('uncertainty_abstention',uncertainty_gate)
    def uncertainty_allow(i):
        root={'x':i,'u':2}; c=Candidate(f'b{i}','t','replace','/x',i,i+10,'x')
        out,cert=eval_one(root,c,{'kind':'uncertainty_interval','path':'/x','radius_path':'/u'})
        good=(len(out.candidates)==1 and cert['gated_count']==0 and verify_robust_envelope_certificate(cert)); return good,not good
    batch('uncertainty_separation',uncertainty_allow)
    def stale(i):
        root={'x':i,'ts':'2026-08-20T10:00:00Z'}; c=Candidate(f'c{i}','t','replace','/x',i,i+1,'x')
        out,cert=eval_one(root,c,{'kind':'clock_freshness','path':'/x','timestamp_path':'/ts','evaluation_time':'2026-08-20T16:00:00Z','max_age_seconds':3600})
        good=not out.candidates and verify_robust_envelope_certificate(cert); return good,bool(out.candidates)
    batch('stale_clock_gate',stale)
    def regime(i):
        root={'mode':'A','x':i}; c=Candidate(f'd{i}','t','replace','/x',i,i+1,'x',metadata={'regime_value':'B'})
        out,cert=eval_one(root,c,{'kind':'regime_guard','path':'/x','regime_path':'/mode','allowed_values':['A','B']})
        good=not out.candidates and verify_robust_envelope_certificate(cert); return good,bool(out.candidates)
    batch('cross_regime_gate',regime)
    def hyst(i):
        root={'state':'OFF','metric':10.5,'u':1}; c=Candidate(f'e{i}','t','replace','/state','OFF','ON','x')
        out,cert=eval_one(root,c,{'kind':'hysteresis','state_path':'/state','metric_path':'/metric','enter_above':10,'exit_below':8,'uncertainty_radius_path':'/u'})
        good=not out.candidates and verify_robust_envelope_certificate(cert); return good,bool(out.candidates)
    batch('hysteresis_band_gate',hyst)
    def wildcard(i):
        root={'rows':[{'x':i,'u':2}]}; c=Candidate(f'f{i}','t','replace','/rows/0/x',i,i+1,'x')
        out,cert=eval_one(root,c,{'kind':'uncertainty_interval','path_pattern':'/rows/*/x','center_path':'/rows/*/x','radius_path':'/rows/*/u'})
        bad=deepcopy(cert); bad['candidate_count_after']=999
        good=not out.candidates and verify_robust_envelope_certificate(cert) and not verify_robust_envelope_certificate(bad); return good,bool(out.candidates)
    batch('wildcard_tamper_firewall',wildcard)
    payload={'contract':'json-consistency-repair.pass031-benchmark.v1','version':'0.31.0','decisions':sum(counts.values()),'expected_decisions':600,
             'counts':counts,'false_mutations':false_mutations,'all_checks_pass':sum(counts.values())==600 and false_mutations==0}
    text=json.dumps(payload,sort_keys=True,separators=(',',':'))+'\n'; Path(__file__).with_name('PASS031_BENCHMARK.json').write_text(text,encoding='utf-8'); print(text,end='')
if __name__=='__main__': main()
