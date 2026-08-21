from copy import deepcopy
from json_consistency_repair.models import AnalysisResult, Candidate, Issue
from json_consistency_repair.robust_envelope import apply_robust_envelope_firewall, verify_robust_envelope_certificate

class C:
    logic_document=None; system_document=None; moment_document=None
    def __init__(self,*rules): self.robust_envelope_rules=tuple(rules)

def run(root,candidate,rule):
    issue=Issue(candidate.analyzer,'violation',candidate.path,'x',repairable=True)
    return apply_robust_envelope_firewall(root,AnalysisResult([issue],[candidate],[]),C(rule))

def main():
    counts={}
    for i in range(100):
        root={'x':100+i,'u':2}; c=Candidate(f'u{i}','t','replace','/x',root['x'],root['x']+1,'x')
        out,cert=run(root,c,{'kind':'uncertainty_interval','path':'/x','radius_path':'/u'})
        assert not out.candidates and cert['gated_count']==1 and verify_robust_envelope_certificate(cert)
    counts['uncertainty_inside_gate']=100
    for i in range(100):
        root={'x':100+i,'u':2}; c=Candidate(f's{i}','t','replace','/x',root['x'],root['x']+10,'x')
        out,cert=run(root,c,{'kind':'uncertainty_interval','path':'/x','radius_path':'/u'})
        assert len(out.candidates)==1 and cert['gated_count']==0 and verify_robust_envelope_certificate(cert)
    counts['uncertainty_separated_allow']=100
    for i in range(100):
        stale=i%2==0; ts='2026-08-20T10:00:00Z' if stale else '2026-08-20T15:30:00Z'
        root={'x':i,'ts':ts}; c=Candidate(f'c{i}','t','replace','/x',i,i+1,'x')
        out,cert=run(root,c,{'kind':'clock_freshness','path':'/x','timestamp_path':'/ts','evaluation_time':'2026-08-20T16:00:00Z','max_age_seconds':3600,'max_future_skew_seconds':60})
        assert bool(out.candidates)==(not stale) and verify_robust_envelope_certificate(cert)
    counts['clock_window']=100
    for i in range(100):
        root={'mode':'A','x':i}; bound='B' if i%2==0 else 'A'
        c=Candidate(f'r{i}','t','replace','/x',i,i+1,'x',metadata={'regime_value':bound})
        out,cert=run(root,c,{'kind':'regime_guard','path':'/x','regime_path':'/mode','allowed_values':['A','B']})
        assert bool(out.candidates)==(bound=='A') and verify_robust_envelope_certificate(cert)
    counts['regime_firewall']=100
    for i in range(100):
        metric=10.5 if i%2==0 else 11.5
        root={'state':'OFF','metric':metric,'u':1}; c=Candidate(f'h{i}','t','replace','/state','OFF','ON','x')
        out,cert=run(root,c,{'kind':'hysteresis','state_path':'/state','metric_path':'/metric','on_value':'ON','off_value':'OFF','enter_above':10,'exit_below':8,'uncertainty_radius_path':'/u'})
        assert bool(out.candidates)==(metric==11.5) and verify_robust_envelope_certificate(cert)
    counts['hysteresis_robust_transition']=100
    for i in range(100):
        root={'rows':[{'x':10+i,'u':2}]}; c=Candidate(f'w{i}','t','replace','/rows/0/x',10+i,11+i,'x')
        rule={'kind':'uncertainty_interval','path_pattern':'/rows/*/x','center_path':'/rows/*/x','radius_path':'/rows/*/u'}
        out,cert=run(root,c,rule); bad=deepcopy(cert); bad['gated_count']=999
        assert not out.candidates and verify_robust_envelope_certificate(cert) and not verify_robust_envelope_certificate(bad)
    counts['wildcard_and_tamper_rejection']=100
    assert sum(counts.values())==600
    print({'PASS031':counts,'total':600})

if __name__=='__main__': main()
