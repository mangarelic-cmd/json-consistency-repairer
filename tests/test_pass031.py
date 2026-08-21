import json
from pathlib import Path
from json_consistency_repair import RepairConfig, repair_object, repair_bundle, StreamingConfig, repair_stream_file
from json_consistency_repair.models import AnalysisResult, Candidate, Issue
from json_consistency_repair.robust_envelope import apply_robust_envelope_firewall, verify_robust_envelope_certificate


def cfg(schema=None,rules=(),**kw):
    return RepairConfig(json_schema=schema,robust_envelope_rules=tuple(rules),min_support=1,max_cycles=5,**kw)


def test_uncertainty_inside_envelope_abstains_and_certifies():
    schema={'type':'object','properties':{'x':{'const':11}}}
    rules=({'kind':'uncertainty_interval','path':'/x','radius_path':'/u'},)
    out,res=repair_object({'x':10,'u':2},cfg(schema,rules))
    assert out['x']==10 and res.committed_edits==0
    assert res.report['remaining_issues'][0]['repairable'] is False
    final=res.report['robust_envelope']['final']
    assert final['gated_count']==1 and verify_robust_envelope_certificate(final)
    assert res.report['final_certification']['checks']['robust_envelope'] is True


def test_uncertainty_outside_envelope_allows_exact_repair():
    schema={'type':'object','properties':{'x':{'const':20}}}
    rules=({'kind':'uncertainty_interval','path':'/x','radius_path':'/u'},)
    out,res=repair_object({'x':10,'u':2},cfg(schema,rules))
    assert out['x']==20 and res.committed_edits==1 and res.remaining_issues==0
    assert res.report['final_certification']['ok'] is True


def test_clock_stale_and_fresh_are_distinguished_without_wall_clock():
    schema={'type':'object','properties':{'x':{'const':2}}}
    base={'kind':'clock_freshness','path':'/x','timestamp_path':'/ts','evaluation_time':'2026-08-20T16:00:00Z','max_age_seconds':3600,'max_future_skew_seconds':60}
    stale,_=repair_object({'x':1,'ts':'2026-08-20T10:00:00Z'},cfg(schema,(base,),enable_final_certification=False))
    fresh,res=repair_object({'x':1,'ts':'2026-08-20T15:30:00Z'},cfg(schema,(base,),enable_final_certification=False))
    assert stale['x']==1
    assert fresh['x']==2 and res.committed_edits==1


def test_clock_rule_without_evaluation_time_is_a_gate():
    schema={'type':'object','properties':{'x':{'const':2}}}
    rule={'kind':'clock_freshness','path':'/x','timestamp_path':'/ts','max_age_seconds':3600}
    out,res=repair_object({'x':1,'ts':'2026-08-20T15:30:00Z'},cfg(schema,(rule,),enable_final_certification=False))
    assert out['x']==1
    reasons=[e['reason'] for d in res.report['robust_envelope']['final']['decisions'] for e in d['evaluations']]
    assert 'CLOCK_EVALUATION_TIME_REQUIRED' in reasons


def test_regime_guard_rejects_cross_regime_candidate_and_accepts_matching():
    root={'mode':'A','x':1}
    i=Issue('t','bad','/x','x',repairable=True)
    c_bad=Candidate('c1','t','replace','/x',1,2,'x',metadata={'regime_value':'B'})
    c_good=Candidate('c2','t','replace','/x',1,2,'x',metadata={'regime_value':'A'})
    rule={'kind':'regime_guard','path':'/x','regime_path':'/mode','allowed_values':['A','B']}
    class C: robust_envelope_rules=(rule,); logic_document=None; system_document=None; moment_document=None
    out,cert=apply_robust_envelope_firewall(root,AnalysisResult([i],[c_bad,c_good],[]),C())
    assert [c.candidate_id for c in out.candidates]==['c2']
    assert cert['gated_count']==1 and verify_robust_envelope_certificate(cert)


def test_hysteresis_requires_threshold_to_survive_uncertainty():
    schema={'type':'object','properties':{'state':{'const':'ON'}}}
    rule={'kind':'hysteresis','state_path':'/state','metric_path':'/metric','on_value':'ON','off_value':'OFF','enter_above':10,'exit_below':8,'uncertainty_radius_path':'/u'}
    blocked,_=repair_object({'state':'OFF','metric':10.5,'u':1},cfg(schema,(rule,),enable_final_certification=False))
    allowed,res=repair_object({'state':'OFF','metric':11.5,'u':1},cfg(schema,(rule,),enable_final_certification=False))
    assert blocked['state']=='OFF'
    assert allowed['state']=='ON' and res.committed_edits==1


def test_bundle_document_scoped_envelope():
    docs={'a.json':{'x':10,'u':2},'b.json':{'x':10,'u':2}}
    schema={'type':'object','properties':{'x':{'const':11}}}
    rule={'kind':'uncertainty_interval','document':'a.json','path':'/x','radius_path':'/u'}
    out,res=repair_bundle(docs,cfg(schema,(rule,),enable_final_certification=False))
    assert out['a.json']['x']==10
    assert out['b.json']['x']==11
    assert res.report['robust_envelope']['documents']['a.json']['final']['enabled'] is True


def test_streaming_record_bridge_obeys_clock_envelope(tmp_path:Path):
    inp=tmp_path/'in.jsonl'; outp=tmp_path/'out.jsonl'
    inp.write_text(json.dumps({'x':1,'ts':'2026-08-20T10:00:00Z'})+'\n'+json.dumps({'x':1,'ts':'2026-08-20T15:30:00Z'})+'\n')
    schema={'type':'object','properties':{'x':{'const':2}}}
    rule={'kind':'clock_freshness','path':'/x','timestamp_path':'/ts','evaluation_time':'2026-08-20T16:00:00Z','max_age_seconds':3600,'max_future_skew_seconds':60}
    res=repair_stream_file(inp,outp,config=StreamingConfig(json_schema=schema,robust_envelope_rules=(rule,),exact_disk_registry=True,min_support=1,max_cycles=4,enable_final_certification=False))
    rows=[json.loads(x) for x in outp.read_text().splitlines() if x.strip()]
    assert rows[0]['x']==1 and rows[1]['x']==2
    assert res.report['robust_envelope']['certificate_samples']
