from __future__ import annotations
import json
from pathlib import Path
from json_consistency_repair.engine import RepairConfig, repair_object
from json_consistency_repair.models import AnalysisResult, Candidate, Issue
from json_consistency_repair.causal_cone import apply_authority_firewall, causal_dominance
from json_consistency_repair.bundle import repair_bundle
from json_consistency_repair.streaming import StreamingConfig, repair_stream_file

def cfg(**kw): return RepairConfig(enable_final_certification=False, **kw)
def cascade_object():
    rows=[{'a':a,'one':1,'b':a+1,'c':a+2} for a in range(1,7)]; rows[-1]['b']=99; return {'rows':rows}

def test_root_cause_dominates_downstream_symptom_candidates():
    repaired,res=repair_object(cascade_object(),cfg(min_support=4,arithmetic_confidence=.8)); assert repaired['rows'][-1]=={'a':6,'one':1,'b':7,'c':8}
    dom=res.report['causal_root_analysis']['cycles'][0]['root_cause_dominance']; assert dom['dominated_candidate_ids']
    selected=set(res.report['minimal_transfer_solver']['cycles'][0]['selected_candidate_ids']); assert selected.isdisjoint(dom['dominated_candidate_ids'])
    assert any(w['dominator_path']=='/rows/5/b' and w['resolved_by_dominator']>w['resolved_by_dominated'] for w in dom['witnesses'])

def test_double_cone_materializes_forward_and_backward_surfaces():
    _,res=repair_object(cascade_object(),cfg(min_support=4,arithmetic_confidence=.8)); cone=res.report['causal_root_analysis']['cycles'][0]['double_cone']; edges={(e['from'],e['to']) for e in cone['graph']['edges']}
    assert ('/rows#a','/rows#b') in edges and ('/rows#b','/rows#c') in edges
    terms=[t for t in cone['terminals'] if t['path']=='/rows/5/c']; assert terms and '/rows#b' in terms[0]['backward_nodes'] and terms[0]['equality_surface']

def test_authority_firewall_blocks_lower_authority_contradiction():
    low=Candidate('low','exact_arithmetic','replace','/x',0,1,'inferred',1.0,1,('r',),{'relation_kind':'exact_arithmetic'}); high=Candidate('high','schema_bridge','replace','/x',0,2,'schema',1.0,1,('s',),{'schema_keyword':'const'})
    out,cert=apply_authority_firewall(AnalysisResult([], [low,high], [])); assert [c.candidate_id for c in out.candidates]==['high']; assert cert['blocked_candidates'][0]['reason']=='LOWER_AUTHORITY_CONTRADICTION'

def test_two_authorities_conflict_and_no_mutation():
    dsl=({'kind':'const','array_path':'/rows','field':'flag','value':False,'rule_id':'dsl_false'},); logic=({'kind':'implies','array_path':'/rows','if':{'field':'trigger','equals':True},'then':{'field':'flag','equals':True}},)
    obj={'rows':[{'trigger':False,'flag':False},{'trigger':False,'flag':False},{'trigger':False,'flag':False},{'trigger':True,'flag':None}]}; repaired,res=repair_object(obj,cfg(constraint_rules=dsl,logic_rules=logic,max_cycles=3))
    assert repaired==obj and res.committed_edits==0 and any(i['code']=='authority_conflict' for i in res.report['remaining_issues']); assert res.report['authority_firewall']['authority_conflicts']

def test_authority_conflict_is_hard_terminal_not_fixed_point_success():
    dsl=({'kind':'const','array_path':'/rows','field':'flag','value':False,'rule_id':'dsl_false'},); logic=({'kind':'implies','array_path':'/rows','if':{'field':'trigger','equals':True},'then':{'field':'flag','equals':True}},)
    obj={'rows':[{'trigger':False,'flag':False} for _ in range(4)]}; obj['rows'][-1]={'trigger':True,'flag':None}; _,res=repair_object(obj,cfg(constraint_rules=dsl,logic_rules=logic,max_cycles=4)); assert res.final_status!='PASS'; term=next(i for i in res.report['remaining_issues'] if i['code']=='authority_conflict'); assert term['severity']=='error' and not term['repairable']

def test_independent_repairs_are_not_discarded_as_causal_symptoms():
    root={'left':0,'right':0}; c1=Candidate('c1','unit','replace','/left',0,1,'left',1.0,1,(),{}); c2=Candidate('c2','unit','replace','/right',0,1,'right',1.0,1,(),{})
    def analyze(v):
        issues=[]
        if v['left']==0: issues.append(Issue('unit','left_open','/left','left','warning',True,{}))
        if v['right']==0: issues.append(Issue('unit','right_open','/right','right','warning',True,{}))
        return AnalysisResult(issues,[c1,c2],[])
    filtered,cert=causal_dominance(root,analyze(root),analyze); assert {c.candidate_id for c in filtered.candidates}=={'c1','c2'} and cert['dominated_candidate_ids']==[]

def test_bundle_exposes_per_document_double_cone():
    docs={'a.json':cascade_object(),'b.json':{'rows':[{'id':i} for i in range(1,7)]}}; repaired,res=repair_bundle(docs,cfg(min_support=4,arithmetic_confidence=.8,max_cycles=5)); assert repaired['a.json']['rows'][-1]['b']==7; ca=res.report['causal_root_analysis']; assert set(ca['documents'])=={'a.json','b.json'} and ca['documents']['a.json']['double_cone']['directed_edge_count']>0

def test_stream_exposes_bounded_causal_cone(tmp_path:Path):
    src=tmp_path/'x.jsonl'; out=tmp_path/'o.jsonl'; rows=[{'a':i,'one':1,'b':i+1} for i in range(1,10)]; rows[-1]['b']=99; src.write_text('\n'.join(json.dumps(x) for x in rows)+'\n'); res=repair_stream_file(src,out,None,StreamingConfig(min_support=4,arithmetic_confidence=.8,enable_final_certification=False),stream_format='jsonl'); assert res.report['causal_root_analysis']['double_cone']['mode']=='BOUNDED_STREAM'

def test_final_report_keeps_source_authority_ledger():
    schema={'type':'object','properties':{'kind':{'const':'invoice'}},'required':['kind']}; _,res=repair_object({'kind':'bad'},cfg(json_schema=schema,schema_source='unit-test-schema')); assert any(x['kind']=='authoritative_json_schema' and x['authority']=='AUTHORITATIVE' for x in res.report['authority_firewall']['relation_authority_ledger'])

def test_pass019_contract_names_are_stable():
    _,res=repair_object(cascade_object(),cfg(min_support=4,arithmetic_confidence=.8)); assert res.report['causal_root_analysis']['contract']=='json-consistency-repair.causal-root-analysis.v1'; assert res.report['authority_firewall']['contract']=='json-consistency-repair.authority-firewall.v1'; assert res.report['causal_root_analysis']['final_double_cone']['contract']=='json-consistency-repair.double-cone.v1'

def test_pass019_public_exports_and_schemas_exist():
    import json_consistency_repair as jcr
    root=Path(__file__).resolve().parents[1]
    for name in ('compile_double_cone','apply_authority_firewall','causal_dominance','prepare_causal_analysis'):
        assert hasattr(jcr,name)
    for name in ('double-cone-v1.schema.json','authority-firewall-v1.schema.json','causal-root-analysis-v1.schema.json'):
        data=json.loads((root/'schemas'/name).read_text())
        assert data['$schema']=='https://json-schema.org/draft/2020-12/schema'
