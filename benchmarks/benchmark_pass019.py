from __future__ import annotations
import json
from json_consistency_repair import __version__
from json_consistency_repair.engine import RepairConfig,repair_object
from json_consistency_repair.models import AnalysisResult,Candidate
from json_consistency_repair.causal_cone import apply_authority_firewall
from json_consistency_repair.provenance import package_code_sha256

root_ok=0; auth_ok=0; abstain_ok=0; false_mutations=0
for n in range(300):
    rows=[{'a':a+n,'one':1,'b':a+n+1,'c':a+n+2} for a in range(1,7)]; rows[-1]['b']=9000+n; obj={'rows':rows}
    out,res=repair_object(obj,RepairConfig(min_support=4,arithmetic_confidence=.8,enable_final_certification=False))
    ok=out['rows'][-1]['b']==n+7 and out['rows'][-1]['c']==n+8 and bool(res.report['causal_root_analysis']['cycles'][0]['root_cause_dominance']['dominated_candidate_ids'])
    root_ok+=int(ok); false_mutations+=int(not ok)
for n in range(150):
    low=Candidate(f'l{n}','exact_arithmetic','replace','/x',0,n+1,'low',1,1,(),{'relation_kind':'exact_arithmetic'}); high=Candidate(f'h{n}','schema_bridge','replace','/x',0,999,'high',1,1,(),{'schema_keyword':'const'})
    out,cert=apply_authority_firewall(AnalysisResult([], [low,high], [])); auth_ok+=int(len(out.candidates)==1 and out.candidates[0].candidate_id==f'h{n}' and len(cert['blocked_candidates'])==1)
for n in range(150):
    dsl=({'kind':'const','array_path':'/rows','field':'flag','value':False,'rule_id':'dsl_false'},); logic=({'kind':'implies','array_path':'/rows','if':{'field':'trigger','equals':True},'then':{'field':'flag','equals':True}},)
    obj={'rows':[{'trigger':False,'flag':False} for _ in range(4)]}; obj['rows'][-1]={'trigger':True,'flag':None}; out,res=repair_object(obj,RepairConfig(constraint_rules=dsl,logic_rules=logic,enable_final_certification=False,max_cycles=3)); ok=out==obj and any(i['code']=='authority_conflict' for i in res.report['remaining_issues']); abstain_ok+=int(ok); false_mutations+=int(out!=obj)
result={'contract':'json-consistency-repair.pass019-benchmark.v1','version':__version__,'package_code_sha256':package_code_sha256(),'root_cause':{'pass':root_ok,'total':300},'authority_precedence':{'pass':auth_ok,'total':150},'authority_conflict_abstention':{'pass':abstain_ok,'total':150},'expected_decisions':root_ok+auth_ok+abstain_ok,'expected_total':600,'false_mutations':false_mutations,'all_checks_pass':root_ok==300 and auth_ok==150 and abstain_ok==150 and false_mutations==0}
print(json.dumps(result,sort_keys=True))
