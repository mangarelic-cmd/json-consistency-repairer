from __future__ import annotations
from pathlib import Path
from json_consistency_repair import RepairConfig
from json_consistency_repair.models import AnalysisResult, Candidate, Issue
from json_consistency_repair.materialization import materialize_missing_witnesses
import json


def required_analysis():
    return AnalysisResult([Issue('schema_bridge','schema_required_missing','/x','missing','error',False,{})],[],[])

def selector_analysis(i):
    issue=Issue('enum_domain','enum_domain_outlier','/x','outside','warning',False,{'domain':[i,i+1],'domain_id':f'd{i}'})
    a=Candidate(f'a{i}','enum_domain','replace','/x','WRONG',i,'choice',1.0,1,('RULE',),{'formula':f'f{i}'})
    b=Candidate(f'b{i}','enum_domain','replace','/x','WRONG',i+1,'choice',1.0,1,('RULE',),{'formula':f'f{i}'})
    return AnalysisResult([issue],[a,b],[])

def main():
    counts={}; false_mutations=0
    def batch(name,fn):
        nonlocal false_mutations
        ok=0
        for i in range(100):
            good,false=fn(i); ok+=int(good); false_mutations+=int(false)
        counts[name]=ok
    def exact(i):
        add,cert=materialize_missing_witnesses({},required_analysis(),RepairConfig(source_context=({'source_id':'a','role':'authoritative','value':{'x':i}},)))
        good=cert['terminals'][0]['status']=='MATERIALIZED_EXACT' and len(add.candidates)==1 and add.candidates[0].new_value==i
        return good,not good
    batch('authoritative_exact',exact)
    def alias(i):
        m={'identity_bridges':[{'canonical_field':'x','logical_id':'x','members':[{'source_id':'__primary__','field':'x'},{'source_id':'old','field':'z'}]}]}
        add,cert=materialize_missing_witnesses({},required_analysis(),RepairConfig(source_context=({'source_id':'old','role':'authoritative','schema_version':i,'value':{'z':i}},),source_manifest=m))
        return (cert['terminals'][0]['status']=='MATERIALIZED_EXACT' and add.candidates[0].new_value==i,False)
    batch('identity_version_bridge',alias)
    def selector(i):
        add,cert=materialize_missing_witnesses({'x':'WRONG'},selector_analysis(i),RepairConfig(source_context=({'source_id':'r','role':'reference','value':{'x':i+1}},)))
        return (cert['terminals'][0]['status']=='MATERIALIZED_EXACT' and add.candidates[0].new_value==i+1,False)
    batch('finite_domain_selector',selector)
    def ambiguous(i):
        add,cert=materialize_missing_witnesses({},required_analysis(),RepairConfig(source_context=({'source_id':'a','role':'authoritative','value':{'x':i}},{'source_id':'b','role':'authoritative','value':{'x':i+1}})))
        good=cert['terminals'][0]['status']=='MULTIPLE_MATERIALIZATIONS_AMBIGUOUS' and not add.candidates
        return good,bool(add.candidates)
    batch('ambiguity_abstention',ambiguous)
    def observer(i):
        add,cert=materialize_missing_witnesses({},required_analysis(),RepairConfig(source_context=({'source_id':'p','role':'previous','value':{'x':i}},)))
        good=cert['terminals'][0]['status']=='MATERIAL_GATE' and not add.candidates
        return good,bool(add.candidates)
    batch('observer_firewall',observer)
    def absent(i):
        add,cert=materialize_missing_witnesses({},required_analysis(),RepairConfig(source_context=()))
        good=cert['terminals'][0]['status']=='ABSENT_CERTIFIED_WITHIN_SEARCH_CONTRACT' and not add.candidates and cert['semantic_guards']['not_found_is_not_absent']
        return good,bool(add.candidates)
    batch('bounded_absence',absent)
    payload={'contract':'json-consistency-repair.pass029-benchmark.v1','version':'0.29.0','decisions':sum(counts.values()),'expected_decisions':600,
             'counts':counts,'false_mutations':false_mutations,'all_checks_pass':sum(counts.values())==600 and false_mutations==0}
    text=json.dumps(payload,sort_keys=True,separators=(',',':'))+'\n'
    Path(__file__).with_name('PASS029_BENCHMARK.json').write_text(text,encoding='utf-8')
    print(text,end='')
if __name__=='__main__': main()
