from __future__ import annotations
import sys, json, tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))

from json_consistency_repair.engine import RepairConfig, repair_object, score
from json_consistency_repair.minimal_transfer import solve_minimal_transfer
from json_consistency_repair.models import AnalysisResult, Candidate, Issue
from json_consistency_repair.bundle import repair_bundle
from json_consistency_repair.streaming import _choose_candidates_with_certificate

counts={}
def hit(k): counts[k]=counts.get(k,0)+1

def c(cid,path,old,new,cost=1):
    return Candidate(cid,'synthetic','replace',path,old,new,'synthetic',1.0,cost,('E',),{})

# 100 coupled two-edit closures: no singleton improves.
for t in range(100):
    c1=c(f'a{t}','/a',0,1); c2=c(f'b{t}','/b',0,1)
    issue=Issue('synthetic','coupled','/a','coupled','warning',True,{})
    base=AnalysisResult([issue],[c1,c2],[])
    def analyze(x,base=base):
        return AnalysisResult([],[],[]) if x['a']==1 and x['b']==1 else base
    d=solve_minimal_transfer({'a':0,'b':0},base,analyze_fn=analyze,score_fn=score,max_patch_size=2,max_exact_options=4)
    assert d.status.startswith('UNIQUE_EXACT_MINIMUM') and len(d.patches)==2
    hit('coupled')

# 100 exact ties: two equal one-edit solutions => abstain.
for t in range(100):
    c1=c(f'x{t}a','/x',0,1); c2=c(f'x{t}b','/x',0,2)
    issue=Issue('synthetic','tie','/x','tie','warning',True,{})
    base=AnalysisResult([issue],[c1,c2],[])
    def analyze(x,base=base): return AnalysisResult([],[],[]) if x['x'] in (1,2) else base
    d=solve_minimal_transfer({'x':0},base,analyze_fn=analyze,score_fn=score,max_patch_size=1,max_exact_options=4)
    assert d.status=='AMBIGUOUS_EXACT_MINIMUM' and not d.patches
    hit('tie_abstain')

# 100 exact metric preference: same closure, lower exact cost wins.
for t in range(100):
    c1=c(f'm{t}a','/x',0,1,cost=1); c2=c(f'm{t}b','/x',0,22,cost=2)
    issue=Issue('synthetic','metric','/x','metric','warning',True,{})
    base=AnalysisResult([issue],[c1,c2],[])
    def analyze(x,base=base): return AnalysisResult([],[],[]) if x['x'] in (1,22) else base
    d=solve_minimal_transfer({'x':0},base,analyze_fn=analyze,score_fn=score,max_patch_size=1,max_exact_options=4)
    assert len(d.patches)==1 and d.patches[0].new_value==1
    hit('metric_unique')

# 100 real engine records with two simultaneous enum representation repairs.
for t in range(100):
    rows=[{'id':i,'status':'Ready','currency':'USD'} for i in range(12)]
    rows[-1]['status']='ready'; rows[-1]['currency']='usd'
    cfg=RepairConfig(min_support=4,enum_confidence=.75,enum_min_value_support=2,enum_normalization_confidence=.70)
    repaired,res=repair_object({'rows':rows},cfg)
    assert repaired['rows'][-1]['status']=='Ready' and repaired['rows'][-1]['currency']=='USD'
    assert len(res.report['cycles'][0]['accepted'])==2
    hit('real_coupled_record')

# 50 partitioned independent records, globally union-revalidated.
for t in range(50):
    rows=[{'id':i,'status':'Ready'} for i in range(12)]
    rows[10]['status']='ready'; rows[11]['status']='ready'
    cfg=RepairConfig(min_support=4,enum_confidence=.75,enum_min_value_support=3,enum_normalization_confidence=.70)
    repaired,res=repair_object({'rows':rows},cfg)
    assert repaired['rows'][10]['status']==repaired['rows'][11]['status']=='Ready'
    assert res.report['cycles'][0]['minimal_transfer']['status']=='UNIQUE_EXACT_MINIMUM_PARTITIONED'
    hit('partition_union')

# 50 bounded-stream record candidate sets: unique pathwise minima vs exact conflict abstention.
for t in range(25):
    cands=[{'analyzer':'stream_enum','path':'/a','old_value':'x','new_value':'X','confidence':1.0,'reason':'r','evidence':['E']},
           {'analyzer':'stream_functional','path':'/b','old_value':0,'new_value':1,'confidence':1.0,'reason':'r','evidence':['F']}]
    chosen,conf,cert=_choose_candidates_with_certificate(cands)
    assert len(chosen)==2 and conf==0 and cert['status']=='UNIQUE_PATHWISE_MINIMUM'
    hit('stream_unique')
for t in range(25):
    cands=[{'analyzer':'stream_enum','path':'/a','old_value':'x','new_value':'X','confidence':1.0,'reason':'r','evidence':['E']},
           {'analyzer':'stream_functional','path':'/a','old_value':'x','new_value':'Y','confidence':1.0,'reason':'r','evidence':['F']}]
    chosen,conf,cert=_choose_candidates_with_certificate(cands)
    assert not chosen and conf==1 and cert['status']=='PARTIAL_WITH_AMBIGUOUS_PATHS'
    hit('stream_tie')


# 50 bundle records with two cross-document repairs in one record.
for t in range(50):
    users={'users':[{'id':f'U{t}-{i}'} for i in range(8)]}
    products={'products':[{'id':f'P{t}-{i}'} for i in range(8)]}
    orders={'orders':[{'id':100+i,'user_id':f'U{t}-{i}','product_id':f'P{t}-{i}'} for i in range(8)]}
    orders['orders'][7]['user_id']=f'u{t}-7'; orders['orders'][7]['product_id']=f'p{t}-7'
    cfg=RepairConfig(min_support=4,reference_confidence=.75,id_uniqueness_confidence=.75,max_cycles=4)
    repaired,res=repair_bundle({'users.json':users,'products.json':products,'orders.json':orders},cfg)
    row=repaired['orders.json']['orders'][7]
    assert row['user_id']==f'U{t}-7' and row['product_id']==f'P{t}-7'
    cert=res.report['cycles'][0]['cross_document_minimal_transfer']
    assert cert['selected_patch_count']==2 and cert['status'].startswith('UNIQUE_EXACT_MINIMUM')
    hit('bundle_coupled')

assert sum(counts.values())==550
print(counts)
print('TOTAL',sum(counts.values()),'PASS')
