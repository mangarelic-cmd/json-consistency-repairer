from __future__ import annotations
import json, os, statistics, subprocess, sys, time
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'benchmarks'/'PASS041_SPEED_BENCHMARK.json'
BASELINE=Path(os.environ.get('JCR_V040_ROOT','/mnt/data/json_v040_original'))


def worker(root:Path,n:int,mode:str='full',dirty:bool=True,repeats:int=1):
    code=r'''
import json,sys,time,statistics
from json_consistency_repair import repair_object,RepairConfig
n=int(sys.argv[1]); mode=sys.argv[2]; dirty=sys.argv[3]=='1'; repeats=int(sys.argv[4])
base=[{'k':f'K{i%5}','v':i%5,'a':i+1,'b':2*(i+1),'total':3*(i+1)} for i in range(n)]
if dirty:
    base[31]['v']=99
    if n>100: base[min(777,n-1)]['total']=-1
t=[]; out=None; rr=None
for _ in range(repeats):
    rows=json.loads(json.dumps(base))
    kw={}
    if 'execution_mode' in RepairConfig.__dataclass_fields__: kw['execution_mode']=mode
    start=time.perf_counter(); out,rr=repair_object(rows,RepairConfig(**kw)); t.append(time.perf_counter()-start)
expected=json.loads(json.dumps(base))
if dirty:
    expected[31]['v']=31%5
    if n>100: expected[min(777,n-1)]['total']=3*(min(777,n-1)+1)
print(json.dumps({'n':n,'mode':mode,'dirty':dirty,'seconds_median':statistics.median(t),'seconds_all':t,
 'status':rr.final_status,'edits':rr.committed_edits,'exact':out==expected,
 'certification_gate':(rr.report or {}).get('certification_gate'),
 'scan_scope':((rr.report or {}).get('execution_profile') or {}).get('scan_scope')}))
'''
    env=os.environ.copy(); env['PYTHONPATH']=str(root/'src')
    p=subprocess.run([sys.executable,'-c',code,str(n),mode,'1' if dirty else '0',str(repeats)],cwd=root,env=env,text=True,capture_output=True,check=True)
    return json.loads(p.stdout.strip().splitlines()[-1])


def syntax_frontier():
    sys.path.insert(0,str(ROOT/'src'))
    from json_consistency_repair.grammar_repair import minimal_grammar_repair
    from json_consistency_repair.security import SecurityLimits
    cases=[
      ('trailing_comma','{"a":1,}',{'a':1}),('missing_comma','{"a":1 "b":2}',{'a':1,'b':2}),
      ('missing_colon','{"a" 1}',{'a':1}),('truncated_obj','{"a":1',{'a':1}),
      ('truncated_nested','{"a":[1,2',{'a':[1,2]}),('single_quotes',"{'a':1}",{'a':1}),
      ('unquoted_key','{a:1}',{'a':1}),('comment','{"a":1/*x*/}',{'a':1}),
      ('duplicate_key','{"a":1,"a":2}',None),('missing_quote','{"a":"x}',{'a':'x'}),
      ('extra_brace','{"a":1}}',{'a':1}),('two_errors','{"a" 1 "b":2}',{'a':1,'b':2}),
      ('array_trailing','[1,2,]',[1,2]),('array_missing_comma','[1 2]',[1,2])]
    rows=[]
    for name,text,expected in cases:
        v,rep=minimal_grammar_repair(text,SecurityLimits(),max_edit_distance=2)
        rows.append({'case':name,'expected':expected,'result':v,'contract_exact':v==expected,
                     'operation':rep[0].get('operation') if rep else None})
    return rows


def main():
    current_full=[]; current_fast=[]; baseline=[]
    for n in (100,500,1000):
        current_full.append(worker(ROOT,n,'full',True,1))
        current_fast.append(worker(ROOT,n,'fast',True,5))
        if BASELINE.exists(): baseline.append(worker(BASELINE,n,'full',True,1))
    fast_valid=[worker(ROOT,n,'fast',False,5) for n in (100,500,1000,5000)]
    fast_dirty_large=worker(ROOT,5000,'fast',True,3)
    syn=syntax_frontier()
    speedups=[]
    if baseline:
        for b,f,ff in zip(baseline,current_full,current_fast):
            speedups.append({'n':b['n'],'v040_to_full_x':b['seconds_median']/f['seconds_median'],
                             'v040_to_fast_x':b['seconds_median']/ff['seconds_median'],
                             'full_to_fast_x':f['seconds_median']/ff['seconds_median']})
    result={
      'benchmark':'PASS041_SC_HOT_PATH_SPEED_AND_COVERAGE','current_root':str(ROOT),'baseline_root':str(BASELINE),
      'architecture':{
        'full':'exhaustive analysis + global correction + replay + independent certification',
        'fast':'all analyzer families scan; expensive falsification and mutation search deepen only around actionable local repair cones; never claims full certification',
        'fast_escalation':'rerun with execution_mode=full when global proof/certification is required'},
      'baseline_v040_full_dirty':baseline,'pass041_full_dirty':current_full,'pass041_fast_dirty':current_fast,
      'pass041_fast_valid':fast_valid,'pass041_fast_dirty_5000':fast_dirty_large,'speedups':speedups,
      'syntax_frontier':syn,'syntax_contract_pass':sum(x['contract_exact'] for x in syn),'syntax_contract_total':len(syn),
      'determinable_syntax_repairs':sum(x['expected'] is not None and x['contract_exact'] for x in syn),
      'ambiguous_refusals_correct':sum(x['expected'] is None and x['contract_exact'] for x in syn),
      'fast_assurance_check':{'all_exact':all(x['exact'] for x in current_fast),
        'never_full_certifies':all(x['certification_gate']=='FAST_SCAN_ONLY' for x in current_fast),
        'scan_scope_all_analyzers':all(x['scan_scope']=='ALL_ANALYZERS' for x in current_fast)},
    }
    OUT.write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps({'output':str(OUT),'speedups':speedups,'fast_1000':current_fast[-1],
                      'full_1000':current_full[-1],'syntax':f"{result['syntax_contract_pass']}/{result['syntax_contract_total']}"},indent=2))

if __name__=='__main__': main()
