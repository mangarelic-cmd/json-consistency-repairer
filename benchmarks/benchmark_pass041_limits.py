from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import json, os, random, statistics, subprocess, sys, time

from json_consistency_repair import RepairConfig, repair_object
from json_consistency_repair.analyzers import analyze_all
from json_consistency_repair.grammar_repair import minimal_grammar_repair
from json_consistency_repair.security import SecurityLimits
from json_consistency_repair._version import __version__

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'benchmarks'/'PASS041_LIMIT_BENCHMARK.json'


def cfg(**kw):
    d=dict(max_cycles=8,strong_fixed_point_cycles_required=2,enable_multisource=False)
    d.update(kw); return RepairConfig(**d)


def corruption_case(kind,m,seed):
    n=40
    if kind=='functional': rows=[{'k':f'K{i%5}','v':i%5} for i in range(n)]
    else: rows=[{'a':i+1,'b':2*(i+1),'total':3*(i+1)} for i in range(n)]
    truth=deepcopy(rows); inds=random.Random(seed).sample(range(n),m)
    for q,i in enumerate(inds):
        if kind=='functional': rows[i]['v']=100+(q%13)
        else: rows[i]['total']=-1000-q
    inp=deepcopy(rows); t=time.perf_counter(); out,res=repair_object({'rows':rows},cfg()); dt=time.perf_counter()-t
    exact=sum(out['rows'][i]==truth[i] for i in inds)
    false_mut=sum(out['rows'][i]!=truth[i] for i in range(n) if i not in inds)
    unchanged_bad=sum(out['rows'][i]==inp[i] and inp[i]!=truth[i] for i in inds)
    return {'seed':seed,'exact':exact,'m':m,'false_mutations':false_mut,'unchanged_bad':unchanged_bad,
            'edits':res.committed_edits,'status':res.final_status,'seconds':dt}


def missing3_case(seed):
    rows=[{'k':f'K{i%5}','v':i%5} for i in range(40)]; truth=deepcopy(rows)
    inds=random.Random(seed).sample(range(40),3)
    for i in inds: rows[i].pop('v')
    t=time.perf_counter(); out,res=repair_object({'rows':rows},cfg()); dt=time.perf_counter()-t
    return {'seed':seed,'indices':inds,'exact':sum(out['rows'][i]==truth[i] for i in inds),'edits':res.committed_edits,'status':res.final_status,'seconds':dt}


def syntax_frontier():
    cases=[
      ('trailing_comma','{"a":1,}',{'a':1}),
      ('missing_comma','{"a":1 "b":2}',{'a':1,'b':2}),
      ('missing_colon','{"a" 1}',{'a':1}),
      ('truncated_obj','{"a":1',{'a':1}),
      ('truncated_nested','{"a":[1,2',{'a':[1,2]}),
      ('single_quotes',"{'a':1}",None),
      ('unquoted_key','{a:1}',None),
      ('comment','{"a":1/*x*/}',None),
      ('duplicate_key','{"a":1,"a":2}',None),
      ('missing_quote','{"a":"x}',{'a':'x'}),
      ('extra_brace','{"a":1}}',{'a':1}),
      ('two_errors','{"a" 1 "b":2}',{'a':1,'b':2}),
      ('array_trailing','[1,2,]',[1,2]),
      ('array_missing_comma','[1 2]',[1,2]),
    ]
    out=[]
    for name,text,expected in cases:
        v,rep=minimal_grammar_repair(text,SecurityLimits(),max_edit_distance=2)
        out.append({'case':name,'repaired':v is not None,'exact':v==expected if expected is not None else v is None,
                    'expected_automatic':expected is not None,'value':v,'report':rep})
    return out


def negative_surfaces():
    rng=random.Random(410410)
    random_trigger=0
    for _ in range(10):
        rows=[{'k':f'K{i%5}','v':rng.randrange(10**9),'a':rng.randrange(1,10**6),'b':rng.randrange(1,10**6)} for i in range(30)]
        a=analyze_all({'rows':rows},cfg())
        random_trigger += int(any(r.get('recovery_route')=='SPARSE_OUTLIER_RECOVERY' for r in a.relations))
    coherent_trigger=0
    for j in range(5):
        rows=[]
        for k in range(5):
            rows += [{'k':f'K{k}','v':k} for _ in range(5)]
            rows += [{'k':f'K{k}','v':1000+j*10+k} for _ in range(3)]
        a=analyze_all({'rows':rows},cfg())
        coherent_trigger += int(any(r.get('recovery_route')=='SPARSE_OUTLIER_RECOVERY' for r in a.relations))
    return {'random_structured_trials':10,'random_sparse_promotions':random_trigger,
            'coherent_competing_mode_trials':5,'coherent_sparse_promotions':coherent_trigger}


def perf_worker_source(srcroot:str,n:int=1000):
    code=r'''
import time, json
from copy import deepcopy
from json_consistency_repair import RepairConfig, repair_object
n=int(__import__('sys').argv[1])
rows=[{'k':f'K{i%5}','v':i%5,'a':i+1,'b':2*(i+1),'total':3*(i+1)} for i in range(n)]
rows[n//3]['v']=99991; rows[(2*n)//3]['total']=-99991
cfg=RepairConfig(max_cycles=8,strong_fixed_point_cycles_required=2,enable_multisource=False)
t=time.perf_counter(); out,res=repair_object({'rows':rows},cfg); dt=time.perf_counter()-t
print(json.dumps({'seconds':dt,'edits':res.committed_edits,'status':res.final_status}))
'''
    env=os.environ.copy(); env['PYTHONPATH']=str(Path(srcroot)/'src')
    p=subprocess.run([sys.executable,'-c',code,str(n)],env=env,text=True,capture_output=True,check=True)
    return json.loads(p.stdout.strip().splitlines()[-1])


def rss_worker(srcroot:str|None):
    if srcroot is None:
        code='import resource; print(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)'
        env=os.environ.copy()
    else:
        code='import resource, json_consistency_repair; print(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)'
        env=os.environ.copy(); env['PYTHONPATH']=str(Path(srcroot)/'src')
    p=subprocess.run([sys.executable,'-c',code],env=env,text=True,capture_output=True,check=True)
    return int(p.stdout.strip().splitlines()[-1])


def main():
    missing=[missing3_case(7388+i) for i in range(3)]
    boundary={}
    for kind in ('functional','arithmetic'):
        rows=[]
        for m in (3,8,12,16):
            vals=[corruption_case(kind,m,s) for s in range(3)]
            rows.append({'wrong':m,'rate':m/40,'trials':vals,
                         'exact_repair_recall':sum(v['exact'] for v in vals)/(m*len(vals)),
                         'zero_false_mutation_trials':sum(v['false_mutations']==0 for v in vals),
                         'mean_seconds':statistics.mean(v['seconds'] for v in vals)})
        boundary[kind]=rows

    syntax=syntax_frontier()
    negatives=negative_surfaces()
    oldroot='/mnt/data/json_v040_original'; newroot=str(ROOT)
    perf={'v0.40.0':[perf_worker_source(oldroot,500)],
          'v0.41.0':[perf_worker_source(newroot,500)]}
    for k in list(perf):
        perf[k+'_median_seconds']=statistics.median(x['seconds'] for x in perf[k])
    plain=rss_worker(None); imported=rss_worker(newroot)
    rss={'plain_interpreter_maxrss_kb':plain,'with_jcr_import_maxrss_kb':imported,'incremental_import_overhead_kb':imported-plain}

    result={
      'engine':'json-consistency-repair','version':__version__,'benchmark':'PASS041_SC_MINIMAL_DISPLACEMENT_LIMITS',
      'three_missing_nonmonotonicity':{'trials':missing,'all_exact':all(x['exact']==3 for x in missing)},
      'wrong_value_boundary':boundary,
      'sparse_route_negative_controls':negatives,
      'syntax_frontier':syntax,
      'syntax_exact_automatic_repairs':sum(x['repaired'] and x['expected_automatic'] and x['exact'] for x in syntax),
      'syntax_total':len(syntax),
      'full_object_performance':perf,
      'rss_attribution':rss,
      'pass_semantics':'NO_UNRESOLVED_VIOLATION_UNDER_CURRENT_CERTIFIED_RELATIONS; NOT_EXTERNAL_GROUND_TRUTH_PROOF',
      'external_market_comparator_gate':{'status':'EXTERNAL_GATE_OPEN','reason':'No specialized JSON repair comparator package/corpus is installed; json/orjson/ujson/json5 are parsers, not semantic repair equivalents.'},
    }
    OUT.write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps({'output':str(OUT),'summary':{
      'three_missing_all_exact':result['three_missing_nonmonotonicity']['all_exact'],
      'functional':[(x['wrong'],x['exact_repair_recall']) for x in boundary['functional']],
      'arithmetic':[(x['wrong'],x['exact_repair_recall']) for x in boundary['arithmetic']],
      'syntax_exact_automatic_repairs':result['syntax_exact_automatic_repairs'],
      'negative_controls':negatives,'perf':perf,'rss':rss}},indent=2))

if __name__=='__main__': main()
