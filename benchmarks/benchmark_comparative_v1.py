from __future__ import annotations
import json, os, random, statistics, subprocess, sys, time, hashlib
from copy import deepcopy
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from json_consistency_repair import RepairConfig, repair_object
from json_consistency_repair.grammar_repair import minimal_grammar_repair
from json_consistency_repair.security import SecurityLimits
from json_consistency_repair._version import __version__

import orjson, ujson, json5, yaml, jsonschema

OUT=ROOT/'benchmarks'/'JSON_COMPARATIVE_BENCHMARK_V1_RESULTS.json'

TOOLS={
    'stdlib_json': lambda s: json.loads(s),
    'orjson': lambda s: orjson.loads(s),
    'ujson': lambda s: ujson.loads(s),
    'json5': lambda s: json5.loads(s),
    'pyyaml_safe': lambda s: yaml.safe_load(s),
}

def canon(x):
    return json.loads(json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False))

def cfg(**kw):
    d=dict(max_cycles=8,strong_fixed_point_cycles_required=2,enable_multisource=False)
    d.update(kw); return RepairConfig(**d)

def strict_correctness(n=500):
    docs=[]
    rng=random.Random(1241)
    for i in range(n):
        obj={'id':i,'name':f'n{i}','ok':bool(i%2),'nums':[i,i+1,rng.randint(-9999,9999)],'meta':{'x':i/10,'none':None,'s':'é\\n"'}}
        docs.append((json.dumps(obj,ensure_ascii=False,separators=(',',':')),obj))
    res={}
    for name,load in TOOLS.items():
        ok=err=0
        for text,expected in docs:
            try:
                val=load(text)
                ok+= canon(val)==canon(expected)
            except Exception:
                err+=1
        res[name]={'semantic_matches':ok,'cases':n,'exceptions':err}
    # JCR exact logical preservation on clean JSON, fewer cases because it is a repair engine not a parser.
    jn=30; ok=edits=0; statuses={}
    for text,expected in docs[:jn]:
        out,r=repair_object(json.loads(text),cfg(max_cycles=4,strong_fixed_point_cycles_required=1))
        ok += canon(out)==canon(expected)
        edits += r.committed_edits
        statuses[r.final_status]=statuses.get(r.final_status,0)+1
    res['jcr_full']={'semantic_matches':ok,'cases':jn,'committed_edits':edits,'statuses':statuses}
    return res

def syntax_cases(per_kind=20):
    cases=[]
    for i in range(per_kind):
        a=i+1; b=2*(i+1); name=f'n{i}'
        cases += [
          ('trailing_comma',f'{{"a":{a},"b":{b},}}',{'a':a,'b':b}),
          ('missing_comma',f'{{"a":{a} "b":{b}}}',{'a':a,'b':b}),
          ('missing_colon',f'{{"a" {a},"b":{b}}}',{'a':a,'b':b}),
          ('truncated_obj',f'{{"a":{a},"b":{b}',{'a':a,'b':b}),
          ('truncated_nested',f'{{"a":{a},"b":[1,2',{'a':a,'b':[1,2]}),
          ('missing_quote',f'{{"a":{a},"name":"{name}}}',{'a':a,'name':name}),
          ('extra_brace',f'{{"a":{a},"b":{b}}}}}',{'a':a,'b':b}),
          ('two_errors',f'{{"a" {a} "b":{b}}}',{'a':a,'b':b}),
          ('array_trailing',f'[{a},{b},]',[a,b]),
          ('array_missing_comma',f'[{a} {b}]',[a,b]),
        ]
    return cases

def syntax_recovery():
    cases=syntax_cases()
    res={name:{'exact_recovery':0,'accepted_wrong_semantics':0,'rejected':0,'cases':len(cases)} for name in TOOLS}
    res['jcr_grammar']={'exact_recovery':0,'accepted_wrong_semantics':0,'rejected':0,'cases':len(cases)}
    by_kind={}
    for kind,text,expected in cases:
        bk=by_kind.setdefault(kind,{k:{'exact':0,'wrong':0,'reject':0} for k in list(TOOLS)+['jcr_grammar']})
        for name,load in TOOLS.items():
            try:
                v=load(text)
                if canon(v)==canon(expected): res[name]['exact_recovery']+=1; bk[name]['exact']+=1
                else: res[name]['accepted_wrong_semantics']+=1; bk[name]['wrong']+=1
            except Exception:
                res[name]['rejected']+=1; bk[name]['reject']+=1
        v,rep=minimal_grammar_repair(text,SecurityLimits(),max_edit_distance=2)
        if v is None:
            res['jcr_grammar']['rejected']+=1; bk['jcr_grammar']['reject']+=1
        elif canon(v)==canon(expected):
            res['jcr_grammar']['exact_recovery']+=1; bk['jcr_grammar']['exact']+=1
        else:
            res['jcr_grammar']['accepted_wrong_semantics']+=1; bk['jcr_grammar']['wrong']+=1
    return {'summary':res,'by_kind':by_kind}

def permissive_coverage(per_kind=20):
    cases=[]
    for i in range(per_kind):
        cases += [
          ('single_quotes',f"{{'a':{i}}}",{'a':i}),
          ('unquoted_key',f'{{a:{i}}}',{'a':i}),
          ('comment',f'{{"a":{i}/*c*/}}',{'a':i}),
        ]
    res={name:{'exact_accept':0,'wrong_accept':0,'reject':0,'cases':len(cases)} for name in TOOLS}
    res['jcr_grammar']={'exact_accept':0,'wrong_accept':0,'reject':0,'cases':len(cases)}
    for kind,text,expected in cases:
        for name,load in TOOLS.items():
            try:
                v=load(text); res[name]['exact_accept' if canon(v)==canon(expected) else 'wrong_accept']+=1
            except Exception: res[name]['reject']+=1
        v,_=minimal_grammar_repair(text,SecurityLimits(),max_edit_distance=2)
        if v is None: res['jcr_grammar']['reject']+=1
        else: res['jcr_grammar']['exact_accept' if canon(v)==canon(expected) else 'wrong_accept']+=1
    return res

def functional_case(m,seed,bounded=False):
    rows=[{'k':f'K{i%5}','v':i%5} for i in range(40)]; truth=deepcopy(rows); inds=random.Random(seed).sample(range(40),m)
    for q,i in enumerate(inds): rows[i]['v']=100+(q%17)
    if bounded:
        rules=tuple({'kind':'implies','array_path':'/rows','if':{'field':'k','equals':f'K{k}'},'then':{'field':'v','equals':k}} for k in range(5))
        conf=cfg(logic_rules=rules)
    else: conf=cfg()
    inp=deepcopy(rows); out,r=repair_object({'rows':rows},conf)
    return {'repaired':sum(out['rows'][i]==truth[i] for i in inds),'corrupted':m,'false_mutations':sum(out['rows'][i]!=truth[i] for i in range(40) if i not in inds),'status':r.final_status,'edits':r.committed_edits,'input':inp,'truth':truth}

def arithmetic_case(m,seed,bounded=False):
    rows=[{'a':i+1,'b':2*(i+1),'total':3*(i+1)} for i in range(40)]; truth=deepcopy(rows); inds=random.Random(seed).sample(range(40),m)
    for q,i in enumerate(inds): rows[i]['total']=-1000-q
    if bounded:
        rule={'kind':'balance','array_path':'/rows','terms':[{'field':'a','coefficient':1},{'field':'b','coefficient':1},{'field':'total','coefficient':-1}],'target':'total'}
        conf=cfg(conservation_rules=(rule,))
    else: conf=cfg()
    inp=deepcopy(rows); out,r=repair_object({'rows':rows},conf)
    return {'repaired':sum(out['rows'][i]==truth[i] for i in inds),'corrupted':m,'false_mutations':sum(out['rows'][i]!=truth[i] for i in range(40) if i not in inds),'status':r.final_status,'edits':r.committed_edits,'input':inp,'truth':truth}

def missing_functional(seed,missing=20):
    rows=[{'k':f'K{i%5}','v':i%5} for i in range(40)]; truth=deepcopy(rows); inds=random.Random(seed).sample(range(40),missing)
    for i in inds: rows[i].pop('v')
    inp=deepcopy(rows); out,r=repair_object({'rows':rows},cfg())
    return {'repaired':sum(out['rows'][i]==truth[i] for i in inds),'corrupted':missing,'false_mutations':sum(out['rows'][i]!=truth[i] for i in range(40) if i not in inds),'status':r.final_status,'edits':r.committed_edits,'input':inp,'truth':truth}

def semantic_repair():
    rates=[2,8,12,16]
    trials=3
    out={'learned_functional':{},'learned_arithmetic':{},'missing_functional':{},'solid_bound_functional':{},'solid_bound_arithmetic':{}}
    for m in rates:
        vals=[functional_case(m,s,False) for s in range(trials)]
        out['learned_functional'][str(m)]={'repaired':sum(v['repaired'] for v in vals),'corrupted':m*trials,'false_mutations':sum(v['false_mutations'] for v in vals),'trial_statuses':[v['status'] for v in vals]}
        vals=[arithmetic_case(m,s,False) for s in range(trials)]
        out['learned_arithmetic'][str(m)]={'repaired':sum(v['repaired'] for v in vals),'corrupted':m*trials,'false_mutations':sum(v['false_mutations'] for v in vals),'trial_statuses':[v['status'] for v in vals]}
    vals=[missing_functional(s,20) for s in range(trials)]
    out['missing_functional']['20']={'repaired':sum(v['repaired'] for v in vals),'corrupted':60,'false_mutations':sum(v['false_mutations'] for v in vals),'trial_statuses':[v['status'] for v in vals]}
    # Test almost-total corruption once a solid independent bound is supplied.
    for m in [16,32,39]:
        fv=[functional_case(m,s,True) for s in range(trials)]
        av=[arithmetic_case(m,s,True) for s in range(trials)]
        out['solid_bound_functional'][str(m)]={'repaired':sum(v['repaired'] for v in fv),'corrupted':m*trials,'false_mutations':sum(v['false_mutations'] for v in fv),'trial_statuses':[v['status'] for v in fv]}
        out['solid_bound_arithmetic'][str(m)]={'repaired':sum(v['repaired'] for v in av),'corrupted':m*trials,'false_mutations':sum(v['false_mutations'] for v in av),'trial_statuses':[v['status'] for v in av]}
    # Conventional parsers preserve the corrupted-but-valid JSON exactly; this is a capability boundary, not a parser defect.
    out['competitor_semantic_repair_api']={name:'NO_SEMANTIC_REPAIR_API_TESTED' for name in TOOLS}
    out['jsonschema']='VALIDATION_ONLY_NO_MATERIALIZING_REPAIR'
    return out

def ambiguity_and_safety(n=100):
    # Duplicate keys: JSON has no unambiguous value-preserving repair without an authority rule.
    texts=[f'{{"a":{i},"a":{i+1}}}' for i in range(n)]
    result={}
    for name,load in TOOLS.items():
        accepted=0; values=[]
        for t in texts:
            try: values.append(load(t)); accepted+=1
            except Exception: pass
        result[name]={'accepted':accepted,'rejected':n-accepted,'note':'acceptance is not counted as correct repair because duplicate-key intent is ambiguous'}
    jrej=0
    for t in texts:
        v,_=minimal_grammar_repair(t,SecurityLimits(),max_edit_distance=2); jrej += v is None
    result['jcr_grammar']={'accepted':n-jrej,'rejected':jrej,'note':'safe rejection expected'}
    # Clean structured random corpora: JCR should not invent edits.
    rng=random.Random(9941); false=0
    for _ in range(20):
        rows=[{'k':f'K{i%5}','v':rng.randrange(10**9),'a':rng.randrange(10**6),'b':rng.randrange(10**6)} for i in range(30)]
        inp={'rows':rows}; repaired,r=repair_object(inp,cfg(max_cycles=4,strong_fixed_point_cycles_required=1)); false += repaired!=inp
    result['jcr_clean_random']={'trials':20,'mutated':false}
    return result

def speed():
    # ~25-35 KiB valid JSON. Shared task is parsing; JCR full includes discovery/verification, so this exposes its overhead rather than pretending equivalence.
    obj={'rows':[{'id':i,'k':f'K{i%7}','a':i,'b':2*i,'s':'x'*20,'arr':[i,i+1,i+2]} for i in range(300)]}
    text=json.dumps(obj,separators=(',',':')); size=len(text.encode())
    result={'bytes':size}
    for name,load in TOOLS.items():
        loops=200 if name!='pyyaml_safe' else 20
        # warmup
        load(text)
        t=time.perf_counter()
        for _ in range(loops): load(text)
        dt=time.perf_counter()-t
        result[name]={'loops':loops,'seconds':dt,'mb_per_s':(size*loops/dt)/1e6}
    times=[]
    for _ in range(3):
        t=time.perf_counter(); repaired,r=repair_object(obj,cfg(max_cycles=4,strong_fixed_point_cycles_required=1)); times.append(time.perf_counter()-t)
    med=statistics.median(times)
    result['jcr_full']={'loops':1,'median_seconds_per_doc':med,'mb_per_s':(size/med)/1e6,'all_trials_seconds':times}
    return result

def versions():
    return {'jcr':__version__,'python':sys.version.split()[0],'orjson':getattr(orjson,'__version__','unknown'),'ujson':getattr(ujson,'__version__','unknown'),'json5':getattr(json5,'__version__','unknown'),'pyyaml':getattr(yaml,'__version__','unknown'),'jsonschema':getattr(jsonschema,'__version__','unknown')}

def main():
    result={
      'benchmark':'JSON_COMPARATIVE_BENCHMARK_V1','scope':'local executable comparison against tools physically available in this environment; no web installation; shared-domain metrics separated from capability gaps',
      'versions':versions(),
      'direct_specialized_json_repair_competitor_gate':{'status':'OPEN','reason':'No dedicated third-party semantic JSON consistency-repair package is installed locally. The installed comparison set consists of strict/permissive parsers and a schema validator.'},
      'strict_valid_json':strict_correctness(),
      'malformed_unique_recovery':syntax_recovery(),
      'permissive_non_json_coverage':permissive_coverage(),
      'semantic_consistency_repair':semantic_repair(),
      'ambiguity_and_safety':ambiguity_and_safety(),
      'valid_json_speed':speed(),
    }
    raw=json.dumps(result,indent=2,sort_keys=True,ensure_ascii=False)
    OUT.write_text(raw,encoding='utf-8')
    print(json.dumps({'output':str(OUT),'sha256':hashlib.sha256(raw.encode()).hexdigest(),'summary':{
      'syntax':result['malformed_unique_recovery']['summary'],
      'semantic':result['semantic_consistency_repair'],
      'speed':result['valid_json_speed'],
      'gate':result['direct_specialized_json_repair_competitor_gate']}},indent=2))

if __name__=='__main__': main()
