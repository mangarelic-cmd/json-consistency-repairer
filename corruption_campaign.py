import random,time,json
from copy import deepcopy
from json_consistency_repair import repair_object, RepairConfig

def cfg(): return RepairConfig(max_cycles=8,strong_fixed_point_cycles_required=2,enable_multisource=False)

def run(kind,m,seed,n=40,mode='mixed'):
 rng=random.Random(seed)
 if kind=='functional':
  rows=[{'k':f'K{i%5}','v':i%5} for i in range(n)]
 elif kind=='arithmetic':
  rows=[{'a':i+1,'b':2*(i+1),'total':3*(i+1)} for i in range(n)]
 truth=deepcopy(rows); inds=rng.sample(range(n),m)
 for q,i in enumerate(inds):
  if kind=='functional':
   if mode=='missing' or (mode=='mixed' and q%2): rows[i].pop('v')
   else: rows[i]['v']=100+(q%13)
  else:
   if mode=='missing': rows[i].pop('total')
   else: rows[i]['total']=-1000-q
 inp=deepcopy(rows)
 t=time.perf_counter(); out,res=repair_object({'rows':rows},cfg()); dt=time.perf_counter()-t
 exact=sum(out['rows'][i]==truth[i] for i in inds)
 unchanged_bad=sum(out['rows'][i]==inp[i] and inp[i]!=truth[i] for i in inds)
 wrong_mut=sum(out['rows'][i]!=truth[i] and out['rows'][i]!=inp[i] for i in inds)
 false_mut=sum(out['rows'][i]!=truth[i] for i in range(n) if i not in inds)
 return {'exact':exact,'m':m,'unchanged_bad':unchanged_bad,'wrong_mut':wrong_mut,'false_mut':false_mut,'edits':res.committed_edits,'status':res.final_status,'seconds':dt}

res=[]
for kind in ['functional','arithmetic']:
 for mode in (['missing','wrong'] if kind=='functional' else ['missing','wrong']):
  for m in [1,2,3,4,6,8,12]:
   for seed in range(3): res.append({'kind':kind,'mode':mode,'seed':seed,'n':40,**run(kind,m,seed,40,mode)})
open('/mnt/data/json_bench_work/CORRUPTION_CAMPAIGN_RAW.json','w').write(json.dumps(res,indent=2))
# aggregate
from collections import defaultdict
agg=defaultdict(list)
for r in res: agg[(r['kind'],r['mode'],r['m'])].append(r)
rows=[]
for k,vals in agg.items():
 kind,mode,m=k; total=sum(v['m'] for v in vals); exact=sum(v['exact'] for v in vals)
 rows.append({'kind':kind,'mode':mode,'corruptions':m,'rate':m/40,'trials':len(vals),'exact_repair_recall':exact/total,'false_mutations':sum(v['false_mut'] for v in vals),'wrong_mutations':sum(v['wrong_mut'] for v in vals),'mean_committed_edits':sum(v['edits'] for v in vals)/len(vals),'statuses':{s:sum(v['status']==s for v in vals) for s in sorted(set(v['status'] for v in vals))},'mean_seconds':sum(v['seconds'] for v in vals)/len(vals)})
rows.sort(key=lambda x:(x['kind'],x['mode'],x['corruptions']))
open('/mnt/data/json_bench_work/CORRUPTION_CAMPAIGN_SUMMARY.json','w').write(json.dumps(rows,indent=2))
for x in rows: print(x)
