import random,time,json
from copy import deepcopy
from json_consistency_repair import repair_object, RepairConfig

def cfg():
 return RepairConfig(max_cycles=8,strong_fixed_point_cycles_required=2,enable_multisource=False)

def eval_case(kind, rate, seed=1,n=40):
 rng=random.Random(seed)
 if kind=='functional':
  rows=[]
  for i in range(n):
   k=f'K{i%5}'; rows.append({'k':k,'v':i%5})
  truth=deepcopy(rows)
  m=max(1,round(rate*n)); inds=rng.sample(range(n),m)
  for i in inds:
   if i%2: rows[i].pop('v')
   else: rows[i]['v']=100+(i%7)
 elif kind=='arith':
  rows=[{'a':i+1,'b':2*(i+1),'total':3*(i+1)} for i in range(n)]
  truth=deepcopy(rows); m=max(1,round(rate*n)); inds=rng.sample(range(n),m)
  for i in inds:
   rows[i]['total']=-999-i
 data={'rows':rows}; t=time.perf_counter(); out,res=repair_object(data,cfg()); dt=time.perf_counter()-t
 tp=sum(out['rows'][i]==truth[i] for i in inds)
 false=0
 for i in range(n):
  if i not in inds and out['rows'][i]!=truth[i]: false+=1
 wrong=sum(out['rows'][i]!=truth[i] and out['rows'][i]!=rows[i] for i in inds)
 return m,tp,false,wrong,res.committed_edits,res.final_status,dt
for kind in ('functional','arith'):
 print('\n',kind)
 for rate in [0.025,0.05,0.075,0.1,0.15,0.2,0.3,0.4]:
  vals=[eval_case(kind,rate,s) for s in (1,2)]
  print(rate, vals)
