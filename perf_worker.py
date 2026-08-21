import sys,time,resource,json
from json_consistency_repair import repair_object,RepairConfig
n=int(sys.argv[1]); corrupt=int(sys.argv[2]) if len(sys.argv)>2 else 1
rows=[]
for i in range(n):
 rows.append({'k':f'K{i%10}','v':i%10,'a':i+1,'b':2*(i+1),'total':3*(i+1)})
for j in range(min(corrupt,n)):
 idx=(n//2+j)%n
 if j%2==0: rows[idx].pop('v',None)
 else: rows[idx]['total']=-1
cfg=RepairConfig(max_cycles=8,strong_fixed_point_cycles_required=2,enable_multisource=False)
t=time.perf_counter(); out,res=repair_object({'rows':rows},cfg); dt=time.perf_counter()-t
rss=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
print(json.dumps({'n':n,'corruptions':corrupt,'seconds':dt,'maxrss_kb':rss,'edits':res.committed_edits,'status':res.final_status,'cycles':res.cycles,'remaining_issues':res.remaining_issues}))
