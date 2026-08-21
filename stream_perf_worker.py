import sys,time,resource,json
from pathlib import Path
from json_consistency_repair.streaming import repair_stream_file,StreamingConfig
n=int(sys.argv[1]); base=Path('/mnt/data/json_bench_work'); p=base/f'_bench_stream_{n}.jsonl'; o=base/f'_bench_stream_{n}.out.jsonl'
with p.open('w',encoding='utf-8') as f:
 for i in range(n):
  row={'k':f'K{i%10}','v':i%10,'a':i+1,'b':2*(i+1),'total':3*(i+1)}
  if i==n//2: row.pop('v')
  f.write(json.dumps(row,separators=(',',':'))+'\n')
cfg=StreamingConfig(max_cycles=6,strong_fixed_point_cycles_required=2)
t=time.perf_counter(); res=repair_stream_file(p,o,config=cfg,stream_format='jsonl'); dt=time.perf_counter()-t
print(json.dumps({'n':n,'bytes':p.stat().st_size,'seconds':dt,'maxrss_kb':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,'edits':res.committed_edits,'status':res.final_status,'cycles':res.cycles,'records':res.records,'peak_tracked_fields':res.peak_tracked_fields}))
p.unlink(missing_ok=True); o.unlink(missing_ok=True)
