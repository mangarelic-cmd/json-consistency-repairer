from __future__ import annotations
import runpy, sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
import json_consistency_repair as pkg
import json_consistency_repair.engine as eng
import json_consistency_repair.streaming as streaming

RealRepairConfig=eng.RepairConfig
RealStreamingConfig=streaming.StreamingConfig

def DecisionRepairConfig(*args,**kwargs):
    kwargs.setdefault('enable_final_certification',False)
    kwargs.setdefault('enable_parallel_tie_routes',False)
    return RealRepairConfig(*args,**kwargs)

def DecisionStreamingConfig(*args,**kwargs):
    kwargs.setdefault('enable_final_certification',False)
    return RealStreamingConfig(*args,**kwargs)

eng.RepairConfig=DecisionRepairConfig
pkg.RepairConfig=DecisionRepairConfig
streaming.StreamingConfig=DecisionStreamingConfig
pkg.StreamingConfig=DecisionStreamingConfig

if len(sys.argv)!=2:
    raise SystemExit('usage: run_inherited_decision_stress.py tests/stress_passNNN.py')
path=ROOT/sys.argv[1]
runpy.run_path(str(path),run_name='__main__')
