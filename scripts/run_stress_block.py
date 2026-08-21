from __future__ import annotations
import ast, sys
from pathlib import Path
if len(sys.argv)!=3: raise SystemExit('usage: run_stress_block.py tests/stress.py LOOP_INDEX')
path=Path(sys.argv[1]); loop_index=int(sys.argv[2]); tree=ast.parse(path.read_text(),filename=str(path))
loops=[n for n in tree.body if isinstance(n,ast.For)]
if not (0<=loop_index<len(loops)): raise SystemExit(f'loop index 0..{len(loops)-1}')
pre=[]
for n in tree.body:
    if isinstance(n,ast.For): continue
    if isinstance(n,ast.Expr) and isinstance(n.value,ast.Call):
        # skip final print calls
        continue
    if isinstance(n,ast.Assert): continue
    pre.append(n)
mod=ast.Module(body=pre+[loops[loop_index]],type_ignores=[]); ast.fix_missing_locations(mod)
ns={'__name__':'__main__','__file__':str(path)}
exec(compile(mod,str(path),'exec'),ns,ns)
print(ns.get('counts',{})); print('BLOCK_TOTAL',sum(ns.get('counts',{}).values()),'PASS')
