from __future__ import annotations

import argparse, json, subprocess, tempfile
from pathlib import Path


def run(exe: str, args: list[str]):
    p=subprocess.run([exe,*args],text=True,capture_output=True)
    stream=p.stdout.strip() if p.stdout.strip() else p.stderr.strip()
    obj=json.loads(stream) if stream else None
    return p.returncode,obj,p.stdout,p.stderr


def write(path: Path, obj):
    path.write_text(json.dumps(obj,ensure_ascii=False),encoding='utf-8')


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--exe',required=True,help='installed json-consistency-repair console executable')
    ap.add_argument('--guide',default='GUIDE_LLM.md')
    ap.add_argument('--contract',default='MACHINE_CONTRACT.md')
    a=ap.parse_args()
    guide=Path(a.guide).read_text(encoding='utf-8')
    contract=Path(a.contract).read_text(encoding='utf-8')
    checks={
        'guide_has_machine_invocation':'--machine' in guide,
        'guide_has_status_10':'STABLE_WITH_REPORTED_ISSUES' in guide and 'exit `10`' in guide,
        'guide_has_security_21':'SECURITY_REFUSAL' in guide and 'exit `21`' in guide,
        'guide_has_dry_run':'--dry-run' in guide and 'would_commit_edits' in guide,
        'contract_identifier':'json-consistency-repair.machine.v1' in contract,
    }
    with tempfile.TemporaryDirectory() as td:
        td=Path(td)
        rows=[{'id':i,'state':'READY' if i%2==0 else 'DONE'} for i in range(10)]; rows[8]['state']='ready'
        dirty=td/'dirty.json'; repaired=td/'repaired.json'; report=td/'repair.json'; write(dirty,{'rows':rows})
        rc,obj,_,_=run(a.exe,['--machine',str(dirty),'-o',str(repaired),'--report',str(report)])
        checks['repair_status_pass']=rc==0 and obj and obj.get('status')=='PASS' and repaired.exists() and report.exists()
        rc2,obj2,_,_=run(a.exe,['--machine',str(repaired),'-o',str(td/'again.json'),'--report',str(td/'again-report.json')])
        checks['rerun_zero_edit']=rc2==0 and obj2 and obj2.get('result',{}).get('committed_edits')==0

        rows=[{'id':i,'state':'READY' if i%2==0 else 'DONE'} for i in range(10)]; rows[8]['state']='ALIEN'
        unresolved=td/'unresolved.json'; write(unresolved,{'rows':rows})
        rc3,obj3,_,_=run(a.exe,['--machine',str(unresolved),'-o',str(td/'unresolved.out.json'),'--report',str(td/'unresolved.report.json')])
        checks['abstention_status_10']=rc3==10 and obj3 and obj3.get('status')=='STABLE_WITH_REPORTED_ISSUES'

        deep=td/'deep.json'; deep.write_text('[[[[0]]]]',encoding='utf-8')
        rc4,obj4,_,_=run(a.exe,['--machine','--max-depth','2',str(deep)])
        checks['security_status_21']=rc4==21 and obj4 and obj4.get('status')=='SECURITY_REFUSAL' and obj4.get('error',{}).get('code')=='max_depth'

        dry=td/'dry.json'; dryout=td/'dry.out.json'; dryrep=td/'dry.report.json'; write(dry,{'rows':[{'id':i,'state':'READY' if i%2==0 else 'DONE'} for i in range(10)]})
        d=json.loads(dry.read_text()); d['rows'][8]['state']='ready'; write(dry,d)
        rc5,obj5,_,_=run(a.exe,['--machine','--dry-run',str(dry),'-o',str(dryout),'--report',str(dryrep)])
        result=obj5.get('result',{}) if obj5 else {}
        checks['dry_run_noncommit']=rc5==0 and result.get('dry_run') is True and result.get('committed_edits')==0 and result.get('would_commit_edits',0)>=1 and not dryout.exists()

    result={'probe':'PASS008_BLANK_AGENT_PUBLIC_SURFACE_V1','uses_source_code':False,'checks':checks,'all_checks_pass':all(checks.values())}
    print(json.dumps(result,sort_keys=True,indent=2))
    if not result['all_checks_pass']:
        raise SystemExit(1)

if __name__=='__main__': main()
