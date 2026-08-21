from __future__ import annotations
import argparse, base64, csv, hashlib, io, json, shutil, sys, tempfile, zipfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SRC=ROOT/'src'/'json_consistency_repair'
sys.path.insert(0,str(ROOT/'src'))
from json_consistency_repair import __version__
from json_consistency_repair.provenance import package_code_sha256

FIXED_DATE=(2024,1,1,0,0,0)
DIST_NAME='json_consistency_repair'
PROJECT='json-consistency-repair'

def zwrite(z:zipfile.ZipFile,name:str,data:bytes):
    info=zipfile.ZipInfo(name,FIXED_DATE); info.compress_type=zipfile.ZIP_DEFLATED; info.external_attr=0o644<<16
    z.writestr(info,data)

def b64hash(data:bytes)->str:
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b'=').decode('ascii')

def metadata()->bytes:
    readme=(ROOT/'README.md').read_text(encoding='utf-8')
    text=f'''Metadata-Version: 2.4\nName: {PROJECT}\nVersion: {__version__}\nSummary: Conservative recursive JSON consistency repair with exact constraint discovery, reversible patches, evidence fusion, and replay verification.\nAuthor: Son D. Bolduc\nLicense-Expression: MIT\nRequires-Python: >=3.10\nDescription-Content-Type: text/markdown\nLicense-File: LICENSE\nProvides-Extra: dev\nRequires-Dist: pytest>=7; extra == "dev"\nRequires-Dist: build>=1; extra == "dev"\n\n{readme}'''
    return text.encode('utf-8')

def build_wheel(path:Path):
    distinfo=f'{DIST_NAME}-{__version__}.dist-info'
    entries={}
    for p in sorted(SRC.glob('*.py'),key=lambda x:x.name): entries[f'json_consistency_repair/{p.name}']=p.read_bytes()
    entries[f'{distinfo}/METADATA']=metadata()
    entries[f'{distinfo}/WHEEL']=b'Wheel-Version: 1.0\nGenerator: jcr-pass041-stdlib\nRoot-Is-Purelib: true\nTag: py3-none-any\n'
    entries[f'{distinfo}/entry_points.txt']=b'[console_scripts]\njson-consistency-repair = json_consistency_repair.cli:main\n'
    entries[f'{distinfo}/top_level.txt']=b'json_consistency_repair\n'
    entries[f'{distinfo}/licenses/LICENSE']=(ROOT/'LICENSE').read_bytes()
    record_name=f'{distinfo}/RECORD'
    rows=[]
    for name,data in sorted(entries.items()): rows.append([name,'sha256='+b64hash(data),str(len(data))])
    rows.append([record_name,'',''])
    sio=io.StringIO(newline=''); w=csv.writer(sio,lineterminator='\n'); w.writerows(rows); entries[record_name]=sio.getvalue().encode('utf-8')
    path.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(path,'w') as z:
        for name,data in sorted(entries.items()): zwrite(z,name,data)

def source_files():
    top=['pyproject.toml','README.md','GUIDE_HUMAN.md','GUIDE_LLM.md','MACHINE_CONTRACT.md','RELEASE.md','LICENSE','CITATION.cff','AUX_PORT_MATRIX.md','PASSES_REMAINING.md']
    for name in top:
        p=ROOT/name
        if p.exists(): yield p,name
    dirs=['src','tests','benchmarks','schemas','scripts','examples','.github']
    for d in dirs:
        base=ROOT/d
        if not base.exists(): continue
        for p in sorted(base.rglob('*')):
            if not p.is_file(): continue
            rel=p.relative_to(ROOT).as_posix()
            if '__pycache__' in rel or '.pytest_cache' in rel or rel.endswith('.pyc'): continue
            yield p,rel

def build_source(path:Path):
    path.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(path,'w') as z:
        for p,rel in source_files(): zwrite(z,rel,p.read_bytes())

def sha(path:Path)->str: return hashlib.sha256(path.read_bytes()).hexdigest()

def assert_version_reconciled():
    import tomllib
    project=tomllib.loads((ROOT/'pyproject.toml').read_text(encoding='utf-8'))
    pv=project['project']['version']
    if pv != __version__:
        raise SystemExit(f'version reconciliation failure: pyproject={pv} runtime={__version__}')
    citation=(ROOT/'CITATION.cff').read_text(encoding='utf-8')
    if f'version: "{__version__}"' not in citation:
        raise SystemExit('version reconciliation failure: CITATION.cff')

def build_pair(outdir:Path):
    assert_version_reconciled()
    wheel=outdir/f'{DIST_NAME}-{__version__}-py3-none-any.whl'; source=outdir/f'{PROJECT}-{__version__}-source.zip'
    build_wheel(wheel); build_source(source); return wheel,source

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--check-reproducible',action='store_true'); ap.add_argument('--git-commit'); ap.add_argument('--git-tag'); ap.add_argument('--zenodo-doi')
    a=ap.parse_args(); dist=ROOT/'dist'; dist.mkdir(exist_ok=True)
    # Public dist is a single-version surface. Historical artifacts belong in history/, not beside the active release.
    for pattern in (f'{DIST_NAME}-*-py3-none-any.whl', f'{PROJECT}-*-source.zip'):
        for p in dist.glob(pattern): p.unlink()
    if a.check_reproducible:
        with tempfile.TemporaryDirectory() as t1, tempfile.TemporaryDirectory() as t2:
            w1,s1=build_pair(Path(t1)); w2,s2=build_pair(Path(t2))
            if w1.read_bytes()!=w2.read_bytes(): raise SystemExit('wheel reproducibility failure')
            if s1.read_bytes()!=s2.read_bytes(): raise SystemExit('source reproducibility failure')
            shutil.copy2(w1,dist/w1.name); shutil.copy2(s1,dist/s1.name)
    else:
        build_pair(dist)
    wheel=dist/f'{DIST_NAME}-{__version__}-py3-none-any.whl'; source=dist/f'{PROJECT}-{__version__}-source.zip'
    bench=ROOT/'benchmarks'/'PASS041_SPEED_BENCHMARK.json'
    manifest={
      'contract':'json-consistency-repair.release-provenance.v1','package':PROJECT,'version':__version__,
      'package_code_sha256':package_code_sha256(),'git_commit':a.git_commit,'git_tag':a.git_tag,'zenodo_doi':a.zenodo_doi,
      'artifacts':{
        wheel.name:{'sha256':sha(wheel),'bytes':wheel.stat().st_size},
        source.name:{'sha256':sha(source),'bytes':source.stat().st_size},
      },
      'benchmark': ({'path':'benchmarks/PASS041_SPEED_BENCHMARK.json','sha256':sha(bench),'bytes':bench.stat().st_size} if bench.exists() else None),
      'reproducible_build_checked':bool(a.check_reproducible),
      'self_hash_note':'This manifest intentionally does not hash itself; release artifacts cannot safely embed self-referential hashes.'
    }
    (ROOT/'RELEASE_PROVENANCE.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    print(json.dumps(manifest,indent=2,sort_keys=True))

if __name__=='__main__': main()
