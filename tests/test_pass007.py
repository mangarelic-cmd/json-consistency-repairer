from __future__ import annotations
import json, re
from pathlib import Path

from json_consistency_repair import __version__, package_code_sha256
from json_consistency_repair.cli import main
from json_consistency_repair.engine import RepairConfig, repair_object
from json_consistency_repair.provenance import EXIT_CODES, MACHINE_CONTRACT, REPORT_CONTRACT, runtime_provenance


def test_version_and_code_digest():
    assert __version__ == runtime_provenance()["version"]
    assert re.fullmatch(r"[0-9a-f]{64}", package_code_sha256())


def test_report_contract_and_provenance():
    data={"rows":[{"id":i,"state":"READY" if i%2==0 else "DONE"} for i in range(20)]}
    _,r=repair_object(data,RepairConfig(min_support=4))
    assert r.report["report_contract"]["name"] == REPORT_CONTRACT
    assert r.report["report_contract"]["schema_version"] == "1.0"
    assert r.report["report_contract"]["status"] == r.final_status
    assert r.report["provenance"]["package_code_sha256"] == package_code_sha256()


def test_machine_pass_one_object(tmp_path,capsys):
    p=tmp_path/'a.json'; p.write_text('{"x":1}\n',encoding='utf-8')
    rc=main(['--machine',str(p)])
    out=capsys.readouterr(); lines=[x for x in out.out.splitlines() if x.strip()]
    assert rc==0 and len(lines)==1 and out.err==''
    obj=json.loads(lines[0]); assert obj['contract']==MACHINE_CONTRACT and obj['status']=='PASS' and obj['exit_code']==0


def test_machine_duplicate_key_input_error(tmp_path,capsys):
    p=tmp_path/'bad.json'; p.write_text('{"x":1,"x":2}',encoding='utf-8')
    rc=main(['--machine','--no-syntax-repair',str(p)])
    out=capsys.readouterr(); assert out.out==''
    obj=json.loads(out.err.strip()); assert rc==EXIT_CODES['INPUT_ERROR']==20 and obj['status']=='INPUT_ERROR'
    assert 'Traceback' not in out.err


def test_machine_security_refusal(tmp_path,capsys):
    p=tmp_path/'deep.json'; p.write_text('[[[[0]]]]',encoding='utf-8')
    rc=main(['--machine','--max-depth','2',str(p)])
    out=capsys.readouterr(); obj=json.loads(out.err.strip())
    assert rc==EXIT_CODES['SECURITY_REFUSAL']==21 and obj['error']['code']=='max_depth'


def test_exit_code_table(capsys):
    rc=main(['--machine','--explain-exit-codes']); out=capsys.readouterr(); obj=json.loads(out.out.strip())
    assert rc==0 and obj['exit_codes']==EXIT_CODES


def test_provenance_command(capsys):
    rc=main(['--machine','--provenance']); out=capsys.readouterr(); obj=json.loads(out.out.strip())
    assert rc==0 and obj['provenance']['version']==__version__
    assert obj['provenance']['package_code_sha256']==package_code_sha256()


def test_schema_files_parse():
    root=Path(__file__).resolve().parents[1]
    for name in ['machine-output-v1.schema.json','report-v1.schema.json']:
        obj=json.loads((root/'schemas'/name).read_text(encoding='utf-8'))
        assert obj['type']=='object'
