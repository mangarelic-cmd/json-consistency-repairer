from __future__ import annotations
import copy, json, subprocess, sys
from pathlib import Path
from json_consistency_repair import repair_object, repair_bundle, repair_stream_file, RepairConfig, StreamingConfig
from json_consistency_repair.certifier import verify_single_packet, verify_report_evidence
from json_consistency_repair.provenance_chain import verify_provenance_chain


def repairable_object():
    rows=[{'id':i,'items':[{'v':1},{'v':2}],'item_count':2} for i in range(21)]
    rows[-1]['item_count']=9
    return {'rows':rows}


def test_pass016_single_cold_replay_and_independent_certifier():
    original=repairable_object()
    repaired,res=repair_object(original,RepairConfig(max_cycles=7))
    assert repaired['rows'][-1]['item_count']==2
    assert res.report['cold_replay']['performed'] is True
    assert res.report['cold_replay']['would_commit_edits']==0
    assert res.report['final_certification']['status']=='CERTIFIED'
    assert res.report['certification_gate']=='PASS'
    assert verify_single_packet(original,repaired,res.report['committed_edits'],res.report)['ok'] is True


def test_tampered_provenance_chain_is_rejected():
    original=repairable_object(); repaired,res=repair_object(original,RepairConfig(max_cycles=7))
    tampered=copy.deepcopy(res.report['provenance_chain'])
    tampered['events'][0]['event']['type']='PATCH_TAMPERED'
    assert verify_provenance_chain(tampered)['ok'] is False


def test_tampered_output_is_rejected_by_independent_certifier():
    original=repairable_object(); repaired,res=repair_object(original,RepairConfig(max_cycles=7))
    bad=copy.deepcopy(repaired); bad['rows'][0]['item_count']=999
    cert=verify_single_packet(original,bad,res.report['committed_edits'],res.report)
    assert cert['ok'] is False and cert['checks']['output_digest'] is False


def test_bundle_gets_cold_replay_provenance_and_final_certificate():
    docs={'a.json':repairable_object(),'b.json':{'rows':[{'id':i,'v':i} for i in range(8)]}}
    repaired,res=repair_bundle(docs,RepairConfig(max_cycles=7))
    assert repaired['a.json']['rows'][-1]['item_count']==2
    assert res.report['strong_fixed_point']['attained'] is True
    assert res.report['cold_replay']['would_commit_edits']==0
    assert res.report['final_certification']['ok'] is True


def test_streaming_gets_cold_replay_and_final_certificate(tmp_path):
    src=tmp_path/'x.jsonl'; out=tmp_path/'o.jsonl'
    rows=[{'id':i,'items':[{'v':1},{'v':2}],'item_count':2} for i in range(21)]; rows[-1]['item_count']=9
    src.write_text('\n'.join(json.dumps(x) for x in rows)+'\n',encoding='utf-8')
    res=repair_stream_file(src,out,None,StreamingConfig(max_cycles=7))
    assert res.report['strong_fixed_point']['attained'] is True
    assert res.report['cold_replay']['would_commit_edits']==0
    assert res.report['final_certification']['ok'] is True


def test_independent_certifier_module_cli(tmp_path):
    original=repairable_object(); repaired,res=repair_object(original,RepairConfig(max_cycles=7))
    inp=tmp_path/'i.json'; out=tmp_path/'o.json'; rp=tmp_path/'r.json'
    inp.write_text(json.dumps(original),encoding='utf-8'); out.write_text(json.dumps(repaired),encoding='utf-8'); rp.write_text(json.dumps(res.report),encoding='utf-8')
    cp=subprocess.run([sys.executable,'-m','json_consistency_repair.certifier','--report',str(rp),'--input',str(inp),'--output',str(out)],capture_output=True,text=True)
    assert cp.returncode==0
    assert json.loads(cp.stdout)['status']=='CERTIFIED'


def test_generic_report_certifier_requires_cold_and_strong():
    original=repairable_object(); _,res=repair_object(original,RepairConfig(max_cycles=7))
    bad=copy.deepcopy(res.report); bad['cold_replay']['would_commit_edits']=1
    assert verify_report_evidence(bad)['ok'] is False

def test_pass016_public_exports_and_schema_contract_files():
    import json_consistency_repair as jcr
    from pathlib import Path
    assert callable(jcr.verify_provenance_chain)
    assert callable(jcr.verify_single_packet)
    assert callable(jcr.audit_patch_order)
    root=Path(__file__).resolve().parents[1]
    for name in ['modal-regime-v1.schema.json','strong-fixed-point-v1.schema.json','cold-replay-v1.schema.json','provenance-chain-v1.schema.json','final-certification-v1.schema.json']:
        data=json.loads((root/'schemas'/name).read_text(encoding='utf-8'))
        assert data['$schema'].endswith('/2020-12/schema')
        assert data['$id'].startswith('json-consistency-repair.')
