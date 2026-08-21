from __future__ import annotations

import json
import re
import tomllib
from datetime import datetime, timedelta
from pathlib import Path

from json_consistency_repair import __version__, package_code_sha256
from json_consistency_repair.analyzers import (
    TypePatternAnalyzer, SchemaStructureAnalyzer, EnumDomainAnalyzer,
    IdentifierReferenceAnalyzer, FunctionalRelationAnalyzer,
    ScopedFunctionalRelationAnalyzer, ExactArithmeticAnalyzer,
    TemporalAnalyzer, SequentialAnalyzer,
)
from json_consistency_repair.bundle import repair_bundle
from json_consistency_repair.cli import main
from json_consistency_repair.engine import RepairConfig, repair_file, repair_object
from json_consistency_repair.streaming import StreamingConfig, discover_stream_knowledge


def cfg(**kw):
    base=dict(min_support=4,min_group_support=2,relation_confidence=.80,scoped_relation_confidence=.85,
              arithmetic_confidence=.80,temporal_confidence=.80,sequential_confidence=.70,
              required_key_confidence=.90,shape_confidence=.70,enum_confidence=.85,
              enum_normalization_confidence=.75,reference_confidence=.80,id_uniqueness_confidence=.80)
    base.update(kw)
    return RepairConfig(**base)


def test_version_is_reconciled_across_public_metadata():
    root=Path(__file__).resolve().parents[1]
    project=tomllib.loads((root/'pyproject.toml').read_text(encoding='utf-8'))
    assert __version__ == project['project']['version']
    assert f'version: "{__version__}"' in (root/'CITATION.cff').read_text(encoding='utf-8')
    assert __version__ in (root/'GUIDE_LLM.md').read_text(encoding='utf-8')
    assert __version__ in (root/'GUIDE_HUMAN.md').read_text(encoding='utf-8')
    assert f'"version": "{__version__}"' in (root/'MACHINE_CONTRACT.md').read_text(encoding='utf-8')


def test_streaming_runtime_version_comes_from_package(tmp_path):
    p=tmp_path/'x.jsonl'
    p.write_text('\n'.join(json.dumps({'id':i,'kind':'A' if i<4 else 'B'}) for i in range(8))+'\n',encoding='utf-8')
    k=discover_stream_knowledge(p,StreamingConfig(min_support=4))
    assert k['version']==__version__


def test_single_dry_run_simulates_full_repair_but_commits_nothing(tmp_path):
    rows=[{'id':i,'state':'READY' if i%2==0 else 'DONE'} for i in range(10)]
    rows[8]['state']='ready'
    src=tmp_path/'in.json'; out=tmp_path/'out.json'; rep=tmp_path/'report.json'
    src.write_text(json.dumps({'rows':rows}),encoding='utf-8')
    result=repair_file(src,out,rep,cfg(dry_run=True))
    report=json.loads(rep.read_text(encoding='utf-8'))
    assert result.committed_edits==0
    assert report['dry_run'] is True and report['would_commit_edits']>=1
    assert report['committed_edits']==[] and report['proposed_edits']
    assert report['replay']['inverse_restores_input'] is True
    assert not out.exists()
    assert json.loads(src.read_text(encoding='utf-8'))['rows'][8]['state']=='ready'


def test_bundle_dry_run_simulates_cross_document_repair_without_publication():
    users={'users':[{'id':f'U{i}'} for i in range(10)]}
    orders={'orders':[{'id':100+i,'user_id':f'U{i}'} for i in range(10)]}
    orders['orders'][9]['user_id']='u9'
    docs={'users.json':users,'orders.json':orders}
    predicted,result=repair_bundle(docs,cfg(dry_run=True))
    assert predicted['orders.json']['orders'][9]['user_id']=='U9'
    assert docs['orders.json']['orders'][9]['user_id']=='u9'
    assert result.committed_edits==0
    assert result.report['committed_patch_set']==[]
    assert result.report['proposed_patch_set']
    assert result.report['would_commit_edits']>=1
    assert result.report['transaction']['patch_count']==0
    assert result.report['transaction']['would_patch_count']>=1
    assert result.report['replay']['inverse_restores_input'] is True


def test_machine_dry_run_exposes_noncommit_semantics(tmp_path,capsys):
    rows=[{'id':i,'state':'READY' if i%2==0 else 'DONE'} for i in range(10)]
    rows[8]['state']='ready'; src=tmp_path/'x.json'; src.write_text(json.dumps({'rows':rows}),encoding='utf-8')
    out=tmp_path/'o.json'
    rc=main(['--machine','--dry-run',str(src),'-o',str(out)])
    captured=capsys.readouterr(); obj=json.loads(captured.out)
    assert rc==0 and obj['result']['dry_run'] is True
    assert obj['result']['committed_edits']==0 and obj['result']['would_commit_edits']>=1
    assert not out.exists()


def _issues(analyzer, data, c=None):
    return analyzer.analyze(data,c or cfg()).issues


def test_each_local_aux_analyzer_has_an_individual_json_terminal():
    # structure / required key
    rows=[{'id':i,'name':f'n{i}'} for i in range(10)]; del rows[9]['name']
    assert _issues(SchemaStructureAnalyzer(),{'rows':rows})
    # type consensus
    rows=[{'id':i,'v':i} for i in range(10)]; rows[9]['v']='9'
    assert _issues(TypePatternAnalyzer(),{'rows':rows})
    # enum domain
    rows=[{'id':i,'state':'READY' if i%2==0 else 'DONE'} for i in range(10)]; rows[8]['state']='ready'
    assert _issues(EnumDomainAnalyzer(),{'rows':rows})
    # identity/reference
    users=[{'id':f'U{i}'} for i in range(10)]; orders=[{'id':100+i,'user_id':f'U{i}'} for i in range(10)]; orders[9]['user_id']='u9'
    assert _issues(IdentifierReferenceAnalyzer(),{'users':users,'orders':orders})
    # functional
    rows=[]
    for i in range(12):
        k='A' if i<6 else 'B'; rows.append({'id':i,'kind':k,'label':'x' if k=='A' else 'y'})
    rows[5]['label']='bad'
    assert _issues(FunctionalRelationAnalyzer(),{'rows':rows})
    # scoped functional: global mapping conflicts, scope-local mapping is stable
    rows=[]
    for scope in ('N','S'):
        for det in ('A','B'):
            for j in range(4):
                target={'N':{'A':'X','B':'Y'},'S':{'A':'Y','B':'X'}}[scope][det]
                rows.append({'scope':scope,'det':det,'target':target,'j':j})
    rows[3]['target']='BAD'
    assert _issues(ScopedFunctionalRelationAnalyzer(),{'rows':rows},cfg(min_scope_support=4,min_scope_group_support=2))
    # exact arithmetic
    rows=[{'a':i+1,'b':2,'total':i+3} for i in range(10)]; rows[5]['total']=999
    assert _issues(ExactArithmeticAnalyzer(),{'rows':rows})
    # temporal
    base=datetime(2026,1,1)
    rows=[{'start':(base+timedelta(days=i)).isoformat(),'end':(base+timedelta(days=i+1)).isoformat()} for i in range(10)]
    rows[5]['end']=(base+timedelta(days=20)).isoformat()
    assert _issues(TemporalAnalyzer(),{'rows':rows})
    # sequential
    rows=[{'n':i*10} for i in range(10)]; rows[5]['n']=999
    assert _issues(SequentialAnalyzer(),{'rows':rows})


def test_federated_aux_consensus_repairs_only_shared_target():
    rows=[]
    for i in range(10):
        plan='A' if i<5 else 'B'; sub,tax,total=(10,2,12) if plan=='A' else (20,4,24)
        if i==4: total=999
        obj={'plan':plan,'subtotal':sub,'tax':tax,'total':total}
        if i%2: obj={'total':total,'tax':tax,'subtotal':sub,'plan':plan}
        rows.append(obj)
    out,r=repair_object({'rows':rows},cfg(arithmetic_direction_confidence=.95))
    assert out['rows'][4]['total']==12
    accepted=[a for cyc in r.report['cycles'] for a in cyc['accepted'] if a['candidate']['path']=='/rows/4/total']
    assert accepted and {'exact_arithmetic','functional_relation'} <= set(accepted[0]['families'])


def test_package_digest_shape_and_no_runtime_dependency_drift():
    assert re.fullmatch(r'[0-9a-f]{64}',package_code_sha256())
    root=Path(__file__).resolve().parents[1]
    project=tomllib.loads((root/'pyproject.toml').read_text(encoding='utf-8'))
    assert project['project']['dependencies']==[]
