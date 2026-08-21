from __future__ import annotations
from copy import deepcopy
import json

from json_consistency_repair import RepairConfig, repair_object
from json_consistency_repair.bundle import repair_bundle
from json_consistency_repair.streaming import StreamingConfig, repair_stream_file
from json_consistency_repair.proof_graph import compile_proof_graph, verify_proof_graph, compare_proof_graphs
from json_consistency_repair.certifier import verify_single_packet


def base_report():
    return {
        'mode':'single','input_digest':'a'*64,'output_digest':'b'*64,
        'cycles':[{'cycle':1,'digest':'b'*64,'accepted':[{'candidate_id':'c1','path':'/x','old_value':0,'new_value':1}],
                   'rejected':[],'minimal_transfer':{'status':'UNIQUE'},'strong_quiet':False}],
        'relations':[{'relation_id':'r1','kind':'const','inputs':[],'output':'x'}],
        'primary_factorization':{'cycles':[{'cycle':1,'factorization':{'factorization_sha256':'f1'},
                                           'dynamic_refactorization':{'status':'INITIAL_FACTORIZATION'}}]},
        'parallel_exact_minimum_routes':{'cycles':[]},
        'dynamic_q_descent':{'cycles':[{'cycle':1,'Q_ANSWER':1,'Q_BOUNDARY':0,'Q_RETURN':0}],'final':{'Q_RETURN':0}},
        'federation_summary':{'final':{'mode_i':{'packets':[{'actor_id':'schema_structure','packet_digest':'p1'}]},
                                      'mode_ii':{'pairwise_objects':[],'hyperobjects':[]}}},
        'boundary_calculus':{'cycles':[],'final':{'registry':{'boundary_count':1}}},
        'provenance_chain':{'contract':'json-consistency-repair.provenance-chain.v1','root_hash':'root','events':[]},
        'committed_edits':[{'operation':'replace','path':'/x','old_value':0,'new_value':1,'metadata':{}}],
    }


def test_proof_graph_is_canonical_and_self_verifying():
    r=base_report(); g1=compile_proof_graph(r); g2=compile_proof_graph(deepcopy(r))
    assert g1['graph_sha256']==g2['graph_sha256']
    assert verify_proof_graph(g1)
    assert g1['node_count']>=8 and g1['edge_count']>=7


def test_tampered_payload_breaks_graph_integrity():
    g=compile_proof_graph(base_report())
    g['nodes'][0]['payload']={'tampered':True}
    assert not verify_proof_graph(g)


def test_same_terminal_but_changed_relation_changes_proof_graph():
    r1=base_report(); r2=deepcopy(r1); r2['relations'][0]['kind']='different_relation'
    g1=compile_proof_graph(r1); g2=compile_proof_graph(r2)
    assert g1['output_digest']==g2['output_digest']
    cmp=compare_proof_graphs(g1,g2)
    assert not cmp['ok']
    assert cmp['section_matches']['RELATION'] is False


def test_same_terminal_but_changed_primary_history_changes_graph():
    r1=base_report(); r2=deepcopy(r1)
    r2['primary_factorization']['cycles'][0]['dynamic_refactorization']['status']='REFACTORIZED'
    cmp=compare_proof_graphs(compile_proof_graph(r1),compile_proof_graph(r2))
    assert not cmp['ok']
    assert cmp['section_matches']['DYNAMIC_REFACTORIZATION'] is False


def test_same_terminal_but_changed_analyzer_packet_changes_graph():
    r1=base_report(); r2=deepcopy(r1)
    r2['federation_summary']['final']['mode_i']['packets'][0]['packet_digest']='p2'
    cmp=compare_proof_graphs(compile_proof_graph(r1),compile_proof_graph(r2))
    assert not cmp['ok']
    assert cmp['section_matches']['ANALYZER_RESPONSE'] is False


def test_engine_performs_full_original_input_proof_graph_replay():
    schema={'type':'object','properties':{'x':{'const':1}}}
    repaired,res=repair_object({'x':0},RepairConfig(json_schema=schema,max_cycles=4,strong_fixed_point_cycles_required=1))
    assert repaired=={'x':1}
    assert verify_proof_graph(res.report['proof_graph'])
    pgr=res.report['proof_graph_replay']
    assert pgr['performed'] and pgr['ok'] and pgr['same_terminal_output']
    assert pgr['expected_graph_sha256']==pgr['replayed_graph_sha256']
    assert res.report['final_certification']['checks']['proof_graph_integrity'] is True
    assert res.report['final_certification']['checks']['proof_graph_replay'] is True


def test_certifier_rejects_forged_proof_replay_even_with_correct_json():
    schema={'type':'object','properties':{'x':{'const':1}}}
    repaired,res=repair_object({'x':0},RepairConfig(json_schema=schema,max_cycles=4,strong_fixed_point_cycles_required=1))
    report=deepcopy(res.report); report['proof_graph_replay']['ok']=False
    verdict=verify_single_packet({'x':0},repaired,report['committed_edits'],report)
    assert verdict['status']=='REJECTED'
    assert verdict['checks']['proof_graph_replay'] is False


def test_bundle_proof_graph_replay_is_exact():
    docs={'a.json':{'x':1},'b.json':{'y':2}}
    _,res=repair_bundle(docs,RepairConfig(max_cycles=3,strong_fixed_point_cycles_required=1))
    assert res.report['proof_graph_replay']['status']=='PROOF_GRAPH_REPLAY_EXACT'
    assert res.report['final_certification']['status']=='CERTIFIED'


def test_streaming_proof_graph_replay_is_exact(tmp_path):
    src=tmp_path/'in.jsonl'; out=tmp_path/'out.jsonl'
    src.write_text('\n'.join(json.dumps({'a':i,'b':i+1}) for i in range(1,5))+'\n',encoding='utf-8')
    res=repair_stream_file(src,out,None,StreamingConfig(max_cycles=3,strong_fixed_point_cycles_required=1),stream_format='jsonl')
    assert res.report['proof_graph_replay']['status']=='PROOF_GRAPH_REPLAY_EXACT'
    assert res.report['final_certification']['status']=='CERTIFIED'


def test_no_certification_still_commits_graph_but_does_not_claim_replay():
    _,res=repair_object({'x':1},RepairConfig(enable_final_certification=False,max_cycles=3,strong_fixed_point_cycles_required=1))
    assert verify_proof_graph(res.report['proof_graph'])
    assert res.report['proof_graph_replay']['performed'] is False
    assert res.report['final_certification']['status']=='NOT_RUN'
