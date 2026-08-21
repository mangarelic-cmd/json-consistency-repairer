from __future__ import annotations
from copy import deepcopy
from json_consistency_repair.proof_graph import compile_proof_graph, verify_proof_graph, compare_proof_graphs


def base(i=0):
    a=f'{i:064x}'[-64:]; b=f'{i+1:064x}'[-64:]
    return {
        'mode':'single','input_digest':a,'output_digest':b,
        'cycles':[{'cycle':1,'digest':b,'accepted':[{'candidate_id':f'c{i}','path':'/x','new_value':1}],
                   'rejected':[],'minimal_transfer':{'status':'UNIQUE'},'strong_quiet':False}],
        'relations':[{'relation_id':f'r{i}','kind':'const','inputs':[],'output':'x'}],
        'primary_factorization':{'cycles':[{'cycle':1,'factorization':{'factorization_sha256':f'f{i}'},'dynamic_refactorization':{'status':'INITIAL_FACTORIZATION'}}]},
        'parallel_exact_minimum_routes':{'cycles':[]},
        'dynamic_q_descent':{'cycles':[{'cycle':1,'Q_ANSWER':1,'Q_BOUNDARY':0,'Q_RETURN':0}],'final':{'Q_RETURN':0}},
        'federation_summary':{'final':{'mode_i':{'packets':[{'actor_id':'schema_structure','packet_digest':f'p{i}'}]},'mode_ii':{'pairwise_objects':[],'hyperobjects':[]}}},
        'boundary_calculus':{'cycles':[],'final':{'registry':{'boundary_count':1}}},
        'provenance_chain':{'contract':'json-consistency-repair.provenance-chain.v1','root_hash':f'root{i}','events':[]},
        'committed_edits':[{'operation':'replace','path':'/x','old_value':0,'new_value':1,'metadata':{}}],
    }


def run():
    counts={k:0 for k in ('determinism','payload_tamper','relation_mismatch','factorization_mismatch','actor_mismatch','exact_replay')}
    total=0
    for i in range(100):
        r=base(i); g1=compile_proof_graph(r); g2=compile_proof_graph(deepcopy(r))
        assert g1['graph_sha256']==g2['graph_sha256'] and verify_proof_graph(g1)
        counts['determinism']+=1; total+=1
    for i in range(100):
        g=compile_proof_graph(base(i)); g['nodes'][0]['payload']={'tampered':True}
        assert not verify_proof_graph(g)
        counts['payload_tamper']+=1; total+=1
    for i in range(100):
        a=base(i); b=deepcopy(a); b['relations'][0]['kind']='other'
        c=compare_proof_graphs(compile_proof_graph(a),compile_proof_graph(b))
        assert not c['ok'] and c['section_matches']['RELATION'] is False
        counts['relation_mismatch']+=1; total+=1
    for i in range(100):
        a=base(i); b=deepcopy(a); b['primary_factorization']['cycles'][0]['dynamic_refactorization']['status']='REFACTORIZED'
        c=compare_proof_graphs(compile_proof_graph(a),compile_proof_graph(b))
        assert not c['ok'] and c['section_matches']['DYNAMIC_REFACTORIZATION'] is False
        counts['factorization_mismatch']+=1; total+=1
    for i in range(100):
        a=base(i); b=deepcopy(a); b['federation_summary']['final']['mode_i']['packets'][0]['packet_digest']='changed'
        c=compare_proof_graphs(compile_proof_graph(a),compile_proof_graph(b))
        assert not c['ok'] and c['section_matches']['ANALYZER_RESPONSE'] is False
        counts['actor_mismatch']+=1; total+=1
    for i in range(100):
        a=compile_proof_graph(base(i)); b=compile_proof_graph(base(i)); c=compare_proof_graphs(a,b)
        assert c['ok'] and c['edge_root_match'] and all(c['section_matches'].values())
        counts['exact_replay']+=1; total+=1
    assert total==600
    print('PASS028_STRESS',total,counts)

if __name__=='__main__': run()
