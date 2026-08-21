from __future__ import annotations
from pathlib import Path
from copy import deepcopy
import json
from json_consistency_repair.proof_graph import compile_proof_graph, verify_proof_graph, compare_proof_graphs


def base(i):
    a=f'{i:064x}'[-64:]; b=f'{i+1:064x}'[-64:]
    return {'mode':'single','input_digest':a,'output_digest':b,
      'cycles':[{'cycle':1,'digest':b,'accepted':[],'rejected':[],'minimal_transfer':{'status':'NO_ADMISSIBLE_CANDIDATES'},'strong_quiet':True}],
      'relations':[{'relation_id':f'r{i}','kind':'stable','inputs':[],'output':'x'}],
      'primary_factorization':{'cycles':[{'cycle':1,'factorization':{'factorization_sha256':f'f{i}'},'dynamic_refactorization':{'status':'INITIAL_FACTORIZATION'}}]},
      'parallel_exact_minimum_routes':{'cycles':[]},'dynamic_q_descent':{'cycles':[],'final':{'Q_RETURN':0}},
      'federation_summary':{'final':{'mode_i':{'packets':[{'actor_id':'type_pattern','packet_digest':f'p{i}'}]},'mode_ii':{'pairwise_objects':[],'hyperobjects':[]}}},
      'boundary_calculus':{'cycles':[],'final':{'registry':{'boundary_count':0}}},
      'provenance_chain':{'contract':'json-consistency-repair.provenance-chain.v1','root_hash':f'root{i}','events':[]}}

def main():
    counts={}; false_accepts=0
    def batch(name,fn):
        nonlocal false_accepts
        ok=0
        for i in range(100):
            good,false=fn(i); ok+=int(good); false_accepts+=int(false)
        counts[name]=ok
    batch('deterministic',lambda i:(verify_proof_graph(compile_proof_graph(base(i))) and compile_proof_graph(base(i))['graph_sha256']==compile_proof_graph(base(i))['graph_sha256'],False))
    def rel(i):
        a=base(i); b=deepcopy(a); b['relations'][0]['kind']='mutated'; c=compare_proof_graphs(compile_proof_graph(a),compile_proof_graph(b)); return (not c['ok'],c['ok'])
    batch('relation_divergence',rel)
    def fac(i):
        a=base(i); b=deepcopy(a); b['primary_factorization']['cycles'][0]['dynamic_refactorization']['status']='REFACTORIZED'; c=compare_proof_graphs(compile_proof_graph(a),compile_proof_graph(b)); return (not c['ok'],c['ok'])
    batch('factorization_divergence',fac)
    def act(i):
        a=base(i); b=deepcopy(a); b['federation_summary']['final']['mode_i']['packets'][0]['packet_digest']='other'; c=compare_proof_graphs(compile_proof_graph(a),compile_proof_graph(b)); return (not c['ok'],c['ok'])
    batch('actor_divergence',act)
    def edge(i):
        a=compile_proof_graph(base(i)); b=deepcopy(a); b['edges'][0]['kind']='CORRUPT'; c=compare_proof_graphs(a,b); return (not c['ok'],c['ok'])
    batch('edge_tamper',edge)
    def exact(i):
        c=compare_proof_graphs(compile_proof_graph(base(i)),compile_proof_graph(base(i))); return (c['ok'],False)
    batch('exact_replay',exact)
    payload={'contract':'json-consistency-repair.pass028-benchmark.v1','version':'0.28.0','decisions':sum(counts.values()),'expected_decisions':600,'counts':counts,'false_accepts':false_accepts,'all_checks_pass':sum(counts.values())==600 and false_accepts==0}
    text=json.dumps(payload,sort_keys=True,separators=(',',':'))+'\n'; Path(__file__).with_name('PASS028_BENCHMARK.json').write_text(text,encoding='utf-8'); print(text,end='')
if __name__=='__main__': main()
