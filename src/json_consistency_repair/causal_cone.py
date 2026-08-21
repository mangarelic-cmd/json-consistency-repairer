from __future__ import annotations
from copy import deepcopy
from typing import Any, Callable
import hashlib, json
from .models import AnalysisResult, Candidate, Issue
from .tree import decode_pointer
from .jsonpatch_exact import apply_candidate

AUTH_INFERRED=1; AUTH_DERIVED_EXACT=2; AUTH_AUTHORITATIVE=3
_AUTHORITATIVE_ANALYZERS={'constraint_dsl','linear_exact','schema_bridge'}
_AUTHORITATIVE_KINDS={'logic_rule_system','logic_rule_system_stream','aggregate_sum_authoritative','aggregate_count_authoritative','balance_authoritative','multiset_balance_authoritative','authoritative_json_schema','authoritative_boundary_contract','linear_exact_system'}
_DIRECTED_KINDS={'cross_source_functional','functional_relation','scoped_functional_relation','temporal_delta','sequential_step','foreign_reference','foreign_reference_cross_document','aggregate_sum','aggregate_count','aggregate_sum_authoritative','aggregate_count_authoritative','constraint_dsl_required','constraint_dsl_type','constraint_dsl_enum','constraint_dsl_const','authoritative_json_schema','recursive_morphology_missing_key'}

def authority_name(tier:int)->str:
    return {1:'INFERRED',2:'DERIVED_EXACT',3:'AUTHORITATIVE'}.get(int(tier),'UNKNOWN')

def relation_authority(rel:dict[str,Any])->int:
    src=str(rel.get('constraint_source') or rel.get('logic_source') or rel.get('source') or rel.get('direction_source') or '').lower(); kind=str(rel.get('kind',''))
    if src=='authoritative' or kind in _AUTHORITATIVE_KINDS or kind.endswith('_authoritative'): return AUTH_AUTHORITATIVE
    if src in {'derived_exact','heldout_validated'}: return AUTH_DERIVED_EXACT
    if kind in {'exact_arithmetic','temporal_delta','functional_relation','scoped_functional_relation','foreign_reference','identifier_uniqueness','aggregate_sum','aggregate_count','scalar_conservation_balance','multiset_conservation'}: return AUTH_DERIVED_EXACT
    return AUTH_INFERRED

def candidate_authority(c:Candidate)->int:
    meta=c.metadata or {}; src=str(meta.get('constraint_source') or meta.get('logic_source') or meta.get('source') or '').lower(); kind=str(meta.get('relation_kind',''))
    if c.analyzer in _AUTHORITATIVE_ANALYZERS or src=='authoritative' or kind in _AUTHORITATIVE_KINDS or kind.endswith('_authoritative'): return AUTH_AUTHORITATIVE
    if src in {'derived_exact','heldout_validated'}: return AUTH_DERIVED_EXACT
    if c.analyzer in {'exact_arithmetic','temporal','functional_relation','scoped_functional_relation','identifier_reference','conservation','logic_exact'}: return AUTH_DERIVED_EXACT
    return AUTH_INFERRED

def _value_key(v:Any)->str: return json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(',',':'),default=str)

def apply_authority_firewall(analysis:AnalysisResult)->tuple[AnalysisResult,dict[str,Any]]:
    out=AnalysisResult(list(analysis.issues),list(analysis.candidates),list(analysis.relations)); by_path={}
    for c in out.candidates: by_path.setdefault(c.path,[]).append(c)
    kept=[]; blocked=[]; conflicts=[]
    for path,group in sorted(by_path.items()):
        top=max(candidate_authority(c) for c in group); top_group=[c for c in group if candidate_authority(c)==top]; top_values={_value_key(c.new_value) for c in top_group}
        if top==AUTH_AUTHORITATIVE and len(top_values)>1:
            ids=sorted(c.candidate_id for c in top_group); conflicts.append({'path':path,'tier':'AUTHORITATIVE','candidate_ids':ids,'distinct_values':len(top_values)})
            out.issues.append(Issue('authority_firewall','authority_conflict',path,'Multiple authoritative constraints require incompatible values at the same JSON path.','error',False,{'candidate_ids':ids,'authority_tier':'AUTHORITATIVE','distinct_values':len(top_values)}))
            for c in group: blocked.append({'candidate_id':c.candidate_id,'path':path,'reason':'AUTHORITY_CONFLICT','authority':authority_name(candidate_authority(c))})
            continue
        if top==AUTH_AUTHORITATIVE:
            for c in group:
                if candidate_authority(c)<top and _value_key(c.new_value) not in top_values: blocked.append({'candidate_id':c.candidate_id,'path':path,'reason':'LOWER_AUTHORITY_CONTRADICTION','authority':authority_name(candidate_authority(c))})
                else: kept.append(c)
        else: kept.extend(group)
    out.candidates=kept
    ledger=[{'relation_id':r.get('relation_id'),'kind':r.get('kind'),'authority':authority_name(relation_authority(r)),'source':r.get('constraint_source') or r.get('logic_source') or r.get('schema_source') or r.get('source') or r.get('direction_source')} for r in sorted(out.relations,key=lambda x:str(x.get('relation_id','')))]
    return out,{'contract':'json-consistency-repair.authority-firewall.v1','candidate_count_before':len(analysis.candidates),'candidate_count_after':len(kept),'blocked_candidates':blocked,'authority_conflicts':conflicts,'relation_authority_ledger':ledger}

def _node(scope:str,field:Any)->str: return f'{scope}#{field}'
def _relation_directed(rel:dict[str,Any])->bool:
    kind=str(rel.get('kind',''))
    if rel.get('output') in (None,'__logic__','__shape__','__morphology__'): return False
    if kind=='exact_arithmetic': return bool(rel.get('direction_certified'))
    if kind.startswith('logic_') or kind=='linear_exact_system': return False
    return kind in _DIRECTED_KINDS or bool(rel.get('direction_certified'))

def causal_graph(relations:list[dict[str,Any]])->dict[str,Any]:
    nodes=set(); edges=[]
    for rel in relations:
        if not _relation_directed(rel): continue
        scope=str(rel.get('array_path') or rel.get('source_array_path') or ''); out=rel.get('output')
        if out is None: continue
        outn=_node(scope,out); nodes.add(outn)
        for f in rel.get('inputs',[]):
            inn=_node(scope,f); nodes.add(inn); edges.append({'from':inn,'to':outn,'relation_id':rel.get('relation_id'),'kind':rel.get('kind'),'authority':authority_name(relation_authority(rel))})
    return {'nodes':sorted(nodes),'edges':sorted(edges,key=lambda e:(e['from'],e['to'],str(e['relation_id'])))}

def _path_to_node(path:str,relations:list[dict[str,Any]])->str|None:
    toks=decode_pointer(path); best=None
    for rel in relations:
        scope=str(rel.get('array_path') or rel.get('source_array_path') or ''); st=decode_pointer(scope)
        if len(toks)>=len(st)+2 and [str(x) for x in toks[:len(st)]]==[str(x) for x in st]:
            field=toks[len(st)+1] if len(toks)==len(st)+2 else toks[-1]; cand=(len(st),_node(scope,field))
            if best is None or cand[0]>best[0]: best=cand
    return best[1] if best else None

def _closure(start:str,adj:dict[str,set[str]])->set[str]:
    seen={start}; stack=[start]
    while stack:
        x=stack.pop()
        for y in adj.get(x,set()):
            if y not in seen: seen.add(y); stack.append(y)
    return seen

def compile_double_cone(analysis:AnalysisResult)->dict[str,Any]:
    graph=causal_graph(analysis.relations); fwd={}; rev={}
    for e in graph['edges']: fwd.setdefault(e['from'],set()).add(e['to']); rev.setdefault(e['to'],set()).add(e['from'])
    cnodes={c.candidate_id:_path_to_node(c.path,analysis.relations) for c in analysis.candidates}; terms=[]
    for idx,issue in enumerate(analysis.issues):
        tnode=_path_to_node(issue.path,analysis.relations); tid='term_'+hashlib.sha1((issue.analyzer+'|'+issue.code+'|'+issue.path+'|'+str(idx)).encode()).hexdigest()[:16]; backward=_closure(tnode,rev) if tnode else set(); reaching=[]; equality=[]
        for c in analysis.candidates:
            cn=cnodes.get(c.candidate_id)
            if not cn: continue
            forward=_closure(cn,fwd)
            if tnode and tnode in forward: reaching.append(c.candidate_id); equality.extend(sorted(backward & forward))
        terms.append({'terminal_id':tid,'path':issue.path,'analyzer':issue.analyzer,'code':issue.code,'terminal_node':tnode,'backward_nodes':sorted(backward),'reaching_candidate_ids':sorted(reaching),'equality_surface':sorted(set(equality))})
    return {'contract':'json-consistency-repair.double-cone.v1','graph':graph,'terminals':terms,'terminal_count':len(terms),'directed_edge_count':len(graph['edges'])}

def causal_dominance(root:Any,analysis:AnalysisResult,analyze_fn:Callable[[Any],AnalysisResult])->tuple[AnalysisResult,dict[str,Any]]:
    baseline={i.signature() for i in analysis.issues}; baseline_errors={i.signature() for i in analysis.issues if i.severity=='error'}; rows=[]
    # Dominance is only defined between patches that compete inside the same concrete record.
    # Singleton carriers cannot have a cause-vs-symptom comparison, so skip their expensive reanalysis.
    groups={}
    for c in analysis.candidates:
        toks=decode_pointer(c.path); carrier=tuple(toks[:-1]) if toks else tuple()
        groups.setdefault(carrier,[]).append(c)
    active_ids={c.candidate_id for g in groups.values() if len(g)>=2 for c in g}
    for c in analysis.candidates:
        if c.candidate_id not in active_ids: continue
        trial=deepcopy(root)
        if not apply_candidate(trial,c): rows.append({'candidate':c,'resolved':set(),'introduced_errors':{'PRECONDITION_FAILED'}}); continue
        after=analyze_fn(trial); aset={i.signature() for i in after.issues}; aerrs={i.signature() for i in after.issues if i.severity=='error'}; rows.append({'candidate':c,'resolved':baseline-aset,'introduced_errors':aerrs-baseline_errors})
    dominated=set(); witnesses=[]
    for a in rows:
        if a['introduced_errors'] or not a['resolved']: continue
        for b in rows:
            if a is b or b['introduced_errors'] or not b['resolved']: continue
            if a['resolved']>b['resolved']:
                ta,tb=decode_pointer(a['candidate'].path),decode_pointer(b['candidate'].path); same_record=len(ta)>1 and len(tb)>1 and ta[:-1]==tb[:-1]
                if not same_record: continue
                dominated.add(b['candidate'].candidate_id); witnesses.append({'dominator':a['candidate'].candidate_id,'dominated':b['candidate'].candidate_id,'dominator_path':a['candidate'].path,'dominated_path':b['candidate'].path,'resolved_by_dominator':len(a['resolved']),'resolved_by_dominated':len(b['resolved'])})
    kept=[c for c in analysis.candidates if c.candidate_id not in dominated]
    return AnalysisResult(list(analysis.issues),kept,list(analysis.relations)),{'contract':'json-consistency-repair.root-cause-dominance.v1','candidate_count_before':len(analysis.candidates),'candidate_count_after':len(kept),'dominated_candidate_ids':sorted(dominated),'witnesses':witnesses}

def prepare_causal_analysis(root:Any,analysis:AnalysisResult,analyze_fn:Callable[[Any],AnalysisResult])->tuple[AnalysisResult,dict[str,Any]]:
    fw,fc=apply_authority_firewall(analysis); cone=compile_double_cone(fw); dom,dc=causal_dominance(root,fw,analyze_fn)
    return dom,{'contract':'json-consistency-repair.causal-root-analysis.v1','authority_firewall':fc,'double_cone':cone,'root_cause_dominance':dc}
