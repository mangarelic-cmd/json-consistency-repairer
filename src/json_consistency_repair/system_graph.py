from __future__ import annotations
from collections import Counter, deque
from copy import deepcopy
from typing import Any
import hashlib, json

from .models import AnalysisResult, Candidate, Issue, digest
from .tree import get, decode_pointer
from .jsonpatch_exact import apply_patch

SCALAR=(str,int,float,bool)

def _rid(payload:dict[str,Any])->str:
    ident={k:v for k,v in payload.items() if k not in {'confidence','support','relation_id'}}
    return hashlib.sha1(json.dumps(ident,sort_keys=True,default=str,separators=(',',':')).encode()).hexdigest()[:20]

def _cid(analyzer:str,op:str,path:str,old:Any,new:Any,meta:dict[str,Any])->str:
    raw=json.dumps([analyzer,op,path,old,new,meta],sort_keys=True,default=str,separators=(',',':')).encode()
    return hashlib.sha1(raw).hexdigest()[:16]

def _candidate(analyzer:str,op:str,path:str,old:Any,new:Any,reason:str,meta:dict[str,Any],cost:int=1)->Candidate:
    return Candidate(_cid(analyzer,op,path,old,new,meta),analyzer,op,path,deepcopy(old),deepcopy(new),reason,1.0,cost,(str(meta.get('rule_id','system')),),meta)

def _as_list(root:Any,path:str)->list[Any]|None:
    try: v=get(root,path)
    except Exception: return None
    return v if isinstance(v,list) else None

def _as_dict(root:Any,path:str)->dict[str,Any]|None:
    try: v=get(root,path)
    except Exception: return None
    return v if isinstance(v,dict) else None

def _path_join(base:str, token:str|int)->str:
    esc=str(token).replace('~','~0').replace('/','~1')
    return (base.rstrip('/') + '/' + esc) if base else '/' + esc

def _stable_rule(rule:dict[str,Any],prefix='system')->dict[str,Any]:
    out=deepcopy(rule)
    if not out.get('rule_id'):
        ident={k:v for k,v in out.items() if k!='rule_id'}
        out['rule_id']=prefix+'_'+hashlib.sha1(json.dumps(ident,sort_keys=True,default=str,separators=(',',':')).encode()).hexdigest()[:16]
    out.setdefault('source','authoritative')
    return out

def _scalar_id(v:Any)->bool:
    return v is not None and isinstance(v,SCALAR) and not isinstance(v,(dict,list))

def _graph_from_rule(root:Any,rule:dict[str,Any]):
    nodes_path=str(rule.get('nodes_path','/nodes')); edges_path=str(rule.get('edges_path','/edges'))
    node_id=str(rule.get('node_id','id')); srcf=str(rule.get('source_field','source')); dstf=str(rule.get('target_field','target'))
    nodes=_as_list(root,nodes_path); edges=_as_list(root,edges_path)
    if nodes is None or edges is None: return None
    ids=[]; positions={}; duplicates=[]
    for i,n in enumerate(nodes):
        if not isinstance(n,dict) or not _scalar_id(n.get(node_id)): continue
        x=n[node_id]; ids.append(x)
        if x in positions: duplicates.append(x)
        positions[x]=i
    idset=set(ids); clean_edges=[]; malformed=[]; dangling=[]
    for i,e in enumerate(edges):
        if not isinstance(e,dict) or not _scalar_id(e.get(srcf)) or not _scalar_id(e.get(dstf)):
            malformed.append(i); continue
        a,b=e[srcf],e[dstf]; clean_edges.append((a,b,i,e))
        if a not in idset or b not in idset: dangling.append((a,b,i))
    return {'nodes_path':nodes_path,'edges_path':edges_path,'node_id':node_id,'source_field':srcf,'target_field':dstf,
            'nodes':nodes,'edges':edges,'ids':ids,'idset':idset,'positions':positions,'duplicates':duplicates,
            'clean_edges':clean_edges,'malformed':malformed,'dangling':dangling}

def _adj(g, *, include_dangling=False):
    a={x:set() for x in g['idset']}
    for s,t,_,_ in g['clean_edges']:
        if include_dangling or (s in g['idset'] and t in g['idset']): a.setdefault(s,set()).add(t)
    return a

def _find_cycle(adj:dict[Any,set[Any]])->list[Any]|None:
    color={}; parent={}
    for start in sorted(adj,key=lambda x:repr(x)):
        if color.get(start,0): continue
        stack=[(start,iter(sorted(adj.get(start,set()),key=lambda x:repr(x))))]; color[start]=1
        while stack:
            u,it=stack[-1]
            try: v=next(it)
            except StopIteration:
                color[u]=2; stack.pop(); continue
            if color.get(v,0)==0:
                parent[v]=u; color[v]=1; stack.append((v,iter(sorted(adj.get(v,set()),key=lambda x:repr(x)))))
            elif color.get(v)==1:
                cyc=[v,u]; cur=u
                while cur!=v and cur in parent:
                    cur=parent[cur]
                    if cur!=v: cyc.append(cur)
                cyc.append(v); cyc.reverse(); return cyc
    return None

def _reachable(adj:dict[Any,set[Any]],root_id:Any)->set[Any]:
    if root_id not in adj: return set()
    seen={root_id}; q=deque([root_id])
    while q:
        u=q.popleft()
        for v in adj.get(u,set()):
            if v not in seen: seen.add(v); q.append(v)
    return seen

def _topological_orders(adj:dict[Any,set[Any]], limit:int=2):
    nodes=set(adj)
    for vs in adj.values(): nodes.update(vs)
    indeg={n:0 for n in nodes}
    for u,vs in adj.items():
        for v in vs: indeg[v]=indeg.get(v,0)+1
    outs=[]
    def rec(order, indeg_now):
        if len(outs)>=limit: return
        if len(order)==len(nodes): outs.append(list(order)); return
        avail=sorted([n for n in nodes if n not in order and indeg_now.get(n,0)==0],key=lambda x:repr(x))
        for n in avail:
            nxt=dict(indeg_now); nxt[n]=-1
            for v in adj.get(n,set()): nxt[v]-=1
            rec(order+[n],nxt)
            if len(outs)>=limit: return
    rec([],indeg)
    return outs

def _shortest_path(adj:dict[Any,set[Any]],src:Any,dst:Any)->list[Any]|None:
    if src==dst and src in adj: return [src]
    if src not in adj or dst not in adj: return None
    q=deque([src]); prev={src:None}
    while q:
        u=q.popleft()
        for v in sorted(adj.get(u,set()),key=lambda x:repr(x)):
            if v in prev: continue
            prev[v]=u
            if v==dst:
                path=[v]; cur=u
                while cur is not None: path.append(cur); cur=prev[cur]
                return list(reversed(path))
            q.append(v)
    return None

def discover_graph_rules(root:Any)->list[dict[str,Any]]:
    """Conservative automatic discovery for obvious {nodes,edges} carriers.

    Discovery only enables topology diagnostics. It never enables destructive repair.
    """
    out=[]
    def rec(v,path):
        if isinstance(v,dict):
            keys=set(v)
            node_key=next((k for k in ('nodes','vertices') if k in keys and isinstance(v[k],list)),None)
            edge_key=next((k for k in ('edges','links') if k in keys and isinstance(v[k],list)),None)
            if node_key and edge_key and v[node_key] and v[edge_key]:
                node_objs=[x for x in v[node_key] if isinstance(x,dict)]
                edge_objs=[x for x in v[edge_key] if isinstance(x,dict)]
                node_id=next((k for k in ('id','uuid','key') if node_objs and sum(k in x for x in node_objs)==len(node_objs)),None)
                src=next((k for k in ('source','from','src') if edge_objs and sum(k in x for x in edge_objs)==len(edge_objs)),None)
                dst=next((k for k in ('target','to','dst') if edge_objs and sum(k in x for x in edge_objs)==len(edge_objs)),None)
                if node_id and src and dst:
                    base='/'+'/'.join(str(x).replace('~','~0').replace('/','~1') for x in path) if path else ''
                    out.append(_stable_rule({'kind':'graph','nodes_path':_path_join(base,node_key),'edges_path':_path_join(base,edge_key),
                                             'node_id':node_id,'source_field':src,'target_field':dst,'source':'inferred'},'graph'))
            for k,x in v.items(): rec(x,path+[k])
        elif isinstance(v,list):
            for i,x in enumerate(v): rec(x,path+[i])
    rec(root,[])
    return out

def analyze_graph_rule(root:Any,rule:dict[str,Any])->AnalysisResult:
    r=AnalysisResult(); rule=_stable_rule(rule,'graph'); g=_graph_from_rule(root,rule)
    if g is None:
        r.issues.append(Issue('graph_system','graph_carrier_missing',str(rule.get('nodes_path','/nodes')),'Configured graph carrier is missing or not an array.','error',False,{'rule_id':rule['rule_id']})); return r
    rel={'kind':'graph_topology','array_path':g['nodes_path'],'inputs':[g['node_id'],g['source_field']],'output':g['target_field'],
         'confidence':1.0,'support':len(g['clean_edges']),'rule_id':rule['rule_id'],'constraint_source':rule.get('source','authoritative'),
         'nodes_path':g['nodes_path'],'edges_path':g['edges_path'],'node_id':g['node_id'],'source_field':g['source_field'],'target_field':g['target_field']}
    rel['relation_id']=_rid(rel); r.relations.append(rel)
    if g['duplicates']:
        r.issues.append(Issue('graph_system','duplicate_node_identity',g['nodes_path'],'Graph contains duplicate node identities.','error',False,{'rule_id':rule['rule_id'],'duplicates':sorted(set(g['duplicates']),key=lambda x:repr(x))}))
    for idx in g['malformed']:
        r.issues.append(Issue('graph_system','malformed_edge',_path_join(g['edges_path'],idx),'Edge lacks a valid source/target identity.','error',False,{'rule_id':rule['rule_id']}))
    for s,t,idx in g['dangling']:
        r.issues.append(Issue('graph_system','dangling_edge',_path_join(g['edges_path'],idx),'Edge references a node identity absent from the graph.','warning',False,{'rule_id':rule['rule_id'],'source':s,'target':t,'source_exists':s in g['idset'],'target_exists':t in g['idset']}))
    adj=_adj(g); cyc=_find_cycle(adj)
    if rule.get('require_acyclic') and cyc:
        r.issues.append(Issue('graph_system','graph_cycle',g['edges_path'],'Authoritative DAG constraint is violated by a directed cycle.','error',False,{'rule_id':rule['rule_id'],'cycle':cyc}))
    root_id=rule.get('root_id')
    if root_id is not None:
        seen=_reachable(adj,root_id); missing=sorted(g['idset']-seen,key=lambda x:repr(x))
        if missing:
            r.issues.append(Issue('graph_system','unreachable_nodes',g['nodes_path'],'Nodes are not reachable from the authoritative root.','warning',False,{'rule_id':rule['rule_id'],'root_id':root_id,'unreachable':missing}))
    order_path=rule.get('order_path')
    if order_path and rule.get('require_topological_order',True) and not cyc and not g['dangling'] and not g['duplicates']:
        try: observed=get(root,str(order_path))
        except Exception: observed=None
        orders=_topological_orders(adj,2)
        if isinstance(observed,list) and len(orders)==1:
            expected=orders[0]
            if observed!=expected:
                meta={'rule_id':rule['rule_id'],'relation_kind':'graph_topological_order_authoritative','constraint_source':'authoritative'}
                r.issues.append(Issue('graph_system','topological_order_violation',str(order_path),'Stored order is not the unique topological order of the authoritative DAG.','warning',True,meta))
                r.candidates.append(_candidate('graph_system','replace',str(order_path),observed,expected,'Restore the unique topological order.',meta))
        elif isinstance(observed,list) and len(orders)>1:
            # Only flag if the observed order is invalid; a valid choice among multiple orders is legitimate.
            pos={v:i for i,v in enumerate(observed)} if len(set(map(repr,observed)))==len(observed) else {}
            valid=set(observed)==g['idset'] and all(pos.get(u,-1)<pos.get(v,-1) for u,vs in adj.items() for v in vs)
            if not valid:
                r.issues.append(Issue('graph_system','topological_order_ambiguous',str(order_path),'Graph has multiple legal topological orders; invalid stored order cannot be repaired uniquely.','warning',False,{'rule_id':rule['rule_id'],'witness_orders':orders[:2]}))
    if rule.get('require_reciprocal') and not g['dangling']:
        pairs={(s,t) for s,t,_,_ in g['clean_edges']}; missing=[]
        for s,t,_,e in g['clean_edges']:
            if (t,s) not in pairs and s!=t: missing.append((t,s,e))
        # One absent reciprocal edge is uniquely reconstructible. Multiple append candidates at '/-' would interact by index, so abstain as a bundle.
        if len(missing)==1:
            s,t,e=missing[0]; defaults=deepcopy(rule.get('edge_defaults') or {})
            safe_shape=set(e).issubset({g['source_field'],g['target_field']}) or bool(rule.get('edge_defaults'))
            if safe_shape:
                new={**defaults,g['source_field']:s,g['target_field']:t}; p=_path_join(g['edges_path'],'-')
                meta={'rule_id':rule['rule_id'],'relation_kind':'graph_reciprocity_authoritative','constraint_source':'authoritative','require_absent':False}
                r.issues.append(Issue('graph_system','missing_reciprocal_edge',g['edges_path'],'Exactly one reciprocal edge is required by the authoritative graph contract.','warning',True,meta))
                r.candidates.append(_candidate('graph_system','add',p,None,new,'Add the uniquely determined reciprocal edge.',meta))
            else:
                r.issues.append(Issue('graph_system','missing_reciprocal_edge_unmaterialized',g['edges_path'],'Reciprocal edge is determined but its extra edge payload is not reconstructible.','warning',False,{'rule_id':rule['rule_id'],'source':s,'target':t}))
        elif missing:
            r.issues.append(Issue('graph_system','multiple_reciprocal_edges_missing',g['edges_path'],'Multiple reciprocal edges are missing; no single append repair is selected.','warning',False,{'rule_id':rule['rule_id'],'count':len(missing)}))
    return r

def _state_universe(transitions):
    s=set()
    for a,b in transitions: s.add(a); s.add(b)
    return s

def _state_adj(transitions):
    d={}
    for a,b in transitions: d.setdefault(a,set()).add(b); d.setdefault(b,set())
    return d

def analyze_state_machine_rule(root:Any,rule:dict[str,Any])->AnalysisResult:
    r=AnalysisResult(); rule=_stable_rule(rule,'state')
    path=str(rule.get('sequence_path','/events')); field=str(rule.get('state_field','state')); seq=_as_list(root,path)
    trans=[]
    for pair in rule.get('transitions',[]):
        if isinstance(pair,(list,tuple)) and len(pair)==2: trans.append((pair[0],pair[1]))
    if seq is None or not trans:
        r.issues.append(Issue('state_machine','state_machine_material_missing',path,'State machine sequence or transition relation is unavailable.','error',False,{'rule_id':rule['rule_id']})); return r
    states=[]
    for i,e in enumerate(seq): states.append(e.get(field) if isinstance(e,dict) else None)
    adj=_state_adj(trans); universe=_state_universe(trans)
    rel={'kind':'state_machine_authoritative','array_path':path,'inputs':[field],'output':field,'confidence':1.0,'support':max(0,len(states)-1),
         'rule_id':rule['rule_id'],'constraint_source':'authoritative','transitions':[list(x) for x in trans],'initial':rule.get('initial'),'terminal':rule.get('terminal')}
    rel['relation_id']=_rid(rel); r.relations.append(rel)
    initial=rule.get('initial')
    if states and initial is not None and states[0]!=initial:
        ok_next=len(states)==1 or states[1] in adj.get(initial,set())
        meta={'rule_id':rule['rule_id'],'relation_kind':'state_machine_authoritative','constraint_source':'authoritative','position':0}
        r.issues.append(Issue('state_machine','initial_state_violation',_path_join(_path_join(path,0),field),'Initial state violates the authoritative state machine.','warning',bool(ok_next),meta))
        if ok_next: r.candidates.append(_candidate('state_machine','replace',_path_join(_path_join(path,0),field),states[0],initial,'Restore authoritative initial state.',meta))
    terminals=rule.get('terminal')
    if terminals is not None and not isinstance(terminals,list): terminals=[terminals]
    terminals=set(terminals or [])
    # Interior state can be repaired only when one and only one state satisfies both adjacent transitions.
    for i in range(1,max(1,len(states)-1)):
        if i>=len(states)-1: break
        prev,cur,nxt=states[i-1],states[i],states[i+1]
        if cur in adj.get(prev,set()) and nxt in adj.get(cur,set()): continue
        possible=sorted([s for s in universe if s in adj.get(prev,set()) and nxt in adj.get(s,set())],key=lambda x:repr(x))
        p=_path_join(_path_join(path,i),field); meta={'rule_id':rule['rule_id'],'relation_kind':'state_machine_authoritative','constraint_source':'authoritative','position':i,'previous':prev,'next':nxt,'possible_states':possible}
        if len(possible)==1:
            r.issues.append(Issue('state_machine','invalid_transition_state',p,'Interior state breaks the authoritative transition graph and has one exact reconstruction.','warning',True,meta))
            r.candidates.append(_candidate('state_machine','replace',p,cur,possible[0],'Restore the unique state compatible with previous and next states.',meta))
        else:
            r.issues.append(Issue('state_machine','invalid_transition_state',p,'Interior state breaks the authoritative transition graph but reconstruction is not unique.','warning',False,meta))
    if len(states)>=2:
        a,b=states[-2],states[-1]
        if b not in adj.get(a,set()):
            p=_path_join(_path_join(path,len(states)-1),field); poss=sorted(adj.get(a,set()),key=lambda x:repr(x)); meta={'rule_id':rule['rule_id'],'relation_kind':'state_machine_authoritative','constraint_source':'authoritative','previous':a,'possible_states':poss}
            if terminals:
                poss=[x for x in poss if x in terminals]; meta['possible_states']=poss
            if len(poss)==1:
                r.issues.append(Issue('state_machine','terminal_transition_violation',p,'Final state has one exact legal successor under the authoritative machine.','warning',True,meta))
                r.candidates.append(_candidate('state_machine','replace',p,b,poss[0],'Restore the unique legal final state.',meta))
            else:
                r.issues.append(Issue('state_machine','terminal_transition_violation',p,'Final transition is illegal and no unique final state is identified.','warning',False,meta))
    target=rule.get('target_state')
    current=states[-1] if states else None
    if target is not None and current is not None:
        plan=_shortest_path(adj,current,target)
        # This is a planning witness, not an instruction to falsify history by changing snapshots.
        rel2={'kind':'state_reachability','array_path':path,'inputs':[field],'output':'__target_state__','confidence':1.0,'support':len(states),
              'rule_id':rule['rule_id'],'constraint_source':'authoritative','current_state':current,'target_state':target,'reachable':plan is not None,'shortest_state_path':plan}
        rel2['relation_id']=_rid(rel2); r.relations.append(rel2)
        if plan is None:
            r.issues.append(Issue('state_machine','target_state_unreachable',path,'Requested target state is unreachable from the current state under the authoritative transition graph.','warning',False,{'rule_id':rule['rule_id'],'current_state':current,'target_state':target}))
    return r

def _toposort_steps(steps:list[dict[str,Any]]):
    ids=[str(s.get('id') or f'step_{i}') for i,s in enumerate(steps)]
    if len(set(ids))!=len(ids): return None,'DUPLICATE_STEP_ID'
    by={i:deepcopy(s) for i,s in zip(ids,steps)}
    deps={i:set(map(str,by[i].get('after',[]) or [])) for i in ids}
    if any(d not in by for ds in deps.values() for d in ds): return None,'UNKNOWN_DEPENDENCY'
    out=[]; done=set()
    while len(out)<len(ids):
        ready=sorted([i for i in ids if i not in done and deps[i]<=done])
        if not ready: return None,'DEPENDENCY_CYCLE'
        # A canonical order is legal only if ready alternatives commute. The caller checks this pairwise on material state.
        x=ready[0]; out.append(x); done.add(x)
    return [(i,by[i]) for i in out],None

def _step_patch(step:dict[str,Any])->dict[str,Any]:
    op=str(step.get('operation') or step.get('op') or '')
    p={'operation':op,'path':str(step.get('path','')),'metadata':deepcopy(step.get('metadata') or {})}
    if 'from_path' in step: p['metadata']['from_path']=str(step['from_path'])
    if 'from' in step: p['metadata']['from_path']=str(step['from'])
    if 'old_value' in step: p['old_value']=deepcopy(step['old_value'])
    if 'new_value' in step: p['new_value']=deepcopy(step['new_value'])
    elif 'value' in step: p['new_value']=deepcopy(step['value'])
    if op=='add': p['metadata'].setdefault('require_absent',True)
    return p

def _pair_commutes(root:Any,a:dict[str,Any],b:dict[str,Any])->bool:
    x=deepcopy(root); ok1,_=apply_patch(x,a); ok2,_=apply_patch(x,b) if ok1 else (False,None)
    y=deepcopy(root); ok3,_=apply_patch(y,b); ok4,_=apply_patch(y,a) if ok3 else (False,None)
    return bool(ok1 and ok2 and ok3 and ok4 and digest(x)==digest(y))


def _exists(root:Any,path:str)->bool:
    try: get(root,path); return True
    except Exception: return False

def _patch_postcondition(root:Any,p:dict[str,Any])->bool:
    op=str(p.get('operation') or p.get('op') or ''); path=str(p.get('path','')); meta=p.get('metadata') or {}
    try:
        if op in {'add','replace'}: return get(root,path)==p.get('new_value',p.get('value'))
        if op=='remove': return not _exists(root,path)
        if op=='move':
            src=str(meta.get('from_path') or p.get('from_path') or p.get('from') or '')
            if not src or _exists(root,src) or not _exists(root,path): return False
            return ('old_value' not in p) or get(root,path)==p.get('old_value')
        if op=='copy':
            src=str(meta.get('from_path') or p.get('from_path') or p.get('from') or '')
            return bool(src and _exists(root,src) and _exists(root,path) and get(root,src)==get(root,path))
        if op=='test': return get(root,path)==p.get('new_value',p.get('value'))
    except Exception: return False
    return False

def _target_tests_hold(root:Any,tests:list[dict[str,Any]])->bool:
    if not tests: return False
    return all(_patch_postcondition(root, {'operation':'test','path':str(t.get('path','')),'new_value':deepcopy(t.get('equals',t.get('value')))}) for t in tests if isinstance(t,dict))

def analyze_migration_rule(root:Any,rule:dict[str,Any])->AnalysisResult:
    r=AnalysisResult(); rule=_stable_rule(rule,'migration'); steps=rule.get('steps') or []
    if not isinstance(steps,list) or not steps:
        r.issues.append(Issue('migration_planner','migration_steps_missing','', 'Migration rule contains no steps.','error',False,{'rule_id':rule['rule_id']})); return r
    ordered,err=_toposort_steps(steps)
    if err:
        r.issues.append(Issue('migration_planner','migration_dependency_error','',f'Migration dependency graph is invalid: {err}.','error',False,{'rule_id':rule['rule_id'],'error':err})); return r
    byid={i:s for i,s in ordered}; ids=[i for i,_ in ordered]; deps={i:set(map(str,(byid[i].get('after') or []))) for i in ids}
    patches={i:_step_patch(byid[i]) for i in ids}
    noncommuting=[]
    # Any pair without a declared path between them must commute, otherwise the migration order is underspecified.
    def depends(a,b):
        seen=set(); stack=list(deps[a])
        while stack:
            x=stack.pop()
            if x==b: return True
            if x in seen: continue
            seen.add(x); stack.extend(deps.get(x,set()))
        return False
    for i,a in enumerate(ids):
        for b in ids[i+1:]:
            if depends(a,b) or depends(b,a): continue
            if not _pair_commutes(root,patches[a],patches[b]): noncommuting.append([a,b])
    rel={'kind':'ordered_migration_plan','array_path':'','inputs':ids,'output':'__migration_target__','confidence':1.0,'support':len(ids),
         'rule_id':rule['rule_id'],'constraint_source':'authoritative','ordered_step_ids':ids,'noncommuting_unordered_pairs':noncommuting}
    rel['relation_id']=_rid(rel); r.relations.append(rel)
    if noncommuting:
        r.issues.append(Issue('migration_planner','migration_order_underspecified','', 'Migration contains non-commuting steps without an explicit dependency order.','error',False,{'rule_id':rule['rule_id'],'pairs':noncommuting})); return r
    target_tests=[x for x in (rule.get('target_tests') or []) if isinstance(x,dict)]
    already_target = _target_tests_hold(root,target_tests) if target_tests else all(_patch_postcondition(root,patches[sid]) for sid in ids)
    if already_target:
        rel['migration_status']='ALREADY_AT_TARGET'
        return r
    # Materialize the plan exactly on a copy. A failed precondition means the rule is not applicable to this document, not that values should be guessed.
    trial=deepcopy(root); exact_steps=[]; inverses=[]
    for sid in ids:
        p=patches[sid]; ok,inv=apply_patch(trial,p)
        if not ok:
            r.issues.append(Issue('migration_planner','migration_precondition_failed',str(p.get('path','')),'Authoritative migration step cannot be applied with its exact preconditions.','warning',False,{'rule_id':rule['rule_id'],'step_id':sid,'patch':p})); return r
        exact_steps.append({**p,'step_id':sid}); inverses.append(inv)
    if digest(trial)==digest(root):
        return r
    target_digest=digest(trial)
    meta={'rule_id':rule['rule_id'],'relation_kind':'ordered_migration_plan','constraint_source':'authoritative','steps':exact_steps,
          'ordered_step_ids':ids,'source_digest':digest(root),'target_digest':target_digest,'inverse_steps':list(reversed(inverses))}
    r.issues.append(Issue('migration_planner','migration_available','', 'Authoritative ordered migration has one exact reachable target.','warning',True,meta))
    r.candidates.append(_candidate('migration_planner','plan','',digest(root),target_digest,'Apply the exact ordered migration plan atomically.',meta,cost=len(exact_steps)))
    return r

def analyze_system_rules(root:Any,config)->AnalysisResult:
    out=AnalysisResult(); explicit=[_stable_rule(x) for x in (getattr(config,'system_rules',()) or ()) if isinstance(x,dict)]
    document=getattr(config,'system_document',None)
    explicit=[x for x in explicit if x.get('document') is None or (document is not None and str(x.get('document'))==str(document))]
    explicit_graphs=[x for x in explicit if x.get('kind')=='graph']
    inferred=discover_graph_rules(root) if getattr(config,'auto_graph_discovery',True) else []
    # Exact path-identical authoritative rules shadow inferred diagnostics.
    explicit_carriers={(x.get('nodes_path'),x.get('edges_path')) for x in explicit_graphs}
    rules=explicit + [x for x in inferred if (x.get('nodes_path'),x.get('edges_path')) not in explicit_carriers]
    for rule in rules:
        kind=rule.get('kind')
        if kind=='graph': part=analyze_graph_rule(root,rule)
        elif kind=='state_machine': part=analyze_state_machine_rule(root,rule)
        elif kind=='migration': part=analyze_migration_rule(root,rule)
        else: continue
        out.issues.extend(part.issues); out.candidates.extend(part.candidates); out.relations.extend(part.relations)
    return out

def system_summary(analysis:AnalysisResult)->dict[str,Any]:
    rels=[r for r in analysis.relations if r.get('kind') in {'graph_topology','state_machine_authoritative','state_reachability','ordered_migration_plan'}]
    return {'contract':'json-consistency-repair.system-graph-state.v1','relation_count':len(rels),
            'graph_relations':sum(r.get('kind')=='graph_topology' for r in rels),
            'state_machine_relations':sum(r.get('kind')=='state_machine_authoritative' for r in rels),
            'reachability_relations':sum(r.get('kind')=='state_reachability' for r in rels),
            'migration_plans':sum(r.get('kind')=='ordered_migration_plan' for r in rels),
            'issue_count':sum(i.analyzer in {'graph_system','state_machine','migration_planner'} for i in analysis.issues),
            'repairable_issue_count':sum(i.analyzer in {'graph_system','state_machine','migration_planner'} and i.repairable for i in analysis.issues)}
