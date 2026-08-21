from __future__ import annotations

"""PASS022 — bounded C189-style federation for JSON analyzers.

MODE I is the immutable analyzer snapshot already materialized by ``analyze_all``.
MODE II never rewrites that snapshot.  It partitions the outputs by actor, broadcasts
active pairwise objects, creates only on-demand hyperobjects, composes certified
directed relations to a bounded fixed point, and exposes an exact Q ledger.
"""
from copy import deepcopy
from dataclasses import replace
from itertools import combinations
from typing import Any
import hashlib, json

from .models import AnalysisResult, Candidate, Issue, digest
from .constraint_ir import compile_typed_constraint_ir
from .jsonpatch_exact import candidate_patch, apply_patch

CONTRACT="json-consistency-repair.c189-federation.v1"
PAIR_CONTRACT="json-consistency-repair.federated-pair.v1"
HYPER_CONTRACT="json-consistency-repair.federated-hyperobject.v1"
Q_CONTRACT="json-consistency-repair.dynamic-q-descent.v1"

ACTORS=(
    "constraint_bridge","moments","system_graph_state","identifier_reference",
    "conservation","logic_exact","sequential","schema_structure",
    "structural_migration","type_pattern","enum_domain","functional_relation",
    "scoped_functional_relation","exact_arithmetic","temporal",
    "modal_firewall","recursive_morphology",
)

KIND_ACTOR={
    "type_consensus":"type_pattern","required_key":"schema_structure","enum_domain":"enum_domain",
    "identifier_uniqueness":"identifier_reference","foreign_reference":"identifier_reference",
    "functional":"functional_relation","scoped_functional":"scoped_functional_relation",
    "exact_arithmetic":"exact_arithmetic","temporal_delta":"temporal","sequence_step":"sequential",
    "logic_exact":"logic_exact","logic_rule_system":"logic_exact","logic_rule_system_stream":"logic_exact",
    "recursive_morphology":"recursive_morphology","modal_regime":"modal_firewall","schema_evolution":"modal_firewall",
    "linear_exact_system":"constraint_bridge","authoritative_json_schema":"constraint_bridge",
    "aggregate_sum":"conservation","aggregate_count":"conservation","aggregate_sum_authoritative":"conservation",
    "aggregate_count_authoritative":"conservation","balance_authoritative":"conservation",
    "multiset_balance_authoritative":"conservation","scalar_conservation_balance":"conservation","multiset_conservation":"conservation",
}


def _stable(prefix:str, payload:Any, n:int=20)->str:
    raw=json.dumps(payload,ensure_ascii=False,sort_keys=True,separators=(",",":"),default=str).encode()
    return f"{prefix}_{hashlib.sha256(raw).hexdigest()[:n]}"


def _actor_for_relation(rel:dict[str,Any])->str:
    kind=str(rel.get("kind") or "")
    if kind in KIND_ACTOR: return KIND_ACTOR[kind]
    if kind.startswith("logic_"): return "logic_exact"
    if "conservation" in kind: return "conservation"
    if kind.startswith("constraint_dsl_"): return "constraint_bridge"
    if kind.startswith("moment_") or kind in {"weighted_mean","weighted_sum","variance","covariance","probability_distribution","uncertainty_variance","unit_normalization"}: return "moments"
    if kind.startswith("system_") or kind in {"dag","state_machine","migration_plan","graph_reciprocity"}: return "system_graph_state"
    if kind.startswith("structural_"): return "structural_migration"
    return str(rel.get("analyzer") or rel.get("source_analyzer") or "unowned_relation")


def _packet(actor:str, analysis:AnalysisResult)->dict[str,Any]:
    issues=[i for i in analysis.issues if i.analyzer==actor]
    candidates=[c for c in analysis.candidates if c.analyzer==actor]
    relations=[r for r in analysis.relations if _actor_for_relation(r)==actor]
    row={
        "actor_id":actor,
        "issue_ids":[_stable("issue",i.signature()) for i in issues],
        "issue_paths":sorted({i.path for i in issues}),
        "candidate_ids":sorted(c.candidate_id for c in candidates),
        "candidate_paths":sorted({c.path for c in candidates}),
        "relation_ids":sorted(str(r.get("relation_id")) for r in relations),
        "relation_fields":sorted({str(x) for r in relations for x in [*(r.get("inputs") or []),r.get("output")] if x not in {None,"__logic__","__shape__","__schema__","__regime__","__morphology__"}}),
        "issue_count":len(issues),"candidate_count":len(candidates),"relation_count":len(relations),
    }
    row["packet_digest"]=digest(row)
    return row


def mode_i_packets(analysis:AnalysisResult)->list[dict[str,Any]]:
    roster=list(ACTORS)
    extras=sorted(({i.analyzer for i in analysis.issues}|{c.analyzer for c in analysis.candidates}|{_actor_for_relation(r) for r in analysis.relations})-set(roster)-{"unowned_relation"})
    return [_packet(a,analysis) for a in [*roster,*extras]]


def _patch_identity(c:Candidate)->tuple[str,str,str,str]:
    return (c.operation,c.path,str((c.metadata or {}).get("from_path","")),json.dumps(c.new_value,ensure_ascii=False,sort_keys=True,separators=(",",":"),default=str))


def _active_pair(left:dict[str,Any],right:dict[str,Any])->tuple[bool,list[str]]:
    reasons=[]
    ip=set(left["issue_paths"]); jp=set(right["issue_paths"])
    cp=set(left["candidate_paths"]); dp=set(right["candidate_paths"])
    if ip & jp: reasons.append("SHARED_ISSUE_PATH")
    if cp & dp: reasons.append("SHARED_CANDIDATE_PATH")
    if cp & jp: reasons.append("LEFT_CANDIDATE_TOUCHES_RIGHT_ISSUE")
    if dp & ip: reasons.append("RIGHT_CANDIDATE_TOUCHES_LEFT_ISSUE")
    if set(left["relation_fields"]) & set(right["relation_fields"]): reasons.append("SHARED_RELATION_FIELD")
    return bool(reasons),reasons


def pairwise_objects(packets:list[dict[str,Any]], max_objects:int=256)->list[dict[str,Any]]:
    rows=[]
    for a,b in combinations(sorted(packets,key=lambda x:x["actor_id"]),2):
        active,reasons=_active_pair(a,b)
        row={"contract":PAIR_CONTRACT,"pair_id":f"O::{a['actor_id']}::{b['actor_id']}","left_actor":a["actor_id"],"right_actor":b["actor_id"],"active":active,"activation_reasons":reasons}
        row["pair_digest"]=digest(row); rows.append(row)
    # Keep every pair for the independence ledger while bounding unexpectedly large plugin rosters.
    return rows[:max(0,int(max_objects))]


def _relation_scope(rel:dict[str,Any])->str:
    return str(rel.get("array_path") or rel.get("source_array_path") or "")


def _directed(rel:dict[str,Any])->bool:
    out=rel.get("output")
    if out in (None,"__logic__","__shape__","__schema__","__regime__","__morphology__"): return False
    kind=str(rel.get("kind") or "")
    if kind=="exact_arithmetic": return bool(rel.get("direction_certified"))
    if kind.startswith("logic_") or kind=="linear_exact_system": return False
    if rel.get("direction_certified") is True: return True
    # Existing deterministic directed families.
    return kind in {"functional","scoped_functional","temporal_delta","sequence_step","foreign_reference",
                    "aggregate_sum","aggregate_count","aggregate_sum_authoritative","aggregate_count_authoritative",
                    "weighted_mean","weighted_sum","variance","covariance","unit_normalization","federated_composite"}


def _compose(left:dict[str,Any], right:dict[str,Any], owners:dict[str,str])->dict[str,Any]|None:
    if not (_directed(left) and _directed(right)): return None
    if _relation_scope(left)!=_relation_scope(right): return None
    mid=left.get("output"); rout=right.get("output")
    if mid is None or rout is None or mid not in (right.get("inputs") or []): return None
    if rout==mid: return None
    lin=list(left.get("inputs") or []); rin=[x for x in (right.get("inputs") or []) if x!=mid]
    inputs=[]
    for x in [*lin,*rin]:
        if x not in inputs and x!=rout: inputs.append(x)
    if not inputs: return None
    sources=[]
    for r in (left,right):
        for rid in (r.get("source_relation_ids") or [r.get("relation_id")]):
            if rid and rid not in sources: sources.append(str(rid))
    source_actors=sorted({owners.get(str(x),"federation") for x in sources})
    if len(source_actors)<2 and "federation" not in source_actors:
        return None
    depth=max(int(left.get("federation_depth",0)),int(right.get("federation_depth",0)))+1
    semantic={"kind":"federated_composite","array_path":_relation_scope(left),"inputs":inputs,"output":rout}
    payload={**semantic,"source_relation_ids":sources,"source_actors":source_actors,"federation_depth":depth}
    # Identity is semantic, not derivation-history based.  Re-deriving a->c through a longer
    # chain is reinforcement of the same relation, not a fresh object that can prevent fixed point.
    rid=_stable("fedrel",semantic)
    confs=[x for x in (left.get("confidence"),right.get("confidence")) if isinstance(x,(int,float))]
    supps=[x for x in (left.get("support"),right.get("support")) if isinstance(x,(int,float))]
    return {**payload,"relation_id":rid,"confidence":min(confs) if confs else None,"support":min(supps) if supps else None,
            "direction_certified":True,"derived_only":True,"federation_contract":CONTRACT}


def _hyperobjects(analysis:AnalysisResult, packets:list[dict[str,Any]], max_hyper:int=256)->tuple[list[dict[str,Any]],list[Candidate]]:
    bypatch={}
    for c in analysis.candidates: bypatch.setdefault(_patch_identity(c),[]).append(c)
    hypers=[]; consensus=[]
    for key,group in sorted(bypatch.items(),key=lambda kv:kv[0]):
        actors=sorted({c.analyzer for c in group})
        if len(actors)>=2:
            h={"contract":HYPER_CONTRACT,"hyperobject_kind":"CONSENSUS_PATCH","participants":actors,"operation":key[0],"path":key[1],"from_path":key[2],"new_value":deepcopy(group[0].new_value),"candidate_ids":sorted(c.candidate_id for c in group)}
            h["hyperobject_id"]=_stable("hyper",h); hypers.append(h)
            rep=max(group,key=lambda c:(c.confidence,-c.cost,c.candidate_id))
            consensus.append(replace(rep,candidate_id=_stable("fedcand",[h["hyperobject_id"],key]),analyzer="federation_consensus",
                                     evidence=tuple(sorted(set(rep.evidence)|{f"actor:{a}" for a in actors})),
                                     metadata={**rep.metadata,"federated_support_actors":actors,"federated_hyperobject_id":h["hyperobject_id"]}))
    # Same path, divergent values -> explicit unresolved hyperobject, never a candidate.
    bypath={}
    for c in analysis.candidates: bypath.setdefault((c.operation,c.path,str((c.metadata or {}).get("from_path",""))),[]).append(c)
    for key,group in sorted(bypath.items(),key=lambda kv:kv[0]):
        vals={json.dumps(c.new_value,ensure_ascii=False,sort_keys=True,separators=(",",":"),default=str) for c in group}
        actors=sorted({c.analyzer for c in group})
        if len(vals)>1 and len(actors)>=2:
            h={"contract":HYPER_CONTRACT,"hyperobject_kind":"CANDIDATE_CONFLICT","participants":actors,"operation":key[0],"path":key[1],"from_path":key[2],"candidate_ids":sorted(c.candidate_id for c in group),"alternative_count":len(vals)}
            h["hyperobject_id"]=_stable("hyper",h); hypers.append(h)
    # Cross actor candidate->issue contact is a real on-demand hyperobject.
    issues_by_path={}
    for i in analysis.issues: issues_by_path.setdefault(i.path,[]).append(i)
    for c in analysis.candidates:
        peers=sorted({i.analyzer for i in issues_by_path.get(c.path,[]) if i.analyzer!=c.analyzer})
        if peers:
            h={"contract":HYPER_CONTRACT,"hyperobject_kind":"CROSS_ACTOR_TERMINAL_CONTACT","participants":[c.analyzer,*peers],"path":c.path,"candidate_id":c.candidate_id,"issue_actors":peers}
            h["hyperobject_id"]=_stable("hyper",h); hypers.append(h)
    uniq={h["hyperobject_id"]:h for h in hypers}
    return [uniq[k] for k in sorted(uniq)][:max_hyper],consensus


def federation_fixed_point(analysis:AnalysisResult, config)->tuple[AnalysisResult,dict[str,Any]]:
    packets=mode_i_packets(analysis)
    pairs=pairwise_objects(packets,getattr(config,"federation_max_pairwise_objects",256))
    hypers,consensus=_hyperobjects(analysis,packets,getattr(config,"federation_max_hyperobjects",256))
    owners={str(r.get("relation_id")):_actor_for_relation(r) for r in analysis.relations}
    relations={str(r.get("relation_id")):r for r in analysis.relations}
    synthetic={}; receipts=[]; quiet=0
    max_cycles=max(1,int(getattr(config,"federation_max_cycles",4)))
    required_quiet=max(1,int(getattr(config,"federation_quiet_cycles_required",2)))
    max_comp=max(0,int(getattr(config,"federation_max_composites",128)))
    for cyc in range(1,max_cycles+1):
        before=set(synthetic); allrels=list(relations.values())+list(synthetic.values()); new=[]
        # Indexed deterministic all-to-all reaction: only relations whose input can consume
        # the exact output field on the same scope are pairwise candidates.
        consume={}
        for right in allrels:
            if not _directed(right): continue
            scope=_relation_scope(right)
            for field in (right.get("inputs") or []):
                consume.setdefault((scope,field),[]).append(right)
        own={**owners,**{rid:"federation" for rid in synthetic}}
        for left in allrels:
            if not _directed(left): continue
            for right in consume.get((_relation_scope(left),left.get("output")),[]):
                if left is right: continue
                row=_compose(left,right,own)
                if row is None: continue
                rid=row["relation_id"]
                if rid not in relations and rid not in synthetic:
                    new.append(row)
        for row in sorted(new,key=lambda x:x["relation_id"]):
            if len(synthetic)>=max_comp: break
            synthetic[row["relation_id"]]=row
        added=sorted(set(synthetic)-before); quiet=quiet+1 if not added else 0
        receipts.append({"cycle":cyc,"broadcast_object_count":len(pairs)+len(hypers)+len(synthetic),"new_composite_relation_ids":added,"new_object_count":len(added),"quiet":not added})
        if quiet>=required_quiet: break
    out=AnalysisResult(list(analysis.issues),list(analysis.candidates)+consensus,list(analysis.relations)+[synthetic[k] for k in sorted(synthetic)])
    # deterministic de-dup candidates by id and relations by id
    out.candidates=list({c.candidate_id:c for c in out.candidates}.values())
    out.relations=list({str(r["relation_id"]):r for r in out.relations}.values())
    cert={"contract":CONTRACT,"mode_i":{"snapshot_actor_count":len(packets),"packets":packets,"independence_barrier":True,"mode_ii_visible_during_mode_i":False},
          "mode_ii":{"pairwise_objects":pairs,"active_pair_count":sum(1 for p in pairs if p["active"]),"hyperobjects":hypers,"hyperobject_count":len(hypers),
                     "synthetic_composite_relations":[synthetic[k] for k in sorted(synthetic)],"composite_relation_count":len(synthetic),"cycle_receipts":receipts,
                     "fixed_point_attained":quiet>=required_quiet,"quiet_streak":quiet,"required_quiet_cycles":required_quiet,
                     "rebroadcast_policy":"CHANGED_OBJECTS_WAKE_DEPENDENT_RELATION_ADAPTERS; NO_COLOR_STATUS_DOMAIN_FILTER"},
          "consensus_candidate_count":len(consensus)}
    cert["federation_digest"]=digest(cert)
    return out,cert


def _candidate_exact_return(root:Any,c:Candidate)->bool:
    trial=deepcopy(root); ok,inv=apply_patch(trial,candidate_patch(c))
    if not ok or inv is None: return False
    ok2,_=apply_patch(trial,inv)
    return bool(ok2 and digest(trial)==digest(root))


def compile_q_descent(root:Any, analysis:AnalysisResult, federation_cert:dict[str,Any])->dict[str,Any]:
    ir=compile_typed_constraint_ir(root,analysis)
    cmap={c.candidate_id:c for c in analysis.candidates}
    conflicts=[h for h in (federation_cert.get("mode_ii") or {}).get("hyperobjects",[]) if h.get("hyperobject_kind")=="CANDIDATE_CONFLICT"]
    rows=[]
    sev={"error":10,"warning":3,"info":1}
    for t in ir.get("terminal_registry",[]):
        path=str(t.get("path") or "")
        cands=[cmap[cid] for cid in t.get("candidate_ids",[]) if cid in cmap]
        return_ok=any(_candidate_exact_return(root,c) for c in cands)
        q_answer=sev.get(str(t.get("severity")),1)
        q_boundary=sum(1 for h in conflicts if h.get("path")==path)
        q_return=0 if return_ok else 1
        rows.append({"terminal_id":t["terminal_id"],"path":path,"analyzer":t.get("analyzer"),"code":t.get("code"),
                     "q_answer":q_answer,"q_boundary":q_boundary,"q_return":q_return,
                     "candidate_count":len(cands),"exact_return_route":return_ok,
                     "minimal_missing_witness":t.get("minimal_missing_witness")})
    global_q={"q_answer":sum(r["q_answer"] for r in rows),"q_boundary":sum(r["q_boundary"] for r in rows),"q_return":sum(r["q_return"] for r in rows)}
    global_q["lexicographic_vector"]=[global_q["q_answer"],global_q["q_boundary"],global_q["q_return"]]
    return {"contract":Q_CONTRACT,"terminal_count":len(rows),"terminals":rows,"global_q":global_q,
            "rule":"SOVEREIGN_CREDIT_ONLY_AFTER_REBUILD_AND_STRICT_LEXICOGRAPHIC_Q_DESCENT"}


def federate_analysis(root:Any, analysis:AnalysisResult, config)->tuple[AnalysisResult,dict[str,Any],dict[str,Any]]:
    if not bool(getattr(config,"enable_federation",True)):
        empty={"contract":CONTRACT,"enabled":False,"mode_i":{"snapshot_actor_count":0,"packets":[]},"mode_ii":{"fixed_point_attained":True,"pairwise_objects":[],"hyperobjects":[],"synthetic_composite_relations":[],"cycle_receipts":[]}}
        return analysis,empty,compile_q_descent(root,analysis,empty)
    fed,cert=federation_fixed_point(analysis,config)
    return fed,cert,compile_q_descent(root,fed,cert)


def q_compare(before:dict[str,Any],after:dict[str,Any])->dict[str,Any]:
    a=list((before.get("global_q") or {}).get("lexicographic_vector") or [0,0,0]); b=list((after.get("global_q") or {}).get("lexicographic_vector") or [0,0,0])
    return {"before":a,"after":b,"strict_descent":tuple(b)<tuple(a),"equal":tuple(b)==tuple(a),"sovereign_credit":bool(tuple(b)<tuple(a))}


def compile_stream_federation(relations:list[dict[str,Any]], issue_samples:list[dict[str,Any]], config)->tuple[dict[str,Any],dict[str,Any]]:
    """Bounded federation view for streaming knowledge.

    Streaming has no sovereign in-memory record set at report time, so MODE I packets are
    built from retained exact relation knowledge only.  No candidate or terminal value is
    invented from sampled issues.
    """
    a=AnalysisResult([],[],list(relations))
    _,cert=federation_fixed_point(a,config)
    q_answer=sum({"error":10,"warning":3,"info":1}.get(str(x.get("severity","warning")),3) for x in issue_samples)
    q_return=sum(1 for x in issue_samples if not bool(x.get("repairable")))
    q={"contract":Q_CONTRACT,"materialization_scope":"BOUNDED_STREAM","terminal_count":len(issue_samples),
       "global_q":{"q_answer":q_answer,"q_boundary":0,"q_return":q_return,"lexicographic_vector":[q_answer,0,q_return]},
       "sampled_only":True,"unmaterialized_terminals_not_treated_as_absent":True}
    return cert,q
