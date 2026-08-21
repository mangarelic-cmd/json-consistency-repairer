from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from fractions import Fraction
from itertools import combinations, product
from typing import Any, Callable
import json

from .models import AnalysisResult, Candidate, canonical_bytes
from .tree import decode_pointer
from .jsonpatch_exact import apply_candidate
from .primary_factorization import factorize_options
from .repair_algebra import compile_repair_path_algebra, candidate_set_admissibility
from .symmetry import compile_symmetry_obstruction


@dataclass(frozen=True)
class PatchOption:
    path: str
    candidate: Candidate
    candidate_ids: tuple[str, ...]
    families: tuple[str, ...]
    evidence: tuple[str, ...]


@dataclass
class MinimalTransferDecision:
    status: str
    patches: list[Candidate]
    certificate: dict[str, Any]
    parallel_routes: list[list[Candidate]] = field(default_factory=list)


def _jkey(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _parent_scope(path: str) -> str:
    toks = decode_pointer(path)
    if not toks:
        return ""
    if len(toks) == 1:
        return ""
    # A JSON object/array record is the natural local interaction carrier.
    out=[]
    for t in toks[:-1]:
        out.append(str(t).replace("~", "~0").replace("/", "~1"))
    return "/" + "/".join(out)


def _cluster_public_scope(options:list[PatchOption]) -> str:
    parents=[]
    for p in options:
        c=p.candidate
        if c.operation=="plan":
            steps=(c.metadata or {}).get("steps") or []
            paths=[str(x.get("path", "")) for x in steps if isinstance(x,dict)]
            pp=_parent_scope(paths[0]) if paths else ""
        else:
            pp=_parent_scope(c.path)
        parents.append(pp)
    if not parents: return ""
    if len(set(parents))==1: return parents[0]
    toks=[decode_pointer(x) for x in parents]
    common=[]
    for vals in zip(*toks):
        if len(set(vals))!=1: break
        common.append(vals[0])
    if not common: return ""
    return "/"+"/".join(str(t).replace("~","~0").replace("/","~1") for t in common)


def _apply(root: Any, c: Candidate) -> bool:
    return apply_candidate(root,c)


def _group_options(candidates: list[Candidate], require_independent_evidence: int) -> tuple[list[PatchOption], list[dict[str,Any]]]:
    grouped: dict[tuple[str,str], list[Candidate]]={}
    for c in candidates:
        grouped.setdefault((c.operation,c.path,str((c.metadata or {}).get('from_path','')),_jkey(c.new_value)),[]).append(c)
    options=[]; rejected=[]
    for (_,path,_,_), group in sorted(grouped.items(), key=lambda kv:(kv[0][1],kv[0][0],kv[0][2],kv[0][3])):
        fams=tuple(sorted({c.analyzer for c in group}))
        evidence=tuple(sorted({e for c in group for e in c.evidence}))
        representative=max(group,key=lambda c:(c.confidence,-c.cost,c.candidate_id))
        if representative.metadata.get("requires_cross_family") and len(fams)<2:
            rejected.append({"candidate_ids":sorted(c.candidate_id for c in group),"path":path,"reason":"missing_direction_anchor_cross_family"})
            continue
        if len(fams)<require_independent_evidence and len(evidence)<require_independent_evidence:
            rejected.append({"candidate_ids":sorted(c.candidate_id for c in group),"path":path,"reason":"insufficient_independent_evidence"})
            continue
        options.append(PatchOption(path,representative,tuple(sorted(c.candidate_id for c in group)),fams,evidence))
    return options,rejected


def _metric(patches: tuple[PatchOption,...]) -> tuple[Fraction,int,int,int]:
    # Exact structural displacement. Fraction keeps the contract exact if future candidate costs become rational.
    cost=sum((Fraction(str(p.candidate.cost)) for p in patches),Fraction(0,1))
    paths=len({p.path for p in patches})
    value_bytes=sum(len(canonical_bytes(p.candidate.new_value)) for p in patches)
    depth=sum(len(decode_pointer(p.path)) for p in patches)
    return cost,paths,value_bytes,depth


def _metric_public(m: tuple[Fraction,int,int,int]) -> dict[str,Any]:
    return {
        "cost":{"numerator":m[0].numerator,"denominator":m[0].denominator},
        "changed_paths":m[1],"canonical_new_value_bytes":m[2],"path_depth_sum":m[3],
    }


def _objective(analysis: AnalysisResult, score_fn: Callable[[list[Any]],int], baseline_signatures:set[Any] | None=None) -> tuple[int,int,int,int]:
    hard=sum(1 for i in analysis.issues if i.severity=="error")
    surviving=(sum(1 for i in analysis.issues if i.signature() in baseline_signatures) if baseline_signatures is not None else len(analysis.issues))
    # PASS041 / SC sovereign-terminal correction: a legal move that closes an
    # already materialized terminal must not be rejected merely because the
    # improved evidence exposes *new* subordinate terminals.  Compare the same
    # frozen terminal first; only then compare the newly visible diagnostic
    # surface.  This fixes the 3/40 non-monotonic benchmark without hiding any
    # newly discovered issue.
    return hard,surviving,score_fn(analysis.issues),sum(1 for i in analysis.issues if i.repairable)


def _compatible(parts: tuple[PatchOption,...]) -> bool:
    seen={}
    for p in parts:
        k=p.path; v=_jkey(p.candidate.new_value)
        if k in seen and seen[k]!=v: return False
        seen[k]=v
    return True


def _evaluate_subset(root:Any, subset:tuple[PatchOption,...], analyze_fn:Callable[[Any],AnalysisResult], score_fn, baseline_signatures:set[Any]) -> dict[str,Any] | None:
    # PASS034: an unordered minimal-transfer subset must be a confluent finite action set.
    # Ordered multi-step semantics belong inside one atomic `plan` candidate or a PASS026 RETURN_PROOF route.
    algebra_guard=candidate_set_admissibility(root,[p.candidate for p in subset])
    if not algebra_guard.get('admissible'):
        return None
    trial=deepcopy(root)
    for p in subset:
        if not _apply(trial,p.candidate):
            return None
    after=analyze_fn(trial)
    return {"trial":trial,"analysis":after,"objective":_objective(after,score_fn,baseline_signatures),"metric":_metric(subset),"subset":subset}


def _solve_cluster(root:Any, options:list[PatchOption], baseline_obj:tuple[int,int,int,int], baseline_signatures:set[Any], *, analyze_fn, score_fn, max_patch_size:int, max_exact_options:int) -> dict[str,Any]:
    # Exact within the declared finite frontier. If it is too large, abstain rather than claim minimality.
    if len(options)>max_exact_options:
        return {"status":"FRONTIER_TOO_LARGE","option_count":len(options),"max_exact_options":max_exact_options,"winner":None,"ties":[]}
    evaluated=[]
    max_k=min(max_patch_size,len({p.path for p in options}),len(options))
    for k in range(1,max_k+1):
        for subset in combinations(options,k):
            if not _compatible(subset): continue
            e=_evaluate_subset(root,subset,analyze_fn,score_fn,baseline_signatures)
            if e is None: continue
            if e["objective"] < baseline_obj:
                evaluated.append(e)
    if not evaluated:
        return {"status":"NO_IMPROVING_TRANSFER","option_count":len(options),"evaluated":0,"winner":None,"ties":[]}
    best_obj=min(e["objective"] for e in evaluated)
    best_obj_rows=[e for e in evaluated if e["objective"]==best_obj]
    best_metric=min(e["metric"] for e in best_obj_rows)
    finalists=[e for e in best_obj_rows if e["metric"]==best_metric]
    # Distinct patch identities with same exact objective and displacement are a true tie.
    identities={tuple((p.candidate.operation,p.path,str((p.candidate.metadata or {}).get('from_path','')),_jkey(p.candidate.new_value)) for p in e["subset"]) for e in finalists}
    if len(identities)>1:
        return {"status":"AMBIGUOUS_EXACT_MINIMUM","option_count":len(options),"evaluated":len(evaluated),
                "best_objective":best_obj,"best_metric":best_metric,"winner":None,"ties":finalists}
    return {"status":"UNIQUE_EXACT_MINIMUM","option_count":len(options),"evaluated":len(evaluated),
            "best_objective":best_obj,"best_metric":best_metric,"winner":finalists[0],"ties":[]}


def solve_minimal_transfer(root:Any, analysis:AnalysisResult, *, analyze_fn:Callable[[Any],AnalysisResult], score_fn:Callable[[list[Any]],int],
                           require_independent_evidence:int=1, max_patch_size:int=4, max_exact_options:int=8,
                           enable_parallel_routes:bool=True, max_parallel_routes:int=16,
                           semantic_quotient_rules:tuple[dict[str,Any],...]=(), enable_symmetry_obstruction:bool=True) -> MinimalTransferDecision:
    baseline_signatures={i.signature() for i in analysis.issues}
    baseline_obj=_objective(analysis,score_fn,baseline_signatures)
    options,rejected=_group_options(analysis.candidates,require_independent_evidence)
    repair_algebra=compile_repair_path_algebra(root,[p.candidate for p in options],max_actions=max(16,max_exact_options*2))
    factorization_clusters,factorization_cert=factorize_options(root,analysis,options)
    if not options:
        cert={"solver_contract":"json-consistency-repair.minimal-transfer.v1","status":"NO_ADMISSIBLE_CANDIDATES","baseline_objective":list(baseline_obj),
              "metric_order":["cost","changed_paths","canonical_new_value_bytes","path_depth_sum"],"rejected_options":rejected,"clusters":[],
              "partition_rule":"primary_relation_connected_components","primary_factorization":factorization_cert,"repair_path_algebra":repair_algebra,
              "symmetry_obstruction":compile_symmetry_obstruction(root,[],quotient_rules=semantic_quotient_rules)}
        return MinimalTransferDecision("NO_ADMISSIBLE_CANDIDATES",[],cert)

    clusters=factorization_clusters
    cluster_reports=[]; chosen=[]; ambiguous=False; overflow=False; ambiguous_groups=[]
    for primary_block_id in sorted(clusters):
        block_options=clusters[primary_block_id]
        res=_solve_cluster(root,block_options,baseline_obj,baseline_signatures,analyze_fn=analyze_fn,score_fn=score_fn,max_patch_size=max_patch_size,max_exact_options=max_exact_options)
        pub={"scope":_cluster_public_scope(block_options),"primary_block_id":primary_block_id,"status":res["status"],"option_count":res.get("option_count",0),"evaluated_improving_subsets":res.get("evaluated",0)}
        if res.get("best_objective") is not None: pub["best_objective"]=list(res["best_objective"])
        if res.get("best_metric") is not None: pub["best_metric"]=_metric_public(res["best_metric"])
        if res["status"]=="UNIQUE_EXACT_MINIMUM":
            w=res["winner"]
            pub["patches"]=[{"path":p.path,"candidate_id":p.candidate.candidate_id,"candidate_ids":list(p.candidate_ids),"families":list(p.families)} for p in w["subset"]]
            chosen.extend(w["subset"])
        elif res["status"]=="AMBIGUOUS_EXACT_MINIMUM":
            ambiguous=True
            ambiguous_groups.append([tuple(e["subset"]) for e in res["ties"]])
            pub["tie_count"]=len(res["ties"])
            pub["ties"]=[[{"path":p.path,"candidate_id":p.candidate.candidate_id} for p in e["subset"]] for e in res["ties"][:8]]
        elif res["status"]=="FRONTIER_TOO_LARGE": overflow=True
        cluster_reports.append(pub)

    # Deduplicate cluster winners and validate the union against the sovereign object.
    uniq={}
    for p in chosen: uniq[(p.candidate.operation,p.path,str((p.candidate.metadata or {}).get('from_path','')),_jkey(p.candidate.new_value))]=p
    union=tuple(uniq[k] for k in sorted(uniq))
    final_status="NO_IMPROVING_TRANSFER"; patches=[]; union_obj=None; union_metric=None
    if union:
        ev=_evaluate_subset(root,union,analyze_fn,score_fn,baseline_signatures)
        if ev is not None and ev["objective"] < baseline_obj:
            union_obj=ev["objective"]; union_metric=ev["metric"]
            patches=[p.candidate for p in union]
            final_status="UNIQUE_EXACT_MINIMUM_PARTITIONED" if len(clusters)>1 else "UNIQUE_EXACT_MINIMUM"
        else:
            final_status="PARTITION_UNION_NOT_GLOBALLY_ADMISSIBLE"
            patches=[]
    parallel_routes=[]
    parallel_frontier_overflow=False
    if ambiguous:
        # Freeze the sovereign snapshot and carry every exact tied route forward.  Unique
        # cluster winners are common prefixes in every branch; no partial MAIN mutation is
        # allowed before RETURN_PROOF.
        base=tuple(uniq[k] for k in sorted(uniq))
        if enable_parallel_routes:
            theoretical=1
            for g in ambiguous_groups: theoretical*=max(1,len(g))
            if theoretical>max_parallel_routes:
                parallel_frontier_overflow=True
                final_status="PARALLEL_ROUTE_FRONTIER_TOO_LARGE"; patches=[]
            else:
                seen_routes={}
                for combo in product(*ambiguous_groups):
                    parts=list(base)
                    for subset in combo: parts.extend(subset)
                    dd={}
                    for p in parts:
                        dd[(p.candidate.operation,p.path,str((p.candidate.metadata or {}).get('from_path','')),_jkey(p.candidate.new_value))]=p
                    route=tuple(dd[k] for k in sorted(dd))
                    if not _compatible(route): continue
                    ident=tuple((p.candidate.operation,p.path,str((p.candidate.metadata or {}).get('from_path','')),_jkey(p.candidate.new_value)) for p in route)
                    seen_routes[ident]=route
                parallel_routes=[[p.candidate for p in seen_routes[k]] for k in sorted(seen_routes)]
                if not parallel_routes:
                    final_status="AMBIGUOUS_EXACT_MINIMUM"; patches=[]
                else:
                    # Preserve the public PASS011 ambiguity status for compatibility while
                    # materializing every tied route for the PASS026 RETURN_PROOF layer.
                    final_status="AMBIGUOUS_EXACT_MINIMUM"; patches=[]
        else:
            final_status="AMBIGUOUS_EXACT_MINIMUM"; patches=[]
    if overflow and not patches and not ambiguous: final_status="FRONTIER_TOO_LARGE"

    symmetry_cert=compile_symmetry_obstruction(root,parallel_routes,quotient_rules=semantic_quotient_rules)
    if enable_symmetry_obstruction and symmetry_cert.get("status")=="SYMMETRY_BLOCKED_REPAIR":
        # A detected automorphism is a no-go certificate, not a hidden tiebreak.  Automatic
        # symmetry inference may only remove unsafe routes; only an explicit quotient declaration
        # is allowed to identify distinct concrete representatives as semantically equivalent.
        parallel_routes=[]
        patches=[]
        final_status="SYMMETRY_BLOCKED_REPAIR"

    cert={"solver_contract":"json-consistency-repair.minimal-transfer.v1","status":final_status,"baseline_objective":list(baseline_obj),
          "objective_order":["hard_errors","surviving_preexisting_terminals","severity_score","repairable_terminals"],
          "metric_order":["cost","changed_paths","canonical_new_value_bytes","path_depth_sum"],
          "exact_metric":True,"max_patch_size":max_patch_size,"max_exact_options_per_cluster":max_exact_options,
          "partition_rule":"primary_relation_connected_components","admissible_option_count":len(options),"rejected_options":rejected,"clusters":cluster_reports,
          "primary_factorization":factorization_cert,"repair_path_algebra":repair_algebra,"symmetry_obstruction":symmetry_cert,
          "parallel_route_contract":"json-consistency-repair.parallel-exact-routes.v1",
          "parallel_route_count":len(parallel_routes),"max_parallel_routes":max_parallel_routes,
          "parallel_route_state":"MATERIALIZED_FOR_RETURN_PROOF" if parallel_routes else "NONE",
          "parallel_route_frontier_overflow":parallel_frontier_overflow}
    if union_obj is not None: cert["union_objective"]=list(union_obj)
    if union_metric is not None: cert["union_metric"]=_metric_public(union_metric)
    cert["selected_patch_count"]=len(patches)
    cert["selected_candidate_ids"]=[c.candidate_id for c in patches]
    return MinimalTransferDecision(final_status,patches,cert,parallel_routes)
