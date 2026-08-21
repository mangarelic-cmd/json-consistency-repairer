from __future__ import annotations
from dataclasses import dataclass, field
from copy import deepcopy
from pathlib import Path
from typing import Any
import json, hashlib
from .models import digest, Candidate, AnalysisResult
from .tree import decode_pointer
from .analyzers import analyze_all
from .io import dump_file, loads_strict, conservative_syntax_repair
from .security import SecurityLimits, enforce_file_size, validate_json_value
from .provenance import report_identity, package_code_sha256
from .constraint_ir import compile_typed_constraint_ir
from .minimal_transfer import solve_minimal_transfer
from .fixedpoint import relation_snapshot, relation_delta, frontier_signature, update_lifecycle, audit_patch_order
from .provenance_chain import build_provenance_chain
from .jsonpatch_exact import apply_candidate, replay_with_inverses
from .causal_cone import prepare_causal_analysis, apply_authority_firewall, compile_double_cone, candidate_authority
from .system_graph import system_summary
from .moments import moment_summary
from .federation import federate_analysis, q_compare
from .multisource import analyze_multisource, multisource_summary
from .boundary import apply_boundary_firewall, boundary_summary
from .parallel_routes import resolve_parallel_routes
from .primary_factorization import compare_factorizations
from .proof_graph import compile_proof_graph, compare_proof_graphs
from .materialization import materialize_missing_witnesses, materialization_summary
from .robust_envelope import apply_robust_envelope_firewall, robust_envelope_summary
from .rectification_packet import compile_rectification_packet, seal_rectification_packet
from .semantic_provenance import apply_semantic_claim_provenance_firewall, semantic_claim_summary, project_verified_semantic_config
from .expression_ir import expression_ir_summary
from .symmetry import symmetry_summary, semantic_quotient_digest
from .controllability import apply_controllability_firewall, compile_control_plan, controllability_summary
from .relation_falsifier import apply_relation_falsification_firewall, relation_falsification_summary
from .persistent_open import (compile_open_obligation_registry, compile_incremental_recompute,
    compile_incremental_equivalence, save_open_obligation_registry)
from .horizon import compile_horizon_surface
from .information_bounds import compile_information_surface

SEVERITY={"error":10,"warning":3,"info":1}

@dataclass
class RepairConfig:
    max_cycles:int=8
    stable_cycles_required:int=2
    min_support:int=4
    min_group_support:int=3
    min_scope_support:int=3
    min_scope_group_support:int=2
    type_confidence:float=0.90
    relation_confidence:float=0.95
    scoped_relation_confidence:float=0.95
    arithmetic_confidence:float=0.95
    # PASS041 / benchmark-directed SC correction.  Ordinary confidence
    # thresholds stay unchanged.  This second route is only for sparse,
    # heterogeneous outliers and is allowed only while PASS037's active
    # relation falsifier is enabled.
    enable_sparse_outlier_recovery:bool=True
    sparse_outlier_confidence_floor:float=0.60
    sparse_outlier_min_mode_support:int=3
    sparse_outlier_min_mode_margin:int=2
    sparse_outlier_max_alternative_count:int=1
    arithmetic_direction_confidence:float=0.90
    temporal_confidence:float=0.95
    sequential_confidence:float=0.75
    max_numeric_fields:int=12
    max_relation_fields:int=12
    required_key_confidence:float=0.95
    shape_confidence:float=0.80
    enum_confidence:float=0.90
    enum_max_values:int=16
    enum_min_value_support:int=2
    enum_normalization_confidence:float=0.75
    id_uniqueness_confidence:float=0.90
    reference_confidence:float=0.90
    require_independent_evidence:int=1
    max_global_patch_size:int=4
    max_global_exact_options_per_cluster:int=8
    enable_parallel_tie_routes:bool=True
    max_parallel_tie_routes:int=16
    enable_witness_materialization:bool=True
    logic_confidence:float=0.95
    logic_min_support:int=4
    logic_min_member_support:int=2
    logic_max_fields:int=8
    logic_max_group_size:int=4
    logic_rules:tuple[dict[str,Any],...]=()
    constraint_rules:tuple[dict[str,Any],...]=()
    record_carrier_mode:bool=False
    json_schema:dict[str,Any]|None=None
    schema_source:str|None=None
    system_rules:tuple[dict[str,Any],...]=()
    system_document:str|None=None
    moment_rules:tuple[dict[str,Any],...]=()
    moment_document:str|None=None
    auto_moment_discovery:bool=True
    moment_confidence:float=0.95
    moment_min_support:int=4
    moment_max_fields:int=8
    auto_graph_discovery:bool=True
    enable_federation:bool=True
    federation_max_cycles:int=4
    federation_quiet_cycles_required:int=2
    federation_max_pairwise_objects:int=256
    federation_max_hyperobjects:int=256
    federation_max_composites:int=128
    enable_multisource:bool=True
    source_context:tuple[dict[str,Any],...]=()
    source_manifest:dict[str,Any]|None=None
    source_min_support:int=4
    source_min_group_support:int=2
    source_max_fields:int=8
    logic_document:str|None=None
    conservation_confidence:float=0.95
    conservation_min_support:int=4
    conservation_min_distinct_aggregates:int=2
    conservation_direction_confidence:float=0.90
    conservation_max_child_fields:int=8
    conservation_max_item_fields:int=8
    conservation_max_balance_fields:int=8
    multiset_confidence:float=0.95
    multiset_min_support:int=4
    conservation_rules:tuple[dict[str,Any],...]=()
    conservation_document:str|None=None
    modal_min_support:int=4
    modal_min_regime_support:int=2
    modal_max_regimes:int=8
    modal_min_gain:float=0.10
    morphology_min_support:int=3
    robust_envelope_rules:tuple[dict[str,Any],...]=()
    enable_semantic_claim_provenance:bool=True
    schema_claim_provenance:dict[str,Any]|None=None
    enable_symmetry_obstruction:bool=True
    semantic_quotient_rules:tuple[dict[str,Any],...]=()
    enable_controllability:bool=True
    enable_relation_falsifier:bool=True
    falsifier_min_rows:int=4
    falsifier_max_relations:int=256
    falsifier_max_negative_controls:int=8
    enable_persistent_open_obligations:bool=True
    prior_open_obligation_registry:dict[str,Any]|None=None
    prior_proof_graph:dict[str,Any]|None=None
    incremental_change_tokens:tuple[str,...]=()
    open_obligation_store_path:str|None=None
    enable_horizon_naturality:bool=True
    prior_horizon_snapshot:dict[str,Any]|None=None
    horizon_change_tokens:tuple[str,...]=()
    horizon_boundary_witnesses:tuple[dict[str,Any],...]=()
    distribution_descriptor:dict[str,Any]|None=None
    horizon_manifest_limit:int=4096
    enable_information_bounds:bool=True
    blind_carrier_max_trials:int=64
    controllability_rules:tuple[dict[str,Any],...]=()
    require_explicit_mutation_permission:bool=False
    max_control_edits:int|None=None
    max_control_cost:int|None=None
    # Internal/public replay offsets: resources already consumed by the same logical control run.
    # Normal callers leave these at zero; cold replay carries them forward so a finite budget
    # cannot be reset merely by re-entering the certifier.
    control_budget_used_before_edits:int=0
    control_budget_used_before_cost:int=0
    strong_fixed_point_cycles_required:int=2
    enable_final_certification:bool=True
    dry_run:bool=False
    syntax_repair:bool=True
    # PASS041 SC hot-path bifurcation. ``full`` preserves the exhaustive engine.
    # ``fast`` performs one complete analyzer scan per pass, then deepens only on
    # directly actionable repair cones and never claims the full certification gate.
    execution_mode:str="full"
    fast_max_passes:int=2
    fast_max_edits:int=128
    fast_allow_multi_field_authoritative:bool=True
    # In fast mode, active falsification is deepened only for relations that can
    # authorize a concrete mutation. All analyzers still scan the full object.
    fast_falsify_action_relations_only:bool=True
    security_limits:SecurityLimits=field(default_factory=SecurityLimits)

@dataclass
class RepairResult:
    input_path:str|None
    output_path:str|None
    report_path:str|None
    final_status:str
    cycles:int
    committed_edits:int
    remaining_issues:int
    input_digest:str
    output_digest:str
    report:dict[str,Any]


def score(issues): return sum(SEVERITY.get(i.severity,1) for i in issues)


def _candidate_groups(cands:list[Candidate]):
    by={}
    for c in cands:
        key=(c.path,json.dumps(c.new_value,sort_keys=True,default=str,ensure_ascii=False))
        by.setdefault(key,[]).append(c)
    return by


def _apply(root,c:Candidate):
    return apply_candidate(root,c)


def _relation_key(rel:dict[str,Any]): return rel["relation_id"]


def _constraint_graph(relations:list[dict[str,Any]]):
    nodes={}; edges=[]
    for rel in relations:
        base=rel.get("array_path","")
        output=rel.get("output")
        out_field=output if output is not None else "__logic__"
        out_id=f"{base}#{out_field}"
        nodes[out_id]={"id":out_id,"array_path":base,"field":out_field}
        inputs=[]
        for field in rel.get("inputs",[]):
            nid=f"{base}#{field}"; nodes[nid]={"id":nid,"array_path":base,"field":field}; inputs.append(nid)
        edges.append({"relation_id":rel["relation_id"],"kind":rel["kind"],"inputs":inputs,"output":out_id,"confidence":rel.get("confidence"),"support":rel.get("support")})
    return {"nodes":sorted(nodes.values(),key=lambda x:x["id"]),"edges":sorted(edges,key=lambda x:x["relation_id"])}



def _issue_matches_candidate(issue, c:Candidate) -> bool:
    if issue.path!=c.path or issue.analyzer!=c.analyzer or not issue.repairable:
        return False
    im=issue.metadata or {}; cm=c.metadata or {}
    # Compare the smallest stable identity of the certified relation, not merely the JSON path.
    identities=(
        ("formula",),
        ("scope_field","scope_value","determinant","target"),
        ("determinant","target"),
        ("start","end","seconds"),
        ("field","step"),
        ("schema_key",),
        ("enum_field","domain_id"),
        ("reference_field","target_array_path","target_id_field"),
    )
    for keys in identities:
        if all(k in cm for k in keys):
            return all(im.get(k)==cm.get(k) for k in keys)
    return True


def _logic_summary(analysis):
    rels=[r for r in analysis.relations if str(r.get("kind","")).startswith("logic_") or r.get("kind")=="logic_exact"]
    systems=[r for r in rels if r.get("kind") in {"logic_rule_system","logic_rule_system_stream"}]
    return {
        "contract":"json-consistency-repair.logic-summary.v1",
        "relation_count":len(rels),
        "violation_count":sum(1 for i in analysis.issues if i.analyzer=="logic_exact"),
        "sat_rule_relations":sum(1 for r in rels if r.get("sat_status")=="SAT"),
        "sat_systems":sum(1 for r in systems if r.get("sat_status")=="SAT"),
        "unsat_systems":sum(1 for r in systems if r.get("sat_status")=="UNSAT"),
        "sat_certificates":[r.get("sat_certificate") for r in systems if r.get("sat_certificate")],
    }


def _conservation_summary(analysis):
    rels=[r for r in analysis.relations if "conservation" in str(r.get("kind","")) or str(r.get("kind","")) in {"aggregate_sum","aggregate_count","aggregate_sum_authoritative","aggregate_count_authoritative","balance_authoritative","multiset_balance_authoritative"}]
    return {
        "contract":"json-consistency-repair.conservation-summary.v1",
        "relation_count":len(rels),
        "aggregate_sum_relations":sum(1 for r in rels if r.get("kind") in {"aggregate_sum","aggregate_sum_authoritative"}),
        "aggregate_count_relations":sum(1 for r in rels if r.get("kind") in {"aggregate_count","aggregate_count_authoritative"}),
        "scalar_balance_relations":sum(1 for r in rels if r.get("kind") in {"scalar_conservation_balance","balance_authoritative"}),
        "multiset_relations":sum(1 for r in rels if r.get("kind") in {"multiset_conservation","multiset_balance_authoritative"}),
        "violation_count":sum(1 for i in analysis.issues if i.analyzer=="conservation"),
        "repairable_violation_count":sum(1 for i in analysis.issues if i.analyzer=="conservation" and i.repairable),
        "symmetric_unoriented_relations":sum(1 for r in rels if r.get("direction_source") in {"symmetric_conservation","symmetric_multiset"}),
    }

def _constraint_bridge_summary(analysis):
    rels=[r for r in analysis.relations if str(r.get("kind","")).startswith("constraint_dsl_") or r.get("kind") in {"linear_exact_system","authoritative_json_schema","authoritative_boundary_contract"}]
    return {
        "contract":"json-consistency-repair.constraint-bridge-summary.v1",
        "relation_count":len(rels),
        "dsl_relations":sum(1 for r in rels if str(r.get("kind","")).startswith("constraint_dsl_")),
        "linear_systems":sum(1 for r in rels if r.get("kind")=="linear_exact_system"),
        "schema_bridges":sum(1 for r in rels if r.get("kind")=="authoritative_json_schema"),
        "boundary_contract_relations":sum(1 for r in rels if r.get("kind")=="authoritative_boundary_contract"),
        "violation_count":sum(1 for i in analysis.issues if i.analyzer in {"constraint_dsl","linear_exact","schema_bridge"}),
        "repairable_violation_count":sum(1 for i in analysis.issues if i.analyzer in {"constraint_dsl","linear_exact","schema_bridge"} and i.repairable),
    }


def _fast_value_key(v:Any)->str:
    return json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(",",":"),default=str)


def _pointer_prefix(a:str,b:str)->bool:
    """True when one non-equal JSON pointer is an ancestor of the other."""
    ta=decode_pointer(a); tb=decode_pointer(b)
    if len(ta)==len(tb): return False
    short,long=(ta,tb) if len(ta)<len(tb) else (tb,ta)
    return list(long[:len(short)])==list(short)


def _fast_select_local_candidates(analysis:AnalysisResult, config:RepairConfig):
    """Select only locally unique, non-overlapping repairs from a full scan.

    The fast path intentionally does not solve the complete global transfer problem.
    It scans every analyzer, but applies only repair cones whose target value is unique
    after all firewalls. Multi-field record clusters are deferred unless every member
    is authoritative. This is the SC minimal displacement: observe globally, act only
    where the residual already has a uniquely supported local move.
    """
    by_path={}
    for c in analysis.candidates:
        by_path.setdefault(c.path,[]).append(c)
    chosen=[]; skipped=[]
    for path,group in sorted(by_path.items()):
        values={_fast_value_key(c.new_value) for c in group}
        if len(values)!=1:
            skipped.append({"path":path,"reason":"FAST_AMBIGUOUS_TARGET","candidate_ids":sorted(c.candidate_id for c in group)})
            continue
        viable=[c for c in group if len(set(c.evidence or ()))>=max(0,int(config.require_independent_evidence))]
        if not viable:
            skipped.append({"path":path,"reason":"FAST_EVIDENCE_GATE","candidate_ids":sorted(c.candidate_id for c in group)})
            continue
        best=sorted(viable,key=lambda c:(-candidate_authority(c),-float(c.confidence),int(c.cost),c.candidate_id))[0]
        chosen.append(best)

    # If several distinct fields in the same record want mutation, that is exactly
    # where cause/symptom competition can arise. Fast mode scans and reports it but
    # defers correction unless every move is authoritative.
    carriers={}
    for c in chosen:
        toks=decode_pointer(c.path); carrier=tuple(toks[:-1]) if toks else tuple()
        carriers.setdefault(carrier,[]).append(c)
    allowed=[]
    for carrier,group in carriers.items():
        paths={c.path for c in group}
        if len(paths)<=1:
            allowed.extend(group); continue
        if config.fast_allow_multi_field_authoritative and all(candidate_authority(c)>=3 for c in group):
            allowed.extend(group); continue
        # Cheap directional cause witness: exact arithmetic/temporal analyzers may
        # certify one output direction from stable structure. If precisely one path
        # in the carrier has that witness, deepen only that path and defer symptoms.
        directed_paths={c.path for c in group if bool((c.metadata or {}).get("direction_certified"))}
        if len(directed_paths)==1:
            keep_path=next(iter(directed_paths))
            for c in group:
                if c.path==keep_path: allowed.append(c)
                else: skipped.append({"path":c.path,"reason":"FAST_DIRECTIONAL_SYMPTOM_DEFERRED","candidate_id":c.candidate_id,"carrier":list(carrier),"selected_cause_path":keep_path})
            continue
        for c in group:
            skipped.append({"path":c.path,"reason":"FAST_COMPLEX_CARRIER_DEFERRED","candidate_id":c.candidate_id,"carrier":list(carrier)})

    # Ancestor/descendant patches are order-sensitive by construction. Defer both.
    blocked=set()
    for i,a in enumerate(allowed):
        for b in allowed[i+1:]:
            if _pointer_prefix(a.path,b.path):
                blocked.add(a.candidate_id); blocked.add(b.candidate_id)
    final=[]
    for c in allowed:
        if c.candidate_id in blocked:
            skipped.append({"path":c.path,"reason":"FAST_OVERLAPPING_PATCH_DEFERRED","candidate_id":c.candidate_id})
        else: final.append(c)
    final=sorted(final,key=lambda c:(c.path,c.candidate_id))[:max(0,int(config.fast_max_edits))]
    if len(allowed)>len(final):
        skipped.append({"reason":"FAST_EDIT_BUDGET","selected":len(final),"available":len(allowed),"limit":int(config.fast_max_edits)})
    return final,skipped


def _fast_analyze(root:Any, requested_config:RepairConfig, analysis_config:RepairConfig, semantic_preflight:dict[str,Any]):
    raw=analyze_all(root,analysis_config)
    # Multi-source is scanned only when a source surface actually exists. With no
    # source carrier there is nothing to evaluate and calling the branch is pure cost.
    ms_cert={"contract":"json-consistency-repair.multisource-assimilation.v1","active":False,"reason":"NO_SOURCE_SURFACE"}
    if bool(getattr(analysis_config,"enable_multisource",True)) and (getattr(analysis_config,"source_context",()) or getattr(analysis_config,"source_manifest",None)):
        ms,ms_cert=analyze_multisource(root,analysis_config)
        raw.issues.extend(ms.issues); raw.candidates.extend(ms.candidates); raw.relations.extend(ms.relations)
    raw.candidates=list({c.candidate_id:c for c in raw.candidates}.values())
    raw.relations=list({str(r.get("relation_id")):r for r in raw.relations if r.get("relation_id")}.values())
    raw,boundary_cert=apply_boundary_firewall(root,raw,analysis_config)
    raw,robust_cert=apply_robust_envelope_firewall(root,raw,analysis_config)
    raw,semantic_cert=apply_semantic_claim_provenance_firewall(root,raw,requested_config,preanalysis=semantic_preflight)
    raw,falsifier_cert=apply_relation_falsification_firewall(root,raw,analysis_config)
    raw,control_cert=apply_controllability_firewall(root,raw,analysis_config)
    filtered,authority_cert=apply_authority_firewall(raw)
    return filtered,{"multisource":ms_cert,"boundary":boundary_cert,"robust":robust_cert,"semantic":semantic_cert,
                     "falsifier":falsifier_cert,"controllability":control_cert,"authority":authority_cert}


def _repair_object_fast(value:Any, config:RepairConfig):
    analysis_config,semantic_preflight=project_verified_semantic_config(config)
    safety_stats=validate_json_value(value,config.security_limits)
    original=deepcopy(value); current=deepcopy(value); initial_digest=digest(original)
    committed=[]; passes=[]; scan_cert=None; final=None; final_cert=None; terminal_scanned=False
    max_passes=max(1,int(config.fast_max_passes))
    for idx in range(1,max_passes+1):
        before,scan_cert=_fast_analyze(current,config,analysis_config,semantic_preflight)
        selected,skipped=_fast_select_local_candidates(before,config)
        used_cost=sum(max(0,int(x.get("cost",1))) for x in committed if isinstance(x,dict))
        selected,control_plan=compile_control_plan(current,selected,analysis_config,preserve_order=False,
            used_edits=max(0,int(config.control_budget_used_before_edits))+len(committed),
            used_cost=max(0,int(config.control_budget_used_before_cost))+used_cost)
        trial=deepcopy(current); applied=[]; failed=[]
        for c in selected:
            if _apply(trial,c): applied.append(c)
            else: failed.append({"candidate_id":c.candidate_id,"path":c.path,"reason":"FAST_PRECONDITION_FAILED"})
        if applied and not config.dry_run:
            current=trial
            committed.extend(c.to_dict() for c in applied)
        elif applied and config.dry_run:
            # Dry-run keeps the published object unchanged but subsequent scan evaluates
            # the hypothetical terminal so the caller sees what the fast path would do.
            current=trial
            committed.extend(c.to_dict() for c in applied)
        passes.append({"pass":idx,"issue_count_before":len(before.issues),"candidate_count_before":len(before.candidates),
                       "selected_count":len(selected),"applied_count":len(applied),"skipped":skipped+failed,
                       "control_plan":control_plan})
        if not applied:
            final=before; final_cert=scan_cert; terminal_scanned=True
            break
    if not terminal_scanned:
        final,final_cert=_fast_analyze(current,config,analysis_config,semantic_preflight)
    # Fast mode is an explicitly weaker assurance profile. It never upgrades itself
    # to the exhaustive proof/cold-replay certification gate.
    status="PASS" if not final.issues else "STABLE_WITH_REPORTED_ISSUES"
    externally_committed=[] if config.dry_run else committed
    identity=report_identity(status)
    identity["report_contract"]={**identity["report_contract"],"name":"json-consistency-repair.fast-scan-report.v1",
                                 "assurance":"FAST_SCAN_ONLY","full_certification":False}
    report={**identity,
            "execution_profile":{"mode":"fast","scan_scope":"ALL_ANALYZERS","action_scope":"UNIQUE_LOCAL_REPAIR_CONES_ONLY",
                                 "full_global_optimization":False,"full_certification":False,"max_passes":max_passes,
                                 "escalate_with":"execution_mode=full"},
            "input_digest":initial_digest,"output_digest":digest(current),"security":{"limits":config.security_limits.to_dict(),"input_validation":safety_stats},
            "cycles":passes,"committed_edits":externally_committed,"proposed_edits":committed if config.dry_run else [],
            "would_commit_edits":len(committed),"remaining_issues":[i.to_dict() for i in final.issues],
            "relations":list(final.relations),"fast_scan_certificate":final_cert,
            "dry_run":bool(config.dry_run),"publication_performed":False if config.dry_run else None,
            "strong_stable":False,"certification_gate":"FAST_SCAN_ONLY",
            "final_certification":{"status":"NOT_RUN_FAST_MODE","ok":False},
            "replay":{"forward_digest":digest(current)}}
    # Preserve exact forward/inverse evidence for the edits fast mode did make; this is
    # cheap and prevents the speed profile from becoming an unverifiable mutation API.
    patch_rows=[{"operation":c.get("operation","replace"),"path":c.get("path",""),"old_value":deepcopy(c.get("old_value")),
                 "new_value":deepcopy(c.get("new_value")),"metadata":deepcopy(c.get("metadata") or {})} for c in committed]
    replay_ok,replayed,inverse_patches=replay_with_inverses(original,patch_rows)
    report["replay"].update({"forward_replays_output":bool(replay_ok and digest(replayed)==digest(current)),"exact_inverse_patches":inverse_patches})
    public_current=original if config.dry_run else current
    return public_current,RepairResult(None,None,None,status,len(passes),len(externally_committed),len(final.issues),initial_digest,digest(public_current),report)


def repair_object(value:Any, config:RepairConfig|None=None):
    config=config or RepairConfig()
    mode=str(getattr(config,"execution_mode","full") or "full").lower()
    if mode not in {"full","fast"}:
        raise ValueError("execution_mode must be 'full' or 'fast'")
    if mode=="fast":
        return _repair_object_fast(value,config)
    analysis_config, semantic_preflight = project_verified_semantic_config(config)
    safety_stats=validate_json_value(value, config.security_limits)
    original=deepcopy(value); current=deepcopy(value)
    initial_digest=digest(original)
    cycles=[]; committed=[]; stable=0; strong_streak=0
    knowledge={"relations":{},"newly_certified":[],"lifecycle":{}}
    previous_snapshot=None; previous_frontier=None
    visited={initial_digest}; any_oscillation=False
    required_strong=max(1,int(config.strong_fixed_point_cycles_required))

    causal_cycles=[]
    federation_cycles=[]
    q_descent_cycles=[]
    multisource_cycles=[]
    boundary_firewall_cycles=[]
    parallel_route_cycles=[]
    primary_factorization_cycles=[]
    witness_materialization_cycles=[]
    robust_envelope_cycles=[]
    semantic_claim_cycles=[]
    repair_path_algebra_cycles=[]
    symmetry_cycles=[]
    controllability_firewall_cycles=[]
    relation_falsification_cycles=[]
    control_plan_cycles=[]
    previous_primary_factorization=None
    # PASS041: content-addressed memoization inside one repair run.  The analyzer
    # stack is deterministic for a fixed analysis_config, and the engine often
    # asks for the exact same sovereign state during causal dominance, minimal
    # transfer evaluation, replay preparation and quiet fixed-point cycles.
    # Reusing the immutable result removes redundant whole-tree analysis without
    # weakening any certifier.  Deep copies keep callers isolated.
    _raw_analysis_cache:dict[str,Any]={}
    def _raw_with_sources(x):
        cache_key=digest(x)
        cached=_raw_analysis_cache.get(cache_key)
        if cached is not None:
            return cached
        raw=analyze_all(x,analysis_config)
        ms,mscert=analyze_multisource(x,analysis_config)
        raw.issues.extend(ms.issues); raw.candidates.extend(ms.candidates); raw.relations.extend(ms.relations)
        # stable de-dup by public identities
        raw.candidates=list({c.candidate_id:c for c in raw.candidates}.values())
        raw.relations=list({str(r.get("relation_id")):r for r in raw.relations if r.get("relation_id")}.values())
        raw,boundary_cert=apply_boundary_firewall(x,raw,analysis_config)
        raw,robust_cert=apply_robust_envelope_firewall(x,raw,analysis_config)
        # Audit against the requested configuration, not the projected one, so every gated
        # attribution remains visible and independently certifiable.
        raw,semantic_cert=apply_semantic_claim_provenance_firewall(x,raw,config,preanalysis=semantic_preflight)
        raw,falsifier_cert=apply_relation_falsification_firewall(x,raw,analysis_config)
        raw,control_cert=apply_controllability_firewall(x,raw,analysis_config)
        result=(raw,mscert,boundary_cert,robust_cert,semantic_cert,falsifier_cert,control_cert)
        _raw_analysis_cache[cache_key]=result
        return result
    def _authority_analysis(x):
        raw,_,_,_,_,_,_=_raw_with_sources(x)
        return apply_authority_firewall(raw)[0]

    for cycle in range(1,config.max_cycles+1):
        raw_before,ms_before,boundary_before,robust_before,semantic_before,falsifier_before,control_before=_raw_with_sources(current)
        multisource_cycles.append({"cycle":cycle,"phase":"before",**ms_before})
        boundary_firewall_cycles.append({"cycle":cycle,"phase":"before",**boundary_before})
        robust_envelope_cycles.append({"cycle":cycle,"phase":"before","certificate":robust_before})
        semantic_claim_cycles.append({"cycle":cycle,"phase":"before","certificate":semantic_before})
        relation_falsification_cycles.append({"cycle":cycle,"phase":"before","certificate":falsifier_before})
        controllability_firewall_cycles.append({"cycle":cycle,"phase":"before","certificate":control_before})
        filtered_before,authority_before=apply_authority_firewall(raw_before)
        federated_before,federation_before,q_before=federate_analysis(current,filtered_before,config)
        # PASS029: unresolved identifiability objects are materialized before optimization.
        # Only bounded, provenance-carrying source evidence may add a candidate; multiple
        # materializations remain an abstention rather than a tiebreak.
        materialized,materialization_cert=materialize_missing_witnesses(current,federated_before,config)
        augmented_before=AnalysisResult(
            issues=list(federated_before.issues)+list(materialized.issues),
            candidates=list(federated_before.candidates)+list(materialized.candidates),
            relations=list(federated_before.relations)+list(materialized.relations),
        )
        augmented_before,materialization_authority=apply_authority_firewall(augmented_before)
        witness_materialization_cycles.append({"cycle":cycle,"certificate":materialization_cert,
                                             "authority_firewall_after_materialization":materialization_authority})
        before,causal_cert=prepare_causal_analysis(current,augmented_before,_authority_analysis)
        causal_cycles.append({"cycle":cycle,**causal_cert})
        federation_cycles.append({"cycle":cycle,"phase":"before",**federation_before})
        sb=score(before.issues)
        accepted=[]; rejected=[]; oscillation=False
        decision=solve_minimal_transfer(
            current,before,
            analyze_fn=_authority_analysis,
            score_fn=score,
            require_independent_evidence=config.require_independent_evidence,
            max_patch_size=config.max_global_patch_size,
            max_exact_options=config.max_global_exact_options_per_cluster,
            enable_parallel_routes=config.enable_parallel_tie_routes,
            max_parallel_routes=config.max_parallel_tie_routes,
            semantic_quotient_rules=analysis_config.semantic_quotient_rules,
            enable_symmetry_obstruction=config.enable_symmetry_obstruction,
        )
        symmetry_cycles.append({"cycle":cycle,"certificate":decision.certificate.get("symmetry_obstruction") or {}})
        repair_path_algebra_cycles.append({"cycle":cycle,"certificate":decision.certificate.get("repair_path_algebra") or {}})
        factorization_cert=(decision.certificate.get("primary_factorization") or {})
        refactor_event=compare_factorizations(previous_primary_factorization,factorization_cert)
        primary_factorization_cycles.append({"cycle":cycle,"factorization":factorization_cert,"dynamic_refactorization":refactor_event})
        previous_primary_factorization=factorization_cert
        return_proof=None
        effective_patches=list(decision.patches)
        sequential_return_route=False
        effective_solver_status=decision.status
        if decision.parallel_routes:
            def _complete_parallel_branch(seed):
                branch_cfg=RepairConfig(**{**config.__dict__,
                    "enable_parallel_tie_routes":False,
                    "enable_final_certification":False,
                    "dry_run":False,
                })
                return repair_object(seed,branch_cfg)
            resolution=resolve_parallel_routes(current,decision.parallel_routes,complete_fn=_complete_parallel_branch,max_routes=config.max_parallel_tie_routes,semantic_quotient_rules=analysis_config.semantic_quotient_rules)
            return_proof=resolution.proof
            effective_solver_status=resolution.status
            parallel_route_cycles.append({"cycle":cycle,**resolution.proof})
            if resolution.proof.get("ok"):
                effective_patches=list(resolution.patches)
                sequential_return_route=True
                decision.certificate["return_proof"]={k:v for k,v in resolution.proof.items() if k!="routes"}
                decision.certificate["return_proof_status"]=resolution.status
                decision.certificate["selected_patch_count_after_return"]=len(effective_patches)
            else:
                effective_patches=[]
                decision.certificate["return_proof"]={k:v for k,v in resolution.proof.items() if k!="routes"}
                decision.certificate["return_proof_status"]=resolution.status
        # PASS036: the mathematically selected repair must also be reachable through the
        # caller's actual mutation-control surface.  The firewall already removed individually
        # forbidden candidates before optimization; this stage checks budgets and precedence.
        control_used_cost=sum(max(0,int(x.get("cost",1))) for x in committed if isinstance(x,dict))
        effective_patches, control_plan = compile_control_plan(current,effective_patches,analysis_config,preserve_order=sequential_return_route,
                                                               used_edits=max(0,int(config.control_budget_used_before_edits))+len(committed),
                                                               used_cost=max(0,int(config.control_budget_used_before_cost))+control_used_cost)
        control_plan_cycles.append({"cycle":cycle,"certificate":control_plan})
        if control_plan.get("reachability") == "UNREACHABLE":
            rejected.append({"reason":"IDENTIFIABLE_BUT_UNREACHABLE","solver_status":effective_solver_status,
                             "controllability_certificate_sha256":control_plan.get("certificate_sha256")})

        if sequential_return_route:
            # RETURN_PROOF certifies an ordered branch.  Commutativity is not required; exact
            # sequential replay and the final independent inverse/cold certifier are the gate.
            trial_order=deepcopy(current); order_ok=True
            for c in effective_patches:
                if not _apply(trial_order,c): order_ok=False; break
            order_audit={"selected_patch_count":len(effective_patches),"order_independent":None,"tested_orders":1,
                         "sequential_return_route":True,"forward_ok":order_ok,"forward_digest":digest(trial_order) if order_ok else None,
                         "return_proof_status":effective_solver_status}
        else:
            order_audit=audit_patch_order(current,effective_patches,_apply)
        if effective_patches and not sequential_return_route and not order_audit.get("order_independent",True):
            rejected.append({"reason":"ORDER_DEPENDENT_PATCH_SET","solver_status":effective_solver_status,"order_audit":order_audit})
        elif effective_patches:
            trial=deepcopy(current); ok=True
            for c in effective_patches:
                if not _apply(trial,c): ok=False; break
            td=digest(trial) if ok else None
            if return_proof and return_proof.get("ok") and return_proof.get("terminal_digest") is not None and td!=return_proof.get("terminal_digest"):
                ok=False
                rejected.append({"reason":"RETURN_PROOF_REPLAY_MISMATCH","solver_status":effective_solver_status,"candidate_digest":td,
                                 "return_terminal_digest":return_proof.get("terminal_digest")})
            if return_proof and return_proof.get("ok") and return_proof.get("status")=="RETURN_PROOF_QUOTIENT_EQUIVALENT":
                qd=semantic_quotient_digest(trial,analysis_config.semantic_quotient_rules) if ok else None
                if qd!=return_proof.get("semantic_quotient_terminal_digest"):
                    ok=False
                    rejected.append({"reason":"RETURN_PROOF_QUOTIENT_REPLAY_MISMATCH","solver_status":effective_solver_status,
                                     "candidate_quotient_digest":qd,"return_quotient_digest":return_proof.get("semantic_quotient_terminal_digest")})
            if ok and td in visited and td!=digest(current):
                oscillation=True; any_oscillation=True
                rejected.append({"reason":"OSCILLATION_DETECTED","solver_status":effective_solver_status,"candidate_digest":td})
            elif ok:
                after=_authority_analysis(trial)
                current=trial; visited.add(td)
                for c in effective_patches:
                    entry={"candidate":c.to_dict(),"score_before":sb,"score_after":score(after.issues),
                           "families":sorted({x.analyzer for x in before.candidates if x.path==c.path and x.new_value==c.new_value}),
                           "acceptance":(("parallel_return_proof_quotient" if (return_proof or {}).get("status")=="RETURN_PROOF_QUOTIENT_EQUIVALENT" else "parallel_return_proof_exact") if sequential_return_route else "minimal_transfer_exact"),
                           "solver_status":effective_solver_status}
                    if sequential_return_route:
                        entry["return_proof_sha256"]=return_proof.get("proof_sha256")
                        entry["selected_route_id"]=return_proof.get("selected_route_id")
                    accepted.append(entry); committed.append(c.to_dict())
            elif not any(x.get("reason")=="RETURN_PROOF_REPLAY_MISMATCH" for x in rejected):
                rejected.append({"reason":"minimal_transfer_precondition_failed","solver_status":effective_solver_status})
        elif before.candidates:
            rejected.append({"reason":"parallel_return_proof_abstention" if decision.parallel_routes else "minimal_transfer_abstention",
                             "solver_status":effective_solver_status})

        raw_after,ms_after,boundary_after,robust_after,semantic_after,falsifier_after,control_after=_raw_with_sources(current)
        multisource_cycles.append({"cycle":cycle,"phase":"after",**ms_after})
        boundary_firewall_cycles.append({"cycle":cycle,"phase":"after",**boundary_after})
        robust_envelope_cycles.append({"cycle":cycle,"phase":"after","certificate":robust_after})
        semantic_claim_cycles.append({"cycle":cycle,"phase":"after","certificate":semantic_after})
        relation_falsification_cycles.append({"cycle":cycle,"phase":"after","certificate":falsifier_after})
        controllability_firewall_cycles.append({"cycle":cycle,"phase":"after","certificate":control_after})
        filtered_after=apply_authority_firewall(raw_after)[0]
        final_analysis,federation_after,q_after=federate_analysis(current,filtered_after,config)
        federation_cycles.append({"cycle":cycle,"phase":"after",**federation_after})
        q_delta=q_compare(q_before,q_after)
        q_descent_cycles.append({"cycle":cycle,"accepted_patch_count":len(accepted),"before":q_before,"after":q_after,"comparison":q_delta})
        for entry in accepted:
            entry["q_descent"]=q_delta
            entry["acceptance_scope"]="SOVEREIGN" if q_delta.get("sovereign_credit") else "LOCAL_ONLY"
        snap=relation_snapshot(final_analysis.relations); delta=relation_delta(previous_snapshot,snap)
        final_frontier=frontier_signature(final_analysis.candidates)
        frontier_changed=(previous_frontier is not None and final_frontier!=previous_frontier)
        lifecycle_events=update_lifecycle(knowledge["lifecycle"],final_analysis.relations,cycle)

        # Backward-compatible knowledge ledger plus lifecycle state.
        current_relations=set(snap)
        for rel in final_analysis.relations:
            rid=_relation_key(rel); entry=knowledge["relations"].get(rid)
            if entry is None:
                entry={"relation":rel,"first_seen_cycle":cycle,"last_seen_cycle":cycle,"seen_cycles":1,"survives_current":True}
                knowledge["relations"][rid]=entry
                knowledge["newly_certified"].append({"cycle":cycle,"relation_id":rid,"relation":rel})
            else:
                entry["last_seen_cycle"]=cycle; entry["seen_cycles"]+=1; entry["relation"]=rel; entry["survives_current"]=True
        for rid,entry in knowledge["relations"].items():
            if rid not in current_relations: entry["survives_current"]=False

        sig=hashlib.sha256(json.dumps(sorted(i.signature() for i in final_analysis.issues),default=str).encode()).hexdigest()
        stable = stable+1 if not accepted else 0
        strong_quiet=bool(not accepted and delta.get("quiet") and previous_frontier is not None and not frontier_changed and
                          not oscillation and order_audit.get("order_independent",True) and
                          bool((federation_after.get("mode_ii") or {}).get("fixed_point_attained",True)))
        strong_streak=strong_streak+1 if strong_quiet else 0
        cycles.append({"cycle":cycle,"accepted":accepted,"rejected":rejected,"minimal_transfer":decision.certificate,
                       "issue_count":len(final_analysis.issues),"score":score(final_analysis.issues),"digest":digest(current),
                       "structural_signature":sig,"stable_streak":stable,"strong_quiet":strong_quiet,
                       "strong_fixed_point_streak":strong_streak,"relation_count":len(final_analysis.relations),
                       "relation_delta":delta,"relation_lifecycle_events":lifecycle_events,"candidate_frontier_signature":final_frontier,
                       "frontier_changed":frontier_changed,"order_audit":order_audit,"oscillation":oscillation})
        previous_snapshot=snap; previous_frontier=final_frontier
        if strong_streak>=required_strong: break

    raw_final,final_multisource,final_boundary_firewall,final_robust_envelope,final_semantic_claim,final_relation_falsification,final_controllability_firewall= _raw_with_sources(current)
    filtered_final,final_authority_firewall=apply_authority_firewall(raw_final)
    final,final_federation,final_q_descent=federate_analysis(current,filtered_final,config)
    _,final_materialization=materialize_missing_witnesses(current,final,config)
    final_double_cone=compile_double_cone(final)
    strong_attained=strong_streak>=required_strong and not any_oscillation
    status="PASS" if not final.issues and strong_attained else ("STABLE_WITH_REPORTED_ISSUES" if strong_attained else "OPEN_REPAIRABLE")
    externally_committed=[] if config.dry_run else committed
    typed_ir=compile_typed_constraint_ir(current, final)
    report={**report_identity(status),"input_digest":initial_digest,
            "security":{"limits":config.security_limits.to_dict(),"input_validation":safety_stats},"output_digest":digest(current),
            "cycles":cycles,"committed_edits":externally_committed,"remaining_issues":[i.to_dict() for i in final.issues],
            "relations":[x for x in final.relations],"constraint_graph":_constraint_graph(final.relations),"typed_constraint_ir":typed_ir,
            "terminal_registry":typed_ir["terminal_registry"],"truth_summary":typed_ir["truth_summary"],
            "identifiability_registry":typed_ir["identifiability_registry"],"identifiability_summary":typed_ir["identifiability_summary"],
            "knowledge_ledger":knowledge,"minimal_transfer_solver":{"contract":"json-consistency-repair.minimal-transfer.v1","cycles":[x["minimal_transfer"] for x in cycles]},
            "typed_expression_ir":expression_ir_summary(analysis_config),
            "repair_path_algebra":{"contract":"json-consistency-repair.repair-path-algebra-summary.v1","cycles":repair_path_algebra_cycles,
                                   "final":repair_path_algebra_cycles[-1] if repair_path_algebra_cycles else None},
            "symmetry_canonicality":symmetry_summary(symmetry_cycles,analysis_config.semantic_quotient_rules),
            "repair_controllability":controllability_summary(controllability_firewall_cycles,control_plan_cycles,final_controllability_firewall),
            "parallel_exact_minimum_routes":{"contract":"json-consistency-repair.parallel-exact-routes.v1","cycles":parallel_route_cycles,
                                               "return_proof_contract":"json-consistency-repair.return-proof.v1"},
            "primary_factorization":{"contract":"json-consistency-repair.primary-factorization-summary.v1","cycles":primary_factorization_cycles,
                                      "final":primary_factorization_cycles[-1] if primary_factorization_cycles else None,
                                      "dynamic_refactorization_contract":"json-consistency-repair.dynamic-refactorization.v1"},
            "witness_materialization":{"contract":"json-consistency-repair.witness-materialization.v1",
                                       "cycles":witness_materialization_cycles,"final":final_materialization,
                                       "summary":materialization_summary(witness_materialization_cycles,final_materialization)},
            "logic_summary":_logic_summary(final),"conservation_summary":_conservation_summary(final),"constraint_bridge_summary":_constraint_bridge_summary(final),
            "system_graph_summary":system_summary(final),"moment_distribution_summary":moment_summary(final),
            "causal_root_analysis":{"contract":"json-consistency-repair.causal-root-analysis.v1","cycles":causal_cycles,"final_double_cone":final_double_cone},
            "federation_summary":{"contract":"json-consistency-repair.c189-federation-summary.v1","cycles":federation_cycles,"final":final_federation},
            "dynamic_q_descent":{"contract":"json-consistency-repair.dynamic-q-descent.v1","cycles":q_descent_cycles,"final":final_q_descent},
            "multisource_assimilation":{"contract":"json-consistency-repair.multisource-assimilation.v1","cycles":multisource_cycles,"final":final_multisource,"summary":multisource_summary(final,final_multisource)},
            "scoped_authority": final_multisource.get("authority_scope_registry") or ((final_multisource.get("source_registry") or {}).get("authority_scope_registry")),
            "evidence_poisoning_firewall": final_multisource.get("evidence_poisoning_firewall") or ((final_multisource.get("source_registry") or {}).get("evidence_poisoning_firewall")),
            "boundary_calculus":{"contract":"json-consistency-repair.boundary-calculus.v1","cycles":boundary_firewall_cycles,
                                  "final":boundary_summary(current,final,analysis_config,final_boundary_firewall)},
            "robust_envelope":{"contract":"json-consistency-repair.robust-envelope.v1","cycles":robust_envelope_cycles,
                               "final":final_robust_envelope,"summary":robust_envelope_summary(robust_envelope_cycles,final_robust_envelope)},
            "semantic_claim_provenance":{"contract":"json-consistency-repair.semantic-claim-provenance-summary.v1","cycles":semantic_claim_cycles,
                                           "final":final_semantic_claim,"summary":semantic_claim_summary(semantic_claim_cycles,final_semantic_claim)},
            "relation_falsification":relation_falsification_summary(relation_falsification_cycles,final_relation_falsification),
            "authority_firewall":final_authority_firewall,
            "strong_stable":strong_attained,
            "strong_fixed_point":{"contract":"json-consistency-repair.strong-fixed-point.v1","attained":strong_attained,
                                   "required_quiet_cycles":required_strong,"quiet_streak":strong_streak,
                                   "oscillation_detected":any_oscillation,"promotion_gate":"COLD_REPLAY_REQUIRED"},
            "dry_run":bool(config.dry_run),"proposed_edits":committed if config.dry_run else [],
            "would_commit_edits":len(committed) if config.dry_run else len(externally_committed),
            "publication_performed":False if config.dry_run else None,"replay":{"forward_digest":digest(current)}}

    report["repair_controllability"]["run_budget"]={
        "max_edits":config.max_control_edits,"max_cost":config.max_control_cost,
        "used_before":{"edits":max(0,int(config.control_budget_used_before_edits)),"cost":max(0,int(config.control_budget_used_before_cost))},
        "used_this_run":{"edits":len(committed),"cost":sum(max(0,int(x.get("cost",1))) for x in committed if isinstance(x,dict))},
        "used_total":{"edits":max(0,int(config.control_budget_used_before_edits))+len(committed),
                      "cost":max(0,int(config.control_budget_used_before_cost))+sum(max(0,int(x.get("cost",1))) for x in committed if isinstance(x,dict))}
    }

    # PASS038: persist typed OPEN obligations and, when a prior registry is supplied,
    # certify the targeted registry transition and conservative proof-node invalidation.
    report["open_obligations"] = compile_open_obligation_registry(report)
    report["incremental_recompute"] = compile_incremental_recompute(
        report["open_obligations"],
        prior_registry=config.prior_open_obligation_registry,
        change_tokens=config.incremental_change_tokens,
        prior_proof_graph=config.prior_proof_graph,
    )
    if config.enable_horizon_naturality:
        report["horizon_naturality"], report["distributed_consistency"] = compile_horizon_surface(
            report, original, current, prior_snapshot=config.prior_horizon_snapshot,
            change_tokens=config.horizon_change_tokens, boundary_witnesses=config.horizon_boundary_witnesses,
            distribution=config.distribution_descriptor or {"mode":"single"},
            max_manifest_entries=max(64,int(config.horizon_manifest_limit)),
        )
    else:
        report["horizon_naturality"]={"contract":"json-consistency-repair.horizon-naturality.v1","disabled":True}
        report["distributed_consistency"]={"contract":"json-consistency-repair.distributed-consistency.v1","disabled":True}
    if config.enable_information_bounds:
        report["residual_information"], report["blind_carrier_reconstruction"] = compile_information_surface(
            current, final.relations, symmetry_surface=report.get("symmetry_canonicality"),
            namespace="root", mode="single", max_trials=max(1,int(config.blind_carrier_max_trials)),
        )
    else:
        report["residual_information"]={"contract":"json-consistency-repair.residual-information-summary.v1","disabled":True}
        report["blind_carrier_reconstruction"]={"contract":"json-consistency-repair.blind-carrier-reconstruction.v1","scope":"summary","disabled":True}

    patch_rows=[{
        "operation":c.get("operation","replace"),"path":c.get("path",""),
        "old_value":deepcopy(c.get("old_value")),"new_value":deepcopy(c.get("new_value")),
        "metadata":deepcopy(c.get("metadata") or {})
    } for c in committed]
    replay_ok, replayed, inverse_patches = replay_with_inverses(original, patch_rows)
    inverse=deepcopy(replayed); inverse_ok=True
    from .jsonpatch_exact import apply_patch as _apply_exact_patch
    for inv in inverse_patches:
        ok,_=_apply_exact_patch(inverse,inv)
        if not ok:
            inverse_ok=False; break
    report["replay"]["forward_replays_output"] = bool(replay_ok and digest(replayed)==digest(current))
    report["replay"]["inverse_restores_input"] = bool(replay_ok and inverse_ok and digest(inverse)==initial_digest)
    report["replay"]["exact_inverse_patches"] = inverse_patches

    # PASS028: commit the complete serialized decision graph before any replay verdict is added.
    # This avoids self-reference while still binding provenance, relations, federation, Q, routes,
    # primary blocks/refactorization, boundaries and the applied chain.
    report["provenance_chain"]=build_provenance_chain(input_digest=initial_digest,output_digest=digest(current),committed=committed,
                                                        cycles=cycles,code_digest=package_code_sha256(),mode="single")
    report["proof_graph"]=compile_proof_graph(report)

    if config.enable_final_certification:
        # Fixed-point cold replay starts from the terminal and must propose zero further edits.
        _cold_used_edits=max(0,int(config.control_budget_used_before_edits))+len(committed)
        _cold_used_cost=max(0,int(config.control_budget_used_before_cost))+sum(max(0,int(x.get("cost",1))) for x in committed if isinstance(x,dict))
        cold_cfg=RepairConfig(**{**config.__dict__,"enable_final_certification":False,"dry_run":True,
                                 "enable_horizon_naturality":False,"enable_information_bounds":False,
                                 "control_budget_used_before_edits":_cold_used_edits,
                                 "control_budget_used_before_cost":_cold_used_cost})
        cold_value,cold_res=repair_object(current,cold_cfg)
        report["cold_replay"]={"contract":"json-consistency-repair.cold-replay.v1","performed":True,
                               "input_digest":digest(current),"output_digest":cold_res.output_digest,
                               "would_commit_edits":cold_res.report.get("would_commit_edits",0),
                               "strong_fixed_point_attained":bool((cold_res.report.get("strong_fixed_point") or {}).get("attained")),
                               "remaining_issue_count":cold_res.remaining_issues,
                               "same_output":digest(cold_value)==digest(current)}
        # Full proof-graph replay restarts from the sovereign original input with empty runtime state.
        proof_cfg=RepairConfig(**{**config.__dict__,"enable_final_certification":False})
        proof_value,proof_res=repair_object(original,proof_cfg)
        pg_replay=compare_proof_graphs(report["proof_graph"], proof_res.report.get("proof_graph") or {})
        pg_replay["same_terminal_output"] = digest(proof_value)==digest(current)
        pg_replay["replayed_output_digest"] = proof_res.output_digest
        pg_replay["ok"] = bool(pg_replay.get("ok") and pg_replay["same_terminal_output"])
        if not pg_replay["ok"]:
            pg_replay["status"]="PROOF_GRAPH_REPLAY_MISMATCH"
        report["proof_graph_replay"]=pg_replay
        report["incremental_equivalence"] = compile_incremental_equivalence(
            report["incremental_recompute"], report["proof_graph"], pg_replay, config.prior_proof_graph)
        # PASS032: one canonical, hash-bound index of the complete serialized rectification trajectory.
        # It is compiled before the independent certifier to avoid self-reference, then sealed by the certifier verdict.
        report["rectification_packet"]=compile_rectification_packet(report)
        final_cert=__import__("json_consistency_repair.certifier", fromlist=["verify_single_packet"]).verify_single_packet(original,current,committed,report)
        report["final_certification"]=final_cert
        report["rectification_packet"]=seal_rectification_packet(report["rectification_packet"],final_cert,report)
        report["certification_gate"]="PASS" if final_cert.get("ok") else "FAIL"
    else:
        report["cold_replay"]={"performed":False,"reason":"FINAL_CERTIFICATION_DISABLED"}
        report["proof_graph_replay"]={"contract":"json-consistency-repair.proof-graph-replay.v1","performed":False,"ok":False,"reason":"FINAL_CERTIFICATION_DISABLED"}
        report["incremental_equivalence"] = compile_incremental_equivalence(
            report["incremental_recompute"], report["proof_graph"], report["proof_graph_replay"], config.prior_proof_graph)
        report["rectification_packet"]=compile_rectification_packet(report)
        report["final_certification"]={"status":"NOT_RUN","ok":False}
        report["certification_gate"]="NOT_RUN"
    from .closure import compile_third_series_closure, compile_fourth_series_closure, compile_fifth_series_progress, compile_fifth_series_closure
    report["third_series_closure"] = compile_third_series_closure(report)
    report["fourth_series_closure"] = compile_fourth_series_closure(report)
    report["fifth_series_progress"] = compile_fifth_series_progress(report,40)
    report["fifth_series_closure"] = compile_fifth_series_closure(report)
    if config.open_obligation_store_path and config.enable_final_certification and (report.get("final_certification") or {}).get("ok"):
        save_open_obligation_registry(config.open_obligation_store_path, report["open_obligations"])
    return current, RepairResult(None,None,None,status,len(cycles),len(externally_committed),len(final.issues),initial_digest,digest(current),report)


def repair_file(input_path:str|Path, output_path:str|Path|None=None, report_path:str|Path|None=None, config:RepairConfig|None=None):
    config=config or RepairConfig(); p=Path(input_path); limits=config.security_limits; syntax=[]
    enforce_file_size(p, limits.max_document_bytes)
    text=p.read_text(encoding="utf-8-sig")
    try: value=loads_strict(text, limits)
    except Exception:
        if not config.syntax_repair: raise
        value,syntax=conservative_syntax_repair(text, limits)
        if value is None: raise
    # Explicitly retain the verified contract in the report; validation is iterative and already ran in loads_strict.
    safety_stats=validate_json_value(value, limits)
    repaired,res=repair_object(value,config)
    res.input_path=str(p); res.output_path=str(output_path) if output_path else None; res.report_path=str(report_path) if report_path else None
    if syntax: res.report["syntax_repairs"]=syntax
    res.report["security"]={"limits":limits.to_dict(),"input_validation":safety_stats,"atomic_publication":True}
    if output_path and not config.dry_run: dump_file(repaired,output_path)
    if report_path: Path(report_path).write_text(json.dumps(res.report,ensure_ascii=False,indent=2,default=str)+"\n",encoding="utf-8")
    return res
