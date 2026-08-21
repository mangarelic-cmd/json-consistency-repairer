from __future__ import annotations

from dataclasses import dataclass, asdict
from enum import Enum
from typing import Any
import hashlib
import json

from .models import AnalysisResult, Candidate, Issue, digest
from .tree import walk
from .identifiability import (
    compile_identifiability_registry, identifiability_summary,
    compile_bundle_cross_identifiability, compile_stream_identifiability,
    IdentifiabilityState,
)


class Truth3(str, Enum):
    """Three-valued truth used by the typed constraint IR.

    TRUE    : certified/decidable from the current material.
    FALSE   : concretely contradicted by the current object.
    UNKNOWN : the current material does not determine the requested reconstruction.
    """
    TRUE = "TRUE"
    FALSE = "FALSE"
    UNKNOWN = "UNKNOWN"


def _stable_id(prefix: str, payload: Any, n: int = 24) -> str:
    raw=json.dumps(payload,ensure_ascii=False,sort_keys=True,separators=(",",":"),default=str).encode("utf-8")
    return f"{prefix}_{hashlib.sha256(raw).hexdigest()[:n]}"


def _json_type(v: Any) -> str:
    if v is None: return "null"
    if isinstance(v,bool): return "boolean"
    if isinstance(v,int): return "integer"
    if isinstance(v,float): return "number"
    if isinstance(v,str): return "string"
    if isinstance(v,list): return "array"
    if isinstance(v,dict): return "object"
    return type(v).__name__


def _shape(v: Any) -> dict[str, Any]:
    if isinstance(v,dict):
        return {"size":len(v),"keys":sorted(v.keys())}
    if isinstance(v,list):
        return {"size":len(v)}
    return {}


def _issue_relation_kind(issue: Issue) -> str | None:
    meta=issue.metadata or {}
    if meta.get("relation_kind"): return str(meta["relation_kind"])
    # Older analyzers did not consistently serialize relation_kind. Keep the bridge explicit.
    return {
        "type_pattern":"type_consensus",
        "schema_structure":"required_key",
        "enum_domain":"enum_domain",
        "identifier_reference":"foreign_reference",
        "functional_relation":"functional",
        "scoped_functional_relation":"scoped_functional",
        "exact_arithmetic":"exact_arithmetic",
        "temporal":"temporal_delta",
        "sequential":"sequence_step",
        "logic_exact":"logic_exact",
        "expression_exact":"typed_expression_exact",
    }.get(issue.analyzer)


def _constraint_matches_issue(rel: dict[str,Any], issue: Issue) -> bool:
    kind=_issue_relation_kind(issue)
    if kind and kind!=rel.get("kind"):
        # identifier_reference emits both uniqueness and foreign reference issues.
        if not (issue.analyzer=="identifier_reference" and rel.get("kind") in {"identifier_uniqueness","foreign_reference"}):
            return False
    base=rel.get("array_path","")
    if base and not (issue.path==base or issue.path.startswith(base+"/")):
        return False
    out=rel.get("output")
    if out:
        token=str(out).replace("~","~0").replace("/","~1")
        if not (issue.path.endswith("/"+token) or issue.path==base):
            # Some relation issues are attached to a neighboring/aggregate field; metadata can still identify them.
            meta=issue.metadata or {}
            if out not in {meta.get("target"),meta.get("field"),meta.get("enum_field"),meta.get("reference_field"),meta.get("schema_key")}:
                return False
    return True


def _candidate_ids_for_issue(issue: Issue, candidates: list[Candidate]) -> list[str]:
    out=[]
    for c in candidates:
        if c.path!=issue.path: continue
        if c.analyzer!=issue.analyzer: continue
        out.append(c.candidate_id)
    return sorted(set(out))


def compile_typed_constraint_ir(root: Any, analysis: AnalysisResult) -> dict[str,Any]:
    """Compile the current JSON state and analysis into a deterministic typed constraint IR.

    This representation is deliberately descriptive in PASS009: it does not choose a repair.
    Later passes may solve over it, but the compiler itself only records typed material,
    constraints, terminals and the distinction FALSE(defect exists) / UNKNOWN(repair unknown).
    """
    object_nodes=[]
    for path,value in walk(root):
        node={
            "node_id":_stable_id("node",[path,_json_type(value)]),
            "path":path,
            "json_type":_json_type(value),
            "value_digest":digest(value),
        }
        node.update(_shape(value))
        object_nodes.append(node)
    object_nodes.sort(key=lambda x:x["path"])

    constraints=[]
    for rel in sorted(analysis.relations,key=lambda x:x["relation_id"]):
        violations=[i for i in analysis.issues if _constraint_matches_issue(rel,i)]
        constraints.append({
            "constraint_id":rel["relation_id"],
            "kind":rel.get("kind"),
            "scope":rel.get("array_path",""),
            "inputs":list(rel.get("inputs",[])),
            "output":rel.get("output"),
            "confidence":rel.get("confidence"),
            "support":rel.get("support"),
            "law_truth":Truth3.TRUE.value,
            "current_satisfaction":Truth3.FALSE.value if violations else Truth3.TRUE.value,
            "violation_count":len(violations),
            "source_relation":rel,
        })

    terminals=[]
    for issue in sorted(analysis.issues,key=lambda i:(i.path,i.analyzer,i.code,i.signature())):
        cids=_candidate_ids_for_issue(issue,analysis.candidates)
        reconstruction_truth=Truth3.TRUE.value if issue.repairable and cids else Truth3.UNKNOWN.value
        payload=[issue.analyzer,issue.code,issue.path,issue.signature()]
        terminals.append({
            "terminal_id":_stable_id("terminal",payload),
            "terminal_type":"DEFECT",
            "path":issue.path,
            "analyzer":issue.analyzer,
            "code":issue.code,
            "severity":issue.severity,
            "satisfaction_truth":Truth3.FALSE.value,
            "reconstruction_truth":reconstruction_truth,
            "repairable":bool(issue.repairable),
            "candidate_ids":cids,
            "metadata":issue.metadata,
        })

    candidates=[]
    for c in sorted(analysis.candidates,key=lambda x:x.candidate_id):
        candidates.append({
            "candidate_id":c.candidate_id,
            "operation":c.operation,
            "path":c.path,
            "analyzer":c.analyzer,
            "old_type":_json_type(c.old_value),
            "new_type":_json_type(c.new_value),
            "old_digest":digest(c.old_value),
            "new_digest":digest(c.new_value),
            "confidence":c.confidence,
            "cost":c.cost,
            "evidence":list(c.evidence),
            "metadata":c.metadata,
            "admissibility_truth":Truth3.TRUE.value,
        })

    identifiability_registry=compile_identifiability_registry(root, analysis)
    ident_by_path={x["path"]:x for x in identifiability_registry}
    for t in terminals:
        ident=ident_by_path.get(t["path"])
        if ident:
            t["observability"]=ident["observability"]
            t["identifiability"]=ident["identifiability"]
            t["solution_count"]=ident["solution_count"]
            t["unique_solution_digest"]=ident["unique_solution_digest"]
            t["minimal_missing_witness"]=ident["minimal_missing_witness"]
            t["reconstruction_truth"]=Truth3.TRUE.value if ident["identifiability"]==IdentifiabilityState.UNIQUE.value else Truth3.UNKNOWN.value

    truth_summary={k:0 for k in (Truth3.TRUE.value,Truth3.FALSE.value,Truth3.UNKNOWN.value)}
    for x in constraints:
        truth_summary[x["law_truth"]]+=1
        truth_summary[x["current_satisfaction"]]+=1
    for x in terminals:
        truth_summary[x["satisfaction_truth"]]+=1
        truth_summary[x["reconstruction_truth"]]+=1

    return {
        "ir_contract":"json-consistency-repair.typed-constraint-ir.v2",
        "root_digest":digest(root),
        "object_node_count":len(object_nodes),
        "constraint_count":len(constraints),
        "terminal_count":len(terminals),
        "candidate_count":len(candidates),
        "object_nodes":object_nodes,
        "constraints":constraints,
        "terminal_registry":terminals,
        "candidates":candidates,
        "identifiability_registry":identifiability_registry,
        "identifiability_summary":identifiability_summary(identifiability_registry),
        "unresolved_terminal_ids":[x["terminal_id"] for x in terminals if x["reconstruction_truth"]==Truth3.UNKNOWN.value],
        "truth_summary":truth_summary,
    }



def compile_bundle_typed_constraint_ir(documents: dict[str,Any], local_analyses: dict[str,AnalysisResult], cross_analysis: Any) -> dict[str,Any]:
    """Compile a deterministic bundle-level IR without erasing document boundaries."""
    docs={name:compile_typed_constraint_ir(documents[name],local_analyses[name]) for name in sorted(documents)}
    cross_constraints=[]
    cross_terminals=[]
    cross_candidates=[]
    issues=list(getattr(cross_analysis,"issues",[]))
    candidates=list(getattr(cross_analysis,"candidates",[]))
    for rel in sorted(getattr(cross_analysis,"relations",[]),key=lambda x:x["relation_id"]):
        rid=rel["relation_id"]
        violations=[bi for bi in issues if (bi.issue.metadata or {}).get("relation_id")==rid]
        cross_constraints.append({
            "constraint_id":rid,"kind":rel.get("kind"),"scope":"cross_document",
            "source_document":rel.get("source_document"),"source_array_path":rel.get("source_array_path",""),
            "reference_field":rel.get("reference_field"),"target_document":rel.get("target_document"),
            "target_array_path":rel.get("target_array_path"),"target_id_field":rel.get("target_id_field"),
            "confidence":rel.get("confidence"),"support":rel.get("support"),
            "law_truth":Truth3.TRUE.value,
            "current_satisfaction":Truth3.FALSE.value if violations else Truth3.TRUE.value,
            "violation_count":len(violations),"source_relation":rel,
        })
    for bi in sorted(issues,key=lambda x:(x.document,x.issue.path,x.issue.analyzer,x.issue.code)):
        issue=bi.issue
        cids=sorted({bc.candidate.candidate_id for bc in candidates if bc.document==bi.document and bc.candidate.path==issue.path and bc.candidate.analyzer==issue.analyzer})
        rt=Truth3.TRUE.value if issue.repairable and cids else Truth3.UNKNOWN.value
        cross_terminals.append({
            "terminal_id":_stable_id("terminal",["bundle",bi.document,issue.analyzer,issue.code,issue.path,issue.signature()]),
            "terminal_type":"DEFECT","scope":"cross_document","document":bi.document,
            "target_document":getattr(bi,"target_document",None),"path":issue.path,"analyzer":issue.analyzer,
            "code":issue.code,"severity":issue.severity,"satisfaction_truth":Truth3.FALSE.value,
            "reconstruction_truth":rt,"repairable":bool(issue.repairable),"candidate_ids":cids,"metadata":issue.metadata,
        })
    for bc in sorted(candidates,key=lambda x:(x.document,x.candidate.candidate_id)):
        c=bc.candidate
        cross_candidates.append({
            "candidate_id":c.candidate_id,"scope":"cross_document","document":bc.document,
            "target_document":getattr(bc,"target_document",None),"operation":c.operation,"path":c.path,
            "analyzer":c.analyzer,"old_type":_json_type(c.old_value),"new_type":_json_type(c.new_value),
            "old_digest":digest(c.old_value),"new_digest":digest(c.new_value),"confidence":c.confidence,
            "cost":c.cost,"evidence":list(c.evidence),"metadata":c.metadata,"admissibility_truth":Truth3.TRUE.value,
        })
    cross_identifiability=compile_bundle_cross_identifiability(documents, cross_analysis)
    cross_ident_by_key={(x["document"],x["path"]):x for x in cross_identifiability}
    for t in cross_terminals:
        ident=cross_ident_by_key.get((t.get("document"),t.get("path")))
        if ident:
            t["observability"]=ident["observability"]
            t["identifiability"]=ident["identifiability"]
            t["solution_count"]=ident["solution_count"]
            t["unique_solution_digest"]=ident["unique_solution_digest"]
            t["minimal_missing_witness"]=ident["minimal_missing_witness"]
            t["reconstruction_truth"]=Truth3.TRUE.value if ident["identifiability"]==IdentifiabilityState.UNIQUE.value else Truth3.UNKNOWN.value

    truth={k:0 for k in (Truth3.TRUE.value,Truth3.FALSE.value,Truth3.UNKNOWN.value)}
    for d in docs.values():
        for k,v in d["truth_summary"].items(): truth[k]+=v
    for c in cross_constraints:
        truth[c["law_truth"]]+=1; truth[c["current_satisfaction"]]+=1
    for t in cross_terminals:
        truth[t["satisfaction_truth"]]+=1; truth[t["reconstruction_truth"]]+=1
    all_unresolved=[]
    all_terminals=[]
    for name,d in docs.items():
        for t in d["terminal_registry"]:
            qt=dict(t); qt["scope"]="local"; qt["document"]=name; qt["qualified_terminal_id"]=f"{name}::{t['terminal_id']}"; all_terminals.append(qt)
        all_unresolved.extend(f"{name}::{tid}" for tid in d["unresolved_terminal_ids"])
    all_terminals.extend(cross_terminals)
    all_unresolved.extend(t["terminal_id"] for t in cross_terminals if t["reconstruction_truth"]==Truth3.UNKNOWN.value)
    all_terminals.sort(key=lambda t:(t.get("document",""),t.get("path",""),t.get("analyzer",""),t.get("terminal_id","")))
    return {
        "ir_contract":"json-consistency-repair.typed-constraint-ir.v2","mode":"bundle","materialization_scope":"FULL",
        "bundle_documents":docs,"cross_document_constraints":cross_constraints,
        "cross_document_terminal_registry":cross_terminals,"terminal_registry":all_terminals,"cross_document_candidates":cross_candidates,
        "identity_registry":list(getattr(cross_analysis,"identity_registry",[])),
        "cross_document_identifiability_registry":cross_identifiability,
        "identifiability_summary":{
            k: sum(d.get("identifiability_summary",{}).get(k,0) for d in docs.values()) + identifiability_summary(cross_identifiability).get(k,0)
            for k in (IdentifiabilityState.UNIQUE.value,IdentifiabilityState.MULTIPLE.value,IdentifiabilityState.NONE.value,IdentifiabilityState.INSUFFICIENT.value)
        },
        "unresolved_terminal_ids":sorted(all_unresolved),"truth_summary":truth,
    }


def compile_stream_typed_constraint_ir(knowledge: dict[str,Any], final_cycle: dict[str,Any], root_digest: str) -> dict[str,Any]:
    """Compile the bounded-memory streaming IR. Only sampled terminals are materialized."""
    constraints=[]
    for rel in sorted(knowledge.get("relations",[]),key=lambda x:x["relation_id"]):
        constraints.append({
            "constraint_id":rel["relation_id"],"kind":rel.get("kind"),"scope":"stream",
            "inputs":list(rel.get("inputs",[])),"output":rel.get("output"),"confidence":rel.get("confidence"),
            "support":rel.get("support"),"law_truth":Truth3.TRUE.value,"current_satisfaction":Truth3.UNKNOWN.value if int(final_cycle.get("issues_observed",0)) else Truth3.TRUE.value,
            "source_relation":rel,
        })
    samples=list(final_cycle.get("issue_samples",[]))
    terminals=[]
    for idx,issue in enumerate(samples):
        repairable=bool(issue.get("repairable"))
        terminals.append({
            "terminal_id":_stable_id("terminal",["stream",idx,issue]),"terminal_type":"DEFECT_SAMPLE","scope":"stream",
            "record":issue.get("record"),"path":issue.get("path",""),"analyzer":issue.get("analyzer"),"code":issue.get("code"),
            "satisfaction_truth":Truth3.FALSE.value,"reconstruction_truth":Truth3.TRUE.value if repairable else Truth3.UNKNOWN.value,
            "repairable":repairable,"sampled":True,
        })
    stream_identifiability=compile_stream_identifiability(final_cycle)
    for idx,t in enumerate(terminals):
        if idx < len(stream_identifiability):
            ident=stream_identifiability[idx]
            t["observability"]=ident["observability"]
            t["identifiability"]=ident["identifiability"]
            t["solution_count"]=ident["solution_count"]
            t["unique_solution_digest"]=ident["unique_solution_digest"]
            t["minimal_missing_witness"]=ident["minimal_missing_witness"]
            t["reconstruction_truth"]=Truth3.TRUE.value if ident["identifiability"]==IdentifiabilityState.UNIQUE.value else Truth3.UNKNOWN.value

    observed=int(final_cycle.get("issues_observed",0))
    unmaterialized=max(0,observed-len(terminals))
    truth={Truth3.TRUE.value:0,Truth3.FALSE.value:observed,Truth3.UNKNOWN.value:0}
    for c in constraints:
        truth[c["law_truth"]]+=1; truth[c["current_satisfaction"]]+=1
    for t in terminals: truth[t["reconstruction_truth"]]+=1
    truth[Truth3.UNKNOWN.value]+=unmaterialized
    return {
        "ir_contract":"json-consistency-repair.typed-constraint-ir.v2","mode":"streaming","materialization_scope":"BOUNDED_STREAM",
        "root_digest":root_digest,"constraints":constraints,"terminal_registry":terminals,
        "observed_terminal_count":observed,"materialized_terminal_sample_count":len(terminals),
        "unmaterialized_terminal_count":unmaterialized,
        "identifiability_registry":stream_identifiability,
        "identifiability_summary":identifiability_summary(stream_identifiability),
        "unresolved_terminal_ids":[t["terminal_id"] for t in terminals if t["reconstruction_truth"]==Truth3.UNKNOWN.value],
        "truth_summary":truth,
    }
