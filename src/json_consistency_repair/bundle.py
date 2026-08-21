from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, asdict, replace
from pathlib import Path, PurePosixPath
from typing import Any
from collections import defaultdict
import hashlib
import json
import os
import shutil
import tempfile
from fractions import Fraction
from itertools import combinations, product

from .analyzers import analyze_all, object_arrays
from .engine import RepairConfig, repair_object, score, _apply
from .io import dump_file, loads_strict, conservative_syntax_repair
from .security import SecurityLimitError, enforce_file_size, validate_json_value
from .provenance import report_identity, package_code_sha256
from .models import Candidate, Issue, AnalysisResult, digest, pointer
from .tree import decode_pointer, get
from .constraint_ir import compile_bundle_typed_constraint_ir
from .fixedpoint import relation_delta
from .provenance_chain import build_provenance_chain
from .causal_cone import apply_authority_firewall, compile_double_cone
from .system_graph import system_summary
from .moments import moment_summary
from .federation import federate_analysis
from .multisource import analyze_multisource, multisource_summary
from .boundary import apply_boundary_firewall, boundary_summary
from .primary_factorization import factorize_options
from .repair_algebra import compile_repair_path_algebra, candidate_set_admissibility
from .expression_ir import expression_ir_summary
from .proof_graph import compile_proof_graph, compare_proof_graphs
from .rectification_packet import compile_rectification_packet, seal_rectification_packet
from .materialization import materialization_summary
from .robust_envelope import apply_robust_envelope_firewall
from .semantic_provenance import apply_semantic_claim_provenance_firewall, semantic_claim_summary, project_verified_semantic_config
from .symmetry import compile_symmetry_obstruction, semantic_quotient_digest, compile_semantic_quotient
from .controllability import apply_controllability_firewall, compile_control_plan
from .relation_falsifier import apply_relation_falsification_firewall
from .persistent_open import (compile_open_obligation_registry, compile_incremental_recompute,
    compile_incremental_equivalence, save_open_obligation_registry)
from .horizon import compile_horizon_surface
from .information_bounds import compile_information_bundle_surface


@dataclass(frozen=True)
class BundleCandidate:
    document: str
    candidate: Candidate
    target_document: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = self.candidate.to_dict()
        d["document"] = self.document
        if self.target_document is not None:
            d["target_document"] = self.target_document
        return d


@dataclass(frozen=True)
class BundleIssue:
    document: str
    issue: Issue
    target_document: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = self.issue.to_dict()
        d["document"] = self.document
        if self.target_document is not None:
            d["target_document"] = self.target_document
        return d


@dataclass
class BundleAnalysis:
    issues: list[BundleIssue]
    candidates: list[BundleCandidate]
    relations: list[dict[str, Any]]
    identity_registry: list[dict[str, Any]]


@dataclass
class BundleRepairResult:
    final_status: str
    cycles: int
    committed_edits: int
    remaining_issues: int
    input_digest: str
    output_digest: str
    report: dict[str, Any]
    input_dir: str | None = None
    output_dir: str | None = None
    report_path: str | None = None


def _jkey(v: Any) -> str | None:
    try:
        return json.dumps(v, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    except TypeError:
        return None


def bundle_digest(documents: dict[str, Any]) -> str:
    h = hashlib.sha256()
    for name in sorted(documents):
        nb = name.encode("utf-8")
        db = digest(documents[name]).encode("ascii")
        h.update(len(nb).to_bytes(8, "big")); h.update(nb)
        h.update(db)
    return h.hexdigest()


def _verified_quotient_rules(config: RepairConfig):
    projected,_=project_verified_semantic_config(config)
    return tuple(getattr(projected,"semantic_quotient_rules",()) or ())


def _bundle_semantic_quotient_digest(documents: dict[str, Any], rules) -> str:
    h=hashlib.sha256()
    for name in sorted(documents):
        nb=name.encode("utf-8")
        db=semantic_quotient_digest(documents[name],rules).encode("ascii")
        h.update(len(nb).to_bytes(8,"big")); h.update(nb); h.update(db)
    return h.hexdigest()


def _singular(name: str) -> str:
    if name.endswith("ies") and len(name) > 3:
        return name[:-3] + "y"
    if name.endswith("ses") and len(name) > 3:
        return name[:-2]
    if name.endswith("s") and not name.endswith("ss") and len(name) > 1:
        return name[:-1]
    return name


def _relation_id(payload: dict[str, Any]) -> str:
    identity = {k: v for k, v in payload.items() if k not in {"confidence", "support", "relation_id"}}
    raw = json.dumps(identity, sort_keys=True, ensure_ascii=False, default=str, separators=(",", ":")).encode("utf-8")
    return hashlib.sha1(raw).hexdigest()[:20]


def _registry_for_documents(documents: dict[str, Any], config: RepairConfig) -> list[dict[str, Any]]:
    registries: list[dict[str, Any]] = []
    for document in sorted(documents):
        root = documents[document]
        for parts, arr in object_arrays(root):
            keys = sorted(set().union(*(o.keys() for o in arr)))
            last = str(parts[-1]) if parts and not isinstance(parts[-1], int) else ""
            preferred: list[str] = []
            for k in ("id", "uuid", f"{_singular(last)}_id" if last else None, f"{_singular(last)}_uuid" if last else None):
                if k and k in keys and k not in preferred:
                    preferred.append(k)
            for key in preferred:
                vals = [o.get(key) for o in arr if o.get(key) is not None and _jkey(o.get(key)) is not None]
                if len(vals) < config.min_support:
                    continue
                encoded = [_jkey(v) for v in vals]
                uniqueness = len(set(encoded)) / len(encoded)
                if uniqueness < config.id_uniqueness_confidence:
                    continue
                # Only a fully unique set becomes a cross-document identity registry.
                if uniqueness != 1.0:
                    continue
                values = {_jkey(v): v for v in vals}
                canonical = sorted(values.keys())
                value_digest = hashlib.sha256("\n".join(canonical).encode("utf-8")).hexdigest()
                registries.append({
                    "document": document,
                    "array_path": pointer(parts),
                    "id_field": key,
                    "count": len(vals),
                    "uniqueness": 1.0,
                    "value_digest": value_digest,
                    "values": values,
                    "raw": vals,
                })
                break
    return registries


def _public_registry(reg: dict[str, Any]) -> dict[str, Any]:
    return {k: reg[k] for k in ("document", "array_path", "id_field", "count", "uniqueness", "value_digest")}


def _field_matches_reference(field: str) -> bool:
    return field.endswith("_id") or field.endswith("_uuid") or field in ("parent_id", "ref_id")


def analyze_bundle(documents: dict[str, Any], config: RepairConfig | None = None) -> BundleAnalysis:
    config = config or RepairConfig()
    registries = _registry_for_documents(documents, config)
    issues: list[BundleIssue] = []
    candidates: list[BundleCandidate] = []
    relations: list[dict[str, Any]] = []

    for document in sorted(documents):
        root = documents[document]
        for parts, arr in object_arrays(root):
            keys = sorted(set().union(*(o.keys() for o in arr)))
            for field in keys:
                if not _field_matches_reference(field):
                    continue
                refs = [o.get(field) for o in arr if o.get(field) is not None and _jkey(o.get(field)) is not None]
                if len(refs) < config.min_support:
                    continue
                scored: list[tuple[float, int, dict[str, Any]]] = []
                for reg in registries:
                    # PASS003 already handles references inside one document. PASS004 adds only cross-document edges.
                    if reg["document"] == document:
                        continue
                    overlap = sum(1 for v in refs if _jkey(v) in reg["values"])
                    confidence = overlap / len(refs)
                    if confidence >= config.reference_confidence:
                        scored.append((confidence, overlap, reg))
                if not scored:
                    continue
                scored.sort(key=lambda x: (-x[0], -x[1], x[2]["document"], x[2]["array_path"], x[2]["id_field"]))
                best = scored[0]
                if len(scored) > 1 and scored[1][0] == best[0] and scored[1][1] == best[1]:
                    # The relation is visible but target identity is not unique.
                    path = pointer(parts)
                    meta = {
                        "reference_field": field,
                        "candidate_targets": [
                            {"document": x[2]["document"], "array_path": x[2]["array_path"], "id_field": x[2]["id_field"], "confidence": x[0], "support": x[1]}
                            for x in scored if x[0] == best[0] and x[1] == best[1]
                        ],
                        "relation_kind": "ambiguous_cross_document_reference_target",
                    }
                    issues.append(BundleIssue(document, Issue(
                        "bundle_reference", "ambiguous_reference_target", path,
                        f"Reference field {field!r} matches multiple cross-document identity registries equally; no target registry is selected.",
                        "warning", False, meta,
                    )))
                    continue

                confidence, overlap, reg = best
                target_values = reg["values"]
                casefold: dict[str, Any] = {}
                if all(isinstance(v, str) for v in reg["raw"]):
                    tmp: dict[str, list[str]] = defaultdict(list)
                    for v in reg["raw"]:
                        tmp[v.casefold()].append(v)
                    casefold = {k: vs[0] for k, vs in tmp.items() if len(vs) == 1}

                relation = {
                    "kind": "foreign_reference_cross_document",
                    "source_document": document,
                    "source_array_path": pointer(parts),
                    "reference_field": field,
                    "target_document": reg["document"],
                    "target_array_path": reg["array_path"],
                    "target_id_field": reg["id_field"],
                    "confidence": round(float(confidence), 12),
                    "support": int(overlap),
                }
                relation["relation_id"] = _relation_id(relation)
                relations.append(relation)

                for i, obj in enumerate(arr):
                    if field not in obj or obj[field] is None:
                        continue
                    value = obj[field]
                    if _jkey(value) in target_values:
                        continue
                    meta = {
                        "reference_field": field,
                        "target_document": reg["document"],
                        "target_array_path": reg["array_path"],
                        "target_id_field": reg["id_field"],
                        "relation_id": relation["relation_id"],
                        "relation_kind": "foreign_reference_cross_document",
                    }
                    path = pointer(parts + [i, field])
                    if isinstance(value, str) and value.casefold() in casefold:
                        canon = casefold[value.casefold()]
                        issue = Issue(
                            "bundle_reference", "cross_document_reference_representation_variant", path,
                            f"Reference {value!r} uniquely matches canonical identifier {canon!r} in {reg['document']}:{reg['array_path']}#{reg['id_field']}.",
                            "error", True, meta,
                        )
                        candidate = Candidate(
                            hashlib.sha1(json.dumps(["bundle_reference", document, path, value, canon], sort_keys=True, default=str).encode()).hexdigest()[:16],
                            "bundle_reference", "replace", path, value, canon,
                            "Restore canonical cross-document foreign-reference representation.",
                            confidence, 1,
                            (f"XFK:{document}:{pointer(parts)}#{field}->{reg['document']}:{reg['array_path']}#{reg['id_field']}", "CASEFOLD_UNIQUE_GLOBAL_ID"),
                            meta,
                        )
                        issues.append(BundleIssue(document, issue, reg["document"]))
                        candidates.append(BundleCandidate(document, candidate, reg["document"]))
                    else:
                        issue = Issue(
                            "bundle_reference", "cross_document_dangling_reference", path,
                            f"Reference {value!r} does not resolve in certified identity registry {reg['document']}:{reg['array_path']}#{reg['id_field']}; no unique replacement is justified.",
                            "error", False, meta,
                        )
                        issues.append(BundleIssue(document, issue, reg["document"]))

    uniq = {x["relation_id"]: x for x in relations}
    return BundleAnalysis(issues, candidates, list(uniq.values()), [_public_registry(r) for r in registries])



def _logic_config(config: RepairConfig, document: str) -> RepairConfig:
    # Bundle descriptors may be global or explicitly document-scoped.  A scoped source/rule
    # never leaks into another document.  Once scoped into the local single-document carrier,
    # the document routing tag is removed so the single-object control firewall can evaluate it.
    ctx=tuple(s for s in (config.source_context or ()) if s.get("document") in (None,"",document))
    control=[]
    for raw in (config.controllability_rules or ()):
        if not isinstance(raw,dict) or raw.get("document") not in (None,"",document):
            continue
        rr=deepcopy(raw); rr.pop("document",None); control.append(rr)
    return replace(config, logic_document=document, conservation_document=document, system_document=document, moment_document=document,
                   source_context=ctx, controllability_rules=tuple(control))


def _full_local_analysis(root: Any, config: RepairConfig, document: str):
    requested=_logic_config(config,document)
    cfg,_=project_verified_semantic_config(requested)
    a=analyze_all(root,cfg)
    ms,_=analyze_multisource(root,cfg)
    a.issues.extend(ms.issues); a.candidates.extend(ms.candidates); a.relations.extend(ms.relations)
    a.candidates=list({c.candidate_id:c for c in a.candidates}.values())
    a.relations=list({str(r.get("relation_id")):r for r in a.relations if r.get("relation_id")}.values())
    a,_=apply_boundary_firewall(root,a,cfg)
    a,_=apply_robust_envelope_firewall(root,a,cfg)
    a,_=apply_semantic_claim_provenance_firewall(root,a,requested)
    a,_=apply_relation_falsification_firewall(root,a,cfg)
    # PASS036: final/local scoring must see only actions reachable through the scoped mutation
    # surface; otherwise bundle scoring could still reward a forbidden local candidate.
    a,_=apply_controllability_firewall(root,a,cfg)
    return a

def _bundle_score(documents: dict[str, Any], config: RepairConfig, cross: BundleAnalysis | None = None) -> tuple[int, int]:
    total = 0; hard = 0
    for document, root in sorted(documents.items()):
        z = _full_local_analysis(root, config, document)
        total += score(z.issues)
        hard += sum(1 for i in z.issues if i.severity == "error")
    cross = cross or analyze_bundle(documents, config)
    total += sum({"error": 10, "warning": 3, "info": 1}.get(i.issue.severity, 1) for i in cross.issues)
    hard += sum(1 for i in cross.issues if i.issue.severity == "error")
    return total, hard


def _delete_added(root: Any, c: Candidate) -> bool:
    toks = decode_pointer(c.path)
    cur = root
    try:
        for token in toks[:-1]:
            cur = cur[int(token)] if isinstance(cur, list) else cur[token]
        last = toks[-1]
        if isinstance(cur, dict) and last in cur and cur[last] == c.new_value:
            del cur[last]; return True
    except Exception:
        return False
    return False


def _apply_inverse(root: Any, c: Candidate) -> bool:
    from .jsonpatch_exact import apply_patch
    op=c.operation; meta=deepcopy(c.metadata or {}); path=c.path
    if op == "plan" and meta.get("inverse_steps"):
        inv={"operation":"plan","path":"","old_value":c.new_value,"new_value":c.old_value,"metadata":{"steps":deepcopy(meta["inverse_steps"])}}
    elif op == "replace":
        if meta.get("add_if_missing") and c.old_value is None:
            inv={"operation":"remove","path":path,"old_value":deepcopy(c.new_value),"new_value":None,"metadata":{"inverse_of":"replace-add"}}
        else:
            inv={"operation":"replace","path":path,"old_value":deepcopy(c.new_value),"new_value":deepcopy(c.old_value),"metadata":{"inverse_of":"replace"}}
    elif op == "add":
        ipath=path
        if ipath.endswith('/-'):
            parent_path=ipath[:-2]
            try: container=get(root,parent_path) if parent_path else root
            except Exception: return False
            if not isinstance(container,list) or not container: return False
            ipath=(parent_path+'/' if parent_path else '/')+str(len(container)-1)
        inv={"operation":"remove","path":ipath,"old_value":deepcopy(c.new_value),"new_value":None,"metadata":{"inverse_of":"add"}}
    elif op == "remove":
        inv={"operation":"add","path":path,"old_value":None,"new_value":deepcopy(c.old_value),"metadata":{"require_absent":True,"inverse_of":"remove"}}
    elif op == "move":
        src=str(meta.get("from_path") or '')
        if not src: return False
        inv={"operation":"move","path":src,"old_value":deepcopy(c.new_value),"new_value":deepcopy(c.old_value),"metadata":{"from_path":path,"inverse_of":"move"}}
    elif op == "copy":
        inv={"operation":"remove","path":path,"old_value":deepcopy(c.new_value),"new_value":None,"metadata":{"inverse_of":"copy"}}
    elif op == "test":
        inv={"operation":"test","path":path,"old_value":deepcopy(c.old_value),"new_value":deepcopy(c.new_value),"metadata":{"inverse_of":"test"}}
    else:
        return False
    ok,_=apply_patch(root,inv); return ok




def apply_bundle_patch_set(documents: dict[str, Any], patch_set: list[dict[str, Any]], *, inverse: bool = False) -> dict[str, Any]:
    """Apply a complete bundle patch set on a copy; fail without exposing a partial result.

    In inverse mode, patches are replayed in reverse order with old/new preconditions swapped.
    """
    trial = deepcopy(documents)
    edits = list(reversed(patch_set)) if inverse else list(patch_set)
    for edit in edits:
        document = edit.get("document")
        if document not in trial:
            raise ValueError(f"patch document missing: {document!r}")
        c = Candidate(**edit["candidate"])
        ok = _apply_inverse(trial[document], c) if inverse else _apply(trial[document], c)
        if not ok:
            mode = "inverse" if inverse else "forward"
            raise ValueError(f"bundle patch precondition failed ({mode}): {document}{c.path}")
    return trial

def _knowledge_relation_key(document: str | None, relation: dict[str, Any]) -> str:
    rid = relation.get("relation_id") or _relation_id(relation)
    return f"{document or '@bundle'}::{rid}"


def _constraint_graph(documents: dict[str, Any], cross: BundleAnalysis, config: RepairConfig) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    for document in sorted(documents):
        local = _full_local_analysis(documents[document], config, document)
        for rel in local.relations:
            base = rel.get("array_path", "")
            output = rel.get("output")
            out_field = output if output is not None else "__logic__"
            out_id = f"{document}:{base}#{out_field}"
            nodes[out_id] = {"id": out_id, "document": document, "array_path": base, "field": out_field}
            inputs = []
            for field in rel.get("inputs", []):
                nid = f"{document}:{base}#{field}"
                nodes[nid] = {"id": nid, "document": document, "array_path": base, "field": field}
                inputs.append(nid)
            edges.append({
                "relation_id": f"{document}::{rel['relation_id']}", "kind": rel["kind"],
                "inputs": inputs, "output": out_id, "confidence": rel.get("confidence"), "support": rel.get("support")
            })
    for rel in cross.relations:
        source = f"{rel['source_document']}:{rel['source_array_path']}#{rel['reference_field']}"
        target = f"{rel['target_document']}:{rel['target_array_path']}#{rel['target_id_field']}"
        nodes[source] = {"id": source, "document": rel["source_document"], "array_path": rel["source_array_path"], "field": rel["reference_field"]}
        nodes[target] = {"id": target, "document": rel["target_document"], "array_path": rel["target_array_path"], "field": rel["target_id_field"]}
        edges.append({
            "relation_id": f"@bundle::{rel['relation_id']}", "kind": rel["kind"],
            "inputs": [source], "output": target, "confidence": rel.get("confidence"), "support": rel.get("support")
        })
    return {"nodes": sorted(nodes.values(), key=lambda x: x["id"]), "edges": sorted(edges, key=lambda x: x["relation_id"])}




def _bundle_candidate_key(bc: BundleCandidate) -> tuple[str,str,str]:
    return (bc.document, bc.candidate.path, json.dumps(bc.candidate.new_value,ensure_ascii=False,sort_keys=True,separators=(",",":"),default=str))

def _bundle_parent(path:str) -> str:
    toks=decode_pointer(path)
    if len(toks)<=1: return ""
    return "/" + "/".join(str(t).replace("~","~0").replace("/","~1") for t in toks[:-1])

def _bundle_metric(xs:tuple[BundleCandidate,...]) -> tuple[Fraction,int,int,int]:
    cost=sum((Fraction(str(x.candidate.cost)) for x in xs),Fraction(0,1))
    paths=len({(x.document,x.candidate.path) for x in xs})
    valbytes=sum(len(json.dumps(x.candidate.new_value,ensure_ascii=False,sort_keys=True,separators=(",",":"),default=str).encode("utf-8")) for x in xs)
    depth=sum(len(decode_pointer(x.candidate.path)) for x in xs)
    return cost,paths,valbytes,depth

def _bundle_metric_public(m):
    return {"cost":{"numerator":m[0].numerator,"denominator":m[0].denominator},"changed_paths":m[1],"canonical_new_value_bytes":m[2],"path_depth_sum":m[3]}

def _bundle_objective(documents:dict[str,Any], config:RepairConfig, cross:BundleAnalysis, baseline_signatures:set[tuple]|None=None):
    total,hard=_bundle_score(documents,config,cross)
    repairable=sum(1 for i in cross.issues if i.issue.repairable)
    if baseline_signatures is None: surviving=len(cross.issues)
    else: surviving=sum(1 for i in cross.issues if (i.document,i.issue.signature()) in baseline_signatures)
    return hard,total,repairable,surviving

def _solve_cross_minimal_transfer(documents:dict[str,Any], cross:BundleAnalysis, config:RepairConfig):
    baseline_signatures={(i.document,i.issue.signature()) for i in cross.issues}
    baseline=_bundle_objective(documents,config,cross,baseline_signatures)
    # group identical proposals; cross analyzer currently has one family but keep the representation future-proof.
    uniq={}
    for bc in cross.candidates:
        uniq[_bundle_candidate_key(bc)]=bc
    clusters={}
    factorization_by_document={}
    bydoc=defaultdict(list)
    for bc in uniq.values(): bydoc[bc.document].append(bc)
    for doc,docopts in sorted(bydoc.items()):
        local_relations=[]
        for rel in cross.relations:
            if rel.get("source_document")!=doc: continue
            local_relations.append({"relation_id":rel.get("relation_id"),"kind":rel.get("kind"),
                "array_path":rel.get("source_array_path",""),"inputs":[rel.get("reference_field")],
                "output":rel.get("reference_field"),"confidence":rel.get("confidence"),"support":rel.get("support")})
        local_analysis=AnalysisResult([],[],local_relations)
        docclusters,fcert=factorize_options(documents[doc],local_analysis,docopts)
        factorization_by_document[doc]=fcert
        for bid,opts in docclusters.items(): clusters[(doc,bid)]=opts
    selected=[]; reports=[]; ambiguous=False; overflow=False; ambiguous_groups=[]
    for (doc,primary_block_id),opts in sorted(clusters.items()):
        scope=_bundle_parent(opts[0].candidate.path) if opts else ""
        if len(opts)>config.max_global_exact_options_per_cluster:
            overflow=True; reports.append({"document":doc,"scope":scope,"primary_block_id":primary_block_id,"status":"FRONTIER_TOO_LARGE","option_count":len(opts)}); continue
        evaluated=[]
        maxk=min(config.max_global_patch_size,len(opts))
        for k in range(1,maxk+1):
            for subset in combinations(opts,k):
                seen={} ; compatible=True
                for bc in subset:
                    key=(bc.document,bc.candidate.path); val=json.dumps(bc.candidate.new_value,sort_keys=True,default=str)
                    if key in seen and seen[key]!=val: compatible=False; break
                    seen[key]=val
                if not compatible: continue
                algebra_guard=candidate_set_admissibility(documents[doc],[bc.candidate for bc in subset])
                if not algebra_guard.get("admissible"): continue
                trial=deepcopy(documents); ok=True
                for bc in subset:
                    if not _apply(trial[bc.document],bc.candidate): ok=False; break
                if not ok: continue
                ac=analyze_bundle(trial,config); obj=_bundle_objective(trial,config,ac,baseline_signatures)
                if obj<baseline: evaluated.append((obj,_bundle_metric(subset),subset))
        if not evaluated:
            reports.append({"document":doc,"scope":scope,"primary_block_id":primary_block_id,"status":"NO_IMPROVING_TRANSFER","option_count":len(opts)}); continue
        bo=min(x[0] for x in evaluated); rows=[x for x in evaluated if x[0]==bo]; bm=min(x[1] for x in rows); finals=[x for x in rows if x[1]==bm]
        ids={tuple(_bundle_candidate_key(x) for x in z[2]) for z in finals}
        if len(ids)>1:
            ambiguous=True; ambiguous_groups.append([tuple(z[2]) for z in finals])
            reports.append({"document":doc,"scope":scope,"primary_block_id":primary_block_id,"status":"AMBIGUOUS_EXACT_MINIMUM","option_count":len(opts),"tie_count":len(ids),"best_objective":list(bo),"best_metric":_bundle_metric_public(bm)}); continue
        winner=finals[0][2]; selected.extend(winner)
        reports.append({"document":doc,"scope":scope,"primary_block_id":primary_block_id,"status":"UNIQUE_EXACT_MINIMUM","option_count":len(opts),"best_objective":list(bo),"best_metric":_bundle_metric_public(bm),"patches":[x.to_dict() for x in winner]})
    # union revalidation over full bundle
    dd={_bundle_candidate_key(x):x for x in selected}; union=tuple(dd[k] for k in sorted(dd)); patches=[]; status='NO_IMPROVING_TRANSFER'; union_obj=None; union_metric=None
    if union:
        trial=deepcopy(documents); ok=True
        for bc in union:
            if not _apply(trial[bc.document],bc.candidate): ok=False; break
        if ok:
            ac=analyze_bundle(trial,config); obj=_bundle_objective(trial,config,ac,baseline_signatures)
            if obj<baseline:
                patches=list(union); status='UNIQUE_EXACT_MINIMUM_PARTITIONED' if len(clusters)>1 else 'UNIQUE_EXACT_MINIMUM'; union_obj=obj; union_metric=_bundle_metric(union)
    parallel_routes=[]; parallel_overflow=False
    if ambiguous:
        if config.enable_parallel_tie_routes:
            theoretical=1
            for g in ambiguous_groups: theoretical*=max(1,len(g))
            if theoretical>config.max_parallel_tie_routes:
                parallel_overflow=True; status='PARALLEL_ROUTE_FRONTIER_TOO_LARGE'; patches=[]
            else:
                base=tuple(dd[k] for k in sorted(dd))
                seen_routes={}
                for combo in product(*ambiguous_groups):
                    parts=list(base)
                    for subset in combo: parts.extend(subset)
                    bykey={_bundle_candidate_key(x):x for x in parts}
                    route=tuple(bykey[k] for k in sorted(bykey))
                    ident=tuple(_bundle_candidate_key(x) for x in route)
                    seen_routes[ident]=route
                parallel_routes=[list(seen_routes[k]) for k in sorted(seen_routes)]
                status='AMBIGUOUS_EXACT_MINIMUM'; patches=[]
        else:
            status='AMBIGUOUS_EXACT_MINIMUM'; patches=[]
    if overflow and not patches and not ambiguous: status='FRONTIER_TOO_LARGE'
    symmetry_documents={}
    if parallel_routes:
        for doc in sorted({bc.document for route in parallel_routes for bc in route}):
            projected=[[bc.candidate for bc in route if bc.document==doc] for route in parallel_routes]
            projected=[r for r in projected if r]
            symmetry_documents[doc]=compile_symmetry_obstruction(documents[doc],projected,quotient_rules=_verified_quotient_rules(config))
        blocked=[d for d,c in symmetry_documents.items() if c.get("status")=="SYMMETRY_BLOCKED_REPAIR"]
        if config.enable_symmetry_obstruction and blocked:
            parallel_routes=[]; patches=[]; status='SYMMETRY_BLOCKED_REPAIR'
    cert={"solver_contract":"json-consistency-repair.bundle-minimal-transfer.v1","status":status,"baseline_objective":list(baseline),"objective_order":["hard_errors","severity_score","repairable_cross_terminals","surviving_preexisting_cross_terminals"],"metric_order":["cost","changed_paths","canonical_new_value_bytes","path_depth_sum"],"exact_metric":True,"clusters":reports,"selected_patch_count":len(patches),
          "partition_rule":"document_scoped_primary_relation_connected_components",
          "primary_factorization":{"contract":"json-consistency-repair.bundle-primary-factorization.v1","documents":factorization_by_document,
                                   "lossless":all((c.get("recomposition_proof") or {}).get("lossless") for c in factorization_by_document.values())},
          "symmetry_obstruction":{"contract":"json-consistency-repair.bundle-symmetry-obstruction.v1","documents":symmetry_documents},
          "parallel_route_contract":"json-consistency-repair.parallel-exact-routes.v1","parallel_route_count":len(parallel_routes),
          "parallel_route_state":"MATERIALIZED_FOR_RETURN_PROOF" if parallel_routes else "NONE","parallel_route_frontier_overflow":parallel_overflow}
    if union_obj is not None: cert['union_objective']=list(union_obj)
    if union_metric is not None: cert['union_metric']=_bundle_metric_public(union_metric)
    return patches,cert,parallel_routes



def _bundle_return_proof(documents:dict[str,Any], routes:list[list[BundleCandidate]], config:RepairConfig)->tuple[list[dict[str,Any]],dict[str,Any]]:
    frozen=bundle_digest(documents); rows=[]; chains={}
    if len(routes)>config.max_parallel_tie_routes:
        return [],{"contract":"json-consistency-repair.return-proof.v1","status":"PARALLEL_ROUTE_FRONTIER_TOO_LARGE","ok":False,"route_count":len(routes),"frozen_input_digest":frozen}
    for route in sorted(routes,key=lambda r:tuple(_bundle_candidate_key(x) for x in r)):
        identity=[_bundle_candidate_key(x) for x in route]
        rid=hashlib.sha256(json.dumps(identity,ensure_ascii=False,separators=(",",":"),default=str).encode()).hexdigest()
        prefix=[{"scope":"cross_document","document":bc.document,"target_document":bc.target_document,"candidate":bc.candidate.to_dict(),"acceptance":"parallel_route_prefix"} for bc in route]
        try: seed=apply_bundle_patch_set(documents,prefix)
        except ValueError:
            rows.append({"route_id":rid,"prefix_applied":False,"closed":False}); continue
        branch_cfg=RepairConfig(**{**config.__dict__,"enable_parallel_tie_routes":False,"enable_final_certification":False,"dry_run":False})
        final,res=repair_bundle(seed,branch_cfg)
        continuation=list(res.report.get("committed_patch_set") or [])
        chain=prefix+continuation
        try: replay=apply_bundle_patch_set(documents,chain); replay_ok=bundle_digest(replay)==bundle_digest(final)
        except ValueError: replay_ok=False
        fp=res.report.get("strong_fixed_point") or {}
        unresolved=sum(1 for c in res.report.get("cycles") or [] if ((c.get("cross_document_minimal_transfer") or {}).get("status")) in {'AMBIGUOUS_EXACT_MINIMUM','PARALLEL_ROUTE_FRONTIER_TOO_LARGE','SYMMETRY_BLOCKED_REPAIR'})
        closed=bool(fp.get("attained") and not fp.get("oscillation_detected") and unresolved==0 and replay_ok)
        row={"route_id":rid,"prefix_applied":True,"seed_digest":bundle_digest(seed),"closed":closed,"final_digest":bundle_digest(final),
             "semantic_quotient_digest":_bundle_semantic_quotient_digest(final,_verified_quotient_rules(config)),
             "remaining_issue_digest":hashlib.sha256(json.dumps(res.report.get("remaining_issues") or [],sort_keys=True,ensure_ascii=False,default=str,separators=(",",":")).encode()).hexdigest(),
             "relation_digest":hashlib.sha256(json.dumps(res.report.get("cross_document_relations") or [],sort_keys=True,ensure_ascii=False,default=str,separators=(",",":")).encode()).hexdigest(),
             "strong_fixed_point":bool(fp.get("attained")),"unresolved_ambiguity_cycles":unresolved,"replay_ok":replay_ok,"total_patch_count":len(chain)}
        rows.append(row); chains[rid]=chain
    finals={r.get("final_digest") for r in rows if r.get("final_digest")}; qfinals={r.get("semantic_quotient_digest") for r in rows if r.get("semantic_quotient_digest")}; issues={r.get("remaining_issue_digest") for r in rows if r.get("remaining_issue_digest")}; rels={r.get("relation_digest") for r in rows if r.get("relation_digest")}
    exact_eq=len(finals)==1 and len(chains)==len(rows)
    qcert=compile_semantic_quotient({},_verified_quotient_rules(config))
    quotient_eq=bool(qcert.get("rule_count") and len(qfinals)==1 and len(chains)==len(rows))
    ok=bool(rows and all(r.get("closed") for r in rows) and (exact_eq or quotient_eq) and len(issues)==1 and len(rels)==1 and len(chains)==len(rows))
    selected=min(chains) if ok else None
    rstatus="RETURN_PROOF_EQUIVALENT" if ok and exact_eq else ("RETURN_PROOF_QUOTIENT_EQUIVALENT" if ok and quotient_eq else "RETURN_PROOF_DIVERGENT")
    proof={"contract":"json-consistency-repair.return-proof.v1","parallel_contract":"json-consistency-repair.parallel-exact-routes.v1","mode":"bundle",
           "status":rstatus,"ok":ok,"frozen_input_digest":frozen,"route_count":len(rows),"routes":rows,
           "checks":{"all_routes_closed":bool(rows and all(r.get("closed") for r in rows)),"exact_terminal_equivalence":exact_eq,"semantic_quotient_terminal_equivalence":quotient_eq,"terminal_equivalence":bool(exact_eq or quotient_eq),"remaining_issue_equivalence":len(issues)==1,"relation_equivalence":len(rels)==1},
           "terminal_digest":next(iter(finals)) if len(finals)==1 else None,"semantic_quotient_terminal_digest":next(iter(qfinals)) if len(qfinals)==1 else None,"semantic_quotient":qcert,
           "selected_route_id":selected,"selection_rule":"lexicographically_smallest_route_id_after_exact_return_equivalence_only" if exact_eq else "lexicographically_smallest_route_id_after_explicit_semantic_quotient_equivalence"}
    tmp=dict(proof); proof["proof_sha256"]=hashlib.sha256(json.dumps(tmp,sort_keys=True,ensure_ascii=False,default=str,separators=(",",":")).encode()).hexdigest()
    return list(chains[selected]) if selected else [],proof


def _bundle_controllability_filter(documents: dict[str,Any], analysis: BundleAnalysis, config: RepairConfig):
    kept=[]; certs={}
    grouped=defaultdict(list)
    for bc in analysis.candidates:
        grouped[bc.document].append(bc)
    blocked_keys=set()
    extra_issues=[]
    for doc, rows in sorted(grouped.items()):
        if doc not in documents: continue
        scoped=_logic_config(config,doc)
        ar=AnalysisResult([], [x.candidate for x in rows], [])
        filtered,cert=apply_controllability_firewall(documents[doc],ar,scoped,document=doc)
        certs[doc]=cert
        allowed_ids={x.candidate_id for x in filtered.candidates}
        for bc in rows:
            if bc.candidate.candidate_id in allowed_ids:
                kept.append(bc)
            else:
                blocked_keys.add((bc.document,bc.candidate.candidate_id))
        for issue in filtered.issues:
            extra_issues.append(BundleIssue(doc,issue))
    # documents with no candidate still get an explicit unconstrained firewall surface later via local reports.
    out=BundleAnalysis(list(analysis.issues)+extra_issues,kept,list(analysis.relations),list(analysis.identity_registry))
    return out,certs


def _bundle_control_plan(documents: dict[str,Any], patches: list[BundleCandidate], config: RepairConfig, *, preserve_order: bool=False,
                         used_edits: int = 0, used_cost: int = 0):
    grouped=defaultdict(list)
    for bc in patches: grouped[bc.document].append(bc)
    plans={}; ordered=[]; ok=True
    for doc in sorted(grouped):
        scoped=_logic_config(config,doc)
        op,cert=compile_control_plan(documents[doc],[x.candidate for x in grouped[doc]],scoped,document=doc,preserve_order=preserve_order,
                                     used_edits=used_edits,used_cost=used_cost)
        plans[doc]=cert
        if cert.get("reachability")=="UNREACHABLE": ok=False
        byid={x.candidate.candidate_id:x for x in grouped[doc]}
        ordered.extend(byid[x.candidate_id] for x in op if x.candidate_id in byid)
    # max_control_* are bundle-wide upper bounds as well as document-local limits.
    total_edits=len(patches); total_cost=sum(max(0,int(x.candidate.cost)) for x in patches)
    if config.max_control_edits is not None and used_edits+total_edits>int(config.max_control_edits): ok=False
    if config.max_control_cost is not None and used_cost+total_cost>int(config.max_control_cost): ok=False
    cert={"contract":"json-consistency-repair.bundle-repair-controllability.v1","ok":ok,
          "status":"CONTROLLABLE" if ok else "IDENTIFIABLE_BUT_UNREACHABLE","documents":plans,
          "requested_action_count":total_edits,"requested_cost":total_cost,
          "budget_used_before":{"edits":used_edits,"cost":used_cost},
          "budget_projected":{"edits":used_edits+total_edits,"cost":used_cost+total_cost},
          "global_budget":{"max_edits":config.max_control_edits,"max_cost":config.max_control_cost}}
    cert["certificate_sha256"]=digest(cert)
    return (ordered if ok else []),cert

def repair_bundle(documents: dict[str, Any], config: RepairConfig | None = None) -> tuple[dict[str, Any], BundleRepairResult]:
    config = config or RepairConfig(); limits=config.security_limits
    if len(documents) > limits.max_bundle_documents:
        raise SecurityLimitError("max_bundle_documents", f"bundle document limit exceeded: {len(documents)} > {limits.max_bundle_documents}", observed=len(documents), limit=limits.max_bundle_documents)
    security_stats={name: validate_json_value(value, limits) for name,value in documents.items()}
    original = deepcopy(documents)
    current = deepcopy(documents)
    initial_digest = bundle_digest(original)
    initial_doc_digests = {k: digest(v) for k, v in sorted(original.items())}
    committed: list[dict[str, Any]] = []
    cycles: list[dict[str, Any]] = []
    knowledge: dict[str, Any] = {"relations": {}, "newly_certified": []}
    previous_relations: set[str] = set()
    stable = 0; strong_streak = 0
    previous_snapshot = None; previous_frontier = None
    visited_digests = {initial_digest}; any_oscillation = False
    required_strong = max(1, int(config.strong_fixed_point_cycles_required))
    bundle_materialization_cycles: list[dict[str, Any]] = []
    bundle_symmetry_documents: dict[str,list[dict[str,Any]]] = defaultdict(list)
    bundle_control_documents: dict[str,dict[str,list[dict[str,Any]]]] = defaultdict(lambda:{"firewall_cycles":[],"control_plan_cycles":[]})
    bundle_cross_control_cycles=[]
    bundle_falsification_documents: dict[str,list[dict[str,Any]]] = defaultdict(list)

    for cycle in range(1, config.max_cycles + 1):
        accepted: list[dict[str, Any]] = []
        rejected: list[dict[str, Any]] = []

        # Independent local attacks first. max_cycles=1 deliberately makes the bundle outer loop
        # responsible for re-analysis on the globally updated state.
        for document in sorted(current):
            scoped=_logic_config(config,document)
            used_cost=sum(max(0,int(((e.get("candidate") or {}).get("cost",1)))) for e in committed if isinstance(e,dict))
            _base_ed=max(0,int(config.control_budget_used_before_edits)); _base_cost=max(0,int(config.control_budget_used_before_cost))
            rem_edits=None if config.max_control_edits is None else max(0,int(config.max_control_edits)-(_base_ed+len(committed)))
            rem_cost=None if config.max_control_cost is None else max(0,int(config.max_control_cost)-(_base_cost+used_cost))
            local_cfg = RepairConfig(**{**scoped.__dict__, "max_cycles": 1, "stable_cycles_required": 1, "dry_run": False, "logic_document": document, "conservation_document": document, "system_document": document, "moment_document": document, "enable_final_certification": False,
                                        "max_control_edits":rem_edits,"max_control_cost":rem_cost})
            repaired, local_result = repair_object(current[document], local_cfg)
            lrc=local_result.report.get("repair_controllability") or {}
            bundle_control_documents[document]["firewall_cycles"].extend(deepcopy(lrc.get("firewall_cycles") or []))
            lrf=local_result.report.get("relation_falsification") or {}
            for fr in lrf.get("cycles") or []:
                if isinstance(fr,dict) and isinstance(fr.get("certificate"),dict):
                    bundle_falsification_documents[document].append({"cycle":cycle,"phase":fr.get("phase"),"certificate":deepcopy(fr["certificate"])})
            bundle_control_documents[document]["control_plan_cycles"].extend(deepcopy(lrc.get("control_plan_cycles") or []))
            if isinstance(lrc.get("final_firewall"),dict): bundle_control_documents[document]["final_firewall"]=deepcopy(lrc.get("final_firewall"))
            for sr in ((local_result.report.get("symmetry_canonicality") or {}).get("cycles") or []):
                if isinstance(sr,dict) and isinstance(sr.get("certificate"),dict):
                    bundle_symmetry_documents[document].append({"cycle":cycle,"certificate":deepcopy(sr["certificate"])})
            for mr in ((local_result.report.get("witness_materialization") or {}).get("cycles") or []):
                cert=deepcopy((mr or {}).get("certificate") or {})
                if cert:
                    bundle_materialization_cycles.append({"cycle":cycle,"document":document,"certificate":cert})
            if local_result.committed_edits:
                current[document] = repaired
                for cdict in local_result.report["committed_edits"]:
                    entry = {"scope": "local", "document": document, "candidate": cdict}
                    committed.append(entry); accepted.append(entry)

        cross = analyze_bundle(current, config)
        cross,cross_control_firewalls=_bundle_controllability_filter(current,cross,config)
        for doc,cert in cross_control_firewalls.items():
            bundle_control_documents[doc]["firewall_cycles"].append({"cycle":cycle,"phase":"cross_before","certificate":deepcopy(cert)})
        cross_patches,cross_certificate,cross_routes=_solve_cross_minimal_transfer(current,cross,config)
        cross_return_proof=None
        if cross_routes:
            route_chain,cross_return_proof=_bundle_return_proof(current,cross_routes,config)
            cross_certificate["return_proof"]={k:v for k,v in cross_return_proof.items() if k!="routes"}
            if cross_return_proof.get("ok"):
                used_cost=sum(max(0,int(((e.get("candidate") or {}).get("cost",1)))) for e in committed if isinstance(e,dict))
                route_chain,control_cert=_bundle_control_plan(current,route_chain,config,preserve_order=True,used_edits=max(0,int(config.control_budget_used_before_edits))+len(committed),used_cost=max(0,int(config.control_budget_used_before_cost))+used_cost)
                bundle_cross_control_cycles.append({"cycle":cycle,"certificate":control_cert})
                if not control_cert.get("ok"):
                    rejected.append({"reason":"IDENTIFIABLE_BUT_UNREACHABLE","solver_status":cross_return_proof.get("status"),"controllability_certificate_sha256":control_cert.get("certificate_sha256")})
                    route_chain=[]
                trial=apply_bundle_patch_set(current,route_chain)
                raw_ok=(cross_return_proof.get("terminal_digest") is not None and bundle_digest(trial)==cross_return_proof.get("terminal_digest"))
                quotient_ok=(cross_return_proof.get("status")=="RETURN_PROOF_QUOTIENT_EQUIVALENT" and _bundle_semantic_quotient_digest(trial,_verified_quotient_rules(config))==cross_return_proof.get("semantic_quotient_terminal_digest"))
                if raw_ok or quotient_ok:
                    current=trial
                    for entry in route_chain:
                        e=deepcopy(entry); e["acceptance"]="parallel_return_proof_quotient" if quotient_ok and not raw_ok else "parallel_return_proof_exact"; e["return_proof_sha256"]=cross_return_proof.get("proof_sha256"); e["selected_route_id"]=cross_return_proof.get("selected_route_id")
                        committed.append(e); accepted.append(e)
                else:
                    rejected.append({"reason":"RETURN_PROOF_REPLAY_MISMATCH","solver_status":cross_return_proof.get("status")})
            else:
                rejected.append({"reason":"parallel_return_proof_abstention","solver_status":cross_return_proof.get("status")})
        elif cross_patches:
            used_cost=sum(max(0,int(((e.get("candidate") or {}).get("cost",1)))) for e in committed if isinstance(e,dict))
            cross_patches,control_cert=_bundle_control_plan(current,cross_patches,config,preserve_order=False,used_edits=max(0,int(config.control_budget_used_before_edits))+len(committed),used_cost=max(0,int(config.control_budget_used_before_cost))+used_cost)
            bundle_cross_control_cycles.append({"cycle":cycle,"certificate":control_cert})
            if not control_cert.get("ok"):
                rejected.append({"reason":"IDENTIFIABLE_BUT_UNREACHABLE","solver_status":cross_certificate.get("status"),"controllability_certificate_sha256":control_cert.get("certificate_sha256")})
            trial=deepcopy(current); ok=bool(cross_patches)
            for bc in cross_patches:
                if not _apply(trial[bc.document],bc.candidate): ok=False; break
            if ok:
                before_score,_=_bundle_score(current,config,cross)
                after_cross=analyze_bundle(trial,config); after_score,_=_bundle_score(trial,config,after_cross)
                current=trial
                for bc in cross_patches:
                    entry={"scope":"cross_document","document":bc.document,"target_document":bc.target_document,"candidate":bc.candidate.to_dict(),"score_before":before_score,"score_after":after_score,"acceptance":"minimal_transfer_exact","solver_status":cross_certificate["status"]}
                    committed.append(entry); accepted.append(entry)
        elif cross.candidates:
            rejected.append({"reason":"cross_document_minimal_transfer_abstention","solver_status":cross_certificate["status"]})

        final_cross = analyze_bundle(current, config)
        cycle_local_analyses = {document: apply_authority_firewall(_full_local_analysis(current[document], config, document))[0] for document in sorted(current)}
        all_relations: list[tuple[str | None, dict[str, Any]]] = []
        for document in sorted(current):
            for rel in cycle_local_analyses[document].relations:
                all_relations.append((document, rel))
        for rel in final_cross.relations:
            all_relations.append((None, rel))
        current_relations = {_knowledge_relation_key(doc, rel) for doc, rel in all_relations}
        new_relations = sorted(current_relations - previous_relations)
        for doc, rel in all_relations:
            key = _knowledge_relation_key(doc, rel)
            qualified = {"scope": "cross_document" if doc is None else "local", "document": doc, "relation": rel}
            entry = knowledge["relations"].get(key)
            if entry is None:
                entry = {"qualified_relation": qualified, "first_seen_cycle": cycle, "last_seen_cycle": cycle, "seen_cycles": 1, "survives_current": True}
                knowledge["relations"][key] = entry
                knowledge["newly_certified"].append({"cycle": cycle, "relation_key": key, **qualified})
            else:
                entry["last_seen_cycle"] = cycle; entry["seen_cycles"] += 1; entry["qualified_relation"] = qualified; entry["survives_current"] = True
        for key, entry in knowledge["relations"].items():
            if key not in current_relations:
                entry["survives_current"] = False
        previous_relations = current_relations

        stable = 0 if accepted else stable + 1
        qualified_snapshot = {}
        for doc, rel in all_relations:
            key = _knowledge_relation_key(doc, rel)
            qualified_snapshot[key] = (str(rel.get("confidence","")), str(rel.get("support","")))
        delta = relation_delta(previous_snapshot, qualified_snapshot)
        frontier_rows=[]
        for doc,a in cycle_local_analyses.items():
            frontier_rows.extend((doc,c.path,json.dumps(c.new_value,sort_keys=True,ensure_ascii=False,default=str)) for c in a.candidates)
        frontier_rows.extend((bc.document,bc.candidate.path,json.dumps(bc.candidate.new_value,sort_keys=True,ensure_ascii=False,default=str)) for bc in final_cross.candidates)
        frontier_sig=hashlib.sha256(json.dumps(sorted(frontier_rows),ensure_ascii=False,separators=(",",":")).encode()).hexdigest()
        frontier_changed = previous_frontier is not None and frontier_sig != previous_frontier
        bd=bundle_digest(current); oscillation=bool(accepted and bd in visited_digests); any_oscillation = any_oscillation or oscillation; visited_digests.add(bd)
        strong_quiet=bool(not accepted and delta.get("quiet") and previous_frontier is not None and not frontier_changed and not oscillation)
        strong_streak = strong_streak + 1 if strong_quiet else 0
        cycles.append({
            "cycle": cycle, "accepted": accepted, "rejected": rejected,
            "bundle_digest": bd, "document_digests": {k: digest(v) for k, v in sorted(current.items())},
            "cross_document_issue_count": len(final_cross.issues), "cross_document_relation_count": len(final_cross.relations),
            "identity_registry_count": len(final_cross.identity_registry), "new_relations": new_relations, "stable_streak": stable,
            "strong_quiet": strong_quiet, "strong_fixed_point_streak": strong_streak, "relation_delta": delta,
            "candidate_frontier_signature": frontier_sig, "frontier_changed": frontier_changed, "oscillation": oscillation,
            "order_audit": {"order_independent": True, "scope": "bundle_partitioned_and_local_audits"},
            "cross_document_minimal_transfer": cross_certificate,
            "parallel_return_proof": cross_return_proof,
        })
        previous_snapshot=qualified_snapshot; previous_frontier=frontier_sig
        if strong_streak >= required_strong:
            break

    final_cross = analyze_bundle(current, config)
    final_local_analyses = {document: apply_authority_firewall(_full_local_analysis(current[document], config, document))[0] for document in sorted(current)}
    final_causal_documents = {document: {"double_cone": compile_double_cone(final_local_analyses[document]),
                                         "authority_firewall": apply_authority_firewall(analyze_all(current[document], _logic_config(config, document)))[1]}
                              for document in sorted(current)}
    remaining: list[dict[str, Any]] = []
    for document in sorted(current):
        for issue in final_local_analyses[document].issues:
            d = issue.to_dict(); d["document"] = document; d["scope"] = "local"; remaining.append(d)
    for bi in final_cross.issues:
        d = bi.to_dict(); d["scope"] = "cross_document"; remaining.append(d)

    strong_attained = strong_streak >= required_strong and not any_oscillation
    status = "PASS" if not remaining and strong_attained else ("STABLE_WITH_REPORTED_ISSUES" if strong_attained else "OPEN_REPAIRABLE")
    final_digest = bundle_digest(current)

    inverse_ok = True
    try:
        inverse = apply_bundle_patch_set(current, committed, inverse=True)
    except ValueError:
        inverse = deepcopy(current); inverse_ok = False
    replay_ok = inverse_ok and bundle_digest(inverse) == initial_digest

    bundle_federation_documents={}
    bundle_q_documents={}
    for document in sorted(current):
        fed_analysis,fed_cert,fed_q=federate_analysis(current[document],final_local_analyses[document],config)
        bundle_federation_documents[document]=fed_cert
        bundle_q_documents[document]=fed_q
    typed_ir = compile_bundle_typed_constraint_ir(current, final_local_analyses, final_cross)
    logic_relations=[(doc,r) for doc,a in final_local_analyses.items() for r in a.relations if str(r.get("kind","")).startswith("logic_") or r.get("kind")=="logic_exact"]
    logic_systems=[r for _,r in logic_relations if r.get("kind")=="logic_rule_system"]
    logic_summary={"contract":"json-consistency-repair.logic-summary.v1","relation_count":len(logic_relations),
                   "violation_count":sum(1 for a in final_local_analyses.values() for i in a.issues if i.analyzer=="logic_exact"),
                   "sat_systems":sum(1 for r in logic_systems if r.get("sat_status")=="SAT"),
                   "unsat_systems":sum(1 for r in logic_systems if r.get("sat_status")=="UNSAT"),
                   "documents_with_logic":sorted({doc for doc,_ in logic_relations})}
    conservation_relations=[(doc,r) for doc,a in final_local_analyses.items() for r in a.relations if "conservation" in str(r.get("kind","")) or r.get("kind") in {"aggregate_sum","aggregate_count","aggregate_sum_authoritative","aggregate_count_authoritative","balance_authoritative","multiset_balance_authoritative"}]
    conservation_summary={"contract":"json-consistency-repair.conservation-summary.v1","relation_count":len(conservation_relations),
                          "violation_count":sum(1 for a in final_local_analyses.values() for i in a.issues if i.analyzer=="conservation"),
                          "repairable_violation_count":sum(1 for a in final_local_analyses.values() for i in a.issues if i.analyzer=="conservation" and i.repairable),
                          "documents_with_conservation":sorted({doc for doc,_ in conservation_relations})}
    bundle_multisource_documents={}
    for document in sorted(current):
        mscfg=_logic_config(config,document)
        msa,mscert=analyze_multisource(current[document],mscfg)
        bundle_multisource_documents[document]={"summary":multisource_summary(msa,mscert),"certificate":mscert}

    bundle_robust_documents={}
    for document in sorted(current):
        rcfg=project_verified_semantic_config(_logic_config(config,document))[0]
        _,rcert=apply_robust_envelope_firewall(current[document],final_local_analyses[document],rcfg)
        bundle_robust_documents[document]={"final":rcert}

    bundle_semantic_documents={}
    for document in sorted(current):
        requested=_logic_config(config,document)
        scfg,_=project_verified_semantic_config(requested)
        # Re-run the semantic attribution audit on the final projected local analysis while
        # retaining the requested configuration in the certificate so gated claims stay visible.
        raw=analyze_all(current[document],scfg)
        ms,_=analyze_multisource(current[document],scfg)
        raw.issues.extend(ms.issues); raw.candidates.extend(ms.candidates); raw.relations.extend(ms.relations)
        raw,_=apply_boundary_firewall(current[document],raw,scfg)
        raw,_=apply_robust_envelope_firewall(current[document],raw,scfg)
        semraw,scert=apply_semantic_claim_provenance_firewall(current[document],raw,requested)
        bundle_semantic_documents[document]={"final":scert}
        _,fcert=apply_relation_falsification_firewall(current[document],semraw,scfg)
        bundle_falsification_documents[document].append({"cycle":"final","phase":"final","certificate":fcert})

    bundle_expression_documents={doc:expression_ir_summary(project_verified_semantic_config(_logic_config(config,doc))[0]) for doc in sorted(current)}
    bundle_repair_algebra_cycles=[]
    for doc in sorted(current):
        cert=compile_repair_path_algebra(current[doc],final_local_analyses[doc].candidates,max_actions=max(16,config.max_global_exact_options_per_cluster*2))
        bundle_repair_algebra_cycles.append({"document":doc,"certificate":cert})

    report = {
        **report_identity(status), "mode": "bundle",
        "security": {"limits": limits.to_dict(), "documents_validated": len(security_stats), "validation": security_stats, "atomic_publication": True},
        "input_digest": initial_digest, "output_digest": final_digest,
        "input_document_digests": initial_doc_digests,
        "output_document_digests": {k: digest(v) for k, v in sorted(current.items())},
        "cycles": cycles, "committed_patch_set": [] if config.dry_run else committed,
        "proposed_patch_set": committed if config.dry_run else [],
        "dry_run": bool(config.dry_run),
        "would_commit_edits": len(committed),
        "publication_performed": False if config.dry_run else None,
        "remaining_issues": remaining,
        "identity_registry": final_cross.identity_registry,"cross_document_minimal_transfer":cross_certificate,
        "witness_materialization":{"contract":"json-consistency-repair.witness-materialization.v1","mode":"bundle",
                                   "cycles":bundle_materialization_cycles,"final":None,
                                   "summary":materialization_summary(bundle_materialization_cycles,None)},
        "parallel_exact_minimum_routes":{"contract":"json-consistency-repair.parallel-exact-routes.v1","mode":"bundle",
                                           "cycles":[c.get("parallel_return_proof") for c in cycles if c.get("parallel_return_proof")],
                                           "return_proof_contract":"json-consistency-repair.return-proof.v1"},
        "cross_document_relations": final_cross.relations,
        "constraint_graph": _constraint_graph(current, final_cross, config),
        "typed_constraint_ir": typed_ir,
        "typed_expression_ir":{"contract":"json-consistency-repair.typed-expression-ir.v1","mode":"bundle","documents":bundle_expression_documents},
        "repair_path_algebra":{"contract":"json-consistency-repair.repair-path-algebra-summary.v1","mode":"bundle","cycles":bundle_repair_algebra_cycles},
        "symmetry_canonicality":{"contract":"json-consistency-repair.symmetry-canonicality-summary.v1","mode":"bundle","rules":list(_verified_quotient_rules(config)),"documents":dict(bundle_symmetry_documents),"cross_document":cross_certificate.get("symmetry_obstruction") if isinstance(cross_certificate,dict) else None},
        "repair_controllability":{"contract":"json-consistency-repair.repair-controllability-summary.v1","mode":"bundle","scope":"document_and_cross_document",
                                  "documents":dict(bundle_control_documents),"firewall_cycles":[],"control_plan_cycles":bundle_cross_control_cycles,
                                  "final_firewall":None,"explicitly_unconstrained":not bool(config.controllability_rules or config.require_explicit_mutation_permission or config.max_control_edits is not None or config.max_control_cost is not None)},
        "relation_falsification":{"contract":"json-consistency-repair.relation-falsification-summary.v1","mode":"bundle","scope":"document_local_inferred_relations",
                                  "documents":{doc:{"cycles":rows[:-1] if rows and rows[-1].get("phase")=="final" else rows,
                                                     "final":((rows[-1].get("certificate") if rows and rows[-1].get("phase")=="final" else None))}
                                               for doc,rows in sorted(bundle_falsification_documents.items())}},
        "terminal_registry": typed_ir["terminal_registry"],
        "truth_summary": typed_ir["truth_summary"],
        "identifiability_summary": typed_ir["identifiability_summary"],
        "cross_document_identifiability_registry": typed_ir["cross_document_identifiability_registry"],
        "logic_summary": logic_summary, "conservation_summary": conservation_summary,
        "moment_distribution_summary":{"contract":"json-consistency-repair.moment-distribution-summary.v1","documents":{doc:moment_summary(a) for doc,a in final_local_analyses.items()}},
        "system_graph_summary":{"contract":"json-consistency-repair.system-graph-state.v1","documents":{doc:system_summary(a) for doc,a in final_local_analyses.items()}},
        "causal_root_analysis":{"contract":"json-consistency-repair.causal-root-analysis.v1","documents":final_causal_documents,
                                "cross_document_scope":"REFERENCE_RELATIONS_REMAIN_SEPARATELY_CERTIFIED"},
        "federation_summary":{"contract":"json-consistency-repair.c189-federation-summary.v1","mode":"bundle","documents":bundle_federation_documents,
                              "cross_document_actor":"identifier_reference_bundle","cross_document_relation_count":len(final_cross.relations),
                              "multisource_relations_included":True},
        "multisource_assimilation":{"contract":"json-consistency-repair.multisource-assimilation.v1","mode":"bundle","documents":bundle_multisource_documents},
        "scoped_authority":{"contract":"json-consistency-repair.scoped-authority.v1","mode":"bundle","documents":{doc:((row.get("certificate") or {}).get("authority_scope_registry")) for doc,row in bundle_multisource_documents.items()}},
        "evidence_poisoning_firewall":{"contract":"json-consistency-repair.evidence-poisoning-firewall.v1","mode":"bundle","documents":{doc:((row.get("certificate") or {}).get("evidence_poisoning_firewall")) for doc,row in bundle_multisource_documents.items()}},
        "boundary_calculus":{"contract":"json-consistency-repair.boundary-calculus.v1","mode":"bundle","documents":{
            doc: boundary_summary(current[doc], final_local_analyses[doc], project_verified_semantic_config(_logic_config(config,doc))[0]) for doc in sorted(current)
        }},
        "robust_envelope":{"contract":"json-consistency-repair.robust-envelope.v1","mode":"bundle","documents":bundle_robust_documents},
        "semantic_claim_provenance":{"contract":"json-consistency-repair.semantic-claim-provenance-summary.v1","mode":"bundle","documents":bundle_semantic_documents},
        "dynamic_q_descent":{"contract":"json-consistency-repair.dynamic-q-descent.v1","mode":"bundle","documents":bundle_q_documents},
        "knowledge_ledger": knowledge,
        "strong_stable": strong_attained,
        "strong_fixed_point": {"contract":"json-consistency-repair.strong-fixed-point.v1","attained":strong_attained,
                               "required_quiet_cycles":required_strong,"quiet_streak":strong_streak,
                               "oscillation_detected":any_oscillation,"promotion_gate":"COLD_REPLAY_REQUIRED"},
        "transaction": {"semantic_all_or_none": True, "patch_count": 0 if config.dry_run else len(committed), "would_patch_count": len(committed), "inverse_restores_bundle": replay_ok},
        "replay": {"forward_digest": final_digest, "inverse_restores_input": replay_ok},
    }
    report["repair_controllability"]["run_budget"]={
        "max_edits":config.max_control_edits,"max_cost":config.max_control_cost,
        "used_before":{"edits":max(0,int(config.control_budget_used_before_edits)),"cost":max(0,int(config.control_budget_used_before_cost))},
        "used_this_run":{"edits":len(committed),"cost":sum(max(0,int(((e.get("candidate") or {}).get("cost",1)))) for e in committed if isinstance(e,dict))},
        "used_total":{"edits":max(0,int(config.control_budget_used_before_edits))+len(committed),
                      "cost":max(0,int(config.control_budget_used_before_cost))+sum(max(0,int(((e.get("candidate") or {}).get("cost",1)))) for e in committed if isinstance(e,dict))}
    }
    report["open_obligations"] = compile_open_obligation_registry(report)
    report["incremental_recompute"] = compile_incremental_recompute(
        report["open_obligations"], prior_registry=config.prior_open_obligation_registry,
        change_tokens=config.incremental_change_tokens, prior_proof_graph=config.prior_proof_graph)
    if config.enable_horizon_naturality:
        report["horizon_naturality"], report["distributed_consistency"] = compile_horizon_surface(
            report, original, current, prior_snapshot=config.prior_horizon_snapshot,
            change_tokens=config.horizon_change_tokens, boundary_witnesses=config.horizon_boundary_witnesses,
            distribution=config.distribution_descriptor or {"mode":"bundle","documents":len(current)},
            max_manifest_entries=max(64,int(config.horizon_manifest_limit)),
        )
    else:
        report["horizon_naturality"]={"contract":"json-consistency-repair.horizon-naturality.v1","disabled":True}
        report["distributed_consistency"]={"contract":"json-consistency-repair.distributed-consistency.v1","disabled":True}
    if config.enable_information_bounds:
        report["residual_information"], report["blind_carrier_reconstruction"] = compile_information_bundle_surface(
            current, {doc: final_local_analyses[doc].relations for doc in sorted(current)},
            symmetry_surface=report.get("symmetry_canonicality"),
            max_trials=max(1,int(config.blind_carrier_max_trials)),
        )
    else:
        report["residual_information"]={"contract":"json-consistency-repair.residual-information-summary.v1","disabled":True}
        report["blind_carrier_reconstruction"]={"contract":"json-consistency-repair.blind-carrier-reconstruction.v1","scope":"bundle_summary","disabled":True}
    report["provenance_chain"]=build_provenance_chain(input_digest=initial_digest,output_digest=final_digest,committed=committed,
                                                       cycles=cycles,code_digest=package_code_sha256(),mode="bundle")
    report["proof_graph"]=compile_proof_graph(report)
    if config.enable_final_certification:
        _cold_used_edits=max(0,int(config.control_budget_used_before_edits))+len(committed)
        _cold_used_cost=max(0,int(config.control_budget_used_before_cost))+sum(max(0,int(((e.get("candidate") or {}).get("cost",1)))) for e in committed if isinstance(e,dict))
        cold_cfg = RepairConfig(**{**config.__dict__, "enable_final_certification": False, "dry_run": True,
                                   "control_budget_used_before_edits":_cold_used_edits,
                                   "control_budget_used_before_cost":_cold_used_cost})
        cold_value, cold_res = repair_bundle(current, cold_cfg)
        report["cold_replay"]={"contract":"json-consistency-repair.cold-replay.v1","performed":True,"input_digest":final_digest,
                               "output_digest":cold_res.output_digest,"would_commit_edits":cold_res.report.get("would_commit_edits",0),
                               "strong_fixed_point_attained":bool((cold_res.report.get("strong_fixed_point") or {}).get("attained")),
                               "remaining_issue_count":cold_res.remaining_issues,"same_output":bundle_digest(cold_value)==final_digest}
        proof_cfg=RepairConfig(**{**config.__dict__,"enable_final_certification":False})
        proof_value,proof_res=repair_bundle(original,proof_cfg)
        pgr=compare_proof_graphs(report["proof_graph"],proof_res.report.get("proof_graph") or {})
        pgr["same_terminal_output"]=bundle_digest(proof_value)==final_digest
        pgr["replayed_output_digest"]=proof_res.output_digest
        pgr["ok"]=bool(pgr.get("ok") and pgr["same_terminal_output"])
        if not pgr["ok"]: pgr["status"]="PROOF_GRAPH_REPLAY_MISMATCH"
        report["proof_graph_replay"]=pgr
    else:
        report["cold_replay"]={"performed":False,"reason":"FINAL_CERTIFICATION_DISABLED"}
        report["proof_graph_replay"]={"contract":"json-consistency-repair.proof-graph-replay.v1","performed":False,"ok":False,"reason":"FINAL_CERTIFICATION_DISABLED"}
    report["incremental_equivalence"] = compile_incremental_equivalence(
        report["incremental_recompute"], report["proof_graph"], report["proof_graph_replay"], config.prior_proof_graph)
    report["rectification_packet"]=compile_rectification_packet(report)
    report["final_certification"]=__import__("json_consistency_repair.certifier", fromlist=["verify_report_evidence"]).verify_report_evidence(report) if config.enable_final_certification else {"status":"NOT_RUN","ok":False}
    if config.enable_final_certification:
        report["rectification_packet"]=seal_rectification_packet(report["rectification_packet"],report["final_certification"],report)
    report["certification_gate"]="PASS" if report["final_certification"].get("ok") else ("NOT_RUN" if not config.enable_final_certification else "FAIL")
    from .closure import compile_third_series_closure, compile_fourth_series_closure, compile_fifth_series_progress, compile_fifth_series_closure
    report["third_series_closure"]=compile_third_series_closure(report)
    report["fourth_series_closure"]=compile_fourth_series_closure(report)
    report["fifth_series_progress"]=compile_fifth_series_progress(report,40)
    report["fifth_series_closure"]=compile_fifth_series_closure(report)
    if config.open_obligation_store_path and config.enable_final_certification and (report.get("final_certification") or {}).get("ok"):
        save_open_obligation_registry(config.open_obligation_store_path, report["open_obligations"])
    return current, BundleRepairResult(status, len(cycles), 0 if config.dry_run else len(committed), len(remaining), initial_digest, final_digest, report)


def _safe_relative_json_files(input_dir: Path, pattern: str = "**/*.json") -> list[Path]:
    files=[]
    base=input_dir.resolve()
    for p in input_dir.glob(pattern):
        if p.is_symlink():
            raise SecurityLimitError("bundle_symlink", f"symlinked bundle input is not accepted: {p}", path=str(p))
        if not p.is_file(): continue
        try: p.resolve().relative_to(base)
        except ValueError as e: raise SecurityLimitError("bundle_path_escape", f"bundle path escapes input directory: {p}", path=str(p)) from e
        files.append(p)
    return sorted(files, key=lambda p: p.relative_to(input_dir).as_posix())


def _read_bundle_dir(input_dir: Path, config: RepairConfig, pattern: str) -> tuple[dict[str, Any], dict[str, list[dict[str, Any]]]]:
    docs: dict[str, Any] = {}; limits=config.security_limits
    syntax_repairs: dict[str, list[dict[str, Any]]] = {}
    files=_safe_relative_json_files(input_dir, pattern)
    if len(files) > limits.max_bundle_documents:
        raise SecurityLimitError("max_bundle_documents", f"bundle document limit exceeded: {len(files)} > {limits.max_bundle_documents}", observed=len(files), limit=limits.max_bundle_documents)
    sizes=[]
    for p in files:
        sizes.append(enforce_file_size(p, limits.max_document_bytes))
    if sum(sizes) > limits.max_bundle_bytes:
        raise SecurityLimitError("max_bundle_bytes", f"bundle byte limit exceeded: {sum(sizes)} > {limits.max_bundle_bytes}", observed=sum(sizes), limit=limits.max_bundle_bytes)
    for p in files:
        rel = p.relative_to(input_dir).as_posix()
        text = p.read_text(encoding="utf-8-sig")
        try:
            value = loads_strict(text, limits)
        except Exception:
            if not config.syntax_repair:
                raise
            value, repairs = conservative_syntax_repair(text, limits)
            if value is None:
                raise
            if repairs:
                syntax_repairs[rel] = repairs
        docs[rel] = value
    if not docs:
        raise ValueError(f"no JSON documents found in bundle directory: {input_dir}")
    return docs, syntax_repairs


def _publish_staged_bundle(documents: dict[str, Any], output_dir: Path, limits) -> None:
    parent = output_dir.parent
    parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}.stage-", dir=parent))
    backup: Path | None = None
    try:
        for rel in sorted(documents):
            # rel came from Path.relative_to and cannot escape, but keep the invariant explicit.
            pp = PurePosixPath(rel)
            if pp.is_absolute() or ".." in pp.parts:
                raise ValueError(f"unsafe bundle path: {rel}")
            target = stage.joinpath(*pp.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            dump_file(documents[rel], target)
        # Verify staged bytes parse before publication.
        for rel in sorted(documents):
            pp = PurePosixPath(rel); staged = stage.joinpath(*pp.parts)
            loads_strict(staged.read_text(encoding="utf-8"), limits)
        if output_dir.exists():
            backup = parent / f".{output_dir.name}.backup-{os.getpid()}"
            if backup.exists(): shutil.rmtree(backup)
            os.rename(output_dir, backup)
        os.rename(stage, output_dir)
        if backup and backup.exists(): shutil.rmtree(backup)
    except Exception:
        if output_dir.exists() and backup and backup.exists():
            shutil.rmtree(output_dir, ignore_errors=True)
            os.rename(backup, output_dir)
        elif backup and backup.exists() and not output_dir.exists():
            os.rename(backup, output_dir)
        shutil.rmtree(stage, ignore_errors=True)
        raise


def repair_bundle_dir(input_dir: str | Path, output_dir: str | Path | None = None, report_path: str | Path | None = None,
                      config: RepairConfig | None = None, pattern: str = "**/*.json") -> BundleRepairResult:
    config = config or RepairConfig()
    src = Path(input_dir)
    if not src.is_dir():
        raise NotADirectoryError(src)
    if output_dir:
        src_res=src.resolve(); out_res=Path(output_dir).resolve()
        if out_res == src_res or src_res in out_res.parents:
            raise ValueError("bundle output must be outside the input directory to preserve source immutability")
    documents, syntax_repairs = _read_bundle_dir(src, config, pattern)
    repaired, result = repair_bundle(documents, config)
    result.input_dir = str(src); result.output_dir = str(output_dir) if output_dir else None; result.report_path = str(report_path) if report_path else None
    if syntax_repairs:
        result.report["syntax_repairs"] = syntax_repairs
    result.report["filesystem_commit"] = {"strategy": "staged_directory_publish_with_rollback", "input_untouched": True, "published": bool(output_dir and not config.dry_run)}
    if output_dir and not config.dry_run:
        _publish_staged_bundle(repaired, Path(output_dir), config.security_limits)
    if report_path:
        Path(report_path).write_text(json.dumps(result.report, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")
    return result
