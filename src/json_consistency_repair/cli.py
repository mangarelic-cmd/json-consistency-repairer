from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from pathlib import Path

from ._version import __version__
from .engine import RepairConfig, repair_file
from .bundle import repair_bundle_dir
from .streaming import StreamingConfig, StreamingParseError, repair_stream_file
from .security import SecurityLimits, SecurityLimitError
from .io import DuplicateKeyError, loads_strict
from .provenance import EXIT_CODES, canonical_machine_json, machine_envelope, runtime_provenance
from .constraint_dsl import parse_dsl, ConstraintDSLError
from .persistent_open import load_open_obligation_registry, verify_open_obligation_registry
from .horizon import verify_horizon_snapshot


def _emit(payload: dict, machine: bool, *, stream=None) -> None:
    stream = stream or sys.stdout
    if machine:
        print(canonical_machine_json(payload), file=stream)
    else:
        print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False), file=stream)


def _result_payload(result, mode: str) -> dict:
    base = {
        "status": result.final_status,
        "cycles": result.cycles,
        "committed_edits": result.committed_edits,
        "remaining_issues": result.remaining_issues,
        "output_digest": result.output_digest,
        "dry_run": bool(result.report.get("dry_run", False)),
        "would_commit_edits": int(result.report.get("would_commit_edits", result.committed_edits)),
        "report_contract": result.report.get("report_contract"),
        "provenance": result.report.get("provenance"),
    }
    if mode == "streaming":
        base.update({"format": result.report["format"], "records": result.records, "peak_tracked_fields": result.peak_tracked_fields})
    return base


def _classify_error(exc: Exception) -> tuple[str, dict]:
    if isinstance(exc, SecurityLimitError):
        return "SECURITY_REFUSAL", {"type": type(exc).__name__, **exc.to_dict()}
    if isinstance(exc, (DuplicateKeyError, json.JSONDecodeError, StreamingParseError, ValueError)):
        return "INPUT_ERROR", {"type": type(exc).__name__, "code": getattr(exc, "code", "invalid_input"), "message": str(exc)}
    if isinstance(exc, (FileNotFoundError, PermissionError, OSError)):
        return "IO_ERROR", {"type": type(exc).__name__, "code": "io_error", "message": str(exc)}
    return "INTERNAL_ERROR", {"type": type(exc).__name__, "code": "internal_error", "message": str(exc)}



def _load_logic_rules(path: str | None, limits: SecurityLimits) -> tuple[dict, ...]:
    if not path:
        return ()
    p=Path(path)
    if p.stat().st_size > limits.max_document_bytes:
        raise ValueError("logic rule file exceeds JSON safety limit")
    value=loads_strict(p.read_text(encoding="utf-8-sig"), limits)
    if isinstance(value, dict):
        value=value.get("rules")
    if not isinstance(value, list):
        raise ValueError("logic rule file must be a JSON array or an object with a 'rules' array")
    if len(value)>256:
        raise ValueError("logic rule file exceeds 256-rule safety bound")
    if not all(isinstance(x,dict) for x in value):
        raise ValueError("every logic rule must be a JSON object")
    return tuple(dict(x) for x in value)


def _load_conservation_rules(path: str | None, limits: SecurityLimits) -> tuple[dict, ...]:
    if not path:
        return ()
    p=Path(path)
    if p.stat().st_size > limits.max_document_bytes:
        raise ValueError("conservation rule file exceeds JSON safety limit")
    value=loads_strict(p.read_text(encoding="utf-8-sig"), limits)
    if isinstance(value, dict):
        value=value.get("rules")
    if not isinstance(value, list):
        raise ValueError("conservation rule file must be a JSON array or an object with a 'rules' array")
    if len(value)>256:
        raise ValueError("conservation rule file exceeds 256-rule safety bound")
    allowed={"aggregate_sum","aggregate_count","balance","multiset_balance"}
    if not all(isinstance(x,dict) and x.get("kind") in allowed for x in value):
        raise ValueError("every conservation rule must be an object with kind aggregate_sum/aggregate_count/balance/multiset_balance")
    return tuple(dict(x) for x in value)





def _load_moment_rules(path: str | None, limits: SecurityLimits) -> tuple[dict, ...]:
    if not path: return ()
    p=Path(path)
    if p.stat().st_size > limits.max_document_bytes: raise ValueError("moment rule file exceeds JSON safety limit")
    value=loads_strict(p.read_text(encoding="utf-8-sig"), limits)
    if isinstance(value,dict): value=value.get("rules")
    if not isinstance(value,list): raise ValueError("moment rule file must be a JSON array or an object with a 'rules' array")
    if len(value)>256: raise ValueError("moment rule file exceeds 256-rule safety bound")
    allowed={"weighted_mean","weighted_sum","variance","covariance","probability_total","uncertainty_variance","unit_normalize"}
    if not all(isinstance(x,dict) and x.get("kind") in allowed for x in value):
        raise ValueError("every moment rule must have kind weighted_mean/weighted_sum/variance/covariance/probability_total/uncertainty_variance/unit_normalize")
    return tuple(dict(x) for x in value)


def _load_robust_envelope_rules(path: str | None, limits: SecurityLimits) -> tuple[dict, ...]:
    if not path: return ()
    p=Path(path)
    if p.stat().st_size > limits.max_document_bytes: raise ValueError("robust-envelope rule file exceeds JSON safety limit")
    value=loads_strict(p.read_text(encoding="utf-8-sig"), limits)
    evaluation_time=None
    if isinstance(value,dict):
        evaluation_time=value.get("evaluation_time"); value=value.get("rules")
    if not isinstance(value,list): raise ValueError("robust-envelope file must be an array or an object with a 'rules' array")
    if len(value)>256: raise ValueError("robust-envelope file exceeds 256-rule safety bound")
    allowed={"uncertainty_interval","clock_freshness","regime_guard","hysteresis"}
    out=[]
    for row in value:
        if not isinstance(row,dict) or row.get("kind") not in allowed: raise ValueError("invalid robust-envelope rule kind")
        rr=dict(row)
        if rr.get("kind")=="clock_freshness" and evaluation_time is not None and "evaluation_time" not in rr: rr["evaluation_time"]=evaluation_time
        out.append(rr)
    return tuple(out)

def _load_semantic_quotient_rules(path: str | None, limits: SecurityLimits) -> tuple[dict, ...]:
    if not path:
        return ()
    p=Path(path)
    if p.stat().st_size > limits.max_document_bytes:
        raise ValueError("semantic quotient file exceeds JSON safety limit")
    value=loads_strict(p.read_text(encoding="utf-8-sig"), limits)
    if isinstance(value,dict):
        value=value.get("rules")
    if not isinstance(value,list):
        raise ValueError("semantic quotient file must be a JSON array or an object with a 'rules' array")
    if len(value)>256:
        raise ValueError("semantic quotient file exceeds 256-rule safety bound")
    out=[]
    for row in value:
        if not isinstance(row,dict):
            raise ValueError("every semantic quotient rule must be an object")
        mode=str(row.get("equivalence") or row.get("mode") or "")
        path=str(row.get("path", ""))
        if mode not in {"unordered_array","unordered_unique_array"}:
            raise ValueError("semantic quotient equivalence must be unordered_array or unordered_unique_array")
        if path and not path.startswith("/"):
            raise ValueError("semantic quotient path must be a JSON Pointer or empty root pointer")
        if mode=="unordered_unique_array" and not bool(row.get("duplicates_are_semantically_irrelevant",False)):
            raise ValueError("unordered_unique_array requires duplicates_are_semantically_irrelevant=true")
        out.append(dict(row))
    return tuple(out)



def _load_controllability_rules(path: str | None, limits: SecurityLimits) -> tuple[dict, ...]:
    if not path: return ()
    p=Path(path)
    if p.stat().st_size > limits.max_document_bytes: raise ValueError("controllability rule file exceeds JSON safety limit")
    value=loads_strict(p.read_text(encoding="utf-8-sig"), limits)
    if isinstance(value,dict): value=value.get("rules")
    if not isinstance(value,list): raise ValueError("controllability file must be an array or an object with a 'rules' array")
    if len(value)>256: raise ValueError("controllability file exceeds 256-rule safety bound")
    out=[]
    for row in value:
        if not isinstance(row,dict): raise ValueError("every controllability rule must be an object")
        out.append(dict(row))
    return tuple(out)

def _load_system_rules(path: str | None, limits: SecurityLimits) -> tuple[dict, ...]:
    if not path:
        return ()
    p=Path(path)
    if p.stat().st_size > limits.max_document_bytes:
        raise ValueError("system rule file exceeds JSON safety limit")
    value=loads_strict(p.read_text(encoding="utf-8-sig"), limits)
    if isinstance(value, dict):
        value=value.get("rules")
    if not isinstance(value, list):
        raise ValueError("system rule file must be a JSON array or an object with a 'rules' array")
    if len(value)>256:
        raise ValueError("system rule file exceeds 256-rule safety bound")
    allowed={"graph","state_machine","migration"}
    if not all(isinstance(x,dict) and x.get("kind") in allowed for x in value):
        raise ValueError("every system rule must have kind graph/state_machine/migration")
    return tuple(dict(x) for x in value)



def _load_sources_manifest(path: str | None, limits: SecurityLimits) -> tuple[tuple[dict, ...], dict | None]:
    if not path:
        return (), None
    p=Path(path)
    if p.stat().st_size > limits.max_document_bytes:
        raise ValueError("source manifest exceeds JSON safety limit")
    manifest=loads_strict(p.read_text(encoding="utf-8-sig"), limits)
    if not isinstance(manifest,dict):
        raise ValueError("source manifest must be a JSON object")
    sources=manifest.get("sources") or []
    if not isinstance(sources,list) or len(sources)>limits.max_bundle_documents:
        raise ValueError("source manifest sources must be a bounded JSON array")
    hints=manifest.get("materialization_hints") or []
    if not isinstance(hints,list) or len(hints)>1024:
        raise ValueError("source manifest materialization_hints must be a bounded array of at most 1024 entries")
    loaded=[]; total=p.stat().st_size; seen=set()
    for row in sources:
        if not isinstance(row,dict): raise ValueError("every source descriptor must be an object")
        sid=str(row.get("source_id") or "").strip(); rel=row.get("path")
        if not sid or sid in seen: raise ValueError("source_id values must be non-empty and unique")
        seen.add(sid)
        if not isinstance(rel,str) or not rel: raise ValueError(f"source {sid!r} requires a path")
        sp=(p.parent / rel).resolve() if not Path(rel).is_absolute() else Path(rel)
        size=sp.stat().st_size
        if size>limits.max_document_bytes: raise ValueError(f"source {sid!r} exceeds JSON safety limit")
        total+=size
        if total>limits.max_bundle_bytes: raise ValueError("source manifest corpus exceeds bundle byte limit")
        value=loads_strict(sp.read_text(encoding="utf-8-sig"),limits)
        item={k:v for k,v in row.items() if k!="path"}; item["source_id"]=sid; item["source_path"]=str(sp); item["value"]=value
        loaded.append(item)
    public={k:v for k,v in manifest.items() if k!="sources"}
    public["sources"]=[{k:v for k,v in x.items() if k!="value"} for x in loaded]
    return tuple(loaded), public

def _load_constraint_rules(path: str | None, limits: SecurityLimits) -> tuple[dict, ...]:
    if not path: return ()
    p=Path(path)
    if p.stat().st_size > limits.max_document_bytes: raise ValueError("constraint file exceeds JSON safety limit")
    return parse_dsl(p.read_text(encoding="utf-8-sig"))


def _resolve_local_refs(schema: dict, document: dict, *, max_depth: int = 32) -> dict:
    def ptr(ref: str):
        if not ref.startswith('#/'): raise ValueError(f"only local schema refs are supported, got {ref!r}")
        cur=document
        for tok in ref[2:].split('/'):
            tok=tok.replace('~1','/').replace('~0','~')
            if not isinstance(cur,dict) or tok not in cur: raise ValueError(f"unresolved local schema ref {ref!r}")
            cur=cur[tok]
        if not isinstance(cur,dict): raise ValueError(f"schema ref {ref!r} does not target an object")
        return cur
    def rec(node, depth, stack):
        if depth>max_depth: raise ValueError("schema ref expansion exceeds depth bound")
        if isinstance(node,list): return [rec(x,depth+1,stack) for x in node]
        if not isinstance(node,dict): return node
        if isinstance(node.get('$ref'),str):
            ref=node['$ref']
            if ref in stack: raise ValueError(f"cyclic local schema ref {ref!r}")
            base=rec(ptr(ref),depth+1,stack+(ref,))
            merged=dict(base); merged.update({k:v for k,v in node.items() if k!='$ref'})
            return rec(merged,depth+1,stack+(ref,))
        return {k:rec(v,depth+1,stack) for k,v in node.items()}
    return rec(schema,0,())

def _load_schema(path: str | None, limits: SecurityLimits) -> dict | None:
    if not path: return None
    p=Path(path)
    if p.stat().st_size > limits.max_document_bytes: raise ValueError("schema file exceeds JSON safety limit")
    value=loads_strict(p.read_text(encoding="utf-8-sig"), limits)
    if not isinstance(value,dict): raise ValueError("JSON Schema must be a JSON object")
    return _resolve_local_refs(value,value)

def _load_openapi_schema(path: str | None, schema_name: str | None, limits: SecurityLimits) -> dict | None:
    if not path: return None
    p=Path(path)
    if p.stat().st_size > limits.max_document_bytes: raise ValueError("OpenAPI file exceeds JSON safety limit")
    value=loads_strict(p.read_text(encoding="utf-8-sig"), limits)
    if not isinstance(value,dict) or not isinstance(value.get("components"),dict): raise ValueError("OpenAPI JSON must contain components")
    schemas=value.get("components",{}).get("schemas",{})
    if not isinstance(schemas,dict) or not schemas: raise ValueError("OpenAPI JSON contains no components.schemas")
    if schema_name:
        if schema_name not in schemas: raise ValueError(f"OpenAPI schema {schema_name!r} not found")
        chosen=schemas[schema_name]
    elif len(schemas)==1: chosen=next(iter(schemas.values()))
    else: raise ValueError("OpenAPI has multiple schemas; use --openapi-schema")
    if not isinstance(chosen,dict): raise ValueError("selected OpenAPI schema is not an object")
    return _resolve_local_refs(chosen,value)

def _load_incremental_prior(registry_path: str | None, report_path: str | None, limits: SecurityLimits):
    if registry_path and report_path:
        raise ValueError("use either --resume-obligations or --incremental-prior-report, not both")
    if report_path:
        p=Path(report_path)
        if p.stat().st_size > limits.max_bundle_bytes:
            raise ValueError("incremental prior report exceeds safety limit")
        value=json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(value,dict):
            raise ValueError("incremental prior report must be a JSON object")
        reg=value.get("open_obligations")
        if not verify_open_obligation_registry(reg or {}):
            raise ValueError("incremental prior report has no valid OPEN obligation registry")
        pg=value.get("proof_graph")
        if pg is not None and not isinstance(pg,dict):
            raise ValueError("incremental prior report proof_graph must be an object")
        hs=((value.get("horizon_naturality") or {}).get("snapshot") if isinstance(value.get("horizon_naturality"),dict) else None)
        if hs is not None and not verify_horizon_snapshot(hs):
            raise ValueError("incremental prior report has an invalid horizon snapshot")
        return reg, pg, hs
    if registry_path:
        return load_open_obligation_registry(registry_path), None, None
    return None, None, None


def _parser() -> argparse.ArgumentParser:
    p=argparse.ArgumentParser(prog="json-consistency-repair")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--machine", action="store_true", help="emit one canonical JSON object and use documented status exit codes")
    p.add_argument("--debug", action="store_true", help="re-raise unexpected exceptions after classification")
    p.add_argument("--provenance", action="store_true", help="print installed engine provenance and exit")
    p.add_argument("--explain-exit-codes", action="store_true", help="print the stable machine exit-code table and exit")
    p.add_argument("input", nargs="?", help="JSON file, JSONL/NDJSON stream, top-level JSON array, or bundle directory")
    p.add_argument("-o","--output", help="output file, or output directory in bundle mode")
    p.add_argument("--report")
    p.add_argument("--bundle", action="store_true", help="treat input as a directory bundle of JSON documents")
    p.add_argument("--bundle-glob", default="**/*.json", help="glob used inside bundle directories (default: **/*.json)")
    p.add_argument("--stream", action="store_true", help="bounded-memory record streaming; auto-enabled for .jsonl/.ndjson")
    p.add_argument("--stream-format", choices=("jsonl","array"), help="force JSONL or top-level array streaming format")
    p.add_argument("--max-tracked-fields", type=int, default=64)
    p.add_argument("--max-functional-groups", type=int, default=256)
    defaults=SecurityLimits()
    p.add_argument("--max-depth", type=int, default=defaults.max_depth)
    p.add_argument("--max-document-bytes", type=int, default=defaults.max_document_bytes)
    p.add_argument("--max-record-bytes", type=int, default=defaults.max_record_bytes)
    p.add_argument("--max-record-nodes", type=int, default=defaults.max_record_nodes)
    p.add_argument("--max-bundle-documents", type=int, default=defaults.max_bundle_documents)
    p.add_argument("--max-bundle-bytes", type=int, default=defaults.max_bundle_bytes)
    p.add_argument("--dry-run",action="store_true")
    p.add_argument("--mode", choices=("full","fast"), default="full", help="full = exhaustive correction/certification; fast = scan all analyzers, repair only uniquely local cones")
    p.add_argument("--max-cycles",type=int,default=8)
    p.add_argument("--stable-cycles",type=int,default=2)
    p.add_argument("--independent-evidence",type=int,default=1)
    p.add_argument("--no-syntax-repair",action="store_true")
    p.add_argument("--logic-rules", help="JSON file with exact authoritative logic rules (implies/xor/exactly_one/one_of/any_of/not_both)")
    p.add_argument("--conservation-rules", help="JSON file with authoritative conservation rules (aggregate_sum/aggregate_count/balance/multiset_balance)")
    p.add_argument("--constraints", help="compact authoritative constraint DSL file")
    p.add_argument("--json-schema", help="authoritative JSON Schema file (JSON)")
    p.add_argument("--openapi", help="authoritative OpenAPI document (JSON); uses components.schemas")
    p.add_argument("--openapi-schema", help="component schema name when --openapi contains multiple schemas")
    p.add_argument("--system-rules", help="optional graph/state-machine/ordered-migration rules JSON")
    p.add_argument("--moment-rules", help="weighted aggregate/moment/distribution/unit rules JSON")
    p.add_argument("--sources-manifest", help="multi-source context manifest (defaults/previous/development/heldout/authoritative/event_log)")
    p.add_argument("--robust-envelope", help="uncertainty/clock/regime/hysteresis robust-envelope rules JSON")
    p.add_argument("--semantic-quotient", help="explicit harmless representation freedoms (unordered arrays / explicit unique-set arrays)")
    p.add_argument("--controllability", help="mutation permissions, immutability, budgets and precedence rules JSON")
    p.add_argument("--require-explicit-mutation-permission", action="store_true", help="deny mutation paths not covered by a controllability rule")
    p.add_argument("--max-control-edits", type=int)
    p.add_argument("--max-control-cost", type=int)
    p.add_argument("--open-obligation-store", help="persist the certified PASS038 OPEN-obligation registry atomically")
    p.add_argument("--resume-obligations", help="load a prior PASS038 OPEN-obligation registry")
    p.add_argument("--incremental-prior-report", help="load prior report registry + proof graph for targeted invalidation")
    p.add_argument("--incremental-change-token", action="append", default=[], help="explicit wake token such as path:/x, source:*, permission:/x; repeatable")
    p.add_argument("--horizon-change-token", action="append", default=[], help="explicit PASS039 boundary-change token; repeatable")
    return p


def main(argv=None) -> int:
    p=_parser(); a=p.parse_args(argv)
    if a.explain_exit_codes:
        payload={"contract":"json-consistency-repair.machine.v1","exit_codes":EXIT_CODES}
        _emit(payload, a.machine); return 0
    if a.provenance:
        _emit({"contract":"json-consistency-repair.provenance.v1","provenance":runtime_provenance()}, a.machine); return 0
    if not a.input:
        p.error("input is required unless --provenance or --explain-exit-codes is used")

    defaults=SecurityLimits()
    limits=replace(defaults, max_depth=a.max_depth, max_document_bytes=a.max_document_bytes, max_record_bytes=a.max_record_bytes,
                   max_record_nodes=a.max_record_nodes, max_bundle_documents=a.max_bundle_documents, max_bundle_bytes=a.max_bundle_bytes)
    inpath=Path(a.input); mode=None
    try:
        logic_rules=_load_logic_rules(a.logic_rules, limits)
        conservation_rules=_load_conservation_rules(a.conservation_rules, limits)
        moment_rules=_load_moment_rules(a.moment_rules, limits)
        source_context,source_manifest=_load_sources_manifest(a.sources_manifest, limits)
        robust_envelope_rules=_load_robust_envelope_rules(a.robust_envelope, limits)
        semantic_quotient_rules=_load_semantic_quotient_rules(a.semantic_quotient, limits)
        controllability_rules=_load_controllability_rules(a.controllability, limits)
        constraint_rules=_load_constraint_rules(a.constraints, limits)
        system_rules=_load_system_rules(a.system_rules, limits)
        schema=_load_schema(a.json_schema, limits)
        openapi_schema=_load_openapi_schema(a.openapi, a.openapi_schema, limits)
        if schema is not None and openapi_schema is not None: raise ValueError("use either --json-schema or --openapi, not both")
        authoritative_schema=schema if schema is not None else openapi_schema
        schema_source="json_schema" if schema is not None else ("openapi" if openapi_schema is not None else None)
        prior_open_registry, prior_proof_graph, prior_horizon_snapshot = _load_incremental_prior(a.resume_obligations, a.incremental_prior_report, limits)
        incremental_change_tokens=tuple(sorted(set(a.incremental_change_token or [])))
        horizon_change_tokens=tuple(sorted(set((a.horizon_change_token or []) + list(incremental_change_tokens))))
        stream_auto=inpath.suffix.lower() in {".jsonl",".ndjson"}
        if a.stream or stream_auto:
            mode="streaming"
            if a.dry_run: raise ValueError("--dry-run is not exposed in streaming mode; use a separate output path")
            cfg=StreamingConfig(max_cycles=a.max_cycles,stable_cycles_required=a.stable_cycles,max_tracked_fields=a.max_tracked_fields,max_functional_groups=a.max_functional_groups,security_limits=limits,
                                logic_rules=logic_rules,conservation_rules=conservation_rules,moment_rules=moment_rules,
                                constraint_rules=constraint_rules,json_schema=authoritative_schema,schema_source=schema_source,system_rules=system_rules,
                                source_context=source_context,source_manifest=source_manifest,robust_envelope_rules=robust_envelope_rules,
                                semantic_quotient_rules=semantic_quotient_rules,controllability_rules=controllability_rules,
                                require_explicit_mutation_permission=a.require_explicit_mutation_permission,max_control_edits=a.max_control_edits,max_control_cost=a.max_control_cost,exact_disk_registry=True,
                                prior_open_obligation_registry=prior_open_registry,prior_proof_graph=prior_proof_graph,incremental_change_tokens=incremental_change_tokens,
                                prior_horizon_snapshot=prior_horizon_snapshot,horizon_change_tokens=horizon_change_tokens,
                                open_obligation_store_path=a.open_obligation_store)
            r=repair_stream_file(a.input,a.output,a.report,cfg,stream_format=a.stream_format)
        else:
            cfg=RepairConfig(max_cycles=a.max_cycles,stable_cycles_required=a.stable_cycles,require_independent_evidence=a.independent_evidence,dry_run=a.dry_run,syntax_repair=not a.no_syntax_repair,execution_mode=a.mode,security_limits=limits,logic_rules=logic_rules,conservation_rules=conservation_rules,constraint_rules=constraint_rules,json_schema=authoritative_schema,schema_source=schema_source,system_rules=system_rules,moment_rules=moment_rules,source_context=source_context,source_manifest=source_manifest,robust_envelope_rules=robust_envelope_rules,
                             semantic_quotient_rules=semantic_quotient_rules,controllability_rules=controllability_rules,
                             require_explicit_mutation_permission=a.require_explicit_mutation_permission,max_control_edits=a.max_control_edits,max_control_cost=a.max_control_cost,
                             prior_open_obligation_registry=prior_open_registry,prior_proof_graph=prior_proof_graph,incremental_change_tokens=incremental_change_tokens,
                             prior_horizon_snapshot=prior_horizon_snapshot,horizon_change_tokens=horizon_change_tokens,
                             open_obligation_store_path=a.open_obligation_store)
            if a.bundle or inpath.is_dir():
                mode="bundle"; r=repair_bundle_dir(a.input,a.output,a.report,cfg,a.bundle_glob)
            else:
                mode="single"; r=repair_file(a.input,a.output,a.report,cfg)
        result=_result_payload(r, mode)
        env=machine_envelope(status=r.final_status, mode=mode, result=result)
        _emit(env, a.machine)
        return EXIT_CODES[r.final_status]
    except Exception as exc:
        status,error=_classify_error(exc)
        env=machine_envelope(status=status, mode=mode, error=error)
        _emit(env, a.machine, stream=sys.stderr)
        if a.debug and status == "INTERNAL_ERROR":
            raise
        return EXIT_CODES[status]


if __name__ == "__main__":
    raise SystemExit(main())
