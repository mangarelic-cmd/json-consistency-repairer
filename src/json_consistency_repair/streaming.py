from __future__ import annotations

from collections import Counter, defaultdict
from copy import deepcopy
from dataclasses import asdict, dataclass, field
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Iterator
import hashlib
import json
import os
import shutil
import tempfile
import sqlite3
from itertools import product

from .models import canonical_bytes, pointer, Candidate, AnalysisResult, digest
from .tree import decode_pointer
from .io import strict_decoder, DuplicateKeyError
from .security import SecurityLimits, SecurityLimitError, validate_json_value, preflight_json_text
from .provenance import report_identity, package_code_sha256
from .constraint_ir import compile_stream_typed_constraint_ir
from ._version import __version__
from .fixedpoint import relation_delta
from .provenance_chain import build_provenance_chain
from .logic_exact import evaluate_rule, repair_candidates_for_rule, rule_system_certificate, stable_rule_id
from .moments import stable_moment_id, evaluate_moment_rule, _json_num
from .federation import compile_stream_federation
from .boundary import compile_boundary_registry
from .proof_graph import compile_proof_graph, compare_proof_graphs
from .rectification_packet import compile_rectification_packet, seal_rectification_packet
from .semantic_provenance import project_verified_semantic_config, preanalysis_as_firewall
from .expression_ir import expression_ir_summary
from .controllability import apply_controllability_firewall, compile_control_plan
from .persistent_open import (compile_open_obligation_registry, compile_incremental_recompute,
    compile_incremental_equivalence, save_open_obligation_registry)
from .horizon import compile_horizon_surface
from .information_bounds import compile_information_surface
from .conservation import (
    stable_conservation_id, aggregate_target_hint, evaluate_conservation_rule,
    conservation_rule_patch, sum_child_values, child_count,
)


@dataclass
class StreamingConfig:
    max_cycles: int = 6
    stable_cycles_required: int = 2
    min_support: int = 4
    min_group_support: int = 3
    relation_confidence: float = 0.95
    arithmetic_confidence: float = 0.95
    arithmetic_direction_confidence: float = 0.90
    enum_normalization_confidence: float = 0.75
    required_key_confidence: float = 0.95
    max_tracked_fields: int = 64
    max_relation_fields: int = 12
    max_numeric_fields: int = 10
    max_functional_groups: int = 256
    min_functional_groups: int = 2
    enum_max_values: int = 32
    issue_sample_limit: int = 50
    chunk_bytes: int = 65536
    security_limits: SecurityLimits = field(default_factory=SecurityLimits)
    logic_rules: tuple[dict[str, Any], ...] = ()
    conservation_confidence: float = 0.95
    conservation_min_support: int = 4
    conservation_min_distinct_aggregates: int = 2
    conservation_direction_confidence: float = 0.90
    conservation_rules: tuple[dict[str, Any], ...] = ()
    moment_rules: tuple[dict[str, Any], ...] = ()
    strong_fixed_point_cycles_required: int = 2
    enable_final_certification: bool = True
    enable_parallel_tie_routes: bool = True
    max_parallel_tie_routes: int = 16
    modal_min_regime_support: int = 2
    modal_max_regimes: int = 8
    enable_federation: bool = True
    federation_max_cycles: int = 4
    federation_quiet_cycles_required: int = 2
    federation_max_pairwise_objects: int = 256
    federation_max_hyperobjects: int = 256
    federation_max_composites: int = 128
    # PASS024 exact disk-backed layer. These bridges are evaluated record-by-record
    # while cross-record functional tables spill to SQLite instead of being discarded.
    exact_disk_registry: bool = False
    constraint_rules: tuple[dict[str, Any], ...] = ()
    json_schema: dict[str, Any] | None = None
    schema_source: str | None = None
    system_rules: tuple[dict[str, Any], ...] = ()
    source_context: tuple[dict[str, Any], ...] = ()
    source_manifest: dict[str, Any] | None = None
    source_min_support: int = 4
    source_min_group_support: int = 2
    source_max_fields: int = 8
    robust_envelope_rules: tuple[dict[str, Any], ...] = ()
    enable_semantic_claim_provenance: bool = True
    schema_claim_provenance: dict[str, Any] | None = None
    enable_symmetry_obstruction: bool = True
    semantic_quotient_rules: tuple[dict[str, Any], ...] = ()
    enable_controllability: bool = True
    enable_relation_falsifier: bool = True
    falsifier_min_rows: int = 4
    falsifier_max_relations: int = 256
    falsifier_max_negative_controls: int = 8
    controllability_rules: tuple[dict[str, Any], ...] = ()
    require_explicit_mutation_permission: bool = False
    max_control_edits: int | None = None
    max_control_cost: int | None = None
    control_budget_used_before_edits: int = 0
    control_budget_used_before_cost: int = 0
    enable_persistent_open_obligations: bool = True
    prior_open_obligation_registry: dict[str, Any] | None = None
    prior_proof_graph: dict[str, Any] | None = None
    incremental_change_tokens: tuple[str, ...] = ()
    open_obligation_store_path: str | None = None
    enable_horizon_naturality: bool = True
    prior_horizon_snapshot: dict[str, Any] | None = None
    horizon_change_tokens: tuple[str, ...] = ()
    horizon_boundary_witnesses: tuple[dict[str, Any], ...] = ()
    distribution_descriptor: dict[str, Any] | None = None
    horizon_manifest_limit: int = 4096
    enable_information_bounds: bool = True
    blind_carrier_max_trials: int = 64


@dataclass
class StreamRepairResult:
    input_path: str
    output_path: str | None
    report_path: str | None
    final_status: str
    cycles: int
    committed_edits: int
    remaining_issues: int
    records: int
    input_digest: str
    output_digest: str
    peak_tracked_fields: int
    report: dict[str, Any]


@dataclass
class _Envelope:
    index: int
    value: Any
    raw: str | None = None


class StreamingParseError(ValueError):
    pass


def _semantic_stream_digest_init():
    return hashlib.sha256()


def _semantic_stream_digest_update(h, value: Any) -> None:
    raw = canonical_bytes(value)
    h.update(len(raw).to_bytes(8, "big"))
    h.update(raw)


def _leaf_items(value: Any, parts: list[str | int] | None = None) -> list[tuple[str, Any, int]]:
    """Scalar dict-leaf paths for record-level inference; arrays are values, not row dimensions."""
    parts = parts or []
    out: list[tuple[str, Any, int]] = []
    order = 0

    def rec(v: Any, p: list[str | int]):
        nonlocal order
        if isinstance(v, dict):
            for k, x in v.items():
                rec(x, p + [k])
        elif isinstance(v, list):
            # Lists can carry complex local structure; PASS005 does not infer cross-record scalar laws through them.
            return
        else:
            out.append((pointer(p), v, order)); order += 1

    rec(value, parts)
    return out


def _get_path(root: Any, path: str) -> tuple[bool, Any]:
    cur = root
    try:
        for token in decode_pointer(path):
            if isinstance(cur, list):
                idx = int(token)
                if idx < 0 or idx >= len(cur): return False, None
                cur = cur[idx]
            elif isinstance(cur, dict):
                if token not in cur: return False, None
                cur = cur[token]
            else:
                return False, None
        return True, cur
    except (ValueError, TypeError):
        return False, None


def _set_path(root: Any, path: str, old: Any, new: Any, *, add_if_missing: bool = False) -> bool:
    toks = decode_pointer(path)
    if not toks: return False
    cur = root
    try:
        for token in toks[:-1]:
            if isinstance(cur, list):
                cur = cur[int(token)]
            elif isinstance(cur, dict) and token in cur:
                cur = cur[token]
            else:
                return False
        last = toks[-1]
        if isinstance(cur, list):
            idx = int(last)
            if idx >= len(cur) or cur[idx] != old: return False
            cur[idx] = new; return True
        if not isinstance(cur, dict): return False
        if last not in cur:
            if add_if_missing:
                cur[last] = new; return True
            return False
        if cur[last] != old: return False
        cur[last] = new; return True
    except (ValueError, TypeError, KeyError, IndexError):
        return False


def _delete_added(root: Any, path: str, new: Any) -> bool:
    toks = decode_pointer(path)
    if not toks: return False
    cur = root
    try:
        for token in toks[:-1]:
            cur = cur[int(token)] if isinstance(cur, list) else cur[token]
        last = toks[-1]
        if isinstance(cur, dict) and last in cur and cur[last] == new:
            del cur[last]; return True
    except (ValueError, TypeError, KeyError, IndexError):
        pass
    return False


def _decimal(v: Any) -> Decimal | None:
    if isinstance(v, bool) or v is None: return None
    try:
        if isinstance(v, Decimal): return v
        if isinstance(v, int): return Decimal(v)
        if isinstance(v, float): return Decimal(str(v))
        if isinstance(v, str):
            s = v.strip()
            if not s: return None
            return Decimal(s)
    except (InvalidOperation, ValueError):
        return None
    return None


def _number_like(x: Decimal, examples: list[Any]) -> Any:
    # Preserve an observed numeric representation when it is unambiguous enough.
    kinds = Counter("str" if isinstance(v, str) else "int" if isinstance(v, int) and not isinstance(v, bool) else "float" if isinstance(v, float) else "other" for v in examples)
    kind = kinds.most_common(1)[0][0] if kinds else "float"
    if kind == "str": return format(x, "f")
    if kind == "int" and x == x.to_integral_value(): return int(x)
    return float(x)


def _jkey(v: Any) -> str:
    return json.dumps(v, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _rid(payload: dict[str, Any]) -> str:
    ident = {k: v for k, v in payload.items() if k not in {"confidence", "support", "direction_confidence", "direction_seen"}}
    return hashlib.sha1(json.dumps(ident, sort_keys=True, default=str, separators=(",", ":")).encode()).hexdigest()[:20]


def _misra_gries_update(counters: dict[str, int], keys: set[str], capacity: int) -> None:
    for key in sorted(keys):
        if key in counters:
            counters[key] += 1
        elif len(counters) < capacity:
            counters[key] = 1
        else:
            dead = []
            for k in list(counters):
                counters[k] -= 1
                if counters[k] <= 0: dead.append(k)
            for k in dead: del counters[k]



class _DiskFunctionalRegistry:
    """SQLite-backed exact functional map used only after an in-memory pair overflows.

    SQLite is part of the Python standard library. The registry is an ephemeral execution
    artifact: report material contains only its deterministic semantic summary, never its path.
    """
    def __init__(self, directory: Path | None = None):
        if directory is None:
            fd, name = tempfile.mkstemp(prefix="json-consistency-registry-", suffix=".sqlite3")
            os.close(fd); self.path = Path(name); self._owned = True
        else:
            directory.mkdir(parents=True, exist_ok=True)
            self.path = directory / "functional-registry.sqlite3"; self._owned = False
            if self.path.exists(): self.path.unlink()
        self.conn = sqlite3.connect(str(self.path))
        self.conn.execute("PRAGMA journal_mode=OFF")
        self.conn.execute("PRAGMA synchronous=OFF")
        self.conn.execute("PRAGMA temp_store=FILE")
        self.conn.execute("CREATE TABLE obs(pair_key TEXT NOT NULL, det_key TEXT NOT NULL, target_key TEXT NOT NULL, n INTEGER NOT NULL, PRIMARY KEY(pair_key,det_key,target_key))")
        self.conn.execute("CREATE TABLE lookup(relation_id TEXT NOT NULL, det_key TEXT NOT NULL, target_json TEXT NOT NULL, support INTEGER NOT NULL, PRIMARY KEY(relation_id,det_key))")
        self.conn.commit(); self.recovered_pairs = 0; self.lookup_rows = 0

    @staticmethod
    def pair_key(det: str, target: str) -> str:
        return json.dumps([det,target],ensure_ascii=False,separators=(",",":"))

    def add_count(self, det: str, target: str, dk: str, tv: str, n: int = 1) -> None:
        pk=self.pair_key(det,target)
        self.conn.execute("INSERT INTO obs(pair_key,det_key,target_key,n) VALUES(?,?,?,?) ON CONFLICT(pair_key,det_key,target_key) DO UPDATE SET n=n+excluded.n",(pk,dk,tv,int(n)))

    def flush_table(self, det: str, target: str, table: dict[str, Counter]) -> None:
        for dk,ctr in table.items():
            for tv,n in ctr.items(): self.add_count(det,target,dk,tv,n)
        self.conn.commit()

    def exact_good(self, det: str, target: str, min_group_support: int) -> dict[str, tuple[str,int]]:
        pk=self.pair_key(det,target); out={}; curdk=None; rows=[]
        for dk,tv,n in self.conn.execute("SELECT det_key,target_key,n FROM obs WHERE pair_key=? ORDER BY det_key,target_key",(pk,)):
            if curdk is None: curdk=dk
            if dk!=curdk:
                total=sum(x[1] for x in rows)
                if total>=min_group_support and rows:
                    best=max(rows,key=lambda x:(x[1],x[0])); out[curdk]=best
                curdk=dk; rows=[]
            rows.append((tv,int(n)))
        if curdk is not None:
            total=sum(x[1] for x in rows)
            if total>=min_group_support and rows:
                out[curdk]=max(rows,key=lambda x:(x[1],x[0]))
        return out

    def bind_relation(self, rid: str, good: dict[str, tuple[str,int]]) -> None:
        self.conn.executemany("INSERT OR REPLACE INTO lookup(relation_id,det_key,target_json,support) VALUES(?,?,?,?)",[(rid,dk,tv,int(n)) for dk,(tv,n) in sorted(good.items())])
        self.conn.commit(); self.recovered_pairs += 1; self.lookup_rows += len(good)

    def get(self, rid: str, dk: str) -> dict[str,Any] | None:
        row=self.conn.execute("SELECT target_json,support FROM lookup WHERE relation_id=? AND det_key=?",(rid,dk)).fetchone()
        if row is None: return None
        return {"value":json.loads(row[0]),"support":int(row[1])}

    def summary(self) -> dict[str,Any]:
        h=hashlib.sha256()
        for row in self.conn.execute("SELECT relation_id,det_key,target_json,support FROM lookup ORDER BY relation_id,det_key"):
            h.update(json.dumps(list(row),ensure_ascii=False,separators=(",",":")).encode("utf-8")); h.update(b"\n")
        return {"contract":"json-consistency-repair.disk-registry.v1","backend":"sqlite3","exact":True,"ephemeral":True,
                "recovered_functional_pairs":self.recovered_pairs,"lookup_rows":self.lookup_rows,"semantic_digest":h.hexdigest()}

    def close(self) -> None:
        try: self.conn.close()
        except Exception: pass

def _decode_stream_value(raw: str, limits: SecurityLimits) -> Any:
    preflight_json_text(raw, limits, byte_limit=limits.max_record_bytes)
    try:
        value = strict_decoder(limits).decode(raw)
    except (DuplicateKeyError, SecurityLimitError, ValueError, json.JSONDecodeError):
        raise
    validate_json_value(value, limits, node_limit=limits.max_record_nodes)
    return value


def _iter_jsonl(path: Path, limits: SecurityLimits) -> Iterator[_Envelope]:
    # Binary readline(size) ensures a hostile single record cannot make memory scale with its unbounded length.
    with path.open("rb") as f:
        idx = 0; line_no = 0; first = True
        while True:
            rawb = f.readline(limits.max_record_bytes + 1)
            if rawb == b"": break
            line_no += 1
            if len(rawb) > limits.max_record_bytes and not rawb.endswith(b"\n"):
                raise SecurityLimitError("max_record_bytes", f"JSONL record at physical line {line_no} exceeds {limits.max_record_bytes} bytes",
                                         observed=len(rawb), limit=limits.max_record_bytes, path=f"line:{line_no}")
            if len(rawb) > limits.max_record_bytes:
                raise SecurityLimitError("max_record_bytes", f"JSONL record at physical line {line_no} exceeds {limits.max_record_bytes} bytes",
                                         observed=len(rawb), limit=limits.max_record_bytes, path=f"line:{line_no}")
            try:
                encoding = "utf-8-sig" if first else "utf-8"
                raw = rawb.decode(encoding).rstrip("\r\n")
            except UnicodeDecodeError as e:
                raise StreamingParseError(f"JSONL UTF-8 failure at physical line {line_no}: {e}") from e
            first = False
            if not raw.strip(): continue
            try:
                value = _decode_stream_value(raw, limits)
            except Exception as e:
                if isinstance(e, SecurityLimitError): raise
                raise StreamingParseError(f"JSONL parse failure at physical line {line_no}: {e}") from e
            yield _Envelope(idx, value, raw)
            idx += 1


def _iter_array(path: Path, chunk_bytes: int, limits: SecurityLimits) -> Iterator[_Envelope]:
    dec = strict_decoder(limits)
    with path.open("r", encoding="utf-8-sig") as f:
        buf = ""; pos = 0; eof = False; started = False; idx = 0
        def refill() -> bool:
            nonlocal buf, pos, eof
            if eof: return False
            chunk = f.read(chunk_bytes)
            if chunk == "": eof = True; return False
            if pos:
                buf = buf[pos:] + chunk; pos = 0
            else:
                buf += chunk
            return True

        refill()
        while True:
            while pos >= len(buf) and refill(): pass
            while True:
                while pos < len(buf) and buf[pos].isspace(): pos += 1
                if pos < len(buf): break
                if not refill(): break
            if not started:
                if pos >= len(buf): raise StreamingParseError("empty JSON input")
                if buf[pos] != "[": raise StreamingParseError("streaming array mode requires a top-level JSON array")
                pos += 1; started = True
            while True:
                while pos < len(buf) and buf[pos].isspace(): pos += 1
                if pos < len(buf): break
                if not refill(): raise StreamingParseError("unterminated JSON array")
            if buf[pos] == "]":
                pos += 1
                tail = buf[pos:] + f.read()
                if tail.strip(): raise StreamingParseError("trailing data after top-level JSON array")
                return
            start = pos
            while True:
                try:
                    preflight_json_text(buf[start:], limits, path=f"record:{idx}")
                    value, end = dec.raw_decode(buf, pos)
                    raw = buf[start:end]
                    try: raw_bytes = len(raw.encode("utf-8"))
                    except UnicodeEncodeError as e: raise SecurityLimitError("invalid_unicode_scalar", f"unpaired Unicode surrogate in array record {idx}") from e
                    if raw_bytes > limits.max_record_bytes:
                        raise SecurityLimitError("max_record_bytes", f"array record {idx} exceeds {limits.max_record_bytes} bytes", observed=raw_bytes, limit=limits.max_record_bytes, path=f"record:{idx}")
                    validate_json_value(value, limits, node_limit=limits.max_record_nodes)
                    pos = end
                    break
                except RecursionError as e:
                    raise SecurityLimitError("decoder_recursion", f"JSON decoder recursion guard triggered at record {idx}", path=f"record:{idx}") from e
                except json.JSONDecodeError as e:
                    if eof:
                        raise StreamingParseError(f"JSON array parse failure near record {idx}: {e}") from e
                    suffix = buf[start:]
                    # Character bound prevents unbounded accumulation before raw_decode succeeds.
                    if len(suffix) > limits.max_record_bytes:
                        raise SecurityLimitError("max_record_bytes", f"array record {idx} exceeds safe streaming bound", observed=len(suffix), limit=limits.max_record_bytes, path=f"record:{idx}")
                    more = f.read(chunk_bytes)
                    if more == "":
                        eof = True; buf = suffix; pos = 0; start = 0
                    else:
                        buf = suffix + more; pos = 0; start = 0
                except (DuplicateKeyError, SecurityLimitError, ValueError) as e:
                    if isinstance(e, SecurityLimitError): raise
                    raise StreamingParseError(f"JSON array parse failure near record {idx}: {e}") from e
            yield _Envelope(idx, value, raw); idx += 1
            while True:
                while pos < len(buf) and buf[pos].isspace(): pos += 1
                if pos < len(buf): break
                if not refill(): raise StreamingParseError("unterminated JSON array")
            if buf[pos] == ",":
                pos += 1; continue
            if buf[pos] == "]": continue
            raise StreamingParseError(f"expected ',' or ']' after array record {idx-1}")

def _format_for_path(path: Path, explicit: str | None = None) -> str:
    if explicit:
        if explicit not in {"jsonl", "array"}: raise ValueError("stream format must be 'jsonl' or 'array'")
        return explicit
    if path.suffix.lower() in {".jsonl", ".ndjson"}: return "jsonl"
    return "array"


def iter_records(path: str | Path, *, stream_format: str | None = None, chunk_bytes: int = 65536, security_limits: SecurityLimits | None = None) -> Iterator[_Envelope]:
    p = Path(path); fmt = _format_for_path(p, stream_format); limits=security_limits or SecurityLimits()
    if fmt == "jsonl": yield from _iter_jsonl(p, limits)
    else: yield from _iter_array(p, chunk_bytes, limits)


class _RecordWriter:
    def __init__(self, path: Path, fmt: str):
        self.path = path; self.fmt = fmt; self.f = path.open("w", encoding="utf-8", newline="\n"); self.first = True
        if fmt == "array": self.f.write("[\n")
    def write(self, value: Any) -> None:
        raw = json.dumps(value, ensure_ascii=False, sort_keys=False, separators=(",", ":"), allow_nan=False)
        if self.fmt == "jsonl": self.f.write(raw + "\n")
        else:
            if not self.first: self.f.write(",\n")
            self.f.write(raw); self.first = False
    def close(self) -> None:
        if self.fmt == "array": self.f.write("\n]\n")
        self.f.close()
    def __enter__(self): return self
    def __exit__(self, exc_type, exc, tb):
        if not self.f.closed:
            if exc_type is None: self.close()
            else: self.f.close()



def _record_aggregate_features(record: Any) -> dict[tuple[str,str,str|None], Decimal]:
    """Bounded-shape aggregate features inside one streaming record.

    PASS013 intentionally limits automatic discovery to direct object-list children of a record.
    Nested/deeper conservation can still be supplied authoritatively.
    """
    out={}
    if not isinstance(record,dict): return out
    for field,value in record.items():
        if not isinstance(value,list) or not all(isinstance(x,dict) for x in value): continue
        out[("count",str(field),None)]=Decimal(len(value))
        if not value: continue
        common=set(value[0].keys())
        for item in value[1:]: common &= set(item.keys())
        for item_field in sorted(common):
            vals=[_decimal(item.get(item_field)) for item in value]
            if any(v is None for v in vals): continue
            out[("sum",str(field),str(item_field))]=sum(vals,Decimal(0))
    return out


def _candidate_aggregate_features(path: Path, fmt: str, cfg: StreamingConfig) -> tuple[list[tuple[str,str,str|None]], int]:
    mg={}; records=0
    reverse={}
    for env in iter_records(path,stream_format=fmt,chunk_bytes=cfg.chunk_bytes,security_limits=cfg.security_limits):
        feats=_record_aggregate_features(env.value)
        keys=set()
        for feat in feats:
            enc=json.dumps(feat,separators=(",",":"))
            reverse[enc]=feat; keys.add(enc)
        _misra_gries_update(mg,keys,cfg.max_tracked_fields)
        records+=1
    return [reverse[k] for k in sorted(mg) if k in reverse],records


def _stream_target_direction(record: dict[str,Any], items_field: str, target_path: str, kind: str) -> bool:
    toks=decode_pointer(target_path)
    if len(toks)!=1: return False
    target=toks[0]
    if aggregate_target_hint(target,kind): return True
    if items_field in record and target in record:
        keys=list(record.keys())
        return keys.index(items_field)<keys.index(target)
    return False

def _candidate_fields(path: Path, fmt: str, cfg: StreamingConfig) -> tuple[list[str], int]:
    mg: dict[str, int] = {}; records = 0
    for env in iter_records(path, stream_format=fmt, chunk_bytes=cfg.chunk_bytes, security_limits=cfg.security_limits):
        if not isinstance(env.value, dict):
            raise StreamingParseError(f"streaming inference requires object records; record {env.index} is {type(env.value).__name__}")
        keys = {p for p, _, _ in _leaf_items(env.value)}
        _misra_gries_update(mg, keys, cfg.max_tracked_fields)
        records += 1
    return sorted(mg), records


def _profile(path: Path, fmt: str, fields: list[str], cfg: StreamingConfig) -> dict[str, Any]:
    presence = Counter(); types: dict[str, Counter] = {f: Counter() for f in fields}; domains: dict[str, Counter] = {f: Counter() for f in fields}
    numeric_examples: dict[str, list[Any]] = {f: [] for f in fields}
    records = 0
    field_set = set(fields)
    for env in iter_records(path, stream_format=fmt, chunk_bytes=cfg.chunk_bytes, security_limits=cfg.security_limits):
        records += 1
        leaves = {p: v for p, v, _ in _leaf_items(env.value) if p in field_set}
        for p, v in leaves.items():
            presence[p] += 1
            if v is not None: types[p][type(v).__name__] += 1
            if isinstance(v, str) and len(domains[p]) <= cfg.enum_max_values:
                domains[p][v] += 1
            if _decimal(v) is not None and len(numeric_examples[p]) < 32:
                numeric_examples[p].append(v)
    ranked = sorted(fields, key=lambda f: (-presence[f], f))
    rel_fields = ranked[:cfg.max_relation_fields]
    numeric = [f for f in rel_fields if sum(1 for _ in numeric_examples[f]) > 0 and presence[f] >= cfg.min_support][:cfg.max_numeric_fields]
    return {
        "records": records,
        "presence": dict(presence),
        "types": {f: dict(c) for f, c in types.items()},
        "domains": {f: dict(c) for f, c in domains.items() if len(c) <= cfg.enum_max_values},
        "numeric_examples": numeric_examples,
        "relation_fields": rel_fields,
        "numeric_fields": numeric,
    }


def _stream_modal_profile(path:Path, fmt:str, cfg:StreamingConfig, fields:list[str], prof:dict[str,Any]):
    preferred=["/type","/kind","/mode","/schema_version","/version","/variant","/record_type"]
    chosen=None; counts=None
    for f in preferred:
        if f not in fields: continue
        dom=prof.get("domains",{}).get(f,{})
        if not dom or not (2<=len(dom)<=cfg.modal_max_regimes): continue
        if sum(dom.values())!=prof.get("records",0): continue
        if min(dom.values())<cfg.modal_min_regime_support: continue
        chosen=f; counts=dom; break
    if not chosen: return {"discriminator":None,"required_by_regime":{},"relations":[]}
    per={k:Counter() for k in counts}; n=Counter()
    for env in iter_records(path,stream_format=fmt,chunk_bytes=cfg.chunk_bytes,security_limits=cfg.security_limits):
        leaves={p:v for p,v,_ in _leaf_items(env.value)}
        val=leaves.get(chosen)
        if not isinstance(val,str) or val not in per: continue
        n[val]+=1
        for f in fields:
            if f in leaves: per[val][f]+=1
    required_by={}; relations=[]
    for val in sorted(per):
        req=[f for f,c in per[val].items() if c>=cfg.min_support and n[val] and c/n[val]>=cfg.required_key_confidence]
        required_by[val]=sorted(req)
        rel={"kind":"modal_regime_stream","inputs":[chosen],"output":"__regime__","regime_field":chosen,"regime_value":val,"confidence":1.0,"support":n[val]}
        rel["relation_id"]=_rid(rel); relations.append(rel)
    if chosen in {"/schema_version","/version"}:
        rel={"kind":"schema_evolution_stream","inputs":[chosen],"output":"__schema__","version_field":chosen,"required_by_version":required_by,"confidence":1.0,"support":sum(n.values())}
        rel["relation_id"]=_rid(rel); relations.append(rel)
    return {"discriminator":chosen,"required_by_regime":required_by,"relations":relations}

def discover_stream_knowledge(path: str | Path, config: StreamingConfig | None = None, *, stream_format: str | None = None, registry_dir: str | Path | None = None) -> dict[str, Any]:
    """Bounded-memory discovery. Record count may grow without increasing retained relation state."""
    cfg = config or StreamingConfig(); p = Path(path); fmt = _format_for_path(p, stream_format)
    fields, first_records = _candidate_fields(p, fmt, cfg)
    prof = _profile(p, fmt, fields, cfg)
    if first_records != prof["records"]: raise RuntimeError("record count changed between streaming discovery scans")
    nrec = prof["records"]
    modal_profile=_stream_modal_profile(p,fmt,cfg,fields,prof)
    rel_fields = prof["relation_fields"]; numeric_fields = prof["numeric_fields"]
    aggregate_features, aggregate_records = _candidate_aggregate_features(p,fmt,cfg)
    if aggregate_records != nrec: raise RuntimeError("record count changed during aggregate discovery scan")

    # Functional relation tables are bounded by max_functional_groups; overflow disables certification for that pair.
    maps: dict[tuple[str, str], dict[str, Counter]] = {}
    overflow: set[tuple[str, str]] = set()
    disk_registry = _DiskFunctionalRegistry(Path(registry_dir) if registry_dir is not None else None) if cfg.exact_disk_registry else None
    observed = Counter()
    for a in rel_fields:
        for b in rel_fields:
            if a != b: maps[(a, b)] = {}

    OPS = {
        "+": lambda a, b: a + b,
        "-": lambda a, b: a - b,
        "*": lambda a, b: a * b,
        "/": lambda a, b: None if b == 0 else a / b,
    }
    formulas: dict[tuple[str, str, str, str], list[int]] = {}
    direction: dict[tuple[str, str, str, str], list[int]] = {}
    aggregate_pairs: dict[tuple[tuple[str,str,str|None],str], list[int]] = {}
    aggregate_direction: dict[tuple[tuple[str,str,str|None],str], list[int]] = {}
    aggregate_distinct: dict[tuple[tuple[str,str,str|None],str], set[str]] = defaultdict(set)
    for feat in aggregate_features:
        for target in numeric_fields:
            aggregate_pairs[(feat,target)]=[0,0]
            aggregate_direction[(feat,target)]=[0,0]

    for target in numeric_fields:
        for a in numeric_fields:
            if a == target: continue
            for b in numeric_fields:
                if b in {target, a}: continue
                for sym in OPS:
                    if sym in {"+", "*"} and b < a: continue
                    formulas[(target, a, sym, b)] = [0, 0]  # support, violations
                    direction[(target, a, sym, b)] = [0, 0] # forward, seen

    for env in iter_records(p, stream_format=fmt, chunk_bytes=cfg.chunk_bytes, security_limits=cfg.security_limits):
        leaf_list = _leaf_items(env.value); leaves = {pp: v for pp, v, _ in leaf_list}; order = {pp: o for pp, _, o in leaf_list}
        aggvals=_record_aggregate_features(env.value)
        if isinstance(env.value,dict):
            for (feat,target),counts in aggregate_pairs.items():
                if feat not in aggvals: continue
                dt=_decimal(leaves.get(target))
                if dt is None: continue
                exp=aggvals[feat]; counts[0 if dt==exp else 1]+=1
                aggregate_distinct[(feat,target)].add(format(exp,"f"))
                aggregate_direction[(feat,target)][1]+=1
                kind,items_field,_=feat
                if _stream_target_direction(env.value,items_field,target,kind): aggregate_direction[(feat,target)][0]+=1
        for det, target in maps:
            if det not in leaves or target not in leaves or leaves[det] is None or leaves[target] is None: continue
            try: dk, tv = _jkey(leaves[det]), _jkey(leaves[target])
            except (TypeError, ValueError): continue
            observed[(det, target)] += 1
            table = maps[(det, target)]
            if (det,target) in overflow:
                if disk_registry is not None: disk_registry.add_count(det,target,dk,tv)
                continue
            if dk not in table and len(table) >= cfg.max_functional_groups:
                overflow.add((det, target))
                if disk_registry is not None:
                    disk_registry.flush_table(det,target,table); disk_registry.add_count(det,target,dk,tv)
                table.clear(); continue
            table.setdefault(dk, Counter())[tv] += 1
        for key in formulas:
            target, a, sym, b = key
            da, db, dt = _decimal(leaves.get(a)), _decimal(leaves.get(b)), _decimal(leaves.get(target))
            if da is None or db is None or dt is None: continue
            exp = OPS[sym](da, db)
            if exp is None: continue
            formulas[key][0 if dt == exp else 1] += 1
            if target in order and a in order and b in order:
                direction[key][1] += 1
                if order[a] < order[target] and order[b] < order[target]: direction[key][0] += 1

    relations: list[dict[str, Any]] = []
    functional_lookup: dict[str, dict[str, Any]] = {}
    for (det, target), table in maps.items():
        obs = observed[(det, target)]
        if obs < cfg.min_support: continue
        if (det,target) in overflow:
            if disk_registry is None: continue
            disk_registry.conn.commit(); good=disk_registry.exact_good(det,target,cfg.min_group_support)
        else:
            good = {dk: max(ctr.items(),key=lambda x:(x[1],x[0])) for dk, ctr in table.items() if sum(ctr.values()) >= cfg.min_group_support}
        if len(good) < cfg.min_functional_groups: continue  # reject degenerate constant-determinant pseudo-relations
        agreements = sum(count for _, count in good.values()); conf = agreements / obs
        if conf < cfg.relation_confidence: continue
        rel = {"kind": "functional_stream", "inputs": [det], "output": target, "determinant": det, "confidence": round(conf, 12), "support": agreements, "groups": len(good),
               "registry_storage":"disk_exact" if (det,target) in overflow else "memory_bounded"}
        rel["relation_id"] = _rid(rel); relations.append(rel)
        if (det,target) in overflow:
            disk_registry.bind_relation(rel["relation_id"],good)
        else:
            functional_lookup[rel["relation_id"]] = {dk: {"value": json.loads(tv), "support": count} for dk, (tv, count) in good.items()}

    arithmetic_lookup: dict[str, dict[str, Any]] = {}
    for key, (sup, viol) in formulas.items():
        total = sup + viol
        if total < cfg.min_support: continue
        conf = sup / total
        if conf < cfg.arithmetic_confidence: continue
        target, a, sym, b = key; fw, seen = direction[key]
        dconf = fw / seen if seen else 0.0
        structural = seen >= cfg.min_support and dconf >= cfg.arithmetic_direction_confidence
        rel = {"kind": "exact_arithmetic_stream", "inputs": [a, b], "output": target, "formula": f"EXACT:{target}={a}{sym}{b}", "operator": sym,
               "confidence": round(conf, 12), "support": sup, "direction_certified": structural, "direction_confidence": round(dconf, 12)}
        rel["relation_id"] = _rid(rel); relations.append(rel)
        arithmetic_lookup[rel["relation_id"]] = {"target": target, "a": a, "b": b, "operator": sym, "direction_certified": structural, "examples": prof["numeric_examples"].get(target, [])}

    aggregate_lookup: dict[str, dict[str,Any]] = {}
    for (feat,target),(sup,viol) in aggregate_pairs.items():
        total=sup+viol
        if total<cfg.conservation_min_support: continue
        conf=sup/total
        if conf<cfg.conservation_confidence: continue
        kind,items_field,value_field=feat
        target_tokens=decode_pointer(target); target_name=target_tokens[-1] if target_tokens else target
        if len(aggregate_distinct[(feat,target)])<cfg.conservation_min_distinct_aggregates and not (kind=="count" and aggregate_target_hint(target_name,"count")):
            continue
        fw,seen=aggregate_direction[(feat,target)]
        dconf=fw/seen if seen else 0.0
        direction=seen>=cfg.conservation_min_support and dconf>=cfg.conservation_direction_confidence
        rkind="aggregate_sum_stream" if kind=="sum" else "aggregate_count_stream"
        rel={"kind":rkind,"inputs":[f"{items_field}[*].{value_field}" if kind=="sum" else f"len({items_field})"],"output":target,
             "items_field":items_field,"value_field":value_field,"aggregate_kind":kind,"confidence":round(conf,12),"support":sup,
             "bridge_kind":"local_to_aggregate","direction_certified":direction,"direction_confidence":round(dconf,12),
             "direction_source":"stream_aggregate_role_or_order" if direction else "unoriented_stream_aggregate"}
        rel["relation_id"]=_rid(rel); relations.append(rel); aggregate_lookup[rel["relation_id"]]={"feature":feat,"target":target,"direction_certified":direction,"examples":prof["numeric_examples"].get(target,[])}

    enums: dict[str, dict[str, Any]] = {}
    for f, counter_dict in prof["domains"].items():
        ctr = Counter(counter_dict)
        if not ctr or sum(ctr.values()) < cfg.min_support: continue
        folded: dict[str, list[str]] = defaultdict(list)
        for val in ctr: folded[val.casefold()].append(val)
        canonical = {}
        for fold, vals in folded.items():
            if len(vals) <= 1: continue
            ranked = sorted(vals, key=lambda v: (-ctr[v], v))
            best = ranked[0]; total = sum(ctr[v] for v in vals)
            if total and ctr[best] / total >= cfg.enum_normalization_confidence:
                # unique top count; ties are not canonicalized
                if len(ranked) == 1 or ctr[ranked[0]] > ctr[ranked[1]]:
                    for v in vals:
                        if v != best: canonical[v] = best
        if canonical:
            rel = {"kind": "enum_representation_stream", "inputs": [], "output": f, "field": f, "canonicalizations": canonical, "confidence": 1.0, "support": sum(ctr.values())}
            rel["relation_id"] = _rid(rel); relations.append(rel); enums[f] = canonical

    required = []
    modal_required=modal_profile.get("required_by_regime",{})
    all_regime_required=set.intersection(*(set(v) for v in modal_required.values())) if modal_required else None
    for f, count in prof["presence"].items():
        conf = count / nrec if nrec else 0.0
        if count >= cfg.min_support and conf >= cfg.required_key_confidence:
            if all_regime_required is not None and f not in all_regime_required:
                continue
            rel = {"kind": "required_leaf_stream", "inputs": [], "output": f, "field": f, "confidence": round(conf, 12), "support": count}
            rel["relation_id"] = _rid(rel); relations.append(rel); required.append(f)
    relations.extend(modal_profile.get("relations",[]))

    # Explicit streaming logic rules are evaluated record-by-record. They must target the record itself
    # (array_path omitted/empty/@record) and may be tagged document=@stream.
    logic_rules=[]
    for raw in cfg.logic_rules or ():
        if not isinstance(raw,dict): continue
        if raw.get("document") not in (None,"@stream"): continue
        if raw.get("array_path") not in (None,"","@record"): continue
        rr=dict(raw); rr.setdefault("rule_id",stable_rule_id(rr,"logic")); logic_rules.append(rr)
    logic_cert=rule_system_certificate(logic_rules) if logic_rules else {"contract":"json-consistency-repair.logic-sat.v1","status":"SAT","assignment":{},"compiled_rule_ids":[],"skipped_non_boolean_rule_ids":[],"clause_count":0,"explored_nodes":0,"unit_propagations":0}
    if logic_rules:
        sysrel={"kind":"logic_rule_system_stream","inputs":sorted(set(str(p.get("field")) for rr in logic_rules for p in (([rr.get("if")] if isinstance(rr.get("if"),dict) else (rr.get("if") or [])) + ([rr.get("then")] if isinstance(rr.get("then"),dict) else []) + (rr.get("items") or [])) if isinstance(p,dict) and p.get("field"))),
                "output":None,"confidence":1.0,"support":nrec,"logic_source":"authoritative","rule_ids":[r["rule_id"] for r in logic_rules],"sat_status":logic_cert["status"],"sat_certificate":logic_cert}
        sysrel["relation_id"]=_rid(sysrel); relations.append(sysrel)
        for rr in logic_rules:
            fields=[]
            if rr.get("kind")=="implies":
                ants=rr.get("if",[]); ants=[ants] if isinstance(ants,dict) else ants
                fields.extend(p.get("field") for p in ants if isinstance(p,dict) and p.get("field"))
                if isinstance(rr.get("then"),dict) and rr["then"].get("field"): fields.append(rr["then"]["field"])
            else:
                fields.extend(p.get("field") for p in rr.get("items",[]) if isinstance(p,dict) and p.get("field"))
            rel={"kind":"logic_exact_stream","inputs":sorted(set(fields)),"output":(rr.get("then") or {}).get("field") if isinstance(rr.get("then"),dict) else None,
                 "confidence":1.0,"support":nrec,"logic_source":"authoritative","logic_rule_id":rr["rule_id"],"logic_kind":rr.get("kind"),"sat_status":logic_cert["status"],"rule":rr}
            rel["relation_id"]=_rid(rel); relations.append(rel)

    conservation_rules=[]
    for raw in cfg.conservation_rules or ():
        if not isinstance(raw,dict): continue
        if raw.get("document") not in (None,"@stream"): continue
        if raw.get("array_path") not in (None,"","@record"): continue
        rr=dict(raw); rr.setdefault("rule_id",stable_conservation_id(rr)); conservation_rules.append(rr)
    for rr in conservation_rules:
        kind=rr.get("kind"); rid=str(rr["rule_id"])
        inputs=[]; output=rr.get("target")
        if kind in {"aggregate_sum","aggregate_count"}: inputs=[str(rr.get("items_field"))]
        elif kind=="balance": inputs=[str(t.get("field")) for t in rr.get("terms",[]) if isinstance(t,dict) and t.get("field")]
        elif kind=="multiset_balance": inputs=[str(rr.get("left_field")),str(rr.get("right_field"))]; output=rr.get("target_side")
        rel={"kind":f"{kind}_authoritative_stream","inputs":inputs,"output":output,"confidence":1.0,"support":nrec,"conservation_source":"authoritative","conservation_rule_id":rid,"rule":rr,"direction_certified":True,"direction_source":"authoritative_rule"}
        rel["relation_id"]=_rid(rel); relations.append(rel)

    moment_rules=[]
    for raw in cfg.moment_rules or ():
        if not isinstance(raw,dict): continue
        if raw.get("document") not in (None,"@stream"): continue
        if raw.get("array_path") not in (None,"","@record"): continue
        rr=dict(raw); rr.setdefault("rule_id",stable_moment_id(rr)); moment_rules.append(rr)
    for rr in moment_rules:
        kind=rr.get("kind"); rid=str(rr["rule_id"])
        rel={"kind":f"{kind}_authoritative_stream","inputs":[x for x in (rr.get("items_field"),rr.get("value_field"),rr.get("weight_field"),rr.get("unit_field")) if isinstance(x,str)],
             "output":rr.get("target") or rr.get("value_field"),"confidence":1.0,"support":nrec,"constraint_source":"authoritative","moment_rule_id":rid,"rule":rr,"bridge_kind":"moment_distribution"}
        rel["relation_id"]=_rid(rel); relations.append(rel)

    relations.sort(key=lambda r: r["relation_id"])
    return {
        "engine": "json-consistency-repair",
        "version": __version__,
        "mode": "streaming",
        "format": fmt,
        "records": nrec,
        "bounded_state": {
            "max_tracked_fields": cfg.max_tracked_fields,
            "tracked_fields": len(fields),
            "max_relation_fields": cfg.max_relation_fields,
            "relation_fields": len(rel_fields),
            "max_functional_groups_per_pair": cfg.max_functional_groups,
            "min_functional_groups": cfg.min_functional_groups,
            "overflowed_functional_pairs": len(overflow),
            "disk_backed_functional_pairs_recovered": (disk_registry.recovered_pairs if disk_registry is not None else 0),
            "tracked_aggregate_features": len(aggregate_features),
        },
        "profile": {
            "presence": prof["presence"],
            "types": prof["types"],
            "relation_fields": rel_fields,
            "numeric_fields": numeric_fields,
        },
        "relations": relations,
        "functional_lookup": functional_lookup,
        "arithmetic_lookup": arithmetic_lookup,
        "aggregate_lookup": aggregate_lookup,
        "enum_lookup": enums,
        "required_fields": required,
        "modal_discriminator": modal_profile.get("discriminator"),
        "modal_required_fields": modal_profile.get("required_by_regime",{}),
        "logic_rules": logic_rules,
        "logic_system_certificate": logic_cert,
        "conservation_rules": conservation_rules,
        "moment_rules": moment_rules,
        "disk_registry_summary": disk_registry.summary() if disk_registry is not None else {"contract":"json-consistency-repair.disk-registry.v1","backend":"disabled","exact":False},
        "_disk_registry": disk_registry,
    }


def _functional_entry(knowledge: dict[str,Any], rid: str, dk: str) -> dict[str,Any] | None:
    entry=knowledge.get("functional_lookup",{}).get(rid,{}).get(dk)
    if entry is not None: return entry
    reg=knowledge.get("_disk_registry")
    return reg.get(rid,dk) if reg is not None else None


def _record_candidates(record: dict[str, Any], knowledge: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    leaf_list = _leaf_items(record); leaves = {p: v for p, v, _ in leaf_list}
    candidates: list[dict[str, Any]] = []; issues: list[dict[str, Any]] = []

    # Representation normalization can unlock determinant groups on a later cycle.
    for field, canonical in knowledge.get("enum_lookup", {}).items():
        if field in leaves and isinstance(leaves[field], str) and leaves[field] in canonical:
            old = leaves[field]; new = canonical[old]
            candidates.append({"analyzer": "stream_enum", "path": field, "old_value": old, "new_value": new, "confidence": 1.0,
                               "reason": "Restore uniquely dominant case representation.", "evidence": [f"ENUM:{field}"], "add_if_missing": False})
            issues.append({"analyzer": "stream_enum", "code": "representation_variant", "path": field, "repairable": True})

    for rel in knowledge.get("relations", []):
        rid = rel["relation_id"]
        if rel["kind"] == "functional_stream":
            det, target = rel["determinant"], rel["output"]
            if det not in leaves or leaves[det] is None: continue
            try: dk = _jkey(leaves[det])
            except (TypeError, ValueError): continue
            entry = _functional_entry(knowledge,rid,dk)
            if not entry: continue
            expected = entry["value"]; exists, old = _get_path(record, target)
            if not exists or old is None:
                # Only add when parent exists; _set_path enforces this.
                candidates.append({"analyzer": "stream_functional", "path": target, "old_value": old if exists else None, "new_value": expected,
                                   "confidence": rel["confidence"], "reason": "Reconstruct from certified streaming functional relation.",
                                   "evidence": [f"FD:{det}->{target}"], "add_if_missing": not exists, "relation_id": rid})
                issues.append({"analyzer": "stream_functional", "code": "missing_from_functional_relation", "path": target, "repairable": True})
            elif old != expected:
                candidates.append({"analyzer": "stream_functional", "path": target, "old_value": old, "new_value": expected,
                                   "confidence": rel["confidence"], "reason": "Restore certified streaming functional relation.",
                                   "evidence": [f"FD:{det}->{target}"], "add_if_missing": False, "relation_id": rid})
                issues.append({"analyzer": "stream_functional", "code": "functional_relation_violation", "path": target, "repairable": True})
        elif rel["kind"] == "exact_arithmetic_stream":
            info = knowledge.get("arithmetic_lookup", {}).get(rid, {})
            target, a, b, sym = info.get("target"), info.get("a"), info.get("b"), info.get("operator")
            da, db = _decimal(leaves.get(a)), _decimal(leaves.get(b))
            if da is None or db is None: continue
            exp = {"+": lambda x,y:x+y, "-": lambda x,y:x-y, "*": lambda x,y:x*y, "/": lambda x,y:None if y==0 else x/y}[sym](da, db)
            if exp is None: continue
            exists, old = _get_path(record, target); dt = _decimal(old) if exists else None
            if dt is not None and dt == exp: continue
            new = _number_like(exp, info.get("examples", []))
            issues.append({"analyzer": "stream_arithmetic", "code": "arithmetic_violation", "path": target, "repairable": bool(info.get("direction_certified"))})
            if info.get("direction_certified"):
                candidates.append({"analyzer": "stream_arithmetic", "path": target, "old_value": old if exists else None, "new_value": new,
                                   "confidence": rel["confidence"], "reason": "Restore exact streaming arithmetic invariant.",
                                   "evidence": [rel["formula"]], "add_if_missing": not exists, "relation_id": rid})

    for rel in knowledge.get("relations",[]):
        if rel.get("kind") not in {"aggregate_sum_stream","aggregate_count_stream"}: continue
        info=knowledge.get("aggregate_lookup",{}).get(rel.get("relation_id"),{})
        feat=tuple(info.get("feature",()))
        if len(feat)!=3: continue
        kind,items_field,value_field=feat
        if kind=="sum": exp=sum_child_values(record,items_field,value_field)
        else:
            cnt=child_count(record,items_field); exp=Decimal(cnt) if cnt is not None else None
        if exp is None: continue
        target=info.get("target"); exists,old=_get_path(record,target); dt=_decimal(old) if exists else None
        if dt is not None and dt==exp: continue
        issues.append({"analyzer":"stream_conservation","code":"aggregate_conservation_violation","path":target,"repairable":bool(info.get("direction_certified")),"relation_id":rel.get("relation_id")})
        if info.get("direction_certified"):
            new=_number_like(exp,info.get("examples",[]))
            candidates.append({"analyzer":"stream_conservation","path":target,"old_value":old if exists else None,"new_value":new,"confidence":rel.get("confidence",1.0),
                               "reason":"Restore exact streaming local-to-aggregate conservation bridge.","evidence":[f"CONSERVATION:{rel.get('relation_id')}"],"add_if_missing":not exists,"relation_id":rel.get("relation_id")})

    for rr in knowledge.get("conservation_rules",[]):
        ev=evaluate_conservation_rule(record,rr)
        if ev.get("status") is not False: continue
        patch=conservation_rule_patch(record,rr); rid=str(rr.get("rule_id"))
        if patch and "path_parts" in patch: pth=pointer(list(patch["path_parts"]))
        elif patch: pth=pointer([patch["path_field"]])
        else: pth=""
        issues.append({"analyzer":"stream_conservation","code":"conservation_violation","path":pth,"repairable":bool(patch),"conservation_rule_id":rid,"residue":str(ev.get("residue"))})
        if patch:
            candidates.append({"analyzer":"stream_conservation","path":pth,"old_value":patch["old_value"],"new_value":patch["new_value"],"confidence":1.0,
                               "reason":"Restore authoritative streaming conservation rule.","evidence":[f"CONSERVATION:{rid}"],"add_if_missing":bool(patch.get("add_if_missing")),"conservation_rule_id":rid})

    # Exact authoritative logical constraints. The record-level solver stays conservative:
    # ambiguous alternatives are preserved for the streaming minimal-transfer gate.
    if knowledge.get("logic_system_certificate",{}).get("status") == "SAT":
        for rule in knowledge.get("logic_rules",[]):
            if evaluate_rule(record,rule) is not False:
                continue
            cs=repair_candidates_for_rule(record,rule,"",analyzer="stream_logic",confidence=1.0)
            rid=str(rule.get("rule_id") or stable_rule_id(rule,"logic"))
            for c in cs:
                candidates.append({"analyzer":"stream_logic","path":c.path,"old_value":c.old_value,"new_value":c.new_value,"confidence":1.0,
                                   "reason":c.reason,"evidence":list(c.evidence),"add_if_missing":bool(c.metadata.get("add_if_missing")),
                                   "logic_rule_id":rid,"logic_kind":rule.get("kind"),"relation_id":c.metadata.get("relation_id")})
            issues.append({"analyzer":"stream_logic","code":"logical_constraint_violation","path":cs[0].path if len(cs)==1 else "",
                           "repairable":bool(cs),"logic_rule_id":rid,"alternative_patch_count":len(cs)})

    # Required-field evidence diagnoses absence but never invents a value by itself.
    required_fields=knowledge.get("required_fields", [])
    disc=knowledge.get("modal_discriminator")
    if disc:
        exists_disc, disc_value=_get_path(record,disc)
        if exists_disc and isinstance(disc_value,str):
            required_fields=knowledge.get("modal_required_fields",{}).get(disc_value,required_fields)
    for field in required_fields:
        exists, _ = _get_path(record, field)
        if not exists:
            issues.append({"analyzer": "stream_schema", "code": "required_leaf_missing", "path": field, "repairable": False})


    # Authoritative moment/distribution rules. Scalar rules may still use the pathwise frontier.
    # PASS024 exact mode delegates multi-path unit plans to the whole-record bridge below.
    for rr in knowledge.get("moment_rules",[]):
        ev=evaluate_moment_rule(record,rr)
        if ev.get("status") is not False: continue
        rid=str(rr.get("rule_id")); kind=rr.get("kind")
        if kind=="unit_normalize":
            if (knowledge.get("disk_registry_summary") or {}).get("exact"):
                continue
            issues.append({"analyzer":"stream_moments","code":"bounded_stream_unit_plan_requires_materialization","path":"","repairable":False,"rule_id":rid})
            continue
        target=ev.get("target"); expected=ev.get("expected")
        if not isinstance(target,str) or expected is None: continue
        exists,old=_get_path(record,"/"+target.replace("~","~0").replace("/","~1"))
        nv=_json_num(expected,[old] if exists else [])
        path="/"+target.replace("~","~0").replace("/","~1")
        repairable=nv is not None
        issues.append({"analyzer":"stream_moments","code":f"{kind}_violation","path":path,"repairable":repairable,"rule_id":rid})
        if repairable:
            candidates.append({"analyzer":"stream_moments","path":path,"old_value":old if exists else None,"new_value":nv,"confidence":1.0,
                               "reason":f"Restore authoritative exact {kind}.","evidence":[f"MOMENT:{rid}"],"add_if_missing":not exists,"relation_id":rid})

    return candidates, issues


def _stream_authority_tier(c:dict[str,Any])->int:
    if c.get("logic_rule_id") or c.get("conservation_rule_id"): return 3
    if c.get("relation_id") or c.get("analyzer") in {"stream_functional","stream_arithmetic","stream_conservation"}: return 2
    return 1

def _choose_candidates_with_certificate(candidates: list[dict[str, Any]], *, enable_parallel_routes:bool=True, max_parallel_routes:int=16) -> tuple[list[dict[str, Any]], int, dict[str,Any]]:
    raw_by_path: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for c in candidates: raw_by_path[c["path"]].append(c)
    filtered=[]; authority_conflicts=[]; authority_blocked=[]
    for path,group in sorted(raw_by_path.items()):
        top=max((_stream_authority_tier(c) for c in group),default=1); topg=[c for c in group if _stream_authority_tier(c)==top]; topvals={_jkey(c.get("new_value")) for c in topg}
        if top==3 and len(topvals)>1:
            authority_conflicts.append({"path":path,"distinct_values":len(topvals)}); authority_blocked.extend(group); continue
        if top==3:
            for c in group:
                if _stream_authority_tier(c)==3 or _jkey(c.get("new_value")) in topvals: filtered.append(c)
                else: authority_blocked.append(c)
        else: filtered.extend(group)
    by_path: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for c in filtered: by_path[c["path"]].append(c)
    accepted=[]; conflicts=len(authority_conflicts); ambiguous_groups=[]
    path_reports=[{"path":x["path"],"status":"AUTHORITY_CONFLICT","alternative_values":x["distinct_values"]} for x in authority_conflicts]
    logic_groups: dict[str, list[dict[str,Any]]] = defaultdict(list)
    normal: dict[str, list[dict[str,Any]]] = defaultdict(list)
    for path, group in by_path.items():
        for c in group:
            if c.get("logic_rule_id"): logic_groups[str(c["logic_rule_id"])].append(c)
            else: normal[path].append(c)
    for rid in sorted(logic_groups):
        group=logic_groups[rid]
        uniq={(c["path"],_jkey(c["new_value"])):c for c in group}
        if len(uniq)!=1:
            conflicts += 1; alts=[dict(uniq[k]) for k in sorted(uniq)]; ambiguous_groups.append(alts)
            path_reports.append({"logic_rule_id":rid,"status":"AMBIGUOUS_LOGIC_MINIMUM","alternative_patches":len(uniq)})
            continue
        c=next(iter(uniq.values())); accepted.append(dict(c))
        path_reports.append({"logic_rule_id":rid,"path":c["path"],"status":"UNIQUE_LOGIC_MINIMUM","alternative_patches":1})
    for path in sorted(normal):
        group=normal[path]
        by_new: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for c in group:
            try: key=_jkey(c["new_value"])
            except (TypeError,ValueError): continue
            by_new[key].append(c)
        if len(by_new)!=1:
            conflicts += 1
            alts=[]
            for key in sorted(by_new):
                winner_group=by_new[key]
                winner=max(winner_group,key=lambda c:(len(set(sum((x.get("evidence",[]) for x in winner_group),[]))),c.get("confidence",0.0),-len(c.get("reason",""))))
                w=dict(winner); w["families"]=sorted({x["analyzer"] for x in winner_group}); w["evidence"]=sorted(set(sum((x.get("evidence",[]) for x in winner_group),[])))
                alts.append(w)
            ambiguous_groups.append(alts)
            path_reports.append({"path":path,"status":"AMBIGUOUS_EXACT_MINIMUM","alternative_values":len(by_new)})
            continue
        winner_group=next(iter(by_new.values()))
        winner=max(winner_group,key=lambda c:(len(set(sum((x.get("evidence",[]) for x in winner_group),[]))),c.get("confidence",0.0),-len(c.get("reason",""))))
        winner=dict(winner); winner["families"]=sorted({x["analyzer"] for x in winner_group}); winner["evidence"]=sorted(set(sum((x.get("evidence",[]) for x in winner_group),[])))
        accepted.append(winner)
        path_reports.append({"path":path,"status":"UNIQUE_EXACT_MINIMUM","supporting_candidates":len(winner_group),"families":winner["families"]})
    routes=[]; frontier_overflow=False
    if ambiguous_groups and enable_parallel_routes:
        theoretical=1
        for g in ambiguous_groups: theoretical*=max(1,len(g))
        if theoretical<=max_parallel_routes:
            seen={}
            for combo in product(*ambiguous_groups):
                route=[dict(x) for x in accepted]+[dict(x) for x in combo]
                ident=tuple(sorted((x.get("path"),_jkey(x.get("new_value")),x.get("analyzer")) for x in route))
                seen[ident]=route
            routes=[seen[k] for k in sorted(seen)]
            accepted=[]
        else:
            frontier_overflow=True
    status=("AUTHORITY_CONFLICT" if authority_conflicts and not ambiguous_groups and not accepted else
            "PARALLEL_EXACT_MINIMUM_REQUIRED" if routes else
            "PARALLEL_ROUTE_FRONTIER_TOO_LARGE" if frontier_overflow else
            "PARTIAL_WITH_AMBIGUOUS_PATHS" if conflicts else
            "UNIQUE_PATHWISE_MINIMUM" if accepted else "NO_ADMISSIBLE_CANDIDATES")
    cert={"solver_contract":"json-consistency-repair.streaming-minimal-transfer.v1","status":status,
          "objective":"close_all_independently_certified_record_paths","exact_metric":True,
          "metric_order":["changed_paths","canonical_new_value_bytes"],"selected_patch_count":len(accepted),"ambiguous_path_count":conflicts,"paths":path_reports,
          "parallel_route_contract":"json-consistency-repair.parallel-exact-routes.v1","parallel_route_count":len(routes),"parallel_route_frontier_overflow":frontier_overflow,
          "parallel_routes":routes,
          "authority_firewall":{"contract":"json-consistency-repair.authority-firewall.v1","conflicts":authority_conflicts,"blocked_candidate_count":len(authority_blocked)}}
    return accepted,conflicts,cert

def _choose_candidates(candidates: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    accepted,conflicts,_=_choose_candidates_with_certificate(candidates)
    return accepted,conflicts



def _resolve_stream_parallel_record(record:dict[str,Any], routes:list[list[dict[str,Any]]], knowledge:dict[str,Any], cfg:StreamingConfig)->tuple[dict[str,Any]|None,dict[str,Any]]:
    frozen=hashlib.sha256(canonical_bytes(record)).hexdigest(); rows=[]; finals={}
    for route in routes:
        rid=hashlib.sha256(json.dumps(route,sort_keys=True,ensure_ascii=False,default=str,separators=(",",":")).encode()).hexdigest()
        cur=deepcopy(record); ok=True
        for c in route:
            if not _set_path(cur,c["path"],c.get("old_value"),c.get("new_value"),add_if_missing=c.get("add_if_missing",False)):
                ok=False; break
        if not ok:
            rows.append({"route_id":rid,"prefix_applied":False,"closed":False}); continue
        unresolved=0; quiet=0
        for _ in range(max(1,min(int(cfg.max_cycles),4))):
            before=deepcopy(cur)
            cands,issues=_record_candidates(cur,knowledge)
            chosen,nconf,cert=_choose_candidates_with_certificate(cands,enable_parallel_routes=False,max_parallel_routes=cfg.max_parallel_tie_routes)
            if nconf:
                unresolved=nconf; break
            for c in chosen:
                _set_path(cur,c["path"],c.get("old_value"),c.get("new_value"),add_if_missing=c.get("add_if_missing",False))
            if _record_bridge_enabled(cfg):
                cur,_=_repair_record_with_pass024_bridges(cur,cfg)
            if cur==before:
                quiet+=1
                if quiet>=1: break
            else: quiet=0
        fcands,fissues=_record_candidates(cur,knowledge)
        _,fconf,_=_choose_candidates_with_certificate(fcands,enable_parallel_routes=False,max_parallel_routes=cfg.max_parallel_tie_routes)
        closed=bool(unresolved==0 and fconf==0)
        fd=hashlib.sha256(canonical_bytes(cur)).hexdigest()
        idig=hashlib.sha256(json.dumps(fissues,sort_keys=True,ensure_ascii=False,default=str,separators=(",",":")).encode()).hexdigest()
        rows.append({"route_id":rid,"prefix_applied":True,"closed":closed,"final_digest":fd,"remaining_issue_digest":idig,"remaining_issue_count":len(fissues),"unresolved_ambiguities":unresolved+fconf})
        finals[rid]=cur
    ds={r.get("final_digest") for r in rows if r.get("final_digest")}; ids={r.get("remaining_issue_digest") for r in rows if r.get("remaining_issue_digest")}
    ok=bool(rows and len(finals)==len(rows) and all(r.get("closed") for r in rows) and len(ds)==1 and len(ids)==1)
    selected=min(finals) if ok else None
    proof={"contract":"json-consistency-repair.return-proof.v1","parallel_contract":"json-consistency-repair.parallel-exact-routes.v1","mode":"streaming_record",
           "status":"RETURN_PROOF_EQUIVALENT" if ok else "RETURN_PROOF_DIVERGENT","ok":ok,"frozen_input_digest":frozen,"route_count":len(rows),"routes":rows,
           "checks":{"all_routes_closed":bool(rows and all(r.get("closed") for r in rows)),"exact_terminal_equivalence":len(ds)==1,"remaining_issue_equivalence":len(ids)==1},
           "terminal_digest":next(iter(ds)) if len(ds)==1 else None,"selected_route_id":selected,"selection_rule":"lexicographically_smallest_route_id_after_exact_return_equivalence_only"}
    tmp=dict(proof); proof["proof_sha256"]=hashlib.sha256(json.dumps(tmp,sort_keys=True,ensure_ascii=False,default=str,separators=(",",":")).encode()).hexdigest()
    return deepcopy(finals[selected]) if selected else None,proof

def _stream_causal_summary(knowledge:dict[str,Any])->dict[str,Any]:
    edges=[]; authorities=[]
    for rel in knowledge.get("relations",[]):
        kind=str(rel.get("kind","")); rid=rel.get("relation_id"); auth="AUTHORITATIVE" if kind.endswith("_authoritative_stream") else ("DERIVED_EXACT" if kind in {"functional_stream","exact_arithmetic_stream","aggregate_sum_stream","aggregate_count_stream"} else "INFERRED")
        authorities.append({"relation_id":rid,"kind":kind,"authority":auth})
        if kind=="functional_stream": edges.append({"from":rel.get("determinant"),"to":rel.get("output"),"relation_id":rid})
        elif kind=="exact_arithmetic_stream" and rel.get("direction_certified"):
            info=knowledge.get("arithmetic_lookup",{}).get(rid,{})
            for src in (info.get("a"),info.get("b")):
                if src is not None: edges.append({"from":src,"to":info.get("target"),"relation_id":rid})
        elif kind in {"aggregate_sum_stream","aggregate_count_stream"}:
            info=knowledge.get("aggregate_lookup",{}).get(rid,{}); feat=info.get("feature",[])
            if len(feat)>=2: edges.append({"from":str(feat[1]),"to":info.get("target"),"relation_id":rid})
    return {"contract":"json-consistency-repair.double-cone.v1","mode":"BOUNDED_STREAM","edges":edges,"relation_authority_ledger":authorities,"dominance_scope":"RECORD_LOCAL_PATHWISE"}


def _record_bridge_enabled(cfg: StreamingConfig) -> bool:
    return bool(cfg.constraint_rules or cfg.json_schema is not None or cfg.system_rules or cfg.source_context or cfg.source_manifest
                or cfg.semantic_quotient_rules or (cfg.exact_disk_registry and cfg.moment_rules))


def _stream_context_as_record_arrays(cfg: StreamingConfig) -> tuple[dict[str,Any], ...]:
    """Adapt development/heldout context to a root record array for stream-level lifecycle checks.

    A source may be a top-level array of objects, may declare stream_records_path, or may contain
    exactly one object-array carrier. Ambiguous carriers are ignored rather than guessed.
    """
    from .analyzers import object_arrays
    adapted=[]
    for src in cfg.source_context or ():
        if str(src.get("role")) not in {"development","heldout"}: continue
        value=src.get("value"); arr=None
        path=src.get("stream_records_path")
        if isinstance(path,str):
            ok,v=_get_path(value,path); arr=v if ok and isinstance(v,list) and all(isinstance(x,dict) for x in v) else None
        elif isinstance(value,list) and len(value)>=3 and all(isinstance(x,dict) for x in value):
            arr=value
        elif isinstance(value,dict):
            carriers=[a for _,a in object_arrays(value)]
            if len(carriers)==1: arr=carriers[0]
        if arr is None: continue
        row={k:deepcopy(v) for k,v in src.items() if k!="value"}; row["value"]=deepcopy(arr); adapted.append(row)
    return tuple(adapted)


def _repair_record_with_pass024_bridges(record: Any, cfg: StreamingConfig) -> tuple[Any,dict[str,Any]]:
    """Exact per-record bridge for DSL/schema/system/multi-source/moment semantics.

    PASS024 composes independent authoritative families as sequential atomic stages. Repeated-array
    analyzers are run against a synthetic one-record array, then projected back to the record. The
    synthetic carrier is never serialized and therefore cannot leak into user data or provenance.
    """
    if not _record_bridge_enabled(cfg):
        return record,{"enabled":False,"committed_edits":0,"remaining_inner_issues":0,"relations":0,"multisource":False,"stages":[]}
    from .engine import RepairConfig, repair_object
    # Verify raw stream rules before adapting routing/path coordinates.  Internal record-carrier
    # copies are then trusted only as transforms of this already-gated configuration.
    cfg, bridge_semantic_preflight = project_verified_semantic_config(cfg)
    bridge_semantic_firewall = preanalysis_as_firewall(bridge_semantic_preflight)
    current=deepcopy(record); committed=0; remaining=0; rels=0; stages=[]
    materialization_totals=Counter(); materialization_proof_samples=[]
    authority_registry_samples=[]; evidence_poison_findings=Counter()
    robust_envelope_samples=[]; robust_gate_reasons=Counter()
    semantic_claim_samples=[]; semantic_claim_blocked=Counter()
    control_firewall_samples=[]; control_plan_samples=[]
    if bridge_semantic_firewall.get("enabled") is not False:
        semantic_claim_samples.append(deepcopy(bridge_semantic_firewall))
        semantic_claim_blocked["configuration_gates"] += int(bridge_semantic_firewall.get("gated_rule_count",0) or 0)

    def _absorb_materialization(res):
        wm=(res.report.get("witness_materialization") or {})
        for crow in wm.get("cycles") or []:
            cert=(crow or {}).get("certificate") or {}
            for k,v in (cert.get("summary") or {}).items():
                materialization_totals[k]+=int(v or 0)
            for t in cert.get("terminals") or []:
                if t.get("status")=="MATERIALIZED_EXACT" and len(materialization_proof_samples)<16:
                    materialization_proof_samples.append({
                        "terminal_id":t.get("terminal_id"),"target_path":t.get("target_path"),
                        "status":t.get("status"),"witness_kind":t.get("witness_kind"),
                        "selected_value_digest":t.get("selected_value_digest"),
                        "materialization_proof_sha256":t.get("materialization_proof_sha256"),
                        "candidate_id":t.get("candidate_id"),
                        "search_sha256":((t.get("search_contract") or {}).get("search_sha256")),
                    })

    def _absorb_authority(res):
        reg=res.report.get("scoped_authority") or {}
        sha=reg.get("registry_sha256") if isinstance(reg,dict) else None
        if sha and all(x.get("registry_sha256")!=sha for x in authority_registry_samples) and len(authority_registry_samples)<16:
            authority_registry_samples.append(deepcopy(reg))
        poison=res.report.get("evidence_poisoning_firewall") or {}
        for f in poison.get("findings") or []:
            if isinstance(f,dict) and f.get("code"): evidence_poison_findings[str(f.get("code"))]+=1

    def _absorb_robust(res):
        rb=res.report.get("robust_envelope") or {}
        final=rb.get("final") or {}
        if isinstance(final,dict) and final.get("certificate_sha256") and all(x.get("certificate_sha256")!=final.get("certificate_sha256") for x in robust_envelope_samples) and len(robust_envelope_samples)<16:
            robust_envelope_samples.append(deepcopy(final))
        for d in final.get("decisions") or []:
            if not d.get("allow"):
                for ev in d.get("evaluations") or []:
                    if ev.get("reason"): robust_gate_reasons[str(ev.get("reason"))]+=1

    def _absorb_semantic(res):
        sp=res.report.get("semantic_claim_provenance") or {}
        final=sp.get("final") or {}
        if isinstance(final,dict) and final.get("certificate_sha256") and all(x.get("certificate_sha256")!=final.get("certificate_sha256") for x in semantic_claim_samples) and len(semantic_claim_samples)<16:
            semantic_claim_samples.append(deepcopy(final))
        semantic_claim_blocked["candidates"] += int(final.get("blocked_candidate_count",0) or 0)
        semantic_claim_blocked["relations"] += int(final.get("blocked_relation_count",0) or 0)

    def _absorb_control(res):
        rc=res.report.get("repair_controllability") or {}
        for row in rc.get("firewall_cycles") or []:
            cert=(row or {}).get("certificate") if isinstance(row,dict) else None
            if isinstance(cert,dict) and cert.get("certificate_sha256") and len(control_firewall_samples)<16 and all(x.get("certificate_sha256")!=cert.get("certificate_sha256") for x in control_firewall_samples):
                control_firewall_samples.append(deepcopy(cert))
        for row in rc.get("control_plan_cycles") or []:
            cert=(row or {}).get("certificate") if isinstance(row,dict) else None
            if isinstance(cert,dict) and cert.get("certificate_sha256") and len(control_plan_samples)<16 and all(x.get("certificate_sha256")!=cert.get("certificate_sha256") for x in control_plan_samples):
                control_plan_samples.append(deepcopy(cert))

    def _base_cfg(**kw):
        robust_rules=kw.pop("robust_envelope_rules",cfg.robust_envelope_rules)
        # Every record-local stage must still see the original source corpus so PASS033 can
        # reproduce SOURCE_EXACT/DERIVED_EXACT claim lineage.  Multi-source repair itself is
        # disabled by default here; the dedicated schema_multisource stage opts back in.
        source_context=kw.pop("source_context",cfg.source_context)
        source_manifest=kw.pop("source_manifest",cfg.source_manifest)
        enable_multisource=kw.pop("enable_multisource",False)
        control_rules=[]
        for raw in cfg.controllability_rules or ():
            if not isinstance(raw,dict) or raw.get("document") not in (None,"","@stream"): continue
            rr=deepcopy(raw); rr.pop("document",None); control_rules.append(rr)
        return RepairConfig(max_cycles=max(3,min(int(cfg.max_cycles),6)),stable_cycles_required=1,strong_fixed_point_cycles_required=1,
                            require_independent_evidence=1,security_limits=cfg.security_limits,enable_final_certification=False,
                            auto_graph_discovery=False,record_carrier_mode=True,robust_envelope_rules=tuple(robust_rules or ()),
                            source_context=source_context,source_manifest=source_manifest,enable_multisource=enable_multisource,
                            enable_semantic_claim_provenance=False,
                            schema_claim_provenance=deepcopy(cfg.schema_claim_provenance),
                            enable_symmetry_obstruction=cfg.enable_symmetry_obstruction,
                            semantic_quotient_rules=cfg.semantic_quotient_rules,enable_relation_falsifier=cfg.enable_relation_falsifier,
                            falsifier_min_rows=cfg.falsifier_min_rows,falsifier_max_relations=cfg.falsifier_max_relations,falsifier_max_negative_controls=cfg.falsifier_max_negative_controls,
                            enable_controllability=cfg.enable_controllability,
                            controllability_rules=tuple(control_rules),require_explicit_mutation_permission=cfg.require_explicit_mutation_permission,
                            max_control_edits=cfg.max_control_edits,max_control_cost=cfg.max_control_cost,**kw)

    def run_stage(name:str, **kw):
        nonlocal current,committed,remaining,rels
        if not any(v for k,v in kw.items() if k not in {"schema_source"}): return
        out,res=repair_object(current,_base_cfg(**kw)); current=out
        _absorb_materialization(res); _absorb_authority(res); _absorb_robust(res); _absorb_semantic(res); _absorb_control(res)
        committed+=int(res.committed_edits); remaining+=int(res.remaining_issues); rels+=len(res.report.get("relations",[]))
        stages.append({"stage":name,"committed_edits":int(res.committed_edits),"remaining_issues":int(res.remaining_issues),"status":res.final_status,
                       "materialization_summary":((res.report.get("witness_materialization") or {}).get("summary") or {})})

    def run_wrapped_stage(name:str, rules_key:str, rules:tuple[dict[str,Any],...]):
        nonlocal current,committed,remaining,rels
        normalized=[]
        for raw in rules or ():
            if not isinstance(raw,dict): continue
            if raw.get("document") not in (None,"@stream"): continue
            ap=raw.get("array_path")
            # Record-local rules in streaming are materialized as a one-element root array.
            if ap not in (None,"","@record"): continue
            rr={k:deepcopy(v) for k,v in raw.items() if k!="document"}
            rr["array_path"]=""
            normalized.append(rr)
        if not normalized or not isinstance(current,dict): return
        wrapped=[deepcopy(current)]
        adapted_robust=[]
        for r in cfg.robust_envelope_rules or ():
            if not isinstance(r,dict) or r.get("document") not in (None,"@stream"): continue
            rr=deepcopy(r)
            for key in ("path","path_prefix","center_path","lower_path","upper_path","radius_path","sigma_path","timestamp_path","regime_path","state_path","metric_path","uncertainty_radius_path"):
                if isinstance(rr.get(key),str): rr[key]="/0"+rr[key] if rr[key] else "/0"
            adapted_robust.append(rr)
        out,res=repair_object(wrapped,_base_cfg(robust_envelope_rules=tuple(adapted_robust),**{rules_key:tuple(normalized)}))
        _absorb_materialization(res); _absorb_authority(res); _absorb_robust(res); _absorb_semantic(res); _absorb_control(res)
        if isinstance(out,list) and len(out)==1 and isinstance(out[0],dict): current=out[0]
        committed+=int(res.committed_edits); remaining+=int(res.remaining_issues); rels+=len(res.report.get("relations",[]))
        stages.append({"stage":name,"committed_edits":int(res.committed_edits),"remaining_issues":int(res.remaining_issues),"status":res.final_status,
                       "materialization_summary":((res.report.get("witness_materialization") or {}).get("summary") or {})})

    # Root-document schema/default/authority semantics operate directly on the record.
    run_stage("schema_multisource",json_schema=cfg.json_schema,schema_source=cfg.schema_source,
              source_context=cfg.source_context,source_manifest=cfg.source_manifest,enable_multisource=True,source_min_support=cfg.source_min_support,
              source_min_group_support=cfg.source_min_group_support,source_max_fields=cfg.source_max_fields)
    # DSL constraints are repeated-record semantics; one stream record is their exact local carrier.
    run_wrapped_stage("constraints","constraint_rules",cfg.constraint_rules)

    # Arbitrary graph/migration plans are root transactions. @stream is only a routing tag.
    system_rules=[]
    for raw in cfg.system_rules or ():
        if not isinstance(raw,dict) or raw.get("document") not in (None,"@stream"): continue
        system_rules.append({k:deepcopy(v) for k,v in raw.items() if k!="document"})
    run_stage("system",system_rules=tuple(system_rules))

    # PASS021 multi-path unit normalization and other moment plans now materialize exactly per record.
    run_wrapped_stage("moments","moment_rules",cfg.moment_rules)

    lifecycle_ctx=_stream_context_as_record_arrays(cfg)
    lifecycle_summary=None
    if lifecycle_ctx and isinstance(current,dict):
        m=deepcopy(cfg.source_manifest or {})
        wrap_cfg=RepairConfig(max_cycles=max(3,min(int(cfg.max_cycles),6)),stable_cycles_required=1,strong_fixed_point_cycles_required=1,
            require_independent_evidence=1,security_limits=cfg.security_limits,enable_final_certification=False,
            source_context=lifecycle_ctx,source_manifest=m,source_min_support=cfg.source_min_support,
            source_min_group_support=cfg.source_min_group_support,source_max_fields=cfg.source_max_fields,
            min_support=max(2,cfg.source_min_support),auto_graph_discovery=False,robust_envelope_rules=cfg.robust_envelope_rules,
            enable_semantic_claim_provenance=False,schema_claim_provenance=deepcopy(cfg.schema_claim_provenance),
            enable_symmetry_obstruction=cfg.enable_symmetry_obstruction,semantic_quotient_rules=cfg.semantic_quotient_rules,
            enable_relation_falsifier=cfg.enable_relation_falsifier,falsifier_min_rows=cfg.falsifier_min_rows,falsifier_max_relations=cfg.falsifier_max_relations,falsifier_max_negative_controls=cfg.falsifier_max_negative_controls,
            enable_controllability=cfg.enable_controllability,controllability_rules=tuple({k:deepcopy(v) for k,v in r.items() if k!="document"} for r in (cfg.controllability_rules or ()) if isinstance(r,dict) and r.get("document") in (None,"","@stream")),
            require_explicit_mutation_permission=cfg.require_explicit_mutation_permission,max_control_edits=cfg.max_control_edits,max_control_cost=cfg.max_control_cost)
        wrapped,wres=repair_object([current],wrap_cfg)
        _absorb_materialization(wres); _absorb_authority(wres); _absorb_robust(wres); _absorb_semantic(wres); _absorb_control(wres)
        if isinstance(wrapped,list) and len(wrapped)==1 and isinstance(wrapped[0],dict): current=wrapped[0]
        committed+=int(wres.committed_edits); remaining+=int(wres.remaining_issues); rels+=len(wres.report.get("relations",[]))
        stages.append({"stage":"multisource_lifecycle","committed_edits":int(wres.committed_edits),"remaining_issues":int(wres.remaining_issues),"status":wres.final_status})
        life=((wres.report.get("multisource_assimilation") or {}).get("final") or {}).get("relation_lifecycle") or {}
        lifecycle_summary={k:life.get(k,0) for k in ("heldout_confirmed","portable","global_refuted","dependent_only")}

    return current,{"enabled":True,"committed_edits":committed,"remaining_inner_issues":remaining,"relations":rels,"stages":stages,
                     "multisource":bool(cfg.source_context),"lifecycle":lifecycle_summary,
                     "witness_materialization":{"totals":dict(sorted(materialization_totals.items())),
                                                "proof_samples":materialization_proof_samples,
                                                "proof_sample_count":len(materialization_proof_samples)},
                     "scoped_authority":{"registry_samples":authority_registry_samples,"registry_sample_count":len(authority_registry_samples),
                                         "evidence_poison_findings":dict(sorted(evidence_poison_findings.items()))},
                     "robust_envelope":{"certificate_samples":robust_envelope_samples,"certificate_sample_count":len(robust_envelope_samples),"gate_reasons":dict(sorted(robust_gate_reasons.items()))},
                     "semantic_claim_provenance":{"certificate_samples":semantic_claim_samples,"certificate_sample_count":len(semantic_claim_samples),"blocked":dict(sorted(semantic_claim_blocked.items()))},
                     "repair_controllability":{"firewall_samples":control_firewall_samples,"control_plan_samples":control_plan_samples},
                     "constraint_bridge":bool(cfg.constraint_rules or cfg.json_schema is not None),"system_bridge":bool(cfg.system_rules),
                     "moment_bridge":bool(cfg.exact_disk_registry and cfg.moment_rules)}


def _apply_knowledge(input_path: Path, output_path: Path, journal_path: Path, knowledge: dict[str, Any], cfg: StreamingConfig, fmt: str,
                     control_used_before: int = 0, control_cost_used_before: int = 0) -> dict[str, Any]:
    input_h = _semantic_stream_digest_init(); output_h = _semantic_stream_digest_init()
    edits = 0; records = 0; issue_count = 0; conflicts = 0; samples: list[dict[str, Any]] = []; solver_status_counts=Counter()
    control_actions_used=0; control_cost_used=0
    parallel_attempted=0; parallel_returned=0; parallel_divergent=0; parallel_proof_samples=[]
    bridge_enabled=_record_bridge_enabled(cfg); bridge_records=0; bridge_committed=0; bridge_remaining=0; bridge_relations=0; lifecycle_totals=Counter()
    stream_materialization_totals=Counter(); stream_materialization_proof_samples=[]
    stream_authority_registry_samples=[]; stream_poison_findings=Counter()
    stream_robust_samples=[]; stream_robust_gate_reasons=Counter()
    stream_semantic_samples=[]; stream_semantic_blocked=Counter()
    stream_control_firewall_samples=[]; stream_control_plan_samples=[]
    if knowledge.get("logic_system_certificate",{}).get("status") == "UNSAT":
        issue_count += 1
        samples.append({"record":None,"analyzer":"stream_logic","code":"logical_rule_system_unsat","path":"","repairable":False,
                        "sat_certificate":knowledge.get("logic_system_certificate")})
    with _RecordWriter(output_path, fmt) as writer, journal_path.open("w", encoding="utf-8", newline="\n") as journal:
        for env in iter_records(input_path, stream_format=fmt, chunk_bytes=cfg.chunk_bytes, security_limits=cfg.security_limits):
            records += 1; _semantic_stream_digest_update(input_h, env.value)
            original=deepcopy(env.value); record=deepcopy(env.value)
            cands, issues = _record_candidates(record, knowledge) if isinstance(record,dict) else ([],[])
            # PASS036: native stream candidates are subject to the same mutation-control surface
            # as record-bridge candidates.  The adapter uses deterministic candidate identities.
            stream_control_firewall=None
            if cands and isinstance(record,dict):
                objs=[]; byid={}
                for j,c in enumerate(cands):
                    cid=f"stream:{env.index}:{j}:{c.get('analyzer')}:{c.get('path')}"
                    op="replace"
                    meta={"add_if_missing":bool(c.get("add_if_missing"))}
                    obj=Candidate(cid,str(c.get("analyzer") or "stream"),op,str(c.get("path") or ""),deepcopy(c.get("old_value")),deepcopy(c.get("new_value")),str(c.get("reason") or "stream repair"),float(c.get("confidence",1.0)),1,tuple(c.get("evidence") or ()),meta)
                    objs.append(obj); byid[cid]=c
                filtered,stream_control_firewall=apply_controllability_firewall(record,AnalysisResult([],objs,[]),cfg,document="@stream")
                allowed={x.candidate_id for x in filtered.candidates}
                cands=[byid[x.candidate_id] for x in objs if x.candidate_id in allowed]
                for ii in filtered.issues:
                    issues.append(ii.to_dict())
            chosen, nconf, solver_cert = _choose_candidates_with_certificate(cands,enable_parallel_routes=cfg.enable_parallel_tie_routes,max_parallel_routes=cfg.max_parallel_tie_routes)
            solver_cert["controllability_firewall"]=stream_control_firewall
            parallel_applied=False
            if solver_cert.get("parallel_routes"):
                parallel_attempted+=1
                resolved,proof=_resolve_stream_parallel_record(record,solver_cert["parallel_routes"],knowledge,cfg)
                if len(parallel_proof_samples)<cfg.issue_sample_limit: parallel_proof_samples.append({"record":env.index,**proof})
                if proof.get("ok") and resolved is not None:
                    record=resolved; parallel_applied=True; parallel_returned+=1; nconf=max(0,nconf-int(solver_cert.get("ambiguous_path_count",0)))
                    solver_cert["status"]="RETURN_PROOF_EQUIVALENT"
                else:
                    parallel_divergent+=1; solver_cert["status"]="RETURN_PROOF_DIVERGENT"
            if chosen and isinstance(record,dict) and not solver_cert.get("parallel_routes"):
                pobj=[]; pmap={}
                for j,c in enumerate(chosen):
                    cid=f"stream-selected:{env.index}:{j}:{c.get('analyzer')}:{c.get('path')}"
                    obj=Candidate(cid,str(c.get("analyzer") or "stream"),"replace",str(c.get("path") or ""),deepcopy(c.get("old_value")),deepcopy(c.get("new_value")),str(c.get("reason") or "stream repair"),float(c.get("confidence",1.0)),1,tuple(c.get("evidence") or ()),{"add_if_missing":bool(c.get("add_if_missing"))})
                    pobj.append(obj); pmap[cid]=c
                ordered,pcert=compile_control_plan(record,pobj,cfg,document="@stream",preserve_order=False,
                                                   used_edits=control_used_before+control_actions_used,
                                                   used_cost=control_cost_used_before+control_cost_used)
                solver_cert["controllability_plan"]=pcert
                if pcert.get("reachability")=="UNREACHABLE":
                    chosen=[]; solver_cert["status"]="IDENTIFIABLE_BUT_UNREACHABLE"
                else:
                    chosen=[pmap[x.candidate_id] for x in ordered]
            for cc,target in ((solver_cert.get("controllability_firewall"),stream_control_firewall_samples),(solver_cert.get("controllability_plan"),stream_control_plan_samples)):
                if isinstance(cc,dict) and cc.get("certificate_sha256") and len(target)<cfg.issue_sample_limit and all(x.get("certificate_sha256")!=cc.get("certificate_sha256") for x in target):
                    target.append(deepcopy(cc))
            conflicts += nconf; solver_status_counts[solver_cert["status"]]+=1
            issue_count += len(issues) + nconf
            if len(samples) < cfg.issue_sample_limit:
                for issue in issues[:cfg.issue_sample_limit - len(samples)]: samples.append({"record": env.index, **issue})

            pathwise_applied=0
            if parallel_applied:
                if record != original:
                    journal.write(json.dumps({"record":env.index,"record_replace":True,"old_record":original,"new_record":record,
                                              "analyzer":"pass026_parallel_return","return_proof":True},ensure_ascii=False,sort_keys=True,separators=(",",":")) + "\n")
                    edits += 1; control_actions_used += 1; control_cost_used += 1
            else:
                for c in chosen:
                    if _set_path(record, c["path"], c["old_value"], c["new_value"], add_if_missing=c.get("add_if_missing", False)):
                        pathwise_applied += 1; control_actions_used += 1; control_cost_used += 1
                        if not bridge_enabled:
                            patch = {"record": env.index, "path": c["path"], "old_value": c["old_value"], "new_value": c["new_value"],
                                     "add_if_missing": c.get("add_if_missing", False), "analyzer": c["analyzer"], "families": c.get("families", []),
                                     "evidence": c.get("evidence", []), "relation_id": c.get("relation_id")}
                            journal.write(json.dumps(patch, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
                            edits += 1

            if bridge_enabled and not parallel_applied:
                bridge_cfg=cfg
                if cfg.max_control_edits is not None or cfg.max_control_cost is not None:
                    rem_edits=None if cfg.max_control_edits is None else max(0,int(cfg.max_control_edits)-(control_used_before+control_actions_used))
                    rem_cost=None if cfg.max_control_cost is None else max(0,int(cfg.max_control_cost)-(control_cost_used_before+control_cost_used))
                    bridge_cfg=StreamingConfig(**{**cfg.__dict__,"max_control_edits":rem_edits,"max_control_cost":rem_cost})
                bridged,bsummary=_repair_record_with_pass024_bridges(record,bridge_cfg); record=bridged; bridge_records+=1
                bridge_committed+=int(bsummary.get("committed_edits",0)); bridge_remaining+=int(bsummary.get("remaining_inner_issues",0)); bridge_relations+=int(bsummary.get("relations",0))
                control_actions_used += int(bsummary.get("committed_edits",0)); control_cost_used += int(bsummary.get("committed_edits",0))
                life=bsummary.get("lifecycle") or {}
                for k,v in life.items(): lifecycle_totals[k]+=int(v or 0)
                wm=bsummary.get("witness_materialization") or {}
                sa=bsummary.get("scoped_authority") or {}
                for reg in sa.get("registry_samples") or []:
                    if isinstance(reg,dict) and reg.get("registry_sha256") and all(x.get("registry_sha256")!=reg.get("registry_sha256") for x in stream_authority_registry_samples) and len(stream_authority_registry_samples)<cfg.issue_sample_limit:
                        stream_authority_registry_samples.append(deepcopy(reg))
                for k,v in (sa.get("evidence_poison_findings") or {}).items(): stream_poison_findings[str(k)]+=int(v or 0)
                rc=bsummary.get("repair_controllability") or {}
                for cert in rc.get("firewall_samples") or []:
                    if isinstance(cert,dict) and cert.get("certificate_sha256") and len(stream_control_firewall_samples)<cfg.issue_sample_limit and all(x.get("certificate_sha256")!=cert.get("certificate_sha256") for x in stream_control_firewall_samples):
                        stream_control_firewall_samples.append(deepcopy(cert))
                for cert in rc.get("control_plan_samples") or []:
                    if isinstance(cert,dict) and cert.get("certificate_sha256") and len(stream_control_plan_samples)<cfg.issue_sample_limit and all(x.get("certificate_sha256")!=cert.get("certificate_sha256") for x in stream_control_plan_samples):
                        stream_control_plan_samples.append(deepcopy(cert))
                sp=bsummary.get("semantic_claim_provenance") or {}
                for cert in sp.get("certificate_samples") or []:
                    if isinstance(cert,dict) and cert.get("certificate_sha256") and all(x.get("certificate_sha256")!=cert.get("certificate_sha256") for x in stream_semantic_samples) and len(stream_semantic_samples)<cfg.issue_sample_limit:
                        stream_semantic_samples.append(deepcopy(cert))
                for k,v in (sp.get("blocked") or {}).items(): stream_semantic_blocked[str(k)]+=int(v or 0)
                rb=bsummary.get("robust_envelope") or {}
                for cert in rb.get("certificate_samples") or []:
                    if isinstance(cert,dict) and cert.get("certificate_sha256") and all(x.get("certificate_sha256")!=cert.get("certificate_sha256") for x in stream_robust_samples) and len(stream_robust_samples)<cfg.issue_sample_limit:
                        stream_robust_samples.append(deepcopy(cert))
                for k,v in (rb.get("gate_reasons") or {}).items(): stream_robust_gate_reasons[str(k)]+=int(v or 0)
                for k,v in (wm.get("totals") or {}).items(): stream_materialization_totals[k]+=int(v or 0)
                for pr in wm.get("proof_samples") or []:
                    if len(stream_materialization_proof_samples)<cfg.issue_sample_limit:
                        stream_materialization_proof_samples.append({"record":env.index,**pr})
                issue_count += int(bsummary.get("remaining_inner_issues",0))
                if record != original:
                    journal.write(json.dumps({"record":env.index,"record_replace":True,"old_record":original,"new_record":record,
                                              "analyzer":"pass029_witness_materialization_record_bridge" if int(((bsummary.get("witness_materialization") or {}).get("totals") or {}).get("MATERIALIZED_EXACT",0))>0 else "pass024_record_bridge",
                                              "pathwise_candidates":pathwise_applied,
                                              "bridge_committed_edits":int(bsummary.get("committed_edits",0))},ensure_ascii=False,sort_keys=True,separators=(",",":")) + "\n")
                    # One atomic record transaction is the externally committed streaming edit.
                    edits += 1
            _semantic_stream_digest_update(output_h, record); writer.write(record)
    return {"records": records, "edits": edits, "issues_observed": issue_count, "conflicts": conflicts, "issue_samples": samples,
            "input_digest": input_h.hexdigest(), "output_digest": output_h.hexdigest(),
            "control_actions_used":control_actions_used,"control_cost_used":control_cost_used,
            "record_bridge":{"enabled":bridge_enabled,"records_evaluated":bridge_records,"atomic_record_transactions":edits if bridge_enabled else 0,
                             "inner_committed_edits":bridge_committed,"remaining_inner_issues":bridge_remaining,"relation_observations":bridge_relations,
                             "lifecycle_totals":dict(sorted(lifecycle_totals.items())),
                             "witness_materialization_totals":dict(sorted(stream_materialization_totals.items())),
                             "witness_materialization_proof_samples":stream_materialization_proof_samples,
                             "authority_registry_samples":stream_authority_registry_samples,
                             "evidence_poison_findings":dict(sorted(stream_poison_findings.items())),
                             "robust_envelope":{"certificate_samples":stream_robust_samples,"certificate_sample_count":len(stream_robust_samples),"gate_reasons":dict(sorted(stream_robust_gate_reasons.items()))},
                             "semantic_claim_provenance":{"certificate_samples":stream_semantic_samples,"certificate_sample_count":len(stream_semantic_samples),"blocked":dict(sorted(stream_semantic_blocked.items()))},
                             "constraint_schema_exact":bool(cfg.constraint_rules or cfg.json_schema is not None),
                             "system_plans_exact":bool(cfg.system_rules),"multisource_enabled":bool(cfg.source_context)},
            "repair_controllability":{"firewall_samples":stream_control_firewall_samples,"control_plan_samples":stream_control_plan_samples},
            "minimal_transfer":{"solver_contract":"json-consistency-repair.streaming-minimal-transfer.v1","status_counts":dict(sorted(solver_status_counts.items())),"selected_patch_count":edits,"ambiguous_path_count":conflicts,
                                "parallel_exact_minimum_routes":{"contract":"json-consistency-repair.parallel-exact-routes.v1","return_proof_contract":"json-consistency-repair.return-proof.v1",
                                                                  "attempted_records":parallel_attempted,"returned_records":parallel_returned,"divergent_records":parallel_divergent,"proof_samples":parallel_proof_samples}}}


def _journal_iter(path: Path) -> Iterator[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip(): yield json.loads(line)


def _inverse_one_cycle(final_path: Path, restored_path: Path, journal_path: Path, cfg: StreamingConfig, fmt: str) -> dict[str, Any]:
    # Journal is ordered by record. PASS024 may persist one whole-record transaction, which
    # makes arbitrary plans/moves/removals exactly reversible without retaining the stream in RAM.
    jiter = iter(_journal_iter(journal_path)); pending = next(jiter, None)
    h = _semantic_stream_digest_init(); ok = True; edits = 0
    with _RecordWriter(restored_path, fmt) as writer:
        for env in iter_records(final_path, stream_format=fmt, chunk_bytes=cfg.chunk_bytes, security_limits=cfg.security_limits):
            patches = []
            while pending is not None and pending["record"] == env.index:
                patches.append(pending); pending = next(jiter, None)
            record = env.value
            if any(p.get("record_replace") for p in patches):
                if len(patches)!=1 or not patches[0].get("record_replace") or record != patches[0].get("new_record"):
                    ok=False; break
                record=patches[0].get("old_record"); edits+=1
            else:
                for p in reversed(patches):
                    if p.get("add_if_missing") and p.get("old_value") is None:
                        applied = _delete_added(record, p["path"], p["new_value"])
                    else:
                        applied = _set_path(record, p["path"], p["new_value"], p["old_value"], add_if_missing=False)
                    if not applied: ok = False; break
                    edits += 1
            if not ok: break
            _semantic_stream_digest_update(h, record); writer.write(record)
    if pending is not None: ok = False
    return {"ok": ok, "restored_digest": h.hexdigest() if ok else None, "inverse_edits": edits}


def _merge_ledger(ledger: dict[str, Any], relations: list[dict[str, Any]], cycle: int) -> list[str]:
    current = {r["relation_id"] for r in relations}; new = []
    for rid, entry in ledger.items(): entry["survives_current"] = rid in current
    for rel in relations:
        rid = rel["relation_id"]
        if rid not in ledger:
            ledger[rid] = {"relation": rel, "first_seen_cycle": cycle, "last_seen_cycle": cycle, "seen_cycles": 1, "survives_current": True,
                           "strength_history": [{"cycle": cycle, "confidence": rel.get("confidence"), "support": rel.get("support")}]}
            new.append(rid)
        else:
            e = ledger[rid]; e["relation"] = rel; e["last_seen_cycle"] = cycle; e["seen_cycles"] += 1; e["survives_current"] = True
            e["strength_history"].append({"cycle": cycle, "confidence": rel.get("confidence"), "support": rel.get("support")})
    return sorted(new)



def _compile_stream_relation_falsification(input_path: Path, knowledge: dict[str,Any], cfg: StreamingConfig, fmt: str) -> dict[str,Any]:
    """Bounded one-pass attacks over native cross-record streaming relations.

    This uses zero-input ablation and lag-one input permutations.  It never retains the full
    stream and never treats a synthetic control as an observation.
    """
    contract="json-consistency-repair.relation-falsification.v1"
    rels=sorted((knowledge.get("relations") or []),key=lambda r:str(r.get("relation_id") or ""))[:max(0,int(cfg.falsifier_max_relations))]
    specs={str(r.get("relation_id")):r for r in rels if r.get("relation_id")}
    acc={rid:{"rows":0,"matches":0,"targets":Counter(),"lag_valid":0,"lag_matches":0,"prev_input":None,
                  "folds":[defaultdict(Counter),defaultdict(Counter)],"fold_truncated":False}
         for rid in specs}
    for env in iter_records(input_path,stream_format=fmt,chunk_bytes=cfg.chunk_bytes,security_limits=cfg.security_limits):
        if not isinstance(env.value,dict): continue
        rec=env.value
        for rid,rel in specs.items():
            kind=str(rel.get("kind") or ""); a=acc[rid]
            if kind=="functional_stream":
                okd,dv=_get_path(rec,str(rel.get("determinant") or ((rel.get("inputs") or [""])[0])))
                okt,tv=_get_path(rec,str(rel.get("output") or ""))
                if not (okd and okt) or dv is None or tv is None: continue
                dk=_jkey(dv); tk=_jkey(tv)
                if dk is None or tk is None: continue
                entry=_functional_entry(knowledge,rid,dk)
                if entry is None: continue
                a["rows"]+=1; a["targets"][tk]+=1
                a["matches"]+=int(_jkey(entry.get("target",entry.get("value")))==tk)
                # Exact split maps are bounded by the declared relation group ceiling.
                fold=a["folds"][env.index%2]
                if dk in fold or len(fold)<max(1,int(cfg.max_functional_groups)):
                    fold[dk][tk]+=1
                else:
                    a["fold_truncated"]=True
            elif kind=="exact_arithmetic_stream":
                ins=list(rel.get("inputs") or []); out=str(rel.get("output") or ""); op=str(rel.get("operator") or "")
                if len(ins)!=2 or op not in {"+","-","*","/"}: continue
                oka,av=_get_path(rec,ins[0]); okb,bv=_get_path(rec,ins[1]); okt,tv=_get_path(rec,out)
                if not (oka and okb and okt): continue
                da,db,dt=_decimal(av),_decimal(bv),_decimal(tv)
                if da is None or db is None or dt is None: continue
                try:
                    exp=(da+db if op=="+" else da-db if op=="-" else da*db if op=="*" else (None if db==0 else da/db))
                except Exception: exp=None
                if exp is None: continue
                a["rows"]+=1; a["targets"][str(dt)]+=1; a["matches"]+=int(exp==dt)
                prev=a.get("prev_input")
                if prev is not None:
                    try:
                        lag=(prev+db if op=="+" else prev-db if op=="-" else prev*db if op=="*" else (None if db==0 else prev/db))
                    except Exception: lag=None
                    if lag is not None:
                        a["lag_valid"]+=1; a["lag_matches"]+=int(lag==dt)
                a["prev_input"]=da
            elif kind=="temporal_delta_stream":
                # The native temporal stream relation already commits an exact constant delta.
                # We serialize its status but leave active perturbation to record bridges until
                # a bounded datetime lag evaluator is available.
                continue

    decisions=[]; blocking=set()
    for rid,rel in specs.items():
        kind=str(rel.get("kind") or ""); src=str(rel.get("constraint_source") or rel.get("source") or "").lower(); a=acc[rid]
        base={"relation_id":rid,"kind":kind,"array_path":"@stream","authoritative":src=="authoritative"}
        if src=="authoritative":
            row={**base,"state":"AUTHORITATIVE_CONTRACT","applicable":False,"reason":"DECLARED_CONSTRAINT_NOT_EMPIRICAL_HYPOTHESIS"}
        elif kind=="functional_stream" and a["rows"]>=max(2,int(cfg.falsifier_min_rows)):
            observed=a["matches"]/a["rows"]
            _,bn=(sorted(a["targets"].items(),key=lambda kv:(-kv[1],kv[0]))[0] if a["targets"] else (None,0)); baseline=bn/a["rows"] if a["rows"] else 0.0
            conflicts=[]
            if not a["fold_truncated"]:
                f0,f1=a["folds"]
                for dk in sorted(set(f0)&set(f1)):
                    c0,c1=f0[dk],f1[dk]
                    if sum(c0.values())<max(1,int(cfg.min_group_support)) or sum(c1.values())<max(1,int(cfg.min_group_support)): continue
                    s0=sorted(c0.items(),key=lambda kv:(-kv[1],kv[0])); s1=sorted(c1.items(),key=lambda kv:(-kv[1],kv[0]))
                    u0=len(s0)==1 or s0[0][1]>s0[1][1]; u1=len(s1)==1 or s1[0][1]>s1[1][1]
                    if u0 and u1 and s0[0][0]!=s1[0][0]: conflicts.append({"determinant_value":dk,"fold0_mode":s0[0][0],"fold1_mode":s1[0][0]})
            if conflicts: state="ACTIVE_REFUTED"
            elif len(a["targets"])<=1 and abs(baseline-observed)<=1e-12: state="NEGATIVE_CONTROL_INVARIANT"
            elif baseline<observed: state="ADVERSARIAL_SURVIVED"
            else: state="OBSERVED_STABLE"
            row={**base,"state":state,"applicable":True,"rows":a["rows"],"observed_agreement":round(observed,12),
                 "zero_input_baseline_agreement":round(baseline,12),"fold_mapping_conflicts":conflicts,
                 "negative_controls":[{"kind":"ZERO_INPUT_ABLATION","agreement":round(baseline,12)}],
                 "negative_control_discriminating":bool(baseline<observed),"fold_state_truncated":bool(a["fold_truncated"])}
        elif kind=="exact_arithmetic_stream" and a["rows"]>=max(2,int(cfg.falsifier_min_rows)):
            observed=a["matches"]/a["rows"]
            _,bn=(sorted(a["targets"].items(),key=lambda kv:(-kv[1],kv[0]))[0] if a["targets"] else (None,0)); baseline=bn/a["rows"] if a["rows"] else 0.0
            lag=a["lag_matches"]/a["lag_valid"] if a["lag_valid"] else None
            if len(a["targets"])<=1 and abs(baseline-observed)<=1e-12: state="NEGATIVE_CONTROL_INVARIANT"
            elif lag is not None and lag<observed: state="ADVERSARIAL_SURVIVED"
            else: state="OBSERVED_STABLE"
            row={**base,"state":state,"applicable":True,"rows":a["rows"],"observed_agreement":round(observed,12),
                 "zero_input_baseline_agreement":round(baseline,12),"negative_controls":([{"kind":"LAG_ONE_INPUT0_PERMUTATION","agreement":round(lag,12)}] if lag is not None else []),
                 "negative_control_discriminating":bool(lag is not None and lag<observed)}
        else:
            row={**base,"state":"OBSERVED_ONLY","applicable":False,"reason":"NO_SAFE_BOUNDED_NATIVE_STREAM_ATTACK_OR_INSUFFICIENT_ROWS","rows":a["rows"]}
        sem=dict(row); row["decision_sha256"]=digest(sem); decisions.append(row)
        if row["state"] in {"ACTIVE_REFUTED","NEGATIVE_CONTROL_INVARIANT"}: blocking.add(rid)
    if cfg.enable_relation_falsifier and blocking:
        knowledge["relations"]=[r for r in knowledge.get("relations",[]) if str(r.get("relation_id")) not in blocking]
        for key in ("functional_lookup","arithmetic_lookup","aggregate_lookup"):
            table=knowledge.get(key)
            if isinstance(table,dict):
                for rid in blocking: table.pop(rid,None)
    states=Counter(r["state"] for r in decisions)
    cert={"contract":contract,"enabled":bool(cfg.enable_relation_falsifier),"root_digest":None,
          "stream_digest":None,"relation_count_examined":len(decisions),"relation_count_total":len(specs),"truncated":len(knowledge.get("relations",[]))>int(cfg.falsifier_max_relations),
          "max_relations":int(cfg.falsifier_max_relations),"states":dict(sorted(states.items())),"relations":decisions,
          "blocked_relation_ids":sorted(blocking if cfg.enable_relation_falsifier else set()),"blocked_candidate_ids":[],
          "blocked_relation_count":len(blocking if cfg.enable_relation_falsifier else set()),"blocked_candidate_count":0,
          "policy":{"authoritative_contracts":"RECORDED_NOT_EMPIRICALLY_FALSIFIED","synthetic_controls":"TEST_ONLY_NEVER_OBSERVATIONS",
                    "active_refutation":"INCOMPATIBLE_INDEPENDENT_DETERMINISTIC_FOLDS","negative_control_invariant":"ZERO_INPUT_BASELINE_EXPLAINS_RELATION_EXACTLY",
                    "mutation_gate_states":["ACTIVE_REFUTED","NEGATIVE_CONTROL_INVARIANT"],"unhandled_family":"OBSERVED_ONLY_NOT_PROMOTED_TO_PORTABLE_BY_THIS_LAYER"}}
    cert["certificate_sha256"]=digest(cert)
    return cert


def repair_stream_file(input_path: str | Path, output_path: str | Path | None = None, report_path: str | Path | None = None,
                       config: StreamingConfig | None = None, *, stream_format: str | None = None) -> StreamRepairResult:
    requested_cfg = config or StreamingConfig(exact_disk_registry=True)
    cfg, semantic_preanalysis = project_verified_semantic_config(requested_cfg)
    semantic_preanalysis_firewall = preanalysis_as_firewall(semantic_preanalysis)
    src = Path(input_path); fmt = _format_for_path(src, stream_format)
    if output_path is None:
        suffix = ".repaired.jsonl" if fmt == "jsonl" else ".repaired.json"
        out = src.with_name(src.stem + suffix)
    else: out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    workdir = Path(tempfile.mkdtemp(prefix="json-consistency-stream-")); cycle_files: list[Path] = []; journals: list[Path] = []
    current = src; cycles = []; ledger: dict[str, Any] = {}; stable = 0; strong_streak = 0; total_edits = 0
    control_budget_base_edits=max(0,int(cfg.control_budget_used_before_edits)); control_budget_base_cost=max(0,int(cfg.control_budget_used_before_cost))
    total_control_actions=control_budget_base_edits; total_control_cost=control_budget_base_cost; initial_digest = None; records = 0; peak_fields = 0
    previous_snapshot = None; previous_frontier = None; visited_digests=set(); any_oscillation=False
    required_strong=max(1,int(cfg.strong_fixed_point_cycles_required))
    try:
        for cycle in range(1, cfg.max_cycles + 1):
            knowledge = discover_stream_knowledge(current, cfg, stream_format=fmt, registry_dir=workdir / f"registry-{cycle}")
            knowledge["relation_falsification"] = _compile_stream_relation_falsification(current,knowledge,cfg,fmt)
            records = knowledge["records"]; peak_fields = max(peak_fields, knowledge["bounded_state"]["tracked_fields"])
            new_relations = _merge_ledger(ledger, knowledge["relations"], cycle)
            stage = workdir / f"cycle-{cycle}{'.jsonl' if fmt == 'jsonl' else '.json'}"
            journal = workdir / f"cycle-{cycle}.patches.jsonl"
            stats = _apply_knowledge(current, stage, journal, knowledge, cfg, fmt,total_control_actions,total_control_cost)
            reg=knowledge.get("_disk_registry")
            if reg is not None:
                knowledge["disk_registry_summary"]=reg.summary(); reg.close(); knowledge["_disk_registry"]=None
            if initial_digest is None: initial_digest = stats["input_digest"]
            inv_path = workdir / f"cycle-{cycle}.inverse{'.jsonl' if fmt == 'jsonl' else '.json'}"
            inv = _inverse_one_cycle(stage, inv_path, journal, cfg, fmt)
            inverse_ok = inv["ok"] and inv["restored_digest"] == stats["input_digest"]
            if not inverse_ok: raise RuntimeError(f"stream inverse replay failed in cycle {cycle}")
            total_edits += stats["edits"]
            total_control_actions += int(stats.get("control_actions_used",0)); total_control_cost += int(stats.get("control_cost_used",0))
            stable = stable + 1 if stats["edits"] == 0 else 0
            snap={str(r["relation_id"]):(str(r.get("confidence","")),str(r.get("support",""))) for r in knowledge["relations"]}
            delta=relation_delta(previous_snapshot,snap)
            frontier_payload={"issues":stats["issue_samples"],"minimal_transfer":stats.get("minimal_transfer"),"relations":sorted(snap)}
            frontier_sig=hashlib.sha256(json.dumps(frontier_payload,sort_keys=True,ensure_ascii=False,default=str,separators=(",",":")).encode()).hexdigest()
            frontier_changed=previous_frontier is not None and frontier_sig!=previous_frontier
            oscillation=bool(stats["edits"] and stats["output_digest"] in visited_digests); any_oscillation=any_oscillation or oscillation
            visited_digests.add(stats["output_digest"])
            strong_quiet=bool(stats["edits"]==0 and delta.get("quiet") and previous_frontier is not None and not frontier_changed and not oscillation)
            strong_streak=strong_streak+1 if strong_quiet else 0
            cycles.append({"cycle": cycle, "records": stats["records"], "committed_edits": stats["edits"], "issues_observed": stats["issues_observed"],
                           "conflicts": stats["conflicts"], "input_digest": stats["input_digest"], "output_digest": stats["output_digest"],
                           "relations": len(knowledge["relations"]), "new_relations": new_relations, "bounded_state": knowledge["bounded_state"],
                           "control_actions_used":stats.get("control_actions_used",0),"control_cost_used":stats.get("control_cost_used",0),
                           "disk_registry": knowledge.get("disk_registry_summary"), "record_bridge":stats.get("record_bridge"),
                           "relation_falsification": knowledge.get("relation_falsification"),
                           "repair_controllability":stats.get("repair_controllability"),
                           "issue_samples": stats["issue_samples"], "minimal_transfer": stats.get("minimal_transfer"),
                           "inverse_replay": {"restores_cycle_input": True, "inverse_edits": inv["inverse_edits"]},
                           "stable_streak": stable,"strong_quiet":strong_quiet,"strong_fixed_point_streak":strong_streak,
                           "relation_delta":delta,"candidate_frontier_signature":frontier_sig,"frontier_changed":frontier_changed,
                           "oscillation":oscillation,"order_audit":{"order_independent":stats.get("conflicts",0)==0}})
            previous_snapshot=snap; previous_frontier=frontier_sig
            cycle_files.append(stage); journals.append(journal)
            current = stage
            if strong_streak >= required_strong: break

        if not cycle_files:
            raise RuntimeError("stream repair executed no cycles")
        # Final stable scan with the latest knowledge: zero-edit stable cycles expose remaining reportable issues.
        final_cycle = cycles[-1]; final_digest = final_cycle["output_digest"]
        remaining = final_cycle["issues_observed"] if final_cycle["committed_edits"] == 0 else 0
        strong_attained=strong_streak>=required_strong and not any_oscillation
        status = "PASS" if strong_attained and remaining == 0 else ("STABLE_WITH_REPORTED_ISSUES" if strong_attained else "OPEN_REPAIRABLE")

        # Verify the complete chain backwards, bounded-memory, one cycle at a time.
        reverse_current = cycle_files[-1]; global_inverse_ok = True
        for i in range(len(cycle_files) - 1, -1, -1):
            restored = workdir / f"global-inverse-{i}{'.jsonl' if fmt == 'jsonl' else '.json'}"
            inv = _inverse_one_cycle(reverse_current, restored, journals[i], cfg, fmt)
            expected = cycles[i]["input_digest"]
            if not inv["ok"] or inv["restored_digest"] != expected:
                global_inverse_ok = False; break
            reverse_current = restored
        if not global_inverse_ok: raise RuntimeError("global streaming inverse replay failed")

        typed_ir = compile_stream_typed_constraint_ir(knowledge, final_cycle, final_digest)
        stream_federation,stream_q=compile_stream_federation(list(knowledge.get("relations",[])),list(final_cycle.get("issue_samples",[])),cfg)
        bridge_rows=[c.get("record_bridge") or {} for c in cycles if (c.get("record_bridge") or {}).get("enabled")]
        bridge_materialization_totals=Counter(); bridge_materialization_samples=[]; bridge_authority_registries=[]; bridge_poison_findings=Counter()
        for br in bridge_rows:
            for k,v in (br.get("witness_materialization_totals") or {}).items(): bridge_materialization_totals[k]+=int(v or 0)
            for pr in br.get("witness_materialization_proof_samples") or []:
                if len(bridge_materialization_samples)<cfg.issue_sample_limit: bridge_materialization_samples.append(pr)
            for reg in br.get("authority_registry_samples") or []:
                if isinstance(reg,dict) and reg.get("registry_sha256") and all(x.get("registry_sha256")!=reg.get("registry_sha256") for x in bridge_authority_registries) and len(bridge_authority_registries)<cfg.issue_sample_limit:
                    bridge_authority_registries.append(reg)
            for k,v in (br.get("evidence_poison_findings") or {}).items(): bridge_poison_findings[str(k)]+=int(v or 0)
        bridge_execution={"contract":"json-consistency-repair.streaming-record-bridge.v1","enabled":bool(bridge_rows),
                          "cycles":len(bridge_rows),"records_evaluated":sum(int(x.get("records_evaluated",0)) for x in bridge_rows),
                          "atomic_record_transactions":sum(int(x.get("atomic_record_transactions",0)) for x in bridge_rows),
                          "inner_committed_edits":sum(int(x.get("inner_committed_edits",0)) for x in bridge_rows),
                          "final_remaining_inner_issues":int((bridge_rows[-1] if bridge_rows else {}).get("remaining_inner_issues",0)),
                          "final_lifecycle":(bridge_rows[-1] if bridge_rows else {}).get("lifecycle_totals",{}),
                          "authority_registry_samples":bridge_authority_registries,
                          "evidence_poison_findings":dict(sorted(bridge_poison_findings.items()))}

        report = {
            **report_identity(status), "mode": "streaming", "format": fmt,
            "input": str(src), "output": str(out), "records": records, "cycles": cycles, "committed_edits": total_edits,
            "remaining_issues": remaining, "input_digest": initial_digest, "output_digest": final_digest,
            "strong_stable": strong_attained,
            "strong_fixed_point": {"contract":"json-consistency-repair.strong-fixed-point.v1","attained":strong_attained,
                                   "required_quiet_cycles":required_strong,"quiet_streak":strong_streak,
                                   "oscillation_detected":any_oscillation,"promotion_gate":"COLD_REPLAY_REQUIRED"},
            "knowledge_ledger": {"relations": ledger, "count": len(ledger)},
            "typed_constraint_ir": typed_ir,
            "typed_expression_ir": expression_ir_summary(cfg),
            "repair_path_algebra":{"contract":"json-consistency-repair.repair-path-algebra-summary.v1","mode":"streaming","cycles":[],"scope":"record_bridge_inherited","record_bridge_enabled":bool(bridge_rows)},
            "symmetry_canonicality":{"contract":"json-consistency-repair.symmetry-canonicality-summary.v1","mode":"streaming","scope":"record_bridge_inherited","record_bridge_enabled":bool(bridge_rows),"rules":list(cfg.semantic_quotient_rules)},
            "repair_controllability":{"contract":"json-consistency-repair.repair-controllability-summary.v1","mode":"streaming","scope":"record_bridge_inherited",
                                      "explicitly_unconstrained":not bool(cfg.controllability_rules or cfg.require_explicit_mutation_permission or cfg.max_control_edits is not None or cfg.max_control_cost is not None),
                                      "firewall_cycles":[{"certificate":x} for x in (list((final_cycle.get("repair_controllability") or {}).get("firewall_samples",[]))+list((final_cycle.get("record_bridge") or {}).get("repair_controllability",{}).get("firewall_samples",[])))],
                                      "control_plan_cycles":[{"certificate":x} for x in (list((final_cycle.get("repair_controllability") or {}).get("control_plan_samples",[]))+list((final_cycle.get("record_bridge") or {}).get("repair_controllability",{}).get("control_plan_samples",[])))],
                                      "final_firewall":None,"run_budget":{"max_edits":cfg.max_control_edits,"max_cost":cfg.max_control_cost,
                                      "used_before_edits":control_budget_base_edits,"used_before_cost":control_budget_base_cost,
                                      "used_this_run_edits":total_control_actions-control_budget_base_edits,"used_this_run_cost":total_control_cost-control_budget_base_cost,
                                      "used_edits":total_control_actions,"used_cost":total_control_cost}},
            "relation_falsification":{"contract":"json-consistency-repair.relation-falsification-summary.v1","mode":"streaming","scope":"stream_knowledge_and_record_bridge",
                                        "cycles":[{"cycle":c.get("cycle"),"certificate":c.get("relation_falsification")} for c in cycles if isinstance(c.get("relation_falsification"),dict)],
                                        "final":final_cycle.get("relation_falsification"),"certificate_samples":[],
                                        "explicitly_no_testable_relations":not bool((final_cycle.get("relation_falsification") or {}).get("relation_count_examined"))},
            "terminal_registry": typed_ir["terminal_registry"], "truth_summary": typed_ir["truth_summary"],
            "identifiability_registry": typed_ir["identifiability_registry"], "identifiability_summary": typed_ir["identifiability_summary"],
            "conservation_summary": {"contract":"json-consistency-repair.conservation-summary.v1",
                                     "rule_count":len(knowledge.get("conservation_rules",[])),
                                     "relation_count":sum(1 for r in knowledge.get("relations",[]) if "conservation" in str(r.get("kind","")) or str(r.get("kind","" )).startswith("aggregate_") or str(r.get("kind","" )).endswith("_authoritative_stream")),
                                     "final_cycle_issue_samples":sum(1 for x in final_cycle.get("issue_samples",[]) if x.get("analyzer")=="stream_conservation")},
            "moment_distribution_summary":{"contract":"json-consistency-repair.moment-distribution-summary.v1",
                                           "rule_count":len(knowledge.get("moment_rules",[])),
                                           "relation_count":sum(1 for r in knowledge.get("relations",[]) if r.get("bridge_kind")=="moment_distribution"),
                                           "final_cycle_issue_samples":sum(1 for x in final_cycle.get("issue_samples",[]) if x.get("analyzer")=="stream_moments")},
            "logic_summary": {"contract":"json-consistency-repair.logic-summary.v1",
                              "rule_count":len(knowledge.get("logic_rules",[])),
                              "system_certificate":knowledge.get("logic_system_certificate"),
                              "final_cycle_logic_issue_samples":sum(1 for x in final_cycle.get("issue_samples",[]) if x.get("analyzer")=="stream_logic")},
            "causal_root_analysis":{"contract":"json-consistency-repair.causal-root-analysis.v1","double_cone":_stream_causal_summary(knowledge),
                                    "authority_firewall":(final_cycle.get("minimal_transfer") or {}).get("authority_firewall",{})},
            "federation_summary":{"contract":"json-consistency-repair.c189-federation-summary.v1","mode":"streaming","final":stream_federation,
                                  "record_bridge_postcondition_reconciled":bool(final_cycle.get("record_bridge",{}).get("enabled"))},
            "dynamic_q_descent":stream_q,
            "disk_backed_registry": knowledge.get("disk_registry_summary"),
            "record_bridge_summary": final_cycle.get("record_bridge") or {"enabled":False},
            "parallel_exact_minimum_routes": {
                "contract":"json-consistency-repair.parallel-exact-routes.v1","mode":"streaming",
                "return_proof_contract":"json-consistency-repair.return-proof.v1",
                "final":((final_cycle.get("minimal_transfer") or {}).get("parallel_exact_minimum_routes") or {})
            },
            "record_bridge_execution": bridge_execution,
            "scoped_authority":{"contract":"json-consistency-repair.scoped-authority.v1","mode":"streaming","registry_samples":bridge_authority_registries,"registry_sample_count":len(bridge_authority_registries)},
            "evidence_poisoning_firewall":{"contract":"json-consistency-repair.evidence-poisoning-firewall.v1","mode":"streaming","findings":dict(sorted(bridge_poison_findings.items()))},
            "robust_envelope":{"contract":"json-consistency-repair.robust-envelope.v1","mode":"streaming","certificate_samples":(final_cycle.get("record_bridge") or {}).get("robust_envelope",{}).get("certificate_samples",[]),"gate_reasons":(final_cycle.get("record_bridge") or {}).get("robust_envelope",{}).get("gate_reasons",{})},
            "semantic_claim_provenance":{"contract":"json-consistency-repair.semantic-claim-provenance-summary.v1","mode":"streaming",
                                           "preanalysis_gate":semantic_preanalysis,"final":semantic_preanalysis_firewall,
                                           "certificate_samples":(final_cycle.get("record_bridge") or {}).get("semantic_claim_provenance",{}).get("certificate_samples",[]),
                                           "blocked":(final_cycle.get("record_bridge") or {}).get("semantic_claim_provenance",{}).get("blocked",{})},
            "witness_materialization":{
                "contract":"json-consistency-repair.witness-materialization.v1","mode":"streaming","cycles":[],
                "final":{
                    "contract":"json-consistency-repair.witness-materialization.v1","mode":"streaming",
                    "bounded_record_materialization":True,
                    "totals":dict(sorted(bridge_materialization_totals.items())),
                    "proof_samples":bridge_materialization_samples,
                    "proof_samples_bounded":True,
                    "absence_scope":"LOADED_BOUNDED_SEARCH_CONTRACT_ONLY",
                },
                "summary":{
                    "contract":"json-consistency-repair.witness-materialization-summary.v1",
                    "totals":dict(sorted(bridge_materialization_totals.items())),
                    "proof_sample_count":len(bridge_materialization_samples),
                }
            },
            "boundary_calculus":{"contract":"json-consistency-repair.boundary-calculus.v1","mode":"streaming",
                                  "registry":compile_boundary_registry(cfg.json_schema,cfg.constraint_rules),
                                  "record_carrier_enforced":bool(cfg.json_schema is not None or cfg.constraint_rules)},
            "memory_contract": {"record_count_independent": True, "max_tracked_fields": cfg.max_tracked_fields, "peak_tracked_fields": peak_fields,
                                "max_relation_fields": cfg.max_relation_fields, "max_functional_groups_per_pair": cfg.max_functional_groups, "min_functional_groups": cfg.min_functional_groups,
                                "issue_samples_per_cycle": cfg.issue_sample_limit, "patch_journal": "disk-backed JSONL",
                                "functional_registry": "SQLite exact spill on in-memory group overflow", "record_bridge_memory_scope":"one validated record",
                                "max_record_bytes": cfg.security_limits.max_record_bytes, "max_record_nodes": cfg.security_limits.max_record_nodes},
            "security": {"limits": cfg.security_limits.to_dict(), "duplicate_keys_rejected": True, "non_finite_numbers_rejected": True,
                         "unicode_scalar_validation": True, "publication_after_full_replay": True},
            "replay": {"inverse_restores_complete_input": True},
        }
        report["open_obligations"] = compile_open_obligation_registry(report)
        report["incremental_recompute"] = compile_incremental_recompute(
            report["open_obligations"], prior_registry=cfg.prior_open_obligation_registry,
            change_tokens=cfg.incremental_change_tokens, prior_proof_graph=cfg.prior_proof_graph)
        if cfg.enable_horizon_naturality:
            report["horizon_naturality"], report["distributed_consistency"] = compile_horizon_surface(
                report, None, None, prior_snapshot=cfg.prior_horizon_snapshot,
                change_tokens=cfg.horizon_change_tokens, boundary_witnesses=cfg.horizon_boundary_witnesses,
                distribution=cfg.distribution_descriptor or {"mode":"streaming","chunk_bytes":cfg.chunk_bytes,"exact_disk_registry":bool(cfg.exact_disk_registry)},
                max_manifest_entries=max(64,int(cfg.horizon_manifest_limit)),
            )
        else:
            report["horizon_naturality"]={"contract":"json-consistency-repair.horizon-naturality.v1","disabled":True}
            report["distributed_consistency"]={"contract":"json-consistency-repair.distributed-consistency.v1","disabled":True}
        if cfg.enable_information_bounds:
            # The streaming report intentionally does not materialize the whole carrier in RAM.
            # PASS040 therefore emits a conservative non-materialized blind surface rather than
            # pretending that a bounded summary proves reconstructability of arbitrary records.
            report["residual_information"], report["blind_carrier_reconstruction"] = compile_information_surface(
                None, knowledge.get("relations",()), symmetry_surface=report.get("symmetry_canonicality"),
                namespace="stream", mode="streaming", max_trials=max(1,int(cfg.blind_carrier_max_trials)),
            )
        else:
            report["residual_information"]={"contract":"json-consistency-repair.residual-information-summary.v1","disabled":True}
            report["blind_carrier_reconstruction"]={"contract":"json-consistency-repair.blind-carrier-reconstruction.v1","scope":"summary","disabled":True}
        report["provenance_chain"]=build_provenance_chain(input_digest=initial_digest or "",output_digest=final_digest,committed=[],cycles=cycles,
                                                           code_digest=package_code_sha256(),mode="streaming")
        report["proof_graph"]=compile_proof_graph(report)
        if cfg.enable_final_certification:
            cold_out=workdir / ("cold-output.jsonl" if fmt=="jsonl" else "cold-output.json")
            cold_cfg=StreamingConfig(**{**requested_cfg.__dict__,"enable_final_certification":False,
                                          "control_budget_used_before_edits":total_control_actions,
                                          "control_budget_used_before_cost":total_control_cost})
            cold_res=repair_stream_file(cycle_files[-1],cold_out,None,cold_cfg,stream_format=fmt)
            report["cold_replay"]={"contract":"json-consistency-repair.cold-replay.v1","performed":True,"input_digest":final_digest,
                                   "output_digest":cold_res.output_digest,"would_commit_edits":cold_res.committed_edits,
                                   "strong_fixed_point_attained":bool((cold_res.report.get("strong_fixed_point") or {}).get("attained")),
                                   "remaining_issue_count":cold_res.remaining_issues,"same_output":cold_res.output_digest==final_digest}
            proof_out=workdir / ("proof-output.jsonl" if fmt=="jsonl" else "proof-output.json")
            proof_cfg=StreamingConfig(**{**requested_cfg.__dict__,"enable_final_certification":False})
            proof_res=repair_stream_file(src,proof_out,None,proof_cfg,stream_format=fmt)
            pgr=compare_proof_graphs(report["proof_graph"],proof_res.report.get("proof_graph") or {})
            pgr["same_terminal_output"]=proof_res.output_digest==final_digest
            pgr["replayed_output_digest"]=proof_res.output_digest
            pgr["ok"]=bool(pgr.get("ok") and pgr["same_terminal_output"])
            if not pgr["ok"]: pgr["status"]="PROOF_GRAPH_REPLAY_MISMATCH"
            report["proof_graph_replay"]=pgr
            report["incremental_equivalence"] = compile_incremental_equivalence(
                report["incremental_recompute"], report["proof_graph"], pgr, cfg.prior_proof_graph)
            report["rectification_packet"]=compile_rectification_packet(report)
            report["final_certification"]=__import__("json_consistency_repair.certifier", fromlist=["verify_report_evidence"]).verify_report_evidence(report)
            report["rectification_packet"]=seal_rectification_packet(report["rectification_packet"],report["final_certification"],report)
            report["certification_gate"]="PASS" if report["final_certification"].get("ok") else "FAIL"
        else:
            report["cold_replay"]={"performed":False,"reason":"FINAL_CERTIFICATION_DISABLED"}
            report["proof_graph_replay"]={"contract":"json-consistency-repair.proof-graph-replay.v1","performed":False,"ok":False,"reason":"FINAL_CERTIFICATION_DISABLED"}
            report["incremental_equivalence"] = compile_incremental_equivalence(
                report["incremental_recompute"], report["proof_graph"], report["proof_graph_replay"], cfg.prior_proof_graph)
            report["rectification_packet"]=compile_rectification_packet(report)
            report["final_certification"]={"status":"NOT_RUN","ok":False}; report["certification_gate"]="NOT_RUN"
        if cfg.enable_final_certification and not report["final_certification"].get("ok"):
            raise RuntimeError("final streaming certification failed")
        from .closure import compile_third_series_closure, compile_fourth_series_closure, compile_fifth_series_progress, compile_fifth_series_closure
        report["third_series_closure"]=compile_third_series_closure(report)
        report["fourth_series_closure"]=compile_fourth_series_closure(report)
        report["fifth_series_progress"]=compile_fifth_series_progress(report,40)
        report["fifth_series_closure"]=compile_fifth_series_closure(report)
        if cfg.open_obligation_store_path and cfg.enable_final_certification and (report.get("final_certification") or {}).get("ok"):
            save_open_obligation_registry(cfg.open_obligation_store_path, report["open_obligations"])
        tmp_publish = out.with_name(out.name + ".tmp")
        shutil.copyfile(cycle_files[-1], tmp_publish); os.replace(tmp_publish, out)
        if report_path:
            rp = Path(report_path); rp.parent.mkdir(parents=True, exist_ok=True); rp.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
        return StreamRepairResult(str(src), str(out), str(report_path) if report_path else None, status, len(cycles), total_edits, remaining, records,
                                  initial_digest or "", final_digest, peak_fields, report)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
