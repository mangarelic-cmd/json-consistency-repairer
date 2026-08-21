from __future__ import annotations
from pathlib import Path
from typing import Any
import json, re, os, tempfile

from .security import SecurityLimits, SecurityLimitError, enforce_file_size, validate_json_value, preflight_json_text


class DuplicateKeyError(ValueError):
    pass


def _pairs_no_dupes(pairs):
    out={}
    for k,v in pairs:
        if k in out: raise DuplicateKeyError(f"duplicate object key: {k!r}")
        out[k]=v
    return out


def _reject_constant(s: str):
    raise ValueError(f"non-finite numeric constant: {s}")


def _bounded_int_factory(limits: SecurityLimits):
    def parse_int(s: str):
        if len(s.lstrip('-')) > limits.max_number_chars:
            raise SecurityLimitError("max_number_chars", f"integer token exceeds {limits.max_number_chars} characters", observed=len(s.lstrip('-')), limit=limits.max_number_chars)
        return int(s)
    return parse_int


def _bounded_float_factory(limits: SecurityLimits):
    def parse_float(s: str):
        if len(s) > limits.max_number_chars:
            raise SecurityLimitError("max_number_chars", f"number token exceeds {limits.max_number_chars} characters", observed=len(s), limit=limits.max_number_chars)
        v=float(s)
        if v == float('inf') or v == float('-inf') or v != v:
            raise ValueError(f"non-finite numeric value: {s}")
        return v
    return parse_float


def strict_decoder(limits: SecurityLimits | None = None) -> json.JSONDecoder:
    lim=limits or SecurityLimits()
    return json.JSONDecoder(object_pairs_hook=_pairs_no_dupes, parse_constant=_reject_constant,
                            parse_int=_bounded_int_factory(lim), parse_float=_bounded_float_factory(lim))


def loads_strict(text: str, limits: SecurityLimits | None = None, *, node_limit: int | None = None) -> Any:
    lim=limits or SecurityLimits()
    # Character count is a cheap pre-parse bound. File-based callers also enforce exact byte size before reading.
    if len(text) > lim.max_document_bytes:
        raise SecurityLimitError("max_document_bytes", f"JSON text exceeds character safety bound: {len(text)} > {lim.max_document_bytes}", observed=len(text), limit=lim.max_document_bytes)
    preflight_json_text(text, lim)
    try:
        value=strict_decoder(lim).decode(text)
    except RecursionError as e:
        raise SecurityLimitError("decoder_recursion", "JSON decoder recursion guard triggered") from e
    validate_json_value(value, lim, node_limit=node_limit)
    return value


def load_file(path: str|Path, limits: SecurityLimits | None = None) -> Any:
    lim=limits or SecurityLimits(); enforce_file_size(path, lim.max_document_bytes)
    return loads_strict(Path(path).read_text(encoding="utf-8-sig"), lim)


def dump_file(value: Any, path: str|Path) -> None:
    target=Path(path); target.parent.mkdir(parents=True, exist_ok=True)
    payload=json.dumps(value, ensure_ascii=False, indent=2, sort_keys=False, allow_nan=False)+"\n"
    fd,tmp=tempfile.mkstemp(prefix=f".{target.name}.tmp-", dir=str(target.parent))
    try:
        with os.fdopen(fd,"w",encoding="utf-8",newline="\n") as f:
            f.write(payload); f.flush(); os.fsync(f.fileno())
        os.replace(tmp,target)
    except Exception:
        try: os.unlink(tmp)
        except OSError: pass
        raise


def conservative_syntax_repair(text: str, limits: SecurityLimits | None = None) -> tuple[Any|None, list[dict]]:
    """Try a tiny set of uniquely validated lexical repairs. Never guess structure."""
    lim=limits or SecurityLimits()
    attempts=[]
    # trailing commas before ] or }
    t1=re.sub(r',\s*([}\]])', r'\1', text)
    if t1 != text: attempts.append(("remove_trailing_commas", t1))
    # UTF-8 BOM is safe to strip
    if text.startswith('\ufeff'): attempts.append(("strip_bom", text.lstrip('\ufeff')))
    valid=[]
    for name,candidate in attempts:
        try: valid.append((name, loads_strict(candidate, lim), candidate))
        except Exception: pass
    # unique canonical object only
    canonical={json.dumps(v, sort_keys=True, separators=(",",":"), ensure_ascii=False, allow_nan=False): (n,v,c) for n,v,c in valid}
    if len(canonical)==1:
        n,v,_=next(iter(canonical.values()))
        return v,[{"operation":n,"confidence":1.0,"reversible":True,"grammar_frontier":"lexical-safe"}]
    # PASS017: bounded grammar frontier. Import lazily to avoid circular initialization.
    from .grammar_repair import minimal_grammar_repair
    v,repairs=minimal_grammar_repair(text,lim,max_edit_distance=2,max_candidates=128)
    if v is not None:
        return v,[{**x,"confidence":1.0,"reversible":True,"grammar_frontier":"bounded-minimal"} for x in repairs]
    return None,[]
