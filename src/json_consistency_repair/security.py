from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any


class SecurityLimitError(ValueError):
    """Input is valid-ish JSON but exceeds the configured safety contract."""

    def __init__(self, code: str, message: str, *, observed: int | None = None, limit: int | None = None, path: str | None = None):
        super().__init__(message)
        self.code = code
        self.observed = observed
        self.limit = limit
        self.path = path

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "message": str(self), "observed": self.observed, "limit": self.limit, "path": self.path}


@dataclass(frozen=True)
class SecurityLimits:
    # Parsed-object limits. Conservative defaults: high enough for normal data, bounded enough for hostile structure.
    max_depth: int = 96
    max_nodes: int = 1_000_000
    max_string_bytes: int = 8 * 1024 * 1024
    max_key_bytes: int = 16 * 1024
    max_number_chars: int = 4096
    max_object_keys: int = 100_000
    max_array_items: int = 1_000_000
    # File/container limits for non-streaming operations.
    max_document_bytes: int = 64 * 1024 * 1024
    max_bundle_documents: int = 2048
    max_bundle_bytes: int = 512 * 1024 * 1024
    # Streaming keeps total corpus unbounded by this contract, but each independently parsed record is bounded.
    max_record_bytes: int = 8 * 1024 * 1024
    max_record_nodes: int = 250_000

    def to_dict(self) -> dict[str, int]:
        return asdict(self)


def _utf8_size(text: str, *, code: str, limit: int, path: str) -> int:
    try:
        n = len(text.encode("utf-8"))
    except UnicodeEncodeError as e:
        raise SecurityLimitError("invalid_unicode_scalar", f"unpaired Unicode surrogate at {path}", path=path) from e
    if n > limit:
        raise SecurityLimitError(code, f"{code} limit exceeded at {path}: {n} > {limit}", observed=n, limit=limit, path=path)
    return n


def validate_json_value(value: Any, limits: SecurityLimits, *, node_limit: int | None = None) -> dict[str, int]:
    """Iterative structural validation so the safety check cannot itself recurse on hostile JSON."""
    max_nodes = limits.max_nodes if node_limit is None else min(limits.max_nodes, node_limit)
    stack: list[tuple[Any, int, str]] = [(value, 0, "")]
    nodes = 0
    peak_depth = 0
    peak_string_bytes = 0
    while stack:
        current, depth, path = stack.pop()
        nodes += 1
        if nodes > max_nodes:
            raise SecurityLimitError("max_nodes", f"node limit exceeded: {nodes} > {max_nodes}", observed=nodes, limit=max_nodes, path=path)
        if depth > limits.max_depth:
            raise SecurityLimitError("max_depth", f"depth limit exceeded at {path or '/'}: {depth} > {limits.max_depth}", observed=depth, limit=limits.max_depth, path=path)
        peak_depth = max(peak_depth, depth)

        if isinstance(current, dict):
            if len(current) > limits.max_object_keys:
                raise SecurityLimitError("max_object_keys", f"object key limit exceeded at {path or '/'}: {len(current)} > {limits.max_object_keys}", observed=len(current), limit=limits.max_object_keys, path=path)
            for key, child in current.items():
                if not isinstance(key, str):
                    raise SecurityLimitError("non_string_key", f"non-string object key at {path or '/'}", path=path)
                kb = _utf8_size(key, code="max_key_bytes", limit=limits.max_key_bytes, path=(path or "") + "/<key>")
                peak_string_bytes = max(peak_string_bytes, kb)
                token = key.replace("~", "~0").replace("/", "~1")
                stack.append((child, depth + 1, (path + "/" + token) if path else "/" + token))
        elif isinstance(current, list):
            if len(current) > limits.max_array_items:
                raise SecurityLimitError("max_array_items", f"array item limit exceeded at {path or '/'}: {len(current)} > {limits.max_array_items}", observed=len(current), limit=limits.max_array_items, path=path)
            for idx in range(len(current) - 1, -1, -1):
                stack.append((current[idx], depth + 1, f"{path}/{idx}" if path else f"/{idx}"))
        elif isinstance(current, str):
            sb = _utf8_size(current, code="max_string_bytes", limit=limits.max_string_bytes, path=path or "/")
            peak_string_bytes = max(peak_string_bytes, sb)
        elif current is None or isinstance(current, (bool, int, float)):
            # Non-finite numbers are rejected by the parser before this point.
            pass
        else:
            raise SecurityLimitError("unsupported_json_type", f"unsupported JSON value type {type(current).__name__} at {path or '/'}", path=path)
    return {"nodes": nodes, "peak_depth": peak_depth, "peak_string_bytes": peak_string_bytes}


def enforce_file_size(path: str | Path, limit: int, *, code: str = "max_document_bytes") -> int:
    p = Path(path)
    size = p.stat().st_size
    if size > limit:
        raise SecurityLimitError(code, f"file size limit exceeded for {p.name}: {size} > {limit}", observed=size, limit=limit, path=str(p))
    return size


def preflight_json_text(text: str, limits: SecurityLimits, *, byte_limit: int | None = None, path: str = "") -> dict[str, int]:
    """Cheap lexical depth/Unicode preflight before CPython's recursive JSON decoder is entered."""
    if byte_limit is not None:
        try: nbytes=len(text.encode("utf-8"))
        except UnicodeEncodeError as e: raise SecurityLimitError("invalid_unicode_scalar", f"unpaired Unicode surrogate at {path or '/'}", path=path) from e
        if nbytes > byte_limit:
            raise SecurityLimitError("max_record_bytes", f"JSON text exceeds byte limit: {nbytes} > {byte_limit}", observed=nbytes, limit=byte_limit, path=path)
    depth=0; peak=0; in_string=False; escaped=False
    for ch in text:
        if in_string:
            if escaped: escaped=False
            elif ch == "\\": escaped=True
            elif ch == '"': in_string=False
            continue
        if ch == '"':
            in_string=True
        elif ch in "[{":
            depth += 1; peak=max(peak,depth)
            if depth > limits.max_depth:
                raise SecurityLimitError("max_depth", f"lexical depth limit exceeded at {path or '/'}: {depth} > {limits.max_depth}", observed=depth, limit=limits.max_depth, path=path)
        elif ch in "]}":
            depth=max(0,depth-1)
    return {"peak_lexical_depth": peak}
