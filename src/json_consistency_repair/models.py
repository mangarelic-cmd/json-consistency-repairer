from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Any
import hashlib, json


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def pointer(parts: list[str | int]) -> str:
    if not parts:
        return ""
    out=[]
    for p in parts:
        s=str(p).replace("~", "~0").replace("/", "~1")
        out.append(s)
    return "/" + "/".join(out)

@dataclass(frozen=True)
class Issue:
    analyzer: str
    code: str
    path: str
    message: str
    severity: str = "warning"
    repairable: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)
    def signature(self):
        return (self.analyzer, self.code, self.path, json.dumps(self.metadata, sort_keys=True, default=str))
    def to_dict(self): return asdict(self)

@dataclass(frozen=True)
class Candidate:
    candidate_id: str
    analyzer: str
    operation: str
    path: str
    old_value: Any
    new_value: Any
    reason: str
    confidence: float = 1.0
    cost: int = 1
    evidence: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)
    def conflict_key(self): return self.path
    def to_dict(self): return asdict(self)

@dataclass
class AnalysisResult:
    issues: list[Issue] = field(default_factory=list)
    candidates: list[Candidate] = field(default_factory=list)
    relations: list[dict[str, Any]] = field(default_factory=list)
