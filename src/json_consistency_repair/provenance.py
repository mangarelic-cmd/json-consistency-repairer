from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ._version import __version__

PACKAGE_NAME = "json-consistency-repair"
REPORT_CONTRACT = "json-consistency-repair.report.v1"
MACHINE_CONTRACT = "json-consistency-repair.machine.v1"
REPORT_SCHEMA_VERSION = "1.0"

EXIT_CODES = {
    "PASS": 0,
    "STABLE_WITH_REPORTED_ISSUES": 10,
    "OPEN_REPAIRABLE": 11,
    "INPUT_ERROR": 20,
    "SECURITY_REFUSAL": 21,
    "IO_ERROR": 30,
    "INTERNAL_ERROR": 70,
}


def package_code_sha256() -> str:
    """Stable digest of shipped Python source files; equal for source tree and wheel when code is equal."""
    base = Path(__file__).resolve().parent
    h = hashlib.sha256()
    for path in sorted(base.glob("*.py"), key=lambda p: p.name):
        data = path.read_bytes()
        h.update(path.name.encode("utf-8"))
        h.update(b"\0")
        h.update(str(len(data)).encode("ascii"))
        h.update(b"\0")
        h.update(data)
        h.update(b"\0")
    return h.hexdigest()


def runtime_provenance() -> dict[str, Any]:
    return {
        "package": PACKAGE_NAME,
        "version": __version__,
        "package_code_sha256": package_code_sha256(),
        # Release-level bindings are intentionally external: a wheel cannot contain its own hash.
        "git_commit": None,
        "zenodo_doi": None,
        "artifact_binding": "see RELEASE_PROVENANCE.json distributed with a tagged release",
    }


def report_identity(status: str) -> dict[str, Any]:
    return {
        "engine": PACKAGE_NAME,
        "version": __version__,
        "report_contract": {
            "name": REPORT_CONTRACT,
            "schema_version": REPORT_SCHEMA_VERSION,
            "status": status,
            "status_exit_code": EXIT_CODES.get(status),
            "truth_scope": "EVIDENCE_AND_DECLARED_CONTRACT_RELATIVE",
            "pass_semantics": "NO_UNRESOLVED_VIOLATION_UNDER_CURRENT_CERTIFIED_RELATIONS; NOT_EXTERNAL_GROUND_TRUTH_PROOF",
        },
        "provenance": runtime_provenance(),
    }


def machine_envelope(*, status: str, mode: str | None, result: dict[str, Any] | None = None,
                     error: dict[str, Any] | None = None) -> dict[str, Any]:
    code = EXIT_CODES[status]
    return {
        "contract": MACHINE_CONTRACT,
        "schema_version": REPORT_SCHEMA_VERSION,
        "ok": code == 0,
        "status": status,
        "exit_code": code,
        "engine": {"name": PACKAGE_NAME, "version": __version__, "package_code_sha256": package_code_sha256()},
        "mode": mode,
        "result": result,
        "error": error,
    }


def canonical_machine_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
