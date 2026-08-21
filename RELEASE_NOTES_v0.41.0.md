# JSON Consistency Repair v0.41.0 — PASS041

Version 0.41.0 is the current verified release of `json-consistency-repair`, a conservative JSON rectification engine that combines bounded syntax recovery with exact consistency analysis, reversible minimal edits, provenance/authority controls, replay verification, cross-document repair, streaming, and explicit abstention when a unique repair is not justified.

## Main release features

- Strict JSON parsing with bounded deterministic grammar/lexical recovery.
- Conflicting duplicate keys are refused rather than silently resolved.
- Exact `Decimal` arithmetic and exact rational constraint handling.
- Functional, arithmetic, temporal, sequential, schema, enum, identity, reference, graph/state, aggregate and conservation constraints.
- JSON Pointer identity for issues and edits.
- Reversible minimal patches, inverse replay and strong fixed-point closure.
- Authority/provenance firewalls and explicit conflict handling.
- Symmetry-aware abstention and controllability/attainability checks.
- Active falsification of discovered relations before they can authorize repair.
- Persistent OPEN obligations with targeted incremental wake-up and full-recompute parity checks.
- Horizon and distributed-coherence checks.
- Residual-information bounds and blind-reconstruction verification.
- Bundle, JSONL/NDJSON and bounded-memory top-level-array streaming modes.
- Two execution profiles:
  - `full`: exhaustive analysis, global correction search, replay, proof graph and independent final certification.
  - `fast`: scans all analyzer families, but deepens expensive correction/falsification only on unique local actionable cones; it reports `FAST_SCAN_ONLY` and never claims full certification.

## Final verification

The frozen PASS041 verification records:

- 462/462 collected regression tests passed.
- PASS041 adversarial stress: 600/600.
- Draft 2020-12 public schemas: 73/73 valid.
- False mutations in PASS041 stress: 0.
- Fresh-source PASS040+PASS041 tests: 25/25.
- Fresh-source PASS041 stress: 600/600.
- Fresh-wheel `pip check`: PASS.
- Wheel and source builds: reproducible byte-for-byte.
- Syntax contract: 14/14 outcomes correct — 13/13 determinable corruptions repaired and 1/1 conflicting duplicate-key ambiguity refused.

Reproducible artifact hashes:

- Wheel SHA-256: `ed8935405d89f6204f73bedda012e003ac87665fba8889de1b40c49ed1e3ddbb`
- Source SHA-256: `c4c68f32959e03d18682acbee7f713ec18ebfb6943666dfcf0c29319e79df634`
- Package-code SHA-256: `3b549b4ec0198b12b4b001e84183b8121f9329797ddd95586dbb0f96800b5932`

## Recorded speed result

On the frozen PASS041 two-error benchmark against the 0.40 baseline, fast mode recorded approximately 62–67× acceleration at 100–1000 rows while preserving the same exact repaired terminal. The optimized full mode recorded approximately 2.2–3.7× acceleration on the same benchmark. These figures are benchmark-specific and are not presented as universal throughput claims.

## Scope

`PASS` is evidence/contract-relative: it means that no unresolved violation remains under the currently certified relations. It is not a claim of inaccessible external ground truth.

The comparative market-wide gate against additional independently available specialized JSON repairers remains separate from internal correctness and can be extended without reopening this release.

## License

MIT License.
