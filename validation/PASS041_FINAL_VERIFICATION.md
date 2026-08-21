# JSON Consistency Repair v0.41.0 — PASS041 Final General Verification

Date: 2026-08-21

## Final status

PASS041 is internally closed as the current maintenance release. The PASS033–PASS040 fifth series remains 8/8 closed; PASS041 does not reopen it. Planned substantive passes remaining: **0**.

## Source-tree verification

- Python bytecode compilation: **PASS**.
- Collected regression tests: **462**.
- Regression tests passed: **462/462**, covering every test file from the core/IO tests through `test_pass041.py`, executed in deterministic batches.
- PASS041 adversarial stress: **600/600**.
- Draft 2020-12 public schemas: **73/73 valid**.
- PASS041 stress false mutations: **0**.

## Fresh-source verification

The reproducible 0.41.0 source archive was extracted into a clean directory and tested from that extracted source:

- PASS040 + PASS041 tests: **25/25**.
- PASS041 stress: **600/600**.
- source `compileall`: **PASS**.

## Fresh-wheel verification

The reproducible 0.41.0 wheel was installed into a new isolated virtual environment:

- `pip check`: **PASS — No broken requirements found**.
- runtime version: **0.41.0**.
- full mode repaired the controlled corruption exactly: **PASS**.
- fast mode repaired the same controlled corruption exactly: **PASS**.
- fast mode reports `scan_scope = ALL_ANALYZERS`.
- fast mode reports `certification_gate = FAST_SCAN_ONLY` and therefore does not masquerade as full certification.
- bounded CLI grammar repair produced the expected strict JSON object: **PASS**.

## Release reproducibility

The release builder constructed wheel and source twice independently and compared bytes:

- wheel reproducibility: **PASS**.
- source reproducibility: **PASS**.
- wheel SHA-256: `ed8935405d89f6204f73bedda012e003ac87665fba8889de1b40c49ed1e3ddbb`.
- source SHA-256: `c4c68f32959e03d18682acbee7f713ec18ebfb6943666dfcf0c29319e79df634`.
- package-code SHA-256: `3b549b4ec0198b12b4b001e84183b8121f9329797ddd95586dbb0f96800b5932`.

Both wheel and source archives pass ZIP integrity checks.

## Fast/full architecture verification

The two-mode split is intact:

- `full`: exhaustive analysis, global correction search, replay, proof graph and independent final certification.
- `fast`: scans all analyzer families, but deepens expensive correction/falsification only on unique local actionable cones. It explicitly stops at `FAST_SCAN_ONLY` assurance.

A fresh bounded 100-row smoke run produced the same exact repaired terminal:

- fast: **0.030312 s**, one exact repair, `FAST_SCAN_ONLY`.
- full: **0.773475 s**, one exact repair, full gate `PASS`.

The recorded reproducible PASS041 speed audit remains included in this package. On the same two-error corpus against the frozen 0.40 baseline it recorded approximately **62–67×** acceleration for fast mode and **2.2–3.7×** for the optimized full mode at 100–1000 rows, while preserving the exact terminal.

## Syntax frontier

The recorded PASS041 syntax contract remains:

- **14/14 contract outcomes correct**.
- **13/13 determinable corruptions repaired**.
- **1/1 conflicting duplicate-key ambiguity refused**.

This includes trailing/missing commas, missing colon, bounded truncation, missing quote, extra brace, two bounded structural errors, single quotes, unquoted keys and comments when the bounded lexical route converges to one strict JSON terminal. Conflicting duplicate keys remain non-canonical without authority.

## Benchmark and limit artifacts

The final package contains the PASS041 speed and limit benchmarks, the independent comparative benchmark, raw results and scripts. Their outer archives passed `unzip -t`, and the principal JSON artifacts parsed successfully.

- comparative benchmark ZIP SHA-256: `9685f81c819c934dca11aa86bcf0a39e118f5ab7ac203ca48c2755361ebbb728`.
- limit benchmark ZIP SHA-256: `b241630253c0f2a14a0100abf9b8d4402e3f08601078070ffbfa8e2b0bdfae82`.

## Final semantic lock

`PASS` remains evidence/contract-relative. It means there is no unresolved violation under the currently certified relations; it is **not** a claim of inaccessible external ground truth.

The external market-wide comparator gate remains distinct from correctness: additional specialized JSON repairers can be added to future comparative campaigns when independently available. No internal PASS041 defect is left open by that gate.
