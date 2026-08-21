# Benchmarks

`PASS008_FINAL_BENCHMARK.json` is the public first-candidate closure benchmark. It is deterministic, synthetic and in-distribution; it is not an external comparative dominance claim.

Run:

```bash
python benchmarks/benchmark_final.py > benchmarks/PASS008_FINAL_BENCHMARK.json
```

It covers single JSON exact repair/abstention, cross-document bundle repair/abstention, second-pass streaming reconstruction, replay, idempotence and hostile-input refusal.

`PASS007_BENCHMARK.json` is retained as historical release-regression evidence from the previous pass.

PASS010 adds `PASS010_BENCHMARK.json`, a byte-deterministic replay of the established 600-decision multi-mode benchmark under the observability/identifiability IR v2. The dedicated identifiability stress campaign is `tests/stress_pass010.py` (600 additional classification checks) and is intentionally kept separate from the behavioral repair benchmark.

PASS012 keeps the inherited 600-decision multi-mode benchmark unchanged as a regression baseline and adds `tests/stress_pass012.py` for 600 exact-logic decisions (SAT/UNSAT, inferred multivariate implications, exact-one ambiguity, bundle scope and bounded streaming logic).

### PASS023
`benchmark_pass023.py` runs 600 deterministic multi-source decisions: defaults, equal-authority conflicts, heldout confirmation, independent counterexample refutation, dependent-replication abstention, and registry determinism. `PASS023_BENCHMARK.json` is the canonical serialized result for 0.23.0.

### PASS027
`benchmark_pass027.py` runs 600 deterministic factorization decisions: strict refinement of a legacy parent carrier, preservation of explicit coupling, unresolved-dependency guarding, dynamic split, dynamic merge, and solver recomposition. `PASS027_BENCHMARK.json` is the canonical serialized result for 0.27.0; `false_mutations` counts forbidden false structural splits that would create unjustified mutation opportunities.

`benchmark_pass028.py` runs 600 deterministic proof-graph decisions covering canonical determinism, relation/factorization/actor divergence, edge tampering and exact replay. `PASS028_BENCHMARK.json` is the canonical serialized result for 0.28.0; `false_accepts` counts divergent or corrupted graphs incorrectly accepted as equivalent.

## PASS029

`benchmark_pass029.py` executes 600 deterministic witness-materialization decisions: authoritative recovery, cross-version identity recovery, finite-domain selection, ambiguity abstention, observer firewall, and bounded-search exhaustion. The required false-mutation count is zero.


## PASS030

`benchmark_pass030.py` executes 600 deterministic scoped-authority decisions: direct path scope, out-of-scope abstention, delegated authority, revocation, schema-version gating, and authority-proof tamper rejection. The required false-mutation count is zero.
