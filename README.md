# json-consistency-repair

Experimental SC-derived JSON rectification engine. It discovers stable constraints, proposes minimal reversible edits, re-analyzes the **physically updated data after every repair cycle**, preserves newly exposed relations in a cumulative knowledge ledger, and requires repeated stable cycles before closure.

## Install

```bash
pip install json-consistency-repair
```

No third-party runtime dependencies are required.

## Quick use

```bash
json-consistency-repair input.json -o repaired.json --report repair.json
```

For bots/agents:

```bash
json-consistency-repair --machine input.json -o repaired.json --report repair.json
```

See `GUIDE_LLM.md` and `MACHINE_CONTRACT.md` for the stable machine protocol and exit codes.

## v0.41.0 final verified release

Version 0.41.0 / PASS041 is the current verified release of the cumulative engine. It preserves the original public-candidate contract and extends it with the later authority, proof, distributed-coherence, information-bound and fast/full execution layers:

- strict JSON parsing, duplicate-key rejection and conservative syntax repair;
- exact `Decimal` arithmetic over `+`, `-`, `*`, `/` without an external CAS;
- functional, scoped, temporal, sequential, schema, enum, identity and reference constraints;
- JSON Pointer identity for issues and edits;
- cumulative knowledge across corrected states;
- global multifile identity registries and cross-document repair;
- semantic all-or-none bundle patches and inverse replay;
- JSONL/NDJSON and top-level-array bounded-memory streaming;
- second-cycle reconstruction from the physically corrected stream;
- explicit memory/resource/security bounds with refusal instead of truncated evidence;
- atomic publication and deterministic semantic SHA-256 digests;
- stable bot/machine contract and exit-code taxonomy;
- deterministic release builder and code/artifact provenance;
- human and LLM guides, JSON schemas, CI/release workflows and citation metadata;
- final multi-mode closure benchmark;
- dry-run simulation that reports proposed edits separately from committed edits and never publishes output;
- source/authority provenance firewalls, symmetry-aware abstention and controllability/attainability checks;
- active relation falsification, persistent OPEN obligations and targeted incremental wake-up with full-recompute parity checks;
- horizon/distributed-coherence checks, residual-information bounds and blind reconstruction tests;
- dual execution profiles: `full` for exhaustive replay/certification and `fast` for all-analyzer scanning with deep search restricted to unique local actionable cones.

## Convergence

```text
analyze state N
  -> certify admissible minimal edits
  -> create state N+1 in the working transaction
  -> re-discover constraints on state N+1
  -> preserve new certified knowledge
  -> continue until two zero-edit cycles
  -> PASS or explicit unresolved/abstention state
```

A correction can therefore expose a relation that did not have enough evidence before the correction; later cycles may use that newly certified relation.

## Dry run

```bash
json-consistency-repair --machine --dry-run input.json -o would-be-output.json --report dry-run.json
```

No output artifact is published. The report distinguishes `committed_edits: []` from `proposed_edits` / `would_commit_edits`, while still running the complete simulated convergence and inverse replay.

## Bundle

```bash
json-consistency-repair --bundle ./bundle -o ./bundle.repaired --report bundle-report.json
```

## Streaming

```bash
json-consistency-repair data.jsonl -o data.repaired.jsonl --report stream-report.json
json-consistency-repair --stream --stream-format array large-array.json -o repaired.json --report stream-report.json
```

## Security rule

An input that exceeds a configured safety boundary is not partially analyzed, truncated into evidence or partially published. It is refused. Security limits are part of the evidence boundary, not a repair heuristic.

## Scientific/release positioning

The software is usable without reading the underlying research. Scientific context, release provenance and Zenodo DOI bindings remain explicit external metadata rather than hidden assumptions in the repair logic. See `RELEASE.md`.

PASS008 is cumulative. PASS007 through PASS001 remain retained in `history/` in the cumulative archive.


## PASS009 typed constraint IR

Every completed analysis now exposes `typed_constraint_ir`. It separates a certified/observed constraint from the current object's satisfaction of that constraint and from the ability to reconstruct a missing/corrupt value. The three truth states are `TRUE`, `FALSE`, and `UNKNOWN`. A certain defect may therefore be `satisfaction_truth=FALSE` while `reconstruction_truth=UNKNOWN`; callers must never treat UNKNOWN as false, zero, absent, or permission to invent a value.

Single JSON materializes the full JSON node/constraint/terminal IR. Bundles preserve document-qualified local terminals plus cross-document constraints. Streaming uses `materialization_scope=BOUNDED_STREAM`: sampled terminals are materialized, while unsampled observed terminals remain explicitly counted rather than silently dropped.

## PASS010 observability and identifiability

PASS010 turns unresolved terminals into an explicit finite decision surface. For each defective JSON path, the report now separates:

- `observability`: `OBSERVED_VALUE`, `OBSERVED_NULL`, `UNOBSERVED`, or `BOUNDED_UNMATERIALIZED`;
- `identifiability`: `UNIQUE`, `MULTIPLE`, `NONE`, or `INSUFFICIENT`;
- the finite certified domains used to decide the class;
- the number/digests of admissible solutions when the solution set is finite;
- the smallest missing witness class that can resolve a non-unique terminal.

The four identifiability outcomes are intentionally different:

- `UNIQUE`: the currently certified finite constraints have exactly one admissible reconstruction;
- `MULTIPLE`: more than one admissible reconstruction remains and one independent selector is required;
- `NONE`: certified finite constraints have empty intersection and at least one governing source/constraint must be revised;
- `INSUFFICIENT`: current material does not define a finite reconstruction domain, or the value is visible but mutation direction is not independently anchored.

PASS010 provides the identifiability surface. PASS011 now consumes that surface with an exact bounded minimal-transfer solver: coupled patch sets are reanalyzed on the sovereign JSON, equal exact minima cause abstention, and oversized exact frontiers are reported rather than silently approximated.


## PASS011 global minimal transfer

PASS011 replaces the inherited single-edit ranking inside the in-memory engine with `json-consistency-repair.minimal-transfer.v1`. The objective is lexicographic: first minimize hard errors, severity score, repairable terminals and surviving pre-existing terminals; only among equally closed states minimize the exact structural displacement `(cost, changed paths, canonical new-value bytes, path depth)`. Costs are represented as exact rational numbers.

Candidate sets that affect the same JSON carrier are enumerated together up to the configured finite frontier. Independent carriers are solved separately and their union is revalidated on the complete object before commit. A true equal minimum returns `AMBIGUOUS_EXACT_MINIMUM`; a frontier larger than the declared exact bound returns `FRONTIER_TOO_LARGE`. Neither condition is silently broken by heuristic tie-breaking. Bundle cross-document repairs use the same policy. Streaming uses a bounded per-record pathwise variant because the complete corpus is intentionally not resident in memory.

## PASS012 exact logical constraints

PASS012 adds finite exact logic to the same minimal-transfer frontier. Inferred high-support rules and explicit authoritative rules remain separate. Supported rule families are `implies`, `xor`, `exactly_one`, `one_of`, `any_of`, and `not_both`. Authoritative rule systems are compiled to finite CNF; a SAT witness means only that the rule system is internally consistent, while an UNSAT certificate blocks data mutation until the governing rules are revised.

```bash
json-consistency-repair input.json --logic-rules logic-rules.json -o repaired.json --report report.json
```

## PASS013 conservation and local↔aggregate bridges

PASS013 adds exact conservation objects. Automatic discovery can certify and repair direct local→aggregate bridges such as:

```text
sum(lines[*].amount) = total
len(lines) = line_count
```

It also discovers symmetric four-field balances and key/quantity multiset conservation. Symmetric laws diagnose a nonzero residue but do **not** invent which side is wrong. A declared authoritative conservation rule can provide the missing orientation:

```json
{
  "rules": [
    {
      "kind": "balance",
      "array_path": "/rows",
      "terms": [
        {"field": "opening", "coefficient": 1},
        {"field": "received", "coefficient": 1},
        {"field": "sold", "coefficient": -1},
        {"field": "closing", "coefficient": -1}
      ],
      "target": "closing"
    }
  ]
}
```

```bash
json-consistency-repair input.json --conservation-rules conservation-rules.json -o repaired.json --report report.json
```

For multisets, a rule declares `left_field`, `right_field`, `key_field`, `quantity_field`, and optionally the authoritative `target_side`. Without a target side, an inferred multiset mismatch remains an exact residue/abstention rather than a guessed patch. Streaming supports bounded-memory aggregate discovery plus authoritative record-level conservation rules.


## PASS014 modal regimes, recursive morphology and schema evolution

PASS014 inserts a modal firewall before repair decisions. Repeated object populations may be partitioned by a materially supported discriminator such as `type`, `kind`, `mode` or `schema_version`; shape, type, enum, functional, arithmetic and temporal laws are then rediscovered inside each regime. A global law that only exists because distinct legitimate regimes were mixed is not allowed to authorize a mutation. `status` is deliberately not treated as a regime merely because it is low-cardinality: it must explain an independent structural/type difference, preventing rare enum variants from disappearing behind a fake regime. Schema-version changes are emitted as `schema_evolution`, and recursive morphology may diagnose a recurrent missing structural key without inventing its value.

## PASS015 strong fixed point and law lifecycle

A zero-edit cycle is no longer sufficient for closure. `json-consistency-repair.strong-fixed-point.v1` requires repeated quiet cycles with no accepted patch, no relation creation/retirement/strength change, no candidate-frontier change, no detected oscillation and no selected patch set whose result depends on application order. Relation lifecycle states are `DISCOVERED`, `REINFORCED`, `WEAKENED`, `UPDATED`, `STABLE` and `RETIRED`. Even `STABLE` relations retain the promotion gate `COLD_REPLAY_REQUIRED`.

## PASS016 cold replay and independent final certification

The public default performs a cold replay after the strong fixed point. The repaired output is passed to a fresh repair run with final certification disabled; closure requires zero proposed edits, the same semantic output and a new strong fixed point. A deterministic SHA-256 provenance chain binds the input digest, installed code digest, every committed patch, cycle evidence and final digest.

The final verifier lives in `json_consistency_repair.certifier` and intentionally does not import the engine, analyzers, modal detector, fixed-point logic or minimal-transfer solver. It verifies serialized digests, forward/inverse patch replay, the provenance hash chain, strong-fixed-point evidence and cold replay. This separation prevents the component that proposed a repair from certifying its own reasoning.

```bash
python -m json_consistency_repair.certifier --report report.json --input input.json --output repaired.json
```

A valid hash proves integrity of the serialized evidence, not truth of the underlying data. Tampering with a patch, cycle, digest or chain link invalidates certification.


## PASS017 structural JSON patch algebra and bounded grammar repair

PASS017 opens the third expansion series without changing the PASS016 closure baseline. The repair engine now has an exact structural transformation primitive for `add`, `remove`, `replace`, `move`, `copy`, and `test`. Every accepted structural transformation produces an exact inverse; move/copy destinations must be unoccupied and a move may not target its own descendant.

Automatic structural migration remains conservative. A repeated-object record is moved/renamed only when one consensus-required key is missing, exactly one rare extra key is available, stable type evidence matches, and the key names provide a direct identity/alias witness. Multiple possible destinations cause abstention.

Malformed JSON receives a bounded grammar search after the older lexical-safe repairs. The engine enumerates a small frontier around the parser failure, keeps only minimum-edit valid parses, and repairs only when every minimum route converges to one canonical JSON value. Ambiguous minimum parses remain input errors rather than guessed data.


## PASS018 general constraint DSL, schema bridges and exact multivariable solving

PASS018 adds optional authoritative inputs without changing the default zero-configuration workflow. A compact DSL compiles `require`, `type`, `enum`, `const`, and exact affine `linear` rules into the same Typed Constraint IR as discovered relations. Rational coefficients are represented with `fractions.Fraction`; a corrupted observed field is repaired only when exactly one one-field change closes the entire authoritative system. Rank-deficient, inconsistent, or direction-ambiguous systems abstain. Multiple missing variables can be reconstructed together when the linear system has a unique exact solution.

```bash
json-consistency-repair input.json --constraints rules.dsl -o repaired.json --report report.json
json-consistency-repair input.json --json-schema schema.json -o repaired.json
json-consistency-repair input.json --openapi openapi.json --openapi-schema Invoice -o repaired.json
```

PASS018 introduced the first JSON Schema/OpenAPI bridge (`type`, `required`, `default`, `const`, `enum`, `properties`, `items`, and conservative `additionalProperties:false`). PASS025 expands this into the boundary/assertion algebra documented below while preserving bounded local `$ref` handling and non-destructive abstention. Constraint/schema bridges are exposed in single, bundle, and streaming execution. In streaming mode, record-local obligations are materialized against one validated record at a time; cross-record functional registries spill exactly to SQLite when the in-memory group bound is exceeded. The engine does not claim an unmaterialized whole-corpus schema solve.

## PASS019 causal root analysis and authority firewall

PASS019 distinguishes causes from downstream symptoms before minimal-transfer selection. Each cycle builds a forward dependency cone from certified relations and a backward cone from active terminals. A candidate may dominate another only when it closes a strict superset of the same pre-existing terminals without introducing a new hard error. Independent repairs are never discarded merely because another patch closes more unrelated issues. Explicit authorities (`constraint DSL`, JSON Schema/OpenAPI, authoritative logic/conservation rules) outrank inferred evidence; incompatible authoritative values produce `AUTHORITY_CONFLICT` and zero mutation.

## PASS020 graph/state systems and ordered migration planning

PASS020 treats graph topology, workflows and migrations as native JSON repair objects. Obvious `{nodes, edges}` carriers are detected automatically for conservative topology diagnostics. Optional authoritative system rules add DAG, reachability, reciprocal-edge, topological-order and state-machine contracts.

```bash
json-consistency-repair input.json --system-rules system-rules.json -o repaired.json --report report.json
```

A stored topological order is changed only when the DAG has one unique legal order. Dangling graph references are diagnosed without inventing node identities. State-machine history is changed only when the previous and next states identify exactly one legal interior state. `state_reachability` can expose the shortest legal path to a requested target without falsifying historical snapshots.

Ordered migrations compile several exact JSON Patch operations into one atomic `plan`. The dependency graph must be acyclic; two unordered steps must commute or the migration is rejected as `migration_order_underspecified`. A plan carries exact source/target digests, step preconditions and inverse steps. Partial application is rolled back, and the PASS016 independent certifier replays the complete plan forward and backward. Appends using JSON Pointer `/-` now serialize the concrete inverse array index rather than an invalid inverse `/-` removal.

PASS020 system-rule execution is exposed in single-document, bundle, and PASS024 streaming mode. Streaming graph/state/migration rules are evaluated against a complete validated record; a multi-step migration is journaled as one whole-record atomic transaction with exact inverse replay rather than being fragmented into unrelated path edits.

## PASS021 — weighted aggregates, moments, distributions, units

PASS021 adds exact rational local-to-aggregate bridges for weighted means/sums, variance, covariance, probability totals, uncertainty-variance sidecars and authoritative unit normalization. Use `--moment-rules rules.json` for explicit authority. Weighted mean and population variance may also be discovered conservatively from repeated object arrays when the aggregate target name provides an independent direction witness. Non-terminating rational results are reported exactly and never rounded into a JSON mutation. Probability members outside `[0,1]` block aggregate normalization rather than being hidden by a repaired total.

## PASS022 — C189 analyzer federation and dynamic Q descent

PASS022 federates the existing analyzers without exposing a new user-facing workflow. MODE I freezes one sovereign JSON snapshot and preserves one independent packet per analyzer. MODE II then broadcasts active pairwise objects, materializes only on-demand consensus/conflict/terminal-contact hyperobjects, and composes certified directed relations across analyzer boundaries to a bounded fixed point. Composite relation identity is semantic (`scope + inputs + output`), while derivation provenance remains metadata, preventing endless re-derivation clones.

Reports expose `federation_summary` and `dynamic_q_descent`. Q is separated into answer debt, boundary/conflict debt, and exact-return debt. An accepted local repair receives sovereign Q credit only after full rebuild and strict lexicographic descent. Bundle reports retain per-document federation; streaming exposes a bounded relation-only federation view and never treats unmaterialized terminals as absent.

## PASS023 — multi-source assimilation without source confusion

`json-consistency-repair` can now consume an optional `--sources-manifest` beside one primary JSON document. Every context file is frozen with a role, digest, support, independence group, and optional schema version before it can influence a repair. `previous` is observer-only by default; `defaults` fills missing values only; authoritative values require explicit manifest paths; event logs require an explicit projection rule.

Development relations are not promoted merely because they fit training data. PASS023 tests them on independent heldout sources. A relation may progress from `DISCOVERED` to `HELDOUT_CONFIRMED` and `PORTABLE`, while any independent counterexample forces `GLOBAL_REFUTED`. A heldout source from the same independence group does not count. Field-identity bridges allow the same logical field to be compared across schema versions without rewriting context files.

```bash
json-consistency-repair current.json --sources-manifest sources.json -o repaired.json --report report.json
```

The default CLI remains the same when no source manifest is supplied.


## PASS024 — exact streaming closure

PASS024 closes the planned third expansion series. Public CLI streaming and the default `repair_stream_file` path use an exact disk-backed functional registry: when a determinant→target table exceeds the in-memory group cap, observations spill to an ephemeral SQLite registry instead of causing the relation to be discarded. The registry retains exact counts, deterministic relation lookup, a semantic digest, and an explicit recovered-pair count.

Record-local authoritative bridges now materialize in streaming mode for DSL/JSON Schema/OpenAPI, ordered system plans, moment/unit plans, defaults/authority sources, and development/heldout lifecycle evidence. Structural or multi-path changes are published as one whole-record transaction in the disk journal, so inverse replay restores the original record exactly. Bundle mode now applies source manifests with document scoping rather than refusing the manifest.

Every final-certified single, bundle, or streaming report also exposes `third_series_closure` (`json-consistency-repair.third-series-closure.v1`). It reconciles the already-produced evidence for strong fixed point, zero-edit cold replay, independent certification, provenance-chain integrity, federation fixed point, multi-source/inverse transaction state, and—when streaming—the exact disk registry plus final record-bridge quietness. `CLOSED` is an audit consequence of those checks, never a substitute for them.

## PASS025 — boundary calculus / bounds-of-bounds / authoritative schema algebra

PASS025 starts the fourth expansion series by making admissible boundaries first-class objects. Every authoritative JSON Schema or DSL boundary is compiled into a deterministic `boundary_registry`; the registry is audited before mutation for contradictory lower/upper/cardinality contracts (`bounds_of_bounds`). If the boundary system is internally inconsistent, mutation is blocked rather than letting a downstream patch hide the contradiction.

Candidate admission now has a separate boundary firewall: a patch may resolve existing defects, but it is rejected if it creates a new authoritative boundary violation on the frozen snapshot. Numeric boundary repair is performed against the **intersection** of active constraints, not one keyword at a time. Inclusive real bounds and discrete `multipleOf` lattices are projected only when the minimum absolute-distance admissible value exists and is unique; open real bounds abstain when no nearest admissible real exists.

The JSON Schema bridge now materializes Draft 2020-12 validation/repair semantics for the main assertion algebra used by JSON data repair: `type`, `const`, `enum`, `minimum`, `exclusiveMinimum`, `maximum`, `exclusiveMaximum`, `multipleOf`, `minLength`, `maxLength`, bounded-safe `pattern`, `minItems`, `maxItems`, `uniqueItems`, `contains`/`minContains`/`maxContains`, `minProperties`, `maxProperties`, `required` + explicit defaults, `dependentRequired`, `dependentSchemas`, `properties`, `patternProperties`, `propertyNames`, `additionalProperties`, `prefixItems`, `items`, `allOf`, `anyOf`, `oneOf`, `not`, and `if/then/else`. Destructive repairs such as arbitrary truncation/deletion remain diagnostic-only unless separately authorized. Local `$ref` support remains bounded and cycle-safe.

The compact DSL gains numeric, length, collection and pattern boundaries (`minimum`, `exclusiveMinimum`, `maximum`, `exclusiveMaximum`, `multipleOf`, `minLength`, `maxLength`, `minItems`, `maxItems`, `uniqueItems`, `minProperties`, `maxProperties`, `pattern`). Explicit DSL scopes may now target any non-empty object array; empirical discovery analyzers retain their own support floors.

Single, bundle and streaming reports expose `boundary_calculus`. Streaming enforces the same schema/DSL boundary contracts record-by-record through the exact PASS024 record carrier. Runtime dependencies remain zero.

## PASS026 — parallel exact-minimum routes + RETURN_PROOF

PASS026 no longer collapses an exact tie into an opaque dead end. When the minimal-transfer solver finds several distinct patches with the same exact objective and displacement, it freezes the sovereign snapshot, materializes every tied route (bounded by `max_parallel_tie_routes`), executes each route on an isolated clone, and permits a return only when all branches close to the same canonical terminal and the same serialized issue/relation/Q witnesses.

The new public contracts are `json-consistency-repair.parallel-exact-routes.v1` and `json-consistency-repair.return-proof.v1`. Divergent routes, open branches, unresolved nested ambiguity, failed preconditions, route-frontier overflow, or mismatched return witnesses all produce abstention. Exact terminal equivalence is required before the deterministic representative route is selected. Single, bundle, and streaming record carriers implement the same rule; streaming returns are journaled as atomic whole-record transactions.

## PASS027 — primary factorization + dynamic refactorization

PASS027 moves exact-search partitioning from JSON syntax toward the dependency structure actually established by the repair analysis. Before minimal-transfer optimization, every admissible patch option is assigned to a `PRIMARY_BLOCK_REGISTRY`. Options are coupled by overlapping touched paths, by concrete relation instances, or by an explicit unresolved-dependency guard. Repeated-array relation instances are row-addressed, so a law learned on `/orders` does not accidentally couple unrelated records.

A legacy parent container may be split only when every option inside it has an explicit relation witness. Absence of a discovered relation is therefore not treated as proof of independence. Each factorization carries a lossless recomposition proof: every frontier option appears exactly once and no known dependency edge crosses blocks. The minimal solver searches blocks independently, then revalidates the union against the sovereign JSON before any commit.

`dynamic_refactorization` recompiles the registry every cycle. Split, merge, replacement, new, and dropped-block events invalidate stale primary block identities. Atomic multi-path plans remain indivisible because all step paths participate in the dependency graph. Bundle cross-document candidates use document-scoped primary factorization; streaming authoritative record bridges inherit the same core factorization.

Public contracts: `json-consistency-repair.primary-factorization.v1` and `json-consistency-repair.dynamic-refactorization.v1`.


## 0.28.0 — PASS028

Full proof-graph cold replay. The engine now commits a canonical cryptographic graph containing the input/output terminals, analyzer MODE I packets, federation pairwise/hyperobjects, certified relations, source/authority evidence, boundary history, primary blocks and dynamic refactorization, PASS026 RETURN_PROOF objects, Q-descent states, cycle decisions, exact applied patches and provenance. Final certification requires two distinct replays: zero-edit replay from the repaired terminal and a complete restart from the sovereign original input that must reconstruct the same proof-graph SHA-256 and the same terminal output. A JSON output that is byte/semantically identical but reached through a different relation, actor packet, factorization history, route proof, Q state or graph edge is therefore not accepted as the same proof. Single, bundle and streaming modes expose `proof_graph` and `proof_graph_replay`.

PASS028 release gate: complete 291-test unit/integration suite, dedicated 600-decision proof-graph stress, deterministic 600-decision benchmark with zero false accepts, exact single/bundle/streaming proof-graph replay, graph tamper rejection, reproducible wheel/source builds, fresh-wheel installation, extracted-source parity, zero-edit terminal cold replay, independent final certification and a cumulative archive retaining exact PASS027 as predecessor.

## PASS029 automatic minimal-witness materialization

PASS029 composes PASS010 identifiability, PASS023 multi-source provenance, PASS028 proof-graph replay and the live repair loop. When an unresolved terminal exposes a precise `minimal_missing_witness`, the engine searches the bounded loaded source contract, including identity bridges, explicit hints and authorized event projections. A unique admissible witness is materialized, provenance-bound, reinjected, and the original terminal is re-analyzed. Competing exact values abstain. Search failure remains `ABSENT_CERTIFIED_WITHIN_SEARCH_CONTRACT`, never world-level absence. Single, bundle and streaming record bridges preserve materialization evidence through cold replay and final certification.


## 0.31.0 — PASS031 robust envelopes

PASS031 adds a pre-optimization robustness firewall.  Candidate repairs may be constrained by explicit uncertainty intervals, deterministic freshness clocks, regime identity and hysteresis bands.  A mutation is suppressed when it is not distinguishable from the admissible uncertainty envelope, is based on stale/future-skewed state, crosses a declared regime, or would flip a hysteretic state before the full uncertainty band crosses the threshold.

Rules are supplied with `--robust-envelope rules.json`.  Time rules never read wall-clock time: `evaluation_time` must be explicit, so proof-graph replay remains deterministic.  JSON-pointer wildcard patterns such as `/rows/*/value` bind repeated-record envelopes without turning array indices into global rules.  The full firewall certificate is committed into the PASS028 proof graph and independently hash-verified by the final certifier.

## 0.30.0 — PASS030 scoped/delegated authority

PASS030 replaces flat source authority with an explicit capability proof over `path × document × schema-version × time × operation`. Authoritative/default sources keep backward-compatible global scope only when no narrower scope is declared. Delegations are bounded, chainable and revocable; a delegate cannot act outside the grantor's active scope or the delegated sub-scope. Explicit authoritative materialization hints and event projections are compiled as narrow manifest grants rather than global source escalation.

The same pass adds an evidence-poisoning firewall. Declared independence groups are only one signal: provenance lineage and manifest-declared correlations collapse derived copies into one effective evidence group. Byte-identical source corpora are always flagged and can be configured as correlated with `evidence_policy.identical_content_is_correlated=true`; they are not silently collapsed by default because independently collected deterministic corpora can legitimately be identical. Development/heldout promotion uses effective evidence groups, so a heldout source derived from development can no longer certify its own parent.

Public contracts: `json-consistency-repair.scoped-authority.v1`, `json-consistency-repair.authority-proof.v1`, and `json-consistency-repair.evidence-poisoning-firewall.v1`. Final proof-graph replay commits these objects, and the independent certifier re-evaluates authority proofs against their hashed registry.



## PASS032: canonical rectification packet
Version 0.32.0 closes the fourth series. Single JSON, bundle, and streaming modes emit a deterministic canonical rectification packet, an independent certifier seal, and a final PASS025→PASS032 closure gate. The packet is an index over the full serialized evidence graph rather than a second competing copy of the evidence.

## 0.33.0 — PASS033 semantic claim provenance firewall

PASS033 opens the fifth series by separating byte integrity from semantic attribution. A rule may be valid JSON and live in an unmodified file while still falsely claiming that it came from a source. Before any analyzer can use an externally attributed rule, the engine compiles a `semantic_claim_provenance` registry and requires a reproducible lineage proof.

Claim classes are explicit: `SOURCE_EXACT`, `DERIVED_EXACT`, `USER_DECLARED`, `INFERRED`, and `UNVERIFIED_ATTRIBUTION`. `SOURCE_EXACT` binds the complete claim to an exact JSON-pointer fragment through a canonical JSON Merkle inclusion proof. `DERIVED_EXACT` re-evaluates a deterministic template whose `$source` leaves are individually inclusion-proved. `USER_DECLARED` is valid only when it makes no external-source attribution. External self-promotion to `INFERRED`, provenance without a stable public rule ID, false source labels, missing source pointers, and non-reproducing derivations are gated before analysis.

The pre-analysis gate is deliberate: an unverified rule cannot become a boundary, relation, graph law, robust envelope, or other intermediate fact that indirectly suppresses or creates an otherwise unrelated repair. The final independent certifier re-verifies claim payload hashes, Merkle proofs, source commitments, deterministic derivations, and firewall certificates. Single JSON, bundle, and streaming record bridges use the same contract. Semantic provenance is committed to the PASS028 proof graph and indexed by the PASS032 rectification packet.

Public contracts include `semantic-claim-provenance-v1`, `semantic-claim-proof-v1`, `json-merkle-inclusion-v1`, `semantic-claim-provenance-firewall-v1`, and the non-closing `fifth-series-progress-v1` ledger.

## 0.34.0 — PASS034 typed expressions and repair-path algebra

PASS034 turns configured formulae and repair actions into typed machine objects. The authoritative expression DSL now accepts `expr name: lhs = rhs` and compiles a safe JSON IR supporting exact `+`, `-`, `*`, `/`, integer powers, square roots, modulo, absolute value, min/max, floor/ceil, finite sums/products, and explicit field dependencies. Arithmetic uses exact rationals; an inverse is emitted only when it is unique and exactly representable in JSON. Sign-symmetric powers, modulo/floor/ceil inversions and non-terminating JSON decimals remain OPEN rather than being approximated.

The minimal-transfer solver now compiles each frozen finite candidate frontier into a repair-path algebra with typed read/write footprints, a strictly decreasing one-shot action-rank termination measure, critical-pair analysis, explicit disjoint commutation proofs, bounded joinability search and a finite-frontier confluence certificate. An unordered multi-patch subset is admissible only when all local critical pairs are joined on that frontier. Ordered PASS026 RETURN_PROOF routes remain ordered and are not falsely required to commute. Algebra certificates are serialized in single/bundle reports, inherited by streaming record bridges, committed into the rectification packet, and independently hash/invariant checked by the final certifier.

PASS034 deliberately makes no theorem about future actions not present in the frozen frontier. `CRITICAL_PAIR_OPEN`, `REWRITE_TERMINATION_FRONTIER_TOO_LARGE`, and non-invertible expression operators are explicit non-mutation states.

## 0.35.0 — PASS035 symmetry obstruction and semantic canonicality

PASS035 detects exact-minimum repair routes that differ only by choosing among indistinguishable repeated members. When an automorphism-like exchange of those members preserves the frozen input evidence but the concrete repaired terminals differ, the engine emits `SYMMETRY_BLOCKED_REPAIR` instead of selecting a JSON index arbitrarily. The certificate records the repair orbit and a minimum symmetry-breaking witness, such as a stable identifier, an authoritative source selector, or explicit ordered-position semantics.

Semantic quotienting is deliberately explicit. A caller may declare representation freedom such as `unordered_array`; duplicate removal is permitted only under the stronger `unordered_unique_array` rule with `duplicates_are_semantically_irrelevant=true`. Array order, set semantics, or duplicate irrelevance are never inferred from data shape alone. PASS033 semantic-claim provenance gates externally attributed quotient rules before they can influence PASS035.

When distinct concrete route terminals are equivalent only under a verified explicit quotient, PASS026 may emit `RETURN_PROOF_QUOTIENT_EQUIVALENT`, but only if remaining issues, certified relations and Q witnesses also agree. Single JSON, bundle and streaming record bridges expose `symmetry_canonicality`; the PASS028 proof graph and PASS032 rectification packet commit the new evidence, and the independent certifier re-verifies the symmetry/quotient certificates.



## 0.36.0 — PASS036 controllability / reachability of repair actions

PASS036 separates identifying a correct target state from proving that the runtime is permitted and able to reach it. Candidate writes are filtered before optimization by a mutation-control contract over JSON-pointer path, document and operation. Rules may declare immutable paths, allowed or denied operations, explicit-permission requirements, edit/cost budgets and ordering constraints. A mathematically identifiable repair that violates the active contract is preserved as `IDENTIFIABLE_BUT_UNREACHABLE`; the engine never weakens the contract to make the repair succeed.

Selected multi-action repairs are compiled into an executable control plan. Declared `must_precede` edges are topologically ordered when possible; precedence cycles are an explicit unreachable state. Atomic plans are checked at every internal write. Run budgets are cumulative across committed cycles, and the already-consumed budget is transported into repaired-terminal cold replay so replay cannot spend the same budget twice; proof-graph replay from the sovereign original input still starts from the original budget state.

The public contracts are `json-consistency-repair.repair-controllability.v1`, `json-consistency-repair.controllability-firewall.v1`, and `json-consistency-repair.repair-controllability-summary.v1`. Single, bundle and streaming surfaces expose the evidence; PASS033 gates externally attributed control policies, PASS028 commits the control evidence into the proof graph, and the independent certifier re-verifies all control certificates.


## 0.37.0 — PASS037 active relation falsification

PASS037 adds a bounded pre-optimization falsification layer for inferred relations. Relations are challenged using deterministic split validation, zero-input ablation and negative controls over the loaded finite carrier. A relation whose deterministic folds infer incompatible mappings becomes `ACTIVE_REFUTED`; a purported dependency that is explained exactly by a zero-input constant baseline becomes `NEGATIVE_CONTROL_INVARIANT`. Both states are removed before federation and cannot authorize a mutation. Non-trivial relations may be promoted to `ADVERSARIAL_SURVIVED`; relation families without a sound bounded attack remain `OBSERVED_ONLY`, never silently promoted to portable. Authoritative schema/DSL/system contracts are recorded as `AUTHORITATIVE_CONTRACT` and are not confused with empirical hypotheses. Synthetic controls are never counted as observations. The same surface is serialized in single, bundle and streaming reports, the PASS028 proof graph, PASS032 rectification packet and the independent certifier.

## 0.38.0 — PASS038 persistent OPEN obligations and incremental recomputation

PASS038 turns unresolved terminals into persistent machine objects rather than forgetting them at process exit. `open_obligations` records typed needs such as `NEED_SOURCE`, `NEED_AUTHORITY_GRANT`, `NEED_SYMMETRY_BREAKER`, `NEED_REWRITE_JOIN`, `NEED_CONTROL_PERMISSION`, `NEED_BOUNDARY_RESOLUTION` and `NEED_PROVENANCE_PROOF`, each with explicit wake and dependency tokens. Registries are hash-bound and can be written atomically for a later run.

A resumed run may supply a prior registry or prior report plus explicit change tokens. The engine wakes only intersecting obligations, conservatively invalidates proof nodes whose declared dependencies intersect the change set, and compares the targeted OPEN-state transition with the registry from the full fresh execution. If an unrelated obligation changes, the result is `FULL_RECOMPUTE_REQUIRED`; nothing is silently discarded. When a prior proof graph is supplied, unchanged node identities may be reused only if the new full proof-graph replay reconstructs the same nodes exactly. JSON publication remains gated by the ordinary cold replay and full proof-graph replay.

CLI surfaces: `--open-obligation-store`, `--resume-obligations`, `--incremental-prior-report`, and repeatable `--incremental-change-token`. Runtime dependencies remain zero.

## 0.39.0 — PASS039 horizon naturality and distributed consistency

PASS039 adds a deterministic horizon snapshot over input/output JSON nodes, localized relation dependencies and the run's distribution descriptor. When a prior PASS039 snapshot is supplied, the engine compares the old and enlarged horizons. Any terminal attached to unchanged old input must remain unchanged unless a newly introduced dependency crosses the old boundary. The certificate then names the exact relation/change path or an explicit authority witness. Unexplained old-scope drift is `HORIZON_DRIFT_UNEXPLAINED` and forces full recomputation rather than silently accepting horizon-sensitive behavior.

The same snapshot carrier supports distributed consistency. Two executions of the same logical input under different shard/worker/window descriptors must produce the same terminal digest. Same-input/different-terminal outcomes become `DISTRIBUTED_CONFLICT`. Overlapping complete manifests are also checked pathwise. Incomplete streaming locality never fabricates a local proof: changed input plus changed terminal falls back to `FULL_RECOMPUTE_REQUIRED`; identical input/output digests remain an exact digest-level invariant.

Public contracts: `json-consistency-repair.horizon-snapshot.v1`, `json-consistency-repair.horizon-naturality.v1`, and `json-consistency-repair.distributed-consistency.v1`. The PASS028 proof graph, PASS032 rectification packet and independent certifier bind and re-evaluate the new surfaces. `--incremental-prior-report` automatically reuses a valid prior horizon snapshot; `--horizon-change-token` can add an explicit boundary-change token.


## 0.40.0 — PASS040 residual information and blind-carrier reconstruction

PASS040 closes the fifth series by separating **reconstructability** from **information that is still genuinely missing**. For a finite declared candidate carrier of cardinality `n`, `residual_information` computes the exact fixed-width selector lower bound `ceil(log2(n))` using integer arithmetic. A singleton carrier requires zero selector bits; a finite ambiguous carrier is `RESIDUAL_INFORMATION_REQUIRED`; an unknown or unmaterialized carrier never receives a fabricated numeric lower bound.

`blind_carrier_reconstruction` tests whether a target can actually be reconstructed from the visible carrier. Before the reconstruction function runs, the target field is physically removed from a deep copy of the tested record. Only peer evidence matching the frozen functional/scoped-functional relation remains visible. The hidden value is consulted afterwards only through its SHA-256 commitment. Exact reconstruction yields `BLIND_RECONSTRUCTED_EXACT`; several admissible peer outputs yield an explicit residual-information debt; no usable peer carrier yields `CARRIER_INSUFFICIENT`; a wrong reconstruction is a hard `BLIND_RECONSTRUCTION_MISMATCH` and fails independent certification. Streaming mode does not pretend that an unmaterialized global carrier is available and reports `CARRIER_NOT_MATERIALIZED`.

The PASS040 surfaces are hash-bound into the PASS028 proof graph, PASS032 rectification packet and independent certifier. `fifth_series_progress` is now **8/8 CLOSED**, and `fifth_series_closure` independently reconciles PASS033–PASS040 with cold replay, proof-graph replay, packet presence, horizon/distributed coherence and the absence of blind-carrier mismatches.

## 0.41.0 — PASS041 benchmark-driven SC minimal-displacement correction

PASS041 is a post-series maintenance/adversarial correction pass. It does not reopen the closed PASS033–PASS040 fifth series. It takes the measured limits of the 0.40.0 external-limit benchmark as explicit terminals and applies the smallest certified changes that remove the internal defects without widening the repair authority indiscriminately.

The minimal-transfer objective now measures surviving pre-existing/frozen terminals before newly exposed diagnostic severity, preventing a correct edit from being rejected merely because it reveals subordinate obligations. Functional and exact-arithmetic analyzers gain a bounded `SPARSE_OUTLIER_RECOVERY` route below the ordinary 0.95 discovery threshold, but only when the active falsifier remains enabled, support stays above a 0.60 floor, the dominant carrier is repeated, and competing values/residuals are individually non-coherent. Repeated competing modes remain an abstention boundary.

`PASS` now carries an explicit truth scope: evidence/declaration-relative consistency is not external ground-truth proof. The bounded grammar frontier can compose two native structural edits, close one unterminated scalar string, normalize closed single-quoted strings, quote unquoted identifier keys, and strip JS-style comments outside strings when the minimum strict-JSON result is unique. Conflicting duplicate keys remain an explicit ambiguity and are never silently resolved.

PASS041 also introduces two execution profiles. `full` preserves exhaustive correction, proof-graph/cold replay and independent certification. `fast` still scans every analyzer family over the sovereign object, but deepens expensive falsification and mutation search only around uniquely actionable local repair cones. It performs exact forward/inverse replay for edits but deliberately reports `FAST_SCAN_ONLY` rather than pretending to have run the full certifier. Pure structural projections, exact-number projections, key-order witnesses and repeated identical-state analyses are cached within one run.
