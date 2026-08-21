# Release synchronization

The software release is one object represented on several platforms, not several independently edited copies.

1. Merge the exact source to the release branch.
2. Run CI, public benchmark and inherited stress campaigns.
3. Build deterministic wheel + source ZIP with `python scripts/build_release.py`.
4. Generate `RELEASE_PROVENANCE.json` from those exact artifacts.
5. Tag the exact commit `vX.Y.Z`.
6. Publish the exact wheel to PyPI.
7. Attach the exact wheel, source ZIP, provenance manifest and benchmark result to the GitHub Release.
8. Let the connected Zenodo GitHub integration archive that tagged release.
9. Add the resulting Zenodo DOI to the publication metadata/CITATION file in the next commit or record metadata without rebuilding the already archived artifact.
10. Keep the conceptual DOI as the stable project citation and the version DOI as the exact-release citation.

The runtime package records a code digest. The external release manifest records artifact hashes because a wheel cannot contain its own cryptographic hash without circularity.

GitHub is the canonical live source. PyPI is the canonical install channel. Zenodo is the canonical scientific archive/citation layer.


## PASS016 release gate

Before publishing the closed PASS016 / 0.16.0 baseline, require: full inherited regression, PASS014/PASS015/PASS016 dedicated stress, three final zero sweeps with the first zero ignored, reproducible wheel/source, fresh-wheel installation, extracted-source parity, independent certifier smoke test, and deterministic benchmark output. Artifact hashes belong in the external release provenance manifest; the artifact does not claim to authenticate or prove its own content.

## PASS016 second-series closure

The 0.16.0 candidate closed after three repeated zero sweeps on one frozen code state. The first zero was ignored; the next two independently repeated the unit/integration suite, PASS014/PASS015/PASS016 dedicated stresses, and the deterministic final benchmark. Future releases may extend the engine, but 0.16.0's closure evidence remains immutable release provenance.


## PASS017 third-series opening

0.17.0 opened the third series over the frozen PASS016 baseline with structural JSON patch algebra and bounded grammar repair.

## PASS020 active candidate

0.21.0 extends the PASS019 cumulative baseline with graph/state-system repair, controllability witnesses and exact ordered migration plans. PASS018 DSL/schema and PASS019 causal-root functionality remain inherited and active. Release requires the inherited unit/integration suite, native PASS016/PASS017/PASS018 certification stresses, the PASS018 600-case benchmark, the historical multi-mode decision benchmark, reproducible wheel/source builds, fresh-wheel installation, extracted-source parity, DSL/schema/OpenAPI CLI smoke tests, and independent final certification.


## PASS018 constraint bridge

Optional flags: `--constraints FILE.dsl`, `--json-schema FILE.json`, `--openapi FILE.json`, and `--openapi-schema NAME`. The DSL and schema/OpenAPI sources are authoritative inputs, not discovered truth. Exact linear systems abstain on ambiguous mutation direction. Local schema refs are bounded and acyclic; external/cyclic refs are refused.


## PASS018 release gate

The active distribution must keep runtime dependencies at zero, resolve only bounded local schema `$ref` values, refuse ambiguous linear mutation direction, and expose `--constraints`, `--json-schema`, `--openapi`, and `--openapi-schema`. Streaming use of PASS018 schema/DSL bridges remains explicitly refused until the disk-backed exact streaming pass rather than silently applying an incomplete global interpretation.


## PASS020 release gate

Require the complete unit/integration suite, PASS020 600-case stress, inherited decision regressions, native PASS016–PASS020 certification stresses, deterministic PASS020 benchmark, historical multi-mode benchmark, reproducible wheel/source builds, fresh-wheel install, `--system-rules` CLI smoke test, source extraction parity, exact plan inverse replay and independent final certification. `dist/` must contain only 0.21.0.

## PASS021 release gate

PASS021 requires 216/216 unit/integration tests, 600/600 dedicated moment stress, native PASS016–PASS020 stresses, deterministic PASS021 benchmark, historical 600/600 decision benchmark, exact inverse replay for unit-normalization plans, finite-decimal firewall for rational outputs, fresh-wheel installation and extracted-source parity. Runtime dependencies remain zero.

## PASS022 release gate

PASS022 requires the complete unit/integration suite, 600/600 dedicated federation stress, semantic fixed-point de-duplication, deterministic MODE I packets and MODE II receipts, consensus/conflict firewalls, recursive directed-relation composition, bundle/streaming report coverage, dynamic Q ledger checks, inherited PASS016–PASS021 native regressions, deterministic PASS022 benchmark, historical multi-mode benchmark, reproducible wheel/source builds, fresh-wheel installation, extracted-source parity, cold replay and independent certification. Runtime dependencies remain zero.

## 0.23.0 — PASS023

- multi-source manifest and source-role firewall;
- deterministic source registry with digests/support/independence groups/schema versions;
- defaults fill-missing-only semantics;
- previous-source observer-only semantics;
- explicit authoritative cross-source values and event-log projections;
- cross-version field identity registry;
- development → heldout → portable lifecycle;
- independent counterexamples force `GLOBAL_REFUTED`;
- same-independence-group replication never counts as heldout;
- source manifests are optional; normal single-file behavior is unchanged.


## 0.24.0 — PASS024

- exact SQLite spill registry for streaming functional groups beyond the in-memory cap;
- recovered overflow relations remain queryable without loading the complete corpus in RAM;
- record-local streaming bridge for DSL, JSON Schema/OpenAPI, ordered system plans, moment/unit plans and multi-source semantics;
- whole-record atomic streaming journal entries for structural/multi-path plans, with exact inverse replay;
- development/heldout lifecycle materialized against streamed primary records;
- bundle source-manifest document scoping and multi-source relations included in final bundle reconciliation;
- `third_series_closure` audit object over fixed point, cold replay, independent certifier, provenance, federation, inverse transaction, multi-source and streaming exact-registry evidence;
- three PASS024 public JSON schemas for the disk registry, record bridge and closure object;
- third expansion series PASS017–PASS024 closed; no planned substantive pass remains in this series.

## PASS024 release gate

PASS024 requires the complete unit/integration suite, the dedicated 600-decision PASS024 stress campaign, deterministic 600-decision PASS024 benchmark with zero false mutations, exact overflow recovery, streaming DSL/schema/system/moment/multi-source witnesses, bundle source scoping, exact inverse replay, zero-edit cold replay, independent certification, third-series closure, reproducible wheel/source builds, fresh-wheel installation, extracted-source parity, and cumulative-archive integrity. Runtime dependencies remain zero.

## 0.25.0 — PASS025

Fourth-series opening: explicit boundary calculus.

- deterministic boundary registry for JSON Schema + authoritative DSL;
- bounds-of-bounds coherence gate before mutation;
- boundary firewall rejecting patches that create new authoritative boundary violations;
- combined numeric projection over the full active constraint intersection;
- conservative treatment of open real boundaries and tied lattice projections;
- expanded Draft 2020-12 JSON Schema assertion/composition algebra;
- expanded DSL boundary vocabulary;
- boundary reports in single, bundle and streaming modes;
- two new public Draft 2020-12 machine schemas for boundary registry and boundary calculus.

PASS025 release gate: complete tests, dedicated 600-decision stress, deterministic 600-decision benchmark with zero false mutations, reproducible wheel/source builds, fresh-wheel validation, extracted-source parity, cold replay and cumulative archive with exact PASS024 predecessor.

## 0.26.0 — PASS026

Parallel exact-minimum route execution and explicit RETURN_PROOF. Equal exact minima are cloned from one frozen snapshot instead of being ranked arbitrarily. MAIN receives a mutation only after every admissible branch reaches the same exact terminal with matching closure witnesses. Divergence, unresolved ambiguity, open fixed points and route-frontier overflow remain non-mutating states. Bundle cross-document ties and streaming record ties use the same bounded route discipline. The independent single-object certifier verifies serialized RETURN_PROOF hashes when a parallel-return mutation was committed.

## 0.27.0 — PASS027

Primary dependency factorization replaces the legacy `parent_json_container` search partition in the core minimal-transfer solver. Every patch frontier is compiled into relation-connected primary blocks with exact option coverage, explicit coupling witnesses and a zero-loss recomposition certificate. Unknown dependency is conservative: a local carrier is not split merely because no relation was found. Dynamic refactorization records and invalidates block identities when the active relation/frontier structure changes. Bundle cross-document repair uses the same document-scoped factorization rule, and the final independent single-object certifier verifies serialized factorization digests and recomposition invariants.

PASS027 release gate: complete unit/integration suite, dedicated 600-decision factorization stress, deterministic 600-decision PASS027 benchmark with zero false structural mutations, inherited PASS016–PASS026 regressions, reproducible wheel/source builds, fresh-wheel installation, extracted-source parity, cold replay, independent certification and a cumulative archive retaining exact PASS026 as predecessor.


## 0.28.0 — PASS028

Full proof-graph cold replay. The engine now commits a canonical cryptographic graph containing the input/output terminals, analyzer MODE I packets, federation pairwise/hyperobjects, certified relations, source/authority evidence, boundary history, primary blocks and dynamic refactorization, PASS026 RETURN_PROOF objects, Q-descent states, cycle decisions, exact applied patches and provenance. Final certification requires two distinct replays: zero-edit replay from the repaired terminal and a complete restart from the sovereign original input that must reconstruct the same proof-graph SHA-256 and the same terminal output. A JSON output that is byte/semantically identical but reached through a different relation, actor packet, factorization history, route proof, Q state or graph edge is therefore not accepted as the same proof. Single, bundle and streaming modes expose `proof_graph` and `proof_graph_replay`.

PASS028 release gate: complete 291-test unit/integration suite, dedicated 600-decision proof-graph stress, deterministic 600-decision benchmark with zero false accepts, exact single/bundle/streaming proof-graph replay, graph tamper rejection, reproducible wheel/source builds, fresh-wheel installation, extracted-source parity, zero-edit terminal cold replay, independent final certification and a cumulative archive retaining exact PASS027 as predecessor.

## 0.29.0 — PASS029

0.29.0 adds automatic minimal-witness materialization over the frozen PASS028 proof-graph baseline. Release requires dedicated PASS029 unit/stress coverage, exact source-role and identity-bridge provenance, ambiguity/gate abstention, reinjection/re-ask closure, proof-graph commitment, cold replay, independent certification, fresh-wheel installation, extracted-source parity, reproducible artifacts and zero external runtime dependencies.


## 0.31.0 — PASS031

- uncertainty-envelope gate (`lower/upper`, radius, sigma × k);
- explicit deterministic freshness clocks with stale/future-skew refusal;
- regime-bound candidate firewall;
- uncertainty-aware hysteresis entry/exit gates;
- wildcard JSON-pointer envelope rules for repeated structures;
- single, bundle and streaming record-bridge integration;
- robust-envelope certificates committed to proof-graph replay and checked by the independent certifier;
- 0 external runtime dependencies.

## 0.30.0 — PASS030

Scoped/delegated authority and evidence-poisoning firewall. Release gate: complete unit/integration regression including all prior PASS002–PASS029 tests, dedicated PASS030 tests, 600/600 PASS030 stress, deterministic 600/600 benchmark with zero false mutations, direct/path/schema/time/operation scope gates, chained delegation and revocation, provenance-lineage heldout rejection, proof/registry tamper rejection, single/bundle/streaming proof-graph replay, reproducible wheel/source builds, fresh-wheel installation, extracted-source parity, zero runtime dependencies, and cumulative archive retaining exact PASS029 as predecessor.



## 0.32.0 / PASS032
Adds the canonical rectification packet, packet/report hash binding, independent packet seal, external re-verification, explicit absence semantics, single/bundle/streaming integration, and the PASS025–PASS032 fourth-series reconciliation gate. Substantive passes remaining in this series: 0.

## 0.33.0 — PASS033

Semantic claim provenance firewall. PASS033 opens the fifth series by making claimed lineage independently reproducible rather than trusting a source label or file hash. Exact source claims use JSON Merkle inclusion proofs; deterministic derived claims re-evaluate proof-carried templates; user-declared rules are explicitly separated from source-derived rules; unverified attribution is gated before any analyzer can consume the law. Single, bundle and streaming outputs bind the semantic registry into the proof graph, rectification packet and independent final certifier. Substantive fifth-series passes remaining after PASS033: 7.

## 0.34.0 — PASS034

Typed Expression IR and finite repair-path algebra. PASS034 adds exact formula constraints without arbitrary evaluation, unique exact inverse synthesis, explicit operator-domain/open states, semantic read/write footprints, finite-frontier termination, critical-pair joinability, disjoint commutation proofs and confluence-gated unordered minimal-transfer subsets. The independent certifier verifies serialized algebra certificates. Single, bundle and streaming record-bridge surfaces expose the new contracts. Substantive fifth-series passes remaining after PASS034: 6.

## 0.35.0 — PASS035

Symmetry obstruction and semantic canonicality. PASS035 detects exact-minimum route orbits in which repeated JSON members are indistinguishable under the frozen evidence and refuses arbitrary index-based selection with `SYMMETRY_BLOCKED_REPAIR`. It emits a scoped minimal symmetry-breaking witness. Explicit semantic quotient rules can declare harmless representation freedom without being inferred from data shape; unordered arrays preserve multiplicity, while duplicate collapse requires an explicit stronger declaration. PASS033 gates externally attributed quotient semantics. PASS026 can return `RETURN_PROOF_QUOTIENT_EQUIVALENT` only after quotient-terminal, remaining-issue, relation and Q equivalence. Single, bundle and streaming surfaces, proof graph, canonical packet and independent certifier are integrated. Substantive fifth-series passes remaining after PASS035: 5.



## 0.36.0 — PASS036

Repair controllability and reachability are now first-class. The engine filters candidates against explicit mutation permissions, immutable paths and operation allow/deny lists before minimal optimization; compiles legal selected actions under cumulative edit/cost budgets and precedence constraints; refuses precedence cycles; validates every write inside atomic plans; transports consumed budgets into terminal cold replay; and exposes a proof-carrying `repair_controllability` summary in single, bundle and streaming modes. Externally attributed control policies remain subject to PASS033 semantic-provenance verification.

PASS036 release gate: complete 398-test unit/integration suite, dedicated 600-decision controllability stress, deterministic 600-decision benchmark with zero false mutations, 59 public Draft 2020-12 schemas, reproducible wheel/source builds, fresh-wheel install and witness, independently extracted-source parity, zero-edit cold replay, exact proof-graph replay, independent final certification, and a reproducible cumulative archive retaining exact PASS035 as the sole cumulative predecessor.


## 0.37.0 — PASS037

- active falsification firewall for inferred relations before federation/optimization;
- deterministic split-fold contradiction detection;
- zero-input ablation and bounded negative controls;
- `ACTIVE_REFUTED` and `NEGATIVE_CONTROL_INVARIANT` mutation gates;
- `ADVERSARIAL_SURVIVED` bounded-survival state and `OBSERVED_ONLY` non-promotion state;
- authoritative contracts separated from empirical hypotheses;
- single, bundle and streaming report surfaces;
- proof-graph, rectification-packet and independent-certifier integration;
- two new public Draft 2020-12 schemas; runtime dependencies remain zero.

PASS037 release gate: complete regression suite by deterministic segments, dedicated 600-case stress, deterministic 600-decision benchmark with zero false mutations, all public schemas Draft 2020-12 valid, reproducible wheel/source, fresh-wheel install and `pip check`, extracted-source parity, exact predecessor hash, and deterministic cumulative ZIP under the repository size ceiling.

## 0.38.0 — PASS038

Persistent OPEN obligations and certified targeted invalidation. PASS038 serializes unresolved repair terminals into `json-consistency-repair.open-obligation-registry.v1`, persists them atomically, wakes only explicit dependency intersections, compiles a conservative proof dependency index, and emits `json-consistency-repair.incremental-recompute.v1`. A targeted obligation transition must match the full fresh registry or the engine records `FULL_RECOMPUTE_REQUIRED`. Optional prior proof graphs support exact-node reuse evidence through `json-consistency-repair.incremental-equivalence.v1`; any drift falls back to the full recomputation path. Publication remains gated by full cold replay and full proof-graph replay.

PASS038 release gate: full 423-test regression, 600/600 dedicated stress, deterministic 600-decision benchmark with zero false mutations, all public Draft 2020-12 schemas valid, reproducible wheel/source builds, fresh-wheel install and CLI persistence/resume witness, extracted-source parity, exact PASS037 predecessor hash, and deterministic cumulative ZIP.

## 0.39.0 — PASS039

Horizon naturality and distributed consistency. A run emits a hash-bound `horizon-snapshot.v1` containing complete bounded input/output node manifests when available, localized relation dependency patterns, semantic input/output digests and the declared distribution descriptor. A prior snapshot creates a naturality comparison: unchanged old terminals must remain invariant under document expansion; changed terminals require a concrete boundary-crossing witness. If locality is incomplete and both horizon and terminal changed, the conservative result is `FULL_RECOMPUTE_REQUIRED`.

For identical logical inputs, changing workers/shards/window descriptors is observationally irrelevant: terminal digests must agree. The distributed certificate rejects same-input/different-terminal behavior as `DISTRIBUTED_CONFLICT`. PASS039 surfaces are included in the proof graph and rectification packet and are independently recomputed by the final certifier. Fifth-series progress is 7/8; PASS040 remains.


## 0.40.0 — PASS040

Residual-information lower bounds, blind-carrier reconstruction, and fifth-series closure. A finite candidate orbit now produces an exact fixed-width selector lower bound; unknown carrier cardinality remains explicitly unbounded rather than being mislabeled as zero information. Blind reconstruction removes the target from the carrier before inference, permits only frozen peer relation evidence, and compares the post-hoc prediction to a hidden SHA-256 commitment. Ambiguity and insufficient carrier produce explicit abstention/debt states; a reconstruction mismatch is a certification failure.

PASS040 is bound into single, bundle and streaming reports, the proof graph, rectification packet and independent certifier. Streaming is deliberately conservative when the complete carrier is not materialized. The fifth-series reconciliation object closes PASS033–PASS040 only when all eight pass layers, final certification, cold replay, proof-graph replay, fixed-point checks, horizon/distributed consistency and PASS040 packet/proof surfaces agree.

## 0.41.0 — PASS041

PASS041 is a benchmark-driven maintenance release derived from the limits measured after 0.40.0. It applies SC minimal-displacement discipline to the non-monotonic three-missing-value witness, sparse already-materialized corruptions, PASS truth-scope wording, repeated full-object analysis, benchmark RSS attribution, and two bounded grammar-frontier gaps.

The sparse recovery route is not a generic confidence-threshold reduction. It is gated by the active relation falsifier, a 0.60 confidence floor, repeated modal support, mode margin, and rejection of coherent alternative modes/residuals. Where the evidence supports two regimes, the engine abstains. PASS remains API-compatible but is explicitly scoped to current certified relations and declared evidence, never external ground truth.

PASS041 also adds an SC hot-path bifurcation. `full` remains the exhaustive certified engine. `fast` scans every analyzer family but deepens expensive work only on local actionable cones and explicitly refuses to claim full certification. On the same two-error corpus used for the PASS041 speed audit, the fast path was about 62–67x faster than the frozen 0.40.0 baseline at 100–1000 rows while producing the same repaired terminal; the optimized full path was about 2.2–3.7x faster.

The grammar frontier now closes 13/13 determinable cases in the targeted 14-case corpus and correctly refuses the one conflicting duplicate-key ambiguity.

The closed fifth series remains closed; PASS041 is post-series corrective maintenance. External market-wide competitor comparison remains an external benchmark gate rather than a product-internal proof obligation.
