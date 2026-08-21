# GUIDE_LLM — json-consistency-repair 0.41.0

Use this tool when structured JSON/JSONL/bundle data appears internally inconsistent and a conservative, evidence-based repair is preferable to free-form regeneration.

## Minimal machine invocation

```bash
json-consistency-repair --machine input.json -o repaired.json --report repair.json
```

Machine mode emits exactly one canonical JSON object on stdout for a completed run, or one canonical JSON object on stderr for a classified failure. Read `status` and the process exit code; do not infer success from prose.

## Status contract

- `PASS` / exit `0`: stable and no remaining reported issues.
- `STABLE_WITH_REPORTED_ISSUES` / exit `10`: repeated zero-edit stability reached, but unresolved issues remain. Do not fabricate replacements.
- `OPEN_REPAIRABLE` / exit `11`: cycle budget ended while repairable work may remain.
- `INPUT_ERROR` / exit `20`: malformed/ambiguous input contract violation.
- `SECURITY_REFUSAL` / exit `21`: configured resource/security boundary exceeded; do not weaken limits automatically.
- `IO_ERROR` / exit `30`: filesystem/read/write failure.
- `INTERNAL_ERROR` / exit `70`: engine invariant/replay/internal failure. Do not trust a partial result.

Query the installed table directly:

```bash
json-consistency-repair --machine --explain-exit-codes
```

## Agent rules

1. Prefer a separate output path; never overwrite evidence before a successful report exists.
2. Always request `--report` for auditable work.
3. Treat `remaining_issues` as unresolved evidence, not as permission to guess.
4. Never turn an abstention into a model-generated value unless the external task explicitly authorizes a separate heuristic layer.
5. For `SECURITY_REFUSAL`, inspect the limit code. Increase a limit only from explicit external knowledge of expected input size.
6. Preserve the report's `provenance.package_code_sha256` with downstream records.
7. A repair is strongest when inverse replay succeeds and repeated execution performs zero new edits.
8. For large JSONL, use streaming mode rather than loading the corpus in the agent context.
9. `--dry-run` is a simulation: require `committed_edits == 0`, inspect `would_commit_edits/proposed_edits`, and do not expect an output file.

## Modes

Single JSON:

```bash
json-consistency-repair --machine a.json -o a.repaired.json --report a.report.json
```

JSONL/NDJSON:

```bash
json-consistency-repair --machine events.jsonl -o events.repaired.jsonl --report events.report.json
```

Top-level array streaming:

```bash
json-consistency-repair --machine --stream --stream-format array big.json -o big.repaired.json --report big.report.json
```

Bundle:

```bash
json-consistency-repair --machine --bundle ./input-bundle -o ./repaired-bundle --report bundle.report.json
```

## Verification loop for an agent

After a successful mutation, run the repaired result again. A converged artifact should normally produce zero committed edits. Keep both reports if provenance matters.

The engine intentionally separates anomaly detection -> repairability -> exact proposed value -> mutation -> re-analysis -> repeated stability. Do not collapse those states in an agent wrapper.


## PASS009 typed constraint IR

Every completed analysis now exposes `typed_constraint_ir`. It separates a certified/observed constraint from the current object's satisfaction of that constraint and from the ability to reconstruct a missing/corrupt value. The three truth states are `TRUE`, `FALSE`, and `UNKNOWN`. A certain defect may therefore be `satisfaction_truth=FALSE` while `reconstruction_truth=UNKNOWN`; callers must never treat UNKNOWN as false, zero, absent, or permission to invent a value.

Single JSON materializes the full JSON node/constraint/terminal IR. Bundles preserve document-qualified local terminals plus cross-document constraints. Streaming uses `materialization_scope=BOUNDED_STREAM`: sampled terminals are materialized, while unsampled observed terminals remain explicitly counted rather than silently dropped.

## PASS010: interpret identifiability before asking for or forcing a repair

When a report contains `identifiability_summary` or `identifiability_registry`, use these semantics exactly:

- `UNIQUE`: exactly one reconstruction survives the currently certified finite constraints. Do not infer that the engine already committed it; inspect `committed_edits` / `proposed_edits`.
- `MULTIPLE`: several finite reconstructions remain. Do not choose one by preference. Read `minimal_missing_witness`; normally one independent selector is sufficient.
- `NONE`: the certified finite domains have empty intersection. Do not invent a value. At least one governing constraint/source must be corrected or withdrawn.
- `INSUFFICIENT`: the current evidence does not define a finite solution set, or legal mutation direction is not identified. Read `minimal_missing_witness` and request exactly that class of evidence when possible.

`OBSERVED_NULL` is not `UNOBSERVED`. `BOUNDED_UNMATERIALIZED` means the streaming report deliberately did not retain the full record in memory; it is not evidence that the record/value does not exist.


## PASS011: machine interpretation of minimal transfer

Read `cycles[*].minimal_transfer.status` before describing why an edit was or was not committed. `UNIQUE_EXACT_MINIMUM` and `UNIQUE_EXACT_MINIMUM_PARTITIONED` are positive solver decisions that were globally revalidated. `AMBIGUOUS_EXACT_MINIMUM` is an abstention, not a failure. `FRONTIER_TOO_LARGE` means exact minimality was not established inside the configured frontier. Do not rewrite either condition as “the repairer could not guess.”

## PASS013 conservation contract

Read conservation output in two stages: (1) is the conservation law certified/currently violated; (2) is a repair direction certified. `scalar_conservation_violation` and inferred `multiset_conservation_violation` are intentionally nonrepairable when the law is symmetric. Do not rewrite this as failure to guess. A nonzero residue can be certain while the responsible field remains unknown.

`--conservation-rules` supplies authoritative direction. Treat `target`/`target_side` as external governing material, not as evidence learned from the corrupted record. Local→aggregate sum/count bridges may obtain direction from the aggregate structural role; all commits still pass through the exact minimal-transfer solver and whole-object replay.


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


## PASS018 constraint bridge

Optional flags: `--constraints FILE.dsl`, `--json-schema FILE.json`, `--openapi FILE.json`, and `--openapi-schema NAME`. The DSL and schema/OpenAPI sources are authoritative inputs, not discovered truth. Exact linear systems abstain on ambiguous mutation direction. Local schema refs are bounded and acyclic; external/cyclic refs are refused.

## PASS020 graph/state/migration rules

Optional `--system-rules FILE.json` accepts authoritative `graph`, `state_machine`, and `migration` rules in single or bundle mode. Never invent a node, edge target, workflow state, or migration order. A graph repair requires a uniquely reconstructible topology object (for example one unique topological order or one uniquely determined reciprocal edge). An interior state repair requires exactly one state compatible with both adjacent transitions. Reachability is a planning witness, not permission to rewrite event history.

A `migration` rule compiles to one atomic `plan` candidate. Dependency cycles fail. Unordered non-commuting steps fail. Every accepted plan must replay inversely and survive cold replay/final certification. `/-` append inverses use the materialized numeric index. PASS024 enables streaming system-rule mutation against one complete validated record at a time. Treat a resulting whole-record journal entry as an atomic transaction; do not split its internal migration steps or infer corpus-wide reachability from one record.

## PASS021 machine discipline

Treat `moment_distribution_summary` as a typed bridge ledger, not as proof that any inferred statistical law is universal. Authoritative rules have `constraint_source=authoritative`; inferred weighted mean/variance relations remain scoped to observed repeated arrays. Never normalize a probability total to hide a member outside `[0,1]`. Never emit an approximate JSON number for a non-terminating exact rational.

## PASS022 machine discipline

Treat MODE I and MODE II as non-substitutable. MODE I packets are immutable snapshot evidence. MODE II may derive pairwise relations, consensus candidates and bounded composite relations, but never rewrite MODE I history. A federated conflict is debt, not a majority vote. A composite relation may inform causal reachability/root-cause analysis only when both source relations are directed. Q progress is sovereign only after rebuild when `(Q_ANSWER,Q_BOUNDARY,Q_RETURN)` decreases lexicographically. Network fixed point is not equivalent to problem closure.

## PASS023 source firewall

Never collapse `current`, `previous`, `defaults`, `development`, `heldout`, `reference`, and `authoritative` into one undifferentiated corpus. Preserve source IDs, digests, support and independence groups. `previous` is not a value oracle. Same-group replication is not heldout evidence. `GLOBAL_REFUTED` dominates development fit. Identity bridges translate field identity for analysis only; they do not silently mutate source documents.


## PASS024 streaming closure discipline

The exact disk registry is a bounded-memory spill mechanism, not an oracle. It preserves functional-group counts that would previously have overflowed the in-memory table, while record-local DSL/schema/system/moment/source bridges operate only on the complete current record. Do not turn `disk_backed_registry.exact=true` into a claim that the entire corpus is resident or that every possible global invariant has been solved.

For final reports, inspect `third_series_closure` only after inspecting its component evidence. `CLOSED` means those serialized checks agree: strong fixed point, cold zero-edit replay, independent certifier, provenance chain, federation fixed point, and the mode-specific inverse/multi-source or streaming exact-registry checks. If final certification is disabled, do not promote `OPEN` to closed by interpretation.

## PASS025 boundary discipline

Treat boundaries before candidates. Do not convert `bounds_of_bounds=CONFLICT` into a guessed patch. Do not choose one keyword projection independently when several numeric boundaries constrain the same value; use the combined boundary intersection. Do not invent an epsilon for `exclusiveMinimum`/`exclusiveMaximum` on a real-valued domain. A tied nearest `multipleOf` projection is ambiguous. A patch that creates any new authoritative boundary violation is forbidden even if it improves a larger downstream score.

## PASS026 parallel-route discipline

An exact tie is not permission to choose. If `parallel_route_count > 0`, treat the frozen input as immutable and inspect the RETURN_PROOF. A route may return only when every clone closes, exact terminal digests agree, remaining-issue witnesses agree, relation witnesses agree, and Q-return witnesses agree. The representative route is selected only after equivalence has been proved. `RETURN_PROOF_DIVERGENT` and route-frontier overflow mean abstention, not a request for a heuristic tie-break.

## PASS027 primary factorization contract

Read `primary_factorization.cycles[*].factorization` before interpreting solver partitioning. `primary_block_count` is not a JSON-container count. A block is a connected component of known concrete repair dependencies. `recomposition_proof.lossless = true`, `information_loss = 0`, and `cross_block_dependency_edge_count = 0` are mandatory for certified factorization. `UNRESOLVED_DEPENDENCY_GUARD` means the engine refused to infer independence from silence. `dynamic_refactorization.events` records split/merge/replacement invalidation between cycles; stale block IDs must not be treated as current objects.


## PASS028 proof-graph replay

A certified run now emits `proof_graph` (`json-consistency-repair.proof-graph.v1`) and `proof_graph_replay` (`json-consistency-repair.proof-graph-replay.v1`). The first is a canonical SHA-256 commitment to the complete serialized decision graph; the second restarts from the original sovereign input and must reproduce the exact graph hash and terminal output. Final certification fails if graph integrity or graph replay fails. Terminal cold replay remains separate and must still produce zero edits.

## PASS029 minimal-witness materialization discipline

An unresolved `minimal_missing_witness` may become a new terminal. The engine searches only the explicitly loaded, bounded source contract: source roles, identity bridges, explicit materialization hints, and authorized event projections. `MATERIALIZED_EXACT` means one exact admissible value survived the witness gates and was reinjected before the original problem was re-asked. `MULTIPLE_MATERIALIZATIONS_AMBIGUOUS` means abstain. `SOURCE_GATE` and `MATERIAL_GATE` mean evidence exists but is ineligible for that witness class. `ABSENT_CERTIFIED_WITHIN_SEARCH_CONTRACT` means only that the loaded bounded search contract was exhausted; it is never a claim of world-level absence. Previous/history sources remain observers unless explicitly authorized. Preserve the materialization certificate and its proof-graph nodes when accepting a repair.

## PASS030 scoped-authority discipline

Never interpret role=`authoritative` as unbounded permission. A mutation from multi-source evidence requires a valid `authority-proof.v1` for the exact target path, document, schema version, evaluation time and operation. Delegated authority must include the complete non-revoked chain. A reference/heldout source cannot self-promote by declaring an authority scope; only direct authority or an explicit manifest/delegation grant can authorize it.

For heldout reasoning, use `effective_evidence_group`, not only the user-supplied `independent_group`. Provenance parent/child copies and explicit correlations are dependent evidence. Do not count a heldout copy as a new confirmation of the relation it was derived from.


## PASS032 robust-envelope contract

Treat `robust_envelope` as a mutation firewall, not as an extra confidence score. A gated candidate is absent from optimization and its terminal is marked non-repairable for that snapshot. `CLOCK_EVALUATION_TIME_REQUIRED`, `STALE_OBSERVATION_GATE`, `FUTURE_SKEW_GATE`, `CROSS_REGIME_CANDIDATE_GATE`, `CANDIDATE_WITHIN_ADMISSIBLE_UNCERTAINTY`, and hysteresis gate states are semantic abstentions. Do not reinterpret them as missing confidence. Proof replay must reproduce the same robust-envelope certificate SHA.


## PASS032 canonical rectification packet
Treat `rectification_packet` as the stable machine-consumable index of the complete repair trajectory. Verify `packet_sha256`, every surface commitment, the independent `certifier_seal`, and `fourth_series_closure`. `NOT_EMITTED` is not equivalent to false, zero, absent, or impossible. Never accept a packet whose report-bound surface SHA differs from the serialized report section.

## PASS033 semantic-attribution discipline

Do not convert file integrity into semantic provenance. `HASH PASS` means bytes are intact; it does not prove a law was stated by the file. For every externally attributed configured law, require a PASS033 proof. Use `SOURCE_EXACT` only for an exact source fragment, `DERIVED_EXACT` only for a deterministic re-derivation from inclusion-proved fragments, and `USER_DECLARED` for caller-supplied rules with no external attribution. Never relabel an unverified external claim as inferred or authoritative. A semantic gate is an OPEN terminal, not permission to guess.

## PASS034 expression/action discipline

Treat configured expressions as typed exact laws, not as a license to evaluate arbitrary code. Preserve exact rational semantics and emit no approximate repair for a non-terminating JSON decimal. Do not choose one branch of an even-power/absolute-value/modulo inversion without a separate symmetry-breaking witness. For multiple unordered repairs, require the PASS034 finite-frontier algebra certificate. `CRITICAL_PAIR_OPEN` is an abstention gate. Do not generalize a finite-frontier confluence result to unknown future actions.

## PASS035 symmetry/canonicality discipline

Never break an exact repair tie by array index, route order, hash order, majority, or aesthetic preference when the candidates lie in one symmetry orbit. Preserve `SYMMETRY_BLOCKED_REPAIR` and report the emitted symmetry-breaking witness. Absence of a distinguishing fact is not permission to invent one.

Never infer that an array is unordered or that duplicates are irrelevant. Apply a semantic quotient only when an explicit rule survives PASS033 provenance gating. `unordered_array` preserves multiplicity. The stronger unique-set quotient requires the explicit duplicate-irrelevance flag. `RETURN_PROOF_QUOTIENT_EQUIVALENT` means concrete representations differ but are equal under that declared quotient while the remaining issue/relation/Q witnesses agree; it is not raw JSON equality.



## PASS036 control discipline

When `repair_controllability` is present, distinguish knowledge from actuation. `IDENTIFIABLE_BUT_UNREACHABLE` means the target repair is known but the currently authorized action surface cannot reach it; do not translate this into `UNKNOWN`, and do not weaken the permission/budget contract unless an external authority explicitly changes it. Respect `immutable`, allowed/denied operations, cumulative edit/cost budgets and precedence. A precedence cycle is an actual control obstruction.

Treat PASS033 as upstream of control policy: a policy attributed to an external source cannot influence mutations unless its semantic provenance is reproducible. For a committed action set, require a valid controllability certificate and final independent certification.


## PASS037 falsification discipline

Before using an inferred relation as a repair premise, inspect `relation_falsification`. Never reinterpret synthetic negative controls as observations. Treat `ACTIVE_REFUTED` and `NEGATIVE_CONTROL_INVARIANT` as hard mutation gates. Treat `ADVERSARIAL_SURVIVED` only as survival of the serialized bounded attacks, not universal validity. Treat `OBSERVED_ONLY` as unpromoted evidence. Authoritative contracts are `AUTHORITATIVE_CONTRACT` and are validated by provenance/authority layers instead of empirical falsification.

## PASS038 persistent-OPEN discipline

Treat `open_obligations` as durable executable state. `OPEN` is not absence and `NOT_FOUND` is not impossibility. A later source, rule, authority grant, symmetry breaker, rewrite join, control permission, boundary decision or provenance proof may wake the corresponding obligation. Do not wake unrelated obligations merely because a new file arrived; use the explicit `wake_tokens`/`dependency_tokens`.

For resumed runs, accept `INCREMENTAL_EQ_FULL` only when the targeted obligation transition equals the full fresh registry. `FULL_RECOMPUTE_REQUIRED` is a safety fallback, not an error to bypass. Opaque proof nodes are global by policy and must be invalidated. Exact node reuse is valid only when `incremental_equivalence` is bound to a successful full proof-graph replay. Never use incremental state to bypass the ordinary final certifier.

## PASS039 horizon discipline

Treat `horizon_naturality.comparison.ok` as a publication gate. `HORIZON_NATURAL` means the enlarged input left all unchanged old terminals invariant. `HORIZON_INVALIDATED_BY_WITNESS` is also admissible because every changed old terminal is tied to a newly crossing localized relation or explicit boundary witness. `HORIZON_DRIFT_UNEXPLAINED` and `FULL_RECOMPUTE_REQUIRED` are not permission to guess; rerun the full problem or supply the missing explicit witness.

Treat `distributed_consistency.ok=false` as a hard determinism failure. The same logical input may not resolve differently merely because shard count, worker count, record window or another distribution descriptor changed.


## PASS040 residual-information / blind-carrier discipline

Never convert a finite ambiguous carrier into a guessed selector. If there are `n` admissible finite candidates, preserve the exact selector-information lower bound; if the carrier cardinality is not established, preserve the unknown state and do not report zero bits. A target is reconstructable from a relation only after a blind trial in which that target was removed before inference. The post-hoc hidden commitment may verify the prediction but may not participate in generating it. Treat `BLIND_RECONSTRUCTION_MISMATCH` as a hard failure, and treat ambiguity or insufficient/unmaterialized carrier as explicit abstention states.

The fifth series is closed only by `fifth_series_closure`, which reconciles PASS033–PASS040 with independent certification, zero-edit cold replay, exact proof-graph replay, fixed-point evidence, horizon/distributed consistency, and PASS040 packet/proof bindings. Do not infer closure merely from the version number or from one PASS040 surface.

## PASS041 benchmark-limit discipline

Do not describe the sparse route as “lowering confidence to 0.60”. The ordinary 0.95 discovery gate remains. `SPARSE_OUTLIER_RECOVERY` is a separate bounded route requiring active falsification, repeated modal support, a strict margin, and non-coherent alternatives/residuals. A coherent second mode is an abstention case.

When a correct edit closes a frozen pre-existing terminal but exposes new subordinate diagnostics, measure the same frozen terminal first, then register and attack the newly exposed obligations. Do not let newly visible warning score retroactively erase genuine same-terminal descent.

Execution-profile rule: `execution_mode="fast"` is not a weaker synonym for certified repair. It must report `scan_scope = ALL_ANALYZERS`, restrict action to unique local cones, target deep falsification only to relations that can authorize a mutation, and keep `certification_gate = FAST_SCAN_ONLY`. Escalate to `execution_mode="full"` for global optimization and independent certification. Never upgrade a fast result to full-certification language.

The grammar frontier may normalize closed single-quoted strings, quote bare identifier keys, strip comments outside strings, close one unterminated string, and compose up to two bounded structural edits only when all minimum-cost strict-JSON routes converge. Conflicting duplicate keys remain an ambiguity.
