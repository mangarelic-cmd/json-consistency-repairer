# Machine contract v1

Contract identifier: `json-consistency-repair.machine.v1`  
Report contract: `json-consistency-repair.report.v1`  
Schema version: `1.0`

## Success/completion envelope

```json
{
  "contract": "json-consistency-repair.machine.v1",
  "schema_version": "1.0",
  "ok": true,
  "status": "PASS",
  "exit_code": 0,
  "engine": {
    "name": "json-consistency-repair",
    "version": "0.41.0",
    "package_code_sha256": "..."
  },
  "mode": "single",
  "result": {"...": "..."},
  "error": null
}
```

`ok` is true only for `PASS`. A completed but unresolved analysis is deliberately not collapsed into success.

## Exit codes

| Code | Status | Meaning |
|---:|---|---|
| 0 | PASS | Stable, no remaining reported issues |
| 10 | STABLE_WITH_REPORTED_ISSUES | Stable but unresolved issues remain |
| 11 | OPEN_REPAIRABLE | Cycle budget ended before strong closure |
| 20 | INPUT_ERROR | Invalid/ambiguous input contract |
| 21 | SECURITY_REFUSAL | Security/resource contract refused input |
| 30 | IO_ERROR | Filesystem/read/write error |
| 70 | INTERNAL_ERROR | Internal/replay invariant failure |

## Determinism

With `--machine`, serialized JSON uses sorted keys, UTF-8 text semantics, compact separators and rejects non-finite numbers. A classified error emits one JSON object to stderr. A completed run emits one JSON object to stdout.

## Report provenance

Every PASS008 report includes:

- package name/version;
- `package_code_sha256`, a digest of the shipped `.py` modules;
- report contract/schema version;
- status and corresponding machine exit code.

A release manifest binds the code digest to wheel/source hashes, Git commit and Zenodo DOI when those external identities exist.

## Dry-run semantics

`--dry-run` executes the complete in-memory convergence but performs no external publication. Machine results expose `dry_run: true`, `committed_edits: 0`, and `would_commit_edits`. The detailed report additionally exposes `proposed_edits` (single JSON) or `proposed_patch_set` (bundle). The reported output digest is the predicted repaired semantic digest, not a claim that an output file was written.


## PASS009 typed constraint IR

Every completed analysis now exposes `typed_constraint_ir`. It separates a certified/observed constraint from the current object's satisfaction of that constraint and from the ability to reconstruct a missing/corrupt value. The three truth states are `TRUE`, `FALSE`, and `UNKNOWN`. A certain defect may therefore be `satisfaction_truth=FALSE` while `reconstruction_truth=UNKNOWN`; callers must never treat UNKNOWN as false, zero, absent, or permission to invent a value.

Single JSON materializes the full JSON node/constraint/terminal IR. Bundles preserve document-qualified local terminals plus cross-document constraints. Streaming uses `materialization_scope=BOUNDED_STREAM`: sampled terminals are materialized, while unsampled observed terminals remain explicitly counted rather than silently dropped.

## Typed Constraint IR v2 — observability / identifiability

PASS010 introduces `json-consistency-repair.typed-constraint-ir.v2` and retains the v1 schema for historical readers.

Machine consumers MUST treat these identifiability states as disjoint:

- `UNIQUE`: one admissible value in the certified finite intersection;
- `MULTIPLE`: two or more admissible values/targets;
- `NONE`: empty certified finite intersection;
- `INSUFFICIENT`: no finite solution set can yet be derived, or legal mutation direction lacks an independent witness.

Machine consumers MUST NOT collapse `NONE`, `MULTIPLE`, and `INSUFFICIENT` into a generic false value. For non-unique states, use `minimal_missing_witness.kind` and `cardinality` as the smallest requested evidence class, not as permission to invent evidence.

Observability states are `OBSERVED_VALUE`, `OBSERVED_NULL`, `UNOBSERVED`, and `BOUNDED_UNMATERIALIZED`.


## Minimal-transfer contract v1

Single-object cycle reports expose `minimal_transfer.solver_contract = "json-consistency-repair.minimal-transfer.v1"`. Bundle cycles expose `cross_document_minimal_transfer.solver_contract = "json-consistency-repair.bundle-minimal-transfer.v1"`. Streaming cycle application statistics expose `json-consistency-repair.streaming-minimal-transfer.v1`. Exact tie and exact-frontier overflow are explicit abstention states.

## PASS013 conservation fields

Reports may include `conservation_summary` with `relation_count`, `violation_count`, and repairability counts. Typed constraint relations may use `aggregate_sum`, `aggregate_count`, `scalar_conservation_balance`, `multiset_conservation`, and authoritative variants. Conservation issues carry exact `residue` metadata when applicable. `--conservation-rules` accepts a JSON array or `{ "rules": [...] }`; invalid rule files are classified as `INPUT_ERROR` rather than internal failures.


## PASS016 final certification fields

Successful reports expose `strong_fixed_point`, `cold_replay`, `provenance_chain`, `final_certification` and `certification_gate`. With final certification enabled, a publishable PASS requires `certification_gate=PASS`. The independent certifier exits 0 on certified evidence and 2 on rejection. A SHA-256 chain establishes integrity/tamper evidence only; it does not turn a discovered relation into a fact about the outside world.


## PASS018 constraint bridge

Optional flags: `--constraints FILE.dsl`, `--json-schema FILE.json`, `--openapi FILE.json`, and `--openapi-schema NAME`. The DSL and schema/OpenAPI sources are authoritative inputs, not discovered truth. Exact linear systems abstain on ambiguous mutation direction. Local schema refs are bounded and acyclic; external/cyclic refs are refused.

## PASS020 machine surfaces

Single-document reports expose `system_graph_summary.contract = json-consistency-repair.system-graph-state.v1`. System rules are optional authoritative inputs with kinds `graph`, `state_machine`, and `migration`. New issue codes include `dangling_edge`, `graph_cycle`, `topological_order_violation`, `topological_order_ambiguous`, `invalid_transition_state`, `target_state_unreachable`, `migration_dependency_error`, `migration_order_underspecified`, `migration_precondition_failed`, and `migration_available`.

`operation=plan` is an atomic exact patch whose `metadata.steps` are applied in declared dependency order and whose `metadata.inverse_steps` restores the source. A plan has root-level source/target semantic digests as `old_value`/`new_value`. `plan` is never partially committed. PASS024 also permits system-rule mutation in streaming mode. The complete current record is the system-plan carrier; multi-path/root plans are serialized as one atomic `record_replace` journal transaction and must replay inversely.

## PASS021 moment/distribution contract

Single and bundle reports expose `moment_distribution_summary` (`json-consistency-repair.moment-distribution-summary.v1`). Streaming exposes the same contract in bounded mode. Rule schema: `schemas/moment-rules-v1.schema.json`. Supported authoritative kinds: `weighted_mean`, `weighted_sum`, `variance`, `covariance`, `probability_total`, `uncertainty_variance`, `unit_normalize`.

## PASS022 federation/Q contract

Single-object reports include `federation_summary` (`json-consistency-repair.c189-federation-summary.v1`) and `dynamic_q_descent` (`json-consistency-repair.dynamic-q-descent.v1`). The final federation packet follows `json-consistency-repair.c189-federation.v1`. MODE I has an independence barrier; MODE II uses bounded pairwise objects, on-demand hyperobjects, semantic relation de-duplication and a quiet-cycle fixed point. Bundle mode exposes per-document packets. Streaming mode is explicitly `BOUNDED_STREAM`; missing in-memory terminals are not certified absent.

## PASS023 machine contracts

Reports may include `multisource_assimilation` with `json-consistency-repair.multisource-assimilation.v1`, a `source_registry`, an `identity_registry`, and `relation_lifecycle`. Lifecycle states include `DISCOVERED`, `DEPENDENT_REPLICATION_ONLY`, `HELDOUT_CONFIRMED`, `PORTABLE`, `GLOBAL_REFUTED`, and `DEVELOPMENT_CONFLICT`.


## PASS024 machine contracts

Streaming reports expose `disk_backed_registry` with contract `json-consistency-repair.disk-registry.v1` and `record_bridge_execution` with contract `json-consistency-repair.streaming-record-bridge.v1`. `disk_backed_registry.exact=true` means the functional relation registry did not discard overflow groups; it does not mean arbitrary global JSON properties were materialized.

A final-certified report in any mode exposes `third_series_closure` with contract `json-consistency-repair.third-series-closure.v1`. `status=CLOSED` requires the mode-specific conjunction of strong fixed point, zero-edit cold replay, independent certifier, provenance-chain verification, federation fixed point, and inverse/multi-source or streaming registry/record-bridge checks. With final certification disabled the closure remains `OPEN`.

In streaming PASS024 mode, record-local DSL/schema/system/moment/source repairs may be represented in the patch journal as a single whole-record transaction. This is deliberate atomicity: the inner plan can contain several exact path operations while the public streaming transaction count is one record replacement.

## PASS025 boundary contracts

Reports may contain:

- `boundary_calculus.contract = json-consistency-repair.boundary-calculus.v1`
- `boundary_calculus.final.registry.contract = json-consistency-repair.boundary-registry.v1` in single mode;
- per-document registries in bundle mode;
- a record-carrier registry in streaming mode.

A `bounds_of_bounds.status = CONFLICT` blocks every mutation under that authoritative contract set. A candidate rejected by `boundary_firewall` must not be reintroduced by minimal-transfer scoring, causal dominance, federation, or a later cycle unless the authoritative boundary material itself changes.

`numeric_boundary_intersection` and DSL combined numeric projections are legal only when the minimum absolute-distance admissible value exists and is unique. No epsilon is invented for open real bounds, and tied nearest multiples are abstentions.

## PASS026 parallel route contracts

Single reports expose `parallel_exact_minimum_routes.contract = "json-consistency-repair.parallel-exact-routes.v1"` and RETURN_PROOF objects with contract `json-consistency-repair.return-proof.v1`. A committed parallel return must have `status = RETURN_PROOF_EQUIVALENT`, `ok = true`, a stable `proof_sha256`, and a selected route chosen only after exact terminal/witness equivalence. Divergent/open/overflow route sets must not mutate MAIN.

## PASS027 primary factorization contracts

The active minimal-transfer partition is `primary_relation_connected_components`. Serialized single-object reports expose `json-consistency-repair.primary-factorization.v1` with a cryptographic `factorization_sha256`, explicit `blocks`, `primary_relation_registry`, `coupling_edges`, and `recomposition_proof`. Final certification rejects a malformed factorization certificate. Dynamic changes use `json-consistency-repair.dynamic-refactorization.v1`; an invalidated block identity has no authority in later cycles.


## PASS028 proof-graph replay

A certified run now emits `proof_graph` (`json-consistency-repair.proof-graph.v1`) and `proof_graph_replay` (`json-consistency-repair.proof-graph-replay.v1`). The first is a canonical SHA-256 commitment to the complete serialized decision graph; the second restarts from the original sovereign input and must reproduce the exact graph hash and terminal output. Final certification fails if graph integrity or graph replay fails. Terminal cold replay remains separate and must still produce zero edits.

## PASS029 witness-materialization fields

Reports may include `witness_materialization` using contract `json-consistency-repair.witness-materialization.v1`. Terminal statuses include `MATERIALIZED_EXACT`, `MULTIPLE_MATERIALIZATIONS_AMBIGUOUS`, `SOURCE_GATE`, `MATERIAL_GATE`, and `ABSENT_CERTIFIED_WITHIN_SEARCH_CONTRACT`. The last status is scoped to the explicitly loaded bounded search contract and must never be interpreted as global absence. Final certification verifies materialization certificate digests and the proof graph commits the corresponding missing-witness terminals.

## PASS030 scoped-authority fields

Single-object reports expose `scoped_authority` (`json-consistency-repair.scoped-authority.v1`) and `evidence_poisoning_firewall` (`json-consistency-repair.evidence-poisoning-firewall.v1`). Authority proofs use `json-consistency-repair.authority-proof.v1` and include the source, target path, operation, document, schema version, evaluation time, matched scope, delegation chain, effective evidence group, authority-registry SHA-256 and proof SHA-256. Bundle mode exposes document-scoped registries; streaming exposes bounded registry samples from the exact per-record bridge.

A certifier must reject a tampered registry/proof hash or a proof that cannot be re-evaluated to the same authorization result.


## PASS031 robust envelope

Machine reports expose `robust_envelope` with contract `json-consistency-repair.robust-envelope.v1`. Serialized firewall certificates use `json-consistency-repair.robust-envelope-firewall.v1` and contain deterministic rule hashes, candidate decision hashes, explicit gate reasons, and a certificate SHA-256. Time-dependent rules require serialized `evaluation_time`; wall-clock time is never an implicit input.


## PASS032 additions
Certified outputs include `rectification_packet` (`json-consistency-repair.rectification-packet.v1`) and `fourth_series_closure` (`json-consistency-repair.fourth-series-closure.v1`). Consumers MUST verify packet surface hashes and MUST preserve the tri-state surface semantics `PRESENT | EXPLICIT_NULL | NOT_EMITTED`; `NOT_EMITTED` MUST NOT be rewritten as false, zero, absent, or impossible.

## PASS033 additions

`semantic_claim_provenance` is evaluated before the ordinary analyzer federation. Its registry contract is `json-consistency-repair.semantic-claim-provenance.v1`; individual claims use `json-consistency-repair.semantic-claim-proof.v1`; exact fragments use `json-consistency-repair.json-merkle-inclusion.v1`; the mutation firewall uses `json-consistency-repair.semantic-claim-provenance-firewall.v1`.

Required semantics:

- source-file hash equality is integrity only and cannot establish semantic attribution;
- `SOURCE_EXACT` requires the full cleaned claim payload to equal the inclusion-proved source fragment;
- `DERIVED_EXACT` requires a deterministic proof-carried template to re-render the full claim from inclusion-proved fragments;
- `USER_DECLARED` cannot carry source pointers or a derived template;
- `INFERRED` is reserved for internally discovered relations and cannot be self-asserted by an external rule;
- an externally attributed rule without a reproducible proof is removed before analysis and cannot indirectly affect boundaries, relations, candidates, or minimal-transfer optimization;
- the final independent certifier re-verifies all proof payloads against the committed source roots;
- `NOT_FOUND` or `UNVERIFIED_ATTRIBUTION` is not world-level falsity.

`fifth_series_progress` uses `json-consistency-repair.fifth-series-progress.v1`. PASS033 leaves this series `IN_PROGRESS`; only PASS040 may emit a fifth-series closure certificate.

## PASS034 additions

`typed_expression_ir` uses `json-consistency-repair.typed-expression-ir.v1`. Configured `expression` rules compile to `json-consistency-repair.typed-expression-rule.v1`; evaluation is non-executable exact IR, not Python `eval`. Exact inversions that are non-unique or not finitely representable as a JSON number are OPEN and do not create candidates.

`repair_path_algebra` uses `json-consistency-repair.repair-path-algebra.v1`. Each action is a `typed-repair-action.v1`; overlapping actions are audited through `critical-pair.v1`. The termination proof is scoped to the frozen finite one-shot candidate frontier. `CONFLUENT_ON_CURRENT_FINITE_FRONTIER` means every serialized local critical pair is joinable in that finite system; it is not a claim about an unbounded future rewrite system. Unordered multi-action subsets with an open pair are inadmissible. Ordered RETURN_PROOF routes are governed by PASS026 instead.

## PASS035 additions

`semantic_quotient` uses `json-consistency-repair.semantic-quotient.v1`. Quotient rules are explicit configuration and are subject to PASS033 semantic-provenance projection before use. `unordered_array` may remove ordering only; it MUST preserve multiplicity. Duplicate collapse is legal only for `unordered_unique_array` with `duplicates_are_semantically_irrelevant=true`. No quotient semantics may be inferred automatically from an array's shape or repeated values.

`symmetry_obstruction` uses `json-consistency-repair.symmetry-obstruction.v1`; report summaries use `json-consistency-repair.symmetry-canonicality.v1`. `SYMMETRY_BLOCKED_REPAIR` is a non-mutation terminal indicating that tied exact-minimum routes select members of an indistinguishable orbit and no certified symmetry breaker exists. `minimal_symmetry_breakers` is a scoped witness requirement, not a claim that the listed examples are present.

PASS026 `json-consistency-repair.return-proof.v1` additionally permits `RETURN_PROOF_QUOTIENT_EQUIVALENT`. Such a proof MUST contain a valid explicit semantic-quotient certificate and MUST still prove equality of serialized remaining-issue, relation and Q witnesses. A deterministic representative route may be selected only after that quotient-equivalence proof succeeds. The independent certifier re-verifies all PASS035 certificates.



## PASS036 additions

`repair_controllability` uses `json-consistency-repair.repair-controllability-summary.v1`. Per-frontier admission certificates use `json-consistency-repair.controllability-firewall.v1`; selected action plans use `json-consistency-repair.repair-controllability.v1`.

Required semantics:

- an identifiable repair forbidden by the active mutation contract is `IDENTIFIABLE_BUT_UNREACHABLE`, not `UNKNOWN`;
- `require_explicit_mutation_permission=true` denies uncovered write paths;
- immutable and operation-denied rules are hard mutation gates;
- edit/cost budgets are cumulative across committed cycles and MUST NOT be reset for repaired-terminal cold replay;
- proof-graph replay from the sovereign original input uses the original run budget state;
- `must_precede` constraints compile to an order only if the precedence graph is acyclic;
- every internal step of an atomic plan must be permitted;
- externally attributed control rules remain subject to PASS033 semantic-claim provenance;
- the independent certifier MUST verify the hashes and internal consistency of all emitted control certificates.


## PASS037 additions

- `relation_falsification.contract = json-consistency-repair.relation-falsification-summary.v1`.
- Each certificate is `json-consistency-repair.relation-falsification.v1` and commits per-relation attack decisions.
- Blocking states are `ACTIVE_REFUTED` and `NEGATIVE_CONTROL_INVARIANT`.
- `ADVERSARIAL_SURVIVED` is bounded-attack survival only.
- `OBSERVED_ONLY` is not portable promotion.
- Synthetic controls are test objects and never observations.
- The independent certifier verifies every serialized falsification certificate, and PASS028/PASS032 bind the surface into the proof graph and rectification packet.

## PASS038 additions

- `open_obligations.contract = json-consistency-repair.open-obligation-registry.v1`.
- `incremental_recompute.contract = json-consistency-repair.incremental-recompute.v1`.
- `incremental_equivalence.contract = json-consistency-repair.incremental-equivalence.v1`.
- Every OPEN object has a stable `obligation_id`, typed `kind`, target paths, wake tokens, dependency tokens and source-detail commitment.
- Registries are integrity-checked before atomic persistence or resume.
- Only explicit token intersections may wake prior obligations.
- Proof nodes with no extractable local dependency are assigned `global:*` and conservatively invalidated.
- `INCREMENTAL_EQ_FULL` certifies equality of the targeted OPEN-obligation transition with the fresh full registry.
- `INCREMENTAL_PROOF_EQ_FULL` may reuse prior proof nodes only when exact node identities survive conservative invalidation and the new full proof-graph replay succeeds.
- Any unexplained obligation or proof-node drift yields `FULL_RECOMPUTE_REQUIRED`.
- Incremental evidence never bypasses cold replay, proof-graph replay, rectification-packet binding or the independent final certifier.

## PASS039 additions

- `horizon_naturality.contract = json-consistency-repair.horizon-naturality.v1`.
- `horizon_naturality.snapshot.contract = json-consistency-repair.horizon-snapshot.v1`.
- `distributed_consistency.contract = json-consistency-repair.distributed-consistency.v1`.
- Complete JSON carriers hash every bounded input/output node; incomplete carriers declare that locality explicitly.
- Unchanged old input locations are horizon-stability obligations. Their terminal values may change only with an emitted boundary-crossing witness.
- Relation witnesses bind target pattern, changed dependency path, relation ID and relation hash.
- Explicit witness tokens must be part of the declared change-token set.
- Unexplained old-scope drift is non-certifiable and requests full recomputation.
- Identical input digests must produce identical output digests across distribution descriptors.
- PASS039 evidence is independently recomputed by the final certifier and committed into the proof graph and rectification packet.


## PASS040 machine surfaces

A certified PASS040 report exposes `residual_information` (`json-consistency-repair.residual-information-summary.v1`) and `blind_carrier_reconstruction` (`json-consistency-repair.blind-carrier-reconstruction.v1`). Finite residual selector bounds use `json-consistency-repair.residual-information-bound.v1`. The independent certifier check is `residual_information_blind_carrier`.

Blind reconstruction is valid only if the trial record was redacted before prediction. A serialized trial with `BLIND_RECONSTRUCTION_MISMATCH` is invalid even if its outer digest is resealed. Unknown/unmaterialized candidate spaces may not assert a finite selector-bit count. PASS040 surfaces must also appear in `rectification_packet` and as `RESIDUAL_INFORMATION_BOUND` / `BLIND_CARRIER_RECONSTRUCTION` nodes in the proof graph.

`fifth_series_progress.status = CLOSED` requires 8/8 layers. `fifth_series_closure` uses contract `json-consistency-repair.fifth-series-closure.v1` and is the reconciliation surface for PASS033–PASS040; it is valid only when all serialized component checks close.

## PASS041 maintenance surfaces

PASS041 preserves the report contract version and status names. `report_contract.truth_scope` is `EVIDENCE_AND_DECLARED_CONTRACT_RELATIVE`; `report_contract.pass_semantics` explicitly states that PASS is not external ground-truth proof. Minimal-transfer certificates publish objective order `hard_errors`, `surviving_preexisting_terminals`, `severity_score`, `repairable_terminals`. Relations recovered through the bounded fallback expose `recovery_route = SPARSE_OUTLIER_RECOVERY` and a sparse-outlier certificate.

### PASS041 execution profiles

`RepairConfig.execution_mode` accepts `full` or `fast`. `full` preserves the complete existing report/certification authority. `fast` publishes `report_contract.name = json-consistency-repair.fast-scan-report.v1`, `report_contract.assurance = FAST_SCAN_ONLY`, `execution_profile.scan_scope = ALL_ANALYZERS`, `execution_profile.action_scope = UNIQUE_LOCAL_REPAIR_CONES_ONLY`, `final_certification.status = NOT_RUN_FAST_MODE`, and `certification_gate = FAST_SCAN_ONLY`. A consumer MUST NOT treat a fast report as equivalent to a full certified report.

Fast mode may target active relation falsification to relations that back a concrete candidate; unrelated relations remain observed but not deep-falsified in that pass. This targeted call-avoidance is legal only because fast mode never claims full certification. Applied edits still carry exact forward/inverse replay evidence.
