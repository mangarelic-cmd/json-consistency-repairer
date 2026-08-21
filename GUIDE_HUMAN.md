# Human guide — json-consistency-repair 0.41.0

`json-consistency-repair` is a conservative JSON rectification engine. It discovers stable relationships inside data, proposes minimal reversible edits, re-analyzes the physically updated data, and stops only after repeated stable cycles or an explicit unresolved state.

## Install

```bash
pip install json-consistency-repair
```

For the local first-candidate wheel:

```bash
pip install dist/json_consistency_repair-0.41.0-py3-none-any.whl
```

## Basic repair

```bash
json-consistency-repair input.json -o repaired.json --report repair.json
```

The report contains input/output semantic SHA-256 digests, cycles, accepted edits, remaining issues, discovered relations, a knowledge ledger, replay verification and package-code provenance.

## Dry run

```bash
json-consistency-repair --dry-run input.json -o repaired.json --report dry-run.json
```

Dry run executes the full repair simulation but publishes no repaired file. `committed_edits` is zero; `proposed_edits` and `would_commit_edits` describe what a real run would commit.

## What it will not do

The engine does not invent a missing value merely because a field is required, choose among equally plausible identities, force a dangling reference to a guessed target, or convert a security/resource overflow into partial evidence. Detection and repair are separate states.

## Large data

`.jsonl` and `.ndjson` are processed in bounded-memory streaming mode automatically. A top-level JSON array can be streamed explicitly:

```bash
json-consistency-repair --stream --stream-format array large.json -o repaired.json --report report.json
```

## Bundles

```bash
json-consistency-repair --bundle ./bundle -o ./bundle.repaired --report bundle-report.json
```

Cross-document references use a global identity registry. Publication is staged and reversible; ambiguous registry targets cause abstention.

## Machine integration

Use `--machine` for a stable one-object JSON protocol and documented exit codes. See `MACHINE_CONTRACT.md` and `GUIDE_LLM.md`.

## Provenance

```bash
json-consistency-repair --provenance
```

The installed package reports a SHA-256 over its shipped Python code. Release-level wheel/source hashes and Git/Zenodo bindings belong in `RELEASE_PROVENANCE.json`, because an artifact cannot safely contain its own hash.


## PASS009 typed constraint IR

Every completed analysis now exposes `typed_constraint_ir`. It separates a certified/observed constraint from the current object's satisfaction of that constraint and from the ability to reconstruct a missing/corrupt value. The three truth states are `TRUE`, `FALSE`, and `UNKNOWN`. A certain defect may therefore be `satisfaction_truth=FALSE` while `reconstruction_truth=UNKNOWN`; callers must never treat UNKNOWN as false, zero, absent, or permission to invent a value.

Single JSON materializes the full JSON node/constraint/terminal IR. Bundles preserve document-qualified local terminals plus cross-document constraints. Streaming uses `materialization_scope=BOUNDED_STREAM`: sampled terminals are materialized, while unsampled observed terminals remain explicitly counted rather than silently dropped.

## PASS010: why the tool may refuse four different ways

The report now tells you whether a bad field has one possible repair (`UNIQUE`), several (`MULTIPLE`), no value satisfying all currently certified finite constraints (`NONE`), or not enough information to define the solution set (`INSUFFICIENT`). For every non-unique case it also emits `minimal_missing_witness`, describing the smallest kind of extra information needed to proceed without guessing.


## PASS011: coupled corrections and exact ties

The repairer may now commit several mutually dependent edits in one transfer when the combined state is better even though no individual edit is sufficient. The report field `cycles[*].minimal_transfer` explains the objective, exact metric, selected patch set and any abstention. `AMBIGUOUS_EXACT_MINIMUM` means two or more distinct patch sets are exactly tied; `FRONTIER_TOO_LARGE` means the configured exact search bound was reached and the engine refuses to claim a global minimum.

## PASS013 conservation

Use automatic conservation discovery for repeated records with nested line/item arrays and parent totals/counts. The report exposes `conservation_summary` and conservation relations inside the typed constraint IR. A symmetric balance or multiset mismatch may be reported without a repair; this means the invariant is identified but the failing side is not.

For business/domain rules whose repair target is known independently, provide `--conservation-rules FILE`. Supported kinds are `aggregate_sum`, `aggregate_count`, `balance`, and `multiset_balance`. Do not add `target` or `target_side` merely to force a repair: it is an authoritative direction witness and should come from the domain contract.


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

## PASS020: graphes, workflows et migrations

Le programme peut maintenant reconnaître automatiquement un JSON de forme `nodes + edges` pour diagnostiquer identités dupliquées et références pendantes. Avec `--system-rules`, on peut déclarer qu'un graphe doit être acyclique, enraciné, réciproque ou accompagné d'un ordre topologique. Une réparation n'est faite que si la reconstruction est unique.

Les machines à états sont traitées de la même façon : un état corrompu entre deux voisins n'est remplacé que si un seul état légal relie les deux. Le rapport peut aussi fournir le chemin légal le plus court vers un état cible sans modifier l'historique.

Les migrations complexes (`move`, `replace`, `add`, etc.) peuvent être déclarées comme un plan ordonné unique. Le plan est atomique : une étape qui échoue annule les précédentes; un ordre non précisé entre opérations non commutatives entraîne une abstention. Le plan complet possède un inverse exact et passe le certificateur indépendant.

## PASS021 moments and units

Use `--moment-rules examples/pass021_moment_rules.json` when a document has authoritative weighted aggregates, variance/covariance sidecars, probability totals, uncertainty propagation, or canonical units. A unit conversion changes value+unit atomically. If the exact answer cannot be represented as a finite JSON decimal, the tool reports it and abstains instead of rounding.

## PASS022 federation

No extra option is normally required. The repairer runs its analyzers independently on the same frozen JSON state, then lets their typed outputs interact. If two analyzers independently support the same exact patch, the report records the consensus. If they disagree, the disagreement remains visible and no winner is fabricated. `federation_summary` shows pairwise/hyperobject activity; `dynamic_q_descent` shows what debt remains and whether a committed correction earned global rather than merely local progress.

## Multi-source context (PASS023)

Use `--sources-manifest` when the current JSON has trustworthy context in other files. Give every source a role. Use `defaults` only for fallback values, `previous` for historical comparison, `development`/`heldout` for relation validation, `authoritative` only for explicitly selected paths, and `event_log` only with an explicit projection. A heldout counterexample blocks promotion of a learned global rule.


## PASS024 streaming completion

Large JSONL/top-level-array repair now keeps exact determinant→target group registries on disk when the in-memory group cap is exceeded. The CLI also accepts the same record-local DSL/JSON Schema/OpenAPI, system migration, moment/unit, and source-manifest inputs in streaming mode. Multi-path changes are committed as one reversible record transaction. Bundle source manifests may be scoped to individual document names.

With final certification enabled, inspect `third_series_closure.status`. `CLOSED` summarizes successful fixed-point, cold replay, independent certification, provenance, federation and mode-specific replay/registry checks; the detailed component fields remain the evidence.

## PASS025 boundary repair

Use ordinary JSON Schema keywords for hard admissible domains. The report now separates a boundary contract from the defects it observes. Contradictory bounds are reported before any mutation. Inclusive numeric bounds and `multipleOf` can be repaired only when the nearest admissible point is unique. Exclusive real limits, string/array truncation, arbitrary duplicate deletion and branch-ambiguous `anyOf`/`oneOf` remain non-destructive diagnostics.

The compact DSL additionally accepts, for example:

```text
scope /rows
minimum score 0
maximum score 100
multipleOf score 5
maxLength name 64
pattern code "^[A-Z0-9_-]+$"
```

## PASS026 tied repairs

When two repairs are exactly tied, the program can now try both on private copies instead of choosing one. It only changes the real document if the independent routes later reconverge to the same certified result. If the routes lead to different valid outcomes, the file is left unchanged and the report records the divergence.

## PASS027 primary blocks

The solver no longer assumes that a JSON parent object is the natural unit of repair. It first builds dependency-primary blocks. Fields connected by an exact relation or overlapping atomic plan remain together; independently witnessed fields may be solved separately even when they share the same object. If independence is not witnessed, the old local carrier is deliberately kept intact. Inspect `primary_factorization.cycles[*].factorization` to see the block registry and its lossless recomposition proof.


## PASS028 proof-graph replay

A certified run now emits `proof_graph` (`json-consistency-repair.proof-graph.v1`) and `proof_graph_replay` (`json-consistency-repair.proof-graph-replay.v1`). The first is a canonical SHA-256 commitment to the complete serialized decision graph; the second restarts from the original sovereign input and must reproduce the exact graph hash and terminal output. Final certification fails if graph integrity or graph replay fails. Terminal cold replay remains separate and must still produce zero edits.

## PASS029 — automatic minimal-witness materialization

When the repairer can state exactly what missing witness would resolve an otherwise blocked repair, PASS029 turns that witness into a bounded search object. It can recover exact values from admissible authoritative/default/reference/heldout sources, identity bridges between schema versions, explicit materialization hints, or explicitly authorized event projections. The recovered witness is reinjected into the real repair loop and the original inconsistency is analyzed again. Conflicting materializations abstain; history is not silently promoted to authority; and a failed bounded search is reported only as absence within the loaded search contract. Single JSON, bundle and streaming record bridges expose the same witness-materialization evidence.

## PASS030 — scoped and delegated authority

A source marked authoritative is no longer automatically authoritative everywhere. It may be restricted by JSON path, bundle document, schema version, explicit evaluation time window, and operation (`add`, `replace`, `witness`, `project`, etc.). A delegated source must carry a valid non-revoked chain from an in-scope authority. If a scope does not match, the repairer records a gate and does not create the mutation candidate.

For independent evidence, inspect `evidence_poisoning_firewall`. Sources connected by explicit derivation provenance or manifest correlation are one effective evidence group even if their declared group names differ. Identical corpora are flagged; strict deduplication is opt-in because identical deterministic test sets can still be independently produced.


## Robust uncertainty, clock, regime and hysteresis envelopes

Use `--robust-envelope robust.json` to prevent a nominally valid patch from being committed outside its admissible operating envelope. The file is either a rule array or `{ "evaluation_time": "...", "rules": [...] }`. Supported rule kinds are `uncertainty_interval`, `clock_freshness`, `regime_guard`, and `hysteresis`. Clock rules require an explicit evaluation time; the program never substitutes the machine clock. Wildcard pointer patterns such as `/rows/*/x` may bind repeated structures.


## PASS032 — canonical rectification packet and fourth-series closure
Every certified run now emits one canonical `rectification_packet` that binds the input/output terminal, accepted and rejected decisions, remaining objects, boundaries, sources, authority, primary factorization, parallel routes, materialization, robust envelopes, Q descent, provenance, proof graph, replay, and fixed-point evidence. The packet receives an independent certifier seal. `fourth_series_closure.status = CLOSED` means PASS025 through PASS032 reconciled under the same serialized evidence.

## PASS033 — semantic claim provenance

A source label is not evidence. If a configured repair law claims external lineage, attach `claim_provenance` to the rule or declare the claim in the source manifest. `SOURCE_EXACT` requires `source_id` plus a JSON pointer whose exact fragment is the rule after provenance metadata is removed. `DERIVED_EXACT` requires a deterministic `template`; leaves of the form `{"$source":{"source_id":"...","pointer":"/..."}}` are reproduced from loaded sources and committed with Merkle inclusion proofs. `USER_DECLARED` is the correct class for an explicit operator supplied by the caller without pretending that it was extracted from another artifact.

A failed attribution disables the law before analysis and remains visible as `semantic_attribution_gate`. It does not mean the claimed source is globally false; it means the loaded bounded source contract does not reproduce the attribution exactly enough to authorize mutation.

## PASS034 — exact expressions and action confluence

Use `expr` for an authoritative exact formula, for example `scope /rows` followed by `expr total_rule: total = subtotal + tax`. A bare field on the left is treated as the declared output unless `solve_for` is explicitly configured. The engine never uses arbitrary Python evaluation. It solves only exact, uniquely invertible operator paths and abstains on sign symmetry, non-invertible operators or exact rationals that cannot be represented finitely by a JSON number.

Before an unordered set of multiple repairs is committed, PASS034 checks the frozen action frontier for termination and critical-pair joinability. A disjoint read/write footprint is a proof of commutation; overlapping actions must demonstrably rejoin or the subset remains OPEN.

## PASS035 — symmetry obstruction and explicit semantic quotient

PASS035 refuses to choose between repair targets that are indistinguishable under the frozen evidence. A tied route set may therefore end in `SYMMETRY_BLOCKED_REPAIR` with an orbit of interchangeable targets and a minimal symmetry-breaking witness. Supplying a stable id, authoritative selector, or explicit positional semantics can break the obstruction in a later run.

Do not treat ordinary arrays as sets. Semantic quotienting is opt-in: `unordered_array` ignores only order and preserves multiplicity; `unordered_unique_array` may ignore duplicates only when `duplicates_are_semantically_irrelevant=true` is stated explicitly. Externally attributed quotient rules pass through the PASS033 provenance firewall. A quotient-equivalent PASS026 return still requires exact agreement of all non-representational return witnesses.



## PASS036 — mutation controllability

Use `--controllability rules.json` when the JSON may be mathematically repairable but only some writes are legally or operationally allowed. Rules may mark paths immutable, restrict operations, impose `must_precede` ordering, or supply edit/cost budgets. `--require-explicit-mutation-permission` turns uncovered mutation paths into denied paths. Top-level `--max-control-edits` and `--max-control-cost` add global caps.

Example:

```json
[
  {"control_rule_id":"identity-lock","path":"/identity/**","immutable":true},
  {"control_rule_id":"status-write","path":"/status","allowed_operations":["replace"],"must_precede":["/published_at"]}
]
```

If the correct value is known but the active contract forbids the required mutation, the report records `IDENTIFIABLE_BUT_UNREACHABLE` instead of inventing a workaround. Budgets are cumulative over the run and are not silently reset by terminal cold replay. Externally attributed control policies must satisfy PASS033 provenance before they can block or permit a mutation.


## PASS037 — active falsification of inferred relations

PASS037 attempts to break inferred relations before allowing them to justify edits. It uses deterministic folds, ablation and bounded negative controls. `ACTIVE_REFUTED` and `NEGATIVE_CONTROL_INVARIANT` are mutation gates. `ADVERSARIAL_SURVIVED` means the relation survived the bounded attacks actually run; it is not a claim of universal truth. `OBSERVED_ONLY` means no safe bounded attack was available. Authoritative contracts are separated from empirical hypotheses, and synthetic controls never become training observations.

## PASS038 — persistent OPEN obligations and resume

When a repair cannot close, the report now contains `open_obligations` instead of requiring a human or automation layer to reconstruct the unresolved state from prose. Persist it directly:

```bash
json-consistency-repair input.json --report run.json --open-obligation-store open.json
```

On a later run, load either the registry or the complete prior report and state what changed:

```bash
json-consistency-repair input.json --incremental-prior-report run.json \
  --incremental-change-token source:* \
  --incremental-change-token path:/customer/id \
  --report resumed.json
```

Only matching OPEN objects are marked for wake-up. The dependency index is deliberately conservative: a proof node whose local dependencies cannot be extracted is treated as global and is invalidated, never silently reused. `INCREMENTAL_EQ_FULL` means the targeted OPEN-state transition exactly matches the fresh full registry. `FULL_RECOMPUTE_REQUIRED` means an indirect or unexplained change was detected. The repaired JSON is still published only after normal cold replay and full proof-graph replay.

## PASS039 — horizon extension and distributed consistency

A report now contains `horizon_naturality` and `distributed_consistency`. The first run registers a baseline snapshot. On a later run, pass the earlier report with `--incremental-prior-report prior-report.json`; PASS038 reuses its OPEN/proof state and PASS039 also imports the prior horizon snapshot. `--horizon-change-token TOKEN` may declare an explicit changed authority/source/schema token. If old unchanged input receives a different repaired terminal without a localized new witness, publication fails instead of accepting the drift.

For the same logical input, different distribution descriptors must yield the same output digest. `DISTRIBUTED_CONFLICT` means the result depends on partitioning and must not be published as a deterministic terminal.


## PASS040 — residual information and blind-carrier reconstruction

Inspect `residual_information` when a repair is blocked by symmetry or another finite candidate set. `RESIDUAL_INFORMATION_REQUIRED` means the engine can prove that a selector is still needed; `minimum_fixed_width_selector_bits` is exact for the declared finite carrier. `FINITE_BOUND_NOT_ESTABLISHED` means the carrier cardinality itself has not been materialized and must not be interpreted as a zero-bit result.

Inspect `blind_carrier_reconstruction` before treating an inferred functional relation as sufficient reconstruction evidence. The tested target is removed before prediction. `BLIND_RECONSTRUCTED_EXACT` is a real leave-one-target-out reconstruction on the loaded carrier; `RESIDUAL_INFORMATION_REQUIRED` means several outputs remain possible; `CARRIER_INSUFFICIENT` means no peer evidence can reconstruct that target; `BLIND_RECONSTRUCTION_MISMATCH` is a hard certification failure. Streaming may report `CARRIER_NOT_MATERIALIZED`, which is an explicit non-claim rather than a failure disguised as success.

`fifth_series_closure.status = CLOSED` means PASS033 through PASS040 have been reconciled under one serialized terminal/proof surface. It does not replace the individual evidence objects; inspect them when diagnosing a run.

## PASS041 — benchmark-driven minimal corrections

PASS041 fixes the measured three-missing non-monotonicity by prioritizing closure of frozen pre-existing terminals before severity from diagnostics that become visible only after a correct edit. It also adds a conservative sparse-outlier route for already-present wrong values. This route is intentionally unavailable for coherent competing modes: repeated alternatives can represent another regime rather than corruption.

`PASS` means no unresolved violation under the currently certified relations and declared evidence. It does not mean equality with unknown external ground truth.

### Fast versus full execution

Use `--mode fast` when latency matters. The fast profile scans all analyzer families but only opens expensive correction/falsification work around uniquely actionable local repair cones. It can repair local functional/arithmetic/syntactic defects, but its report is explicitly `FAST_SCAN_ONLY` and it does not claim independent full certification.

Use `--mode full` when the output must pass the complete global optimizer, cold replay, proof-graph replay and independent certifier. A fast result can always be escalated by rerunning the same input/output state with `--mode full`.

PASS041's bounded syntax frontier now closes all 13 determinable cases in the 14-case adversarial syntax corpus; the fourteenth case, conflicting duplicate keys, is correctly refused as ambiguous. Single quotes, unquoted identifier keys and JS-style comments are handled only through bounded lexical adapters whose result must still parse as strict JSON.
