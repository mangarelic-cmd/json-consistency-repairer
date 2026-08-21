# Zenodo metadata — JSON Consistency Repair v0.41.0

## Resource type

Software

## Title

JSON Consistency Repair v0.41.0 — Conservative Causal JSON Rectification Engine

## Creator

Son D. Bolduc

## Version

0.41.0

## Publication date

2026-08-21

## License

MIT License

## GitHub repository

https://github.com/mangarelic-cmd/json-consistency-repairer

## Description — English

JSON Consistency Repair v0.41.0 is a conservative JSON rectification engine designed to recover determinable syntax damage and repair semantic inconsistencies only when the available evidence identifies a justified correction.

The software combines strict JSON parsing with bounded deterministic grammar and lexical recovery, exact constraint discovery, reversible minimal patches, strong fixed-point closure, provenance and authority controls, active falsification of discovered relations, symmetry-aware abstention, controllability and attainability checks, persistent OPEN obligations, targeted incremental recomputation, horizon/distributed-coherence checks, residual-information bounds, and blind-reconstruction verification.

It supports single JSON documents, multi-document bundles, JSONL/NDJSON, and bounded-memory top-level-array streaming. Cross-field and cross-record relations include functional, arithmetic, temporal, sequential, schema, enum, identity, reference, aggregate, conservation, graph/state and migration constraints. Conflicting duplicate keys are deliberately refused unless an authority resolves the ambiguity.

Version 0.41.0 introduces two execution profiles. `full` performs exhaustive analysis, global correction search, replay, proof-graph reconstruction and independent final certification. `fast` still scans all analyzer families but restricts expensive deep correction/falsification to unique local actionable cones; it explicitly reports `FAST_SCAN_ONLY` and does not masquerade as full certification.

The frozen PASS041 verification records 462/462 regression tests passed, 600/600 adversarial stress cases, 73/73 valid Draft 2020-12 public schemas, zero false mutations in the PASS041 stress campaign, successful fresh-source and fresh-wheel checks, and byte-for-byte reproducible wheel/source builds. The syntax contract records 13/13 determinable targeted corruptions repaired and 1/1 conflicting duplicate-key ambiguity correctly refused.

`PASS` is evidence/contract-relative: it means that no unresolved violation remains under the currently certified relations. It is not a claim of inaccessible external ground truth. Comparative benchmarks and raw validation artifacts are included so that performance and scope can be evaluated independently.

## Description — Français

JSON Consistency Repair v0.41.0 est un moteur conservateur de rectification JSON conçu pour récupérer les dommages syntaxiques déterminables et réparer les incohérences sémantiques uniquement lorsque les informations disponibles identifient une correction justifiée.

Le logiciel combine l'analyse JSON stricte avec une récupération grammaticale et lexicale déterministe et bornée, la découverte exacte de contraintes, des patchs minimaux réversibles, une fermeture à point fixe fort, des contrôles de provenance et d'autorité, la falsification active des relations découvertes, l'abstention en présence de symétries, les contrôles de contrôlabilité et d'atteignabilité, les objets OPEN persistants, le recalcul incrémental ciblé, les contrôles de cohérence d'horizon et distribuée, les bornes d'information résiduelle et la vérification par reconstruction aveugle.

Le moteur prend en charge les documents JSON uniques, les ensembles multi-documents, JSONL/NDJSON et le streaming borné en mémoire de tableaux JSON de premier niveau. Les relations interchamps et interenregistrements comprennent notamment les contraintes fonctionnelles, arithmétiques, temporelles, séquentielles, de schéma, d'énumération, d'identité, de référence, d'agrégation, de conservation, de graphe/état et de migration. Les clés dupliquées conflictuelles sont refusées lorsqu'aucune autorité ne permet de lever l'ambiguïté.

La version 0.41.0 fournit deux profils d'exécution. `full` effectue l'analyse exhaustive, la recherche globale de correction, le replay, la reconstruction du graphe de preuve et la certification finale indépendante. `fast` scanne toujours toutes les familles d'analyseurs, mais limite les recherches approfondies coûteuses aux cônes locaux dont la correction est unique et actionnable; il signale explicitement `FAST_SCAN_ONLY` et ne se présente jamais comme une certification complète.

La vérification figée PASS041 enregistre 462/462 tests de régression réussis, 600/600 cas de stress adversarial, 73/73 schémas publics Draft 2020-12 valides, zéro fausse mutation dans la campagne de stress PASS041, des vérifications réussies depuis une source extraite et un wheel fraîchement installé, ainsi que des builds wheel/source reproductibles octet pour octet. Le contrat syntaxique enregistre 13/13 corruptions ciblées déterminables réparées et 1/1 ambiguïté de clés dupliquées conflictuelles correctement refusée.

`PASS` reste relatif aux preuves et contrats actuellement certifiés : il signifie qu'aucune violation non résolue ne subsiste sous ces relations certifiées. Il ne constitue pas une affirmation de vérité externe inaccessible. Les benchmarks comparatifs et les artefacts bruts de validation sont fournis afin que la portée et les performances puissent être évaluées indépendamment.

## Keywords — English

JSON repair; JSON consistency; data repair; causal computing; semantic validation; constraint discovery; deterministic repair; reversible patching; data integrity; provenance; active falsification; schema validation; JSONL; streaming; software quality
