# JSON Consistency Repair v0.40.0 — Benchmark de limites V1

Date: 2026-08-20  
Objet: mesurer ce que le moteur fait réellement, y compris ses échecs, seuils, abstentions, faux négatifs et coûts d'exécution. Ce document n'est pas un benchmark promotionnel.

## 1. Conclusion courte

Le moteur est nettement plus qu'un réparateur syntaxique JSON. Sa force réelle est la reconstruction conservatrice de structure et de valeurs quand un porteur causal/relationnel suffisant existe, avec abstention explicite lorsque l'information est insuffisante ou contradictoire.

Mais le benchmark met aussi en évidence une limite centrale: **avec les seuils par défaut, la découverte automatique de valeurs déjà présentes mais fausses perd très vite son autorité lorsque les erreurs contaminent la relation elle-même**. Sur les deux familles isolées testées (mapping fonctionnel et relation arithmétique), 2 valeurs fausses sur 40 (5 %) sont réparées exactement; 3 sur 40 (7,5 %) suffisent à faire disparaître la relation certifiée et le moteur peut alors retourner `PASS` sans corriger les valeurs fausses. `PASS` signifie donc « aucune violation restante selon les relations actuellement certifiées », et non « égalité garantie avec une vérité externe inconnue ».

À l'inverse, les valeurs **manquantes** ne contaminent pas la relation de la même façon. Le moteur peut reconstruire des taux de manque très élevés tant qu'il subsiste le support minimal nécessaire: dans la campagne isolée, une relation arithmétique `a+b=total` a reconstruit 36 valeurs manquantes sur 40 avec seulement 4 lignes complètes; elle échoue à 37 manquantes car il ne reste plus que 3 témoins alors que `min_support=4`. Pour une relation fonctionnelle à 5 clés, 3 témoins propres par clé suffisent: 25 valeurs manquantes sur 40 ont été reconstruites; avec seulement 2 témoins par clé, la reconstruction tombe à zéro.

Donc le produit est actuellement très fort comme **reconstructeur de données absentes sous contrainte**, et beaucoup plus conservateur comme **détecteur autonome de corruption déjà matérialisée**.

## 2. Environnement et artefact testé

- `json-consistency-repair` 0.40.0
- Python 3.13.5
- AMD EPYC 9V74, 5 vCPU disponibles
- mémoire conteneur: 5.9 GiB
- SHA-256 source ZIP: `698c070e65e7ef1b266b124d59e057a726a778f4b2561056263f4a20facc197e`
- SHA-256 wheel: `de544045dfdf6a4285da780206e07826af29440681ec2b6ae9c749db21c4e214`
- RSS maximal après simple import du package: environ 114 520 KiB dans cet environnement

Les mesures de temps sont spécifiques à cette machine et ne doivent pas être transposées directement à une autre machine.

## 3. Reconstruction automatique: valeurs fausses

Campagne isolée, 40 lignes, relation nette sans bruit parasite. Configuration par défaut (`relation_confidence=0.95`, `arithmetic_confidence=0.95`).

| Famille | Valeurs fausses | Taux | Réparées exactement | Faux changements sur lignes propres | Statut final |
|---|---:|---:|---:|---:|---|
| Fonctionnelle | 1/40 | 2,5 % | 1/1 | 0 | PASS |
| Fonctionnelle | 2/40 | 5 % | 2/2 | 0 | PASS |
| Fonctionnelle | 3/40 | 7,5 % | 0/3 | 0 | PASS |
| Fonctionnelle | 4/40 | 10 % | 0/4 | 0 | PASS |
| Fonctionnelle | 8/40 | 20 % | 0/8 | 0 | PASS |
| Fonctionnelle | 16/40 | 40 % | 0/16 | 0 | PASS |
| Arithmétique | 1/40 | 2,5 % | 1/1 | 0 | PASS |
| Arithmétique | 2/40 | 5 % | 2/2 | 0 | PASS |
| Arithmétique | 3/40 | 7,5 % | 0/3 | 0 | PASS |
| Arithmétique | 4/40 | 10 % | 0/4 | 0 | PASS |
| Arithmétique | 8/40 | 20 % | 0/8 | 0 | PASS |
| Arithmétique | 16/40 | 40 % | 0/16 | 0 | PASS |

Le seuil observé correspond directement au seuil de confiance de 0,95: 38/40 observations propres donnent 0,95; 37/40 donnent 0,925. Une fois sous le seuil, la relation empirique n'est plus autorisée à corriger les données.

### Conséquence importante

Un `PASS` peut être obtenu sur un document contenant encore des erreurs de vérité externe si ces erreurs ont détruit le support permettant de découvrir la relation qui les aurait révélées. Ce n'est pas une fausse mutation; c'est un **faux négatif épistémique**. Pour un produit public, la sémantique devrait être formulée explicitement comme « certified relative to available evidence/contracts ».

## 4. Reconstruction automatique: valeurs manquantes

Même corpus de 40 lignes.

### Relation arithmétique

`a+b=total`, avec `min_support=4`.

| Lignes complètes restantes | `total` manquants | Réparés exactement | Statut |
|---:|---:|---:|---|
| 4 | 36/40 | 36/36 | PASS |
| 3 | 37/40 | 0/37 | PASS |

C'est une frontière nette de support: quatre observations propres suffisent à identifier la relation dans ce corpus; trois ne suffisent plus.

### Relation fonctionnelle

5 clés, 8 lignes par clé, mapping exact `k -> v`, `min_group_support=3`.

| Témoins propres par clé | Valeurs `v` manquantes | Réparées exactement | Statut |
|---:|---:|---:|---|
| 3 | 25/40 | 25/25 | PASS |
| 2 | 30/40 | 0/30 | PASS |

Le plafond n'est donc pas un pourcentage global: il dépend de la distribution du support par groupe.

### Anomalie observée à investiguer

Dans les campagnes de 40 lignes, **3 valeurs manquantes (7,5 %) ont parfois produit `STABLE_WITH_REPORTED_ISSUES` et zéro correction alors que 4, 6, 8, 12 ou 16 valeurs manquantes étaient ensuite toutes réparées**. Sur le témoin inspecté, les candidats existaient mais le solveur minimal retournait `NO_IMPROVING_TRANSFER`.

Ce comportement non monotone n'est pas une limite théorique voulue; c'est un point d'ingénierie à auditer. Il peut résulter d'une interaction entre diagnostics de forme, registres de terminaux et objectif de transfert minimal. Il faut le traiter comme un défaut potentiel avant de présenter le moteur comme monotone en quantité d'évidence.

## 5. Réglage des seuils: puissance contre conservatisme

En abaissant volontairement la confiance pour correspondre au taux de contamination, les mêmes corpus ont été entièrement réparés:

| Famille | Taux faux | Seuil de confiance | Exactement réparé | Faux changements observés |
|---|---:|---:|---:|---:|
| Fonctionnelle | 20 % | 0,80 | 8/8 | 0 |
| Fonctionnelle | 30 % | 0,70 | 12/12 | 0 |
| Fonctionnelle | 40 % | 0,60 | 16/16 | 0 |
| Arithmétique | 20 % | 0,80 | 8/8 | 0 |
| Arithmétique | 30 % | 0,70 | 12/12 | 0 |
| Arithmétique | 40 % | 0,60 | 16/16 | 0 |

Cela montre que le moteur possède la capacité de correction; la limite par défaut est surtout une décision d'autorité/confiance. Mais abaisser le seuil augmente nécessairement la surface où une corrélation accidentelle pourrait être promue. Sur 10 corpus aléatoires propres pour chacun des seuils 0,95 / 0,80 / 0,70 / 0,60, aucune mutation n'a été observée, mais 10 essais par seuil sont insuffisants pour annoncer un taux de faux positifs industriel.

## 6. Contrôles négatifs: faux changements

Campagnes exécutées:

- 20 corpus aléatoires propres, 20 lignes chacun, seuils par défaut: **0 corpus muté, 0 édition**.
- 30 corpus aléatoires avec un champ `y` manquant mais sans relation causale suffisante: **0 reconstruction inventée, 30 abstentions, 0 fausse reconstruction**.
- 10 corpus aléatoires propres à chacun des seuils 0,95 / 0,80 / 0,70 / 0,60: **0 corpus muté dans les 40 essais**.

Ces résultats confirment le caractère conservateur du moteur sur les corpus testés, mais ne constituent pas encore une estimation statistique sérieuse du taux de faux positifs.

## 7. Syntaxe: ce que le réparateur accepte et refuse réellement

Le réparateur syntaxique est volontairement étroit. Sur 14 cas ciblés:

Réparés exactement: 8/14.

- virgule terminale d'objet
- virgule manquante entre membres
- deux-points manquant
- accolade terminale manquante
- deux fermetures de conteneur manquantes à EOF
- délimiteur final en trop
- virgule terminale de tableau
- virgule manquante dans un tableau

Refusés: 6/14.

- quotes simples
- clé non quotée
- commentaire JavaScript
- clé dupliquée
- guillemet non fermé
- deux erreurs structurelles distinctes dans le même fragment

Donc ce n'est pas un parseur permissif général de « dirty JSON ». Il privilégie les réparations minimales convergentes et refuse les syntaxes dont la reconstruction n'est pas unique sous son petit front de grammaire.

## 8. Frontières de sécurité observées

Les limites par défaut ont été testées exactement au bord:

| Ressource | Valeur acceptée | Première valeur refusée |
|---|---:|---:|
| profondeur | 96 | 97 (`max_depth`) |
| longueur d'un nombre | 4096 caractères | 4097 (`max_number_chars`) |
| longueur d'une clé UTF-8 | 16384 octets | 16385 (`max_key_bytes`) |
| chaîne | 8 388 608 octets | 8 388 609 (`max_string_bytes`) |
| nœuds | 1 000 000 | 1 000 001 (`max_nodes`) |

Autres bornes contractuelles présentes dans 0.40.0: document non-streaming 64 MiB, bundle 2048 documents / 512 MiB, record streaming 8 MiB / 250 000 nœuds, tableau 1 000 000 éléments, objet 100 000 clés.

## 9. Coût de calcul du moteur complet

Corpus: objets à 5 champs, 2 corruptions, certification finale active, 3 cycles observés.

| Lignes | Temps | RSS max | Débit effectif approximatif |
|---:|---:|---:|---:|
| 10 | 0,504 s | 126 928 KiB | 19,8 lignes/s |
| 50 | 1,343 s | 130 612 KiB | 37,2 lignes/s |
| 100 | 1,941 s | 132 696 KiB | 51,5 lignes/s |
| 250 | 4,393 s | 138 164 KiB | 56,9 lignes/s |
| 500 | 7,378 s | 147 672 KiB | 67,8 lignes/s |
| 1000 | 14,299 s | 158 124 KiB | 69,9 lignes/s |

Le coût est élevé par rapport à un parseur JSON: le moteur fait découverte de relations, optimisation de patch, replay, graphes de preuve, falsification, bornes d'information et certification. Sur ce benchmark, la croissance devient proche de linéaire après le coût fixe de démarrage, mais ~70 lignes/s reste lent pour un outil de masse non-streaming.

## 10. Streaming

Un record manquant à réparer dans un JSONL à 5 champs:

| Records | Temps | RSS max | Débit |
|---:|---:|---:|---:|
| 100 | 0,486 s | 117 456 KiB | 206 rec/s |
| 1 000 | 3,596 s | 117 752 KiB | 278 rec/s |
| 5 000 | 17,053 s | 118 868 KiB | 293 rec/s |
| 7 500 | 25,077 s | 121 076 KiB | 299 rec/s |
| 10 000 | 33,449 s | 120 720 KiB | 299 rec/s |

Point fort matériel: la mémoire reste pratiquement plate pendant cette montée de 100 à 10 000 records, alors que le débit se stabilise autour de 300 records/s dans cet environnement. La couche streaming est donc beaucoup plus crédible pour les gros corpus que le mode objet complet.

## 11. Bundle / multi-document

Réparation d'une référence croisée avec deux documents de même taille:

| Lignes par document | Temps | Réparation |
|---:|---:|---|
| 10 | 0,975 s | exacte |
| 100 | 1,852 s | exacte |
| 500 | 6,004 s | exacte |
| 1000 | 10,791 s | exacte |

Contrôles négatifs:

- variante de casse vers une cible unique: réparée;
- référence pendante `NOPE`: abstention avec `cross_document_dangling_reference`;
- deux collections cibles également plausibles: abstention avec `ambiguous_reference_target`.

C'est une vraie capacité supérieure à un parseur JSON classique: la réparation porte sur la cohérence du système de documents, pas seulement sur la syntaxe d'un fichier.

## 12. Microbenchmark de parsing pur

Payload JSON valide: 1 342 235 octets. Médiane sur 3 exécutions.

| Parseur | Temps médian |
|---|---:|
| `ujson 5.12.1` | 0,0065 s |
| `orjson 3.11.9` | 0,0070 s |
| `json` stdlib | 0,0091 s |
| `json-consistency-repair.loads_strict` | 0,1303 s |
| `json5 0.14.0` | 10,1891 s |

Cette table ne compare pas les capacités de réparation. Elle montre seulement le coût de la lecture stricte JCR: détection de clés dupliquées, validation de profondeur, nœuds, chaînes, nombres et sécurité. Elle est environ 14× plus lente que `json.loads` sur cet échantillon, et environ 19–20× plus lente qu'orjson/ujson.

Aucun concurrent complet de réparation sémantique n'a été utilisé dans cette campagne. Il serait incorrect d'en déduire une supériorité de marché.

## 13. Verrous avancés attaqués directement

Six témoins adversariaux ciblés ont été rejoués contre 0.40.0:

1. symétrie de deux porteurs interchangeables -> `SYMMETRY_BLOCKED_REPAIR`, pas de tiebreak arbitraire;
2. correction identifiable mais chemin immuable -> `IDENTIFIABLE_BUT_UNREACHABLE`, aucune mutation;
3. relation empirique détruite par split-fold -> `ACTIVE_REFUTED`, relation bloquée;
4. reconstruction aveugle -> cible réellement retirée du porteur avant prédiction, hash scellé vérifié;
5. dérive d'horizon non expliquée -> rejet;
6. même entrée distribuée menant à deux terminaux différents -> conflit distribué détecté.

Les 6 tests ciblés ont passé.

## 14. Ce qu'on possède exactement aujourd'hui

### Solide

- réparation syntaxique conservatrice et bornée;
- reconstruction de champs manquants depuis relations fonctionnelles, arithmétiques, contraintes, schémas et systèmes de documents;
- capacité très élevée de reconstruction de données absentes lorsque quelques témoins propres suffisent;
- abstention réelle sur ambiguïté, références pendantes, symétries et relations falsifiées;
- patchs réversibles, cold replay, graphes de preuve et certification indépendante;
- contrôle de permission/atteignabilité;
- streaming à mémoire stable;
- cohérence bundle/multi-document;
- objets OPEN persistants, horizon/distribution, bornes d'information et blind reconstruction.

### Limites actuelles mesurées

1. **Valeurs fausses auto-découvertes:** seuil par défaut très conservateur; dans le corpus 40 lignes, >5 % de corruption suffit à faire disparaître une relation à confiance 0,95.
2. **`PASS` n'est pas une vérité externe:** le moteur peut certifier son état relatif à l'évidence disponible tout en laissant une corruption inconnue.
3. **Discontinuité de réparation des champs manquants autour d'un cas 3/40:** anomalie de solveur/objectif à corriger ou expliquer formellement.
4. **Mode objet complet lent:** ~14,3 s pour 1000 lignes dans ce test, contre ~33,4 s pour 10 000 records en streaming.
5. **Empreinte de base élevée:** environ 112 MiB RSS rien qu'après import dans cet environnement.
6. **Syntax repair volontairement incomplet:** ne remplace pas un parser permissif JSON5/JavaScript.
7. **Pas encore de benchmark externe complet contre les meilleurs repairers spécialisés:** on sait précisément ce que JCR fait dans cette campagne, pas encore s'il domine tous les concurrents publics.

## 15. Verdict technique

Le moteur 0.40.0 est déjà une architecture de rectification sémantique inhabituelle et beaucoup plus profonde qu'un simple JSON fixer. La caractéristique la plus forte n'est pas « il répare tout » mais **il sait reconstruire quand le porteur est suffisant et s'abstenir lorsque le terminal n'est pas justifié**.

Le benchmark ne permet toutefois pas encore de dire « meilleur repairer JSON du monde ». Deux points doivent être réglés avant une telle affirmation: le comportement non monotone observé sur certains manques, et une campagne externe contre d'autres repairers sur un corpus commun avec vérité terrain.

Pour la comparaison avec le CSV: le JSON a maintenant la profondeur architecturale correspondante, mais son profil pratique est différent. Il est extraordinairement fort sur la reconstruction de données absentes sous relations, tandis que la détection autonome de valeurs fausses est volontairement bridée par la confiance afin d'éviter les mutations aventureuses. C'est précisément cette frontière qu'il faut maintenant optimiser, pas ajouter des fonctions au hasard.
