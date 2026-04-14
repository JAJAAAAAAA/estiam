# Rapport de projet — DevSecOps

**Module :** 5DVSCOPS — 2025/2026
**Enseignant :** Laurent FREREBEAU
**Étudiant :** _[À compléter]_
**Date :** _[À compléter]_
**Lien du dépôt :** _[https://github.com/USER/devsecops-demo]_
**Branche analysée :** `main`

---

## Table des matières

1. [Contexte et objectifs du projet](#1-contexte-et-objectifs-du-projet)
2. [Cadre théorique DevSecOps](#2-cadre-théorique-devsecops)
3. [Architecture du pipeline mis en place](#3-architecture-du-pipeline-mis-en-place)
4. [Outillage retenu et justification](#4-outillage-retenu-et-justification)
5. [Mise en œuvre détaillée — partie par partie](#5-mise-en-œuvre-détaillée--partie-par-partie)
6. [Analyse des vulnérabilités détectées](#6-analyse-des-vulnérabilités-détectées)
7. [Politique de sécurité Conftest / Rego](#7-politique-de-sécurité-conftest--rego)
8. [Réflexion sécurité — supply chain, SCA, gouvernance](#8-réflexion-sécurité)
9. [Limites du projet et axes d'amélioration](#9-limites-du-projet-et-axes-damélioration)
10. [Conclusion](#10-conclusion)
11. [Annexes](#annexes)

---

## 1. Contexte et objectifs du projet

Ce projet s'inscrit dans le cadre du module **5DVSCOPS — DevSecOps** de l'année 2025/2026. Il a pour objectif de mettre en pratique les concepts théoriques vus en cours en construisant, de bout en bout, **un pipeline CI/CD intégrant des contrôles de sécurité automatisés** sur une application réaliste.

L'application support choisie est une **petite API REST en Python / Flask**, conteneurisée avec Docker et déployable sur Kubernetes. Cette stack est représentative d'un grand nombre d'applications modernes « cloud-native » et permet d'exercer plusieurs catégories de scans :

- les **dépendances applicatives** (paquets Python),
- l'**image de conteneur** (paquets OS et binaires),
- les **manifests d'infrastructure** (YAML Kubernetes),
- une **politique organisationnelle codifiée** (Rego).

Les objectifs pédagogiques visés, tels que listés dans le sujet du projet, sont :

1. Comprendre le rôle de la sécurité dans un pipeline CI/CD.
2. Savoir intégrer des outils open-source de sécurité (static & image scanning).
3. Mettre en place des règles de sécurité codifiées dans un pipeline.
4. Identifier des vulnérabilités dans des dépendances, conteneurs et configurations.

Ce rapport reprend chacune de ces dimensions et les replace dans le cadre théorique du DevSecOps tel qu'enseigné dans le module.

---

## 2. Cadre théorique DevSecOps

### 2.1 Définition

Le **DevSecOps** (Development + Security + Operations) est l'approche qui consiste à **intégrer la sécurité à chaque étape du cycle de développement logiciel**, de la conception au déploiement, en automatisant les contrôles et en partageant la responsabilité de la sécurité entre toutes les équipes (développement, sécurité, opérations). Il s'oppose au modèle traditionnel où la sécurité intervient **en fin de cycle**, sous forme d'audits ou de tests d'intrusion ponctuels — modèle qui ne tient plus dès lors qu'une organisation déploie plusieurs fois par jour.

Le DevSecOps n'est donc pas un outil, c'est une **culture** : la sécurité est l'affaire de tous, et chaque ligne de code est susceptible d'être analysée automatiquement avant d'atteindre la production.

### 2.2 Le principe fondateur : Shift-Left

Le principe de **Shift-Left Security** consiste à **déplacer les contrôles de sécurité le plus tôt possible dans le cycle de développement** — idéalement dans l'IDE du développeur ou au moment du commit, plutôt qu'à la veille d'une mise en production. La justification est à la fois économique et opérationnelle : il est admis qu'une vulnérabilité corrigée au stade du développement coûte de l'ordre de **100 fois moins cher** qu'une vulnérabilité corrigée en production (chiffrage IBM Security Cost of Data Breach 2024).

Dans notre projet, le Shift-Left se matérialise concrètement par :

- l'exécution **automatique** du pipeline à chaque `git push`,
- le **lint du Dockerfile** (hadolint) avant même le build,
- le **lint des manifests Kubernetes** (yamllint + kube-linter),
- les **scans Trivy** sur les dépendances et l'image dans le même run,
- l'exécution d'une **politique Rego** sur les manifests avant tout déploiement.

Le développeur n'a pas à attendre un audit : il a un retour automatique en quelques minutes après son commit.

### 2.3 Les principes complémentaires

Le Shift-Left n'est qu'un des principes du DevSecOps. Les autres piliers, tels qu'enseignés dans le module, sont :

| Principe | Définition | Application dans notre projet |
|---|---|---|
| **Security as Code** | Les politiques de sécurité sont du code versionné, pas des documents PDF | Notre règle Rego (`policy/security.rego`) est dans le repo, versionnée comme le code applicatif |
| **Continuous Security** | Les contrôles s'exécutent à chaque commit, pas ponctuellement | Le workflow se déclenche sur `push` et `pull_request` |
| **Defense in Depth** | Empiler plusieurs couches de contrôles | hadolint + yamllint + kube-linter + Trivy FS + Trivy image + Conftest = 6 couches |
| **Zero Trust** | Ne jamais faire confiance implicitement, vérifier chaque composant | Le `permissions:` du workflow accorde le **moindre privilège** possible au `GITHUB_TOKEN` |
| **Fail Fast, Fix Fast** | Bloquer immédiatement si un seuil est dépassé | Modulé dans notre projet (voir § 5.6 sur les security gates) |
| **Measure Everything** | Mesurer pour pouvoir améliorer | Métriques DORA, MTTR — discutées au § 8 |
| **Shared Responsibility** | La sécurité concerne tout le monde | Symbolisée par les Security Champions dans une équipe |

### 2.4 Les familles d'outils — SAST, DAST, SCA, IAST, IaC scan, secret scanning

Le DevSecOps s'appuie sur des **catégories d'outils** qu'il est essentiel de bien distinguer, car elles couvrent des angles de sécurité différents et sont **complémentaires**.

| Catégorie | Acronyme | Cible | Quand ? | Exemples open-source |
|---|---|---|---|---|
| **Static Application Security Testing** | SAST | Code source (sans l'exécuter) | Build | Semgrep, Bandit, CodeQL |
| **Dynamic Application Security Testing** | DAST | Application en cours d'exécution | Test | OWASP ZAP, Nuclei |
| **Interactive Application Security Testing** | IAST | Application instrumentée pendant les tests | Test | Contrast (commercial) |
| **Software Composition Analysis** | SCA | Dépendances open-source | Build | Trivy, Grype, OWASP Dependency-Check |
| **Container scanning** | — | Image Docker (OS + libs) | Release | Trivy, Grype, Syft |
| **IaC scanning** | — | Terraform, K8s YAML, CloudFormation | Deploy | Checkov, tfsec, kube-linter, Conftest |
| **Secret scanning** | — | Clés API, mots de passe en clair | Code | GitLeaks, TruffleHog |

Notre projet active spécifiquement les catégories **SCA**, **container scanning** et **IaC scanning**. Le SAST et le secret scanning ne sont pas activés dans la version « minimum + bonus Conftest » que nous livrons, mais ils sont décrits au § 9 comme amélioration possible, conformément à la philosophie de defense in depth.

### 2.5 Métriques DORA

Le rapport **DORA State of DevOps** (publié chaque année par Google Cloud) définit **quatre métriques** qui font référence pour mesurer la performance — et indirectement la maturité sécurité — d'une équipe d'ingénierie logicielle :

| Métrique DORA | Définition | Pourquoi c'est lié à la sécurité |
|---|---|---|
| **Deployment Frequency** | Fréquence des déploiements en production | Plus on déploie souvent, plus on peut corriger vite |
| **Lead Time for Changes** | Temps entre un commit et son déploiement en production | Mesure le temps qu'une correction met à atteindre la prod |
| **Mean Time To Recover (MTTR)** | Temps moyen pour récupérer après un incident | Mesure la résilience opérationnelle |
| **Change Failure Rate** | Pourcentage de déploiements générant un incident | Mesure la qualité et la sécurité des releases |

Une cinquième métrique apparaît dans la littérature DevSecOps : le **MTTR appliqué aux vulnérabilités** (Mean Time To Remediate), c'est-à-dire le temps moyen entre la détection d'une CVE et son correctif déployé. C'est la métrique qui mesure le mieux **l'efficacité réelle** d'un programme DevSecOps.

---

## 3. Architecture du pipeline mis en place

### 3.1 Vue d'ensemble

Le pipeline est implémenté en **GitHub Actions**, conformément au sujet du projet. Il s'organise en **6 jobs** dont certains peuvent s'exécuter en parallèle. Le schéma ci-dessous représente le flux d'exécution et les dépendances entre jobs :

```
                         ┌─────────────┐
                         │  git push   │
                         └──────┬──────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        │                       │                       │
        ▼                       ▼                       ▼
┌───────────────┐      ┌────────────────┐      ┌──────────────────┐
│ lint-         │      │  lint-yaml     │      │ scan-            │
│ dockerfile    │      │ (yamllint +    │      │ dependencies     │
│ (hadolint)    │      │  kube-linter)  │      │  (Trivy FS)      │
└───────┬───────┘      └────────┬───────┘      └──────────────────┘
        │                       │
        ▼                       ▼
┌───────────────┐      ┌────────────────┐
│ build-image   │      │ policy-check   │
│ (docker       │      │ (Conftest /    │
│  buildx)      │      │  Rego)         │
└───────┬───────┘      └────────────────┘
        │
        ▼
┌───────────────┐
│ scan-image    │
│ (Trivy image) │
└───────┬───────┘
        │
        ▼
┌──────────────────────────────────────┐
│  Upload SARIF → onglet Security      │
│  Logs disponibles dans Actions       │
└──────────────────────────────────────┘
```

### 3.2 Choix de conception

Plusieurs choix architecturaux structurent ce pipeline et méritent d'être justifiés :

**Choix 1 — Décomposition en jobs distincts plutôt qu'en un job monolithique.**
L'avantage est double : (a) parallélisation et donc gain de temps d'exécution, (b) lisibilité des logs — chaque job a son propre onglet et ses propres logs dans l'UI GitHub Actions. C'est aussi une bonne pratique en termes de **traçabilité** : on sait précisément quel contrôle a échoué.

**Choix 2 — Build de l'image avant le scan d'image.**
Le job `scan-image` dépend de `build-image` via la directive `needs:`. L'image est passée d'un job à l'autre via le mécanisme d'**artefacts** GitHub Actions (`upload-artifact` / `download-artifact`). C'est nécessaire car chaque job tourne sur un runner différent qui ne partage pas son daemon Docker.

**Choix 3 — `permissions:` minimales.**
Le bloc `permissions:` du workflow accorde uniquement `contents: read` (lecture du code) et `security-events: write` (publication des SARIF dans l'onglet Security). C'est l'application directe du **principe du moindre privilège** (Least Privilege) — l'un des piliers du DevSecOps. Sans ce bloc, GitHub accorde par défaut un token avec beaucoup plus de droits, ce qui constituerait une faille en cas de compromission d'une action tierce.

**Choix 4 — Export SARIF vers l'onglet Security.**
Le format **SARIF** (Static Analysis Results Interchange Format) est le format standard JSON utilisé par GitHub Advanced Security pour centraliser les résultats des outils d'analyse. En publiant les résultats Trivy au format SARIF via `github/codeql-action/upload-sarif`, on bénéficie automatiquement de la vue **Code scanning alerts** de GitHub, qui présente les findings avec leur historique, leur statut (open/dismissed) et leur sévérité.

**Choix 5 — `exit-code: '0'` sur les scans.**
Dans la version « minimum » que nous livrons, les jobs de scan sont configurés pour **ne pas casser le pipeline** même en cas de findings. Ce choix est volontairement pédagogique : il permet à tous les jobs d'aller au bout et de produire des artefacts exploitables pour le rapport. En production, on basculerait sur `exit-code: '1'` avec un seuil (par exemple : bloquer sur `CRITICAL` quand un correctif existe). Cette nuance est discutée en détail au § 5.6 sur les **security gates**.

---

## 4. Outillage retenu et justification

Le tableau ci-dessous récapitule les outils utilisés, leur catégorie selon la taxonomie du module, et la justification de leur choix.

| Outil | Catégorie | Type | Justification |
|---|---|---|---|
| **GitHub Actions** | Orchestration CI/CD | SaaS | Imposé par le sujet, gratuit avec un compte GitHub, intégration native au repo, écosystème d'actions très riche |
| **hadolint** | Lint Dockerfile | Open-source | Standard de fait pour Dockerfile, action GitHub officielle, règles documentées (DL3xxx, SC2xxx) |
| **yamllint** | Lint YAML syntaxique | Open-source | Vérifie la syntaxe YAML pure (indentation, longueur de ligne, etc.) |
| **kube-linter** | Lint sécurité K8s | Open-source (StackRox/RedHat) | Détecte les mauvaises pratiques K8s spécifiques (run as root, no resources limits, image tag latest, etc.) |
| **Trivy** | SCA + Container scan | Open-source (Aqua Security) | Scanner unifié couvrant FS, images, K8s et IaC. Action officielle Aqua. Bases NVD + GHSA + OSV |
| **Conftest** | Policy as Code | Open-source (Open Policy Agent) | Permet d'écrire des règles métier en **Rego**, langage déclaratif officiel d'OPA |

### 4.1 Pourquoi Trivy plutôt qu'un autre scanner ?

Plusieurs scanners SCA / container existent dans l'écosystème open-source : **Trivy** (Aqua), **Grype** (Anchore), **OWASP Dependency-Check**, et côté commercial **Snyk** ou **Black Duck**. Trivy a été choisi pour les raisons suivantes :

- **Couverture la plus large** : un seul outil scanne les dépendances applicatives (Python, Node.js, Java, Go…), les images de conteneurs, les manifests Kubernetes, les fichiers Terraform, et même les secrets.
- **Sources de vulnérabilités multiples** : Trivy croise NVD, GHSA, OSV et plusieurs bases distributeurs (Debian, Alpine, Red Hat). C'est important car **aucune base n'est exhaustive** prise isolément.
- **Action GitHub officielle** maintenue par Aqua Security, ce qui garantit la pérennité.
- **Format SARIF supporté nativement**, ce qui permet l'intégration directe dans GitHub Security.
- **Performance** : Trivy est réputé plus rapide que ses concurrents sur les images de grande taille.

### 4.2 Pourquoi Conftest / Rego plutôt que de durcir kube-linter ?

`kube-linter` applique des règles **prédéfinies** par ses auteurs. Il est très pratique pour détecter les mauvaises pratiques connues, mais on ne peut pas facilement coder ses propres règles métier. **Conftest**, lui, exécute des règles écrites en **Rego**, le langage déclaratif d'**OPA (Open Policy Agent)**. Cela permet de coder absolument n'importe quelle règle métier — par exemple : « tous les pods de mon entreprise doivent avoir le label `cost-center` », ou « la registry de provenance des images doit être notre registry interne ».

Les deux outils sont **complémentaires** et c'est exactement ce que fait notre pipeline : kube-linter assure les vérifications « universelles », Conftest applique notre politique organisationnelle propre (pas de root).

---

## 5. Mise en œuvre détaillée — partie par partie

Le sujet du projet découpe le travail en 5 parties. Cette section retrace, partie par partie, ce qui a été fait et les choix opérés.

### 5.1 Partie 1 — Préparation

**Demande du sujet :** disposer d'un dépôt contenant une petite API Flask (ou Node.js) avec un Dockerfile et un fichier Kubernetes YAML.

**Réalisation :** plutôt que de cloner un repo existant (qui aurait pu être déjà sécurisé et donc ne rien remonter aux scans), nous avons choisi de **créer une application volontairement vulnérable**. C'est une démarche pédagogique assumée : pour démontrer qu'un pipeline détecte effectivement des vulnérabilités, encore faut-il qu'il en existe. Une petite API Flask exposant trois endpoints (`/`, `/health`, `/echo`) a été codée. Le `requirements.txt` épingle volontairement des versions obsolètes :

```
Flask==2.0.1
Werkzeug==2.0.1
Jinja2==2.11.3
itsdangerous==2.0.1
click==8.0.1
requests==2.25.0
urllib3==1.26.4
```

Toutes ces versions ont des CVE publiques connues, ce qui garantira un retour visible de Trivy.

### 5.2 Partie 2 — Pipeline CI/CD GitHub Actions (build + lint)

**Demande :** créer un workflow qui (a) build l'image Docker, (b) lint le Dockerfile, (c) lint les YAML.

**Réalisation :** trois jobs distincts.

**Job `lint-dockerfile`** : utilise l'action `hadolint/hadolint-action@v3.1.0`. Le seuil est positionné à `error` pour ne casser le pipeline que sur les erreurs et non sur les warnings, conformément à un usage pragmatique : on ne veut pas qu'un avertissement de style bloque les développeurs.

**Job `lint-yaml`** : enchaîne `yamllint` (vérification syntaxique pure) puis `kube-linter` (vérification sécurité). `kube-linter` est en `continue-on-error: true` car sa fonction première est de **documenter** les findings, pas de bloquer.

**Job `build-image`** : utilise `docker/setup-buildx-action` puis `docker/build-push-action`. L'image est construite avec `push: false` (on ne pousse rien sur un registry distant) et `load: true` (l'image est rechargée dans le daemon Docker du runner pour pouvoir être scannée par Trivy ensuite). Elle est ensuite **sauvegardée en artefact** via `docker save` + `actions/upload-artifact`, pour pouvoir être récupérée par le job `scan-image`.

### 5.3 Partie 3 — Scan de sécurité Trivy

**Demande :** intégrer Trivy pour scanner les dépendances et l'image, identifier et documenter les vulnérabilités.

**Réalisation :** deux jobs séparés.

**Job `scan-dependencies`** utilise `aquasecurity/trivy-action@0.28.0` en mode `scan-type: fs` sur le dossier `app/`. Trivy détecte automatiquement le fichier `requirements.txt` et le scanne contre sa base de CVE. Le scan est exécuté **deux fois** : une fois en format `table` (lisible dans les logs, joli rendu) et une fois en format `sarif` (uploadé vers l'onglet Security via `github/codeql-action/upload-sarif`).

**Job `scan-image`** récupère l'artefact image (`docker load -i /tmp/image.tar`) puis exécute Trivy en mode `image-ref`. Comme pour les dépendances, double exécution table + SARIF. Ce job dépend du job `build-image` via `needs:`.

**Filtrage de sévérité** : `severity: HIGH,CRITICAL`. C'est un compromis volontaire — afficher tous les niveaux MEDIUM et LOW noierait l'analyse sous des dizaines de findings de faible importance. En production, ce paramètre serait à débattre selon le contexte métier.

### 5.4 Partie 4 — Politique de sécurité (Conftest, bonus)

**Demande :** créer une règle Conftest interdisant un pod en root et l'intégrer au pipeline.

**Réalisation :** voir le détail au § 7. Le job `policy-check` télécharge Conftest dans le runner (la version `0.56.0` au moment de la rédaction), puis exécute `conftest test --policy policy/ k8s/`. Le code de retour est capturé pour information mais le job ne casse pas le pipeline (`exit 0`), pour la même raison pédagogique que les scans Trivy.

### 5.5 Partie 5 — Rendu et synthèse

**Demande :** documenter la démarche, les vulnérabilités, les règles. Présenter les fichiers, les captures et l'analyse de risques.

**Réalisation :** ce document est cette synthèse. Il est livré au format Markdown, exportable en PDF.

### 5.6 Approfondissement — Security gates et politique de blocage

Un point important du cours mérite ici une explication détaillée : la notion de **security gate**. Un security gate est un point de contrôle automatisé du pipeline qui **bloque le déploiement** si certains critères de sécurité ne sont pas satisfaits. C'est ce qui transforme un simple « pipeline de scan » (qui produit des rapports) en un véritable **pipeline DevSecOps** (qui empêche la livraison de code vulnérable).

La grille de blocage généralement recommandée dans le cours est la suivante :

| Sévérité | SAST | SCA | Secrets |
|---|---|---|---|
| CRITICAL | 🚫 Bloque | 🚫 Bloque | 🚫 Bloque |
| HIGH | ⚠️ Alerte | 🚫 Bloque | 🚫 Bloque |
| MEDIUM | 📋 Log | ⚠️ Alerte | 🚫 Bloque |
| LOW | 📋 Log | 📋 Log | ⚠️ Alerte |

À noter : les **secrets** sont **toujours bloquants** quel que soit leur niveau, car une clé API ou un mot de passe exposé est immédiatement exploitable.

Dans notre projet, nous avons fait le choix pédagogique de **ne pas bloquer** afin que le rapport puisse exhiber les findings de tous les jobs. Pour passer en mode bloquant, il suffirait de :

1. Sur le job `scan-dependencies` : remplacer `exit-code: '0'` par `exit-code: '1'` et garder `severity: HIGH,CRITICAL`. Le pipeline cassera si une CVE HIGH ou CRITICAL est détectée.
2. Sur le job `scan-image` : idem.
3. Sur le job `policy-check` : retirer le `exit 0` final pour laisser le code de retour de Conftest casser le job.

L'exercice demande une discussion d'équipe : un seuil trop bas génère un **bruit insupportable** (faux positifs et CVE non exploitables qui bloquent les développeurs sans valeur ajoutée), un seuil trop haut **laisse passer** des vrais risques. La bonne pratique est généralement :

- **Critical avec fix disponible → bloquant** : pas d'excuse, il y a un correctif.
- **High avec fix disponible → bloquant** sur les nouvelles dépendances, **alerte** sur les existantes (avec une dette technique tracée).
- **Critical sans fix → exception manuelle** documentée, suivie via un ticket.
- **Secrets → toujours bloquant**.

---

## 6. Analyse des vulnérabilités détectées

> _Note : cette section doit être complétée avec les résultats réels du run du pipeline. Les exemples ci-dessous sont représentatifs de ce que l'on observe avec les versions épinglées dans `requirements.txt`._

### 6.1 Dépendances Python (job `scan-dependencies` — Trivy FS)

Le scan Trivy filesystem sur `app/requirements.txt` remonte plusieurs CVE. Voici un exemple de résultats attendus :

| Package | Version installée | CVE | Sévérité | Version corrigée |
|---|---|---|---|---|
| Flask | 2.0.1 | CVE-2023-30861 | HIGH | 2.2.5 |
| Werkzeug | 2.0.1 | CVE-2023-25577 | HIGH | 2.2.3 |
| Werkzeug | 2.0.1 | CVE-2023-46136 | HIGH | 3.0.1 |
| Jinja2 | 2.11.3 | CVE-2024-22195 | MEDIUM | 3.1.3 |
| Jinja2 | 2.11.3 | CVE-2024-34064 | HIGH | 3.1.4 |
| requests | 2.25.0 | CVE-2023-32681 | MEDIUM | 2.31.0 |
| urllib3 | 1.26.4 | CVE-2023-43804 | HIGH | 1.26.17 |
| urllib3 | 1.26.4 | CVE-2024-37891 | MEDIUM | 1.26.19 |

**Analyse :** ces vulnérabilités illustrent parfaitement plusieurs concepts du cours.

- **Vulnérabilités directes vs transitives** : ici toutes les vulnérabilités touchent des dépendances **directement déclarées** dans `requirements.txt`. Mais Werkzeug est aussi une dépendance transitive de Flask. Un SCA bien configuré doit traiter les deux. Selon les chiffres du cours (Snyk Open Source Security Report), **54 % des vulnérabilités dans les applications modernes se trouvent dans des dépendances transitives** — celles que le développeur n'a pas explicitement choisies.
- **Bases CVE consultées** : Trivy croise la **NVD** (National Vulnerability Database, gérée par le NIST) qui est la référence mondiale pour les CVE, mais aussi la **GitHub Advisory Database** et **OSV** (Open Source Vulnerabilities, Google).
- **Score CVSS** : chaque CVE est associée à un score **CVSS** (Common Vulnerability Scoring System) sur une échelle de 0 à 10, qui mesure de façon standardisée la sévérité technique. C'est ce score qui détermine la classification HIGH / CRITICAL / MEDIUM / LOW.
- **Vulnérabilité ≠ exposition** : une nuance importante du cours. Une vulnérabilité est **exploitable** dans votre contexte ; une exposition est **présente** mais peut ne pas être exploitable (par exemple, une fonction vulnérable jamais appelée par votre code). Dans une vraie démarche de tri, on commence par identifier les **vraies expositions** pour éviter le bruit des faux positifs.

**Recommandations :**

1. **Mettre à jour toutes les dépendances** vers leurs versions corrigées les plus récentes :
   ```
   Flask>=3.0.0
   Werkzeug>=3.0.1
   Jinja2>=3.1.4
   requests>=2.32.0
   urllib3>=2.2.0
   ```
2. **Activer GitHub Dependabot** dans les paramètres du repo (`Settings → Code security → Dependabot`). Dependabot ouvre automatiquement des Pull Requests de mise à jour dès qu'une nouvelle CVE est publiée sur une dépendance utilisée.
3. **Pinning des versions** : utiliser un fichier de lock (`pip-compile` produit un `requirements.lock`) pour garantir la **reproductibilité des builds** et éviter qu'une mise à jour transitive non testée passe inaperçue.
4. Mettre en place une **politique de mise à jour régulière** : par exemple, une revue trimestrielle des dépendances même en l'absence de CVE.

### 6.2 Image Docker (job `scan-image` — Trivy image)

Le scan de l'image construite à partir du `Dockerfile` (`python:3.9-slim`) remonte typiquement :

- Une vingtaine à une centaine de CVE sur les paquets OS Debian de l'image de base (`libssl`, `libc`, `zlib`, `libxml2`, `libsqlite3`, etc.).
- Les mêmes CVE Python que le scan FS (puisque les paquets sont installés dans l'image).
- Des paquets non nécessaires en production embarqués dans l'image de base.

**Recommandations sur le Dockerfile :**

1. **Mettre à jour l'image de base** vers `python:3.12-slim-bookworm` (ou `python:3.12-alpine` pour une empreinte encore plus réduite). Une version plus récente de l'image de base élimine **immédiatement** des dizaines de CVE.
2. **Pinner précisément la version** : `python:3.12.4-slim-bookworm` plutôt que `python:3.12-slim`, pour garantir la reproductibilité du build.
3. **Build multi-stage** : utiliser une première stage pour installer pip et les dépendances de build, puis une seconde stage minimale qui ne contient que le nécessaire à l'exécution. Cela divise la surface d'attaque par 2 à 5.
4. **Ajouter un `USER appuser`** dans le Dockerfile pour ne pas tourner le processus en root au sein du conteneur.
5. **`HEALTHCHECK`** : déclarer un healthcheck Docker pour permettre à l'orchestrateur (et à hadolint) de vérifier l'état du conteneur.

Exemple de Dockerfile durci :

```dockerfile
# ===== Stage 1 : build =====
FROM python:3.12.4-slim-bookworm AS builder
WORKDIR /build
COPY app/requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# ===== Stage 2 : runtime =====
FROM python:3.12.4-slim-bookworm
RUN groupadd -g 1000 appuser && \
    useradd -m -u 1000 -g 1000 appuser
WORKDIR /app
COPY --from=builder /root/.local /home/appuser/.local
COPY app/ .
ENV PATH=/home/appuser/.local/bin:$PATH
USER appuser
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=3s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')" || exit 1
CMD ["python", "app.py"]
```

### 6.3 Manifests Kubernetes (jobs `lint-yaml` + `policy-check`)

`kube-linter` et `Conftest` remontent typiquement les findings suivants :

| Finding | Outil | Sévérité | Recommandation |
|---|---|---|---|
| `runAsUser: 0` détecté sur le conteneur `api` | Conftest | CRITICAL (politique) | Mettre `runAsNonRoot: true` et un UID non-zéro |
| `runAsNonRoot` non défini explicitement | Conftest (warn) | LOW | Déclarer explicitement `runAsNonRoot: true` |
| `allowPrivilegeEscalation` non défini | kube-linter | HIGH | Forcer à `false` |
| `readOnlyRootFilesystem` non défini | kube-linter | MEDIUM | Forcer à `true` |
| `capabilities.drop: [ALL]` non défini | kube-linter | MEDIUM | Drop toutes les capabilities Linux |
| Image pointée avec un tag mutable (`latest` ou SHA non figé) | kube-linter | MEDIUM | Pinner par digest SHA256 |

**Recommandation de `securityContext` durci :**

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
  fsGroup: 1000
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop: [ALL]
  seccompProfile:
    type: RuntimeDefault
```

C'est la configuration **minimale recommandée** par les standards Kubernetes (PodSecurity Admission profile **restricted**) et par les benchmarks CIS Kubernetes.

---

## 7. Politique de sécurité Conftest / Rego

### 7.1 Présentation de Conftest et de Rego

**Conftest** est un outil de la suite **Open Policy Agent (OPA)** qui permet d'évaluer des **politiques** écrites en langage **Rego** sur des fichiers de configuration structurés (YAML, JSON, HCL, Dockerfile, etc.). Conftest charge tous les fichiers `.rego` du dossier passé à l'option `--policy` et les applique à chaque fichier d'entrée. C'est ce que l'on appelle du **Policy as Code** : les règles métier sont du code versionné, testable, et déployable comme n'importe quel autre composant du système.

**Rego** est un langage **déclaratif** dérivé de Datalog. On ne dit pas « comment » vérifier quelque chose, on dit « ce qui est interdit » (règles `deny`) ou « ce qui est recommandé » (règles `warn`).

### 7.2 La règle implémentée

Le fichier `policy/security.rego` contient les règles suivantes :

```rego
package main

# Helpers : on identifie les ressources Kubernetes qui contiennent
# une PodSpec (Pod, Deployment, StatefulSet, DaemonSet)
is_pod_spec_owner { input.kind == "Deployment" }
is_pod_spec_owner { input.kind == "StatefulSet" }
is_pod_spec_owner { input.kind == "DaemonSet" }
is_pod_spec_owner { input.kind == "Pod" }

# Récupération de la PodSpec selon le kind
pod_spec = spec {
    input.kind == "Pod"
    spec := input.spec
}
pod_spec = spec {
    input.kind != "Pod"
    spec := input.spec.template.spec
}

# Règle 1 : deny si un conteneur tourne en runAsUser: 0
deny[msg] {
    is_pod_spec_owner
    container := pod_spec.containers[_]
    container.securityContext.runAsUser == 0
    msg := sprintf(
      "Le conteneur '%s' tourne en tant que root (runAsUser: 0). Interdit.",
      [container.name],
    )
}

# Règle 2 : deny si la PodSpec elle-même demande root
deny[msg] {
    is_pod_spec_owner
    pod_spec.securityContext.runAsUser == 0
    msg := "Le Pod tourne en tant que root au niveau du podSecurityContext. Interdit."
}

# Règle 3 : warn si runAsNonRoot n'est pas explicitement déclaré
warn[msg] {
    is_pod_spec_owner
    container := pod_spec.containers[_]
    not container.securityContext.runAsNonRoot
    msg := sprintf(
      "Le conteneur '%s' ne déclare pas explicitement runAsNonRoot: true (recommandé).",
      [container.name],
    )
}
```

### 7.3 Explication ligne par ligne

- **`package main`** : nom du package Rego. Conftest cherche par défaut les règles dans le package `main`.
- **`is_pod_spec_owner`** : règle helper qui retourne `true` si la ressource analysée est l'un des kinds Kubernetes qui embarquent une PodSpec. La répétition de la règle avec différentes conditions est l'équivalent d'un OU logique en Rego.
- **`pod_spec = spec`** : règle helper qui extrait la PodSpec à la bonne profondeur selon le kind. Pour un `Pod` elle est à la racine (`input.spec`), pour un `Deployment` elle est sous `input.spec.template.spec`.
- **`deny[msg]`** : règle qui contribue au set `deny` avec un message si toutes les conditions du corps sont vraies. Conftest collecte tous les messages générés par toutes les règles `deny` et fait échouer le test s'il y en a au moins un.
- **`container := pod_spec.containers[_]`** : itération sur tous les conteneurs de la PodSpec. Le `_` est l'opérateur d'itération anonyme de Rego.
- **`warn[msg]`** : équivalent de `deny` mais ne fait pas échouer Conftest, juste produit un avertissement.

### 7.4 Exécution attendue

Sur le `deployment.yaml` du projet (qui contient volontairement `runAsUser: 0`), la sortie de Conftest est :

```
FAIL - k8s/deployment.yaml - main - Le conteneur 'api' tourne en tant que root (runAsUser: 0). Interdit.
WARN - k8s/deployment.yaml - main - Le conteneur 'api' ne déclare pas explicitement runAsNonRoot: true (recommandé).

15 tests, 13 passed, 1 warning, 1 failure
```

Le code de retour est `1` en cas d'au moins un `FAIL`, `0` sinon. C'est ce code qui permet d'intégrer la règle dans un security gate bloquant.

### 7.5 Pourquoi cette règle est essentielle

Tourner un conteneur en **root** (UID 0) est l'une des mauvaises pratiques les plus dangereuses en environnement Kubernetes. Si un attaquant parvient à compromettre l'application (par exemple via une vulnérabilité d'exécution de code à distance), il hérite immédiatement des privilèges root **dans le conteneur**. À partir de là, plusieurs scénarios d'escalade sont possibles :

- exploitation d'une vulnérabilité du runtime (containerd, runc) pour s'évader du conteneur (cf. CVE-2024-21626 « Leaky Vessels »),
- accès aux métadonnées du cloud provider (instance metadata service) pour récupérer des credentials,
- pivot latéral sur d'autres pods ou services du cluster.

Forcer `runAsNonRoot: true` ne supprime pas tous ces risques mais **réduit drastiquement la surface d'attaque** et impose à l'attaquant des étapes supplémentaires.

---

## 8. Réflexion sécurité

Cette section reprend les concepts plus larges du cours et les met en perspective avec le projet réalisé.

### 8.1 Sécurité de la supply chain logicielle

La **supply chain logicielle** désigne l'ensemble des composants, outils, processus et personnes impliqués dans la création et la livraison d'un logiciel — de la première ligne de code écrite jusqu'au binaire qui tourne en production. C'est devenu, ces dernières années, **l'un des vecteurs d'attaque les plus critiques**. Le cours évoque trois cas emblématiques que l'on peut rappeler ici :

- **SolarWinds Orion (2020)** — des attaquants ont compromis le pipeline de build de SolarWinds pour injecter une backdoor dans une mise à jour officielle du produit Orion, distribuée à des milliers d'organisations dont des agences fédérales américaines. C'est l'attaque qui a popularisé le terme « supply chain attack » dans le grand public.
- **Log4Shell (CVE-2021-44228)** — une vulnérabilité critique dans Log4j 2, une bibliothèque de logging Java omniprésente. Elle illustre le risque des **dépendances transitives** : Log4j était souvent une dépendance de niveau 3 ou 4 dans les arbres de dépendances Java, donc invisible sans SCA. Sa découverte a déclenché une crise mondiale fin 2021.
- **XZ Utils (CVE-2024-3094, 2024)** — un contributeur malveillant a passé **plus de deux ans** à gagner la confiance des mainteneurs d'XZ Utils (une bibliothèque de compression utilisée partout sous Linux) avant d'introduire une backdoor dans une release. Détectée presque par hasard. Illustre le risque humain et social dans l'open source.

À ces cas s'ajoutent d'autres techniques d'attaque sur la supply chain à connaître :

- **Typosquatting** — la publication de paquets malveillants avec des noms volontairement très similaires à des paquets légitimes (`reqeusts` au lieu de `requests`, par exemple). Le développeur qui se trompe d'une lettre installe le paquet piégé.
- **Dependency confusion** — exploite la priorité que les gestionnaires de paquets donnent parfois aux registries publics par rapport aux registries privés internes. Si un attaquant publie sur npm public un paquet du même nom qu'un paquet privé interne, le client peut résoudre la version publique malveillante.

Notre projet, à son échelle modeste, applique plusieurs principes de défense de la supply chain :

- **Pinning des versions** dans `requirements.txt` (chaque paquet a une version exacte).
- **Scan systématique** de toutes les dépendances à chaque commit via Trivy.
- **Activation recommandée de Dependabot** pour suivre les CVE en continu.
- **Image de base depuis un registry de confiance** (Docker Hub officiel `python`).

### 8.2 SBOM, CycloneDX et Cosign — pour aller plus loin

Pour atteindre un véritable niveau de maturité supply chain, deux pratiques supplémentaires sont essentielles et constituent des **améliorations naturelles** de notre projet (voir § 9) :

**SBOM (Software Bill of Materials)** : un inventaire exhaustif et structuré de **tous** les composants logiciels d'une application, leurs versions, leurs licences et leurs dépendances. C'est l'équivalent informatique d'une « liste d'ingrédients » sur un produit alimentaire. Deux formats standards dominent :

- **CycloneDX** (OWASP) — particulièrement adapté à la sécurité, supporte le format **VEX** (Vulnerability Exploitability eXchange) pour documenter quelles CVE sont exploitables ou non dans un contexte donné.
- **SPDX** (Linux Foundation) — historiquement plus orienté licences open source.

L'outil **Syft** (Anchore) permet de générer un SBOM à partir d'une image Docker ou d'un repo. Le **Cyber Resilience Act** européen (entré en vigueur en 2024) **impose la fourniture d'un SBOM** pour les produits numériques vendus dans l'UE — c'est désormais une obligation réglementaire et plus seulement une bonne pratique.

**Signature cryptographique avec Cosign / Sigstore** : signer chaque artefact (image, SBOM, binaire) avec une clé cryptographique permet à un consommateur de vérifier qu'il s'agit bien de la version produite par le pipeline officiel et qu'elle n'a pas été altérée. Le projet **Sigstore** (Cosign + Rekor + Fulcio) propose une infrastructure de signature **« keyless »** : l'identité du signataire est attestée par OIDC plutôt que par une clé privée à protéger, ce qui simplifie énormément l'adoption.

### 8.3 Le framework SLSA

**SLSA** (Supply chain Levels for Software Artifacts, prononcé « salsa ») est un framework de Google standardisé par l'OpenSSF qui définit **quatre niveaux de maturité** pour la sécurisation d'une supply chain :

| Niveau | Exigences principales |
|---|---|
| **SLSA L1** | Build documenté, génération de provenance basique |
| **SLSA L2** | Build hébergé sur un service, provenance signée |
| **SLSA L3** | Builds **hermétiques** (sans accès réseau pendant la compilation), source vérifiée, provenance non falsifiable |
| **SLSA L4** | Two-person review obligatoire, builds reproductibles |

La **provenance** d'un artefact est l'ensemble des métadonnées vérifiables qui décrivent **comment, quand et où** un artefact a été produit. Avoir une provenance signée, c'est pouvoir prouver à un consommateur que l'image qu'il utilise vient bien de votre pipeline, à partir de tel commit, exécuté sur tel runner, à telle date.

Notre projet, en l'état, atteint à peine **SLSA L1** — il manque la génération formelle d'une provenance. C'est l'un des chantiers d'amélioration listés au § 9.

### 8.4 Software Composition Analysis (SCA) — approfondissement

Le SCA est la catégorie d'outils qui analyse spécifiquement les **dépendances tierces** d'une application. C'est précisément ce que fait Trivy en mode `fs` dans notre pipeline. Quelques notions importantes du cours méritent d'être rappelées :

- **Le SCA est une analyse boîte blanche** : elle a accès aux fichiers de manifeste (`requirements.txt`, `package.json`, `pom.xml`, `go.sum`, etc.) et à leur arbre de dépendances complet.
- **Ce qu'il ne détecte PAS** : il ne détecte **pas** les vulnérabilités dans le code source propriétaire de l'application — c'est le rôle du **SAST**. Le SCA et le SAST sont complémentaires.
- **Le rôle des fichiers de lock** : `package-lock.json`, `Pipfile.lock`, `go.sum`, etc. Ils figent les versions exactes de toutes les dépendances **transitives**, ce qui rend les builds reproductibles et permet au SCA de connaître précisément ce qui est installé.
- **Le risque des dépendances transitives** : selon Snyk SOSS Report, **54 % des vulnérabilités** se trouvent dans des dépendances transitives, c'est-à-dire celles que le développeur n'a pas explicitement choisies.
- **Faux positifs** : un faux positif en SCA est une alerte générée pour une vulnérabilité **présente** mais qui n'est pas exploitable dans votre contexte (par exemple, parce que la fonction vulnérable n'est jamais appelée). C'est la principale source de friction pour les développeurs et le motif n°1 de désengagement vis-à-vis des outils. Le format VEX vise précisément à formaliser ces décisions de tri.

### 8.5 Gestion des licences open source

Un aspect souvent oublié du SCA est la **conformité des licences**. Toutes les licences open source ne se valent pas :

| Licence | Type | Risque pour usage commercial |
|---|---|---|
| **MIT** | Permissive | Faible — usage libre, simple attribution |
| **Apache 2.0** | Permissive | Faible — clauses brevet en plus |
| **BSD 2/3-Clause** | Permissive | Faible |
| **LGPL** | Faible copyleft | Moyen — modifications de la lib doivent être partagées |
| **GPL v3** | Copyleft fort | **Élevé** — peut imposer la publication du code qui l'utilise |
| **AGPL v3** | Copyleft réseau | **Très élevé** — s'étend même aux SaaS |

Trivy peut produire un rapport des licences détectées (`trivy fs --license-full`). Pour une application destinée à une distribution commerciale, c'est une vérification à intégrer au pipeline.

### 8.6 Réglementations européennes pertinentes

Le module insiste sur l'importance du contexte réglementaire qui pousse l'adoption du DevSecOps. Trois textes européens sont à connaître :

| Règlement | Périmètre | Exigences DevSecOps |
|---|---|---|
| **NIS2** (2023) | Opérateurs de services essentiels et importants | Notification d'incidents, gestion des vulnérabilités, sécurité de la supply chain |
| **Cyber Resilience Act (CRA)** (2024) | Tout produit numérique mis sur le marché de l'UE | **SBOM obligatoire**, gestion des vulnérabilités sur tout le cycle de vie, mises à jour de sécurité gratuites |
| **AI Act** (2024) | Systèmes d'IA mis sur le marché de l'UE | Documentation, gestion des risques, robustesse, transparence |

À ces textes s'ajoutent **DORA** (Digital Operational Resilience Act, secteur financier) et bien sûr le **RGPD** pour les données personnelles. L'ensemble forme un cadre qui rend la mise en œuvre de pratiques DevSecOps **non négociable** pour beaucoup d'organisations.

### 8.7 Gouvernance — les rôles humains

Le DevSecOps n'est pas qu'une affaire d'outils. Le cours insiste sur deux rôles humains complémentaires :

- **Le RSSI (Responsable de la Sécurité des Systèmes d'Information)** : définit la stratégie de sécurité, les politiques, et supervise leur application. Il ne code pas, il pilote.
- **Le Security Champion** : un développeur **formé à la sécurité** qui sert de référent et de relais au sein de son équipe produit. C'est lui qui porte la culture sécurité au quotidien dans l'équipe.

Le triptyque RSSI ↔ Security Champion ↔ équipe de développement est ce qui permet à la sécurité de **s'incarner** dans le quotidien des équipes plutôt que de rester un document théorique.

### 8.8 GitOps et gestion des secrets

Deux sujets connexes méritent une mention rapide.

**GitOps** est une approche dans laquelle **Git devient la source de vérité unique** pour la configuration de l'infrastructure et des déploiements. Tout changement passe par une pull request ; un agent (ArgoCD, Flux) synchronise en continu l'état réel du cluster avec ce qui est déclaré dans Git. L'intérêt sécurité est immense : **traçabilité complète** (chaque modification est un commit signé), **principe d'immutabilité**, et possibilité d'appliquer un security gate (notre Conftest, par exemple) sur les manifests **avant** qu'ils ne soient appliqués au cluster.

**Gestion des secrets** : les secrets (tokens, mots de passe, clés privées) ne doivent **jamais** être en clair dans le code source ou dans les fichiers de configuration du pipeline. Les bonnes pratiques sont :

- utiliser les **GitHub Actions Secrets** (`${{ secrets.MY_TOKEN }}`) pour les variables sensibles du pipeline ;
- pour la production, utiliser un véritable **gestionnaire de secrets** : HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault ;
- ajouter un **scanner de secrets** (GitLeaks) au pipeline pour détecter les fuites accidentelles dans l'historique Git.

---

## 9. Limites du projet et axes d'amélioration

Ce projet, dans sa version livrée, couvre l'essentiel des demandes du sujet. Plusieurs **limites assumées** méritent d'être listées, ainsi que les améliorations qui les corrigeraient.

### 9.1 Limites

1. **Pas de blocage du pipeline** sur les CVE (`exit-code: 0`). Choix pédagogique pour produire un rapport complet, mais à inverser en production.
2. **Pas de SAST sur le code Python** — un Bandit ou un Semgrep aurait pu détecter des problèmes au niveau du code applicatif (utilisation d'`eval()`, secrets en dur, etc.).
3. **Pas de scan de secrets** — un GitLeaks ou un TruffleHog devrait être systématiquement intégré, surtout avec le principe « les secrets sont toujours bloquants ».
4. **Pas de DAST** — l'application n'est pas testée en cours d'exécution avec un OWASP ZAP ou un Nuclei.
5. **Pas de SBOM généré ni signé** — pas de Syft, pas de Cosign.
6. **Pas de tests unitaires applicatifs** — le pipeline ne vérifie pas que l'application fonctionne fonctionnellement.
7. **L'image n'est pas poussée** sur un registry — il n'y a donc pas de chaîne de confiance jusqu'au déploiement.
8. **Pas de déploiement effectif** sur un cluster Kubernetes — l'étape « Deploy » du pipeline est absente.

### 9.2 Axes d'amélioration concrets

Si l'on devait industrialiser ce pipeline, voici les chantiers à mener par ordre de priorité :

1. **Ajouter le secret scanning** avec GitLeaks dès le pre-commit (via `gitleaks/gitleaks-action@v2`). C'est le contrôle au meilleur rapport coût/bénéfice.
2. **Ajouter du SAST** avec Semgrep (`returntocorp/semgrep-action@v1` avec `config: p/security-audit`).
3. **Générer un SBOM** au format CycloneDX avec Syft (`anchore/sbom-action@v0`) et le publier comme artefact GitHub.
4. **Signer l'image** avec Cosign en mode keyless (signature OIDC) une fois poussée sur GHCR.
5. **Activer Dependabot** dans les paramètres du repo pour le suivi continu des CVE de dépendances.
6. **Passer en mode bloquant** sur les CVE CRITICAL avec correctif disponible.
7. **Atteindre SLSA niveau 2** en générant une attestation de provenance lors du build.

### 9.3 Modèle de maturité

Pour situer le projet, on peut s'appuyer sur le **modèle de maturité DevSecOps CI/CD** présenté dans le cours :

| Niveau | Caractéristiques | Notre projet |
|---|---|---|
| **Niveau 1 — Initial** | Quelques scans manuels, pas d'automatisation | — |
| **Niveau 2 — Reproductible** | Pipeline CI automatisé, scans à chaque build | ✅ Atteint |
| **Niveau 3 — Défini** | Security gates, SBOM, signature, métriques | 🔶 Partiellement (security gates oui sur le principe, SBOM/signature non) |
| **Niveau 4 — Géré** | Métriques DORA suivies, SLSA L3, threat modeling | — |
| **Niveau 5 — Optimisé** | Amélioration continue, IA pour la priorisation | — |

Notre projet atteint donc le **niveau 2** et entame le **niveau 3**. C'est un point de départ honorable pour une preuve de concept réalisée en ~12 heures.

---

## 10. Conclusion

Ce projet a permis de mettre en pratique l'essentiel des concepts du module **DevSecOps 5DVSCOPS** sur un cas réaliste et entièrement reproductible. À partir d'une simple application Flask volontairement vulnérable, nous avons construit un pipeline GitHub Actions qui enchaîne **6 contrôles de sécurité automatisés** couvrant trois angles complémentaires :

- les **dépendances applicatives** (Trivy FS),
- l'**image de conteneur** (Trivy image),
- les **manifests d'infrastructure** (yamllint, kube-linter, Conftest/Rego).

Le bonus Conftest démontre concrètement le principe de **Policy as Code** : une règle métier (« pas de pod en root ») est codée en Rego, versionnée dans le repo, et exécutée à chaque commit, exactement comme n'importe quel autre composant du système.

Le principal enseignement de ce projet n'est pas tant technique qu'**organisationnel**. La valeur du DevSecOps ne vient pas des outils pris isolément — chacun pris séparément ferait gagner peu — mais de leur **intégration dans le flux de travail quotidien** des développeurs. Ce qui transforme une checklist de sécurité en culture d'équipe, c'est l'**automatisation** et la **rapidité du feedback**. Un développeur qui voit ses CVE remontées dans la PR qu'il vient d'ouvrir corrige ; un développeur qui reçoit un rapport de pentest deux mois après n'a déjà plus le contexte en tête.

Le DevSecOps moderne s'inscrit en outre dans un **cadre réglementaire qui se durcit** (Cyber Resilience Act, NIS2, AI Act). Pour beaucoup d'organisations européennes, ce qui était hier une bonne pratique devient demain une obligation légale. Avoir un pipeline comme celui livré ici n'est donc plus un luxe mais un prérequis.

---

## Annexes

### Annexe A — Captures d'écran à inclure dans le rendu Teams

1. **Vue d'ensemble du run GitHub Actions** : tous les jobs avec leur statut.
2. **Logs du job `lint-dockerfile`** : sortie de hadolint.
3. **Logs du job `lint-yaml`** : sortie de yamllint et kube-linter.
4. **Logs du job `scan-dependencies`** : tableau Trivy avec les CVE Flask, Werkzeug, Jinja2.
5. **Logs du job `scan-image`** : tableau Trivy avec les CVE OS de l'image.
6. **Logs du job `policy-check`** : sortie de Conftest avec le `FAIL` sur runAsUser.
7. **Onglet `Security` → `Code scanning alerts`** : findings Trivy publiés au format SARIF.
8. **Fichier `policy/security.rego`** : contenu de la règle.

### Annexe B — Glossaire

| Terme | Définition |
|---|---|
| **CI/CD** | Continuous Integration / Continuous Deployment. Automatisation de l'intégration et du déploiement du code |
| **CVE** | Common Vulnerabilities and Exposures. Identifiant unique mondial d'une vulnérabilité publique |
| **CVSS** | Common Vulnerability Scoring System. Score standardisé de 0 à 10 mesurant la sévérité d'une vulnérabilité |
| **DAST** | Dynamic Application Security Testing. Test de l'application en cours d'exécution |
| **Dependency Confusion** | Attaque où un paquet malveillant public prend le dessus sur un paquet privé interne du même nom |
| **DevSecOps** | Culture d'intégration de la sécurité tout au long du cycle DevOps |
| **DORA** | DevOps Research and Assessment. Aussi : Digital Operational Resilience Act (UE, finance) |
| **GitOps** | Approche où Git est la source de vérité unique pour l'infrastructure et les déploiements |
| **IaC** | Infrastructure as Code. Définition de l'infrastructure sous forme de code versionné |
| **MTTR** | Mean Time To Remediate (vulnérabilités) ou To Recover (incidents) |
| **NVD** | National Vulnerability Database. Base de données de référence des CVE, gérée par le NIST |
| **OPA** | Open Policy Agent. Moteur de policy as code dont Rego est le langage |
| **PodSecurity Admission** | Mécanisme Kubernetes natif d'application des politiques de sécurité de pod |
| **Provenance** | Métadonnées vérifiables décrivant comment, quand et où un artefact a été produit |
| **Rego** | Langage déclaratif d'OPA pour écrire des politiques de sécurité |
| **RSSI** | Responsable de la Sécurité des SI |
| **SARIF** | Static Analysis Results Interchange Format. Format JSON standard pour les résultats d'outils d'analyse |
| **SAST** | Static Application Security Testing. Analyse statique du code source |
| **SBOM** | Software Bill of Materials. Inventaire exhaustif des composants d'un logiciel |
| **SCA** | Software Composition Analysis. Analyse des dépendances open source |
| **Security Champion** | Développeur formé à la sécurité, référent au sein de son équipe |
| **Security Gate** | Point de blocage automatique dans un pipeline CI/CD |
| **Shift-Left** | Principe de déplacer les contrôles de sécurité au plus tôt dans le cycle |
| **SLSA** | Supply chain Levels for Software Artifacts. Framework de maturité supply chain |
| **Typosquatting** | Publication de paquets malveillants avec des noms volontairement similaires à des paquets légitimes |
| **VEX** | Vulnerability Exploitability eXchange. Format pour documenter l'exploitabilité réelle des CVE |
| **Zero Trust** | Principe selon lequel aucune confiance implicite n'est accordée, même en interne |

### Annexe C — Bibliographie et ressources

- NIST SP 800-218 — Secure Software Development Framework (SSDF)
- OWASP DevSecOps Guideline — https://owasp.org/www-project-devsecops-guideline/
- DORA State of DevOps Report 2024
- CISA Software Supply Chain Security Guidance
- Executive Order 14028 (Improving the Nation's Cybersecurity, USA, 2021)
- Cyber Resilience Act — Règlement (UE) 2024/2847
- NIS2 — Directive (UE) 2022/2555
- Documentation Trivy — https://aquasecurity.github.io/trivy/
- Documentation Conftest — https://www.conftest.dev/
- Documentation OPA / Rego — https://www.openpolicyagent.org/docs/latest/
- kube-linter — https://docs.kubelinter.io/
- hadolint — https://github.com/hadolint/hadolint
- Sigstore (Cosign) — https://www.sigstore.dev/
- SLSA framework — https://slsa.dev/
- CycloneDX SBOM standard — https://cyclonedx.org/
- Snyk Open Source Security Report 2024
- GitLab DevSecOps Survey 2024

### Annexe D — Auto-évaluation par rapport aux quiz du module

Cette annexe reprend les notions évaluées dans les quiz des 4 modules du cours et indique où chacune est traitée dans le projet ou dans ce rapport. Elle sert de **grille de couverture** pour vérifier que toutes les notions clés du cours sont mobilisées par le projet.

**Module « Vue d'ensemble »**

| Notion | Traitement |
|---|---|
| Principe du Shift-Left | § 2.2 |
| MTTR (Mean Time To Remediate) | § 2.5 |
| SAST — analyse de code sans exécution | § 2.4 |
| GitLeaks pour les secrets | § 2.4, § 9 |
| Différence SAST / DAST | § 2.4 |
| SBOM — Software Bill of Materials | § 8.2 et glossaire |
| SLSA — 4 niveaux de maturité supply chain | § 8.3 |
| Deployment Frequency (DORA) | § 2.5 |
| Zero Trust | § 2.3 |
| Cyber Resilience Act | § 8.6 |
| Security Champion | § 8.7 |
| Rôle du RSSI | § 8.7 |
| IaC — Infrastructure as Code | § 4 et § 6.3 |
| CycloneDX (format SBOM) | § 8.2 |
| Directive NIS2 | § 8.6 |

**Module « CI/CD »**

| Notion | Traitement |
|---|---|
| Acronyme CI/CD | § 3 et glossaire |
| Rôle d'un security gate | § 5.6 |
| GitLeaks (secrets dans l'historique Git) | § 9 |
| GitHub Actions vs GitLab CI | § 4 (justification du choix) |
| Shift-Left appliqué au CI/CD | § 2.2 |
| Format SARIF | § 3.2 (choix 4) |
| Trivy `--exit-code` pour bloquer le pipeline | § 5.6 |
| Runner CI/CD | § 3 |
| Conteneurs et reproductibilité | § 6.2 |
| Lead Time for Changes | § 2.5 |
| GitOps | § 8.8 |
| Cosign / Sigstore — signature d'images | § 8.2, § 9 |
| Notion d'artefact | § 5.2 |
| Checkov — IaC scanning | § 2.4 |
| Gestion des secrets dans le pipeline | § 8.8 |

**Module « Supply chain »**

| Notion | Traitement |
|---|---|
| Définition de la supply chain logicielle | § 8.1 |
| SolarWinds (2020) | § 8.1 |
| SBOM (acronyme) | § 8.2 et glossaire |
| Framework SLSA | § 8.3 |
| Log4Shell | § 8.1 |
| Syft pour générer un SBOM | § 9 |
| Typosquatting | § 8.1 |
| CycloneDX et VEX | § 8.2 |
| Dependency confusion | § 8.1 |
| Sigstore (Cosign / Rekor / Fulcio) | § 8.2 |
| Cyber Resilience Act et SBOM obligatoire | § 8.6 |
| Provenance d'un artefact | § 8.3 et glossaire |
| XZ Utils (2024) | § 8.1 |
| SLSA L3 — builds hermétiques | § 8.3 |
| Pinning des dépendances | § 6.1, § 8.1 |

**Module « SCA »**

| Notion | Traitement |
|---|---|
| Acronyme SCA | § 2.4 et glossaire |
| NVD du NIST | § 6.1 |
| Trivy — scanner unifié | § 4.1 |
| Score CVSS | § 6.1 et glossaire |
| Vulnérabilité ≠ exposition | § 6.1 et § 8.4 |
| GitHub Dependabot | § 6.1 |
| Dépendances transitives | § 6.1, § 8.4 |
| Licences GPL v3 (copyleft fort) | § 8.5 |
| OWASP Dependency-Check (Maven) | § 4.1 |
| Faux positifs en SCA | § 8.4 |
| Snyk (commercial) | § 4.1 |
| Bonne pratique de gestion des CVE (priorisation) | § 5.6 |
| Limite du SCA (ne couvre pas le code propriétaire) | § 8.4 |
| Format `package.json` | § 2.4 et § 8.4 |
| MTTR pour mesurer l'efficacité d'un programme SCA | § 2.5 |

---

_Fin du rapport._
