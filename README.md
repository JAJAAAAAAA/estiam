# DevSecOps Demo — Pipeline CI/CD sécurisé

Projet réalisé dans le cadre du module **5DVSCOPS 2025/2026**.

## 🎯 Objectif

Mettre en place un pipeline GitHub Actions intégrant des contrôles de sécurité
sur une petite API Flask conteneurisée et déployable sur Kubernetes.

## 📁 Structure du dépôt

```
.
├── app/                       Application Flask
│   ├── app.py
│   └── requirements.txt       (volontairement vulnérable)
├── Dockerfile                 (volontairement vulnérable)
├── k8s/
│   ├── deployment.yaml        (volontairement vulnérable - runAsUser: 0)
│   └── service.yaml
├── policy/
│   └── security.rego          Règle Conftest interdisant l'exécution en root
├── .github/workflows/
│   └── ci.yml                 Pipeline DevSecOps
├── RAPPORT.md                 Rapport synthétique
└── README.md
```

## ⚙️ Pipeline DevSecOps

Le pipeline s'exécute automatiquement à chaque push sur `main` ou pull request.
Il enchaîne 6 jobs :

| # | Job | Outil | Rôle |
|---|---|---|---|
| 1 | `lint-dockerfile` | hadolint | Vérifie les bonnes pratiques Dockerfile |
| 2 | `lint-yaml` | yamllint + kube-linter | Vérifie syntaxe et bonnes pratiques K8s |
| 3 | `build-image` | docker buildx | Construit l'image Docker |
| 4 | `scan-dependencies` | Trivy FS | Scanne `requirements.txt` (CVE) |
| 5 | `scan-image` | Trivy image | Scanne l'image Docker (OS + libs) |
| 6 | `policy-check` | Conftest / Rego | Applique la politique de sécurité |

Les rapports Trivy au format SARIF sont publiés dans l'onglet **Security** du
dépôt GitHub.


## 📝 Vulnérabilités intentionnelles

Ce projet contient **volontairement** des vulnérabilités pour démontrer la
détection par les outils :

- Dépendances Python obsolètes (Flask 2.0.1, Werkzeug 2.0.1, etc.)
- Image de base Python 3.9-slim avec CVE OS connues
- Conteneur tournant en `root` (Dockerfile + manifest K8s)
- Pas de `securityContext` durci, pas de `readOnlyRootFilesystem`

Voir `RAPPORT.md` pour l'analyse complète et les recommandations.
