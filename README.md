## 📝 Vulnérabilités intentionnelles

Ce projet contient **volontairement** des vulnérabilités pour démontrer la
détection par les outils :

- Dépendances Python obsolètes (Flask 2.0.1, Werkzeug 2.0.1, etc.)
- Image de base Python 3.9-slim avec CVE OS connues
- Conteneur tournant en `root` (Dockerfile + manifest K8s)
- Pas de `securityContext` durci, pas de `readOnlyRootFilesystem`

Voir `RAPPORT.md` pour l'analyse complète et les recommandations.
