# Dockerfile volontairement "naïf" pour exposer plusieurs mauvaises pratiques
# que les outils de scan vont remonter (image base ancienne, run as root,
# pas de multi-stage, pas de pinning de version OS). Le rapport explique
# comment l'améliorer.

FROM python:3.9-slim

# Bonne pratique : créer un répertoire de travail dédié
WORKDIR /app

# Copie des dépendances en premier pour profiter du cache de couches
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copie du code applicatif
COPY app/ .

EXPOSE 5000

# /!\ Pas de USER non-root => sera détecté par hadolint et par Conftest côté K8s
CMD ["python", "app.py"]
