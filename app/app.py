"""
Petite API Flask de démonstration pour le projet DevSecOps.
Volontairement minimaliste — l'objectif n'est pas le code applicatif mais
de fournir une cible représentative pour les scans de sécurité.
"""
from flask import Flask, jsonify, request
import os

app = Flask(__name__)


@app.route("/")
def index():
    return jsonify(
        {
            "service": "devsecops-demo-api",
            "status": "ok",
            "version": os.environ.get("APP_VERSION", "0.1.0"),
        }
    )


@app.route("/health")
def health():
    # Endpoint utilisé par les liveness/readiness probes Kubernetes
    return jsonify({"status": "healthy"}), 200


@app.route("/echo", methods=["POST"])
def echo():
    data = request.get_json(silent=True) or {}
    return jsonify({"received": data}), 200


if __name__ == "__main__":
    # 0.0.0.0 nécessaire dans un conteneur pour être joignable depuis l'hôte
    app.run(host="0.0.0.0", port=5000)
