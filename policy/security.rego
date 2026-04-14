# Politique de sécurité Conftest / OPA Rego
#
# Règles appliquées sur les manifests Kubernetes :
#   1. Un Pod/Deployment ne doit pas tourner en tant que root (UID 0).
#   2. runAsNonRoot doit être explicitement vrai (defense in depth).
#
# Conftest charge automatiquement les fichiers .rego du dossier passé
# en argument (par défaut ./policy).

package main

# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

# On ne s'intéresse qu'aux ressources qui décrivent des Pods.
is_pod_spec_owner {
    input.kind == "Deployment"
}
is_pod_spec_owner {
    input.kind == "StatefulSet"
}
is_pod_spec_owner {
    input.kind == "DaemonSet"
}
is_pod_spec_owner {
    input.kind == "Pod"
}

# Récupère la spec du pod, qu'elle soit à la racine (Pod) ou sous template (Deployment...)
pod_spec = spec {
    input.kind == "Pod"
    spec := input.spec
}
pod_spec = spec {
    input.kind != "Pod"
    spec := input.spec.template.spec
}

# ----------------------------------------------------------------------------
# Règle 1 : interdiction de runAsUser = 0 (root) sur un conteneur
# ----------------------------------------------------------------------------
deny[msg] {
    is_pod_spec_owner
    container := pod_spec.containers[_]
    container.securityContext.runAsUser == 0
    msg := sprintf(
        "Le conteneur '%s' tourne en tant que root (runAsUser: 0). Interdit.",
        [container.name],
    )
}

# ----------------------------------------------------------------------------
# Règle 2 : interdiction de runAsUser = 0 au niveau du pod
# ----------------------------------------------------------------------------
deny[msg] {
    is_pod_spec_owner
    pod_spec.securityContext.runAsUser == 0
    msg := "Le Pod tourne en tant que root au niveau du podSecurityContext. Interdit."
}

# ----------------------------------------------------------------------------
# Règle 3 (warning) : runAsNonRoot devrait être explicitement à true
# ----------------------------------------------------------------------------
warn[msg] {
    is_pod_spec_owner
    container := pod_spec.containers[_]
    not container.securityContext.runAsNonRoot
    msg := sprintf(
        "Le conteneur '%s' ne déclare pas explicitement runAsNonRoot: true (recommandé).",
        [container.name],
    )
}
