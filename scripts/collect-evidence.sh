#!/usr/bin/env bash
# Registra el entorno de ejecución para la Tabla A1/B1 ("Versiones y configuración").
# Uso: ./scripts/collect-evidence.sh <etiqueta>
set -uo pipefail
cd "$(dirname "$0")/.."
source scripts/versions.env
L="${1:-local}"
F="evidencias/entorno-$L.txt"
{
  echo "Fecha (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "Sistema: $(uname -a)"
  echo "Docker: $(docker --version)"
  echo "Compose: $(docker compose version 2>/dev/null)"
  echo
  echo "== Git =="
  echo "Remoto: $(git remote get-url origin 2>/dev/null)"
  echo "Rama: $(git rev-parse --abbrev-ref HEAD 2>/dev/null)"
  echo "Commit: $(git rev-parse HEAD 2>/dev/null)"
  echo "Etiquetas en este commit: $(git tag --points-at HEAD 2>/dev/null | tr '\n' ' ')"
  echo
  echo "== Herramientas (imagen y digest) =="
  for v in SEMGREP_IMAGE DEPCHECK_IMAGE GITLEAKS_IMAGE HADOLINT_IMAGE TRIVY_IMAGE ZAP_IMAGE; do
    img="${!v}"
    d="$(docker image inspect --format '{{index .RepoDigests 0}}' "$img" 2>/dev/null || echo 'no descargada')"
    echo "$v=$img  digest=$d"
  done
  echo
  echo "== Reglas de Semgrep =="
  echo "p/javascript, p/nodejs, p/owasp-top-ten"
  echo
  echo "== Huellas SHA-256 de los reportes de reports/$L =="
  (cd "reports/$L" 2>/dev/null && sha256sum *.json *.html 2>/dev/null)
} | tee "$F"
echo "Guardado en $F"
