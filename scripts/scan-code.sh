#!/usr/bin/env bash
# Capa de código: Semgrep + OWASP Dependency-Check + Gitleaks.
# Uso: ./scripts/scan-code.sh <etiqueta>     (baseline | after | ci | local)
# Los reportes quedan en reports/<etiqueta>/ en formato JSON.
set -uo pipefail
cd "$(dirname "$0")/.."
source scripts/versions.env

L="${1:-local}"
OUT="reports/$L"
mkdir -p "$OUT" .dc-data
UIDGID="$(id -u):$(id -g)"

echo "== Semgrep ($SEMGREP_IMAGE) =="
docker run --rm --user "$UIDGID" -v "$PWD:/src" -w /src "$SEMGREP_IMAGE" \
  semgrep scan --config p/javascript --config p/nodejs --config p/owasp-top-ten \
  --metrics=off --exclude reports --exclude evidencias --exclude node_modules --exclude terraform \
  --json --output "$OUT/semgrep.json" . || true

echo "== OWASP Dependency-Check ($DEPCHECK_IMAGE) =="
# La clave de la NVD (gratuita) acelera mucho la descarga de la base de datos: https://nvd.nist.gov/developers/request-an-api-key
NVD_ARG=()
[ -n "${NVD_API_KEY:-}" ] && NVD_ARG=(--nvdApiKey "$NVD_API_KEY")
docker run --rm --user "$UIDGID" -v "$PWD:/src" -v "$PWD/.dc-data:/usr/share/dependency-check/data" \
  "$DEPCHECK_IMAGE" --project NodeGoat --scan /src --format JSON --out "/src/$OUT" \
  --exclude "**/reports/**" --exclude "**/evidencias/**" "${NVD_ARG[@]}" || true
# Dependency-Check escribe dependency-check-report.json; consolidate.py lo busca con ese nombre.

echo "== Gitleaks ($GITLEAKS_IMAGE) =="
# --redact: el reporte no guarda el secreto en claro (los reportes se versionan en el repositorio)
docker run --rm --user "$UIDGID" -v "$PWD:/repo" "$GITLEAKS_IMAGE" detect --source /repo \
  --report-format json --report-path "/repo/$OUT/gitleaks.json" --redact --exit-code 0 || true

echo "Listo. Reportes en $OUT/"
ls -la "$OUT"
