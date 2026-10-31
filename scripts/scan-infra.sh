#!/usr/bin/env bash
# Capa de infraestructura: Hadolint + Trivy (imagen y configuración) + ZAP baseline (pasivo).
# Uso: ./scripts/scan-infra.sh <etiqueta>
set -uo pipefail
cd "$(dirname "$0")/.."
source scripts/versions.env

L="${1:-local}"
OUT="reports/$L"
mkdir -p "$OUT" .trivy-cache
UIDGID="$(id -u):$(id -g)"
PROJECT=ng

echo "== Hadolint ($HADOLINT_IMAGE) =="
docker run --rm -i -v "$PWD/.hadolint.yaml:/.config/hadolint.yaml:ro" "$HADOLINT_IMAGE" hadolint -f json - < Dockerfile > "$OUT/hadolint.json" || true

echo "== Construyendo la imagen =="
docker build -t "nodegoat:$L" .

echo "== Trivy: imagen ($TRIVY_IMAGE) =="
docker save "nodegoat:$L" -o "$OUT/imagen.tar"
docker run --rm --user "$UIDGID" -e TRIVY_CACHE_DIR=/cache -v "$PWD/.trivy-cache:/cache" -v "$PWD/$OUT:/work" \
  "$TRIVY_IMAGE" image --input /work/imagen.tar --format json --output /work/trivy-image.json || true
rm -f "$OUT/imagen.tar"

echo "== Trivy: configuración (Dockerfile, Compose, Terraform) =="
docker run --rm --user "$UIDGID" -e TRIVY_CACHE_DIR=/cache -v "$PWD/.trivy-cache:/cache" -v "$PWD:/work" \
  "$TRIVY_IMAGE" config --skip-dirs reports --skip-dirs evidencias --skip-dirs node_modules \
  --format json --output "/work/$OUT/trivy-config.json" /work || true

echo "== ZAP baseline ($ZAP_IMAGE) =="
if [ ! -f .env ]; then
  echo "Creando .env temporal con credenciales aleatorias"
  printf 'MONGO_USER=ngadmin\nMONGO_PASSWORD=%s\n' "$(openssl rand -hex 16)" > .env
fi
docker compose -p "$PROJECT" up -d --build --wait
docker compose -p "$PROJECT" run --rm web npm run db:seed || echo "AVISO: revisa el nombre del script de siembra en package.json"
chmod 777 "$OUT"   # el contenedor de ZAP escribe como otro usuario
docker run --rm --network "${PROJECT}_default" -v "$PWD/$OUT:/zap/wrk:rw" "$ZAP_IMAGE" \
  zap-baseline.py -t http://web:4000 -J zap.json -r zap.html -I || true
docker compose -p "$PROJECT" down -v

echo "Listo. Reportes en $OUT/"
ls -la "$OUT"
