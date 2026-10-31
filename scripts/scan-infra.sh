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
docker build -t "nodegoat:$L" . || {
  echo "::error::docker build falló. Causa habitual: package-lock.json desincronizado con package.json (npm ci). Regenera y commitea el lock."
  exit 1
}

echo "== Trivy: imagen ($TRIVY_IMAGE) =="
docker save "nodegoat:$L" -o "$OUT/imagen.tar"
docker run --rm --user "$UIDGID" -e TRIVY_CACHE_DIR=/cache -v "$PWD/.trivy-cache:/cache" -v "$PWD/$OUT:/work" \
  "$TRIVY_IMAGE" image --input /work/imagen.tar --format json --output /work/trivy-image.json || true
rm -f "$OUT/imagen.tar"

echo "== Trivy: configuración (Dockerfile, Compose, Terraform) =="
TRIVY_IGN=()
[ -f .trivyignore ] && TRIVY_IGN=(--ignorefile /work/.trivyignore)
docker run --rm --user "$UIDGID" -e TRIVY_CACHE_DIR=/cache -v "$PWD/.trivy-cache:/cache" -v "$PWD:/work" \
  "$TRIVY_IMAGE" config --skip-dirs reports --skip-dirs evidencias --skip-dirs node_modules \
  "${TRIVY_IGN[@]}" --format json --output "/work/$OUT/trivy-config.json" /work || true

echo "== ZAP baseline ($ZAP_IMAGE) =="
if [ ! -f .env ]; then
  echo "Creando .env temporal con credenciales aleatorias"
  printf 'MONGO_USER=ngadmin\nMONGO_PASSWORD=%s\nCOOKIE_SECRET=%s\nCRYPTO_KEY=%s\n' \
    "$(openssl rand -hex 16)" "$(openssl rand -hex 32)" "$(openssl rand -hex 32)" > .env
fi
docker compose -p "$PROJECT" up -d --build --wait || {
  echo "::error::La aplicación no quedó sana. Últimas líneas del log de web:"
  docker compose -p "$PROJECT" logs web --tail 60
  docker compose -p "$PROJECT" down -v
  exit 1
}
# No se usa "npm run db:seed": necesita cross-env y grunt (devDependencies), que la imagen de producción no incluye.
docker compose -p "$PROJECT" run --rm web node artifacts/db-reset.js || echo "AVISO: falló la siembra de la base de datos (artifacts/db-reset.js)"
chmod 777 "$OUT"   # el contenedor de ZAP escribe como otro usuario
echo "== ZAP baseline anónimo =="
docker run --rm --network "${PROJECT}_default" -v "$PWD/$OUT:/zap/wrk:rw" "$ZAP_IMAGE" \
  zap-baseline.py -t http://web:4000 -J zap-anon.json -r zap-anon.html -I || true

echo "== ZAP baseline autenticado (inicia sesión con curl y pasa la cookie a ZAP) =="
ZAP_USER="${ZAP_USER:-admin}"; ZAP_PASS="${ZAP_PASS:-Admin_123}"   # usuario de prueba de la siembra (no es un secreto real)
JAR="$(mktemp)"
CSRF="$(curl -s -c "$JAR" -b "$JAR" http://127.0.0.1:4000/login | grep -o 'name="_csrf" value="[^"]*"' | head -1 | sed 's/.*value="//; s/"$//')"
curl -s -o /dev/null -c "$JAR" -b "$JAR" --data-urlencode "_csrf=$CSRF" \
  --data-urlencode "userName=$ZAP_USER" --data-urlencode "password=$ZAP_PASS" http://127.0.0.1:4000/login
COOKIE="$(awk -F'\t' '$6=="sessionId" || $6=="connect.sid" {n=$6; v=$7} END{if (n!="") print n"="v}' "$JAR")"
rm -f "$JAR"
if [ -z "$COOKIE" ]; then
  echo "AVISO: no se obtuvo la cookie de sesión; zap.json queda igual al escaneo anónimo"
  cp "$OUT/zap-anon.json" "$OUT/zap.json" 2>/dev/null || true
else
  ZOPTS="-config replacer.full_list(0).description=sesion -config replacer.full_list(0).enabled=true"
  ZOPTS+=" -config replacer.full_list(0).matchtype=REQ_HEADER -config replacer.full_list(0).matchstr=Cookie"
  ZOPTS+=" -config replacer.full_list(0).regex=false -config replacer.full_list(0).replacement=$COOKIE"
  ZOPTS+=" -config globalexcludeurl.url_list.url(0).regex=.*/logout.* -config globalexcludeurl.url_list.url(0).enabled=true"
  docker run --rm --network "${PROJECT}_default" -v "$PWD/$OUT:/zap/wrk:rw" "$ZAP_IMAGE" \
    zap-baseline.py -t http://web:4000/dashboard -J zap.json -r zap.html -I -z "$ZOPTS" || true
fi
docker compose -p "$PROJECT" down -v

echo "Listo. Reportes en $OUT/"
ls -la "$OUT"
