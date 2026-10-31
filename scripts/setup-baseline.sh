#!/usr/bin/env bash
# Paso 0: obtener NodeGoat, crear TU repositorio y marcar la línea base.
# Uso: ./scripts/setup-baseline.sh https://github.com/<usuario>/nodegoat-secure.git
set -euo pipefail
DEST_URL="${1:?Indica la URL de tu repositorio vacío}"
git clone https://github.com/OWASP/NodeGoat.git nodegoat-work
cd nodegoat-work
git remote rename origin upstream
git remote add origin "$DEST_URL"
git tag -a baseline -m "Línea base: estado original de NodeGoat"
git push -u origin HEAD
git push origin baseline
echo "Línea base: $(git rev-parse HEAD)  (etiqueta: baseline)"
echo "Ahora copia dentro de nodegoat-work el contenido de este kit (Dockerfile, scripts/, terraform/, .github/...)."
echo "OJO: el commit de la línea base debe ser SOLO el código original; el kit se agrega en un commit posterior."
