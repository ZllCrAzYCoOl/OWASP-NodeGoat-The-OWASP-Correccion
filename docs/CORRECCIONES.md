# Correcciones de seguridad aplicadas a NodeGoat

Cada fila es un commit sugerido (`fix(A2): ...`) para la columna "Corrección aplicada (commit)" de la Tabla A2.
Hagan los commits en este orden y uno por fila, para que cada corrección quede trazable.

| # | Categoría OWASP | Archivo(s) | Corrección | Cómo comprobarla |
|---|---|---|---|---|
| 1 | A5 / A6 Secretos en el código | `config/env/all.js`, `config/env/development.js`, `config/env/test.js` | `cookieSecret`, `cryptoKey` y la clave de ZAP salen de variables de entorno (`COOKIE_SECRET`, `CRYPTO_KEY`, `ZAP_API_KEY`); en producción la app no arranca sin ellas | Gitleaks sin hallazgos; la app falla con un mensaje claro si falta la variable |
| 2 | A6 Exposición en registros | `config/config.js`, `server.js` | El registro de arranque oculta secretos y la cadena de conexión; el error de conexión ya no imprime la URL con la contraseña | `docker compose logs web` no muestra la contraseña de Mongo |
| 3 | A1-1 Inyección SSJS | `app/routes/contributions.js` | `eval()` reemplazado por `parseInt(valor, 10)` | Semgrep: desaparece la regla de `eval`; en /contributions, `1+1` se rechaza |
| 4 | A1-2 Inyección NoSQL | `app/data/allocations-dao.js` | Se elimina `$where`; el umbral se valida (0–99) y se consulta con `$gt`. También se corrige un doble `callback` | `/allocations/2?threshold=0';while(true){}'` devuelve error y no cuelga |
| 5 | A1-3 Inyección en logs | `app/routes/session.js` | Se eliminan saltos de línea del dato registrado | Un usuario con `%0d%0a` no genera líneas falsas en el log |
| 6 | A2-1 Contraseñas | `app/data/user-dao.js`, `artifacts/db-reset.js` | Contraseñas con hash y sal (`bcryptjs`); la siembra también las guarda con hash; se rechazan objetos en el login (NoSQL) | En Mongo, `password` empieza por `$2a$` |
| 7 | A2-2 Autenticación y sesión | `app/routes/session.js` | Mensaje de error idéntico, regeneración de sesión al iniciar sesión, política de contraseña 8–18 con mayúscula, minúscula y número | Con `admin` correcto/incorrecto el mensaje es el mismo |
| 8 | A3 XSS | `server.js`, `app/routes/profile.js`, `app/routes/research.js`, `app/views/memos.html` | Escape automático de plantillas, solo URL http(s) en el sitio web, salida escapada en investigación, `marked` con sanitización | ZAP/Semgrep: menos alertas de XSS; `<script>` en un memo se ve como texto |
| 9 | A4 Referencia directa insegura | `app/routes/allocations.js` | El usuario sale de la sesión y no de la URL | `/allocations/1` con `user1` muestra solo sus datos |
| 10 | A5 Configuración | `server.js` | Cookie `sessionId` HttpOnly + SameSite + caducidad, sin `x-powered-by`, cabeceras (CSP, X-Frame-Options, nosniff, Referrer-Policy) | ZAP: desaparecen alertas de cabeceras y cookies |
| 11 | A6 Datos sensibles | `app/data/profile-dao.js` | SSN, fecha de nacimiento y datos bancarios cifrados con AES-256-GCM (IV aleatorio, clave de `CRYPTO_KEY`) | En Mongo, `ssn` se ve como `hex:hex:hex`; en pantalla se ve en claro |
| 12 | A7 Control de acceso | `app/routes/index.js` | `/benefits` solo para administradores | `user1` abriendo `/benefits` es redirigido |
| 13 | A8 CSRF | `server.js`, `app/views/benefits.html`, `app/views/memos.html` | `csurf` activado; token en todos los formularios | Un POST sin `_csrf` devuelve 403 |
| 14 | A10 Redirección abierta / SSRF | `app/routes/index.js`, `app/routes/research.js` | `/learn` solo acepta HTTPS a hosts permitidos; /research usa una URL base fija y valida el símbolo | `/learn?url=https://evil.com` devuelve 400 |
| 15 | A9 Componentes | `package.json` (y `package-lock.json`) | Ver abajo | `npm audit --omit=dev`, Dependency-Check y Trivy |
| 16 | Infraestructura | `docker-compose.yml`, `.env.example`, `terraform/*`, `.trivyignore` | Secretos de la app por entorno / Secrets Manager (KMS); excepción documentada para la salida 443 | Trivy config sin críticos |

## Dependencias (A9): qué cambió y por qué

El 90 % de los 23 críticos viene de dos fuentes:

- **`forever`** (no se usa: la app arranca con `node server.js`) arrastraba `chokidar`, `set-value`, `mixin-deep`, `fsevents`, `node-pre-gyp`/`tar` y `minimist` viejos. Se elimina.
- **Herramientas de desarrollo de 2016–2019** (`cypress` 3, `mocha` 2, `grunt-*`, `nodemon` 1, `selenium-webdriver`, `zaproxy`, `grunt-retire`): traen `handlebars`, `babel-traverse`, `json-schema`, `growl`, `getobject`, `lodash` 4.17.11. Se retiran porque el análisis de seguridad lo hace ahora el pipeline (Semgrep, Dependency-Check, Gitleaks, Trivy, ZAP). `db:seed` ya no usa Grunt: es `node artifacts/db-reset.js`.
- **`mongodb` 2.x → 3.7** (trae `bson` ≥ 1.1.4, que corrige CVE-2020-7610), **`marked` 0.3.5 → 4.3**, **`needle` 2.2.4 → 3.x**, **`bcrypt-nodejs` → `bcryptjs`**, y se quitan `underscore` (solo se importaba sin usar), `helmet`, `node-esapi` y `dont-sniff-mimetype` (reemplazados por código propio).

Riesgos que quedan y deben decirse en el informe: `swig` 1.4.2 no tiene mantenimiento (sin versión corregida), la imagen base y `mongo:4.4` están fuera de soporte, y la aplicación se sirve por HTTP (HTTPS requeriría un balanceador con certificado).

Opcional: si no van a usar más las pruebas heredadas, eliminen `Gruntfile.js`, `cypress.json`, `nodemon.json`, `test/` y `.travis.yml` con `git rm`.

## Cómo aplicarlo (en este orden)

1. Copien los archivos del paquete sobre el proyecto, respetando las rutas.
2. **Regeneren el lock (obligatorio; el Dockerfile usa `npm ci`):**
   ```powershell
   Remove-Item -Recurse -Force node_modules -ErrorAction SilentlyContinue
   Remove-Item package-lock.json
   npm install
   npm audit --omit=dev
   ```
3. Agreguen `COOKIE_SECRET` y `CRYPTO_KEY` al `.env` (con `.env.example` como guía):
   ```powershell
   -join ((48..57)+(65..90)+(97..122) | Get-Random -Count 48 | ForEach-Object {[char]$_})
   ```
   Repítanlo para cada clave.
4. Prueben local: `docker compose down -v; docker compose up -d --build --wait; docker compose run --rm web node artifacts/db-reset.js`. Entren con `admin` / `Admin_123`, y prueben contribuciones, perfil, memos y beneficios.
5. Hagan los commits (uno por fila de la tabla) y suban. Revisen Actions.
6. Si Trivy aún marca críticos/altos del sistema operativo o de Node, suban la base: `--build-arg NODE_TAG=22-alpine` en `docker build` (o cambien el `ARG` del Dockerfile), y repitan la prueba del paso 4.

## Línea base (imprescindible para la Tabla 3)

Hoy no existe la etiqueta `baseline` ni hay reportes en `reports/baseline`. Sin ellos no hay porcentaje de mitigación. El commit original es `057c952` (Cargue del proyecto original).

```powershell
git tag -a baseline 057c952 -m "Línea base: NodeGoat original"
git push origin baseline
git worktree add ..\ng-baseline baseline
Copy-Item -Recurse scripts, .semgrepignore, .hadolint.yaml, .trivyignore ..\ng-baseline
```
En WSL, dentro de `ng-baseline`: `./scripts/scan-code.sh baseline` y `./scripts/scan-infra.sh baseline`. Copien `reports/baseline` al proyecto y hagan commit. Hagan la misma ejecución sobre el código final como `after` y comparen:

```bash
python3 scripts/consolidate.py --compare reports/baseline reports/after
```

Los 23 críticos que vieron hoy son el estado actual de su rama, no la línea base.
