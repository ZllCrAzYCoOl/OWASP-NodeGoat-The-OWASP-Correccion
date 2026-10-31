# Dónde va cada evidencia en el informe

Convención: guarda las capturas en `evidencias/capturas/` con el nombre indicado. Cada captura debe mostrar
la fecha/hora y, en lo posible, el comando completo. Enmascara el ID de cuenta de AWS, IP personales y tokens.

| Parte del informe | Qué hay que poner | Cómo se obtiene | Archivo |
|---|---|---|---|
| Módulo 1: URL del repositorio y commit de la línea base | URL de tu repo y hash de la etiqueta `baseline` | `git rev-parse baseline` | `entorno-baseline.txt` |
| **Figura 1** | Ejecución de los 3 análisis sobre la línea base y resumen | Terminal con `scan-code.sh baseline` + `consolidate.py --dir reports/baseline` | `fig1-analisis-baseline.png` |
| **Figura 2** | Diff de un hallazgo corregido + nuevo análisis sin ese hallazgo | `git show <commit>` o la vista "Files changed"; luego el resumen de `after` | `fig2-antes-despues.png` |
| **Tabla 3** | Conteos por herramienta/severidad, % de mitigación | `consolidate.py --compare reports/baseline reports/after` (sale en `reports/after/comparacion.md`) | `comparacion.md` |
| Análisis de Tabla 3 | % obtenido, herramientas con más hallazgos, no corregidos | `hallazgos.csv` (columna herramienta/severidad) | `hallazgos.csv` |
| **Figura 3** | Una ejecución del flujo con el estado de cada verificación | Pestaña Actions de GitHub (jobs code, infra, gate, publish) | `fig3-github-actions.png` |
| **Tabla 4** | Hallazgos críticos+altos iniciales y finales de Hadolint, Trivy, ZAP; estado del flujo | Sección "Tabla 4" de `comparacion.md`; estado = aprobado/bloqueado de Actions | `comparacion.md` |
| Tabla A1 (versiones y configuración) | Versiones, reglas, entorno y fecha | `collect-evidence.sh` | `entorno-*.txt` |
| Tabla A2 | Id, herramienta, severidad, regla/CWE/CVE, ubicación, commit, verificación | `hallazgos.csv` + `git log --oneline` | `hallazgos.csv` |
| Tabla B1 | Versiones, umbral de bloqueo (críticos), entorno | `versions.env`, `devsecops.yml`, `entorno-*.txt` | `scripts/versions.env` |
| Tabla B2 | Enlace por archivo al repositorio | URL permanente con el commit: `https://github.com/<usuario>/<repo>/blob/<commit>/Dockerfile` (igual para docker-compose.yml, `terraform/`, `.github/workflows/devsecops.yml`) | — |
| Módulo 3 y Tabla C1: despliegue funcionando | Servicio ECS activo, tarea RUNNING, aplicación abierta en el navegador | Consola ECS > Clusters > nodegoat; `aws-task-ip.sh` | `c1-ecs-servicio.png`, `c1-app-navegador.png` |
| C1: identidad (IAM) | Rol de ejecución con política administrada, rol de la tarea sin permisos, rol de GitHub con OIDC acotado al repo | Consola IAM; `evidencias/aws/iam-*.json` | `c1-iam.png` |
| C1: red (VPC y grupos de seguridad) | Regla de entrada 4000 solo desde tu IP; salida 443; grupo por defecto vacío | Consola VPC > Security groups; `security-group.json` | `c1-red.png` |
| C1: cifrado (KMS) | Clave con rotación activa; log groups y ECR cifrados con ella | Consola KMS; `kms-key.json`, `kms-rotation.json`, `ecr-repo.json` | `c1-kms.png` |
| C1: registro de eventos | CloudTrail activo y multi-región con validación de archivos; log group de la app con eventos; flow logs | Consola CloudTrail y CloudWatch; `cloudtrail-status.json`, `log-group.json` | `c1-logs.png` |
| C1: postura de seguridad | Reporte de Prowler o Scout Suite y hallazgos relevantes | `reports/prowler/*.html` | `prowler.html` |
| Resultados globales (% en 3 capas) | Porcentaje de mitigación global y nuevos hallazgos introducidos | Última línea de `comparacion.md` | `comparacion.md` |

## Reglas para que la evidencia sea creíble
1. Los números del informe salen de los reportes JSON del repositorio, no de capturas escritas a mano.
2. Cada cifra debe poder rastrearse: herramienta, versión, regla y fecha (`entorno-*.txt`).
3. Gitleaks se ejecuta con `--redact`: no subas secretos reales al repositorio ni a las capturas.
4. Si un hallazgo se descarta como falso positivo, queda en `evidencias/falsos_positivos.json` con su justificación.
5. Completa los campos en amarillo del informe (URL/commit, figuras, Tablas 3 y 4, análisis y conclusiones) solo con datos de estas ejecuciones.
