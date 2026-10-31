#!/usr/bin/env bash
# Guarda como JSON la configuración real de AWS (evidencia del Módulo 3 / Anexo C).
# Uso: ./scripts/aws-evidence.sh      (con las credenciales de AWS activas y Terraform ya aplicado)
set -uo pipefail
cd "$(dirname "$0")/.."
O=evidencias/aws
mkdir -p "$O"
tf() { terraform -chdir=terraform output -raw "$1"; }
CLUSTER="$(tf ecs_cluster_name)"; SERVICE="$(tf ecs_service_name)"
SG="$(tf task_security_group_id)"; KEY="$(tf kms_key_id)"; REPO="$(tf ecr_repository_name)"
TRAIL="$(tf cloudtrail_name)"; LG="$(tf log_group_name)"; EXEC="$(tf execution_role_name)"; TASKR="$(tf task_role_name)"

aws ecs describe-services --cluster "$CLUSTER" --services "$SERVICE"       > "$O/ecs-service.json"
aws ecs describe-task-definition --task-definition "$SERVICE"              > "$O/ecs-task-definition.json"
aws ec2 describe-security-groups --group-ids "$SG"                         > "$O/security-group.json"
aws kms describe-key --key-id "$KEY"                                       > "$O/kms-key.json"
aws kms get-key-rotation-status --key-id "$KEY"                            > "$O/kms-rotation.json"
aws ecr describe-repositories --repository-names "$REPO"                   > "$O/ecr-repo.json"
aws ecr describe-images --repository-name "$REPO"                          > "$O/ecr-images.json"
aws cloudtrail get-trail-status --name "$TRAIL"                            > "$O/cloudtrail-status.json"
aws cloudtrail describe-trails --trail-name-list "$TRAIL"                  > "$O/cloudtrail-trail.json"
aws logs describe-log-groups --log-group-name-prefix "$LG"                 > "$O/log-group.json"
aws iam get-role --role-name "$EXEC"                                       > "$O/iam-execution-role.json"
aws iam get-role --role-name "$TASKR"                                      > "$O/iam-task-role.json"
aws iam list-attached-role-policies --role-name "$EXEC"                    > "$O/iam-execution-role-policies.json"
aws sts get-caller-identity --query 'Account' --output text | sed 's/[0-9]\{8\}$/********/' > "$O/cuenta-enmascarada.txt"
echo "Evidencia guardada en $O/. Revisa los JSON antes de subirlos: enmascara el ID de cuenta si lo prefieres."
