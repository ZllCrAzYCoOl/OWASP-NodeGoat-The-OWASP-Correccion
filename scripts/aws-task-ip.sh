#!/usr/bin/env bash
# Muestra la IP pública de la tarea de Fargate para abrir la aplicación en el navegador.
set -euo pipefail
cd "$(dirname "$0")/../terraform"
CLUSTER="$(terraform output -raw ecs_cluster_name)"
SERVICE="$(terraform output -raw ecs_service_name)"
TASK="$(aws ecs list-tasks --cluster "$CLUSTER" --service-name "$SERVICE" --query 'taskArns[0]' --output text)"
ENI="$(aws ecs describe-tasks --cluster "$CLUSTER" --tasks "$TASK" \
  --query "tasks[0].attachments[0].details[?name=='networkInterfaceId'].value" --output text)"
IP="$(aws ec2 describe-network-interfaces --network-interface-ids "$ENI" --query 'NetworkInterfaces[0].Association.PublicIp' --output text)"
echo "Aplicación: http://$IP:4000"
