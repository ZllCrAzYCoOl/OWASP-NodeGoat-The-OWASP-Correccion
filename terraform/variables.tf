variable "region" {
  type    = string
  default = "us-east-1"
}

variable "project" {
  type    = string
  default = "nodegoat"
}

variable "allowed_cidr" {
  type        = string
  description = "Única IP/rango que puede abrir la aplicación, p. ej. 190.1.2.3/32. NO uses 0.0.0.0/0."
  validation {
    condition     = var.allowed_cidr != "0.0.0.0/0"
    error_message = "Restringe el acceso a tu IP (x.x.x.x/32)."
  }
}

variable "image_tag" {
  type        = string
  description = "Etiqueta de la imagen en ECR (los 12 primeros caracteres del commit)."
}

variable "desired_count" {
  type        = number
  default     = 1
  description = "Usa 0 en el primer apply (antes de subir la imagen a ECR) y luego 1."
}

variable "github_repo" {
  type        = string
  description = "Repositorio autorizado a publicar en ECR, formato ORG/REPO."
}

variable "create_github_oidc" {
  type        = bool
  default     = true
  description = "Pon false si tu cuenta de AWS ya tiene el proveedor OIDC de GitHub."
}
