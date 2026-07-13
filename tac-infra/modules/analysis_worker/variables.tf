variable "environment" {
  type        = string
  description = "Deployment environment (staging|prod). The proof slice is staging-only."
}

variable "region" {
  type        = string
  description = "Region scope (composite tenant/env/region scope survives to enterprise)."
}

variable "image_digest" {
  type        = string
  description = "Immutable image digest (sha256:...). NEVER a tag. Chosen from the server-side approved-digest allowlist by the plan."
  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.image_digest))
    error_message = "image_digest must be an immutable sha256 digest, not a tag."
  }
}

variable "replicas" {
  type    = number
  default = 1
}

variable "config" {
  type        = map(string)
  default     = {}
  description = "Non-secret worker config. Secrets are injected at runtime by the platform, never via Terraform vars."
}
