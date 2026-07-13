# Desired state for staging. An L3 deploy changes worker1_image_digest (only).
# The value is supplied by an approved plan (chosen server-side from the digest
# allowlist) — never a raw tag from a model.

variable "worker1_image_digest" {
  type    = string
  default = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}

module "tac_analysis_worker_1" {
  source       = "../../modules/analysis_worker"
  environment  = "staging"
  region       = "us-local"
  image_digest = var.worker1_image_digest
  replicas     = 1
  config       = { QUEUE = "staging-analysis", LOG_LEVEL = "info" }
}

output "worker1_running_digest" {
  value = module.tac_analysis_worker_1.running_digest
}
