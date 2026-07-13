# tac-infra: DESIRED STATE for one stateless analysis worker.
#
# This module is provider-agnostic. In the $0 pilot the worker is modeled with the
# null provider (no cloud, no cost) so the desired-state shape, digest pinning, and
# plan/apply flow are exercised end-to-end. A real provider (Fly.io Machines,
# Kubernetes, etc.) swaps in here behind the SAME variables/outputs interface — no
# rewrite (the executor's plan/apply/validate/rollback contract is unchanged).
#
# A change to image_digest is the ONLY intended change for an L3 deploy; the
# deterministic policy engine (in tac-platform) enforces "exactly one worker image
# update, no create/delete/destroy, $0 cost".

resource "null_resource" "worker" {
  count = var.replicas

  triggers = {
    environment  = var.environment
    region       = var.region
    image_digest = var.image_digest        # immutable digest — the desired running version
    config       = jsonencode(var.config)
  }
}
