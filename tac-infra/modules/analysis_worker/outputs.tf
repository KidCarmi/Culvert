output "running_digest" {
  value       = var.image_digest
  description = "The desired running image digest (asserted against provider truth by the validator)."
}

output "worker_ids" {
  value = [for r in null_resource.worker : r.id]
}
