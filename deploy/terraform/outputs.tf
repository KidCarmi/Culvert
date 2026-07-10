# Non-secret outputs for operator confirmation after apply.
output "r2_bucket_name" {
  description = "The release-catalog R2 bucket name."
  value       = cloudflare_r2_bucket.release_catalog.name
}

output "release_environment" {
  description = "The protected GitHub environment gating releases."
  value       = github_repository_environment.release.environment
}

output "v_tag_ruleset_name" {
  description = "The GitHub ruleset protecting v* release tags."
  value       = github_repository_ruleset.v_tag_protection.name
}
