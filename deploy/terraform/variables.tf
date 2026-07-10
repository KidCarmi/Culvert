# Inputs are typed + described with NO real-value defaults: `terraform validate`
# (with -backend=false) treats unset required variables as unknown values and does
# not error — only `plan`/`apply` demand values — so fake defaults would only mask
# genuine omissions. Owners supply values via terraform.tfvars (gitignored;
# see terraform.tfvars.example).

variable "cloudflare_account_id" {
  type        = string
  description = "Cloudflare account ID that owns the R2 bucket."
}

variable "r2_bucket_name" {
  type        = string
  description = "R2 bucket name for the release catalog (e.g. culvert-release-catalog)."
}

variable "github_owner" {
  type        = string
  description = "GitHub owner/org of the Culvert repository (e.g. KidCarmi)."
}

variable "github_repository" {
  type        = string
  description = "GitHub repository name (e.g. Culvert)."
}

variable "release_reviewer_user_ids" {
  type        = list(number)
  description = "GitHub user IDs required to approve a deployment to the protected `release` environment. Numeric IDs, NOT logins."
  default     = []
}

variable "release_reviewer_team_ids" {
  type        = list(number)
  description = "GitHub team IDs required to approve a deployment to the protected `release` environment."
  default     = []
}
