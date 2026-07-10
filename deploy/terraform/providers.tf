# Credential-free provider blocks: authentication is supplied at APPLY time via the
# environment (CLOUDFLARE_API_TOKEN; GITHUB_TOKEN) — never committed. `terraform
# validate` never constructs an API client or checks auth, so these validate cleanly
# without credentials. Do NOT add dummy token values here.
provider "cloudflare" {}

provider "github" {
  owner = var.github_owner
}
