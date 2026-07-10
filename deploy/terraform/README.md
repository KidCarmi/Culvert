# Culvert release-platform guardrails (Terraform)

**Declarations-only. This skeleton is NEVER auto-applied by CI.** CI runs only
`terraform fmt -check` + `terraform validate` (no credentials, no state, no backend,
no `apply`) so the skeleton can't rot. The repository **owner** applies it manually to
provision the R2 / GitHub guardrails — see
[`docs/operator/catalog-hosting-r2-activation.md`](../../docs/operator/catalog-hosting-r2-activation.md).

## What it declares

- `cloudflare_r2_bucket` — the release-catalog bucket.
- `github_repository_environment "release"` — the protected deploy environment + reviewers.
- `github_repository_ruleset` — `v*` tag protection (blocks **delete + force-move**;
  creation stays allowed so the auto-tag release job can push new `vX.Y.Z` tags).

Version-sensitive / owner-specific guardrails — R2 **custom domain**, cache rules,
Smart Tiered Cache, disabling `r2.dev` — are intentionally left as **TODO comments**
in `r2.tf` (their schemas need owner detail this skeleton must not invent; the R2
custom-domain resource does not exist in the pinned v4 provider) and are documented in
the activation runbook.

## Provider pins

`cloudflare ~> 4.52`, `github ~> 6.0` (see `versions.tf`). v4 of the Cloudflare
provider is deliberately pinned for schema stability; revisit at activation.

## Usage (owner)

```bash
cp terraform.tfvars.example terraform.tfvars   # fill in; gitignored
export CLOUDFLARE_API_TOKEN=…                   # never committed
export GITHUB_TOKEN=…
terraform init
terraform plan
terraform apply
```

Credentials are supplied via the environment only; nothing secret is committed.
