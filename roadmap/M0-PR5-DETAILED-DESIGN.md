# M0-PR5 — IaC guardrails skeleton + activation docs — Detailed Design (v1)

**Milestone:** M0 (Foundation & Safety) — PR 5 of 5 (final M0 slice).
**Single objective:** land a **declarations-only** Terraform skeleton for the R2/GitHub
guardrails (kept **un-applied** — no owner credentials, no live resources), a CI
`terraform fmt -check` + `validate` lane so the skeleton **can't rot** (TEST-M6), and
the operator **activation runbook** `docs/operator/catalog-hosting-r2-activation.md`
that turns the dormant R2 publisher (PR3) live.

Authority: `roadmap/M0-DETAILED-DESIGN.md` §4.6 (E4-staging), §10 (owner
prerequisites). Independent of PR3/PR4 code. `TestWorkflowInvariants` already shipped
in PR3 — **not** re-included here.

## 1. Scope

| In scope | Out of scope |
|---|---|
| `deploy/terraform/**` — declarations-only skeleton (Cloudflare + GitHub providers), parameterized, no secrets, no live apply | Actually creating any Cloudflare/GitHub resource (owner-only) |
| CI lane: `terraform fmt -check -recursive` + `init -backend=false` + `validate`, path-gated on `deploy/terraform/**` | Any `terraform apply`, remote state, credentials |
| `docs/operator/catalog-hosting-r2-activation.md` — owner activation runbook | R2 publisher code (PR3), legacy retirement (PR4) |

## 2. Hard constraint (environment) — local validation is unavailable

Terraform/OpenTofu **cannot be installed in this authoring environment**: the agent
egress proxy denies `get.opentofu.org` and the GitHub release download hosts with a
policy **403** (not retryable). Consequences, designed around:

- **The CI `validate` lane is the AUTHORITATIVE first validation**, not a
  double-check. This is acceptable — a `validate` lane whose whole purpose is TEST-M6
  ("otherwise validate-clean is untested") is exactly the right place for it.
- To minimize blind-authoring risk, the skeleton is **conservative**: it declares
  only resources with **stable, well-known provider schemas**, pins **explicit
  provider versions**, and represents genuinely version-sensitive / owner-specific
  config (Cloudflare cache rules, custom-domain wiring) as **clearly-marked TODO
  comments referencing the runbook**, rather than fabricating schema I cannot verify
  (honors "no invented resource detail," §4.6).
- Planning review includes a provider-schema sanity pass; CI iteration (batched
  pushes) closes any residual schema drift.

## 3. Design

### 3.1 `deploy/terraform/` layout (declarations-only)

```
deploy/terraform/
  versions.tf            # terraform{} required_version + required_providers (PINNED)
  providers.tf           # provider "cloudflare" / "github" — NO hardcoded creds
  variables.tf           # typed, described inputs; NO real-value defaults
  r2.tf                  # cloudflare_r2_bucket (+ custom-domain/cache: TODO refs)
  github.tf              # github_repository_environment "release" + github_repository_ruleset "v*"
  outputs.tf             # non-secret outputs (bucket name, env name) for operator confirmation
  terraform.tfvars.example  # placeholder values (owner copies → terraform.tfvars, gitignored)
  README.md              # "declarations-only, never auto-applied; owner runs it"
  .gitignore             # terraform.tfvars, .terraform/, *.tfstate*
```

- **Providers**: `cloudflare/cloudflare` and `integrations/github`, version-pinned.
  Auth is supplied at **apply** time via env (`CLOUDFLARE_API_TOKEN`, `GITHUB_TOKEN`)
  — never in the repo. `provider` blocks are credential-free (schema-valid; `validate`
  does not require live auth).
- **Resources chosen for schema stability** (validate-clean without live apply):
  - `cloudflare_r2_bucket` — `account_id` + `name` from variables.
  - `github_repository_environment` "release" — reviewers + deployment-branch policy
    (the protected `release` env from §10).
  - `github_repository_ruleset` — `v*` tag protection (the `v*` ruleset from §10).
- **TODO-marked (not fabricated)**: R2 custom domain + Cloudflare cache rules
  (`cloudflare_ruleset` cache phase) + Smart Tiered Cache + disabling `r2.dev` —
  version-sensitive (provider v4↔v5 churn); declared as commented intent pointing at
  the runbook, so the file validates and the guardrail is documented without inventing
  schema I can't verify locally.

### 3.2 CI lane (TEST-M6 — can't rot)

Add a **path-gated job to the Deep gate** (`pr-deep-gate.yml`), mirroring the
`packaging` classifier so it becomes part of the **required Deep gate** when
`deploy/terraform/**` changes (a separate non-required workflow would let the skeleton
rot). Wiring:
- Add a `terraform` output to the `changes` classify job (case `deploy/terraform/*`),
  and include the workflow-self-change escalation.
- New job `Deep · terraform (fmt/validate)`, `needs: changes`, `if:
  needs.changes.outputs.terraform == 'true'`:
  - `harden-runner` egress **audit** (a new lane whose exact registry hosts
    —`registry.terraform.io`, `releases.hashicorp.com`— are provider-download
    dependent; audit is the repo's baseline for new lanes, block-flip later).
  - `hashicorp/setup-terraform@<pinned SHA>` (pin a specific terraform version).
  - `terraform fmt -check -recursive` (offline; deterministic).
  - `terraform init -backend=false` then `terraform validate` in `deploy/terraform`.
- `permissions: contents: read` only. No id-token, no cloud creds — `validate` needs
  neither.

### 3.3 Activation runbook (`docs/operator/catalog-hosting-r2-activation.md`)

Exact, ordered owner steps to take the **dormant** R2 publisher (PR3) live, folding in
the activation preconditions the PR3 reviewers surfaced:
1. Provision Cloudflare: R2 bucket, **custom domain** that publicly serves **BOTH**
   `history/stable/**` (staging — required for the verify step) **and**
   `release-catalog/**` (live); disable `r2.dev`; Smart Tiered Cache; cache rules.
2. Create the 5 GitHub **secrets** (`R2_S3_ENDPOINT`, `R2_S3_ACCESS_KEY_ID`,
   `R2_S3_SECRET_ACCESS_KEY`, `R2_BUCKET`, `CF_ZONE_ID`, `CF_CACHE_PURGE_TOKEN`) +
   the `R2_PUBLIC_BASE` var.
3. **Add the R2 endpoint host + the `R2_PUBLIC_BASE` host to the publisher's
   harden-runner allow-list** (PR3 §header; the workflow is `egress-policy: block`).
4. Protect the `release` env + reviewers; add the `v*` ruleset (Terraform applies
   these guardrails — link the skeleton).
5. **Only then** set `vars.R2_PUBLISH_ENABLED=true`.
6. **Smoke checklist**: a re-published tag verifies staged → promotes (watch the
   `--if-none-match` create-only + `--copy-source-if-match` ETag round-trip once —
   PR3 impl-review LOW), and `/api/releases` reflects the served catalog.
- **Expiry-window note**: activating R2 does **not** refresh `expires_at`; if the
  latest release's 180-day window has lapsed, verify fails closed (no promote) until a
  fresh release / the M1 re-sign cron.
- **CODEOWNERS**: recommend a CODEOWNERS entry on
  `.github/workflows/publish-catalog-r2.yml` (a merged edit inherits R2 secrets —
  PR3 impl-review LOW).

## 4. Test / validation strategy

- CI `terraform fmt -check` + `validate` (the lane itself is the test — TEST-M6).
- `gofmt`/`go vet`/`go build` unaffected (no Go changes).
- The Deep-gate self-change rule re-runs all deep jobs on the workflow edit (proves
  the new classifier + job wire up).
- Markdown docs: internal-link/section sanity (manual).

## 5. Rollback

Fully additive and inert: `deploy/terraform/**` is never applied; the CI lane only
runs on terraform changes; docs are inert. Delete the directory → nothing live
changes.

## 6. Open questions for planning review

1. **Provider-schema sanity** (KEY, given no local validate): are the three chosen
   resources' required arguments correct for the pinned provider versions? Which
   provider major (cloudflare v4 vs v5) to pin for the least-churn `validate`?
2. Deep-gate job vs a standalone `terraform-validate.yml` — is making it a required
   Deep-gate lane (this design) right, or is a path-filtered standalone enough?
3. Is representing cache-rules/custom-domain as TODO comments acceptable under
   "declarations-only + no invented detail," or should they be fully declared?
4. `setup-terraform` vs `setup-opentofu` — which toolchain does CI standardize on?
5. Egress **audit** vs **block** for the new lane (provider downloads).
