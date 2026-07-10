# Activating Cloudflare-R2 catalog hosting

This runbook turns the **dormant** R2 catalog publisher
(`.github/workflows/publish-catalog-r2.yml`, shipped in M0-PR3) **live**. Until you
complete it, that workflow skips cleanly (green, no writes) and GitHub Pages remains
the authoritative catalog host. Every step here requires **owner** credentials — none
of it is done by CI.

> Trust model reminder: R2 (staging and live) is **untrusted transport**. Integrity
> comes from the catalog's keyless Sigstore signature verified **in the binary**
> against the baked trusted root + pinned `ci.yml` identity. R2 provides
> availability, never trust — a tampered/MITM'd catalog cannot pass the verify step
> and so can never be promoted.

## Prerequisites

- A **signed catalog bundle is attached to the target release**
  (`culvert-release-catalog-<tag>.tar.gz`, produced by `ci.yml`'s `catalog-pipeline`
  on a `v*` tag). The publisher `gh release download`s it and FATALs if absent — so
  keyless signing must be live and a signed release must exist.
- The latest release's catalog is **not expired** (`expires_at`, 180-day window).
  Activating R2 does **not** refresh expiry — if the window has lapsed, the verify
  step fails closed (no promote) until a fresh release or the M1 re-sign cron. Cut a
  fresh release first if needed.
- The IaC guardrails from `deploy/terraform/` are applied (R2 bucket, protected
  `release` environment, `v*` tag ruleset) — see that directory's README.

## Step 1 — Cloudflare: bucket + public custom domain + cache

1. Create the R2 bucket (or `terraform apply` the skeleton's `cloudflare_r2_bucket`).
2. Bind a **custom domain** (e.g. `catalog.<your-domain>`) to the bucket on a
   **proxied** Cloudflare zone. It MUST publicly serve **BOTH** prefixes:
   - `history/stable/**` — the **staging** prefix the verify step fetches;
   - `release-catalog/**` — the **live** pointer clients read.
   If the domain only covers `release-catalog/`, the verify step's fetch of the
   staged URL fails and **nothing ever promotes**.
3. **Disable the public `r2.dev` endpoint** — serve only via the custom domain.
4. Configure cache rules + Smart Tiered Cache as desired (these are the TODO-marked
   items in `deploy/terraform/r2.tf`; version-sensitive, configure by hand or in a
   follow-up TF change).

## Step 2 — GitHub: secrets + variables

Create these on the repository (Settings → Secrets and variables → Actions).

**6 secrets** (all read by the publisher; a missing one fails the job closed):

| Secret | Used by |
|---|---|
| `R2_S3_ENDPOINT` | stage / promote (`aws s3api --endpoint-url`) |
| `R2_S3_ACCESS_KEY_ID` | stage / promote |
| `R2_S3_SECRET_ACCESS_KEY` | stage / promote |
| `R2_BUCKET` | stage / promote |
| `CF_ZONE_ID` | cache purge |
| `CF_CACHE_PURGE_TOKEN` | cache purge — token needs **Zone → Cache Purge** on the catalog zone |

**2 variables:**

| Variable | Used by |
|---|---|
| `R2_PUBLIC_BASE` | verify + confirm (e.g. `https://catalog.<your-domain>`) |
| `R2_PUBLISH_ENABLED` | the dormant gate — **leave unset until the last step** |

## Step 3 — Add the public-base host to the publisher's egress allow-list (merged edit)

The publisher runs `harden-runner` with `egress-policy: block`. Its allow-list already
covers `*.r2.cloudflarestorage.com` (the S3 API) and `api.cloudflare.com` (purge). The
host that is **not** yet covered and **is required** is your **`R2_PUBLIC_BASE`
custom-domain host** — the verify step (`go test … TestServedVerify_BakedRootGate`
fetching `$R2_PUBLIC_BASE/$PREFIX`) and the confirm step both contact it.

Add `catalog.<your-domain>:443` to the `allowed-endpoints` block in
`.github/workflows/publish-catalog-r2.yml` and **merge it to `main`**. This is a
workflow-file edit, not a UI toggle: `workflow_run` executes the **default-branch**
copy of the workflow, so the change only takes effect once merged.

> Recommended: add a **CODEOWNERS** entry for
> `.github/workflows/publish-catalog-r2.yml` — a merged edit to it inherits the R2/CF
> secrets, so it should require review.

## Step 4 — Protect the release surface

Ensure the protected `release` environment (+ reviewers) and the `v*` tag ruleset are
in place (the `deploy/terraform/` skeleton declares both; `terraform apply` or
configure by hand).

## Step 5 — Enable

Only now set the variable **`R2_PUBLISH_ENABLED=true`**. Order matters: enabling before
Step 3's allow-list host is merged would let the job run and fail closed at the verify
fetch.

## Step 6 — Smoke test

Trigger a publish (re-run the tag's CI, or `workflow_dispatch` the publisher with a
signed tag) and watch one full pass:

1. **stage** — create-only upload to `history/stable/<tag>/` (a re-run of the same tag
   hits the `--if-none-match` 412 path and continues; a divergent object aborts loudly).
2. **verify** — the staged URL passes the baked-root served gate (fails closed otherwise).
3. **promote** — sidecars + manifests copied first, then `index.json` **last**,
   ETag-pinned (`--copy-source-if-match`) to the verified staged object. Confirm the
   ETag round-trip works against your R2 (the one live-smoke item flagged in review).
4. **confirm** — the live `index.json` digest converges to the promoted digest.

Then confirm a Control Plane pointed at `CULVERT_RELEASE_CATALOG_URL=https://catalog.<your-domain>/release-catalog`
auto-seeds and `/api/releases` reflects the served catalog.

## Rollback

Set `R2_PUBLISH_ENABLED` back to unset/false — the publisher goes dormant again;
Pages remains authoritative. No R2 object is deleted by disabling.
