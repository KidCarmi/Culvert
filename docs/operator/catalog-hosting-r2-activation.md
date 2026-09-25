# Activating Cloudflare-R2 catalog hosting

> **Correction (2026-09-21): GitHub Pages has been retired as a catalog origin.**
> R2 is now the **sole** catalog host — see
> [`release-publication-gating.md` §7b](release-publication-gating.md#7b-catalog-origin-r2-only).
> The steps below still correctly describe how this appliance's R2 publisher was
> brought live and are kept as a historical activation record, but two claims in
> this file are now **false and must not be followed**: the framing that leaving
> `R2_PUBLISH_ENABLED` unset is a harmless "dormant" no-op (Pages no longer exists
> to fall back to — `publish-catalog-r2.yml`'s `assert-publication-target` job now
> FAILS the run when the variable is not `true`, precisely so that state is loud
> instead of silent), and the **Rollback** section's claim that unsetting it
> restores Pages as authoritative. Once R2 is live, `R2_PUBLISH_ENABLED` must stay
> `true`; there is no fallback host to roll back onto.

This runbook turns the **dormant** R2 catalog publisher
(`.github/workflows/publish-catalog-r2.yml`, shipped in M0-PR3) **live**. Until you
complete it, the workflow does not publish. **At the time this runbook was written**
it skipped cleanly (green, no writes) and GitHub Pages remained the authoritative
catalog host; today it FAILS (red) via `assert-publication-target` while
`R2_PUBLISH_ENABLED` is not `true`, and Pages has been retired (see the correction
above). Every step here requires
**owner** credentials — none of it is done by CI.

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

> **Scope note — the `release` environment does NOT gate these R2 credentials.** The
> publisher reads `secrets.R2_*` / `secrets.CF_*` as **repository** Actions secrets and
> does not declare `environment: release`, so the protected `release` environment
> (Step 4) and its reviewers do **not** approval-gate an R2 publish. The `release`
> environment protects the GitHub release/deploy surface generally; it is not, as
> shipped, a gate on the R2 publisher. Treat the R2/CF secrets as
> repository-secret-tier (a merged edit to `publish-catalog-r2.yml` can use them once
> `R2_PUBLISH_ENABLED=true` — hence the Step 3 CODEOWNERS recommendation).
>
> **Optional hardening — gate each R2 publish behind reviewer approval.** If you want
> every R2 publish to require a `release`-environment reviewer, move the six secrets to
> **environment secrets** on the `release` environment and add `environment: release`
> to the `publish` job in `publish-catalog-r2.yml`. Trade-off: this changes R2
> publishing from automated (on tag) to **approval-gated** — the `workflow_run`-driven
> job will pause pending a reviewer, and the environment's deployment policy must
> permit the default-branch context the publisher runs in. This is a deliberate
> product choice (deferred here; not enabled by the skeleton).

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
configure by hand). The `v*` ruleset blocks **deletion + force-move** of release tags
but **allows creation** so the auto-tag job can push new `vX.Y.Z` tags. As noted in
Step 2, the `release` environment does not, as shipped, gate the R2 publisher — see the
optional-hardening note there to change that.

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

**Historical — do not follow.** This section originally said setting
`R2_PUBLISH_ENABLED` back to unset/false made the publisher dormant again with
GitHub Pages remaining authoritative. That is no longer true: Pages has been
retired as a catalog origin, so unsetting the variable stops the catalog from
being published anywhere and turns `publish-catalog-r2.yml`'s
`assert-publication-target` job red (by design — see the correction banner at the
top of this file and
[`release-publication-gating.md` §7b](release-publication-gating.md#7b-catalog-origin-r2-only)).
No R2 object is deleted by disabling, but doing so is not a safe rollback.
