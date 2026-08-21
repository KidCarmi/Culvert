# Operator guide: activating the public SaaS URL-category feed (`feeds.culvertlabs.com`)

> **Audience:** the release owner activating the F5 feed publisher in production.
> **Companion:** `roadmap/FEEDS-F6-ACTIVATION-RUNBOOK.md` holds the phase-by-phase
> stop/go gates, the abort/recovery matrix, and the read-only preflight evidence.
> This guide is the concrete how-to for the resources, credentials, protected tag,
> first-publication verification, and day-2 renewal.
>
> **Nothing in this repository creates any infrastructure.** No R2 bucket, DNS
> record, Cloudflare setting, GitHub environment, variable, secret, ruleset, or tag
> is provisioned by merging this PR — every step below is an **operator action**.

## 0. What you are turning on

The publisher (`.github/workflows/publish-feeds.yml`) generates, keyless-signs, and
publishes a signed URL-category feed to Cloudflare R2 behind
`https://feeds.culvertlabs.com/v1/url-categories/saas/manifest.sigstore.json`. It is
**dormant** until you set `FEEDS_PUBLISH_ENABLED=true` **and** provision the R2 /
Cloudflare credentials in a protected environment. Appliances (F3 clients) stay
**disabled by default** (`Managed && Enabled`) and only fetch the feed once an
operator explicitly enables it.

## 1. Required resources, ownership & permissions

| Resource | Value | Owner |
|---|---|---|
| R2 bucket | **`culvert-feeds-prod`** (empty; distinct from `culvert-catalog`) | Release owner |
| Public origin | **`https://feeds.culvertlabs.com`** (hard-pinned in the client; cannot change without a code release) | Release owner |
| Cloudflare zone | `culvertlabs.com` (must be in the **same account** as the bucket) | Infra |
| GitHub environment | **`feeds-production`** with **required reviewer(s)** + deployment tag policy `feeds-v*` | Release owner |
| Protected tag | **`feeds-v1.0.0`** (lightweight; never moved/recreated) | Release owner |

## 2. GitHub variables (non-secret)

Set as **repository variables**:

| Variable | Value |
|---|---|
| `FEEDS_PUBLISH_ENABLED` | `true` — **set this LAST** (the master gate; §7) |
| `FEEDS_PUBLIC_BASE` | `https://feeds.culvertlabs.com` |
| `FEEDS_SIGNING_TAG` | `feeds-v1.0.0` (exact `feeds-vX.Y.Z`) |
| `FEEDS_SIGNING_TAG_SHA` | the exact **40-hex commit SHA** the tag points to |

The workflow proves at runtime that it is executing at `FEEDS_SIGNING_TAG` and that the
tag resolves to `FEEDS_SIGNING_TAG_SHA` **before** it signs — a mismatch fails closed.

## 3. GitHub secrets (in the `feeds-production` environment only)

Store as **environment** secrets under `feeds-production` (never repository-wide):

| Secret | Contents | Scope |
|---|---|---|
| `FEEDS_R2_S3_ENDPOINT` | `https://<ACCOUNT_ID>.r2.cloudflarestorage.com` | — |
| `FEEDS_R2_S3_ACCESS_KEY_ID` | R2 access key id | **Object Read & Write, scoped to `culvert-feeds-prod` only** |
| `FEEDS_R2_S3_SECRET_ACCESS_KEY` | R2 secret access key | (pair) |
| `FEEDS_R2_BUCKET` | `culvert-feeds-prod` | must equal the bucket name |
| `FEEDS_CF_ZONE_ID` | the `culvertlabs.com` zone id | — |
| `FEEDS_CF_CACHE_PURGE_TOKEN` | Cloudflare API token | **Zone → Cache Purge on `culvertlabs.com` only** |

Only **Job B** (the publisher) reads these — it binds `environment: feeds-production`.
**Job A** (the signer) holds an OIDC `id-token` and **no** R2/Cloudflare credential.

### 3.1 Minimum R2 token scope (why bucket-level)
R2 API tokens scope to an **account** or a **bucket** — there is **no key-prefix**
granularity ([R2 tokens](https://developers.cloudflare.com/r2/api/tokens/)). Scope the
publisher token to `culvert-feeds-prod` **only**, so a leaked token cannot touch
`culvert-catalog` or any other bucket. The security boundary against Job A is that Job A
holds **no** R2 token at all — not prefix isolation.

### 3.2 Credential rotation
- **R2 token:** create a new bucket-scoped Object-R/W token → update
  `FEEDS_R2_S3_ACCESS_KEY_ID` + `FEEDS_R2_S3_SECRET_ACCESS_KEY` → revoke the old token.
- **CF purge token:** regenerate the zone Cache-Purge token → update
  `FEEDS_CF_CACHE_PURGE_TOKEN` → revoke the old.
- Both are Job-B-only; rotation never touches Job A or the OIDC signing path.
- On suspected compromise: **set `FEEDS_PUBLISH_ENABLED=false` first**, then rotate.

## 4. Custom domain & caching

1. Add the custom domain `feeds.culvertlabs.com` to the `culvert-feeds-prod` bucket
   (the zone must already be in the account). Wait for **Active**.
2. **Caching:** `.json` is **not** in Cloudflare's default-cached extension set
   ([default cache behavior](https://developers.cloudflare.com/cache/concepts/default-cache-behavior/)),
   so by default neither the manifest nor the artifact is edge-cached and **the R2
   origin is authoritative**. Do **not** enable "Cache Everything" on the manifest path
   — the mutable `manifest.sigstore.json` must stay origin-authoritative. You may
   optionally add a Cache Rule to long-cache the **immutable artifact** path
   (`saas-*.json`) with `Cache-Control: public, max-age=31536000, immutable`.
3. Do **not** use the `r2.dev` development URL for production (rate-limited, no cache/WAF).

> The publisher's compare-and-swap reads the live version + ETag from the **R2 origin**
> via authenticated S3 (`s3api`), never the CDN — so CAS correctness is independent of
> cache behavior. The post-promote purge targets only the envelope URL.

## 5. Protected signing tag & SHA verification

1. **Create the `feeds-v*` tag ruleset FIRST** (before the tag exists): restrict tag
   **creation** to authorized identities and **prohibit tag update + deletion** (a named
   break-glass bypass only). The production tag must be a **lightweight** tag and must
   **never** be moved or recreated.
2. Create `feeds-v1.0.0` pointing at the reviewed `main` commit that carries
   `publish-feeds.yml`.
3. **Verify** and record the SHA the operator will pin:
   ```bash
   git rev-parse feeds-v1.0.0^{commit}      # the 40-hex commit SHA
   gh api repos/KidCarmi/Culvert/git/refs/tags/feeds-v1.0.0 --jq '.object.type,.object.sha'
   # object.type MUST be "commit" (lightweight); object.sha MUST equal the pinned SHA.
   ```
   Set `FEEDS_SIGNING_TAG_SHA` to that value. The publisher and the renewal dispatcher
   both re-check this at runtime.

> **Why the tag does not publish prematurely:** the tag push triggers the workflow, but
> every signing step and the whole publish job are gated on `FEEDS_PUBLISH_ENABLED=='true'`.
> With the gate still false, a `feeds-v*` tag push **signs and publishes nothing.**

## 6. Enablement order (avoid the scheduler/manual/tag race)

1. Confirm §1–§5 complete: bucket Active on the custom domain, TLS valid, pre-publish
   URL returns **404**, both tokens minimum-scope, `feeds-production` reviewers ready,
   tag + SHA pinned, tag ruleset active.
2. Confirm the `feeds-v1.0.0` tag push already ran Job A cleanly under the pinned
   identity (Job B was skipped because the gate was off).
3. **Set `FEEDS_PUBLISH_ENABLED=true` — the LAST enabling control.**
4. Trigger exactly one run (re-run the tag context, or `workflow_dispatch` **on the
   `feeds-v1.0.0` tag ref**). Job B pauses for `feeds-production` approval.
5. **Duplicate-invocation safety:** `concurrency: feeds-publish` serializes runs; the
   envelope CAS (`If-None-Match:*` first, then strictly-greater `feed_version` + `If-Match`)
   makes a second run a no-op or a 412 abort — never an overwrite of a newer envelope.
6. **Containment:** if anything is unexpected, **set `FEEDS_PUBLISH_ENABLED=false`
   immediately.** Existing immutable/CAS-guarded objects are not corrupting; see §9.

## 7. First-publication verification (two independent paths)

After the run completes, verify the **public** bytes two independent ways **before**
enabling any appliance.

**Path A — the production Go verifier (authoritative):**
```bash
# Fetch the public bytes into a dir, then run the exact shipped verify path:
mkdir pub && cd pub
curl -fsS https://feeds.culvertlabs.com/v1/url-categories/saas/manifest.sigstore.json -o manifest.sigstore.json
ART=$(jq -r '.payload_b64' manifest.sigstore.json | base64 -d | jq -r '.artifact_path')
curl -fsS "https://feeds.culvertlabs.com/v1/url-categories/saas/$ART"           -o "$ART"
curl -fsS "https://feeds.culvertlabs.com/v1/url-categories/saas/$ART.sigstore"  -o "$ART.sigstore"
cd ..
CULVERT_FEED_PUBLISH_DIR=pub go test -json -run '^TestFeedPublishVerifyGate$' -count=1 . \
  | jq -e 'select(.Test=="TestFeedPublishVerifyGate" and .Action=="pass")'
```

**Path B — independent `cosign verify-blob`** using the pinned identity from
`feeds_identity.env` (issuer + SAN regex are the single source of truth, byte-equal to
the Go constants):
```bash
ISSUER=$(grep '^CULVERT_FEED_SIGSTORE_ISSUER=' feeds_identity.env | cut -d= -f2-)
SAN=$(grep    '^CULVERT_FEED_SIGSTORE_SAN_REGEX=' feeds_identity.env | cut -d= -f2-)
jq -r '.payload_b64' pub/manifest.sigstore.json | base64 -d > payload.json
cosign verify-blob --bundle <(jq -c '.bundle' pub/manifest.sigstore.json) \
  --certificate-oidc-issuer="$ISSUER" --certificate-identity-regexp="$SAN" payload.json
# repeat for the artifact + its .sigstore
```

Also confirm: content-type + cache headers; canonical envelope (`payload_b64`+`bundle`
only); schema/protocol/feed id; `feed_version > 0`; `generated_at`/`expires_at` present;
validity == 14 d and ≤ 30 d; the public artifact **recomputes** to the manifest's
`category_count`/`host_count` (that equality is the check — do not hardcode a count); no
unexpected objects; no unsigned/raw fallback. **Both paths must pass.**

## 8. Weekly renewal (`resign-feeds.yml`)

`.github/workflows/resign-feeds.yml` re-triggers the publisher weekly at the pinned tag
to keep the 14-day window fresh (each run mints a strictly-greater Unix-second
`feed_version`). It holds **`contents: read` + `actions: write` only** — no `id-token`,
no R2/CF credential, no environment — so it **cannot sign or publish itself**; it only
dispatches `publish-feeds.yml` at `FEEDS_SIGNING_TAG`. **For the pre-GA posture, every
weekly publication still pauses for the `feeds-production` required-reviewer approval** —
there is no unattended production publication. When the master gate is off, renewal is a
clean no-op.

## 9. Abort / retry / rollback / purge

- **Never overwrite an older manifest without CAS; never restore an older `feed_version`.**
  A corrective rollback = publish a **strictly-newer corrected version**.
- Objects written before a failed CAS are harmless **immutable orphans**; leave them.
- A **purge failure is not a manifest rollback** — retry the purge; `.json` is not
  default-cached, so staleness risk is low and clients revalidate.
- **First CAS conflict** (`If-None-Match:*` 412): another writer created the key — verify
  it is the intended bytes, else abort; never overwrite.
- **Replacement CAS conflict** (`If-Match` 412): a newer envelope won; re-run derives a
  strictly-greater version and retries.
- **Public verification failure:** do not enable any node; if the bytes are bad, publish a
  corrected strictly-newer version.
- **Credential compromise:** set `FEEDS_PUBLISH_ENABLED=false`, rotate (§3.2), then resume.
- Full matrix: `roadmap/FEEDS-F6-ACTIVATION-RUNBOOK.md` §9.

## 10. Canary, monitoring & evidence capture

- **Canary:** enable the feed on **one** non-production / no-customer appliance only; run a
  manual refresh; verify provenance, `feed_version`, freshness, rollback floor, activation
  record, and policy-visible matching; test a newly-supplied host and an override add/remove;
  prove offline cached (Last-Known-Good) recovery and no legacy GitHub/raw fetch; soak
  before enabling more nodes. (See runbook Phase 6.)
- **Monitoring:** watch the publisher run history, the `feeds-production` approval queue,
  the live `expires_at` (should always be < 14 days old), and the appliance-side feed
  status/metrics for fetch/verify failures.
- **Evidence to capture per publication:** the run URL, `feed_version`, artifact SHA-256 +
  size, `expires_at`, the envelope ETag, the object keys, and both §7 verification
  transcripts.

## 11. Explicit caching note

`.json` responses are **not cached by default** by Cloudflare, and this deployment keeps
the mutable `manifest.sigstore.json` **origin-authoritative** (no Cache-Everything on the
manifest path). The compare-and-swap and every publisher freshness read go to the R2
origin over authenticated S3, never the CDN — so publication correctness never depends on
cache state, and the post-promote purge is a belt-and-suspenders refresh of the one
envelope URL.
