# FEEDS-F6-ACTIVATION-RUNBOOK — F6A Preflight & First-Publication Runbook

> **Status:** F6 **readiness-hardening** (code/docs/tests only). This document is the
> preflight evidence + operator runbook; the accompanying PR hardens the pipeline
> (`environment` binding, master-gate dominance over signing, tag/SHA pinning, the
> `resign-feeds.yml` renewal dispatcher). **This PR creates NO infrastructure and mutates
> NO GitHub/Cloudflare/R2/DNS/tag/secret/variable/environment/ruleset/workflow-run/cache/
> feed state.** Execution of the phases below is deferred to operational review (F6
> activation). F3 clients remain **disabled** throughout and through first-publication
> verification.
>
> **Base:** `origin/main @ b9fafff` (PR #1010 merged). **Branch:** `claude/feeds-f6a-preflight`.
> **Doc retrieval date for all external links:** **2026-08-02**. Code references marked
> `b9fafff` are the merged F5 baseline; items marked **[FACT/code — this PR]** are added by
> this hardening PR.

Legend: **[FACT/code]** = verified in this repo at `b9fafff`. **[FACT/doc]** =
verified against official docs (link + date). **[FACT/live]** = verified via a
read-only authenticated API call. **[INFER]** = reasoned expectation, operator to
confirm. **[UNVERIFIED]** = not inspectable from here — **requires operator check**.

---

## 1. Repository / branch / worktree state

| Item | Value | Source |
|---|---|---|
| Base branch | `origin/main` @ `b9fafff` (Merge PR #1010) | `git log` |
| PR #1010 present on main | **Yes** — `feeds_gen.go`, `feeds_gen_test.go`, `feeds_publish_workflow_test.go`, `.github/workflows/publish-feeds.yml` all present | `git ls-tree origin/main` |
| Working branch | `claude/feeds-f6a-preflight` (fresh, off `origin/main`) | `git checkout -B` |
| Worktree | **Clean** before authoring this file (`git status --porcelain` empty) | `git status` |
| Files changed this checkpoint | **only** `roadmap/FEEDS-F6-ACTIVATION-RUNBOOK.md` (this file) | — |
| Commit / push / PR | **none** | — |

---

## 2. Exact F5 artifacts & evidence inspected (read-only, `b9fafff`)

- `.github/workflows/publish-feeds.yml` — the merged two-job publisher.
- `feeds_gen.go` / `feeds_gen_test.go` — generator + gates (`TestFeedGenGate`, `TestFeedGenKeylessVerify`, `TestFeedPublishVerifyGate`, `TestFeedGen_ArtifactNameShape`).
- `feeds_publish_workflow_test.go` — workflow-invariant wall.
- `feeds_identity.env` + `internal/urlcatfeed/identity.go` — pinned signing identity (SSOT).
- `internal/urlcatfeed/schema.go` — protocol/feed/ceiling constants.
- `internal/urlcatfeed/generate.go` — artifact-name format + manifest fields.
- `saas_feed_config.go` — F3 client URL contract + `runtimeEnabled()` gate.
- `internal/urlcat/default_categories.json` — the source dataset (counts).
- `roadmap/FEEDS-DISTRIBUTION-F0-DESIGN.md` (§4, §6, §10, §11) and `roadmap/FEEDS-DISTRIBUTION-F3-DESIGN.md`.

### 2.1 Load-bearing constants (do not re-derive; cite these)

| Constant | Value | Source |
|---|---|---|
| Public origin | `https://feeds.culvertlabs.com` | `saas_feed_config.go` `saasFeedOfficialHost` |
| Manifest URL (mutable envelope) | `https://feeds.culvertlabs.com/v1/url-categories/saas/manifest.sigstore.json` | `saasFeedManifestPath` + `builtinSaaSFeedURL` |
| R2 key prefix | `v1/url-categories/saas/` | `publish-feeds.yml` (`PREFIX`) |
| Envelope object key | `v1/url-categories/saas/manifest.sigstore.json` | `publish-feeds.yml` |
| Immutable artifact key | `v1/url-categories/saas/saas-<feed_version>-<YYYYMMDD>.json` | `generate.go` `artPath` = `"saas-%08d-%s.json"` |
| Artifact bundle key | `…/saas-<feed_version>-<YYYYMMDD>.json.sigstore` | `generate.go` `sigPath` |
| Protocol | `signed_manifest_v1` (no unsigned/raw fallback) | `schema.go` `Protocol` |
| Feed id | `url-categories/saas` | `schema.go` `FeedID` |
| Schema version | `1` | `schema.go` `SchemaVersion` |
| `feed_version` | UTC **Unix seconds** of the single job-start `generated_at` (strictly increasing; **10 digits** today) | `feeds_gen.go` `deriveFeedVersion` |
| Default validity | **14 d** (`336 h`) | `feeds_gen.go` `feedNormalValidity`; workflow `validity_hours` default 336 |
| Hard validity ceiling | **30 d** (`720 h`) | `schema.go` `MaxValidity` |
| Artifact size ceiling | 8 MiB | `schema.go` `MaxArtifactSize` |
| Cosign bundle ceiling | 1 MiB | `schema.go` `MaxBundleBytes` |
| OIDC issuer | `https://token.actions.githubusercontent.com` | `feeds_identity.env` / `identity.go` |
| Pinned SAN regex | `^https://github\.com/KidCarmi/Culvert/\.github/workflows/publish-feeds\.yml@refs/tags/feeds-v[0-9]+\.[0-9]+\.[0-9]+$` | `feeds_identity.env` / `identity.go` (SSOT, byte-equal-pinned by `TestFeedIdentitySSOT`) |
| Master gate var | `FEEDS_PUBLISH_ENABLED` (`== 'true'` dominates **signing + publication**) | `publish-feeds.yml` **[FACT/code — this PR]** |
| Signing-ref pin vars | `FEEDS_SIGNING_TAG` (exact `feeds-vX.Y.Z`) + `FEEDS_SIGNING_TAG_SHA` (40-hex) | `publish-feeds.yml` + `resign-feeds.yml` **[FACT/code — this PR]** |

### 2.2 Expected first-publication content counts

Computed from `internal/urlcat/default_categories.json` @ `b9fafff`: **21 categories,
625 unique (case-folded) hosts**. **[FACT/code]**

> **Do not hardcode these as a gate.** The generator normalizes + dedupes, and the
> **signed manifest's** `category_count` / `host_count` are authoritative. The F5
> pipeline already enforces `recomputed(public artifact) == manifest counts`
> (`verifyFeedArtifactAndEnvelope`, `feeds_gen.go`). Phase 5 verifies the public
> bytes recompute to the signed manifest — that equality is the check, not a fixed
> "625". **[FACT/code]**

---

## 3. Current readiness inventory

### 3.1 GitHub

| Item | State | Source |
|---|---|---|
| `publish-feeds.yml` triggers | `push: tags: ["feeds-v*"]` **+** `workflow_dispatch` (input `validity_hours`). **No `schedule:`/cron.** | `publish-feeds.yml` **[FACT/code]** |
| `feeds-v*` signing tag exists? | **No** — 200 tags inspected (all `v*` / `v0.0.*` release tags); **no `feeds-v*`** | `list_tags` p1+p2 **[FACT/live]** |
| Var `FEEDS_PUBLISH_ENABLED` present/value | **[UNVERIFIED — requires operator check]** — repo variables are not listable via the available API tooling. Workflow is **dormant** unless it equals `'true'`. | `publish-feeds.yml` gate **[FACT/code]** |
| Var `FEEDS_PUBLIC_BASE` present/value | **[UNVERIFIED — requires operator check]** — expected `https://feeds.culvertlabs.com` | — |
| Secrets `FEEDS_R2_*`, `FEEDS_CF_*` present? | **[UNVERIFIED — requires operator check]** — secret **names** (not values) must be confirmed in the target environment | — |
| GitHub environment (`feeds-production`) exists / protection rules | **[UNVERIFIED — requires operator check]** | — |
| Repo/tag rulesets (a `feeds-v*` tag ruleset) | **[UNVERIFIED — requires operator check]** | — |
| Actions permissions (default token, allowed actions) | **[UNVERIFIED — requires operator check]** — the workflow pins actions by SHA and requests least-privilege per job (§5) | `publish-feeds.yml` **[FACT/code]** |
| Whether a scheduled dispatch can run today | **N/A** — no scheduled trigger exists for feeds (unlike catalog `resign-catalog.yml`) | **[FACT/code]** |

### 3.2 Cloudflare / R2

| Item | State | Source |
|---|---|---|
| R2 buckets in account | Exactly **one**: `culvert-catalog` (created 2026-07-10). | `r2_buckets_list` **[FACT/live]** |
| Recommended bucket `culvert-feeds-prod` | **Available** (does not exist) | `r2_buckets_list` **[FACT/live]** |
| Zone `culvertlabs.com` present in account | **[INFER — operator confirm]** — the catalog is served at `catalog.culvertlabs.com` from `culvert-catalog`, so the zone is almost certainly in this account; R2 custom domains **require** the zone be in the same account. | doc + inference |
| DNS record for `feeds.culvertlabs.com` | **[UNVERIFIED — requires operator check]** — no DNS read tool available here. Expected: **absent** pre-activation (custom-domain connect creates the CNAME). | — |
| Custom-domain availability for `feeds.culvertlabs.com` | **[INFER]** — available if the subdomain is unused | — |
| R2 conditional-write / CAS support | **Supported** — see §6 | doc **[FACT/doc]** |

---

## 4. Required resources, variables, secrets & permission matrix

### 4.1 Resources to provision (Phase 1/2)

| Resource | Recommended value | Notes |
|---|---|---|
| R2 bucket | **`culvert-feeds-prod`** | Distinct from `culvert-catalog`. **Reconcile naming:** F0 §F6 row names the Terraform resource `cloudflare_r2_bucket "culvert-feeds"`. Pick one bucket name and keep `FEEDS_R2_BUCKET` byte-equal to it. **[FACT/code: F0 §F6]** |
| Public hostname | **`feeds.culvertlabs.com`** | Hard-pinned in the client URL contract — **cannot** change without a code change (`saasFeedOfficialHost`). **[FACT/code]** |
| GitHub environment | **`feeds-production`** | Holds Job B's R2/CF secrets; carries required-reviewer / branch-and-tag deployment protection. |
| Signing tag | **`feeds-v1.0.0`** → the reviewed `main` commit that carries `publish-feeds.yml` | SemVer `feeds-vMAJOR.MINOR.PATCH` only (SAN regex rejects anything else). **[FACT/code]** |
| Tag ruleset | Restrict **creation** of `feeds-v*` + prohibit **update/deletion** (break-glass bypass only) | Mirrors the catalog's `v-tag-protection` precedent. |

### 4.2 GitHub variables (non-secret) — exact names consumed by the workflow

| Name | Value | Consumed by | Owner |
|---|---|---|---|
| `FEEDS_PUBLISH_ENABLED` | `true` (the **last** enabling control) | Job A signing steps **and** Job B (master-gate dominance) | Release owner |
| `FEEDS_PUBLIC_BASE` | `https://feeds.culvertlabs.com` | Job B public-verify + purge steps | Release owner |
| `FEEDS_SIGNING_TAG` | `feeds-v1.0.0` (exact `feeds-vX.Y.Z`) | Job A/B signing-ref pin + `resign-feeds.yml` | Release owner |
| `FEEDS_SIGNING_TAG_SHA` | the exact **40-hex** commit the tag points to | Job A/B signing-ref pin + `resign-feeds.yml` | Release owner |

**[FACT/code — exact names pinned by `TestFeedsPublisherSecretContract` (4 vars after this PR).]**

### 4.3 GitHub secrets — exact names (report presence only; never values)

| Name | Secret | Min permission | Job | Owner/system |
|---|---|---|---|---|
| `FEEDS_R2_S3_ENDPOINT` | non-secret in practice but stored as secret | n/a (URL `https://<ACCOUNT_ID>.r2.cloudflarestorage.com`) | **B only** | R2 |
| `FEEDS_R2_S3_ACCESS_KEY_ID` | **yes** | R2 **Object Read & Write**, **scoped to `culvert-feeds-prod`** | **B only** | R2 token |
| `FEEDS_R2_S3_SECRET_ACCESS_KEY` | **yes** | (pair of the above) | **B only** | R2 token |
| `FEEDS_R2_BUCKET` | non-secret | n/a — must equal the bucket name | **B only** | R2 |
| `FEEDS_CF_ZONE_ID` | non-secret | n/a | **B only** | CF zone |
| `FEEDS_CF_CACHE_PURGE_TOKEN` | **yes** | CF **Zone → Cache Purge** on the `culvertlabs.com` zone **only** | **B only** | CF API token |

**[FACT/code — exact names pinned by `TestFeedsPublisherSecretContract`; every one referenced only inside Job B (`feeds_publish_workflow_test.go::assertFeedsPrivilegeBoundary`).]**

- **Job A MUST be unable to access all six** — enforced structurally: Job A references zero secrets (`jobSecretRefs(generate) == ∅`). **[FACT/code]**
- **Rotation:** R2 token → create a new bucket-scoped token, update the two `FEEDS_R2_S3_*` secrets, revoke the old. CF purge token → regenerate, update `FEEDS_CF_CACHE_PURGE_TOKEN`, revoke old. Both are Job-B-only; rotation never touches Job A / OIDC.
- **Verification:** after storing, a **dry-run `workflow_dispatch` on a non-tag ref** exercises Job A only (generate, no sign, no publish — Job B skipped by the `feeds-v*` gate), proving nothing publishes before the tag/gate are ready.

---

## 5. Privilege matrix (proof the production setup preserves the boundary)

### Job A — `generate` (signer)
| Requirement | Evidence @ `b9fafff` | Status |
|---|---|---|
| `id-token: write` | job `permissions: id-token: write` | ✅ **[FACT/code]** |
| No R2 credential | references none of `FEEDS_R2_*` | ✅ **[FACT/code]** |
| No Cloudflare credential | references none of `FEEDS_CF_*` | ✅ **[FACT/code]** |
| No repository write | `contents: read` (top-level + job) | ✅ **[FACT/code]** |
| No `environment:` binding | Job A binds no environment (only Job B does) | ✅ **[FACT/code — this PR]** |
| **Signs only when master gate on** | every signing step gated `vars.FEEDS_PUBLISH_ENABLED == 'true' && startsWith(github.ref,'refs/tags/feeds-v')` | ✅ **[FACT/code — this PR]** |
| **Proves signing-ref pin before cosign** | a pin step (grammar + 40-hex SHA + `ref_name`/`sha` equality, fail-closed) runs before `cosign sign-blob` | ✅ **[FACT/code — this PR]** |
| Identity matches `feeds_identity.env` | `TestFeedIdentitySSOT` pins env == Go constants; SAN regex demands `feeds-vX.Y.Z` | ✅ **[FACT/code]** |

### Job B — `publish` (publisher)
| Requirement | Evidence | Status |
|---|---|---|
| R2 + CF creds via environment | six `FEEDS_*` secrets under **`environment: feeds-production`** (Job B binds it) | ✅ **[FACT/code — this PR, B-1 resolved]** |
| Required-reviewer approval before mutation | `environment: name: feeds-production` pauses Job B for approval | ✅ **[FACT/code — this PR]** (reviewer rule is an **operator** setting, B-3) |
| **No** OIDC | job `permissions:` = `contents: read` + `actions: read`; **no `id-token`** | ✅ **[FACT/code]** |
| Master gate + signing-ref pin re-asserted | Job B `if:` keys `FEEDS_PUBLISH_ENABLED`; a pin re-assert step fails closed on tag/SHA mismatch | ✅ **[FACT/code — this PR]** |
| Verifies all signed bytes before mutation | `Re-verify downloaded bundle` step (`TestFeedPublishVerifyGate`, enforcing pass-proof) precedes the first `put-object` | ✅ **[FACT/code]** |
| Immutable writes + CAS + read-back + exact purge | step order verify→stage(create-only)→public-verify→CAS-promote→purge+public-verify | ✅ **[FACT/code]** |

### Weekly dispatcher — `resign-feeds.yml` (added this PR)
A weekly renewal dispatcher **now exists**: `.github/workflows/resign-feeds.yml`
(schedule `Mon 04:17 UTC` + manual dispatch). **[FACT/code — this PR, B-6 resolved]**

| Requirement | Evidence | Status |
|---|---|---|
| No OIDC / no R2-CF / no environment | `permissions: contents:read + actions:write`; references no secrets; binds no environment | ✅ **[FACT/code]** |
| Cannot sign or publish directly | runs no `cosign`; only `gh workflow run publish-feeds.yml` | ✅ **[FACT/code]** |
| Cannot create/move tags | no tag write; validates + dispatches an existing tag only | ✅ **[FACT/code]** |
| Dispatches only the pinned protected tag | `--ref "$SIGNING_TAG"` from `vars.FEEDS_SIGNING_TAG`; asserts lightweight tag resolves to `FEEDS_SIGNING_TAG_SHA` | ✅ **[FACT/code]** |
| Ineffective while master gate disabled | `FEEDS_PUBLISH_ENABLED != 'true'` ⇒ clean no-op | ✅ **[FACT/code]** |
| No unattended publication (pre-GA) | dispatched run's Job B still requires `feeds-production` approval | ✅ **[FACT/code]** |

- Pinned by `TestResignFeedsWorkflowInvariants`.

---

## 6. Official-documentation findings (retrieval date 2026-08-02)

### 6.1 GitHub OIDC identity for a tag-triggered workflow — **[FACT/doc]**
Fulcio embeds the workflow identity as a **SAN URI** `https://github.com/{job_workflow_ref}`,
where `job_workflow_ref` = `OWNER/REPO/.github/workflows/WORKFLOW.yml@refs/tags/TAG`
for a tag push. This is byte-identical in structure to the pinned feeds SAN and to the
**already-operational** release-catalog identity (`release_identity.env`, proven on `v*`
tag releases). ⇒ Only a run of `publish-feeds.yml` on a `refs/tags/feeds-vX.Y.Z` tag can
mint a feed-valid signing identity.
Sources: [Sigstore Fulcio OIDC docs](https://github.com/sigstore/fulcio/blob/main/docs/oidc.md),
[OIDC in Fulcio](https://docs.sigstore.dev/certificate_authority/oidc-in-fulcio/),
[GitHub OIDC reference](https://docs.github.com/actions/reference/openid-connect-reference).

### 6.2 R2 bucket-scoped tokens; **no key-prefix isolation** — **[FACT/doc]**
R2 API-token Access Policies scope to **Account** or **Bucket** resources
(`com.cloudflare.edge.r2.bucket.<ACCOUNT>_<JURISDICTION>_<BUCKET_NAME>`). There is **no
key-prefix resource** — a bucket-scoped write token can write **any** key in that bucket.
This confirms F0 §11.4: the real boundary is *Job A holds no R2 token at all*, not prefix
scoping. Object R/W tokens work with the **S3-compatible API (SigV4)** only — matching the
publisher's `aws s3api`. Source: [R2 Authentication / Tokens](https://developers.cloudflare.com/r2/api/tokens/) (doc dateModified 2026-07-13).

### 6.3 S3 conditional `PutObject` (`If-None-Match` / `If-Match`) → 412 — **[FACT/doc]**
R2 supports conditional writes: `PutObject` with `If-None-Match: *` (create-only) and
`If-Match: <etag>` (compare-and-swap); a failed precondition returns **`412
PreconditionFailed`**. This is the mechanism behind the create-only artifact writes and the
single-object envelope CAS. Sources: [R2 Extensions (conditional operations)](https://developers.cloudflare.com/r2/api/s3/extensions/),
[Upload Objects (conditional put → 412)](https://developers.cloudflare.com/r2/objects/upload-objects/).

### 6.4 ETag for a single-part write — **[FACT/doc]**
A single `PutObject` object's ETag is the MD5 of its bytes; **multipart** ETags differ
(hash-of-part-hashes + `-N`). The manifest envelope is a single small `PutObject`, so its
ETag is a stable content MD5 — a sound `If-Match` CAS token. Source: [Upload Objects → ETags](https://developers.cloudflare.com/r2/objects/upload-objects/#etags).
> **The CAS never reads the ETag/version from the CDN** — the publisher reads them from the
> **R2 origin** via authenticated `s3api` (`publish-feeds.yml`), so CAS correctness is
> cache-independent. **[FACT/code]**

### 6.5 R2 custom domains + caching + purge — **[FACT/doc]**
- Public buckets are **private by default**; a **custom domain** (zone in the **same
  account**) is required for Cloudflare cache/WAF/Access — the `r2.dev` dev URL gets none of
  these and is rate-limited (**do not** use it for production).
- **Default cache behavior:** only certain file extensions are cached by default; **`.json`
  is not in the default-cached set**. Without a "Cache Everything"/Cache Rule, the manifest
  and artifact (both `.json`) are **not edge-cached** — the origin is authoritative.
- **Purge:** single-file purge by exact URL via `POST /zones/{zone}/purge_cache` — the token
  needs the zone **Cache Purge** permission.
Sources: [Public Buckets / Custom Domains + Caching](https://developers.cloudflare.com/r2/buckets/public-buckets/),
[Default Cache Behavior](https://developers.cloudflare.com/cache/concepts/default-cache-behavior/),
[Purge cache](https://developers.cloudflare.com/cache/how-to/purge-cache/).

> **Caching recommendation (Phase 1):** do **not** enable "Cache Everything" on the
> **manifest** path (keep the mutable envelope origin-authoritative or short-TTL). Optionally
> long-cache the **immutable artifact** path via a Cache Rule (`Cache-Control:
> public, max-age=31536000, immutable`) since those keys never change. The workflow already
> purges only the envelope URL after promote. **[INFER — operator sets Cache Rules]**

### 6.6 Environment secrets + required reviewers — **[FACT/doc, standard GitHub]**
GitHub **environment** protection rules (required reviewers, wait timer, deployment
branch/tag policy) gate a job that declares `environment:`; the environment's secrets are
only exposed to a job pinned to that environment, and a required-reviewer rule pauses the job
until approval. (Applied in Phase 1 via Blocker B-1.) Source: [GitHub environments / protection rules](https://docs.github.com/actions/deployment/targeting-different-environments/using-environments-for-deployment).

---

## 7. Exact activation sequence (numbered; hard stop/go gates)

> Roles for the whole sequence: **Operator** (executes), **Reviewer** (independent
> approver of each Go gate), **Abort owner** (authority to set the gate false / rotate
> creds). Record a change window. Every "GO" gate is **fail-closed**: unresolved ⇒ stop.

### Phase 0 — Freeze & evidence  *(BLOCKING BEFORE INFRA)*
1. Record `origin/main` SHA and the `publish-feeds.yml` blob SHA; confirm the tag you will
   cut points at that reviewed commit.
2. Confirm the two required gates on that SHA are green (Fast + Deep PR gate history).
3. Confirm **F3 default disabled**: an untouched appliance is `Managed=false` ⇒
   `runtimeEnabled()==false` ⇒ no network to `feeds.culvertlabs.com`
   (`saas_feed_config.go`). No node may be enabled in Phases 0–5. **[FACT/code]**
4. Confirm **no public manifest** yet: `GET https://feeds.culvertlabs.com/v1/url-categories/saas/manifest.sigstore.json` → expect DNS-fail / 404 (record it).
5. Name Operator / Reviewer / Abort owner; open the change window.
- **GO gate P0:** all five recorded; `feeds-v*` tag confirmed absent (§3.1). Else stop.

### Phase 1 — Infrastructure (documentation only in F6A)  *(BLOCKING BEFORE TAG)*
1. Create bucket **`culvert-feeds-prod`** (empty). Keep `FEEDS_R2_BUCKET` = this exact name.
2. Connect custom domain **`feeds.culvertlabs.com`** to the bucket (zone must be in the same
   account). Wait for status **Active**.
3. Configure cache: **no** Cache-Everything on the manifest path; optional immutable Cache
   Rule on the artifact path (§6.5).
4. Create the **R2 Object Read & Write token scoped to `culvert-feeds-prod` only**; capture
   `FEEDS_R2_S3_ACCESS_KEY_ID` / `_SECRET_ACCESS_KEY` / endpoint.
5. Create the **CF Cache-Purge token** scoped to the `culvertlabs.com` zone only.
6. Create GitHub environment **`feeds-production`** with **required reviewer(s)** and a
   **deployment tag policy limited to `feeds-v*`**.
7. Store the six secrets in **`feeds-production`** (never echo values). Set the variables
   (`FEEDS_PUBLIC_BASE=https://feeds.culvertlabs.com`; set `FEEDS_SIGNING_TAG` +
   `FEEDS_SIGNING_TAG_SHA` in Phase 2; **leave `FEEDS_PUBLISH_ENABLED` absent/`false`**).
8. Verify DNS/TLS resolves and the pre-publication URL returns **404** (bucket empty).
- **GO gate P1:** bucket Active on the custom domain, TLS valid, 404 served, both tokens
  minimum-scope, environment protection on, secrets present by name, `FEEDS_PUBLISH_ENABLED`
  still not `true`. (Job B's `environment: feeds-production` binding is now in the workflow —
  B-1 resolved — so the environment protection genuinely applies.) Else stop.

### Phase 2 — Signing identity  *(BLOCKING BEFORE TAG → this phase creates the tag last)*
1. Create the **`feeds-v*` tag ruleset FIRST**: restrict `creation` to authorized identity;
   **prohibit tag `update` and `deletion`** except a named break-glass bypass. The tag must
   be **lightweight** (never annotated/moved) — `resign-feeds.yml` refuses a non-lightweight
   tag.
2. Only then create **`feeds-v1.0.0`** pointing at the reviewed `main` commit from P0.
3. Set `FEEDS_SIGNING_TAG=feeds-v1.0.0` and `FEEDS_SIGNING_TAG_SHA=<40-hex commit>` (verify
   with `git rev-parse feeds-v1.0.0^{commit}` and `gh api …/git/refs/tags/feeds-v1.0.0`).
4. **Race avoidance — why the tag does not publish OR sign prematurely:** after this PR, the
   master gate `FEEDS_PUBLISH_ENABLED=='true'` dominates **both** signing (Job A) and
   publication (Job B). With the gate still false, a `feeds-v*` tag push **signs nothing and
   publishes nothing** — Job A's signing steps skip, so no OIDC identity is even minted, and
   Job B is skipped. (This is stronger than the pre-PR "sign first, publish later": now
   nothing at all happens until the gate is on and the tag/SHA pin matches.) **[FACT/code]**
- **GO gate P2:** ruleset active *before* the tag existed; tag is **lightweight**, on the
  correct commit, and resolves to `FEEDS_SIGNING_TAG_SHA`; the triggered tag-push run
  **signed NOTHING** (Job A's signing steps skipped because the gate is off) and Job B was
  **skipped** — proving master-gate dominance over signing. Else abort (see A-1). *(Under
  this PR the first signing happens in Phase 4, not here.)*

### Phase 3 — Master-gate enablement  *(BLOCKING BEFORE GATE ENABLE)*
Ordering that avoids a scheduler/manual/tag race:
1. Re-validate: bucket/domain Active, secrets present, environment reviewers ready,
   `FEEDS_SIGNING_TAG`/`_SHA` pinned to the P2 tag/commit, **no** existing R2 objects. (No
   signing has happened yet — it is gated behind the enable in step 3.)
2. Confirm environment **required reviewer** is online for the approval.
3. **Set `FEEDS_PUBLISH_ENABLED=true` — this is the LAST enabling control.**
4. Trigger **exactly one** intended run: re-run the `feeds-v1.0.0` tag context (or a
   `workflow_dispatch` **on the `feeds-v1.0.0` tag ref** so `github.ref` is the tag).
5. **Duplicate-invocation safety:** `concurrency: feeds-publish, cancel-in-progress:false`
   serializes runs; the envelope **CAS** (`If-None-Match:*` first publish, then strictly-
   greater `feed_version` + `If-Match`) makes a second run either a no-op or a 412 abort —
   **never** an overwrite of a newer envelope. **[FACT/code]**
6. **Containment:** if *anything* is unexpected, **set `FEEDS_PUBLISH_ENABLED=false`
   immediately** — future runs stop; already-written objects are handled per §9 (they are
   immutable/CAS-guarded, not corrupting).
- **GO gate P3:** exactly one run proceeded to Job B under environment approval. Else contain.

### Phase 4 — First publication (expected state machine + evidence)
Job B, in order (`publish-feeds.yml`). Capture the bracketed evidence from each:
1. Job A obtained GitHub OIDC identity → [Fulcio cert SAN == pinned regex].
2. Dataset readiness passed → [`EvaluateReadiness.Ready==true`; generator log line].
3. Version + 14-day manifest generated → [`feed_version`, `generated_at`, `expires_at`, `artifact_path`].
4. Artifact + manifest signed → [`saas-*.json.sigstore`, `manifest-payload.json.sigstore` non-empty].
5. Handoff verified (Job A keyless end-to-end) → [`TestFeedGenKeylessVerify` `Action=="pass"`; `manifest.sigstore.json` written].
6. Job B independently re-verifies the downloaded bundle → [`TestFeedPublishVerifyGate` pass; `verified.json` `feed_version`].
7. Immutable objects create + read-back → [`put-object --if-none-match '*'` success; byte-identity guard on any 412].
8. **Initial envelope commit uses `If-None-Match: '*'`** (first publish) → [`put-object` 200; captured ETag].
9. Envelope read-back verifies → [public envelope digest == promoted digest].
10. Exact manifest cache key purged → [`purge_cache` 200 for the envelope URL only].
11. Final report (no secrets) → [`feed_version`, artifact SHA-256 + size, `expires_at`, envelope ETag, object keys].
- **GO gate P4:** every step's evidence captured; convergence confirmed. Else abort per §9.

### Phase 5 — Independent public verification (before ANY node)  *(BLOCKING BEFORE CLIENT CANARY)*
Use **two independent paths** (see §8). Verify, over the **public** origin:
- DNS + TLS hostname; HTTP status + redirect behavior; content-type + cache headers.
- Exactly the expected objects; **no** unexpected objects / mutable aliases.
- Envelope is strict canonical (`payload_b64` + `bundle` only); Sigstore **issuer + SAN**
  match the pinned identity; artifact path + `.sigstore` present.
- Artifact size + SHA-256 == signed manifest; schema/protocol/feed id == expected;
  `feed_version > 0`; `generated_at`/`expires_at` present; validity == 14 d and ≤ 30 d.
- Counts: public artifact **recomputes** to the manifest `category_count`/`host_count`
  (≈ 21 / 625; the **equality** is the gate, not a literal). `EvaluateReadiness == true`.
- No unsigned/raw fallback path exists (client rejects any non-official URL).
- **GO gate P5:** both paths PASS on the public bytes. Else abort (public-verify failure, §9).

### Phase 6 — Client canary (document; **do not execute** in F6A)
On **one** non-production / no-customer node only:
1. Capture pre-state + current policy behavior; confirm it is not already managed.
2. Enable the signed feed **only** on that canary (GUI/CP PUT ⇒ `Managed=true`).
3. One manual refresh; verify downloaded provenance, `feed_version`, freshness, counts,
   rollback floor, activation record, and policy-visible category matching.
4. Test one host newly supplied by the feed; test an override add + remove.
5. Restart the node **offline** → prove cached/LKG recovery. Simulate endpoint unavailability
   → prove Last-Known-Good behavior. Confirm **no** legacy GitHub/raw SaaS request is made.
6. Soak for a defined period; **all other nodes stay disabled**.
- **GO gate P6:** canary healthy across the soak; provenance + LKG + no-legacy-fetch proven.

### Phase 7 — Broader enablement (criteria only; **not authorized here**)
Enable more nodes only after: P6 soak clean; ≥1 successful scheduled/next-version publish
observed end-to-end; rollback-floor monotonicity observed across two versions; abort/recovery
rehearsed; on-call + runbook signed off. **No rollout authorized by this document.**

---

## 8. First-run shakeout — verification paths & gate classification

### 8.1 Two independent verification paths (Phase 5)
- **Path A — production Go verifier (authoritative):** run `TestFeedPublishVerifyGate` against
  a dir populated from the **public** bytes (`CULVERT_FEED_PUBLISH_DIR`) — the exact baked-root
  + pinned-identity path the appliance uses (`verifyFeedBundleDir`, `feeds_gen.go`). **[FACT/code]**
- **Path B — independent tooling:** `cosign verify-blob` using the identity from
  `feeds_identity.env` (`--certificate-oidc-issuer` = `CULVERT_FEED_SIGSTORE_ISSUER`,
  `--certificate-identity-regexp` = `CULVERT_FEED_SIGSTORE_SAN_REGEX`) over the decoded
  `payload_b64` + the envelope `bundle`, and over the artifact + its `.sigstore`; plus a
  manual JSON/size/SHA-256/counts check. A pass on **both** is required.

### 8.2 Shakeout gate classification
**BLOCKING BEFORE INFRA**
- R2 CAS semantics unverified *(RESOLVED — §6.3 documented)*.
- Any mismatch between F5 output and F3 input (URL/path/protocol/feed id/schema) — **checked
  equal** in §2.1 *(RESOLVED)*.

**BLOCKING BEFORE TAG**
- Missing/incorrect `feeds-v*` tag protection (ruleset must exist **before** the tag) — operator (**B-3**).
- Job B `environment:` binding — **RESOLVED this PR** (Job B binds `feeds-production`); the reviewer *rule itself* is an operator setting (**B-3**).
- Signer job able to receive publish credentials — **structurally false** *(RESOLVED, §5)*.
- Publisher job able to receive OIDC — **structurally false** *(RESOLVED, §5)*.
- Signing not gated by the master switch / no tag-SHA pin — **RESOLVED this PR** (gate dominates signing + tag/SHA pin proven before cosign).

**BLOCKING BEFORE GATE ENABLE**
- Absent environment protection / required reviewer (operator setting — **B-3**).
- `FEEDS_PUBLISH_ENABLED` set true before P1/P2 complete.
- Unresolved workflow shell/runtime assumptions (**Blocker B-2**: never run end-to-end).

**BLOCKING BEFORE CLIENT CANARY**
- Inability to independently verify the public envelope (both §8.1 paths must pass).
- Feed enabled on any node by default — **structurally false** (`Managed&&Enabled`) *(RESOLVED)*.

**POST-CANARY**
- Weekly re-sign freshness for feeds — **RESOLVED this PR** (`resign-feeds.yml`; still approval-gated pre-GA).
- Broader rollout criteria (§ Phase 7).

---

## 9. Abort & recovery matrix

Invariants (apply to every row): **never overwrite an older manifest without CAS; never
restore an older `feed_version`; corrective rollback = publish a strictly-newer corrected
version; objects written before a failed CAS are harmless immutable orphans; a purge failure
is not a manifest rollback; setting `FEEDS_PUBLISH_ENABLED=false` stops future publication but
does not erase existing public objects; client disablement preserves the safe local posture;
credential compromise ⇒ gate off + rotate.**

| Failure | Immediate action | Recovery |
|---|---|---|
| Signing identity mismatch (SAN/issuer) | Abort run; **do not** enable gate | Fix workflow/tag identity; re-cut a **new** `feeds-vX.Y.(Z+1)`; never reuse a tag |
| Dataset/generator failure | Abort in Job A (no objects written) | Fix dataset/readiness; re-run; nothing to clean |
| Artifact upload failure (create-only) | Abort before CAS | Re-run; create-only is idempotent (byte-identity guard on 412) |
| Immutable read-back mismatch | **Hard abort** (possible substitution) | Investigate origin bytes; do **not** promote; escalate to credential review |
| Initial CAS conflict (`If-None-Match:*` 412) | Abort | Another publisher already created it — verify it's the intended bytes, else abort; do not overwrite |
| Replacement CAS conflict (`If-Match` 412) | Abort without overwrite | A newer envelope won; re-run derives a strictly-greater version and retries |
| Manifest read-back mismatch | Abort; treat as not-published | Re-run; investigate origin/CDN skew (origin is authoritative) |
| Purge failure after successful CAS | **Do NOT roll back the manifest** | Retry purge; since `.json` is not default-cached, staleness risk is low; client revalidates |
| Public verification failure (P5) | **Do not enable any node** | Diagnose (transport vs signature); if bytes bad, publish a corrected strictly-newer version |
| Client signature rejection | Keep node disabled | Fix identity/bytes; canary re-verifies before re-enable |
| Client activation failure | Revert canary to disabled (safe posture preserved) | Diagnose provenance/floor; retry on canary only |
| Unexpected policy behavior | Disable canary feed | Compare feed-owned vs admin-override layers; do not roll fleet |
| Stale/expired feed | Publish a fresh strictly-newer version | Never restore an older version to "fix" freshness |
| Compromised signing workflow | `FEEDS_PUBLISH_ENABLED=false`; freeze `feeds-v*` ruleset; rotate nothing R2 (Job A holds none) | Rebuild workflow from reviewed main; new tag; new signing run |
| Compromised R2/CF credential | `FEEDS_PUBLISH_ENABLED=false`; **rotate** R2 token + CF purge token; revoke old | Re-issue minimum-scope creds; resume from Phase 3 |

---

## 10. Blockers requiring operator action or credentials

| ID | Blocker | Class | Status |
|---|---|---|---|
| **B-1** | Job B `environment:` binding — needed for environment secrets + required-reviewer approval to apply to publication. | BLOCKING BEFORE TAG | **RESOLVED (this PR)** — Job B binds `environment: name: feeds-production`; pinned by `TestFeedsWorkflowInvariants`. The reviewer *rule* itself is still an operator setting (B-3). |
| **B-2** | The workflow has **never run end-to-end** — invariant tests pin structure, not runtime shell behavior. Treat the first run as a supervised shakeout. | BLOCKING BEFORE GATE ENABLE | **OPEN** — operator supervision (unchanged). |
| **B-3** | GitHub **variables/secrets/environments/rulesets/Actions-permissions** are **[UNVERIFIED]** here (not inspectable via available tooling). | BLOCKING BEFORE TAG | **OPEN / UNVERIFIED** — operator reads/creates current state. |
| **B-4** | **DNS** record for `feeds.culvertlabs.com` and **zone presence** are **[UNVERIFIED]**; custom domain requires the zone in the same account. | BLOCKING BEFORE INFRA | **OPEN / UNVERIFIED** — operator confirms zone + connects domain. |
| **B-5** | Production bucket-name reconciliation (`culvert-feeds-prod` vs F0's `culvert-feeds`). | BLOCKING BEFORE INFRA | **RESOLVED (this PR)** — standardized on **`culvert-feeds-prod`** across the runbook, operator doc, and the narrow F0 §F6 text; `FEEDS_R2_BUCKET` must equal it (operator sets the value). |
| **B-6** | Weekly re-sign freshness dispatcher for feeds. | POST-CANARY | **RESOLVED (this PR)** — `.github/workflows/resign-feeds.yml` added; cannot sign/publish itself; approval-gated pre-GA; pinned by `TestResignFeedsWorkflowInvariants`. |
| **B-7** | Operator doc `docs/operator/feeds-hosting-r2-activation.md` absent. | POST-CANARY | **RESOLVED (this PR)** — operator doc created. |

> B-2/B-3/B-4 remain the real gates before live activation: nothing in this PR runs the
> workflow end-to-end or touches GitHub/Cloudflare/DNS state.

---

## 11. Confirmations (as of the F6 readiness-hardening PR on `claude/feeds-f6a-preflight`)

1. This PR changes **code/docs/tests only**: `.github/workflows/publish-feeds.yml` (gate +
   pinning + `environment`), `.github/workflows/resign-feeds.yml` (new), `feeds_publish_workflow_test.go`
   (extended invariants), `docs/operator/feeds-hosting-r2-activation.md` (new), this runbook,
   and narrow F0/F3/F5 design text. No application/runtime Go code behavior changed.
2. **No external mutation occurred**: no GitHub variable/secret/environment/ruleset/tag/
   workflow-run change; no Cloudflare/R2/DNS/cache/feed-object change; no signing; no tag
   creation; `FEEDS_PUBLISH_ENABLED` was not set. All GitHub/Cloudflare API calls used during
   preflight were **read-only** (`list_tags`, `r2_buckets_list`, docs search).
3. Read-only authenticated calls made during preflight: `git fetch origin main`; GitHub
   `list_tags` (2 pages); Cloudflare `r2_buckets_list`; Cloudflare docs search; one blocked
   GitHub-docs WebFetch (403) substituted by web search. No credentials/keys/secret values printed.
4. **F6 activation is NOT executed.** No `feeds-v1.0.0` tag, no environment, no enable. This PR
   only makes the pipeline *ready*; activation remains the operator sequence in §7.
