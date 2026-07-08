# Culvert Release/Update Hosting Migration — GitHub Pages → Cloudflare R2

**Status:** DESIGN ONLY. No code changes, no workflow changes, no client behavior
change until this plan is reviewed and approved. Every recommendation below is
tied to a concrete repository finding (file:line). Assumptions are marked
**[ASSUMPTION]**. Things that are currently unsafe/brittle are marked **[RISK]**.

**Author framing:** senior platform / security architect building an
enterprise-grade update channel for a security product.

**Prime finding that shapes everything:** Culvert's catalog **transport is
already untrusted by design**. Integrity comes from an in-binary keyless
Sigstore signature (baked `trusted_root.json` + pinned `ci.yml@refs/tags/v*`
identity) verified before parse, plus per-manifest SHA-256 binding, freshness,
and a monotonic rollback floor. The Pages host "only provides AVAILABILITY,
never trust" (`.github/workflows/publish-catalog-pages.yml:7-12`). **Therefore
moving Pages → R2 is a hosting/availability change, not a trust change.** This
is what makes the migration low-risk and almost entirely additive.

---

## Table of contents

1. Current-state analysis
2. Target architecture (R2)
3. Migration plan
4. Security design
5. Automation design
6. Implementation phases (0–6)
7. Risk register
8. Concrete outputs (file-by-file, workflow-by-workflow, schemas, snippets, pseudocode, tests, rollback)
9. Product Release Operations (PM / Release Engineering)
10. Open decisions & assumptions ledger

---

## 1. Current-state analysis

### 1.1 The five layers today (the separation the goal asks for already partially exists)

| Layer | Where it lives today | Trust property |
|---|---|---|
| **1. Source code** | GitHub repo `KidCarmi/Culvert` (public today) | — |
| **2. Build artifacts** | Container images in GHCR `ghcr.io/kidcarmi/culvert` (+ `-updater`); release binaries as GitHub Release assets | cosign keyless image signatures; SLSA provenance; digest-addressed |
| **3. Release metadata** | Signed catalog bundle `culvert-release-catalog-<ref>.tar.gz` attached to the GitHub Release, then unpacked to **GitHub Pages** at `https://kidcarmi.github.io/Culvert/release-catalog` | Sigstore-signed `index.json`; per-manifest SHA-256; freshness; rollback floor |
| **4. Signatures** | `index.json.sigstore` (keyless, primary), optional `index.json.sig` (ed25519), cosign image sigs, `.sigstore.json` per binary — all in Rekor | Verified **in the binary**, offline (integrated Rekor timestamp) |
| **5. Runtime update consumption** | Appliance CP fetches `CULVERT_RELEASE_CATALOG_URL` → verifies → dispatches `repo@sha256:<digest>` to the `culvert-maint` agent → `docker pull` by digest | Digest-pinned; agent hard-verifies running `RepoDigest` |

The migration touches **layer 3 hosting only** (and the automation that writes
it). Layers 1, 2, 4, 5 are affected only where they *reference* the Pages URL or
*depend on repo visibility*.

### 1.2 Where catalog files are generated today

- **Generator:** `release_gen.go::generateReleaseCatalog` (`release_gen.go:70`).
  Deterministic, byte-stable (compact `json.Marshal`, sorted releases/platforms/
  map keys — `release_gen.go:11-15,81-83,181`). Produces `index.json` +
  `manifests/<release_id>.json`. Determinism is load-bearing because the loader
  authenticates each manifest by hashing its **raw bytes**
  (`release_catalog.go:16-20`, `catalogLoadRelease` `release_catalog.go:291`).
- **Driven by CI, never hand-edited:** the `catalog-pipeline` job in
  `ci.yml` (job "Supply Chain · Release catalog gate") builds a spec from the
  **pushed image digest** (`needs.docker.outputs.proxy_digest`), sets
  `catalog_version = (count of v* tags)+1`, `expires_at = generated_at + 90d`,
  one entry `release_id: culvert-<version>`, `repo: ghcr.io/kidcarmi/culvert`,
  `list_digest: <pushed digest>`, `channels: ["recommended"]`, then runs
  `TestReleaseCatalogGate` which round-trips the bundle through the **real**
  `LoadVerifiedCatalog` (gate == runtime, no drift).

### 1.3 Where signatures / checksums are generated today

- **Catalog signature (keyless, tag path only):**
  `cosign sign-blob --yes --bundle index.json.sigstore index.json`
  in `catalog-pipeline`. Then `TestReleaseCatalogKeylessVerify`
  (`CULVERT_RELEASE_GEN_VERIFY_SIGSTORE=1`) proves the **shipped in-binary
  verifier** (baked `trusted_root.json` + pinned identity) accepts it — a
  natural OIDC SAN that doesn't match the pinned `ci.yml` identity **fails the
  release**.
- **Image signature parity:** `cosign verify --certificate-oidc-issuer / 
  --certificate-identity-regexp` against the values read from
  `release_identity.env` (SSOT, pinned byte-equal to the Go constants
  `officialSigstoreIssuer` / `officialSigstoreSANRegex` at
  `release_catalog_sigstore.go:71-72` by `TestReleaseIdentitySSOT`).
- **Checksums:** `writeReleaseBundle` emits an **audit-only** `checksums.txt`
  (`release_gen.go:251`) — the Control Plane never reads it; authenticated
  integrity is the per-manifest `manifest_sha256` + the index signature.
- **ed25519 (secondary):** `index.json.sig` envelope
  (`release_catalog_verify.go`), keyed by a baked ring
  (`bakedReleaseTrustKeysJSON`, empty in OSS, linker-injected at official build).
  **[ASSUMPTION]** the official build currently ships **Sigstore-only** (baked
  ed25519 ring empty); the ed25519 path is the operator-extension escape hatch.

### 1.4 Where release files are published today

- **GitHub Release** (per tag): binaries + `.sigstore.json` + SBOMs + the
  `culvert-release-catalog-<ref>.tar.gz` bundle + SLSA provenance
  (`ci.yml` jobs `release`, `provenance`, `aggregate-subjects`,
  `verify-reproducible`).
- **GitHub Pages** (per tag, via `workflow_run` on CI success):
  `publish-catalog-pages.yml` downloads the tarball from the Release, refuses an
  unsigned bundle (`test -s index.json.sigstore` — `:109`), stages
  `site/release-catalog/{index.json,index.json.sigstore,manifests/}`, deploys to
  `https://kidcarmi.github.io/Culvert/release-catalog`.
- **The public consumption contract** the client depends on is exactly:
  `GET <base>/index.json`, `<base>/index.json.sig` (only if ed25519 configured),
  `<base>/index.json.sigstore`, `<base>/manifests/<ref>.json`
  (`release_catalog_http.go:246-255,285,327,355`). **That is the entire surface
  R2 must serve.**

### 1.5 GHCR image publishing today

- `docker` job (`ci.yml`): `docker/login-action` to `ghcr.io` with
  `github.actor` + `secrets.GITHUB_TOKEN`, `packages: write`. Multi-arch
  (`linux/amd64,linux/arm64`), `provenance: true`, `sbom: true`. The
  **manifest-list digest** (`steps.build.outputs.digest`) is the trust anchor:
  it is the catalog `list_digest`, the cosign subject, and the target of the
  image-sig verify.
- Runtime pulls are **by digest**: `ComposePullDigest`
  (`cmd/culvert-maint/internal/runner/templates_upgrade.go:289`) runs
  `docker pull <proxy_repo>@sha256:<digest>` then `ComposeTagPinned` retags to
  the local `culvert/proxy:pinned` tag the compose file references
  (`docker-compose.yml:93,245`). GHCR is currently pulled **anonymously**.

### 1.6 Update client / system catalog code

- **New path (strategic):** `HTTPCatalogProvider` (`release_catalog_http.go`) →
  `LoadVerifiedCatalog` → `CatalogHolder`/`Refresher` → `Dispatcher`
  (`release_dispatch.go`) → `DispatchExecutor` (`release_dispatch_exec.go`) →
  agent `POST /v1/upgrades/apply` with `image_ref = repo@sha256:<digest>`.
  Consumes `CULVERT_RELEASE_CATALOG_URL` (`release_wiring.go:61`,
  auto-seed `release_autoseed.go`, `runStartupAutoSeed` `release_wiring.go:322`).
- **Legacy path (fallback, tag-based):** `update.go` + `update_cluster.go` talk
  to the `culvert-updater` sidecar (`docker-compose.yml:56-79`, pulls
  `ghcr.io/kidcarmi/culvert-updater:latest`). Picks a version from the registry
  or from an **unauthenticated** GitHub tags API call:
  `checkGitHubLatestTag` → `https://api.github.com/repos/KidCarmi/Culvert/tags`
  (`update.go:309-314`). Pulls **by tag**, not digest.

### 1.7 What breaks when the repo becomes private

| # | Breakage | Root cause (finding) | Severity |
|---|---|---|---|
| B1 | **Public Pages URL stops serving the catalog** | GitHub Pages from a **private** repo is plan-gated (Free: disabled; Pro/Team/Enterprise: can be public but is not guaranteed, and "private Pages" requires viewer auth → breaks anonymous appliance fetch). `CULVERT_RELEASE_CATALOG_URL=https://kidcarmi.github.io/Culvert/release-catalog` (`publish-catalog-pages.yml:5`) becomes unreliable/unauthenticated-inaccessible. | **Critical** — this is *the* reason to migrate |
| B2 | **Direct Release-asset download requires auth** | Private-repo release assets need a token. `publish-catalog-pages.yml` uses `GITHUB_TOKEN` internally (fine in CI), but any human/appliance fetching assets directly breaks. | Medium |
| B3 | **Legacy `update.go` GitHub-tag fallback returns 404** | `checkGitHubLatestTag` hits the tags API **unauthenticated** (`update.go:309`). Private repo ⇒ 404 ⇒ the legacy update checker silently reports "no update." | Medium (legacy path only) |
| B4 | **Anonymous GHCR pulls fail *if images also go private*** | `ComposePullDigest` runs a bare `docker pull` with no login (`templates_upgrade.go:289`); `scripts/install.sh` seeds `${PROXY_REPO}:latest` anonymously. If the GHCR package visibility flips to private, every pull needs registry credentials on the appliance host. | **High** if images go private (goal says "likely private") |
| B5 | **CI internal `gh release download` still works** | Uses `GITHUB_TOKEN` with `contents: read`. No breakage. | None |

**What does NOT break (important):**

- **Signing & verification are unaffected by repo privacy.** The keyless
  identity is `https://token.actions.githubusercontent.com` +
  `github.com/KidCarmi/Culvert/.github/workflows/ci.yml@refs/tags/v*`
  (`release_catalog_sigstore.go:71-72`). A private repo still runs the workflow,
  Fulcio still issues a cert with that SAN, Rekor is public, and the in-binary
  verifier still validates offline. **No signing change is required by going
  private.** (Renaming `ci.yml` would break it — but privacy alone does not.)
- **The client's trust model** — untrusted transport, in-binary verify — means
  pointing `CULVERT_RELEASE_CATALOG_URL` at R2 needs **zero client crypto
  change**.

---

## 2. Target architecture (R2)

### 2.1 One-paragraph target

Publish the *same* signed catalog bundle CI already produces to a **Cloudflare R2
bucket** exposed through a **custom domain** `catalog.culvertlabs.com` on the
`culvertlabs.com` Cloudflare zone (orange-clouded, cached, WAF-eligible). Images
stay in GHCR (private is fine; see §4.3 for the pull-credential design). The
appliance keeps using `CULVERT_RELEASE_CATALOG_URL` and its existing in-binary
verification — only the URL value changes. Rings (`stable`/`beta`/`dev`) are R2
path prefixes, each serving its own independently-signed `index.json`. Nothing
about trust, digests, or the agent changes.

### 2.2 Cloudflare R2 bucket layout

**[ASSUMPTION]** account owns `culvertlabs.com` as a Cloudflare zone (or will add
it via partial/CNAME setup — R2 custom domains require the zone in the same
account, per CF docs).

Bucket name: **`culvert-catalog`** (single production bucket; optionally a
separate `culvert-catalog-staging` for pre-prod dual-publish tests).

```
culvert-catalog/                         (R2 bucket, custom domain: catalog.culvertlabs.com)
├── stable/                              # GA ring  → CULVERT_RELEASE_CATALOG_URL=https://catalog.culvertlabs.com/stable
│   ├── index.json                       # signed; contains all GA releases + channel pointers
│   ├── index.json.sigstore              # keyless bundle over raw index.json
│   ├── index.json.sig                   # OPTIONAL ed25519 sidecar (only if ed25519 ring is baked/configured)
│   └── manifests/
│       ├── culvert-1.4.2.json           # immutable, content-addressed (manifest_sha256 in index)
│       └── culvert-1.4.3.json
├── beta/                                # pre-release ring (separate signed index)
│   ├── index.json
│   ├── index.json.sigstore
│   └── manifests/…
├── dev/                                 # nightly/edge ring (separate signed index)
│   ├── index.json
│   ├── index.json.sigstore
│   └── manifests/…
├── history/                             # immutable append-only archive of every published index (rollback/audit)
│   ├── stable/
│   │   ├── v41/                         # keyed by catalog_version
│   │   │   ├── index.json
│   │   │   ├── index.json.sigstore
│   │   │   └── manifests/…
│   │   └── v42/…
│   ├── beta/…
│   └── dev/…
└── .well-known/
    └── culvert-catalog.json             # OPTIONAL machine-readable discovery: ring list, current catalog_version per ring
```

**Design decisions:**

- **Rings are paths, not a new schema.** The appliance's ring == which base URL
  it points at. This reuses the existing `CULVERT_RELEASE_CATALOG_URL` contract
  verbatim and requires **no client change**.
- **In-index channels stay as-is.** `recommended` / `lts` / `critical`
  (`release_catalog.go:71-75`) remain *pointers within a ring's catalog*. Two
  orthogonal concepts, cleanly separated: ring = maturity/rollout stage, channel
  = which release within that ring. Do **not** collapse them.
- **`manifests/` are immutable** (content-addressed; the index binds each by
  `manifest_sha256`). Long cache TTL, `immutable`.
- **`index.json` + sidecars are mutable pointers.** Short cache TTL,
  `must-revalidate`, purged on every publish.
- **`history/` is append-only.** Every publish also writes the full bundle under
  `history/<ring>/v<catalog_version>/`. This is the rollback/audit substrate and
  never mutates.

### 2.3 Custom domain layout under `catalog.culvertlabs.com`

| Path | Purpose | Cache-Control (set at upload) | Edge cache |
|---|---|---|---|
| `/stable/index.json` | GA pointer file | `public, max-age=60, must-revalidate` | short (60s) + purge-on-publish |
| `/stable/index.json.sigstore` | GA signature | `public, max-age=60, must-revalidate` | short + purge-on-publish |
| `/stable/index.json.sig` | optional ed25519 | `public, max-age=60, must-revalidate` | short + purge-on-publish |
| `/stable/manifests/*.json` | immutable manifests | `public, max-age=31536000, immutable` | 1y |
| `/beta/*`, `/dev/*` | same shape per ring | same policy | same |
| `/history/**` | immutable archive | `public, max-age=31536000, immutable` | 1y |
| `/.well-known/culvert-catalog.json` | discovery | `public, max-age=300` | 5m |

Because R2 public buckets behind a custom domain only cache "certain file types"
by default and `application/json` is **not** among them, we **must** add a
**Cache Rule** ("Cache Everything") scoped to `catalog.culvertlabs.com` so the
JSON is edge-cached (CF docs, R2 public buckets → Caching). Use **Smart Tiered
Cache** so there is a single upper tier next to the bucket (CF-recommended for
R2). Origin `Cache-Control` set on the object at upload time is honored via
Origin Cache Control / Cache Rules edge-TTL config.

### 2.4 Stable/beta/dev channel structure (rings)

- **`dev`** — every `main` push can publish here (fast, low trust bar, short
  `expires_at`, e.g. 14d). Consumers: internal test fleet only.
- **`beta`** — release candidates / pre-release tags (`v1.5.0-rc.1`). Moderate
  `expires_at` (30d). Consumers: opted-in beta appliances.
- **`stable`** — GA tags only, promoted from beta after health gates. Longer
  `expires_at` (see §2.8 expiry — **90d is too short for a security product's
  auto-seed floor; recommend 180d + a scheduled re-sign**).

An appliance changes rings by changing `CULVERT_RELEASE_CATALOG_URL`. Ring
membership is an operator/product decision, not baked.

### 2.5 Release manifest structure

**Unchanged from today** — reuse the shipped schema exactly (that is the point).
`index.json` (`catalogIndexFile`, `release_catalog.go:161`) +
`manifests/<ref>.json` (`catalogManifestFile`, `release_catalog.go:177`). See §8.4
for the JSON schemas. The generator already emits this shape
(`release_gen.go`). **No schema migration is required for the hosting move.**

Two *optional, additive* schema extensions are proposed later for phased rollout
and richer ops (§9.7): a top-level `rollout` object and a per-release
`yanked`/`revoked` flag. Both are **forward-compatible** (unknown fields are
tolerated — `release_catalog.go:41-42`) so they can ship without breaking older
appliances, but they require client logic to *honor*, so they are Phase 6.

### 2.6 Signature strategy

- **Primary: keyless Sigstore, unchanged.** `index.json.sigstore` over raw
  `index.json`, verified in-binary against the baked `trusted_root.json` + pinned
  `ci.yml@refs/tags/v*` identity, offline (integrated Rekor timestamp).
- **R2 serves signature bytes only; it is never a trust root.** A compromised R2
  cannot forge a valid catalog (§4.6).
- **Secondary (optional): ed25519** `index.json.sig` for operators who bake their
  own trust root — orthogonal, unchanged, and served the same way.
- **Scheme-selection is artifact-owns-outcome** (`verifyIndexSignature`): a
  present-but-invalid sidecar **rejects** (no strip-one-sig downgrade). R2 must
  therefore serve sidecars **atomically-consistent** with their index (§2.7).

### 2.7 Rollback strategy (catalog-level)

**Anti-rollback is a feature, not a bug.** `catalog_version` is monotonic; the
appliance persists a floor (`release_catalog_state.json`) and refuses any lower
version (`checkCatalogRollback`, `release_catalog_freshness.go:106`). So you
**cannot** "roll back" by re-publishing an older, lower-versioned index — and you
shouldn't want to (that is exactly the downgrade attack the floor prevents).

Correct rollback / "pull a bad release" primitives:

1. **Supersede-forward (the normal case):** publish a **new, higher**
   `catalog_version` whose `recommended`/`lts` channel points back at the
   last-good release and which omits or `yanked`-flags the bad one. Appliances
   accept it (version went up) and the bad release is no longer offered.
2. **Emergency revocation (§9.13):** same mechanism, expedited — publish a higher
   `catalog_version` that removes the bad release from `releases[]` entirely and
   re-points every channel to the prior good release. Purge cache immediately.
   Because manifests are content-addressed, the bad manifest can also be
   physically deleted from R2 (defense in depth; the index no longer references
   it anyway).
3. **Break-glass genuine downgrade** (accept a *lower* version) is an operator
   action on the appliance (delete/lower the floor), never a server-side move —
   consistent with the existing design (enterprise plan Phase 3 "explicit
   break-glass recovery flag" is still ☐).
4. **`history/`** retains every prior signed bundle so an operator or the
   pipeline can re-inspect / re-serve a known-good `index.json` for a ring.

### 2.8 Cache strategy

- **Immutable manifests + history:** `max-age=31536000, immutable`. Never
  purged; content-addressed so a stale edge copy is always correct.
- **Mutable index + sidecars:** short `max-age` (60s) **and** an explicit
  **cache purge on publish** (purge the 2–3 pointer URLs by path after upload —
  §5). This bounds worst-case staleness to `min(edge TTL, time-to-purge)` and
  makes a new release visible near-instantly.
- **Atomicity across the pointer set:** `index.json`, `index.json.sigstore`,
  `index.json.sig` must flip together. Publish order (§5.4): upload **manifests
  first** (immutable, safe to appear early) → upload the new **sidecars** → upload
  **index.json last** → **purge** index + sidecars together. Because the client
  verifies the index signature over raw bytes *before* fetching manifests
  (two-phase, `release_catalog_http.go` §5.1), a client that races the publish
  either sees the fully-old set (old index + old sig, both cached) or fetches the
  new index and its matching new sig. A brief window where a client gets **new
  index + old sig** is possible if purges land out of order → **purge index.json
  LAST is wrong; purge sidecars first or purge as a set.** Correct rule:
  **upload all new bytes, then issue a single purge for index+sidecars together;
  if the platform can't purge atomically, purge sidecars before index** so a
  re-fetch never pairs a new index with an old signature. See §5.4 and RISK-R7.
- **Smart Tiered Cache** to minimize R2 origin egress and give consistent TTLs.
- **`cf-cache-status`** should be monitored (HIT ratio) — a low HIT ratio on
  manifests indicates a misconfigured Cache Rule.

### 2.9 Expiry strategy

- **Security expiry is the signed `expires_at`,** enforced in-binary
  (`checkCatalogFreshness`, load-time and use-time). R2 object lifecycle is
  **not** a security control.
- **[RISK] 90-day `expires_at` is too short for a low-cadence security product.**
  If no release ships for 90 days, `stable/index.json` expires and **auto-seed
  fails closed → `available:false`** on fresh installs and refreshers. For a
  security appliance this is an availability foot-gun. **Recommendations:**
  - Raise `stable` `expires_at` to **180d** (config in the `catalog-pipeline`
    spec step; today it is `+90d`).
  - Add a **scheduled re-sign/re-publish workflow** (weekly cron) that
    regenerates + re-signs the *current* `stable` index with a fresh
    `generated_at`/`expires_at` and an **incremented `catalog_version`** but the
    **same releases/digests** — sliding the freshness window forward without a new
    software release. This is the "short-lived timestamp/freshness metadata"
    the enterprise plan §Phase 3 flags as a gap.
  - Longer term, consider a separate short-lived **timestamp role** (TUF-style)
    so the *content* index can be long-lived while a small signed timestamp file
    carries freshness — deferred, noted.

---

## 3. Migration plan

### 3.1 Step-by-step (Pages → R2), additive-first

1. **Provision Cloudflare** (§3.2). Create bucket, custom domain, cache rules,
   scoped tokens. No client impact.
2. **Add an R2 upload job to CI** that runs *after* `catalog-pipeline` on the tag
   path, uploading the **same** signed bundle to `history/stable/v<N>/` and
   `stable/` with the correct `Cache-Control` per object, then a **download-back
   verify** (fetch from `catalog.culvertlabs.com`, run the in-binary verifier),
   then a **cache purge**. **Pages stays untouched.** (Phase 1.)
3. **Dual-publish** — both Pages and R2 serve byte-identical bundles. Point a
   canary appliance at `https://catalog.culvertlabs.com/stable` and confirm
   `available:true`, correct `catalog_version`/`expires_at`, and a successful
   digest-pinned dispatch. (Phase 2.)
4. **Switch the documented default** `CULVERT_RELEASE_CATALOG_URL` to
   `https://catalog.culvertlabs.com/stable` in README/installers/compose comments
   (env stays operator-set; installer still never bakes a URL —
   `release_management_install_contract_test.go` forbids a baked default; the
   *documented recommended value* changes, and optionally a
   `CULVERT_RELEASE_CATALOG_URL` default is added to `.env.example`). (Phase 3.)
5. **Make the repo private.** Verify R2 + GHCR paths (fix B3/B4 first). (Phase 4.)
6. **Remove the Pages dependency** — delete `publish-catalog-pages.yml`,
   decommission the Pages site, update the landing docs to point at R2. (Phase 5.)
7. **Harden** — key rotation runbook, monitoring/alerting on R2 availability +
   catalog freshness, phased rollout, emergency revocation runbook. (Phase 6.)

### 3.2 Required Cloudflare setup

1. Zone `culvertlabs.com` in the Cloudflare account (full or partial/CNAME).
2. R2 bucket `culvert-catalog` (+ optional `culvert-catalog-staging`).
3. **Custom domain** `catalog.culvertlabs.com` connected to the bucket
   (R2 → bucket → Settings → Custom Domains → Add). **Do not** use the `r2.dev`
   dev URL for production (rate-limited, no cache/WAF — CF docs).
4. **Disable the bucket's `r2.dev` public dev URL** (so the only public path is
   the cached, WAF-eligible custom domain).
5. **Cache Rule:** match `Host eq catalog.culvertlabs.com` → *Cache eligibility:
   Eligible for cache* + *Edge TTL: Use Origin Cache-Control*; enable **Smart
   Tiered Cache** on the zone. (JSON isn't cached by default on R2 public
   buckets.)
6. **Cache Response/Edge rules** to enforce per-path TTL if origin headers are
   insufficient (immutable for `/**/manifests/**` and `/history/**`; short for
   `**/index.json*`).
7. **WAF / rate-limit** (Phase 6): a permissive rate-limit rule on
   `catalog.culvertlabs.com` to blunt abusive polling; managed ruleset on.
8. **Two scoped credentials** (§4.5): an **R2 write** token (bucket-scoped,
   object read/write, **no delete on `history/`** if the token API supports
   prefix conditions; otherwise a narrow S3 access key) and a **Cache Purge**
   token (zone `Cache Purge` only). Store as GitHub Actions secrets in a
   protected `release` environment.
9. **[ASSUMPTION]** min TLS 1.2+ on the zone; HSTS optional (catalog is
   integrity-verified regardless, but TLS still protects availability/privacy of
   *which* versions a customer polls).

### 3.3 Required GitHub repository secrets

| Secret | Scope | Used by |
|---|---|---|
| `R2_ACCOUNT_ID` | Cloudflare account id | R2 upload job |
| `R2_ACCESS_KEY_ID` / `R2_SECRET_ACCESS_KEY` | **bucket-scoped** S3 creds, write to `culvert-catalog` only | R2 upload job (via `aws s3`/`rclone`/`wrangler`) |
| `CF_ZONE_ID` | zone id for `culvertlabs.com` | cache purge step |
| `CF_CACHE_PURGE_TOKEN` | API token with **Zone → Cache Purge** only | cache purge step |
| *(if GHCR goes private, for appliances)* `GHCR_PULL_TOKEN` model | **not a repo secret** — a per-customer/read-only pull token distributed out of band (§4.3) | appliance `docker login` |

All R2/CF secrets gated behind a protected **`release` GitHub Environment** with
required reviewers, and only referenced on the **tag path** (never PR, never
`main` for the *production* bucket). **[ASSUMPTION]** OIDC-to-Cloudflare is not
yet GA for R2 S3 creds; if/when it is, prefer short-lived OIDC over static keys.

### 3.4 Required GitHub Actions changes (summary; details §5, §8.2)

- **New job `publish-catalog-r2`** in `ci.yml` (tag path, `needs:
  catalog-pipeline`): upload bundle to R2 with per-object `Cache-Control`,
  download-back verify against `catalog.culvertlabs.com`, purge cache. Idempotent,
  fail-closed, never touches the running catalog on failure.
- **New scheduled workflow `catalog-resign.yml`** (weekly): re-sign + re-publish
  the current `stable` index with a fresh freshness window and bumped
  `catalog_version` (fixes the 90d expiry foot-gun).
- **Modify `publish-catalog-pages.yml`:** unchanged in Phase 1–2 (dual-publish);
  **deleted in Phase 5**.
- **Modify the `catalog-pipeline` spec step:** ring-aware (`stable` on `v*`,
  `beta` on `v*-rc*`, `dev` optional on `main`), raise `stable` `expires_at`.

### 3.5 Required code changes in the updater/client

The client needs **no change to fetch from R2** (untrusted transport). Required
changes are for *repo-privacy fallout* and *hygiene*, not for R2 itself:

- **`update.go::checkGitHubLatestTag` (`update.go:309`)** — breaks on a private
  repo (B3). Options: (a) delete the GitHub-tags fallback and rely on the
  registry/catalog only; (b) authenticate it; (c) **preferred:** retire the
  legacy tag path per `D1.6d-P1.6-release-dispatch-plan.md §12` (Phase B
  default-off, Phase C removal). Mark the GitHub-tags fallback **default-off**
  in Phase 4.
- **GHCR private pull (B4)** — if images go private: the maintenance agent's
  `ComposePullDigest` and the installers' seed step need a `docker login ghcr.io`
  with a read-only pull token *before* the pull. This is a **new, small** wiring
  (env/config for a pull secret + a login step in the sudoers-bounded runner or a
  pre-pull hook). See §4.3.
- **Optional [Phase 6]:** honor a new `rollout` field and `yanked` flag in the
  catalog (client logic; additive, forward-compatible).
- **Optional:** surface the configured catalog origin host + last-seed outcome on
  `/api/releases` (the P1.7 plan flagged this as a deferred stretch).

### 3.6 Required documentation changes

- `README.md:194` — change the recommended `CULVERT_RELEASE_CATALOG_URL` value to
  the R2 URL; note repo is private and images may be private (pull-token note).
- `docs/operator/enterprise-release-catalog-plan.md` — resolve "Open Decisions →
  Catalog publication location" to **R2 behind a custom domain**; update the
  Target Architecture "publishes catalog bundle" line.
- `docs/operator/release-management-agent.md` — add a "private GHCR" wiring
  section (pull token) and the R2 origin.
- `docs/operator/sigstore-trusted-root-lifecycle.md` — note that hosting moved to
  R2 but the trust model is unchanged; reiterate that renaming `ci.yml` (not
  privacy) is what would break the pinned identity.
- **New:** `docs/operator/catalog-hosting-r2.md` — the R2 hosting runbook
  (bucket layout, cache, purge, revocation, re-sign, DR).
- `publish-catalog-pages.yml` header + landing page — retire in Phase 5.
- `CLAUDE.md` "Release catalog" bullets — add the R2 hosting note.

---

## 4. Security design

### 4.1 Catalog and manifest signing (unchanged, restated)

- Keyless Sigstore over **raw** `index.json` bytes; the index binds every
  manifest by `manifest_sha256`, so signing the index transitively authenticates
  all manifests. Determinism (`release_gen.go`) is what makes raw-byte hashing
  stable.
- ed25519 secondary scheme for self-baked trust roots.
- **[RISK — pre-existing]** the ed25519 baked ring is empty in OSS; official
  builds are Sigstore-only **[ASSUMPTION]**. That means a **single** trust
  scheme in practice. Sigstore is well-anchored (Fulcio + Rekor + pinned
  identity), but consider baking an ed25519 org root as an independent second
  scheme so a Sigstore-ecosystem incident (e.g. a Fulcio/TUF problem) doesn't
  fully disable Release Management. Multi-scheme is already supported
  (`NewTrustStoreWithSigstore`, artifact-owns-outcome selection).

### 4.2 Verification flow on the appliance (unchanged, restated)

```
CULVERT_RELEASE_CATALOG_URL = https://catalog.culvertlabs.com/stable
  → HTTPCatalogProvider.Stage (SSRF-guarded dial, bounded reads, conditional GET):
      Phase 1: GET index.json + index.json.sigstore (+ .sig if ed25519 configured)
               verify signature over RAW index bytes against baked trusted_root
               + pinned ci.yml identity, OFFLINE (integrated Rekor ts)   ── TRUST GATE
               (forged/unsigned index ⇒ ZERO manifest fetches)
      Phase 2: parse trusted index → enumerate manifest_refs → GET each
  → LoadVerifiedCatalog (re-verify, defense in depth) → per-manifest sha256 check
  → checkCatalogFreshness (expires_at present + not past, 5-min skew, no future-dating)
  → checkCatalogRollback (catalog_version ≥ 1 and ≥ persisted floor)
  → atomic publish into CatalogHolder; floor raised only after in place
  → Resolve(channel) → PinnedRef = repo@sha256:<list_digest>
  → Dispatcher (repo-equality / air-gap rewrite) → agent /v1/upgrades/apply
  → agent pulls repo@sha256:<digest>, retags culvert/proxy:pinned, hard-verifies RepoDigest
```

R2 sits entirely on the UNTRUSTED side of the trust boundary. Every byte it
serves is re-verified in the binary.

### 4.3 Digest pinning for container images (unchanged + private-GHCR add)

- The catalog `list_digest` == the CI-pushed manifest-list digest (enforced by
  `TestReleaseCatalogGate`, `CULVERT_RELEASE_EXPECT_DIGEST`). The agent pulls
  **only** `repo@sha256:<64hex>` (`validatePinnedDigestRef`) and hard-verifies
  the running `RepoDigest`. Mutable tags are never dispatched. **No change.**
- **Private GHCR pull credential design (new, for B4):**
  - Create a **read-only** GHCR pull token (fine-grained PAT with `read:packages`
    on the `culvert`/`culvert-updater` packages, or a GitHub App installation
    token minted per-customer). **Never** a write/`packages:write` token on the
    appliance.
  - Distribute out of band (not in the public catalog, not in the image, not in
    the installer — enterprise plan security invariant "Logs and API responses
    never expose … credentials"). Options: customer-portal-issued, or an
    org-level pull secret provisioned during onboarding.
  - Wire a `docker login ghcr.io -u <user> --password-stdin` step immediately
    before `ComposePullDigest` in the agent runner (sudoers-bounded), and before
    the installer seed. Keep the credential in a 0600 file (same layer as
    `metrics_token`/upstream creds).
  - **Digest verification still backstops a registry compromise:** even a
    malicious registry can only serve blobs whose content hashes to the pinned
    digest (Docker verifies the manifest digest on pull), so a private-registry
    credential leak is a *confidentiality/availability* issue, not an integrity
    bypass.
  - **[ASSUMPTION]** the product decision is that images go private. If images
    stay **public in GHCR** (metadata private, images public), B4 disappears and
    no pull-credential work is needed — recommended if there is no business
    reason to hide the image bytes, since the digest pin already prevents
    tampering. **This is a key open decision (§10).**

### 4.4 Key management model

| Trust material | Type | Location | Rotation |
|---|---|---|---|
| Sigstore `trusted_root.json` | PUBLIC (Fulcio/Rekor/CT/TSA roots) | baked embed + `CULVERT_RELEASE_SIGSTORE_TRUSTED_ROOT` override | TUF refresh; documented in `sigstore-trusted-root-lifecycle.md` |
| Pinned identity (issuer + SAN) | PUBLIC config | `release_catalog_sigstore.go:71-72` + `release_identity.env` (SSOT) | coordinated code+env change + overlap window (renaming `ci.yml`) |
| ed25519 catalog root (optional) | PUBLIC key | baked `bakedReleaseTrustKeysJSON` + `CULVERT_RELEASE_CATALOG_TRUST_KEYS` | multi-key ring (`key_id`, `not_before/after`) — enterprise plan Phase 4 |
| Sigstore signing key | EPHEMERAL (Fulcio) | never stored — per-run cert | N/A (keyless) |
| **R2 write credential** | **SECRET (new)** | GitHub `release` env secret | rotate on schedule + on suspected leak (§4.9) |
| **CF cache-purge token** | **SECRET (new)** | GitHub `release` env secret | rotate on schedule |
| **GHCR pull token (if private)** | **SECRET (new)** | appliance 0600 file | rotate per customer policy |

The migration introduces **no new *signing* keys** (keyless). The only new
long-lived secrets are **infra credentials** (R2 write, cache purge, optional
GHCR pull) — all least-privilege, none capable of forging a catalog.

### 4.5 CI secret handling

- R2 write + cache-purge tokens live **only** in a protected `release`
  Environment (required reviewers, wait timer optional), referenced **only** on
  the tag path (`if: startsWith(github.ref, 'refs/tags/v')`).
- The R2 write token is **bucket-scoped** and (where the API allows) **denied
  delete on `history/**`** so a CI compromise can't erase the audit trail.
- The cache-purge token is **Cache-Purge only** (cannot edit DNS/WAF/DNS/rules).
- `harden-runner` egress policy on the R2 job (audit → block once the egress
  allowlist is known: `*.r2.cloudflarestorage.com`, `api.cloudflare.com`,
  `catalog.culvertlabs.com`).
- No secret is ever echoed; upload tooling uses `--password-stdin`/env, not argv.

### 4.6 Preventing malicious catalog takeover

Threat: attacker gains write to R2 (leaked token, CF account compromise) and
serves a malicious `index.json` pointing at an attacker image digest.

Defenses (defense in depth):

1. **In-binary signature verification is the hard wall.** The malicious index
   must carry a valid `index.json.sigstore` from the **pinned `ci.yml@refs/tags/v*`
   identity**. R2 write alone cannot produce that — the attacker would also need
   to compromise GitHub Actions OIDC for that exact repo+workflow+tag. A
   self-signed or wrong-identity signature is **rejected** (tests:
   `release_catalog_sigstore_test.go` wrong-workflow/attacker-repo cases).
2. **Artifact-owns-outcome** prevents strip-one-sig downgrade: serving a valid
   index with a stripped/garbage `.sigstore` **rejects**, doesn't fall back to
   unsigned.
3. **Freshness + rollback floor:** even a *replayed old-but-validly-signed*
   catalog is refused if its `catalog_version` is below the appliance floor, and
   an expired one is refused.
4. **Digest pin + cosign image sig + CI digest-match gate:** the pointed-to image
   must exist at that digest and (optionally, if the CP enforces image sigs) be
   cosign-signed by the same identity. Docker verifies the digest on pull.
5. **R2 least-privilege + object-lock on `history/`** limits blast radius and
   preserves forensics.
6. **[Phase 6] `.well-known/culvert-catalog.json` + monitoring:** an external
   canary that fetches + verifies every ring every few minutes and alerts on any
   verification failure or unexpected `catalog_version` regression detects a
   takeover fast.

**Residual:** R2 takeover can cause **denial** (serve garbage/expired ⇒
appliances fail closed to `available:false`) — an availability, not integrity,
impact. That is acceptable and is exactly the current Pages posture.

### 4.7 Handling compromised CI credentials

CI is the **real** high-value target because it holds the signing *identity*
(OIDC). Mitigations (mostly already present — restate + strengthen):

- **Tag-path-only signing** + `require-gate.sh … assert` binding to the actual
  gate **workflow files** (not spoofable check-run names) on the tagged commit
  (`ci.yml` `docker`/`catalog-pipeline`/`release` guards). The real control
  against arbitrary tags is the **`v*` tag ruleset** (protected tags) — ensure it
  requires the gate and restricts who/what can push `v*`.
- **Protected `release` Environment** with required human reviewers gating the R2
  publish + (ideally) the signing job.
- **SLSA provenance + reproducible-build verification** (`verify-reproducible`,
  `provenance`) — a tampered build is caught before assets ship.
- **Rekor transparency:** every signature is publicly logged; an unexpected
  signing event for `ci.yml` is externally detectable (monitor Rekor for the
  identity).
- **Minimize `id-token: write` scope** to the exact jobs that sign.
- **On suspected CI compromise:** (1) revoke R2 + cache-purge tokens; (2) freeze
  releases (disable the `release` environment); (3) publish a higher
  `catalog_version` from a clean runner that removes any suspect release; (4)
  audit Rekor for unexpected signatures under the identity; (5) if the identity
  itself is suspect, rotate the pinned SAN (new workflow file) + `release_identity.env`
  + baked constants with an overlap window (§4.8).

### 4.8 Rotating signing keys / identity

- **Sigstore trusted root:** TUF-refresh the baked `trusted_root.json` per
  `sigstore-trusted-root-lifecycle.md` (public material; `TestSigstore_BakedRootCanBeParsed`
  guards non-empty + parseable).
- **Pinned identity (issuer/SAN):** rotate by (a) update `release_identity.env`,
  (b) update `officialSigstoreIssuer/SANRegex` constants (kept byte-equal by
  `TestReleaseIdentitySSOT`), (c) ship a build accepting **both** old and new SAN
  during an overlap window, (d) cut over, (e) drop the old. Renaming `ci.yml`
  triggers exactly this dance.
- **ed25519 ring (if adopted):** multi-key ring with `key_id` +
  `not_before`/`not_after`, overlap windows, CI fixtures for old/new/expired/
  unknown/wrong-purpose keys — enterprise plan Phase 4 (still ☐). Recommended to
  land alongside the migration to give a **second, independently-rotatable**
  trust scheme.
- **Infra tokens (R2/purge/GHCR-pull):** scheduled rotation (e.g. 90d) + on-leak;
  no code change, no appliance impact.

---

## 5. Automation design

### 5.1 End-to-end pipeline (target, tag path)

```
merge to main
  └─ CI: test → smoke → docker (build+push GHCR, sign images) → catalog-pipeline (gen+gate, main: unsigned)
        → auto-tag (waits for BOTH gates on the SHA) → push v* tag
push v* tag
  └─ CI: test → smoke → docker → catalog-pipeline:
             • build spec from pushed digest (ring = stable/beta by tag shape)
             • gen bundle, gate (digest match), sign-blob keyless (index.json.sigstore)
             • keyless end-to-end verify (in-binary) + image-sig identity parity
             • package tar + attach to Release
        → publish-catalog-r2 (NEW):
             • upload manifests/ (immutable Cache-Control)
             • upload index.json.sigstore (+ .sig), then index.json (short Cache-Control)
             • mirror full bundle to history/<ring>/v<N>/
             • DOWNLOAD-BACK from catalog.culvertlabs.com → in-binary verify
             • purge cache (index + sidecars, as a set)
        → publish-catalog-pages (EXISTING, deleted in Phase 5)
        → release (binaries, sign, SBOM) → provenance (SLSA)
weekly cron
  └─ catalog-resign (NEW): re-sign current stable index, bump catalog_version, slide expires_at, re-publish+purge
```

### 5.2 The new `publish-catalog-r2` job — behavior contract

- **Inputs:** the artifact `release-catalog-bundle` (already produced by
  `catalog-pipeline`) and the target ring (derived from the tag: `vX.Y.Z` →
  `stable`; `vX.Y.Z-rc.N` / `-beta.N` → `beta`).
- **Ordering (atomicity, §2.8):** upload immutable `manifests/**` first → upload
  `index.json.sigstore` (+ `.sig`) → upload `index.json` → upload `history/<ring>/v<N>/**`.
- **Download-back verify (mandatory gate):** fetch
  `https://catalog.culvertlabs.com/<ring>/{index.json,index.json.sigstore,manifests/*}`
  and run the **real in-binary verifier** (`go test -run TestReleaseCatalogKeylessVerify`
  or a small `verify` harness pointed at the live URL) — proves what's *served*
  verifies, not just what was *generated*. **Fail the job if it doesn't verify.**
- **Cache purge:** purge the index + sidecar URLs together, then a second
  download-back to confirm the *new* `catalog_version` is what the edge serves.
- **Idempotent + safe:** re-running with the same tag re-uploads identical bytes
  (deterministic generation) → no-op. A partial failure leaves the *old* pointer
  intact because `index.json` is uploaded last and purge is last.

### 5.3 Failure behavior

| Failure | Behavior |
|---|---|
| Upload of `manifests/` fails | Abort before touching `index.json`; old catalog fully intact; job red. |
| Upload of sidecar/index fails | Abort; old pointer intact (new index not yet uploaded or purge not issued); job red. |
| **Download-back verify fails** | **Do not purge** (so the edge keeps serving the old, good catalog); job red; alert. This is the critical safety gate — a bad publish is caught before customers see it. |
| Cache purge fails | Job red; new bytes are at origin but edge may serve stale up to TTL (60s). Retry purge; alert. Not a correctness problem (bytes are signed + fresh), only latency. |
| `catalog-resign` fails | Old stable index keeps serving until its `expires_at`; alert with lead time (window is 180d, so ample time to fix). |

### 5.4 Rollback behavior (automation)

- **Bad release just published:** trigger `catalog-revoke` (manual
  `workflow_dispatch`, §9.13) → regenerate `stable` index at a **higher**
  `catalog_version` omitting the bad release, re-sign, upload, **purge**. The
  `history/` copy of the prior good index is available to diff/re-serve.
- **R2/edge incident:** Pages (until Phase 5) or a re-point of the appliance URL
  back to the last-known-good origin is the break-glass. After Phase 5, R2 +
  Cloudflare's own resilience is the availability layer; the `history/` archive +
  a documented "re-serve last-good" runbook is the recovery.

---

## 6. Implementation phases

Each phase is independently shippable, additive-first, and reversible. Gates are
concrete and testable.

### Phase 0 — Audit current release/update flow ✅ (this document)

Deliverable: §1. Findings pinned to file:line. **Exit gate:** review sign-off on
§1.7 (what breaks) and §10 (open decisions), especially the GHCR public/private
decision.

### Phase 1 — Add R2 upload path without changing clients

- Provision Cloudflare (§3.2) using a **staging** bucket first
  (`culvert-catalog-staging`, custom domain `catalog-staging.culvertlabs.com`).
- Add `publish-catalog-r2` job (§5.2) writing to **staging** on tag builds.
- **No client change; Pages unchanged.**
- **Exit gate:** a tagged build lands a byte-identical, in-binary-verifiable
  bundle at the staging URL; download-back verify green; cache purge works;
  `history/` populated.

### Phase 2 — Dual catalog to Pages and R2 (production)

- Point `publish-catalog-r2` at the **production** bucket + custom domain.
- Both Pages and R2 serve the same bundle.
- Point a **canary appliance** at `https://catalog.culvertlabs.com/stable`;
  confirm `available:true`, correct `catalog_version`/`expires_at`, and a full
  digest-pinned dispatch through the agent.
- Add the `catalog-resign` weekly workflow (fixes the expiry foot-gun) targeting
  R2.
- **Exit gate:** canary runs a real update from R2 end-to-end; monitoring
  (external verify canary) green for ≥1 week; both origins byte-identical
  (a CI diff step).

### Phase 3 — Switch default update endpoint to `catalog.culvertlabs.com`

- Change the **documented recommended** `CULVERT_RELEASE_CATALOG_URL` to
  `https://catalog.culvertlabs.com/stable` (README, compose comments,
  `.env.example` default, operator docs). Installer still **never bakes** a URL
  (`release_management_install_contract_test.go`); a documented default + an
  optional `.env.example` value is the mechanism.
- Freeze the legacy `update.go` GitHub-tags fallback (mark default-off — pre-B3).
- **Exit gate:** new installs default to R2; existing installs unaffected (their
  env is whatever they set); no public-behavior change without operator action.

### Phase 4 — Make the GitHub repo private

- **Pre-requisites (must land first):**
  - B3: `update.go::checkGitHubLatestTag` default-off / removed / authenticated.
  - B4: if images go private, GHCR pull-credential wiring shipped + tested
    (§4.3). If images stay public, no-op.
- Flip repo visibility to private.
- **Exit gate:** with the repo private, a fresh appliance install auto-seeds from
  R2 (`available:true`), pulls the pinned digest (with pull creds if private),
  and updates successfully; signing/verification still green (identity unaffected
  by privacy); CI still publishes to R2 + Release.

### Phase 5 — Remove GitHub Pages dependency

- Delete `.github/workflows/publish-catalog-pages.yml`; decommission the Pages
  site; remove the Pages landing/docs references.
- **Exit gate:** no workflow references Pages; the only public catalog origin is
  `catalog.culvertlabs.com`; docs updated.

### Phase 6 — Harden signing, rollback, and monitoring

- (Optional) bake a second **ed25519** org trust root for scheme independence
  (§4.1) + Phase-4 key-rotation fixtures.
- Emergency-revocation workflow (`catalog-revoke`) + runbook (§9.13).
- External **verify canary** (a Worker or scheduled job that fetches + verifies
  every ring and alerts on failure / version regression) + R2 availability +
  freshness dashboards.
- Phased rollout mechanism (rings + optional `rollout` percentage field, §9.7) —
  client change, forward-compatible.
- WAF/rate-limit tuning; block egress on the R2 job.
- **Exit gate:** revocation drill executed; canary alerting proven; rollout
  mechanism demonstrated on the test fleet.

---

## 7. Risk register

Legend: **L**ikelihood × **I**mpact (Low/Med/High). "Owner mitigation" = the
control in *this* design.

| ID | Risk | L | I | Owner mitigation | Residual |
|---|---|---|---|---|---|
| R1 | **Broken update path** (appliances can't reach catalog) | M | H | Dual-publish (Phase 2) + canary before cutover; Pages retained until Phase 5; `history/` re-serve runbook; R2 on Cloudflare's anycast. Fail-closed = `available:false`, proxy keeps running (catalog not on hot path). | Availability dip; no security impact |
| R2 | **Bad manifest** (wrong/missing digest, malformed) | L | H | `TestReleaseCatalogGate` (digest match) + deterministic gen + download-back in-binary verify before purge; loader fail-closed on any shape error. | Caught in CI, never served |
| R3 | **Stale cache** (edge serves old index after publish) | M | M | Short TTL (60s) + explicit purge-on-publish + post-purge download-back confirm; manifests immutable so never wrongly stale. | ≤60s worst case |
| R4 | **Expired catalog** (no release for >expiry) | M | H | Raise stable `expires_at` to 180d + weekly `catalog-resign` sliding the window; alert with long lead time. | Requires the cron to keep running (monitor it) |
| R5 | **Private GHCR pull failure** | M | H | Explicit pull-credential wiring (§4.3) landed **before** Phase 4; digest verify backstops registry compromise; **or** keep images public (recommended if no business reason). | Credential distribution/rotation burden |
| R6 | **Signature verification failure** (legit) | L | H | Download-back verify in CI (catch producer-side); artifact-owns-outcome prevents accidental downgrade; SSOT identity test prevents CI↔binary drift. | Fail-closed (safe) |
| R7 | **Cache/publish non-atomicity** (new index paired with old sig at edge) | M | M | Upload sidecars before index; purge index+sidecars as a set (sidecars first if not atomic); client two-phase verify rejects a mismatch (fails closed, retries next refresh). | Transient fail-closed, self-heals |
| R8 | **Clock skew** (freshness false-positive) | L | M | Existing 5-min skew tolerance (`catalogClockSkew`); future-dating rejected; appliance uses its own clock (NTP assumed). | Documented; recommend NTP |
| R9 | **Rollback / downgrade attack** | L | H | Monotonic `catalog_version` floor persisted; lower versions refused; revocation is *forward* (higher version), never a lower re-publish; `history/` immutable. | Break-glass downgrade is operator-local only |
| R10 | **CI token leak** (R2 write / purge) | L | H | Bucket-scoped, `release`-env-gated, tag-path-only, no delete on `history/`, `--password-stdin`, egress-blocked runner; rotation; **cannot forge a signature** (leak ⇒ DoS at worst, caught by verify canary). | DoS possible until token revoked |
| R11 | **R2 permission misconfiguration** (public write / list) | L | H | Public **read-only** via custom domain; disable `r2.dev`; write only via scoped S3 creds; deny bucket listing at root (R2 default: no root listing); IaC/checklist review; verify canary detects unexpected content. | Config drift — periodic audit |
| R12 | **CI OIDC / identity compromise** (can sign) | L | H | Tag ruleset + gate binding + protected env + reviewers; Rekor monitoring for the identity; SLSA/reproducible-build; revocation + identity rotation runbook. | The genuine worst case — see §4.7 |
| R13 | **`ci.yml` renamed** breaks pinned identity | L | H | SSOT test + documented coordinated-rotation dance + overlap window; CLAUDE.md warning. | Process control |
| R14 | **Cloudflare account/zone compromise** | L | H | 2FA + hardware keys on the CF account; scoped API tokens (never global key); audit logs; verify canary; in-binary signature still blocks integrity bypass (DoS only). | Availability/DoS |
| R15 | **Sigstore ecosystem incident** (Fulcio/Rekor/TUF) | L | M | Optional independent ed25519 scheme (§4.1); offline verification (no runtime call to sigstore.dev); air-gap bundles unaffected. | Mitigated by second scheme if adopted |

---

## 8. Concrete outputs

### 8.1 File-by-file change plan

| File | Phase | Change |
|---|---|---|
| `.github/workflows/ci.yml` | 1–2 | Add `publish-catalog-r2` job (needs `catalog-pipeline`, tag path); ring-aware spec step; raise stable `expires_at` to 180d. |
| `.github/workflows/catalog-resign.yml` | 2 | **New** weekly cron: re-sign + re-publish current stable index, bump `catalog_version`, slide `expires_at`, purge. |
| `.github/workflows/catalog-revoke.yml` | 6 | **New** `workflow_dispatch`: regenerate stable index omitting a named release at a higher version, re-sign, upload, purge. |
| `.github/workflows/publish-catalog-pages.yml` | 5 | **Delete** (kept & untouched in 1–4). |
| `release_gen.go` | — | No change (schema/generation reused). Possibly add optional `rollout`/`yanked` emission in Phase 6 (additive). |
| `release_catalog.go` | 6 (opt) | Optional: parse `rollout`/`yanked` (forward-compatible today; honoring them is the change). |
| `release_catalog_http.go` | — | No change (already fetches the exact R2 surface). |
| `release_wiring.go` | 3 | No behavior change; docs/comments for the R2 default. Optional: surface catalog origin host on status. |
| `update.go` | 3–4 | `checkGitHubLatestTag` (`:309`) default-off/removed/authenticated (B3). Freeze legacy tag path (`D1.6d-P1.6 §12`). |
| `cmd/culvert-maint/internal/runner/templates_upgrade.go` | 4 (if private) | Add a `docker login ghcr.io` pre-pull step (sudoers-bounded) for private GHCR (B4). |
| `cmd/culvert-maint/internal/server/handlers_upgrade_apply.go` | 4 (if private) | Thread the pull credential into the apply stages before `pull`. |
| `packaging/sudoers/culvert-maint` | 4 (if private) | Allow the `docker login` invocation (narrow, stdin password). |
| `packaging/culvert-maint/config.example.toml` | 4 (if private) | Add optional `ghcr_pull_secret_ref`. |
| `scripts/install.sh` / `packaging/culvert-maint/install.sh` | 4 (if private) | `docker login` before the `${PROXY_REPO}:latest` seed when a pull secret is configured. |
| `docker-compose.yml` | 3 | Comment: recommended `CULVERT_RELEASE_CATALOG_URL` = R2; (no baked default). |
| `.env.example` | 3 | Add `CULVERT_RELEASE_CATALOG_URL=https://catalog.culvertlabs.com/stable`. |
| `README.md` | 3,4 | Update env table (`:194`) + a "private repo / private images" note. |
| `docs/operator/enterprise-release-catalog-plan.md` | 3 | Resolve "publication location" open decision → R2. |
| `docs/operator/release-management-agent.md` | 4 | Add private-GHCR pull wiring. |
| `docs/operator/sigstore-trusted-root-lifecycle.md` | 3 | Note hosting move; trust unchanged. |
| `docs/operator/catalog-hosting-r2.md` | 2 | **New** R2 hosting runbook. |
| `CLAUDE.md` | 3 | Add R2 hosting bullet under Release catalog. |
| `release_management_install_contract_test.go` | 3 | Assert installer still bakes **no** URL; `.env.example` default is documentation, not a baked default. |

### 8.2 Workflow-by-workflow change plan

- **`ci.yml`** — add `publish-catalog-r2` (§5.2); no rename (name "CI" is
  load-bearing for the Pages trigger until Phase 5, and harmless after).
- **`publish-catalog-pages.yml`** — untouched 1–4; deleted in 5.
- **`catalog-resign.yml`** (new) — weekly; reuses `release_gen` +
  `TestReleaseCatalogGate` + keyless sign + the R2 upload/verify/purge steps.
- **`catalog-revoke.yml`** (new) — dispatch; same publish machinery, revocation
  spec.
- **`security-release-gate.yml` / `qa-gate.yml`** — unchanged; the R2 job runs
  *after* `catalog-pipeline`, itself gated by `require-gate.sh`.

### 8.3 Proposed R2 bucket structure

See §2.2 (bucket tree) and §2.3 (per-path Cache-Control). Summary:
`<ring>/index.json[.sigstore|.sig]` (mutable, short TTL, purged) +
`<ring>/manifests/*.json` (immutable, 1y) + `history/<ring>/v<N>/**` (immutable) +
`.well-known/culvert-catalog.json` (discovery).

### 8.4 Proposed JSON schemas (current, reused verbatim)

**`index.json`** (`catalogIndexFile`, `release_catalog.go:161`):

```jsonc
{
  "schema_version": 1,
  "generated_at": "2026-07-08T12:00:00Z",   // RFC3339 UTC
  "expires_at":   "2027-01-04T12:00:00Z",   // enforced in-binary; raise to +180d for stable
  "catalog_version": 42,                     // monotonic; rollback floor
  "channels": { "recommended": "culvert-1.4.3", "lts": "culvert-1.2.7" },
  "releases": [
    { "release_id": "culvert-1.4.3", "version_id": "1.4.3",
      "manifest_ref": "culvert-1.4.3.json",
      "manifest_sha256": "<64hex over the RAW manifest bytes>" }
  ]
}
```

**`manifests/<release_id>.json`** (`catalogManifestFile`, `release_catalog.go:177`):

```jsonc
{
  "schema_version": 1,
  "release_id": "culvert-1.4.3",
  "version_id": "1.4.3",
  "severity": "normal",                      // or "critical"
  "created_at": "2026-07-08T12:00:00Z",
  "image": {
    "repo": "ghcr.io/kidcarmi/culvert",
    "list_digest": "sha256:<64hex>",         // manifest-LIST digest == CI pushed digest
    "platforms": ["linux/amd64","linux/arm64"]
  },
  "min_upgrade_from": "1.2.0",               // parsed; enforcement is a later slice
  "changelog_url": "https://…",
  "notes": "…"
}
```

**`index.json.sigstore`** — cosign keyless bundle (Fulcio cert + sig + Rekor
proof) over the raw `index.json` bytes. **`index.json.sig`** — ed25519 envelope
`{schema_version, alg:"ed25519", key_id, sig(base64)}` (optional).

**Proposed additive fields (Phase 6, forward-compatible):**

```jsonc
// index.json (optional)
"rollout": { "release_id": "culvert-1.4.3", "percent": 25, "salt": "2026-07-08" }
// manifests/<id>.json (optional)
"yanked": true, "yanked_reason": "CVE-2026-XXXX regression"
```

**`.well-known/culvert-catalog.json`** (new, discovery, not a trust root):

```jsonc
{
  "rings": ["stable","beta","dev"],
  "current": { "stable": 42, "beta": 57, "dev": 611 },  // catalog_version per ring
  "base": "https://catalog.culvertlabs.com",
  "generated_at": "2026-07-08T12:00:00Z"
}
```

### 8.5 Proposed GitHub Actions YAML snippets

**`publish-catalog-r2` job (sketch, in `ci.yml`):**

```yaml
  publish-catalog-r2:
    name: Supply Chain · Publish catalog to R2
    needs: [docker, catalog-pipeline]
    if: startsWith(github.ref, 'refs/tags/v')
    runs-on: ubuntu-latest
    environment: release                      # protected: reviewers + secrets
    permissions:
      contents: read
      id-token: write                          # for the in-binary keyless verify test
    env:
      AWS_ENDPOINT_URL: https://${{ secrets.R2_ACCOUNT_ID }}.r2.cloudflarestorage.com
      AWS_ACCESS_KEY_ID: ${{ secrets.R2_ACCESS_KEY_ID }}
      AWS_SECRET_ACCESS_KEY: ${{ secrets.R2_SECRET_ACCESS_KEY }}
      AWS_DEFAULT_REGION: auto
      BUCKET: culvert-catalog
      BASE_URL: https://catalog.culvertlabs.com
    steps:
      - uses: step-security/harden-runner@… { egress-policy: audit }   # → block in Phase 6
      - uses: actions/checkout@…                                        # for the verify test
      - name: Require gate approval on the tagged commit
        run: .github/scripts/require-gate.sh security-release-gate.yml "$GITHUB_SHA" assert
      - name: Download signed catalog bundle
        uses: actions/download-artifact@… { name: release-catalog-bundle, path: bundle }
      - name: Resolve ring + version
        id: r
        run: |
          set -euo pipefail
          TAG="${GITHUB_REF_NAME}"
          case "$TAG" in *-rc.*|*-beta.*) RING=beta;; *) RING=stable;; esac
          V="$(jq -r .catalog_version bundle/index.json)"
          echo "ring=$RING" >>"$GITHUB_OUTPUT"; echo "ver=$V" >>"$GITHUB_OUTPUT"
      - name: Upload manifests (immutable)
        run: |
          aws s3 cp bundle/manifests "s3://$BUCKET/${{ steps.r.outputs.ring }}/manifests" \
            --recursive --cache-control "public,max-age=31536000,immutable" --content-type application/json
      - name: Upload sidecars then index (mutable, short TTL)
        run: |
          CC="public,max-age=60,must-revalidate"
          aws s3 cp bundle/index.json.sigstore "s3://$BUCKET/${{ steps.r.outputs.ring }}/index.json.sigstore" --cache-control "$CC"
          [ -f bundle/index.json.sig ] && aws s3 cp bundle/index.json.sig "s3://$BUCKET/${{ steps.r.outputs.ring }}/index.json.sig" --cache-control "$CC" || true
          aws s3 cp bundle/index.json "s3://$BUCKET/${{ steps.r.outputs.ring }}/index.json" --cache-control "$CC" --content-type application/json
      - name: Mirror to immutable history
        run: |
          aws s3 cp bundle "s3://$BUCKET/history/${{ steps.r.outputs.ring }}/v${{ steps.r.outputs.ver }}" \
            --recursive --cache-control "public,max-age=31536000,immutable"
      - name: Download-back + in-binary verify (fail closed)
        env: { CULVERT_RELEASE_GEN_VERIFY_SIGSTORE: "1", CATALOG_URL: "${{ env.BASE_URL }}/${{ steps.r.outputs.ring }}" }
        run: go test -run TestReleaseCatalogServedVerify -count=1 -v .   # NEW test: fetch live URL, verify
      - name: Purge cache (index + sidecars as a set)
        run: |
          curl -fsS -X POST "https://api.cloudflare.com/client/v4/zones/${{ secrets.CF_ZONE_ID }}/purge_cache" \
            -H "Authorization: Bearer ${{ secrets.CF_CACHE_PURGE_TOKEN }}" -H "Content-Type: application/json" \
            --data "{\"files\":[\"$BASE_URL/${{ steps.r.outputs.ring }}/index.json\",\"$BASE_URL/${{ steps.r.outputs.ring }}/index.json.sigstore\",\"$BASE_URL/${{ steps.r.outputs.ring }}/index.json.sig\"]}"
      - name: Confirm edge serves the new version
        run: |
          test "$(curl -fsS "$BASE_URL/${{ steps.r.outputs.ring }}/index.json" | jq -r .catalog_version)" = "${{ steps.r.outputs.ver }}"
```

(Wrangler or `rclone` are equally valid; `aws s3` shown for familiarity. R2 is
S3-compatible.)

### 8.6 Proposed updater verification pseudocode (appliance side — UNCHANGED, restated for the review)

```text
fetch_and_verify(base_url, trust /*baked root + pinned ci.yml identity*/, floor):
    # Phase 1 — trust gate (release_catalog_http.go)
    idx_bytes        = GET base_url + "/index.json"            (bounded, SSRF-guarded, conditional)
    sigstore_bytes   = GET base_url + "/index.json.sigstore"   (only if sigstore scheme active)
    sig_bytes        = GET base_url + "/index.json.sig"        (only if ed25519 scheme active)
    outcome = verify_index_signature(idx_bytes, sigstore_bytes, sig_bytes, trust)
        # artifact-owns-outcome: present-but-invalid ⇒ REJECT (no downgrade)
        # offline: uses integrated Rekor timestamp; identity must match pinned SAN+issuer
    if outcome == REJECT: return FAIL_CLOSED("signature")     # keep current catalog

    # Phase 2 — only on a trusted index
    idx = parse(idx_bytes)                                     # now trusted
    for entry in idx.releases:
        man = GET base_url + "/manifests/" + entry.manifest_ref   (shape-validated bare name)
        assert sha256(man) == entry.manifest_sha256           # per-manifest authenticity
    cat = LoadVerifiedCatalog(staged_dir, trust)              # re-verify (defense in depth)

    # Freshness + rollback (release_catalog_freshness.go)
    assert cat.expires_at present and now <= cat.expires_at + 5min
    assert now <= cat.generated_at + 5min  (no future-dating)
    assert cat.catalog_version >= 1 and cat.catalog_version >= floor
    publish_atomic(cat); raise_floor(cat.catalog_version)

    # Resolve → dispatch (release_dispatch*.go) — unchanged
    target = cat.Resolve(channel)                             # PinnedRef = repo@sha256:<list_digest>
    reconcile_repo(target, agent.proxy_repo)                  # equality or one air-gap rewrite
    if agent.running_repo_digests contains target: return ALREADY_CURRENT
    op = agent.POST /v1/upgrades/apply { image_ref: target, rollback_on_failure: true, … }
    watch(op); verify running RepoDigest == target else FAILED_NEEDS_ATTN
```

The only *new* pseudocode the migration adds is Phase-6 rollout honoring:

```text
    # OPTIONAL Phase 6 — phased rollout (additive, forward-compatible)
    if idx.rollout and idx.rollout.release_id == target.release_id:
        bucket = crc32(stable_node_id + idx.rollout.salt) % 100
        if bucket >= idx.rollout.percent:
            target = previous_recommended    # not yet in the rollout cohort
```

### 8.7 Test plan

**Existing tests that must stay green (no regression):**
`TestReleaseCatalogGate`, `TestReleaseCatalogKeylessVerify`, `TestReleaseIdentitySSOT`,
`TestGenerateReleaseCatalog_Deterministic`, `TestPhase1CI_FailClosedMatrix`,
`release_catalog_sigstore_test.go`, `release_autoseed_test.go`,
`release_management_install_contract_test.go`.

**New tests:**

| Test | Level | Asserts |
|---|---|---|
| `TestReleaseCatalogServedVerify` | CI (live) | Fetch `catalog.culvertlabs.com/<ring>` and verify with the real in-binary verifier; fails the publish if served bytes don't verify. |
| R2 layout contract | unit | Upload script produces the exact `<ring>/index.json[.sigstore], manifests/*, history/<ring>/v<N>/*` layout with correct `Cache-Control`. |
| Cache-atomicity e2e | e2e | Rapid publish; a poller never pairs a new index with an old signature (fails closed + self-heals) — validates §2.8/R7. |
| Expiry/re-sign | e2e | `catalog-resign` bumps `catalog_version` + slides `expires_at`, same digests; appliance accepts (version up), floor raised. |
| Revocation | e2e | `catalog-revoke` publishes higher version omitting a release; appliance stops offering it, refuses the old lower-version replay. |
| Private-GHCR pull (if private) | e2e | With images private, agent `docker login` + digest pull succeeds; without creds it fails closed with a clear error. |
| Legacy-tag fallback off | unit | `update.go` GitHub-tags path is default-off / doesn't 404-brick on a private repo. |
| Extend `appliance-catalog-update-e2e.yml` / `catalog-e2e.yml` | e2e | Repoint at an R2-shaped origin (local S3 mock or the staging bucket). |

**External monitoring (not CI):** a scheduled verify canary hitting every ring +
alerting on verify-fail / version regression / `available:false`.

### 8.8 Rollback plan (the migration itself)

| Situation | Rollback |
|---|---|
| R2 job flaky in Phase 1–2 | Disable `publish-catalog-r2`; Pages still authoritative; no customer impact. |
| R2 origin bad after Phase 3 default switch | Appliances that already set the Pages URL are unaffected; new installs can be told to set the Pages URL; re-enable Pages if deleted (it isn't until Phase 5). |
| Discovered bad catalog on R2 | `catalog-revoke` (forward, higher version) + purge; re-serve `history/` last-good if needed. |
| Post-Phase-5 R2 outage | Cloudflare resilience is the primary; break-glass: re-enable a temporary Pages publish (revert the Phase-5 deletion) or serve `history/` last-good from an alternate origin; appliances fail closed meanwhile (proxy keeps running). |
| Repo-private regression (Phase 4) | Repo visibility is reversible; flip back to public while B3/B4 are fixed. |

---

## 9. Product Release Operations (PM / Release Engineering)

Goal: the PM approves promotions and monitors health — never hand-edits
manifests, catalogs, or infra. Everything below is designed so the human decision
surface is **"promote?" and "roll back?"**, nothing else.

### 9.1 Dev → production journey

```
Developer merges to main
  → CI validates everything (fast + deep gates, race+coverage, security gate, QA gate)
  → (optional) dev ring auto-publish for the internal test fleet
  → auto-tag bumps patch, waits for BOTH gates on the SHA, pushes v* tag
  → tag build: images pushed+signed, catalog generated+gated+signed, bundle attached
  → publish-catalog-r2 → beta ring (rc tags) or stable (GA tags), download-back verified, cache purged
  → smoke validation (canary appliance runs a real update from the ring)
  → RELEASE APPROVAL (the single human gate — protected `release` environment reviewer)
  → gradual rollout (rings + optional percentage)
  → telemetry validation (health signals green)
  → automatic promotion of the channel pointer to `recommended` on stable
```

This mirrors the ideal flow in the brief; the **only manual step is Release
Approval** (a GitHub Environment review + a "promote channel" action).

### 9.2 Exact promotion workflow

1. **RC cut:** tag `vX.Y.Z-rc.N` → publishes to **beta** ring. `beta`'s
   `recommended` channel points at the rc.
2. **Beta soak:** beta appliances (opted-in) run it; telemetry + manual QA.
3. **Promote to stable:** a `workflow_dispatch` "promote" action re-generates the
   **stable** index at a higher `catalog_version`, adding the *same release_id +
   same digest* (no rebuild, no re-sign of the image — the image digest is
   identical) and pointing `stable.recommended` at it. Re-sign the **catalog**
   (new bytes ⇒ new keyless sig), upload, purge. **No manifest hand-editing** —
   the promote workflow takes `release_id` + target ring and does the rest.
4. **Phased pointer move:** optionally stage the `recommended` move via the
   `rollout` percentage (§9.7) before it becomes 100%.

### 9.3 Approvals required

- **Automated (no human):** build, test, scan, image push+sign, catalog
  gen+gate+sign, R2 publish to **beta/dev**, download-back verify.
- **Manual (human):** **promotion to `stable`** and **`recommended` pointer
  move** (protected `release` environment reviewer). Emergency **revocation**
  (dispatch, admin-gated). That's the entire human surface.

### 9.4 Automated vs manual matrix

| Step | Auto | Manual |
|---|---|---|
| CI validation, race, coverage, security/QA gates | ✅ | |
| Image build/push/sign, SLSA provenance | ✅ | |
| Catalog gen/gate/sign, digest-match | ✅ | |
| Publish to dev/beta, download-back verify, cache purge | ✅ | |
| Canary smoke on beta | ✅ | |
| **Promote beta → stable** | | ✅ approve |
| **Move `recommended` pointer / rollout %** | | ✅ approve |
| Weekly re-sign (freshness) | ✅ | |
| **Emergency revocation** | | ✅ dispatch |

### 9.5 Artifacts produced every release

Per tag: multi-arch images (GHCR, signed, provenance/SBOM) + release binaries
(+ `.sigstore.json` + SBOMs) + SLSA provenance + the signed catalog bundle
(`index.json`, `index.json.sigstore`, `manifests/*`, `checksums.txt`) on the
GitHub Release **and** in R2 (`<ring>/` + `history/<ring>/v<N>/`). All already
produced today except the R2 copy (this plan) — nothing new to hand-make.

### 9.6 Release dashboard (what should appear)

Two surfaces:

- **Appliance-facing (exists):** `/api/releases` — `available`, `verify_mode`,
  `trust_schemes`, `catalog_version`, `expires_at`, `generated_at`, `releases`,
  `channels` (`release_api.go:231-247`). Add: catalog origin **host** + last
  seed/refresh outcome (P1.7 deferred stretch).
- **Release-engineering-facing (new, Phase 6):** a dashboard sourced from
  `.well-known/culvert-catalog.json` + Rekor + CI + the verify canary showing per
  ring: current `catalog_version`, `generated_at`/`expires_at` (with a
  days-to-expiry countdown), the release each channel points at, rollout %,
  fleet adoption (from opt-in telemetry), verify-canary status, R2/edge health,
  and the last successful publish/re-sign time. This is the PM's monitoring
  surface.

### 9.7 Release notes generation

- Source: PR titles/labels between tags (conventional commits already advised by
  `code-review.yml`) → generate a changelog → set `changelog_url` (and/or
  `notes`) in the manifest at generation time (the field exists,
  `catalogManifestFile.ChangelogURL/Notes`). Automate via
  `release-please`/`git-cliff`-style generation in CI; the PM edits prose only if
  desired, never the manifest JSON.

### 9.8 Rollback points tracked

- Every `catalog_version` per ring is an immutable rollback/audit point in
  `history/<ring>/v<N>/`. The dashboard lists them with their pointed-at release
  + digest. "Roll back" = publish-forward to a higher version pointing at an
  earlier good release (§2.7) — the history archive tells the PM exactly which
  digest that was.

### 9.9 Hotfix releases

- Branch from the released tag, fix, tag `vX.Y.(Z+1)`; the normal pipeline runs.
  Fast-track: an rc can be skipped for a `severity: critical` hotfix, going
  straight to stable via the promote workflow (still gate-approved). The
  `critical` channel can point at it to signal urgency (severity is
  prominence/alert, not auto-apply — `D1.6d-P1.6 §2.1`).

### 9.10 Beta → stable promotion

See §9.2 step 3 — a workflow that re-publishes the **same digest** into the
stable index at a higher version. No rebuild, no image re-sign; catalog re-signed
because its bytes change. Fully automated except the approval.

### 9.11 Knowing a release is healthy before broad rollout

- **Pre-rollout:** all CI gates + canary appliance runs the *real* digest-pinned
  update on beta and reports success (`verify running RepoDigest == target`).
- **During rollout:** opt-in appliance telemetry (dispatch success/fail rate,
  post-update health-gate results, rollback events) + the verify canary + error
  budgets (mirroring `update_cluster.go`'s canary/soak/error-budget pattern,
  `update_cluster.go:274,820`). Auto-halt the pointer move if the error budget
  is exceeded.

### 9.12 Phased rollout (1% / 5% / 25% / 100%)

Two composable layers:

- **Rings (coarse):** dev → beta → stable. Operator/product opts fleets into
  rings.
- **Percentage (fine, within stable):** the optional `rollout` field (§8.4);
  each appliance deterministically buckets itself by `hash(node_id + salt) % 100`
  and only adopts the rollout release if `bucket < percent`. The promote workflow
  steps `percent` 1 → 5 → 25 → 100 on a schedule or on approval, each step gated
  by telemetry (§9.11). At 100% the `recommended` pointer is simply the rollout
  release and the `rollout` field is dropped.
- **[Important product note]** Culvert dispatch is **operator-confirmed, not
  auto-apply** today (`D1.6d-P1.6` non-goal). So "rollout %" controls what the
  catalog **offers** as `recommended` to each appliance; an appliance still
  applies on operator confirm (or on a future opt-in auto-apply). This is the
  honest, safe default for a security appliance and should be stated to
  stakeholders — "gradual rollout" = gradual *offering*, with optional auto-apply
  as a separate, opt-in capability.

### 9.13 Emergency revocation (pull a release immediately)

Runbook (`catalog-revoke.yml`, dispatch, admin-gated):

1. Input: `ring`, `release_id` to pull, reason.
2. Regenerate the ring index at **`catalog_version + 1`**, removing the release
   from `releases[]` and re-pointing every channel that referenced it to the
   prior good release; mark it `yanked` in history metadata.
3. Re-sign (keyless), upload, **mirror to history**, **purge cache**, confirm the
   edge serves the new version.
4. (Optional, defense in depth) physically delete the yanked
   `manifests/<id>.json` from the live ring (the index no longer references it;
   the immutable copy stays in `history/`).
5. Alert the fleet (dashboard + opt-in push).
- **Why forward, not down:** the monotonic floor means appliances that already
  saw the bad version won't accept a lower one; a higher version that omits the
  release is the only mechanism that reliably retracts it everywhere. Worst-case
  latency = cache TTL (60s) + purge.

### 9.14 Minimizing manual work — summary

The PM/RE human surface is exactly three buttons: **Promote (beta→stable)**,
**Advance rollout / move `recommended`**, **Revoke**. Everything else —
building, testing, scanning, pushing, generating, signing, uploading,
verifying-back, purging, re-signing for freshness — is automated and fail-closed.
No human ever edits a manifest, an index, a signature, or an R2 object by hand.

---

## 10. Open decisions & assumptions ledger

**Decisions needed before Phase 1 (recommended answers in bold):**

1. **Do container images go private in GHCR, or stay public?** **Recommendation:
   keep images public** (metadata/source private) unless there's a business
   reason to hide image bytes — the digest pin already prevents tampering, and it
   eliminates B4 + the entire pull-credential subsystem. If they must be private,
   §4.3 covers it.
2. **Legacy `update.go` GitHub-tags fallback (B3):** **retire it** (per
   `D1.6d-P1.6 §12`) rather than authenticate it — the digest-pinned catalog path
   supersedes it.
3. **Stable `expires_at`:** **180d + weekly re-sign** (vs today's 90d).
4. **Second trust scheme:** **bake an ed25519 org root** for Sigstore-ecosystem
   independence (optional but recommended for a security product).
5. **Ring naming:** `stable/beta/dev` (proposed) — confirm nomenclature.
6. **Domain:** `catalog.culvertlabs.com` (given). Confirm `culvertlabs.com` is/will
   be a Cloudflare zone in the same account as the R2 bucket.
7. **Auto-apply:** stays **operator-confirmed** (recommended); an opt-in
   auto-apply-on-`recommended` is a separate future capability.

**Assumptions (marked [ASSUMPTION] inline):** official builds are Sigstore-only
today (empty baked ed25519 ring); `culvertlabs.com` is Cloudflare-managed;
OIDC-to-R2 creds not yet used (static scoped keys for now); GitHub plan supports
protected Environments (Team/Enterprise).

**Pre-existing issues surfaced (independent of this migration):** 90d expiry
foot-gun (R4); single trust scheme in practice (§4.1); legacy tag-based update
paths (`update.go`/`update_cluster.go`) with no signature chain — all already
flagged for retirement in the roadmap.

---

---

## 11. Post-review addendum (design corrections from the security review)

An independent Palo Alto-style security architecture review
(`roadmap/R2-CATALOG-MIGRATION-REVIEW.md`) confirmed the core thesis (untrusted
transport, in-binary verification, additive migration) but found **three P0
defects that would brick real appliances** — latent in the current code and
*activated for the first time* by this plan's new workflows. These corrections
are **binding on the plan above** and must be resolved on paper before Phase 1.

### P0-1 + P0-2 — The rollback floor is a single GLOBAL integer; rings must share ONE `catalog_version` space

**Verified:** `catalogStateFile` is one unkeyed `{"highest_accepted_version": int}`
(`release_catalog_freshness.go:61-63`), and today's only writer is CI's
`(count of v* tags)+1` (`ci.yml`).

**The §2.2/§2.4 ring model as written is WRONG.** Independent per-ring
`catalog_version` counters (the §8.4 `.well-known` example `dev:611, beta:57,
stable:42`) mean:
- Repointing an appliance from a higher-numbered ring to a lower one (dev→stable)
  **permanently wedges it at `available:false`** — its floor (611) exceeds
  stable's version (42). No attacker required.
- The three writers this plan adds (CI tag build, weekly re-sign, revoke) each
  "bump" the version with no shared authority → they collide, and the next real
  tag release is **rejected as a rollback** against a floor a cron already
  advanced (self-inflicted downgrade DoS).

**Correction (supersedes §2.2, §2.4, §8.4):**
- **One monotonic `catalog_version` authority spanning ALL rings.** Every publish
  (any ring, any writer: tag build, resign, revoke) draws the next version from a
  **single shared counter** — a small `version-counter` object in R2 read-modify-
  written under a conditional-PUT / lease (or an equivalent single source such as
  a monotonic derivation the pipeline agrees on). CI, resign, and revoke all use
  it; none invents its own.
- Because the version space is global and monotonic, a given appliance's floor is
  coherent no matter which ring it points at — moving stable→beta→dev is always
  "forward" (higher numbers) and never wedges. `dev` naturally carries the
  highest numbers (it publishes most), `stable` the lowest of the recent set, but
  all are drawn from the same increasing sequence, so no ring ever emits a number
  below an appliance's floor for a catalog it legitimately should accept.
- **Ring-downgrade caveat (documented):** moving an appliance to a ring whose
  *current* release is an older global version than one it already accepted is
  still a floor violation **by design** (that IS a downgrade). This is correct
  behavior, but operators must be told: ring changes go "up the freshness
  ladder," and a genuine ring downgrade is a break-glass floor reset
  (§2.7 item 3), not a routine repoint. The `.well-known` file therefore reports
  the **single global** current version plus which release each ring currently
  offers — not per-ring version counters.
- The enterprise plan's still-open "explicit break-glass recovery flag to accept
  a lower version" (Phase 3, `enterprise-release-catalog-plan.md`) becomes a
  **hard prerequisite** for supporting any ring downgrade at all.

### P0-3 — No production client-side refresh; the expiry mitigation never reaches a running appliance

**Verified:** production wiring builds a bare `NewCatalogHolder`
(`release_wiring.go:225-228`), not the `Refresher`/ticker; refresh is only the
admin-triggered `rm.refresh` closure, and `isExpiredNow` hides the catalog at
`expires_at` on the read path (`release_catalog_freshness.go:93-102`,
`release_catalog_holder.go`).

**Consequence:** §2.9/§3.4/R4's headline fix — "a weekly re-sign slides the
freshness window" — is **inert** for a long-running appliance. It keeps
serving its loaded catalog and, at `expires_at`, flips to `available:false` until
a **restart or a manual/API refresh**. Publishing a fresh catalog to R2 does not,
by itself, reach it.

**Correction (supersedes §2.9, and re-sequences §6):**
- **Wiring the production periodic refresh (the existing `Refresher`/ticker, or an
  equivalent jittered client-side re-fetch of `CULVERT_RELEASE_CATALOG_URL`) is a
  HARD PREREQUISITE, promoted from Phase 6 to Phase 2** — the R2 cutover is not
  safe without it. Without a client that periodically re-pulls, none of
  re-sign, revocation, or phased-rollout pointer moves propagate without operator
  action, which defeats the entire "PM presses three buttons" model (§9).
- Interval: jittered (e.g. 1h ± jitter) with single-flight + backoff (the
  `Refresher` already implements this per `D1.6d-P1.5`); conditional GET (ETag)
  keeps it cheap and cache-friendly.
- Until that refresh is wired, treat re-sign/revocation as requiring an explicit
  appliance-side "refresh now" (admin API) and **say so** — do not claim
  automatic freshness propagation.

### P1 items accepted from the review (fold into the phases)

- **Download-back verify can false-green on a stale edge cache** (§5.2): the
  verify currently runs against the URL *before* the purge, so it can validate the
  *old* cached index. **Fix:** purge first (or bypass cache with a
  cache-busting/`no-cache` fetch), then verify the *served new* bytes, then a
  final confirm. Make the post-purge confirm a full re-verify, not just a `jq`
  `catalog_version` check.
- **Single Sigstore trust scheme:** promote "bake an independent ed25519 org
  root" (§4.1) from optional to **recommended-before-Phase-5**, so deleting Pages
  doesn't leave a single-scheme, single-origin trust+availability chain.
- **Do not delete Pages (Phase 5) until a *tested secondary origin* exists.**
  A single origin/URL with manual DR is the DR weak point (review DR score 4).
  Keep a second, verified origin (Pages, or a second R2 bucket / alternate
  hostname the client can be pointed at) and a tested "re-serve last-good"
  runbook before removing Pages.
- **Keep container images PUBLIC in GHCR** (confirms §4.3 / §10 decision #1): the
  digest pin already prevents tampering, so private images add credential-
  distribution attack surface for zero integrity gain. Only go private with a
  concrete business justification.
- **The legacy `updater` sidecar also pulls by tag anonymously** (§1.6, B3/B4
  siblings): freeze/retire it on the same schedule as the `update.go` tag path,
  and confirm it isn't the silent update mechanism on any appliance before the
  repo goes private.

### Review scorecard (as delivered)

| Dimension | Score (/10) |
|---|---|
| Security | 8 |
| Reliability | 4 |
| Operability | 5 |
| Maintainability | 6 |
| Scalability | 8 |
| Disaster Recovery | 4 |
| Release Engineering maturity | 6 |

**Verdict: Ship-with-changes** — the security framing, least-privilege token
model, and additive sequencing are sound and preserved; **Reliability and DR are
the gating axes** and are addressed by the P0/P1 corrections above (global version
authority, wired client refresh, tested secondary origin). Do not start Phase 1
until P0-1/P0-2/P0-3 are resolved in the design.

---

*This plan has completed one independent security-architecture review round; see
`roadmap/R2-CATALOG-MIGRATION-REVIEW.md` for the full attack-path analysis and
prioritized change list. Implementation remains gated on the P0 resolutions
above; the current GitHub Pages flow is untouched.*
