# Culvert Release Platform — Master Design (Canonical Engineering Specification)

**Status:** CANONICAL. This document supersedes and consolidates all prior
release-platform design and review documents:
`R2-CATALOG-MIGRATION-PLAN.md`, `R2-CATALOG-MIGRATION-REVIEW.md`,
`R2-CATALOG-MIGRATION-FINAL-ATTACK-REVIEW.md`, `R2-CATALOG-OPERATIONS-REVIEW.md`,
`CUSTOMER-LIFECYCLE-OPERATIONS-REVIEW.md`. Those are now **historical context
only**. Engineering executes from THIS document.

**This is a specification, not a review.** It states final decisions, why each was
chosen over its alternative, and the exact backlog / milestones / order / gates to
implement. It does **not** begin implementation; the next phase is detailed
engineering design for **Epic M0**.

**Two standing product decisions (owner-confirmed) shape everything below:**
- **Initial scope = STABLE-ONLY** (one ring). Multi-ring (beta/dev) is deferred.
- **Container images stay PUBLIC in GHCR.** (Digest pinning already prevents
  tampering; private images would add credential distribution for no integrity
  gain.)

---

## Executive Summary

### Architecture goals
Deliver a **production-grade, signed, digest-pinned software-update channel** for a
self-hosted enterprise security product, hosted on **Cloudflare R2 behind
`catalog.culvertlabs.com`**, that remains correct and available while the source
repository is private, and that scales to thousands of customers with **no
publish-side redesign**.

### Design philosophy
**Transport is untrusted; trust is cryptographic and in-binary.** The appliance
verifies a keyless-signed catalog offline (baked Sigstore root + pinned CI
identity, per-manifest SHA-256, freshness, monotonic rollback floor) *before*
parsing or fetching anything. Hosting (Pages → R2) is therefore an
**availability** change, never a trust change. Everything additive-first; every
failure fails **closed** (never a wrong update) and **safe** (the running proxy is
never taken down by a release-channel fault).

### Operational philosophy
**Publish once to a CDN; the fleet pulls.** Release cost is **O(releases), not
O(customers)** — this is the platform's core scaling property and must be
preserved. Because the model is pull-based and privacy-preserving, **fleet
visibility is earned, not assumed**: telemetry is **opt-in**, and support is
served by a **signed support-bundle export**, not phone-home. Humans make product
decisions; machines do everything else (build, sign, gate, publish, verify,
purge, re-sign, monitor).

### Product philosophy
The self-hosted, air-gap-capable, no-mandatory-phone-home posture is a **selling
point** to security buyers — keep it. Make the **human lifecycle** around it
turnkey (guided install, one-click updates/rollback, support bundle, licensing,
EOL signaling) **without adding architectural complexity**. A Product Manager
approves promotions and monitors health; a PM never edits JSON, manifests,
digests, R2 objects, or CI.

---

## Final Architecture

```
 SOURCE (private repo)
   │  merge to main → CI
   ▼
 CI/CD (GitHub Actions, ci.yml)
   ├─ build multi-arch image  ──► CONTAINER REGISTRY: GHCR ghcr.io/kidcarmi/culvert (PUBLIC), pushed BY DIGEST
   ├─ cosign keyless SIGN image + SLSA provenance + SBOM (CycloneDX, signed)
   ├─ generate RELEASE METADATA deterministically from the pushed digest (release_gen.go)
   ├─ gate: TestReleaseCatalogGate (round-trip through the REAL verifier; list_digest == pushed digest)
   ├─ SIGN catalog index (keyless Sigstore → index.json.sigstore ; + ed25519 index.json.sig once E7 lands)
   └─ PUBLISH to CLOUDFLARE R2 (stage → verify → promote → purge)  ──► catalog.culvertlabs.com/stable/
                                                                         index.json[.sigstore|.sig]
                                                                         manifests/<release>.json
                                                                         history/stable/v<N>/…  (immutable)
 CUSTOMER CONTROL PLANE (self-hosted)
   ├─ periodic HTTP REFRESH of CULVERT_RELEASE_CATALOG_URL (E3)
   ├─ VERIFY (two-phase: signature over raw index BEFORE manifest fetch; per-manifest SHA-256;
   │         freshness expires_at; rollback floor) — offline, fail-closed
   ├─ operator-confirmed DISPATCH → culvert-maint agent
   ├─ agent PULLS repo@sha256:<digest> (public GHCR, anonymous), retags culvert/proxy:pinned, restarts,
   │         HARD-VERIFIES running RepoDigest == target
   └─ ROLLBACK: inline auto-rollback on failure + manual rollback to the recorded anchor digest
 DISASTER RECOVERY
   └─ second independent origin (different account/provider) + immutable history/ re-serve + tested runbook
```

| Layer | Final decision |
|---|---|
| **Source code** | Private GitHub repo. Privacy does **not** affect signing/verification (the OIDC identity is unchanged) — but it **does** break the unauthenticated `update.go` GitHub-tags fallback (retire it, E5) and would break anonymous GHCR pulls *only if images went private* (they stay public). |
| **CI/CD** | `ci.yml` remains the single pipeline; add the R2 publish job (E1). Name `CI` stays load-bearing until Pages retirement. |
| **Build** | Multi-arch (`linux/amd64,linux/arm64`), reproducible, provenance + SBOM. Unchanged. |
| **Signing** | **Keyless Sigstore** over the raw index (primary). **ed25519 second scheme REQUIRED before Pages retirement** (E7) — an independent **migrate-off escape hatch**, not live failover (see Security Model). Image cosign signatures unchanged. |
| **SBOM** | Per-module CycloneDX, signed. Surfaced in the Release Console evidence card (E10). Unchanged. |
| **Container registry** | **GHCR, public.** Pulled **by digest**, anonymously. No pull-credential subsystem. |
| **Release metadata** | Existing catalog schema, reused verbatim (`index.json` + `manifests/<id>.json`). Generated deterministically (E1/RB-2). |
| **Cloudflare R2** | Bucket `culvert-catalog`, custom domain `catalog.culvertlabs.com`, `r2.dev` disabled, cached (Cache-Everything rule + Smart Tiered Cache). Provisioned as **IaC** (E4). |
| **Catalog** | `stable/` only initially. `index.json` + sidecars = short TTL, purged on publish; `manifests/` + `history/` = immutable. |
| **Update agent** | `culvert-maint`, unchanged; dispatch is CP-side and operator-confirmed. |
| **Verification** | In-binary, offline, two-phase, fail-closed. Unchanged; the interlock test (`TestReleaseCatalogServedVerify`) is new (E1/RB-4). |
| **Rollback** | Forward-supersede at a higher `catalog_version` (never a lower re-publish) + inline agent auto-rollback + manual anchor-digest rollback. Break-glass version allocation for revoke when the allocator is unavailable (E9/C-6). |
| **Disaster recovery** | Second **independent** origin before Pages deletion; immutable `history/` re-serve; tested drill (E6). |
| **Customer update flow** | Refresh → verify → notify → schedule → operator-confirm (or opt-in critical auto-apply) → apply → validate → one-click rollback. |

---

## Release Platform

### Release lifecycle (stable-only)
```
main merge → CI gates → auto-tag v* (waits for BOTH gates on the SHA) → tag build:
  build+sign image → gen+gate+sign catalog → PUBLISH to R2 stable (stage→verify→promote→purge)
  → customer CPs refresh & verify → operator-confirmed apply (opt-in auto-apply for critical)
Weekly: freshness re-sign (same catalog_version, fresh timestamps) — slides the expiry window.
On incident: emergency revoke (forward-supersede at a higher version).
EOL: per-release supported_until / LTS metadata drives in-product banners.
```

### Versioning (the single most important correctness decision)
- `catalog_version` is a **single monotonic integer**, enforced on the appliance
  by a persisted floor (accepts `version ≥ floor`).
- **Only the TAG BUILD allocates a new version** (`(count of v* tags)+1`,
  deterministic). **Revoke** allocates `last+1`. **These two allocators are
  serialized by a shared CI concurrency group.**
- **The weekly re-sign NEVER allocates** — it republishes the *current* release at
  the *same* `catalog_version` with fresh `generated_at`/`expires_at`. (An equal
  version passes the floor; freshness only needs new timestamps.)
- Result: **a single writer, collision-free, with no distributed CAS.** The full
  atomic version-counter (former "GATE-C") is **only** required if/when multiple
  rings or concurrent publishers exist, and is therefore **deferred with rings.**

### Promotion workflow (stable-only)
There is one ring, so "promotion" = **publish to `stable`** on a tag, gated by the
protected `release` GitHub Environment (one human approval). Multi-ring
graduation (beta→stable, promote-then-repoint) is deferred with rings.

### Release approval
Exactly **one** human gate: approval in the protected `release` Environment
(required reviewer). Everything before (build/sign/gate) and after
(publish/verify/purge) is automated.

### Rollback
Forward-supersede: publish a **higher** `catalog_version` pointing `recommended`
at the last-good release and omitting/`yanked`-flagging the bad one. The monotonic
floor forbids a lower re-publish **by design**. Appliance-side, the agent's inline
auto-rollback and the manual anchor-digest rollback handle a bad apply.

### Emergency release / Hotfix
Expedited **full-gate** hotfix lane (no RC soak; all gates run). One-click PM
approve → publish → `critical` channel points at the fix → refresher pulls within
the interval → opt-in critical auto-apply installs; others get a prominent
notification. **Break-glass version allocation (C-6):** if the allocator is
unavailable, a dual-control, audited manual allocation of `last+1` is permitted so
a down allocator can never block a CVE response.

### Release history / Retention
Every publish writes the full bundle to immutable `history/stable/v<N>/`
(create-only). This is the audit + rollback + DR substrate. Retain indefinitely
(objects are tiny); manifests are content-addressed. `history/` is never mutated
or deleted by the pipeline.

### Release metadata
Reuse the shipped schema verbatim. Additive, forward-compatible fields introduced
later: `supported_until` / `lts` (EOL, E13) and — only with rings — `rollout`
(percentage) and `yanked`.

---

## Customer Operations

### Onboarding & installation
Self-hosted: Linux host + Docker + `scripts/install.sh` (seeds pinned image, wires
`culvert-maint`, health-validates). **Before Enterprise GA:** a **first-run wizard
+ install preflight** (validate NTP/clock, Docker posture, ports, DNS, TLS) that
**refuses or loudly warns** rather than booting subtly-broken; and a **turnkey form
factor** (OVA/ISO or certified cloud image) — Culvert is software today, not an
appliance, which is the largest onboarding friction.

### Production readiness
Reuse and extend `diagnostics.go`'s `OperatorContract` (ok/warn/fail + actionable
hints) into an explicit readiness screen: admin+2FA, TLS-not-self-signed, **NTP
synced**, **backup configured AND test-restore passed**, log/SIEM sink,
catalog reachable+fresh+verified, cert-expiry > 30d, HA quorum (if clustered),
license valid (when it exists), default-deny active.

### Daily operations
Health verdict; **scheduled backups by default**; cert-expiry alerts; update
discovery+notification+scheduling; policy management (config-versioned, one-click
rollback); logs → SIEM; reference Grafana dashboard + alert rules shipped with the
product.

### Support
**Signed, redacted support-bundle export** (extends `diagnostics.go`): health
verdict + version/digest + config-version summary + recent audit + update history
+ health timeline — one click, safe to email or hand over air-gapped. **No vendor
remote access** (keep off by design; the bundle is the channel).

### Disaster recovery
Primitives are strong (HA fencing lease; backup/restore with
validation→analyzer→offline commit; config-version rollback). **Add runbooks** for
the human crises: lost admin (break-glass reset), lost CA passphrase, full site
rebuild, decommission/secure-wipe.

### Renewal
Driven by a **signed offline license file** (`/data/license.json`, verified with
the *existing* signing primitives — no new crypto): entitlement + support tier +
`expires_at` + `eol_at`; the UI shows renewal/EOL banners; the catalog carries
`supported_until`/LTS so "am I supported?" is answerable in-product.

### End of Life
`culvert decommission`: export config + final audit archive → secure-wipe `/data`
(CA keys, KEK material, sessions) → confirm. Documented runbook.

### Support Bundle (specification)
A single command/UI action produces a signed archive containing: `OperatorContract`
JSON, product+catalog version and running digest, `configBackup` *summary* (never
secrets), the last N audit entries, update/dispatch history, freshness/verify
state, and host/agent health — **redacted and safe** for offline transfer.

### Telemetry philosophy
**Opt-in, aggregate, privacy-first.** Default OFF. A "release health beacon" may
report anonymized `{install-id, from/to catalog_version, outcome, error-class,
arch}` — no PII, no policy, no traffic. Air-gapped customers **export a signed
health bundle** instead. The vendor Release Console shows fleet metrics with an
explicit **"coverage: N% reporting"** so partial/zero telemetry is honest, never
faked. A security product **earns** telemetry; it never forces phone-home.

---

## Product Operations

| Role | How they operate (target) |
|---|---|
| **Product Manager** | In the **Release Console**: Create (pick a green build, write note prose) → Review (auto-assembled evidence: gates, signature identity, SBOM, provenance, changelog, freshness) → **Approve** (one click, the protected-env review = the audit record) → Promote (publish to stable) → Monitor (opt-in telemetry health) → Complete (auto). **Never edits JSON/manifests/digests/R2/CI.** Revoke and re-sign are console **buttons**. |
| **Release Engineering** | Owns the pipeline + IaC guardrails; runs the versioning contract (single-allocator, shared concurrency group, no-bump re-sign); operates the verify canary + alerting; owns rotation of infra tokens and the trusted-root aging cadence. |
| **Support Engineering** | Works from the **support bundle**; triages version/digest, health verdict, config-version diffs, update history, audit anomalies; guided config rollback or backup restore; escalates with the bundle attached; never requests remote access. |
| **SRE** | Owns release-channel SLOs (publish success, verify-back pass rate, canary uptime, catalog freshness); runs the synthetic verify canary that pages on verify-fail/version-regression/edge outage; owns the DR drill. The proxy hot path is never in the release-channel blast radius (fail-safe). |
| **Engineering** | merge → auto-tag → gated build → console-driven promote/verify/monitor. Release notes auto-generated from conventional-commit PRs. RB-2 determinism + RB-4 served-verify make releases safe for any engineer, not just the author. |

---

## Security Model (accepted decisions, consolidated)

- **Signing.** Keyless Sigstore (`cosign sign-blob`) over the **raw** `index.json`,
  tag-path only. The index binds each manifest by SHA-256, so signing the index
  transitively authenticates all manifests. Determinism is load-bearing.
- **Second scheme.** An independent **ed25519** catalog root (REQUIRED before Pages
  retirement, E7). It is a **migrate-off escape hatch**, **not** live failover:
  under the shipped `artifact-owns-outcome` rule a *present-but-invalid* `.sigstore`
  hard-rejects and never falls through to ed25519, so dual-serving does **not**
  rescue a Sigstore-incident. Live durability comes from **B-2 root aging** (ship a
  fresh TUF `trusted_root.json` in every build + a build-time "root not near
  expiry" check).
- **Verification.** In-binary, offline (integrated Rekor timestamp), two-phase
  (verify raw index → then enumerate/fetch manifests), per-manifest SHA-256,
  freshness (`expires_at` required, 5-min skew, no future-dating), rollback floor.
  Fail-closed. R2 sits entirely on the untrusted side; every byte is re-verified.
- **Trust anchors.** Baked Sigstore `trusted_root.json` (public) + pinned identity
  (`token.actions.githubusercontent.com` + `…/ci.yml@refs/tags/v*`), SSOT in
  `release_identity.env` (kept byte-equal to the Go constants by test). ed25519
  public ring (E7). **No private signing keys in repo/image/installer/catalog.**
- **Threat model / supply chain.** R2 write compromise = **denial only** (fail-safe
  to `available:false`), never integrity bypass (signature is the wall). The
  **real** high-value target is CI/OIDC (it holds the signing identity) — mitigated
  by: **verified `v*` protected-tag ruleset** (as IaC, asserted not assumed),
  **Rekor identity monitoring** with a paging response (MTTR < refresh interval),
  **minimized `id-token: write`** (only signing jobs; the R2 publish job carries
  `contents: read` only), SLSA provenance + reproducible-build, and
  **operator-confirmed apply** as the human-in-loop backstop.
- **Repository privacy.** Does not affect signing/verification/build/runtime.
  Breaks only the unauthenticated GitHub-tags legacy checker (retired, E5).
- **Public images.** No secrets are baked (only public trust material); the sole
  "exposure" is product IP — an accepted business decision. Digest pinning +
  Docker's on-pull digest verification make a public registry safe.
- **Catalog integrity end-to-end.** Deterministic gen → CI gate asserts
  `list_digest == pushed digest` → keyless sign → **stage→verify→promote** (the
  live pointer is never overwritten with unverified bytes) → cache purge → served
  verify. A bad or tampered catalog is rejected in CI, at the edge verify, or in
  the binary — never applied.

---

## Final Decisions

| # | Decision | Reason | Alternative rejected | Future evolution |
|---|---|---|---|---|
| D1 | **Host on Cloudflare R2 behind `catalog.culvertlabs.com`** | Decouples public metadata availability from repo visibility; CDN-cached, WAF-eligible; pull-based static artifact scales O(releases) | GitHub Pages (breaks when repo private); OCI artifact / release assets (auth-gated when private) | Second independent origin for DR (E6) |
| D2 | **STABLE-ONLY initially** | Removes the entire distributed-CAS counter + graduation machinery from launch; genuinely single-writer; fastest safe path | Full rings (beta/dev) now — unneeded complexity before a second ring is real | Add rings + the atomic version-counter + graduation tooling when a second ring is required |
| D3 | **PUBLIC GHCR images** | Digest pin already prevents tampering; avoids per-customer pull-credential distribution (pure added attack surface for zero integrity gain) | Private images + pull tokens | Revisit only with a concrete IP-confidentiality business case |
| D4 | **Re-sign NEVER bumps `catalog_version`; tag-build + revoke are the only allocators, serialized by a shared CI concurrency group** | Makes stable-only a true single-writer → no collisions, no CAS. Fixes the concurrent-writer defect (RB-1) | Non-atomic `max(tag,last)+1` across un-serialized workflows (collides at equal version) | Atomic CAS counter when multiple rings/publishers exist |
| D5 | **Deterministic catalog spec (no wall-clock in the spec step)** | Re-runs are idempotent; with create-only `history/`, a partial/retried publish cannot wedge a version (fixes RB-2) | Embedding `date -u` in the spec (non-idempotent) | — |
| D6 | **Publish via stage→verify→promote (verify the staged `history/v<N>/` bytes, then promote to live)** | The live pointer is never overwritten with unverified bytes; a verify failure leaves the prior catalog fully intact at origin and edge (fixes the Codex live-overwrite defect) | "Upload to live then verify then maybe-don't-purge" (origin already serves bad bytes after TTL) | — |
| D7 | **R2 publish job carries `contents: read` only (no `id-token: write`)** | It only *verifies* an already-signed bundle; OIDC there would let a compromised step forge a token matching the pinned identity | Granting `id-token` "for the verify test" (the offline verify needs none) | — |
| D8 | **Wire a production periodic HTTP refresher** | Without it, re-sign/revoke/rollout never reach running appliances (fixes RB-3). Not a flag — new HTTP integration (the shipped Refresher drives a local dir) | Assuming the existing Refresher is production-wired | Opt-in critical auto-apply on top |
| D9 | **`expires_at` = 180d + weekly no-bump re-sign** | A low-cadence security product must not brick auto-seed at 90d of silence; the re-sign slides the freshness window without a software release | 90d expiry with no re-sign (self-inflicted `available:false`) | Optional short-lived timestamp role (TUF-style) |
| D10 | **Rollback = forward-supersede at a higher version + C-6 break-glass allocation** | The monotonic floor forbids lower re-publish (anti-downgrade); break-glass ensures a down allocator can't block an emergency revoke | Lower-version re-publish (reopens downgrade attack); pure fail-closed allocator (blocks CVE response) | — |
| D11 | **ed25519 second scheme REQUIRED before Pages deletion; framed as escape hatch, not failover; B-2 root aging is the durability control** | `artifact-owns-outcome` means a present-but-invalid `.sigstore` never falls through, so ed25519 can't hot-rescue; root aging is what actually prevents offline verification death | "Dual-serving = live Sigstore-incident failover" (false under the code) | Multi-key ed25519 ring with rotation windows |
| D12 | **Keep apply OPERATOR-CONFIRMED; opt-in critical auto-apply later, gated on a hardened detection→response MTTR** | Human-in-loop is the backstop against a valid-identity malicious catalog; auto-apply without fast detection removes it | Default auto-apply now | Opt-in critical auto-apply once A-2/A-4 MTTR < refresh interval |
| D13 | **Do NOT delete Pages until a tested, independent secondary origin + re-serve runbook exist** | Single-origin + single aging root is the DR weak point; a same-account second bucket is DR theater | Delete Pages at cutover | — |
| D14 | **Retire the legacy tag-based update paths** (`update.go` GitHub-tags checker; `updater` sidecar) | Unauthenticated GitHub-tags 404s on a private repo; both pull by tag with no signature chain; superseded by digest-pinned catalog dispatch | Authenticating/keeping the tag path | Remove the sidecar from compose after cutover |
| D15 | **IaC = Terraform guardrails only** (R2 bucket/policy, custom domain, cache rules, `release` env protections, `v*` ruleset, monitors); pipeline owns artifact uploads | Guardrails must not drift and must be *asserted* (GATE-A); artifacts are the pipeline's job | Heavier control plane (Crossplane/operator) — overengineering for one bucket/zone | Extend as products/rings grow |
| D16 | **Opt-in telemetry + signed support-bundle export; never mandatory phone-home** | Security buyers air-gap; the model must earn visibility; the bundle serves support offline | Mandatory telemetry (customer-hostile); no observability (blind support) | Unified per-product fleet view |
| D17 | **Build a vendor Release Console; PM never edits machinery** | Turns "PM only makes product decisions" from aspiration into reality; makes releases safe for any engineer | git-tag + workflow_dispatch choreography by hand (release-engineering defect) | Multi-product-aware console |
| D18 | **Reuse the shipped catalog schema; extensions are additive/forward-compatible** | Unknown fields are tolerated; no migration needed | Schema rewrite for hosting | `supported_until`/`lts`; (rings) `rollout`/`yanked` |

---

## Deferred Features

### Required for MVP (first R2 publish, internal)
D1, D4, D5, D6, D7, D8; deterministic pipeline; `TestReleaseCatalogServedVerify`;
Cloudflare provisioned via IaC (D15); `publish-catalog-r2` to a **staging** bucket;
verify canary skeleton.

### Required before Customer Cutover / repo-private
D2, D3, D9, D10, D14; dual-publish (Pages + R2); wired refresher proven end-to-end;
verify canary + alerting live; GATE-A signing-surface controls (verified `v*`
ruleset, Rekor monitor + response, minimized `id-token`).

### Required before Pages Retirement
D11 (ed25519 second scheme + KMS custody + root aging), D13 (tested independent
secondary origin + re-serve runbook).

### Required before Enterprise GA
Release Console (D17); opt-in telemetry + support-bundle export (D16); first-run
wizard + preflight; scheduled backups + cert-expiry alerts; update
notification/scheduling/one-click rollback; offline license + EOL metadata; crisis
runbooks; a turnkey form factor (OVA/ISO or certified image).

### Future enhancements
Rings (beta/dev) + atomic CAS version-counter + graduation tooling; percentage
rollout (`rollout` field + client bucketing); opt-in critical auto-apply.

### Five-year (multi-product: SWG/CDR/Browser/Agent/DLP/ZT)
Per-product catalog namespaces under the same domain/signing; product-aware Console
+ unified fleet view; **cross-product compatibility/bundle metadata** (the one real
operational redesign — metadata + console, not hosting).

---

## Engineering Backlog (Epics)

> Complexity: S (≤ few days) · M (1–2 wks) · L (3–4 wks) · XL (multi-month).

### E1 — R2 Publishing Pipeline & Correctness Core
- **Objective:** publish a signed catalog to R2 correctly and idempotently.
- **Tasks:** deterministic spec step (D5); `publish-catalog-r2` job with
  stage→verify→promote→purge (D6), `contents: read` only (D7); `history/v<N>/`
  create-only; `TestReleaseCatalogServedVerify` (RB-4); target a **staging** bucket first.
- **Dependencies:** E4 (Cloudflare + secrets) for a live run; mockable via S3 local first.
- **Acceptance:** a tag publishes a bundle to staging that the **real in-binary
  verifier** accepts against the served URL; re-running the same tag is a no-op and
  cannot wedge a version; verify-fail leaves the prior live pointer intact.
- **Risks:** R2 `If-*` semantics; cache-consistency at the edge. **Rollback:** feature-flag the job off; Pages remains authoritative.
- **Complexity:** L.

### E2 — Version Authority (single-writer)
- **Objective:** collision-free monotonic `catalog_version` (D4).
- **Tasks:** re-sign never allocates; shared CI concurrency group across tag-build + revoke; a concurrency test firing tag-build + revoke together asserting distinct, monotonic versions and no `history/` overwrite.
- **Dependencies:** E1.
- **Acceptance:** the concurrency test passes; no two publishes share a version.
- **Risks:** an un-grouped future workflow reintroduces collision. **Rollback:** none needed (additive guardrail). **Complexity:** M.

### E3 — Production Client Refresh
- **Objective:** running appliances discover new/re-signed/revoked catalogs automatically (D8).
- **Tasks:** drive `HTTPCatalogProvider` from a production refresher (jittered interval, single-flight, backoff, ETag/304); verify → freshness → rollback → atomic publish; raise floor only on accepted pull; tests incl. silent-stop detection + expiry-hides-catalog behavior.
- **Dependencies:** E1 (something to fetch).
- **Acceptance:** an appliance converges to a freshly published/re-signed catalog within the interval without restart; a bad/expired catalog fails safe (proxy unaffected).
- **Risks:** unattended floor-raise amplifies a bad version fleet-wide → gated on E2 correctness. **Rollback:** config flag to disable the ticker (manual refresh remains). **Complexity:** L.

### E4 — Cloudflare + IaC Guardrails + Signing-Surface (GATE-A)
- **Objective:** provisioned, drift-proof infra + a defended signing surface (D15, GATE-A).
- **Tasks:** Terraform (Cloudflare provider: bucket/policy, custom domain, cache rules, WAF/rate-limit; GitHub provider: `release` env protections, `v*` ruleset, required checks); an automated ruleset-attestation check; Rekor identity monitor + paging response; minimize `id-token` scope.
- **Dependencies:** owner provides CF account + secrets.
- **Acceptance:** `terraform plan` is clean; the ruleset-assertion check is green; a Rekor-monitor drill classifies known vs unknown signing correctly.
- **Risks:** OIDC-to-CF not GA (use scoped static keys). **Rollback:** infra is additive; no customer impact. **Complexity:** L.

### E5 — Legacy Retirement
- **Objective:** remove repo-private breakage and the unsigned tag paths (D14).
- **Tasks:** default-off/remove `update.go::checkGitHubLatestTag`; freeze then remove the `updater` sidecar from compose (keep binary self-update out of scope).
- **Dependencies:** none.
- **Acceptance:** with the repo private, no code path makes an unauthenticated GitHub call; the sidecar is not the update mechanism anywhere.
- **Risks:** a customer relying on the legacy path. **Rollback:** re-enable the sidecar (kept until cutover). **Complexity:** S–M.

### E6 — DR: Secondary Origin + Verify Canary + Alerting
- **Objective:** detect release-channel faults and survive an origin loss (D13).
- **Tasks:** synthetic canary (fetch+verify every ring every few min, page on fail/regression/outage); a second **independent** origin (different account/provider) + a tested "re-serve last-good from `history/`" runbook; DR drill.
- **Dependencies:** E1.
- **Acceptance:** canary pages on an injected fault; a DR drill fails over and appliances converge.
- **Risks:** same-account "secondary" is theater (forbidden). **Rollback:** n/a. **Complexity:** M–L.

### E7 — Trust Durability (ed25519 + KMS + root aging)
- **Objective:** survive multi-year field life and a Sigstore rotation (D11).
- **Tasks:** bake an org ed25519 root; dual-sign on the tag path; KMS/HSM custody with human-controlled *lifecycle* (automation principal signs each call); ship a fresh TUF `trusted_root.json` per build + build-time expiry check; rotation fixtures.
- **Dependencies:** owner provisions the KMS/HSM key.
- **Acceptance:** dual-scheme verify green; a build with a near-expiry baked root fails CI, not the field.
- **Risks:** weak key custody = net negative. **Rollback:** n/a (additive scheme). **Complexity:** L.

### E8 — Freshness Re-sign + Expiry
- **Objective:** the freshness heartbeat (D9).
- **Tasks:** weekly workflow that re-signs the current stable index at the **same** version with new timestamps (E2's no-allocate rule); raise stable `expires_at` to 180d.
- **Dependencies:** E1, E2.
- **Acceptance:** a re-sign slides `expires_at`, keeps `catalog_version`, and refreshing appliances accept it.
- **Risks:** cron silently stops → alert on missed re-sign. **Rollback:** manual re-sign. **Complexity:** S–M.

### E9 — Emergency Ops
- **Objective:** fast, auditable CVE response (D10).
- **Tasks:** expedited full-gate hotfix lane; `catalog-revoke` (forward-supersede) + C-6 dual-control break-glass allocation; `critical` channel; console buttons (E10); customer-comms trigger.
- **Dependencies:** E1, E2, E10.
- **Acceptance:** a revocation drill removes a release forward; a down allocator does not block revoke (break-glass path exercised, audited).
- **Risks:** break-glass misuse → dual-control + audit. **Rollback:** n/a. **Complexity:** M.

### E10 — Release Console + Release Notes
- **Objective:** PM operates releases without touching machinery (D17).
- **Tasks:** thin app over catalog + CI/Rekor + telemetry; Create→Review→Approve→Promote→Monitor→Complete; revoke/re-sign as buttons; evidence card; conventional-commit release-note generation.
- **Dependencies:** E1, E9, E11 (health tiles).
- **Acceptance:** a PM cuts and promotes a release end-to-end touching only build-selection, note prose, and one approval.
- **Risks:** scope creep. **Rollback:** CI/git path remains. **Complexity:** L–XL.

### E11 — Telemetry + Support Bundle
- **Objective:** earn fleet visibility; unblock support (D16).
- **Tasks:** opt-in health beacon (aggregate, no PII) + signed air-gap health export; **support-bundle export** extending `diagnostics.go`; console fleet tiles with coverage-%.
- **Dependencies:** E10 (surface).
- **Acceptance:** support bundle exports a signed, redacted archive; opt-in beacon reports outcomes; console shows honest coverage.
- **Risks:** privacy review must pass. **Rollback:** telemetry default-off. **Complexity:** L.

### E12 — Customer Onboarding & Update UX
- **Objective:** low-friction day-one and updates.
- **Tasks:** first-run wizard + install preflight (NTP/Docker/ports/DNS/TLS) using `OperatorContract`; scheduled backups + backup-tested readiness; cert-expiry alerts; update notification + maintenance-window scheduling + one-click rollback; reference observability pack.
- **Dependencies:** E3 (update discovery).
- **Acceptance:** the readiness verdict gates "production ready"; a fresh install cannot silently boot mis-timed/mis-TLS'd.
- **Risks:** none material. **Rollback:** features are additive/optional. **Complexity:** L.

### E13 — Commercial Lifecycle (license + EOL)
- **Objective:** clean purchase/renewal/EOL (D18 metadata).
- **Tasks:** signed offline license file (reuse verification primitives); EOL/`supported_until`/LTS catalog metadata + in-UI banners; renewal prompts.
- **Dependencies:** external license-issuance process (owner).
- **Acceptance:** an expired/near-EOL license/version surfaces in-product; no runtime crypto added.
- **Risks:** license UX friction. **Rollback:** license optional at first. **Complexity:** M.

### E14 — Turnkey Form Factor + Lifecycle Runbooks
- **Objective:** appliance-grade onboarding + crisis playbooks.
- **Tasks:** OVA/ISO or certified cloud image (or a hardened near-appliance installer); runbooks for lost admin, lost CA passphrase, site rebuild, decommission/secure-wipe.
- **Dependencies:** E12.
- **Acceptance:** a non-expert can stand up and recover a node from the runbooks + image.
- **Risks:** packaging cost. **Rollback:** DIY compose remains. **Complexity:** XL.

---

## Milestones

### M0 — Foundation & Safety (correctness + first staging publish)
- **Goals:** the pipeline is correct and cannot wedge; a signed catalog reaches R2 staging and verifies as served.
- **Deliverables:** E1, E2, E5; E4 (provision + IaC guardrails, staging bucket).
- **Blocking deps:** owner provisions CF account + secrets (staging).
- **Acceptance gate (Design Complete → M0 done):** deterministic re-run is a no-op; single-writer concurrency test green; `TestReleaseCatalogServedVerify` green against the staging URL; stage→verify→promote proven (verify-fail leaves prior pointer intact); no unauthenticated GitHub calls remain.

### M1 — Dual-Publish + Client Refresh + Detection
- **Goals:** R2 (prod) + Pages both serve; appliances auto-refresh; faults are detected.
- **Deliverables:** E1 (prod bucket), E3, E6 (canary + alerting), E8.
- **Blocking deps:** M0.
- **Acceptance gate (Internal Validation):** a canary appliance updates end-to-end from R2; a re-sign converges to the fleet within the interval; the verify canary pages on an injected fault; both origins byte-identical.

### M2 — Default Switch + Repo Private
- **Goals:** new installs default to R2; the repo goes private without breakage.
- **Deliverables:** doc/installer default = R2; E5 complete; GATE-A (E4) complete; flip private.
- **Blocking deps:** M1; GATE-A green.
- **Acceptance gate (Customer Rollout — soft):** a fresh install auto-seeds from R2 (`available:true`) and updates; private repo breaks nothing (signing, install, runtime all green); legacy tag path off.

### M3 — Trust Durability + Pages Retirement
- **Goals:** two independent trust schemes; a tested secondary origin; Pages removed.
- **Deliverables:** E7; E6 secondary origin + DR drill; delete `publish-catalog-pages.yml`.
- **Blocking deps:** M2; E7 + secondary origin green.
- **Acceptance gate (GitHub Pages Retirement):** dual-scheme verify green; DR drill passes (failover + converge); no workflow references Pages; the only public origin is `catalog.culvertlabs.com` with a tested independent secondary.

### M4 — Emergency Ops + Console + Telemetry
- **Goals:** operable at scale; PM releases without touching machinery; support isn't blind.
- **Deliverables:** E9, E10, E11.
- **Blocking deps:** M2 (M3 recommended).
- **Acceptance gate (Production Ready):** a revocation drill succeeds (incl. break-glass); a PM runs a full release touching only product decisions; support bundle + opt-in telemetry work with honest coverage.

### M5 — Customer Onboarding Hardening
- **Goals:** low-friction install/update/recover.
- **Deliverables:** E12.
- **Blocking deps:** M1 (E3).
- **Acceptance gate:** readiness verdict gates production; no silent day-one misconfig; one-click rollback works.

### M6 — Enterprise GA
- **Goals:** commercial lifecycle + turnkey form factor.
- **Deliverables:** E13, E14.
- **Blocking deps:** M4, M5.
- **Acceptance gate (Enterprise Ready):** license + EOL surfaced in-product; a non-expert onboards and recovers from the image + runbooks.

---

## Implementation Order (and why)

1. **M0 (correctness first).** A pipeline that can wedge itself under its own weekly
   cron (RB-1/RB-2) or overwrite the live pointer before verifying (D6) is
   unshippable at any customer count. Nothing else may proceed on a broken core.
2. **M1 (refresh before cutover).** Re-sign, revoke, and rollout are **inert**
   without a production refresher (D8); and you must **detect** faults (E6) before
   customers depend on the channel. Dual-publish keeps Pages as the safety net.
3. **M2 (private only after legacy fixes).** Going private before E5 would 404 the
   legacy checker and confuse customers; GATE-A must defend the signing surface
   before customers depend on it.
4. **M3 (delete Pages last, never single-origin/single-root).** Retire Pages only
   after a **tested independent secondary** (D13) and a **second trust scheme +
   root aging** (D11) — otherwise you strand the channel on one origin and one
   aging root.
5. **M4 (operability before scale).** Console + telemetry + emergency ops turn a
   working channel into an *operated* one — required before 500 customers.
6. **M5 then M6 (customer experience, then commercial).** Harden onboarding/update
   UX, then add the commercial wrapper and turnkey form factor for Enterprise GA.

**Avoid parallelizing:** E2 depends on E1; E3 depends on E1 *and* is gated on E2
correctness (unattended floor-raise); E7/E6-secondary gate M3; E9/E10/E11 gate M4.
Rings and the CAS counter are **out of the critical path entirely** (deferred).

---

## Final Acceptance Gates (objective pass/fail)

| Gate | PASS criteria (all must hold) |
|---|---|
| **Design Complete** | This document is ratified; every review decision merged; no open conflict; M0 scoped. |
| **Implementation Complete (per milestone)** | All epic acceptance criteria for the milestone green in CI; no known correctness defect; docs/runbooks for that milestone written. |
| **Internal Validation (M1)** | Canary appliance updates E2E from R2; re-sign converges to fleet within the interval; verify canary pages on an injected fault; Pages and R2 byte-identical; verify-fail never mutates the live pointer. |
| **Production Ready (M4)** | Revocation drill (incl. break-glass) succeeds; PM completes a release touching only product decisions; support bundle + opt-in telemetry live; SLOs + alerting green; repo private with nothing broken. |
| **Customer Rollout (M2)** | Fresh install auto-seeds + updates from R2; GATE-A green (verified `v*` ruleset + Rekor monitor+response + minimized `id-token`); operator-confirmed apply retained. |
| **Enterprise Ready (M6)** | License + EOL surfaced in-product; first-run wizard/preflight blocks silent misconfig; scheduled backups + cert alerts on; crisis runbooks validated; turnkey form factor available. |
| **GitHub Pages Retirement (M3)** | Dual trust scheme (Sigstore + ed25519) verifies; TUF root-aging build-check green; tested **independent** secondary origin + re-serve runbook; DR drill passes; **zero** workflow/doc references to Pages. |

---

## Definitions of "done" the platform must always satisfy (invariants)

1. The live catalog pointer is **never** overwritten with unverified bytes.
2. `catalog_version` **never** collides, regresses, or splits.
3. A release-channel fault **never** takes down a customer's proxy (fail-safe).
4. Verification is **offline, in-binary, fail-closed**; R2/CF/edge are untrusted.
5. Apply stays **operator-confirmed** unless a customer opts into critical
   auto-apply *and* the detection→response MTTR is hardened.
6. A PM **never** hand-edits JSON, manifests, digests, signatures, R2 objects, or
   CI variables in a normal release.
7. Telemetry is **opt-in**; support works **offline** via the signed support bundle.
8. Pages is retired **only** behind a tested independent secondary origin **and** a
   second, independently-rotatable trust scheme with a root-aging answer.

---

*End of canonical specification. Next phase: detailed engineering design for Epic
M0 (E1 + E2 + E5 + E4-staging). Do not begin implementation until M0 detailed
design is complete and ratified.*
