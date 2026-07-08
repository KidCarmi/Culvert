# Security-Architecture Review — R2 Catalog Migration Plan

**Reviewer role:** Principal Security Architect (adversarial pre-implementation review)
**Subject:** `roadmap/R2-CATALOG-MIGRATION-PLAN.md` (GitHub Pages → Cloudflare R2 for the release-catalog hosting of a security product)
**Date:** 2026-07-08
**Method:** Every claim below was checked against the shipped code, not taken on the plan's word. File:line references are to the current tree.

---

## Executive verdict

**Verdict: SHIP-WITH-CHANGES — but do NOT begin Phase 1 until the three P0 blockers below are resolved on paper.**

The plan's central thesis is **correct and well-evidenced**: the catalog transport is already untrusted by design, integrity is enforced in-binary (keyless Sigstore over raw `index.json`, pinned `ci.yml@refs/tags/v*` identity, per-manifest SHA-256, freshness, monotonic floor), and R2 sits entirely on the untrusted side. I verified this end-to-end (`release_catalog_verify.go`, `release_catalog_sigstore.go:71-72`, `release_catalog_http.go:114-158`, `trusted_root.json` is the real 6787-byte Sigstore public-good root, not the empty OSS placeholder). **Moving Pages → R2 genuinely is a hosting/availability change, not a trust change.** The migration is low-risk *for confidentiality/integrity*.

However, the plan is **materially wrong or silent on three things that will brick real appliances**, and they are not R2 problems — they are latent defects in the *versioning and freshness control plane* that the migration's new workflows (weekly re-sign, promote, revoke, rings) will *activate for the first time*:

1. **The monotonic rollback floor is a single global integer, not keyed by ring/origin. The plan's "rings = change the URL" model and its independent per-ring `catalog_version` sequences are mutually incompatible with that floor.** Repointing any appliance from a higher-numbered ring to a lower-numbered ring (the plan's own `.well-known` example shows `dev:611, beta:57, stable:42`) **permanently wedges it** to `available:false`. (P0-1)
2. **There is no single monotonic authority for `catalog_version`.** Today it is `(count of v* tags)+1` computed in CI (`.github/workflows/ci.yml:442`). The plan adds *two more* independent writers (the weekly `catalog-resign` cron and the `catalog-revoke` dispatch) that each "bump `catalog_version`" with no shared counter. These collide and regress against each other, and the next real tag release will be **rejected as a rollback** against a floor the cron already advanced. This is a self-inflicted downgrade DoS. (P0-2)
3. **There is no automatic client-side catalog refresh in production.** The `Refresher` with its interval ticker exists (`release_catalog_refresher.go`) but is **not wired** into `loadReleaseManagement` (`release_wiring.go:194-300`); production uses a bare `CatalogHolder` plus an admin-triggered `rm.refresh`. Therefore the plan's headline mitigation for the expiry foot-gun — "a weekly re-sign slides the freshness window forward" — **does not reach a running appliance**. A long-running appliance still hides its catalog at `expires_at` (`release_catalog_holder.go:79` use-time `isExpiredNow`) regardless of how often the origin is re-signed, until it restarts or an admin clicks refresh. (P0-3)

None of these are introduced by R2, but the plan *depends on* the re-sign/promote/revoke/ring machinery working, and that machinery is built on these broken foundations. They must be designed before implementation, not discovered in Phase 6.

Everything else is P1/P2 hardening. The Cloudflare-side security posture (scoped tokens, `release` environment, tag-path-only, no-delete-on-history, in-binary verify as the hard wall) is sound and the plan articulates it well.

---

## 1. Assumption ledger — what holds and what breaks

| # | Plan's claim / assumption | Verified? | Verdict |
|---|---|---|---|
| A1 | Transport is untrusted; R2 write alone cannot forge a catalog (§4.6) | `release_catalog_verify.go:250-285`, `release_catalog_sigstore.go:146-171` | **HOLDS.** Signature verified over raw bytes before parse; wrong-identity rejected. |
| A2 | Pinned identity `ci.yml@refs/tags/v*`, privacy doesn't break signing (§1.7) | `release_catalog_sigstore.go:71-72` | **HOLDS.** SAN anchors repo+workflow-file+tag; Fulcio issues the same SAN from a private repo. |
| A3 | Artifact-owns-outcome stops strip-one-sig downgrade (§2.6) | `release_catalog_verify.go:221-311` (`schemeReject` never falls through) | **HOLDS.** |
| A4 | SSRF-guarded, bounded, conditional fetch (§4.2) | `release_catalog_http.go:114-158` (dial-time guard on resolved IP + redirects), `:428` bounded | **HOLDS** and is better than the plan implies (dial-time, closes DNS-rebind). |
| A5 | Sigstore-only in practice; ed25519 ring empty (§4.1 [ASSUMPTION]) | `bakedReleaseTrustKeysJSON=""` (`release_wiring.go:79`); `trusted_root.json` real | **HOLDS** — single effective scheme. This is a real fragility (see §4). |
| A6 | "90d expiry foot-gun; weekly re-sign slides the window" (§2.9/R4) | `ci.yml:441` `+90 days`; **no production refresher** | **BREAKS.** Re-sign never reaches running appliances (P0-3). Mitigation is illusory for the installed fleet. |
| A7 | Rings are just path prefixes, "no client change" (§2.1/§2.4) | `release_catalog_freshness.go:52-63` floor is one global int | **BREAKS.** Ring-switch = rollback wedge (P0-1). |
| A8 | Supersede-forward / omit-bad-release revocation (§2.7, §9.13) | `ci.yml:445-452` spec emits **one** entry; floor is global | **PARTIALLY BREAKS.** Generator supports multi-entry (`release_gen.go:56,90`), but no workflow assembles a multi-release "carry prior good forward" spec, and the version-authority to publish a *higher* version reliably does not exist (P0-2). |
| A9 | "release_gen.go — No change" (§8.1) | `release_gen.go` supports N entries + channels | **HOLDS for the generator**, but the *spec-assembly + versioning* control plane the plan needs is undescribed and non-trivial (§ below). |
| A10 | Download-back verify is the pre-customer safety gate (§5.2, §5.3) | Ordering in §8.5 snippet: upload → verify → purge | **WEAK.** Verify runs *before* purge and can validate a **stale cached old index** (false green); the post-purge confirm only `jq`-checks `catalog_version`, not the signature (P1). |
| A11 | Private-GHCR pull is "a new, small wiring" (§3.5, §4.3) | `templates_upgrade.go:289` anon pull; sudoers binds `docker pull <digest>` literal (`:253`) | **UNDERSTATED.** Needs a new sudoers verb, a credential store readable by the `culvert-maint` sudo user, plus distribution+rotation. Not "small." |
| A12 | Legacy `update.go` tag fallback 404s on private repo (B3) | `update.go:309-333` uses `http.DefaultClient`, no auth | **HOLDS.** Also the `updater` sidecar pulls `ghcr.io/kidcarmi/culvert-updater:latest` by tag anonymously (`docker-compose.yml:57`) — same breakage, not called out. |
| A13 | "3 human buttons"; everything else automated (§9.14) | — | **HOLDS only in steady state.** Setup, token rotation (90d), TUF root refresh, `ci.yml`-rename dance, and the P0 versioning fixes are all real manual/eng work. |
| A14 | Digest pin backstops a private-registry compromise (§4.3) | `validatePinnedDigestRef` (`templates_upgrade.go:271`) | **HOLDS.** Registry compromise = confidentiality/availability, not integrity. |
| A15 | Fail-closed = `available:false`, proxy keeps running (§7 R1) | `release_catalog_holder.go:77-88` | **HOLDS.** Catalog is not on the proxy hot path. |

---

## 2. Concrete attack paths

### AP-1 — R2 token / Cloudflare account compromise → catalog takeover
- **Capability:** attacker obtains the bucket-scoped S3 write creds or the CF account.
- **Steps:** overwrite `/stable/index.json` (+ sidecars) with an attacker-crafted index pointing at an attacker image digest.
- **What breaks / what holds:** **Integrity holds.** The appliance re-verifies the Sigstore bundle against the pinned `ci.yml@refs/tags/v*` identity before parse (`release_catalog_verify.go:259-268`). A forged or stripped signature rejects (`schemeReject`). The attacker cannot mint a bundle without also compromising GitHub Actions OIDC for that exact repo+workflow+tag.
- **Residual:** **Denial.** Serving garbage/expired ⇒ `available:false`. Acceptable, matches current Pages posture. Plan's controls (R10/R14) are adequate. **One gap:** the plan does not require **object-versioning or object-lock** on the *live* pointer objects (only "no delete on `history/`"), so an attacker can overwrite `stable/index.json` and there is no immutable record of what was served at time T for forensics. Recommend R2 bucket versioning on the whole bucket.

### AP-2 — Ring-switch rollback wedge (self-inflicted, no attacker needed) — **P0**
- **Capability:** none. An operator does exactly what the plan says: change `CULVERT_RELEASE_CATALOG_URL` from one ring to another.
- **Steps:** appliance on `beta` (floor persisted at, say, 57 in `release_catalog_state.json`) is repointed to `stable` (`catalog_version=42`). At next seed/refresh, `checkCatalogRollback` (`release_catalog_freshness.go:106-114`) computes `42 < 57` → `errCatalogRollback` → the catalog is refused → `available:false`.
- **What breaks:** the appliance is **bricked for updates** until an operator performs the (still-unimplemented — plan §2.7 item 3) break-glass floor reset. `dev` (plan's example `611`) → `stable` guarantees this.
- **Plan's control:** none. §2.7 asserts "rollback is a feature" but never reconciles the *global, unkeyed* floor with *independent per-ring version lines*.
- **Fix required:** either (a) key the floor by ring/origin (`release_catalog_state.json` becomes a map keyed by base URL), or (b) mandate a **single monotonic `catalog_version` line shared across all rings** (a release in `dev` and its later promotion to `stable` reuse/advance the same global counter), or (c) treat a ring change as an explicit break-glass floor reset with an operator flag. This is a design decision that must be made **before Phase 1**, because rings are introduced in Phase 1–2.

### AP-3 — Version-authority collision → real releases rejected (self-inflicted) — **P0**
- **Capability:** none. Normal operation of the plan's own new workflows.
- **Steps:** with 41 tags, a GA release publishes `catalog_version=42` (`ci.yml:442`), floor→42. Three weekly `catalog-resign` runs (no new tags) publish 43, 44, 45 (plan §2.9 "incremented `catalog_version`"), floor→45. A new tag is pushed → `git tag --list 'v*' | wc -l` = 42 → `catalog_version = 43`. The appliance computes `43 < 45` → **rollback refused**; the genuine new release never installs.
- **What breaks:** the update channel silently stops delivering *real* releases after the first few re-signs.
- **Plan's control:** none — the plan says "bump `catalog_version`" in three places (tag CI, resign, revoke) with no shared counter.
- **Fix required:** a **single monotonic version source** consulted by all four writers (tag build, resign, promote, revoke). Options: derive from a persisted counter object in R2 (read-modify-write under a lock/If-Match), or use a strictly increasing clock-derived integer (e.g. `unix_seconds`, which the tag build, resign, and revoke can all compute monotonically), or a Cloudflare KV counter. `(count of v* tags)+1` must be retired as the source of truth once re-sign exists.

### AP-4 — Expiry brick despite a healthy re-sign cron — **P0**
- **Capability:** none. Low release cadence (normal for a security appliance).
- **Steps:** appliance seeds catalog at T0 with `expires_at = T0+90d` (or +180d). It runs for months. The weekly cron dutifully re-signs `stable` at the origin. But the appliance **never re-fetches** (no production ticker; `Refresher` unwired). At `expires_at`, `GetCatalog` returns nil (`release_catalog_holder.go:79`) → `available:false`.
- **What breaks:** the entire installed fleet loses update visibility on the same day, with no attacker and no outage.
- **Plan's control:** the re-sign cron — which **only helps fresh installs, restarts, and manual admin refreshes**. §2.9/R4 present it as the fix; it is not, for running appliances.
- **Fix required:** **wire a bounded, jittered client-side refresh ticker** (the `Refresher` already exists — `release_catalog_refresher.go:79 SetSchedule`, `:156 RunTicker`) into `loadReleaseManagement`, default e.g. 6–24h with jitter, conditional-GET (ETag/304 already implemented, `release_catalog_http.go:277-310`) so it is cheap. Without this, do **not** rely on freshness expiry as a security control for a low-cadence product — raise `expires_at` far higher and treat expiry as a soft signal. (Note the tension: freshness *is* the anti-replay control; the right answer is client polling + a moderate window, not a very long window.)

### AP-5 — Stale-cache false-green in the download-back gate — P1
- **Capability:** none; a race with the edge cache.
- **Steps:** publish uploads new bytes, then (per §8.5) does the in-binary verify against `catalog.culvertlabs.com/stable/index.json` **before** purging. If the edge still has the previous release's `index.json` cached (same URL, 60s TTL), the verify fetches and validates the **old** index (which is validly signed → green). The job then purges and runs the final confirm — which only checks `catalog_version` via `jq`, not the signature.
- **What breaks:** the "critical safety gate" (§5.3) can pass without ever verifying the newly-uploaded bytes; a hosting-layer corruption of the new object is not caught by the gate that exists to catch it.
- **Fix required:** purge **before** the download-back verify (or fetch with a cache-buster / `Cache-Control: no-cache` request and assert the served `catalog_version` equals the expected new value *and* the signature verifies, as one step). The confirm-by-`jq` must be replaced by a confirm-by-in-binary-verify.

### AP-6 — DNS / domain takeover of `catalog.culvertlabs.com` — Low impact, covered
- **Capability:** hijack DNS or the CF zone.
- **Outcome:** DoS + privacy leak (which versions a customer polls). **Integrity holds** (in-binary verify). Plan R14 is adequate. **Add:** CAA records on `culvertlabs.com` to constrain cert issuance; document that the appliance has **no secondary origin** (single `CULVERT_RELEASE_CATALOG_URL`) so takeover = full-channel DoS with manual recovery only (see DR §3).

### AP-7 — CI / OIDC identity compromise — the genuine worst case
- **Capability:** push a `v*` tag from a controlled workflow, or subvert the signing job.
- **Outcome:** attacker can mint a catalog-valid signature. This is the **only** path to an integrity bypass, and it is **unchanged by the migration** (plan §4.7 is honest about this).
- **Controls verified:** signing is tag-path-only (`ci.yml:472-473 if: startsWith(github.ref,'refs/tags/v')`), keyless, Rekor-logged. **Gaps the plan under-specifies:** (1) it *asserts* a "`v*` tag ruleset (protected tags)" but I could not confirm one exists — this must be verified and made a hard prerequisite, since the pinned identity accepts **any** `refs/tags/v*` run of `ci.yml`; (2) no Rekor monitoring is actually implemented (plan lists it as a mitigation but it is aspirational). **Recommend:** implement the Rekor-identity monitor as a Phase-2 deliverable, not Phase-6 "harden."

### AP-8 — `.well-known/culvert-catalog.json` as an alert-suppression oracle — Low
- The discovery file is unsigned and R2-writable. If the Phase-6 verify canary or PM dashboard reads *it* to detect "version regression," an R2-write attacker forges it (e.g. reports the expected version) to mask a takeover. **Fix:** the canary must derive truth from the **signed** `index.json` it verifies in-binary, never from `.well-known`. Keep `.well-known` strictly advisory. Better: consider dropping it — it adds attack surface for a convenience the signed index already provides.

### AP-9 — Private-GHCR credential on the appliance — moderate, understated
- Distributing a `read:packages` PAT/app-token to every appliance, storing it in a 0600 file readable by the `culvert-maint` sudo boundary, and adding a `docker login` sudoers verb (`packaging/sudoers/culvert-maint`) is real attack surface and real rotation burden. `docker login` writes creds to a docker config that the sudo user must own; a compromised `culvert-maint` user can now exfiltrate a pull token. **The digest pin means this buys nothing for integrity** (AP verified via `validatePinnedDigestRef`). **Recommendation stands with the plan's own §10.1: keep images public.** Hiding image bytes for a product whose source is going private but whose *binaries are already public GitHub Release assets and cosign-transparency-logged* is security theater that adds a credential-distribution subsystem for no integrity gain.

---

## 3. Weaknesses by category

### 3.1 Reliability
- **No client-side refresh (P0-3)** is the dominant reliability defect — the fleet's freshness depends on restarts.
- **Single origin, single URL.** The appliance holds one `CULVERT_RELEASE_CATALOG_URL` (`release_wiring.go:61`). There is no secondary/failover origin list. Post-Phase-5 (Pages deleted), a Cloudflare/R2 incident or a bad DNS change is a **total channel outage** with only manual recovery. For an enterprise security product this is thin.
- **Fail-closed is correct** and the proxy keeps serving — good. The blast radius of any catalog failure is "no updates," not "no proxy."

### 3.2 Operability
- **The "3 buttons" hide a versioning service that doesn't exist.** Promote/revoke/resign each need to (a) read the current signed index from `history/`, (b) carry prior-good releases forward into a multi-entry spec, (c) allocate the next global `catalog_version`, (d) re-sign, upload, purge, verify-back. That is a stateful release-control-plane, not three `workflow_dispatch` YAMLs. The plan should name and design it.
- **Weekly re-sign cron is a SPOF with weak monitoring** ("alert with lead time"). Combined with no client polling, a silently-failing cron *plus* the expiry model means the failure is invisible until the fleet bricks. Monitor the cron's *success*, and alert on `min(days-to-expiry across live catalog copies)`.
- **Cache purge failure** is correctly bounded (≤60s TTL) — fine.
- **Runbook completeness:** revocation and key/identity rotation are described but the **break-glass floor reset** (needed for AP-2 and for genuine downgrades) is still ☐ (plan §2.7 item 3). It is a prerequisite for the ring model, not a nice-to-have.

### 3.3 Maintainability / supply-chain
- **Single trust scheme (Sigstore-only).** Verified: `bakedReleaseTrustKeysJSON=""`. A Sigstore-ecosystem incident (Fulcio/Rekor/TUF) disables *new* seeds/verifies (cached catalogs still verify offline via integrated timestamp). The plan's optional ed25519 org root (§4.1) should be **promoted from optional to required** for a security product — it is the only independently-rotatable second scheme, and `NewTrustStoreWithSigstore` already supports it.
- **Baked `trusted_root.json` will age.** It is a static embed (`release_catalog_sigstore.go:52`) fetched 2026-06-26. When Sigstore rotates Fulcio/Rekor keys, a long-lived appliance with an old baked root may fail to verify **newly-signed** catalogs until the binary itself is updated — a chicken-and-egg with the update channel. This is pre-existing but **amplified** by a low-cadence security product on R2. Document the coupling and the TUF-refresh cadence as an operational commitment, and consider supporting an operator-refreshable root path (already exists: `CULVERT_RELEASE_SIGSTORE_TRUSTED_ROOT`) with a signed root-update flow.
- **`ci.yml` rename fragility** is real and correctly flagged (R13); the SSOT test (`release_identity.env` ↔ constants) is a good control.

### 3.4 Scalability
- **Poll amplification is currently a non-issue** *because there is no polling* — but that is the P0-3 bug, not a design win. Once polling is added (it must be), size it: `fleet × 1/interval` conditional GETs. With 304s (already implemented) and a 60s-TTL edge cache in front of R2, even a large fleet collapses to a trivial origin load — **this is exactly what R2+edge is good at**, and is a point in the migration's favor. Recommend interval ≥ 6h + jitter to avoid thundering herds after a global restart.
- **Catalog growth:** if the plan moves to multi-release indices (needed for revocation), `index.json` grows with retained releases; keep it bounded (e.g. last N + LTS) and rely on `history/` for the long tail. `manifests/` are immutable/1y-cached — fine.
- **R2 egress cost:** R2 has zero egress fees; with Smart Tiered Cache the origin barely sees traffic. Cost is a non-concern; this is a genuine improvement over Pages' opacity.

### 3.5 Unnecessary complexity (called out)
- **`history/**` mirror on every publish** is reasonable for audit, but the plan also proposes physically deleting yanked manifests from the live ring (§9.13 step 4) "defense in depth" — this is pointless: the index no longer references them and they are content-addressed/immutably cached, so deletion only risks breaking an in-flight client mid-fetch. Drop it.
- **`.well-known/culvert-catalog.json`** adds an unsigned surface for information the signed index already carries (AP-8). Cut it unless a concrete consumer needs it, and if kept, never let a trust/alert decision depend on it.
- **`dev` ring auto-publishing on every `main` push** to `catalog_version` (plan §2.4, example `dev:611`) is the single biggest driver of the AP-2/AP-3 version-inflation wedge. If rings keep independent version lines, `dev` should not share a monotonic authority with `stable`; if they share one authority, `dev`'s churn will race the floor. Either way, `dev` per-push publishing needs a version model that cannot poison `stable`.

---

## 4. Is it production-ready for an enterprise security product?

**Not as written.** The *hosting* move is production-ready and low-risk. The *release-operations* layer the plan bundles in (rings, weekly re-sign, promote, revoke) is **not** — it rests on a global rollback floor and a tag-count version source that break under exactly the workflows the plan adds, and it assumes a client refresh loop that does not exist. These are designable in days, but they are correctness blockers, not polish.

An enterprise security update channel must guarantee: (a) a healthy appliance never bricks itself through normal operation (AP-2/3/4 violate this), and (b) a bad release can be pulled fleet-wide with bounded latency (revocation depends on the version authority and on client polling, both missing). Fix those and this is a strong, well-reasoned architecture.

---

## 5. Scorecard

| Dimension | Score | One-line justification |
|---|---|---|
| **Security** | **8/10** | In-binary keyless verify is the hard wall and it holds against R2/CF/DNS compromise; deductions for single trust scheme (Sigstore-only) and unproven `v*` tag ruleset / Rekor monitoring. |
| **Reliability** | **4/10** | No client refresh loop, single origin/URL, and self-wedging version/floor interactions make the *installed fleet* fragile despite correct fail-closed behavior. |
| **Operability** | **5/10** | "3 buttons" is aspirational; the versioning/spec-assembly control plane and break-glass floor reset are undesigned; re-sign SPOF with weak monitoring. |
| **Maintainability** | **6/10** | Clean reuse of generator/verifier; but single scheme, aging baked root, and `ci.yml`-rename coupling are standing liabilities. |
| **Scalability** | **8/10** | R2 + edge cache + 304s is the right substrate and scales cheaply; only caveat is thundering-herd once polling is added (solvable with jitter). |
| **Disaster Recovery** | **4/10** | Post-Phase-5 single origin with manual "re-enable Pages / serve history from an alternate origin" recovery and no appliance-side failover URL. |
| **Release Engineering maturity** | **6/10** | Strong provenance/signing/gates already; but the monotonic-version authority, promote/revoke assembly, and rollout telemetry are sketches, not mechanisms. |

**Overall: SHIP-WITH-CHANGES.** The migration is sound; the release-ops scaffolding it carries must be corrected first.

---

## 6. Required changes before implementation

### P0 — Blockers (design + resolve before Phase 1)

- **P0-1 — Reconcile the rollback floor with rings.** (AP-2) Choose one: key `release_catalog_state.json` by ring/origin, OR mandate a single global monotonic `catalog_version` line across all rings, OR make ring-change an explicit break-glass floor reset. Implement the still-☐ break-glass floor reset (plan §2.7 item 3) *as part of this*, since the ring model cannot ship without it. — ties to `release_catalog_freshness.go:52-114`.
- **P0-2 — Establish a single monotonic `catalog_version` authority** consulted by tag-build, `catalog-resign`, `catalog-promote`, and `catalog-revoke`. Retire `(count of v* tags)+1` (`ci.yml:442`) as the source of truth. Without this, re-sign and revocation regress the version and reject real releases. (AP-3)
- **P0-3 — Wire a production client-side refresh ticker** (bounded interval + jitter + conditional GET) into `loadReleaseManagement` (`release_wiring.go`), reusing the existing `Refresher.SetSchedule`/`RunTicker` (`release_catalog_refresher.go:79,156`). Until this exists, the freshness/expiry model and the weekly re-sign do not protect or reach the installed fleet. (AP-4)

### P1 — Required for a credible enterprise channel

- **P1-1 — Fix the download-back gate ordering** (AP-5): purge before verify (or cache-bust), and confirm by **in-binary signature verification of the served bytes**, not a `jq` version check. — `ci.yml` new `publish-catalog-r2` job, §8.5.
- **P1-2 — Design the release-ops control plane** the "3 buttons" imply: multi-entry spec assembly (carry prior-good forward), history read-back, version allocation, re-sign/upload/verify/purge. Name it, don't bury it in three `workflow_dispatch` YAMLs. (Operability)
- **P1-3 — Add a second, independently-rotatable trust scheme** (bake an ed25519 org root; promote plan §4.1 from optional to required) and land the Phase-4 key-rotation fixtures. Mitigates a Sigstore-ecosystem incident. — `release_wiring.go:79`, `NewTrustStoreWithSigstore`.
- **P1-4 — Provide origin resilience / DR:** either keep a warm secondary origin (e.g. retain a Pages or second-bucket publish behind a second hostname) or support an appliance-side ordered list of catalog origins with failover. Do not delete Pages (Phase 5) until a tested secondary exists. Document a concrete R2-down runbook with an RTO. (DR)
- **P1-5 — Confirm and require the `v*` tag protection ruleset** (who/what can push `v*`, gate-required) and **implement Rekor-identity monitoring** in Phase 2, since the pinned identity trusts any `refs/tags/v*` run of `ci.yml`. (AP-7)
- **P1-6 — Keep container images public** (plan §10.1 recommendation) unless a written business requirement forces otherwise; the digest pin already prevents tampering (AP-9), and going private adds a credential-distribution + sudoers + rotation subsystem for zero integrity gain. If forced private, treat §4.3 as a full slice, not "small wiring," and include the `updater` sidecar's own `-updater:latest` anonymous pull (`docker-compose.yml:57`).
- **P1-7 — Retire the legacy `update.go` GitHub-tags fallback** (`update.go:309`) rather than authenticate it (plan §10.2), before repo privacy. It silently reports "no update" on a private repo (B3).

### P2 — Nice-to-have / de-risking

- **P2-1 — Enable R2 bucket object versioning** on live pointer objects for forensics (AP-1 residual), not only `history/`.
- **P2-2 — Add CAA records** on `culvertlabs.com` and min-TLS 1.2 (plan already assumes TLS) to constrain cert issuance during a DNS-takeover attempt (AP-6).
- **P2-3 — Drop `.well-known/culvert-catalog.json`** (AP-8) or explicitly forbid any trust/alert decision from depending on it.
- **P2-4 — Drop the "physically delete yanked manifest from the live ring" step** (plan §9.13.4) — pointless and mildly risky to in-flight clients.
- **P2-5 — Size and jitter the refresh interval** (once P0-3 lands) to avoid a post-restart thundering herd; document the fleet-scale origin QPS with 304s.
- **P2-6 — Document the baked `trusted_root.json` aging coupling** (§3.3) and the TUF-refresh cadence as an operational commitment; expose a signed root-refresh path.

---

## 7. Points where the plan is right and should be preserved

- The untrusted-transport framing and "R2 is never a trust root" (§4.6) are correct and are the reason this migration is safe.
- Additive-first, dual-publish, canary-before-cutover, Pages-retained-until-Phase-5 sequencing (§3.1) is the right migration shape — *except* Pages should not be deleted until a tested secondary origin exists (P1-4).
- `release`-environment gating, tag-path-only secrets, bucket-scoped creds, no-delete-on-history, `--password-stdin`, harden-runner egress block (§4.5) are all correct least-privilege controls.
- Keeping images public and retiring the legacy tag path (§10) are the right calls — elevate them from "recommendations" to decisions.

---

*Bottom line: approve the hosting migration; block on P0-1/2/3 (global floor vs rings, version authority, client refresh loop), which are latent defects the new workflows would activate. None are R2's fault; all must be fixed before the re-sign/promote/revoke/ring machinery ships.*
