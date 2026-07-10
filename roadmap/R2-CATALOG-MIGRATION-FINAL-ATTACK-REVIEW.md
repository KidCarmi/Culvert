# R2 Catalog Migration — Final Independent Pre-Implementation Attack Review

**Reviewer role:** Principal Product Security Architect (independent, no prior ownership).
**Target:** `roadmap/R2-CATALOG-MIGRATION-PLAN.md` (GitHub Pages → Cloudflare R2, repo→private, STABLE-ONLY ring + PUBLIC GHCR images).
**Method:** implementation-first. Every verdict is tied to `file:line` or a named workflow step. The plan's prose was treated as an unproven claim set until checked against code/tests/CI.

---

## 1. Executive verdict

**CONDITIONALLY APPROVED — for the STABLE-ONLY + PUBLIC-IMAGES scope only, and NOT to start Phase 1 until the release-blocking findings below are resolved on paper.**

The core thesis is **correct and proven by code**: the catalog transport is already untrusted; integrity is an in-binary keyless Sigstore verification over raw `index.json` bytes (`release_catalog_verify.go`, `release_catalog_sigstore.go`), plus per-manifest SHA-256 binding (`release_catalog.go:311-315`), freshness (`release_catalog_freshness.go`), a monotonic rollback floor, and digest-pinned image pulls (`validatePinnedDigestRef`). Moving hosting to R2 is genuinely a hosting/availability change, not a trust change. The plan has already absorbed three review rounds (§11–§13) and correctly self-identified its biggest defects (global-version-space bricking, unwired client refresh, single trust scheme).

**However**, the plan's own recommended lowest-risk path — **Amendment 4 "stable-only, defer the CAS counter"** — rests on a **factually incorrect premise about CI serialization** that reintroduces the exact fleet-poisoning defect (P0-2) the CAS counter was meant to prevent, *as soon as the mandatory weekly re-sign cron ships*. That is the headline new finding of this review and it is release-blocking. Several load-bearing artifacts the plan cites as if they exist (`TestReleaseCatalogServedVerify`, the production HTTP refresher, the `v*` tag ruleset check) **do not exist in the repository** and are new work, not config flips.

STABLE-ONLY + PUBLIC-IMAGES remain the **correct initial choices**. The scope reduction is right; the plan just under-specifies the parts that stable-only still needs.

---

## 2. Release-blocking findings

### RB-1 — Stable-only + the mandatory re-sign cron is a *two-writer* system with NO serialization; Amendment 4's "no CAS needed" premise is false

**Evidence.**
- Today's version rule is `catalog_version = (count of v* tags) + 1` (`ci.yml:443`). It is collision-free *only* because tag builds are the sole writer and each tag build has a distinct tag count.
- Amendment 4 (plan §13) keeps stable-only "single-writer" and claims: *"the resign/revoke writers are the same CI, serialized by the existing release concurrency."* This is **incorrect**. CI concurrency is `group: ci-${{ github.ref }}` (`ci.yml:19-24`). A weekly `catalog-resign.yml` fires on `schedule` (ref = default branch); a tag build runs on the tag ref; `catalog-e2e.yml` already demonstrates the per-ref pattern (`catalog-e2e.yml:48-49`). **Different refs ⇒ different concurrency groups ⇒ NO mutual serialization.** The plan never specifies a shared concurrency group across these workflows.
- The re-sign cron is **mandatory**, not optional: it is the headline fix for the 90-day expiry foot-gun (R4), promoted to Phase 2 (§3.4, §5.1). So stable-only inherently has ≥2 concurrent writers.
- Amendment 4's `next = max(tag_count, last_published)+1` requires reading `last_published` from the live R2 index — a network **read-modify-write with no atomic primitive**. Two concurrent writers both read `last_published=N`, both compute `N+1`, both publish a *different* document at version `N+1`. Appliances accept either (rollback gate accepts `version == floor`; only `< floor` is refused — `release_catalog_freshness.go:106-114`), so the fleet non-deterministically runs one of two distinct "version N+1" catalogs. **This is P0-2 resurfacing in the "safe" stable-only path.**

**Why it matters:** the plan explicitly says the wired unattended refresh (RB-3) "auto-poisons floors fleet-wide" if a version is wrong (§12 "Refresher reality"), yet Amendment 4 waives the counter correctness gate for stable-only on a false serialization premise.

**Required remediation (smallest safe form):**
- **Preferred and simplest:** the weekly re-sign **must NOT bump `catalog_version`.** Freshness only needs a new `generated_at`/`expires_at`; appliances accept an equal version (`version == floor`) and slide freshness with zero counter contention. Re-signing at the *same* version removes the second writer entirely. (It must write its refreshed bundle to a resign-keyed path, **not** overwrite the release's immutable `history/v<N>/`.) This makes stable-only genuinely single-allocator (only tag builds allocate versions) and Amendment 4's premise becomes *true*.
- If the team insists the re-sign bump the version, then a shared cross-workflow serialization (single named `concurrency` group spanning `ci.yml` tag path + `catalog-resign.yml` + `catalog-revoke.yml`) OR the GATE-C CAS counter is **required even for stable-only** — Amendment 4 cannot be taken as written.

### RB-2 — The "idempotent re-run re-uploads identical bytes" claim is false; the spec embeds wall-clock time

**Evidence.** The catalog spec is built with `NOW=$(date -u ...)` and `EXP=$(date -u -d '+90 days')` (`ci.yml:440-441`), and `created_at`, `generated_at`, `expires_at` all consume `$NOW`/`$EXP` (`ci.yml:447-450`). Re-running the *same tag* on a different day produces a different `index.json` and different `manifests/*` bytes (hence a different `manifest_sha256`). `TestGenerateReleaseCatalog_Deterministic` proves determinism only for a **fixed spec input** — it does **not** cover cross-run CI re-execution.

**Consequence for the stage→verify→promote model (§5.2/§8.5):**
- `history/v<N>/` written create-only (`If-None-Match`) + a partial first attempt (index written, `.sigstore` not) permanently wedges version `N`: a re-run generates a *different* index (new dates), create-only blocks the overwrite, but the re-run's fresh `.sigstore` is over the *new* index → download-back verify pairs old-index+new-sig → **hard reject, forever, at that version.**
- Even without a partial write, the `.sigstore` bundle is inherently non-deterministic (per-run Fulcio cert + Rekor timestamp), so "re-running re-uploads identical bytes → no-op" (§5.2) is wrong for the signature sidecar.

**Required remediation:** the spec's `generated_at`/`expires_at`/`created_at` for a given tag must be **derived deterministically from the tag** (e.g. the tag's commit/creation timestamp), not `date -u` at job runtime. Define re-run semantics explicitly: either "a version number is single-use; a failed publish burns it and the retry allocates a new one" (cleanest with RB-1's no-bump resign) or make the whole bundle byte-reproducible from the tag. Do not ship the `history/` create-only model on top of a wall-clock spec.

### RB-3 — There is NO production client-side catalog refresh; the entire re-sign/revoke/rollout propagation story is inert until new code ships

**Evidence.** Production wiring builds a **bare `NewCatalogHolder`** (`release_wiring.go:223-229`) with startup auto-seed (`runStartupAutoSeed`) and an **admin-only** `rm.refresh` closure (`release_wiring.go:287-296`). The `Refresher`/`RunTicker` (`release_catalog_refresher.go`) is used **only in tests** (grep: `NewRefresher`/`RunTicker` appear only in `release_catalog_refresher_test.go` and the file itself). At `expires_at` a long-running appliance flips to `available:false` on the read path (`release_catalog_holder.go:77-83`, `release_catalog_freshness.go:93-102`) and stays there until restart or an admin API call.

**Consequence:** "weekly re-sign slides the freshness window" (§2.9, R4) and "PM presses three buttons and the fleet converges" (§9) are **inert** for running appliances. The plan is honest about this (P0-3, §12 "Refresher reality"), but it is release-blocking for the STABLE-ONLY cutover because the cutover's safety argument (Pages retained, R2 canary, fail-closed) assumes the fleet actually re-pulls. **The `Refresher` drives a local directory, not `HTTPCatalogProvider`** — so this is new HTTP integration (jittered ticker + single-flight + ETag against the remote origin, auto-raising the floor), not "turn on the existing loop." It must ship, with its own failure-mode tests, before Phase 2 as §12 states.

### RB-4 — `TestReleaseCatalogServedVerify` (the CI safety gate the whole stage→verify→promote model depends on) does not exist

**Evidence.** grep for `TestReleaseCatalogServedVerify` across `*_test.go` → **no matches.** It is referenced as load-bearing in §5.2 step 3, §8.5, and §8.7. The nearest existing test, `TestReleaseCatalogKeylessVerify`, consumes a **local dir** (`CULVERT_RELEASE_GEN_OUT`), not an HTTP origin. A test that fetches from `catalog.culvertlabs.com/history/<ring>/v<N>/` and verifies with the real in-binary path is entirely new. Note also the SSRF asymmetry: production `HTTPCatalogProvider` wires `guard: isPrivateHost` (`release_catalog_http.go:89`), which would reject a localhost/S3-mock origin — a CI harness against a local mock must set `guard=nil`, diverging from the production code path it claims to exercise.

**Required remediation:** write `TestReleaseCatalogServedVerify` (and the local-mock e2e) before Phase 1 exit; the download-back gate is the single safety interlock protecting the live pointer and cannot be a named placeholder. Make the post-promote confirm a **full re-verify**, not the `jq .catalog_version` check shown in `ci.yml` §8.5 (the plan itself notes this in §11 P1).

### RB-5 — The "compromised workflow can't mint a rogue signed catalog" defense rests on a repo setting that no code verifies

**Evidence.** `require-gate.sh` explicitly documents its own limit (`require-gate.sh:30-35`): on the tag path it is **checked out from the tagged tree**, so an attacker who can push an arbitrary `v*` tag strips the guard; *"The only control against an attacker-controlled tagged tree is the repo ruleset restricting v* creation."* The pinned identity trusts **any** `refs/tags/v*` run of `ci.yml` (`release_catalog_sigstore.go:72`, `release_identity.env:14`). There is **no** automated check in the repo that the `v*` protected-tag ruleset exists or matches policy. GATE-A A-1 correctly demands one — but it is unbuilt.

**Verdict on the claim "a compromised release workflow cannot bypass approval + tag protections": UNPROVEN.** The integrity of the entire channel reduces to an assumed, unverified GitHub ruleset. **Required:** GATE-A A-1's automated ruleset attestation must be green before any customer-facing cutover; treat it as blocking for cutover (not merely Phase 6).

---

## 3. High / Medium / Low findings

**HIGH**

- **H-1 (repo-privacy breaks the designated secondary origin).** The plan requires a "genuinely independent secondary origin" and names *"the retained GitHub Pages origin"* as a candidate (§12), while B1 simultaneously states private-repo Pages is unreliable/auth-gated for anonymous appliance fetch. Phase 4 (repo private) can therefore **disable the very secondary origin** the DR posture depends on, *before* Phase 5 stands up an R2-based alternative. The Pages-as-secondary story collapses once private. Resolve the ordering: stand up an independently-credentialed non-Pages secondary **before** flipping private, or keep the repo public until the alternate origin is proven.
- **H-2 (B4 confirmed — anonymous GHCR pulls).** `ComposePullDigest` runs a bare `docker pull` (`templates_upgrade.go:285-289`); `scripts/install.sh:527` and `packaging/culvert-maint/install.sh:442` seed `${PROXY_REPO}:latest` with no `docker login`. If images go private, every appliance breaks. The plan's recommendation to **keep images public** is correct and eliminates this entirely; ratify decision §10#1 = public. If images ever go private, the digest pin still backstops integrity (Docker verifies the manifest digest on pull), so the exposure is confidentiality/availability only — but the credential-distribution subsystem (§4.3) is real new attack surface for zero integrity gain.

**MEDIUM**

- **M-1 (B3 confirmed — legacy tag check 404s silently).** `checkGitHubLatestTag` hits `https://api.github.com/repos/…/tags` with **no `Authorization` header** (`update.go:309-322`, only `Accept`+`User-Agent`). Private repo ⇒ 404 ⇒ returns `""` ⇒ silent "no update." Retire it (decision §10#2 = retire is correct). Also confirm the **legacy `updater` sidecar** (pulls `-updater:latest` by tag, anonymously — `ci.yml:308-310`) isn't the silent update mechanism on any live appliance before going private (§12 correctly flags this).
- **M-2 (future-dating rejection is stricter than the documented skew).** `checkCatalogFreshness` rejects any catalog whose `generated_at` is more than 5 min in the future (`release_catalog_freshness.go:80-83`). Every fresh publish (and especially the weekly re-sign) stamps `generated_at = now`. Any appliance whose clock **lags the signer by >5 min** will reject a legitimately-fresh catalog as future-dated. R8 frames skew as benign ("NTP assumed"); this specific rejection is a real per-publish false-positive vector for a fleet with imperfect NTP. Document the hard NTP requirement and consider widening skew for the future-dating check specifically.
- **M-3 (revocation can be blocked by the very counter that protects integrity).** Correctly caught by Amendment 1 (C-6 dual-control break-glass). In stable-only, the analog is: a wedged version-N history entry (RB-2) or an unreachable `last_published` read blocks an emergency revoke exactly when you need it. The RB-1 "resign reuses version" simplification does **not** apply to revoke (revoke *must* supersede-forward at a higher version). Ensure the break-glass audited allocation (C-6) is available even in stable-only.
- **M-4 (cache/signature non-atomicity residual).** Artifact-owns-outcome (`release_catalog_verify.go:259-284`) means a new index paired with an old `.sigstore` at the edge is a **hard reject**, not a downgrade — safe, but it is a transient `available:false` that self-heals only on the next refresh (which, per RB-3, does not exist yet in production). Until RB-3 ships, a purge-ordering glitch strands an appliance until restart/admin-refresh. Purge index+sidecars as a set, and land RB-3 first.

**LOW**

- **L-1 (public image = product-source exposure).** The Dockerfile bakes only public material (GeoIP CC-BY DB, YARA starter rules, public trust roots) — **no secret** (`Dockerfile:1-108`). But the entire product compiles into the binary (`package main`, flat), so "public image" = shipping the closed-source product to anyone. That is a **product/IP decision**, not a security one; the plan slightly conflates "digest pin prevents tampering" (true) with "no reason to hide the bytes" (a business call). Flag it to stakeholders explicitly; the security conclusion (no secret leak) is sound.
- **L-2 (`.well-known/culvert-catalog.json` is unsigned and unconsumed).** It is discovery metadata, correctly *not* a trust root, but nothing in the client reads it and nothing signs it. Ensure no future client logic ever trusts it for version/floor decisions (that would be an unsigned rollback-metadata channel).
- **L-3 (`min_upgrade_from` parsed but not enforced).** `release_catalog.go:355` parses it; enforcement is "a later slice." A revoke/graduation that assumes upgrade-path gating exists would be wrong. Not a migration blocker; note it.

---

## 4. Unproven load-bearing assumptions

| # | Assumption (plan) | Verdict | Evidence |
|---|---|---|---|
| A1 | Official builds are Sigstore-only (empty baked ed25519 ring) ⇒ single scheme in practice | **Plausible but unproven** (build-time ldflag; not visible in tree). If true, GATE-B durability is load-bearing. | `release_wiring.go:79` (empty `bakedReleaseTrustKeysJSON`) |
| A2 | The `v*` tag ruleset exists and enforces gate + restricts actors | **Unproven / assumed** — no code verifies it | `require-gate.sh:30-35`; GATE-A A-1 unbuilt |
| A3 | Re-sign/revoke writers are "serialized by existing concurrency" | **Incorrect** | `ci.yml:19-24` per-ref groups |
| A4 | Idempotent re-run re-uploads identical bytes | **Incorrect** | `ci.yml:440-450` wall-clock spec |
| A5 | Production periodically re-pulls the catalog | **Incorrect (today)** — bare holder, admin-only refresh | `release_wiring.go:223-229` |
| A6 | R2 supports `If-Match`/`If-None-Match` conditional PUT (C-1/C-2) | **Unproven** — plan itself marks `[ASSUMPTION]`, says verify in Phase 1 | plan §12 C-1 |
| A7 | `culvertlabs.com` is a CF zone in the same account as the bucket | **Operational assumption** | plan §2.2 `[ASSUMPTION]` |
| A8 | Protected GitHub Environments available (plan tier) | **Operational assumption** | plan §3.3 |
| A9 | R2 takeover is availability-only, never integrity | **Proven with one caveat** — a compromised R2 can *freeze* a fleet within the freshness window (serve an in-window valid older catalog), bounded by `expires_at` | `release_catalog_verify.go`, `release_catalog_freshness.go` |

---

## 5. Attack simulation matrix

| Scenario | Expected secure behavior | Current evidence | Missing test | Required remediation |
|---|---|---|---|---|
| **Swap index, keep old sig** | Reject (sig over raw bytes fails) | `ed25519.Verify(pub, idxBytes, sig)` / Sigstore `WithArtifact` (`release_catalog_verify.go:338`, `release_catalog_sigstore.go:162-166`) | — (covered) | none |
| **Swap sig, keep old index** | Reject; artifact-owns-outcome, no fallback | `verifyIndexSignature` schemeReject (`:259-284`) | — | none |
| **Expired-but-validly-signed** | Reject at load + hidden at use-time | `checkCatalogFreshness` / `isExpiredNow` (`freshness:69-102`) | — | none |
| **Replay older valid catalog** | Reject if `< floor`; accept if fresh appliance (then floor advances) | `checkCatalogRollback` (`:106-114`) | — | none; document freeze-within-window bound |
| **Valid catalog → nonexistent image digest** | Pull fails; agent hard-verifies RepoDigest; proxy keeps running | `validatePinnedDigestRef`, agent verify (`templates_upgrade.go`) | e2e for dangling digest | add e2e |
| **Modify a manifest post-publication** | Reject (per-manifest sha256) | `release_catalog.go:311-315` | — | none |
| **Delete a referenced manifest** | Load fails closed (dangling required ref) | `catalogLoadRelease` read error (`:307-309`) | served-origin variant | RB-4 test |
| **Edge bytes ≠ origin bytes** | Sig mismatch ⇒ reject; self-heal on next refresh | artifact-owns-outcome | cache-atomicity e2e (named, unwritten) | write it + land RB-3 |
| **Two workflows, same version** | Distinct versions, no `history` overwrite | **FAILS** — no cross-workflow serialization | concurrency test (unwritten) | **RB-1** |
| **Two versions concurrently** | Monotonic, distinct | Only safe if single allocator | — | RB-1 |
| **Re-run a partial release** | Clean retry, no wedge | **FAILS** — wall-clock spec + create-only wedges version | — | **RB-2** |
| **Fail after stage, before promote** | Live pointer untouched (correct) | promote is last write (§5.2) | RB-4 harness | write test |
| **Fail after promote, before purge** | Origin serves new verified bytes; edge stale ≤TTL | correctness-safe (both signed+fresh) | — | retry purge; alert |
| **Publish without protected env** | Blocked (env gate) | plan §3.3 (assumed) | — | verify env exists (A8) |
| **Sign from a non-tag workflow** | Fulcio SAN ≠ pinned ⇒ reject | pinned `ci.yml@refs/tags/v*` (`sigstore.go:72`) | — (sigstore_test cases) | none |
| **Create/move a protected v\* tag** | Blocked by ruleset | **UNPROVEN** (no code) | ruleset attestation | **RB-5 / GATE-A A-1** |
| **Restart with expired local catalog** | `available:false`, proxy runs | `isExpiredNow` (`holder:77-83`) | — | none |
| **Start with no network** | Auto-seed fails closed; last cache/local used; proxy runs | `autoSeedCatalog` fail-closed (`release_autoseed.go:49-92`) | — | none |
| **10-min / 1-day clock skew** | ≤5min tolerated; beyond ⇒ reject fresh publish (future-dating) | `freshness:73-83` | skew matrix test | **M-2**; document NTP |
| **HTTP 200 malformed JSON** | Reject bounded | `readAllBounded` + parse (`http.go:428`) | — | none |
| **Redirect to loopback/link-local** | SSRF guard at dial + redirect | `safeDialContext`/`checkRedirect` (`http.go:114-158`) | — | none |
| **Oversized catalog/manifest** | Reject at 1 MiB | `catalogMaxReadBytes` (`release_catalog.go:47`) | — | none |
| **Interrupted image pull** | Rollback-on-failure; hard-verify | agent apply stages | e2e | add |
| **Correct digest, wrong CPU arch** | Manifest-list digest covers both arches; pull resolves per-arch | `platforms:[amd64,arm64]` (`ci.yml:450`) | arch-mismatch e2e | add |
| **Thousands polling after a release** | Edge absorbs (short-TTL index, immutable manifests) + jitter | Cache Rule + jittered refresh (RB-3, unwired) | load test | land RB-3 with jitter |
| **Revoke latest** | Supersede-forward at higher version + purge | §9.13 (tooling unwritten) | revoke e2e | build revoke + C-6 |
| **Re-promote prior good at higher version** | Accepted (version up) | rollback gate | graduation e2e | RB-1-clean |
| **Rotate CF creds / signing identity** | No appliance impact / overlap-window dance | key model §4.4/§4.8 | — | runbook |
| **Sigstore root unavailable/stale offline** | Verify still offline (integrated Rekor ts); but aging root ⇒ new catalogs fail | `WithIntegratedTimestamps` (`sigstore.go:126-129`) | build-time root-expiry check (unbuilt) | **GATE-B B-2** |
| **GitHub down, R2 up** | Appliance updates fine (catalog+images independent of github.com once private-pull solved) | R2 origin + GHCR | — | keep images public (H-2) |
| **R2 down, appliance holds valid catalog** | Keeps serving until `expires_at`; proxy runs | holder retains last-good | — | none |

---

## 6. PM release-flow assessment (runbooks + misuse callouts)

The plan's target — **PM surface = {Promote, Advance/Move-recommended, Revoke}, never hand-edit JSON/digests/signatures/R2 objects** — is the right north star and is mostly achievable. Assessment per scenario (stable-only reality):

- **Normal patch (GA tag `vX.Y.Z`).** Initiator: merge→auto-tag (automated). PM approves the protected `release` environment. Automated: build, sign, gen+gate, R2 publish (stage→verify→promote→purge), download-back verify. Evidence before approval: green gates + canary dispatch. Can still fail after approval: purge lag (≤TTL), RB-1 collision if resign fires concurrently. Health: `/api/releases` `available:true` + correct `catalog_version`/`expires_at`. Reversed by: forward-supersede revoke. **Clean once RB-1/RB-2/RB-4 fixed.**
- **Minor feature.** Same as patch; no extra surface.
- **Security hotfix.** Branch from tag, `vX.Y.(Z+1)`, `severity: critical`, `critical` channel points at it. Note (correct, §9.12): severity is prominence, **not** auto-apply — a human still confirms. Fast-track skips rc but still gate-approved.
- **Failed release before publication.** Nothing live changed (promote is the only live write). Job red; retry. **Caveat RB-2:** a partial `history` write can burn the version — fix before relying on this.
- **Bad release after publication.** Emergency revoke (below).
- **Emergency revocation.** `catalog-revoke.yml` (unbuilt), dispatch, admin-gated: regenerate stable index at **higher** version omitting the release, re-point channels, upload, purge, confirm. **Misuse/foot-gun:** requires the version counter/allocator to be reachable (M-3); C-6 break-glass must exist. **Blocked today:** the tooling doesn't exist and the fleet won't re-pull (RB-3), so revocation latency = human refresh, not 60s.
- **Rollback to last-known-good.** Forward-supersede pointing at the earlier good digest; `history/` tells the PM which digest. Never a lower re-publish (floor forbids). Correct.
- **Release with no rollout.** Stable-only has no percentage rollout (that's a deferred Phase-6 client change, §9.7). "No rollout" = publish to `stable`, `recommended` points at it; every appliance offered it on next refresh. Honest.
- **Release to internal test appliances.** Stable-only has **no `dev`/`beta` ring**. There is no built-in internal-only channel at go-live — the plan's ring model is deferred. **Misuse callout:** the §9 promotion narrative (rc→beta soak→promote) is *ring-dependent* and does **not** exist in the stable-only scope. Do not present beta-soak as available at cutover.
- **Promotion to all customers.** = publishing `stable`. Fine.

**Misuse callouts (parts still requiring hand-work or that misrepresent stable-only):**
1. The **rc→beta→stable graduation** narrative (§9.2, §9.10, GATE-D) is entirely deferred with rings — do not imply it exists at go-live.
2. The **weekly re-sign "bumps catalog_version"** instruction (§2.9, §5.1) is the RB-1 hazard; change it to "same version, refreshed freshness."
3. **No PM JSON/digest hand-editing is required** in the normal path — the plan holds here (spec is CI-generated from the pushed digest, `ci.yml:427-452`). Good. The one place a human *could* be tempted to hand-edit is emergency revoke; the revoke workflow must take `release_id` + `ring` and do the rest (§9.13) — enforce that in tooling, do not leave it as a runbook that edits `index.json`.

---

## 7. Automation gaps + IaC recommendation

**Remaining manual operations, classified:**

| Operation | Classification |
|---|---|
| Promote/approve release (protected env review) | **Must remain human** |
| Move `recommended` pointer | Must remain human (or gated auto) |
| Emergency revoke dispatch | Must remain human (+ C-6 dual-control) |
| CF provisioning (bucket, custom domain, cache rules) | **Should be IaC now** (see below) |
| GitHub Environment protections + `v*` tag ruleset | **Should be IaC/attested now** (GATE-A A-1) |
| R2/CF token rotation | Can automate later (scheduled) |
| Cache purge on publish | Already automated (CI) |
| Version allocation | Must be automated + single-allocator (RB-1) |
| Re-sign cron | Automated (fix RB-1 first) |
| Secondary-origin DR failover | Documented + drilled; semi-manual acceptable at go-live |

**Dangerous manual steps to remove before production:** any hand-edit of `index.json`/manifests/digests/`.sigstore`/R2 objects (the plan already forbids these — keep it that way); any human-invented `catalog_version` (C-3 fail-closed); resign that manually bumps the version (RB-1).

**IaC recommendation (smallest practical for stable-only, no over-engineering):**
- Use the **Terraform Cloudflare provider** for the *declarative, drift-prone, security-relevant* surface only: the R2 bucket, custom domain binding, the "Cache Everything + Origin Cache-Control" Cache Rule, disabling the `r2.dev` public URL, and the WAF/rate-limit rule. These are exactly the settings whose silent drift (R11: public write/list) is a HIGH risk, so they belong in reviewed, versioned config. Keep the Terraform state small and single-purpose.
- Do **not** IaC the object uploads — those are the CI publish job (`aws s3`/`rclone`/`wrangler`), which is the right tool and already dynamic per release.
- The **GitHub `v*` tag ruleset + `release` environment protections** should be captured as code/attestation (GATE-A A-1's periodic check) rather than click-ops, because they are the *only* control against a rogue tag (RB-5). A tiny scheduled job that reads the ruleset via the GitHub API and asserts the expected policy is sufficient — no need for full org-level Terraform.
- **Avoid** at go-live: a Durable-Object/D1 CAS counter (GATE-C) — unnecessary if RB-1's no-bump resign is adopted and rings are deferred. This is the plan's own Amendment 4 intent; just fix the serialization premise.

---

## 8. Exact pre-implementation changes required (before Phase 1)

1. **RB-1:** rewrite the re-sign design to **reuse `catalog_version`** (no bump; refreshed `generated_at`/`expires_at`; written to a resign-keyed path, not the release's `history/v<N>/`). If a bump is kept, add a single shared cross-workflow `concurrency` group or the CAS counter. Delete the "serialized by existing concurrency" claim.
2. **RB-2:** make the catalog spec's timestamps **deterministic from the tag** (not `date -u` at runtime). Define version-reuse-on-retry semantics. Do not layer create-only `history/` over a wall-clock spec.
3. **RB-3:** implement and test the **production HTTP refresher** (jittered ticker + single-flight + backoff + ETag driving `HTTPCatalogProvider`, auto-raising the floor). Wire it in `release_wiring.go`. This is new integration, not a flag.
4. **RB-4:** write `TestReleaseCatalogServedVerify` + the local-mock e2e; make the post-promote confirm a full re-verify.
5. Correct the plan text: remove the "idempotent re-run" and ring-based promotion narratives from the stable-only scope; state plainly that beta/graduation do not exist at go-live.

## 9. Exact pre-customer-cutover gates

1. **RB-5 / GATE-A A-1:** automated `v*` tag-ruleset attestation green.
2. **GATE-A A-2/A-4:** Rekor identity monitor live **with liveness alerting** and a paging on-call whose target **MTTR < refresh interval** (Amendment 3).
3. **GATE-A A-3:** `publish-catalog-r2` carries **no `id-token: write`** (verify in the merged workflow).
4. **A-5:** apply stays **operator-confirmed** (do not enable auto-apply unless A-4's response leg is hardened).
5. RB-1..RB-4 shipped and tested; canary runs a real digest-pinned update from R2 end-to-end.
6. Independently-credentialed **non-Pages** secondary origin proven (H-1), with a tested "re-serve last-good from `history/`" drill.

## 10. Exact pre-Pages-deletion gates (Phase 5)

1. **GATE-B B-2 (the real durability exit):** a fresh TUF `trusted_root.json` shipped in **every** release build + a **build-time check** that the baked root is not within N days of expiry (Amendment 2 correctly makes B-2, not B-1, the exit criterion). `TestSigstore_BakedRootCanBeParsed` alone is insufficient.
2. **GATE-B B-1 (reframed):** if an ed25519 second scheme is baked, it is a **migrate-off-Sigstore escape hatch** (drop `.sigstore` from new publishes), **NOT** live failover — because `artifact-owns-outcome` (`release_catalog_verify.go:259-284`) rejects a present-but-invalid `.sigstore` without ever consulting ed25519. **Amendment 2's correction is accurate and verified.** Do not document ed25519 as hot Sigstore-outage failover.
3. **B-1a custody reconciled with the unattended resign:** a scoped KMS/HSM automation principal signs; human dual-control governs key *lifecycle*, not each signing call (Amendment 2) — else the resign cron cannot run.
4. The independent secondary origin (H-1) exists and is drilled; do **not** delete Pages while it is the only tested secondary and privacy hasn't yet been proven not to have broken it.

---

## 11. Final production scorecard (0–10)

| Dimension | Score | One-line justification |
|---|---|---|
| **Security** | **8** | Trust model is genuinely sound and code-proven (in-binary verify, artifact-owns-outcome, freshness, rollback floor, digest pin); capped by the unverified `v*` ruleset (RB-5) being the sole rogue-tag control. |
| **Reliability** | **5** | RB-1 (concurrent-writer version collision) + RB-2 (non-idempotent re-run) + RB-3 (no production refresh) are live-fleet reliability defects; recoverable on paper but unbuilt. |
| **Operability** | **5** | Clean PM surface *intended*, but revoke/graduation tooling and the refresher don't exist; standing assets (Rekor monitor liveness, resign cron, secondary origin) must be operated to the assumed standard. |
| **Maintainability** | **6** | Reuses the shipped schema/generator verbatim (good); the counter/ring/graduation complexity is correctly deferred, but the plan carries ring-era prose into the stable-only scope, inviting drift. |
| **Scalability** | **8** | R2 + Cloudflare anycast + immutable manifests + short-TTL index scales to a large fleet; jittered refresh (once built) blunts thundering herds. |
| **Disaster recovery** | **5** | Forward-supersede + `history/` are sound primitives, but the named secondary origin (Pages) is undermined by repo-privacy (H-1) and the fleet can't auto-recover without RB-3. |
| **Release engineering** | **7** | Strong existing supply chain (keyless sign, SLSA, reproducible-build, digest-match gate); the new R2 publish path's safety interlock (RB-4) is a placeholder and version allocation (RB-1) is under-specified. |
| **Product operations** | **6** | "Three buttons" is achievable and no JSON hand-editing is required in the normal path; but beta/graduation/rollout are deferred, so several §9 runbooks describe capabilities that don't exist at go-live. |

---

## 12. Final recommendation

**Implement — but fix RB-1 through RB-5 in the design/code first; do NOT start Phase 1 until they are resolved.** The migration is worth doing and the architecture is fundamentally correct.

- **STABLE-ONLY: correct initial choice.** Deferring rings/CAS-counter/graduation is right. The plan's own Amendment 4 is the right scope — it just has to fix the false "serialized by existing concurrency" premise (RB-1) and adopt the **no-version-bump re-sign** simplification, which makes stable-only genuinely single-allocator and removes the need for the CAS counter honestly (rather than by assertion).
- **PUBLIC GHCR IMAGES: correct initial choice.** Eliminates B4 and an entire credential-distribution attack surface for zero integrity loss (digest pin backstops). Ratify §10#1 = public. The only cost is IP exposure of the product binary — a business decision to state explicitly (L-1), not a security one.
- **Defer:** rings, CAS counter, GATE-C/D machinery, `rollout` percentage, ed25519 second scheme as "failover" (it isn't).
- **Do NOT build (as described):** the version-bumping weekly re-sign; the "idempotent re-run" assumption; any Pages-as-independent-secondary posture after going private.

---

## 13. The five most likely ways this fails in production

1. **Concurrent writer version collision (RB-1).** The weekly re-sign fires while a tag release publishes; both allocate the same `catalog_version` with different content (no cross-workflow serialization, `ci.yml:19-24`). The fleet non-deterministically runs one of two "same-version" catalogs, and/or the real next release is refused as a rollback against a floor the cron already advanced. **This is the single most likely failure and it is self-inflicted, no attacker needed.**
2. **Re-sign/revoke never reaches running appliances (RB-3).** Because there is no production refresher (`release_wiring.go:223-229`), a freshness re-sign or an emergency revoke sits on R2 while long-running appliances flip to `available:false` at `expires_at` or keep offering a yanked release until an operator manually refreshes each one. The "PM presses a button, the fleet converges" model silently doesn't.
3. **A partial/rerun publish wedges a version permanently (RB-2).** Wall-clock timestamps in the spec (`ci.yml:440-450`) + create-only `history/` mean a failed-then-retried publish produces a different index at the same version, and the download-back verify rejects the mismatched index/signature forever at that version — bricking that release number.
4. **Repo-privacy silently disables the DR secondary (H-1).** Phase 4 flips the repo private, private-repo Pages stops serving anonymously (B1), and the "retained Pages secondary origin" the DR plan (§12) leans on is gone before the R2-based alternative exists — leaving a single-origin channel exactly when the plan claims two.
5. **Rogue `v*` tag mints a valid-identity catalog (RB-5).** The pinned identity trusts any tagged `ci.yml` run (`sigstore.go:72`) and `require-gate.sh` is strippable from the tagged tree (`require-gate.sh:30-35`); with the `v*` ruleset merely assumed (no automated attestation), a compromised token that can push a tag produces a fully-valid signed catalog. Detection (Rekor monitor) + operator-confirmed apply are the only backstops, and both are unbuilt at go-live.

---

*Findings are tied to repository evidence, not plan prose. The plan's three prior review rounds correctly identified the availability P0s and trust-durability gates; this review's new contribution is that (a) Amendment 4's stable-only "no-CAS" path is unsafe as written because the mandatory re-sign is a second unserialized writer, (b) the spec is non-deterministic across CI re-runs, and (c) three cited safety artifacts (`TestReleaseCatalogServedVerify`, the production refresher, the tag-ruleset check) do not exist. Resolve RB-1..RB-5 before Phase 1.*
