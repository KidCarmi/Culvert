# M0 — Foundation & Safety — Detailed Engineering Design (v2, post planning-review)

**Milestone:** M0 (first). **Canonical parent:** `CULVERT-RELEASE-PLATFORM-MASTER-DESIGN.md`.
**Branch base:** `main` @ `9b30c81`. **Epics:** E1 (publishing pipeline & correctness
core), E2 (version authority), E5 (legacy retirement), E4-staging (guardrails
without owner creds).

**v2 changelog:** revised after four independent planning reviews
(architecture/correctness, security/supply-chain, reliability/operations,
testability/simplicity). The headline change is the **version-authority redesign**
(§4.2): `catalog_version` is now a **pure, monotonic encoding of the release
semver**, not a shell tag-count — which eliminates the non-idempotency/collision
race AND makes re-sign-no-allocate automatic. All blocking/high findings and their
resolutions are tabulated in §14.

Self-contained: restates the master-design decisions M0 implements.

---

## 1. Scope

M0 makes release-catalog **generation + publish deterministic, idempotent, and
single-writer**, adds a **served-catalog verification interlock**, lands a
**dormant** R2 publish workflow, retires the **legacy unauthenticated GitHub tag**
discovery, and lands **IaC guardrails + activation docs** — **without owner
credentials** and **without changing any live customer behavior**.

M0 must prove (each mapped to its evidence type — executable **test** vs
**workflow-lint/design**, per review finding TEST-H3/ARCH-M4):
| # | Must prove | Evidence |
|---|---|---|
| 1 | Catalog generation deterministic | test (`TestGenerateReleaseCatalog_Deterministic` + new spec tests) |
| 2 | Re-running the same release is idempotent | test (`TestReleaseSpec_Idempotent` incl. grown/divergent tag history) |
| 3 | Re-sign does not allocate a new `catalog_version` | test (semver-derived version ⇒ same release ⇒ same version, by construction) |
| 4 | Two publishers can't create conflicting content at a version | **design** (semver-derived version is race-free) + **workflow-lint** (create-only history) |
| 5 | Staged bytes verified before live promotion | **workflow-lint** (job step order) |
| 6 | Verify failure can't mutate the live pointer | **workflow-lint** (promote gated on verify success) |
| 7 | R2 job has no `id-token: write` | **workflow-lint** (asserted) |
| 8 | Served bytes checked by the real in-binary verifier | test (baked-root env-gated served variant) |
| 9 | Missing CF creds ⇒ explicit safe-skip, never partial | **workflow-lint** (`vars`-gate present; no `secrets.*` in `if`) |
| 10 | Legacy unauthenticated GitHub tag discovery retired/disabled | test (default path takes no GitHub-tags branch) |
| 11 | Existing GitHub Pages behavior unchanged | design (no M0 change touches `publish-catalog-pages.yml`) |

## 2. Non-goals (deferred)

No live R2 publishing (job dormant). No rings/CAS-counter/graduation. No revoke, no
re-sign **cron** (M1/E8) — the re-sign **contract** is satisfied by construction
(§4.2). No client refresher (M1/E3). No repo-private flip (M2). No Pages changes
(M3). No OIDC in the new job. No telemetry/console (M4). `history/<ring>/…` uses the
constant `stable` — **not** ring machinery (ARCH-LOW7).

## 3. Repository findings (evidence)

- **RB-2 (timestamp non-determinism):** `ci.yml:440-443` uses `date -u` for
  `generated_at`/`expires_at`/`created_at`. Re-run ⇒ different bytes ⇒ different
  `manifest_sha256` (`release_catalog.go:313` hashes raw manifest bytes).
- **RB-1 + version non-idempotency (BLOCKING, arch+reliability):**
  `catalog_version = (count of v* tags)+1` (`ci.yml:443`) is a **live count** — a
  re-run of an *older* tag after newer tags exist yields a *higher* version
  (non-idempotent), and two tags present in one checkout count the same → collision
  accepted (`release_catalog_freshness.go:110` accepts `version == floor`). A
  concurrency group over the counter does **not** fix this (both runs read the same
  committed tag set).
- **Served-verify gap:** the CI gate verifies **generated** bytes, never **served**;
  no served test exists.
- **E5:** `checkGitHubLatestTag` (`update.go:309`, sole caller `:412`) GETs
  `api.github.com/repos/KidCarmi/Culvert/tags` **unauthenticated** → 404 on a
  private repo. It also served a **registry-semver-gap** role (`update.go:404-408`)
  for public users, so default-off is a behavior change, not purely a bugfix.
- **Deferred private-repo fetches (M2, not M0):** `internal/saasfeed/saasfeed.go:37`
  (`raw.githubusercontent.com/KidCarmi/Culvert/…`) and `scripts/install.sh:5` raw
  bootstrap share the private-flip 404 mode — inventoried here, fixed in M2.
- **Pages:** `publish-catalog-pages.yml` (`workflow_run` on `CI`) is untouched.

## 4. Design

### 4.1 Deterministic spec construction (E1 / fixes RB-2)

Timestamp + version derivation moves out of wall-clock shell into a pure, tested Go
function, **folded into the existing gate** (no new writer-test — TEST-H1):

```
type SpecInputs struct {
    Version    string   // "1.4.3" (from tag ref / version_bare)
    Repo       string
    ListDigest string   // "sha256:<64hex>"
    Platforms  []string
    CommitISO  string   // tagged-commit committer date (git %cI); DETERMINISTIC per tag
    ExpiryDays int      // 180 (D9)
    Mode       specMode // specModeRelease | specModeResign
    ResignNow  string   // resign-only: RFC3339 "now" (M1 supplies; unused in M0)
    CreatedAt  string   // resign-only: the release's ORIGINAL created_at (carried forward)
}
func buildReleaseSpec(in SpecInputs) (releaseCatalogSpec, error)   // pure; assembles + normalizes; NO clock, NO git, NO network
```

- **Timestamps are inputs, normalized to UTC `Z`** inside `buildReleaseSpec`
  (`time.Parse(RFC3339, CommitISO).UTC().Format(RFC3339)`) — `git %cI` emits a
  numeric offset (`+00:00`), which would change bytes vs the retired `…Z` form and
  break `manifest_sha256` (SEC-M5 / TEST-M1 / ARCH-LOW6 / REL-M5, unanimous).
- **`generated_at` (release mode) = normalized `CommitISO`** (idempotent per tag).
  **`expires_at` = `generated_at` + `ExpiryDays`** via a `deriveExpiry(genAt, days)`
  helper. **`created_at` = `generated_at`** in release mode (a release's creation ==
  its tagged commit).
- **`buildReleaseSpec` is assembly + normalization only; `generateReleaseCatalog`
  remains the SOLE validator** (TEST-M3 / avoids a second drift-prone validation
  site). It maps `SpecInputs` → `releaseCatalogSpec` and computes `catalog_version`
  (§4.2) + `expires_at`; the existing generator validates.
- **CI wiring:** the `spec` step gathers immutable git facts in shell — `COMMIT_ISO`
  (`git log -1 --format=%cI "$GITHUB_REF_NAME"`), `VERSION`, `DIGEST` — **no clock,
  no tag-count**. `TestReleaseCatalogGate` is extended to read
  `CULVERT_RELEASE_SPEC_{COMMIT_ISO,VERSION,DIGEST,REPO}` and call `buildReleaseSpec`
  internally (replacing the pre-built spec-file read), so the same gate both builds
  and round-trips through the real loader — one gate, timestamp+version math in
  tested Go, the `date -u` heredoc deleted.

### 4.2 Version authority — semver-derived, race-free (E2 / fixes BLOCKING-1 + HIGH-2 + resign contract)

**`catalog_version` is a pure, monotonic function of the release semver — never a
tag count, never git state, never wall-clock:**

```
catalogVersionFromSemver(v) = major*1_000_000 + minor*1_000 + patch
   // each component validated < 1000 (fail closed otherwise; bound revisited with pre-release/rings)
```

Why this closes every version finding at once:
- **Deterministic + idempotent (fixes BLOCKING-1):** depends only on the tag's
  semver, so re-running any tag — before or after newer/older tags exist — yields
  the identical version. No dependency on the mutable tag set.
- **Monotonic (GA order == semver order on stable):** a later GA release has a
  higher semver ⇒ higher `catalog_version`; the appliance floor accepts it. A
  backport (`v1.2.10` after `v1.5.0`) encodes *lower* ⇒ the floor refuses the
  downgrade for `v1.5.0` appliances (correct anti-downgrade) while `v1.2.x`
  appliances still accept it.
- **Collision-free:** distinct semver ⇒ distinct integer. No race, so the RB-1
  concurrency-group-for-correctness is **unnecessary** (removes HIGH-2 and the
  `cancel-in-progress` burst-drop hazard, REL-HIGH-2, as a *correctness* concern).
- **Re-sign-no-allocate is automatic (must-prove #3):** re-sign republishes the
  *same* release ⇒ same semver ⇒ same `catalog_version`, by construction. No
  contract to enforce separately; `created_at` is carried forward unchanged
  (`SpecInputs.CreatedAt`), so a re-signed index differs from the original **only**
  in `generated_at`/`expires_at` (ARCH-M3 / REL-H3 resolved).
- **Migration-safe:** the current on-disk scheme is `count+1` (small, ~16); the
  first semver-derived version (e.g. `v0.0.16` → `16000`) is strictly larger, so
  the floor only ever moves up — no appliance regression.
- M0's catalog is **single-entry** (CI emits one release per index, `ci.yml:448`);
  the version is that release's semver. Multi-release indexes (future) revisit
  version identity — noted, deferred.

**Single-entry, single-allocator context:** allocation happens only in the
tag-path spec build (`buildReleaseSpec`), a pure function — there is no shared
mutable source to race on. The `history/stable/v<N>/` write remains **create-only**
(defense-in-depth: two publishes of the same version must be byte-identical or the
create fails), asserted by workflow-lint. No dedicated concurrency group is required
for version correctness; if one is later added for R2-upload *isolation* it is not
load-bearing for versioning.

### 4.3 Served-catalog verification interlock (E1 / D6, RB-4)

**Extend the existing `fakeCatalogServer` httptest harness**
(`release_catalog_http_test.go:19-58`) — do NOT add a parallel origin fake
(TEST-H2 / REL-M1). It already drives the **real** `HTTPCatalogProvider` +
`LoadVerifiedCatalog` with etag/304/redirect/slow/tamper/truncate negatives.

Add only the genuinely-missing coverage:
- **expired** and **rollback (lower version)** — driven through an explicit
  `freshnessPolicy{enabled, now: injected, statePath}` (`applyFreshnessAndRollback`,
  `release_catalog_freshness.go:120`), because `Stage`/`LoadVerifiedCatalog` do NOT
  run freshness/rollback themselves (ARCH-M4). Use an **injected clock**
  (`mustTime`, `release_catalog_freshness_test.go:94`), never `time.Now()` (no rot).
- **oversized body** (reuse `bytes.Repeat(…, catalogMaxReadBytes+1)` +
  `readAllBounded`, `release_catalog_bundle_test.go:228`).
- **weak-ETag** case and a **redirecting-origin** negative (`checkRedirect`,
  `release_catalog_http.go:148`).
- **Sigstore-served** path.
- The whitebox test **must set `p.guard = nil`** for the loopback httptest host
  (ARCH-LOW5).

**Two distinct served-verify roles (SEC-HIGH-1 / REL-M2):**
1. **Local plumbing proof** (`TestReleaseCatalogServedVerify`, virtual signer via
   `ca.NewVirtualSigstore`): proves HTTP transport + two-phase verify + freshness
   plumbing. Self-contained.
2. **Baked-root served gate** (env-gated, `CULVERT_RELEASE_SERVED_URL`): constructs
   the trust store from `newSigstoreVerifier(bakedSigstoreTrustedRootJSON,
   officialSigstoreIdentity())` + `NewTrustStoreWithSigstore(nil, VerifyEnforce, sv)`
   and drives the real provider against an external served URL. This is the variant
   the dormant R2 job invokes against the **staged** URL to satisfy must-prove #8 —
   a virtual signer cannot verify real Fulcio-signed production bytes.

### 4.4 Dormant R2 stage→verify→promote workflow (E1 / D6, D7)

New job `publish-catalog-r2` (placement decided in PR3 review):
- **Permissions `contents: read` ONLY — no `id-token: write`** (D7; verify-only).
- **Dormant gate via `vars`, not `secrets`** (SEC-HIGH-2 / REL-HIGH-1 — `secrets`
  is unavailable in `if:`): `if: ${{ github.ref_type == 'tag' && vars.R2_PUBLISH_ENABLED == 'true' }}`.
  Absent the var ⇒ clean skip (green, neutral); never a partial run.
- **stage → verify → promote → purge → confirm:**
  1. upload immutable `manifests/**` to live — safe-early **iff** manifest object
     keys are unique-per-publish (they are: `release_id = culvert-<version>` is
     unique per release, `release_gen.go:92`) — precondition documented (REL-M3);
  2. stage the full bundle to `history/stable/v<N>/` **create-only**;
  3. **verify the STAGED URL** with the baked-root served gate (§4.3 role 2);
  4. **promote by server-side-copying the verified staged objects** to live (NOT
     re-uploading the local artifact — SEC-M3), only on verify success;
  5. purge index+sidecars; cache-busting confirm.
- Fails closed at every step; verify-fail ⇒ no promote ⇒ live pointer untouched.

### 4.5 Legacy retirement (E5)

`checkGitHubLatestTag`: gate the fallback **off by default** behind read-once
`CULVERT_LEGACY_GH_TAG_CHECK` (default off ⇒ no unauthenticated GitHub call ⇒ no
private-repo 404 brick); loud one-line log; code retained for the compat window.
- **Testability (TEST-M4):** `checkGitHubLatestTag` has no client seam. Test at the
  **caller** (`checkUpdate`, `update.go:412`): assert the default build does **not**
  take the GitHub-tags branch (observe the gated bool / a no-dial counter), or add a
  minimal base-URL override for an httptest assertion — chosen in PR4.
- **Behavior-change note (REL-M4):** the fallback also covered the
  registry-semver-gap for public users; default-off may reduce update *visibility*
  there. Documented in the PR + `update.go` comment. `saasfeed`/`install.sh` raw
  fetches are **M2**, not M0.

### 4.6 IaC guardrails + activation docs (E4-staging)

- `deploy/terraform/` **declarations-only** skeleton (Cloudflare + GitHub providers)
  for the guardrails (R2 bucket/policy, custom domain, cache rules, `release` env
  protections, `v*` ruleset) — no secrets, no invented resource detail.
- A **CI `terraform fmt -check` + `validate`** step wired into a lane so the
  skeleton can't rot (TEST-M6) — otherwise "validate-clean" is untested.
- `docs/operator/catalog-hosting-r2-activation.md`: exact owner activation steps
  (bucket/domain, the 5 secrets, set `vars.R2_PUBLISH_ENABLED=true`).
- **Workflow-lint test** (`TestWorkflowInvariants`, parses YAML) — load-bearing
  assertions: R2 job has **no `id-token: write`**; the dormant gate uses `vars`
  (no `secrets.*` in any job `if:`). Intent assertions (dormant-job config, per
  TEST-M5): create-only history flag present. Labeled as intent, not behavior.

## 5. State transitions & trust boundaries

Spec build: immutable git facts → `buildReleaseSpec` (pure, normalizes, derives
version) → existing generator (validates) → deterministic bytes. Publish (dormant):
untrusted staging (`history/stable/v<N>/`) → **baked-root in-binary verify (trust
boundary)** → server-side-copy promote to live. Verify: unchanged, offline,
fail-closed; origin untrusted.

## 6. Failure behavior

| Failure | Behavior |
|---|---|
| Spec inputs missing/invalid, or semver component ≥ 1000 | `buildReleaseSpec` error; CI step fails closed. |
| Old-tag re-run would ship an already-expired catalog | `buildReleaseSpec` guard: reject if `expires_at` ≤ generation `now` reference (REL-H3) — fail closed, don't ship dead-on-arrival. |
| Non-deterministic drift (bug) | determinism/idempotency tests fail in CI. |
| Version collision (bug) | impossible by construction (distinct semver); create-only history is the backstop. |
| Served bytes don't verify | baked-root served gate fails; dormant job (when live) does not promote. |
| Missing CF creds / `vars` unset | dormant job **skips** (green, neutral); no writes. |
| Private repo (legacy path) | default build makes no GitHub-tags call. |

## 7. Rollback behavior

All M0 changes are additive/CI-local: revert the spec refactor commit → old shell
returns; served-verify + workflow-lint are pure additions; dormant R2 job gated off
(deleting it changes nothing live; Pages authoritative); legacy gate is a default-off
flag; IaC/docs inert.
**Operational note (REL-M4, M0→M1 window):** with the legacy fallback default-off,
the R2 path dormant, and no re-sign cron until M1/E8, the Pages-served catalog's
180-day `expires_at` must not lapse before M1 ships. Mitigation: this window is
short; if M1 risks slipping past the expiry margin, pull the re-sign cron forward.
An interim manual live-pointer rollback (revoke is M1) is documented in the
activation runbook.

## 8. Test strategy

- `TestReleaseSpec_Deterministic` / `_Idempotent` — same inputs → identical spec;
  **including a re-run against a grown/divergent tag set** asserting identical
  `catalog_version` (BLOCKING-1 regression guard).
- `TestCatalogVersionFromSemver` — monotonic (`v1.4.3 < v1.4.4 < v1.5.0`), distinct,
  boundary (`v0.0.1 → 1 ≥ 1`), component-bound fail-closed (`≥1000`), backport-lower.
- `TestReleaseSpec_UTCNormalize` — `+NN:NN` input → `…Z` output.
- `TestReleaseSpec_ResignPreservesIdentity` — resign inputs ⇒ same `catalog_version`
  + same `created_at` + same `manifest_sha256`; only `generated_at`/`expires_at`
  differ.
- `TestReleaseSpec_OldTagExpiredGuard` — a commit-date old enough that
  `+180d` is past ⇒ error.
- Served: extend `fakeCatalogServer` with expired/rollback (injected clock +
  `statePath`), oversized, weak-ETag, redirect, Sigstore-served; `p.guard=nil`.
- `TestWorkflowInvariants` — no `id-token` in the R2 job; `vars`-gate (no
  `secrets.*` in `if`); create-only history flag.
- `TestLegacyGhTagCheck_DisabledByDefault` — default build takes no GitHub-tags
  branch (caller-level).
- Regression: `TestGenerateReleaseCatalog_Deterministic`, `TestReleaseCatalogGate`,
  keyless/verify suites stay green. `go test ./...`, `-race` on the catalog surface,
  `go vet`, `terraform validate`.

## 9. Acceptance criteria

All 11 must-prove items demonstrated by their mapped evidence type (§1 table);
existing Pages + release flow byte-unchanged; no owner credential used; required CI
gates green per PR.

## 10. Owner prerequisites (activate later; do NOT block M0)

Cloudflare account/bucket/domain, R2 S3 creds, cache-purge token, zone ID, cache
rules, Smart Tiered Cache, disabled `r2.dev`; GitHub secrets, `vars.R2_PUBLISH_ENABLED`,
protected `release` env + reviewers, `v*` ruleset. In `catalog-hosting-r2-activation.md`.

## 11. Risks

| Risk | Mitigation |
|---|---|
| Semver encoding overflow (component ≥ 1000) | validate + fail closed; bound documented; revisit for pre-release/rings. |
| Old-tag re-run ships expired catalog | `_OldTagExpiredGuard` fail-closed. |
| Committer-date TZ drift | UTC-`Z` normalization + `_UTCNormalize` test. |
| Dormant job accidentally runs | `vars` gate + tag-path gate; workflow-lint asserts. |
| Legacy default-off masks registry-gap updates for public users | documented; flag opt-in retained. |
| Terraform skeleton rots | CI `fmt -check`/`validate`. |

## 12. PR split

| PR | Scope | Boundary rationale |
|---|---|---|
| **M0-PR1** | `release_spec.go` (`SpecInputs`, `buildReleaseSpec`, `catalogVersionFromSemver`, `deriveExpiry`, UTC normalize, expired-guard) + fold into `TestReleaseCatalogGate` + deterministic CI spec step + version/spec tests | correctness core; smallest revertable unit fixing RB-1/RB-2. |
| **M0-PR2** | Extend `fakeCatalogServer` served-verify cases + baked-root env-gated served gate | pure test addition. |
| **M0-PR3** | Dormant `publish-catalog-r2` (vars-gated, no id-token, stage→verify→promote, server-side-copy) + `TestWorkflowInvariants` | isolated CI surface; reviewable for the security invariants alone. |
| **M0-PR4** | Legacy `checkGitHubLatestTag` default-off + caller-level test | isolated runtime-client change. |
| **M0-PR5** | Terraform guardrails skeleton + `validate` CI + activation docs | inert infra/docs. |

## 13. Definition of Done

§9 met; §8 tests green (incl. `-race` on the catalog surface, `go vet`,
`terraform validate`); no `date -u`/wall-clock/tag-count/hardcoded
digest/version/domain in the spec path; dormant R2 job `contents: read` only,
`vars`-gated skip; Pages + release flow byte-unchanged; tracker updated; each PR
merged (by owner) with required gates green.

---

## 14. Planning-review findings & resolutions (traceability)

| Finding | Sev | Resolution in v2 |
|---|---|---|
| ARCH-B1 / REL-B1 — version from mutable tag-count is non-idempotent + collision-prone | **BLOCKING** | §4.2 — `catalog_version` = pure semver encoding; idempotency test over grown/divergent history. |
| SEC-H2 / REL-H1 — `secrets.*` not available in `if:` | HIGH | §4.4 — gate on `vars.R2_PUBLISH_ENABLED`; workflow-lint asserts no `secrets.*` in `if`. |
| SEC-H1 — served gate used a virtual signer, not the baked root | HIGH | §4.3 — two roles; the dormant-job gate uses baked root + pinned identity (env-gated served variant). |
| REL-H2 — `cancel-in-progress:false` drops the pending run under bursts | HIGH | §4.2 — versioning no longer depends on a concurrency group; race removed by construction. |
| REL-H3 / ARCH-M3 — committer-date vs re-sign freshness; `created_at==generated_at` breaks resign | HIGH/MED | §4.1/§4.2 — two spec modes; `created_at` immutable/carried-forward; old-tag expired guard. |
| ALL — `git %cI` is `+00:00` not `Z` → byte drift | MED | §4.1 — UTC-`Z` normalization + `_UTCNormalize` test. |
| TEST-H1 — env-gated writer-test is test-as-CLI anti-pattern | HIGH | §4.1 — fold spec construction into the existing `TestReleaseCatalogGate`; no writer-test. |
| TEST-H2 / REL-M1 — parallel served harness duplicates `fakeCatalogServer` | HIGH/MED | §4.3 — extend the existing harness; add only missing cases. |
| TEST-H3 / ARCH-M4 — #4/#6/#9 aren't Go-testable; freshness not exercised | HIGH/MED | §1 table — relabeled as workflow-lint/design; §4.3 wires explicit `freshnessPolicy`. |
| SEC-M3 — promote may re-upload local, not verified staged bytes | MED | §4.4 — promote = server-side copy of the verified staged objects. |
| SEC-M4 — E5 inventory incomplete (saasfeed, install.sh) | MED | §3/§4.5 — inventoried, explicitly deferred to M2. |
| REL-M3 — manifests-to-live-early safety precondition unstated | MED | §4.4 — precondition documented (`release_id` unique-per-publish). |
| REL-M4 — legacy fallback dual role; M0→M1 expiry window | MED | §4.5/§7 — documented behavior-change + expiry-window mitigation. |
| TEST-M3 — `buildReleaseSpec` risks a 2nd validator | MED | §4.1 — assembly-only + `deriveExpiry`; generator stays sole validator. |
| TEST-M4 — no client seam for legacy test | MED | §4.5 — test at caller / minimal override, decided in PR4. |
| TEST-M6 — terraform skeleton rot | MED | §4.6 — CI `fmt -check`/`validate`. |
| ARCH-LOW5/6/7 — httptest `guard=nil`; `%cI` label; `<ring>` segment | LOW | §4.3/§4.1/§2 — addressed. |

**Disposition:** all BLOCKING and HIGH findings resolved in this design. Proceed to
implement M0-PR1.
