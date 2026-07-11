# M1 — Dual-publish verification, production refresh, detection, re-sign — Detailed Design (v2, post design-review)

> **v2 note:** three independent design reviews (security/trust, release-ops/CI,
> appliance-runtime) returned approve-with-fixes with 2 BLOCKING + 5 HIGH findings.
> §9 records every finding and its binding resolution; where §1–§4 conflict with §9,
> **§9 wins**. Slice D is GATED on the two BLOCKING security fixes.

**Milestone:** M1 (post-M0 acceptance, `roadmap/M0-ACTIVATION-EVIDENCE.md`).
**Scope (frozen by owner):** (1) dual-publish verification, (2) production HTTP
catalog refresh, (3) detection/canary/alerting, (4) weekly no-bump re-sign +
180-day freshness. **Out:** repo-private (M2), Pages retirement (M3), rings/
percentage rollout/telemetry/Release Console (M4+), any M0 redesign absent a proven
regression. Plus two M0-activation regression guards (one already shipped).

## 0. Prerequisite audit (evidence)

| Fact | Evidence |
|---|---|
| Manual refresh seam exists | `release_api.go:63` `refresh func(context.Context) error`; `POST /api/releases/catalog-refresh` (line 190, 264-297) drives the REAL auto-seed path; proven live in the M0 tamper drill ("Refresh failed" = this endpoint failing closed) |
| Auto-seed is startup-only today | `release_autoseed.go` (called from startup wiring); no periodic loop |
| Re-sign spec mode implemented, CI plumbing absent | `release_spec.go:44-206` `specModeResign` (requires `resign_now`+`resign_created_at`, preserves `created_at`+`catalog_version`); no `RESIGN` env in `ci.yml`/`release_gen_test.go` |
| Signing context is pinned to tag refs of ci.yml | `officialSigstoreSANRegex = ^…/ci\.yml@refs/tags/v.*$`; `ci.yml` has `workflow_dispatch` ⇒ dispatching **at a tag ref** yields a matching SAN |
| R2 publisher refuses re-signed bytes at an existing tag prefix | create-only staging + origin-digest guard (M0-PR3): different index bytes at `history/stable/<tag>/` ⇒ loud abort — CORRECT for releases, must be designed around for re-signs |
| Alerting engine available | `alerts.go:35` `fireAlert(event, AlertPayload)` (delivery + retry in `internal/alerts`) |
| Live baseline | R2 live serves verified `v1.0.0` (`catalog_version=341`, `expires_at 2026-09-25`); Pages authoritative; publisher enabled |

## 1. Slice A — Dual-publish verification (PR M1-1)

**Goal:** after each release, PROVE Pages and R2 serve the same verified catalog.

- New job `dual-publish-verify` in `publish-catalog-r2.yml` (after the confirm step)
  — or a separate `workflow_run` workflow; decision at review. It fetches
  `index.json` from BOTH origins (`kidcarmi.github.io/Culvert/release-catalog`,
  `catalog.culvertlabs.com/release-catalog`), asserts sha256(pages) ==
  sha256(r2) == the release-bundle digest, and runs the env-gated baked-root served
  gate against BOTH origins.
- Divergence ⇒ job fails RED + (Slice C) fires an alert. It never mutates either
  origin (verify-only; `contents: read`, no id-token).
- Timing caveat: Pages deploys via its own `workflow_run`; the check must tolerate
  Pages lag (bounded retry, e.g. 10 min) before declaring divergence.

## 2. Slice B — Production HTTP catalog refresh (PR M1-2)

**Goal:** appliances converge on new/re-signed catalogs without restarts.

- Background loop in the proxy (new `release_refresh.go`): every
  `release.refresh_interval` (default **6h**, jittered ±10%, YAML+env, GUI parity
  via `/api/releases` + settings panel), call the EXISTING `rm.refresh` seam.
- Semantics (all already enforced by the holder/auto-seed path — the loop adds no
  new trust logic): unchanged catalog (ETag 304) ⇒ no-op; new verified catalog ⇒
  install + floor ratchet; verify/freshness/rollback failure ⇒ keep current catalog,
  count + alert (Slice C). Never fails the proxy hot path.
- Runs ONLY when `CULVERT_RELEASE_CATALOG_URL` is configured (same condition as
  startup auto-seed). Loop registered via the background-services startup slice;
  clean shutdown via context.
- Concurrency: serialize with the manual refresh endpoint (single-flight mutex —
  both call the same seam).

## 3. Slice C — Detection / canary / alerting (PR M1-3)

**Goal:** operators learn about catalog problems from alerts, not outages.

- New alert events via `fireAlert`: `release_catalog_stale` (installed catalog’s
  `expires_at - now < threshold`, default 30d — the 180-day freshness watchdog),
  `release_catalog_refresh_failing` (N consecutive refresh failures, default 3),
  `release_catalog_recovered` (first success after failures). Emitted by the Slice-B
  loop; state in the refresh loop (no new stores).
- `/api/releases` gains `last_refresh{at,ok,error}`, `consecutive_failures`,
  `expires_in_days` (GUI parity: surface in the Release panel).
- Prometheus: `culvert_release_catalog_refresh_total{result}`,
  `culvert_release_catalog_expires_in_seconds` gauge.
- **Canary (bounded to scope):** the dual-publish job (Slice A) IS the publish-side
  canary; appliance-side “canary” here = the stale/failing alerts above. No rings,
  no percentage rollout (out of scope).

### 3.1 Implementation decisions (M1-3, 2026-07-10)

- **Latches (RT-H2)** live on `releaseManager` under `statusMu` (no new stores):
  `refreshFailingLatched` + `staleLatched`. Transitions are computed under the
  lock and FIRED after unlock (`release_alerts.go`). Enforcement:
  `TestStaleAlert_OncePerCrossing` + `TestRefreshFailingAlert_TransitionsOnly`.
- **`recovered` pairs with a fired `refresh_failing`** — a sub-threshold blip
  (fail, fail, success) is completely silent; transitions only, no per-evaluation
  noise (answers §2 Q2 as reviewed).
- **Stale evaluation points:** every `runRefresh` (loop ticks incl. 304 no-ops +
  manual refresh) + ONCE at startup wiring — an appliance booting with an
  already-stale catalog alerts immediately, via `deferStartupAlert` (webhooks
  load in a later startup slice; queue-then-flush). Restart re-fires a
  still-active alert once (latch reset on restart — accepted + documented).
- **Alert seam:** `releaseAlertFire` (defaults to `deferStartupAlert`; Dispatch
  is non-blocking) so the latch tests capture synchronously.
- **Thresholds are constants** (30d / 3 failures) — recorded deferral: not a
  config option, so the GUI-parity rule doesn't bite; an env/GUI knob waits for
  a deployment that needs one.
- **Metrics (RT-L1):** `releaseCatalogWritePrometheus` appender in
  `handleMetrics`; the expiry gauge is scrape-time from the installed catalog
  and OMITTED when no catalog/expiry is published (absent series beats a fake 0,
  which Prometheus would read as "expired").
- **API/GUI:** `expires_in_days` (floor; negative = expired) next to
  `expires_at` on `/api/releases`; Release-panel origin strip gains the expiry
  row with warn color inside the 30d threshold.

### 3.2 M1-3 implementation review (2026-07-10) — fixes folded in

Independent review verdict: **ship-with-fixes** (no BLOCKING/HIGH; concurrency,
wiring order, metrics-shape, GUI-XSS, and design compliance all traced clean).
Accepted findings + enforcement per the §10 rule:

| Finding | Sev | Fix | Enforcement |
| --- | --- | --- | --- |
| Expired catalog invisible to detection in enforce mode (`GetCatalog` hides it at use time ⇒ watchdog/gauge went blind at exactly the terminal moment; boot-after-lapse never alerted) | MED | `holder.PublishedRaw()` observability accessor (`rm.observeCatalog`) for the watchdog + gauge + API expired-reason (`reason:"installed catalog expired"`, negative `expires_in_days`); boot-after-lapse (Reload refuses expired dir) fires a latched `release_catalog_stale` at wiring | `TestReleaseExpiry_RuntimeLapseStaysObservable`, `TestStaleAlert_BootAfterLapse` |
| Evaluation WIRING not test-enforced (deleting the startup/runRefresh eval calls stayed green) | MED | — (wiring was correct; tests were missing) | `TestStaleAlert_FiresAtStartupWiring`, `TestStaleAlert_EvaluatedOnRunRefresh` |
| `expires_in_days` truncated toward zero (12h past expiry read "0 days", not EXPIRED) | LOW | `math.Floor` | asserted in `TestReleaseExpiry_RuntimeLapseStaysObservable` (−2 not −1 at 36h past) |
| Stale startup-ordering comments (webhooks actually load BEFORE release wiring; `deferStartupAlert` is passthrough there) | LOW | comments corrected — the queue path is ordering robustness, not a live dependency | doc-only |
| Empty alert `Host` with fetch disabled; UI hardcodes the 30d threshold | LOW | `alertHost()` fallback (`local-catalog`); cross-referencing comments on the Go constant + panel | doc/code-only |

**Recorded residual (accepted-by-design):** a refresh that installs a *newer but
still-stale* catalog (stale A → stale B) does not re-alert — the latch re-arms
only on a fresh crossing, consistent with once-per-crossing; a re-sign pipeline
that limps along extending expiry by <30d each week alerts once, not weekly.
Revisit only if M1-4's cadence gate (SEC-F5) proves insufficient.

## 4. Slice D — Weekly no-bump re-sign + 180-day freshness (PR M1-4, most complex)

**Goal:** the served catalog’s `expires_at` never lapses even with no releases.

- **Signing context:** a tiny scheduler workflow (`resign-catalog.yml`, weekly cron
  + manual dispatch; `actions: write` ONLY) resolves the latest `v*` tag and
  dispatches **`ci.yml` at that tag ref** with a `resign=true` input — so the
  keyless signature’s SAN is `ci.yml@refs/tags/v<latest>` and matches the pinned
  identity. The scheduler itself signs nothing (no id-token).
- **ci.yml resign path:** `workflow_dispatch` gains a `resign` boolean input. When
  true, `catalog-pipeline` runs a REDUCED path: skip build/docker/release; download
  the tag’s existing release bundle; extract `created_at` from the CURRENT index;
  run the gate in `specModeResign` (new envs `CULVERT_RELEASE_SPEC_RESIGN=1`,
  `_RESIGN_NOW`, `_RESIGN_CREATED_AT`) → byte-new index, SAME `catalog_version` +
  `created_at`, fresh `generated_at`/`expires_at` (+180d); keyless-sign; **verify
  end-to-end** (`TestReleaseCatalogKeylessVerify`); attach to the release as a
  versioned resign asset (`culvert-release-catalog-<tag>-r<YYYYMMDD>.tar.gz`) —
  the original release asset is never replaced.
- **R2 publish of a re-sign:** the R2 publisher gains a matching `resign` dispatch
  input: stage to `history/stable/<tag>-r<YYYYMMDD>/` (create-only preserved; a
  NEW prefix, so the M0 digest guard stays intact for real releases), verify the
  staged URL through the baked-root gate, promote (idempotent copy; live pointer
  last), purge, confirm. Rollback floor: `catalog_version` unchanged ⇒ `>= floor`
  passes; appliances accept via ETag-change + verify.
- **Pages re-sign:** `publish-catalog-pages.yml` is UNTOUCHED (M3 boundary). Its
  `workflow_dispatch` can already republish a tag; the resign asset naming keeps its
  `culvert-release-catalog-*` glob compatible — **decision for review:** whether the
  weekly flow also re-dispatches Pages (dual-publish parity for re-signs) or Pages
  keeps the original signature until its retirement (divergence-by-design the Slice-A
  check must then tolerate for resigns). Recommended: re-dispatch Pages too, keeping
  the two origins byte-identical (its newest-asset pick must then prefer the newest
  `culvert-release-catalog-*` file — verify its `head -n1` glob ordering).
- **Failure posture:** every step fails closed; a failed re-sign leaves both origins
  serving the previous (still-valid) catalog; the Slice-C stale alert is the
  backstop (fires at 30d remaining, giving ~5 weekly retries before lapse).

### 4.1 Implementation decisions (M1-4, 2026-07-10)

- **`CULVERT_RELEASE_SPEC_RESIGN_CREATED_AT` env DROPPED** (delta from the §4
  provisional env list): SEC-F1 requires every entry fact to come ONLY from the
  signature-verified bundle — an env-provided created_at would be a spoofable
  side-channel around verify-before-read. The gate takes `_RESIGN_SRC` (bundle
  dir), `_VERSION` (from the dispatch ref), `_RESIGN_NOW`, `GEN_OUT` only.
- **The resign gate core is `buildResignSpecFromVerified`**
  (release_resign_gate_test.go): verify-first (LoadVerifiedCatalog — signature +
  structure, expiry-TOLERANT by design: re-signing a lapsed catalog is the
  recovery case), single-entry assert, version binding, spec rebuilt from
  verified bytes. Always-on unit tests (`TestResignGate_*`) mutation-prove
  SEC-F1 without the CI-only path; `TestReleaseResignGate` is the CI entrypoint
  wiring the REAL baked root + pinned identity.
- **Resign invariants pinned in the gate**: same `catalog_version`, same
  `created_at`, byte-identical manifests, index differs ONLY in
  `generated_at`/`expires_at` (+180d), deterministic re-runs.
- **OPS-F1 implemented as guard + structural skip**: `resign-dispatch-guard`
  fails loudly on a bare tag dispatch, AND `docker` skips all tag-ref
  dispatches — its needs-chain (catalog-pipeline, release, provenance) then
  skips, so a dispatched tag run can never overwrite release assets even if the
  guard were deleted (the invariant test pins both halves).
- **Pages ordering fix adopted** (the §4 "decision for review", recommended
  option): the weekly flow re-dispatches Pages for dual-publish parity, and the
  Pages bundle pick now prefers the newest `-rYYYYMMDD` asset with an
  exact-original fallback — verification showed the old `ls | head -n1` picked
  the OLDEST resign (`-` sorts before `.`), the exact OPS-F2 hazard.
- **SEC-F5 canary**: `verify-dual-publish.yml` gains a weekly cron (Mon 09:00
  UTC, after the 03:00 re-sign) asserting live `generated_at` age ≤ 14d;
  schedule-runs only (push-path verifies must not fail on a legitimately old
  catalog).
- **Scheduler alerting = RED run** (OPS-F4 "alert on timeout"): the scheduler
  holds no webhook credentials by design; a bounded-poll timeout or failed
  downstream run fails the scheduler run itself — GitHub's workflow-failure
  notification is the M1 alert channel, with the appliance-side stale alert as
  the runtime backstop.
- **SEC-F7 (owner precondition, activation gate)**: before enabling the weekly
  cron in production, the `v-tag-protection` ruleset MUST gain `creation=true`
  with `bypass_actors` = the Actions bot — tag CREATION becomes load-bearing
  once a tag dispatch is a signing event. Listed in the M1-4 PR body and the
  operator runbook; not enforceable in code from this repo.

### 4.2 M1-4 implementation review (2026-07-10) — fixes folded in

Adversarial review verdict: **ship-with-fixes** — the three BLOCKING controls
(SEC-F1/F2a/F2b) verified correctly built and test-pinned (incl. the
same-version/different-created_at substitution being impossible: deterministic
generator ⇒ byte-identical manifests per version; `fetch-depth:0` fetches all
tags so the latest-tag assert holds for tag-ref checkouts). Accepted findings:

| Finding | Sev | Fix | Enforcement |
| --- | --- | --- | --- |
| SEC-F2b live read went through the CDN, which ignores request `Cache-Control` (the repo's own purge step exists because of that) — a days-stale edge copy could under-report `generated_at` and let an older signed re-sign roll the live pointer back | MED | Binding reads the live index from the R2 ORIGIN via authenticated `s3api get-object`; only a genuine NoSuchKey counts as first-publish, any other read failure fails closed | `TestResignR2PublisherInvariants` (step signature now matches the s3api read) |
| The §10 M1-4 plan row's `(version, generated_at)` appliance ratchet (SEC-F4) was missing — re-signs never bump the version, so the version-only floor was blind to a same-version replay, leaving the SEC-F2b rollback with no appliance backstop | MED (scope) | SHIPPED: `catalogStateFile` gains `highest_accepted_generated_at`; `checkCatalogReplay` refuses equal-version/strictly-older `generated_at` at both the holder gate and the auto-seed read-only gate; equality accepted (restart-reload idempotency — recorded delta from the §10 row's "strictly newer to install" wording); legacy version-only state files check nothing until the first post-upgrade install writes the pair (fail-safe migration) | `TestApply_SameVersionResignReplayRefused` |
| "Reduced path: no build" inaccurate — `test`+`smoke` still ran on resign dispatches | LOW | Both skip tag-ref dispatches now | doc/CI-cost only |
| `dispatch_and_wait` duplicated verbatim in two scheduler steps | LOW | Merged into one step, helper defined once | cosmetic |
| Scheduler run-discovery relies on `gh run list --branch <tag>` matching tag-dispatched runs | LOW (recorded) | Fail-closed either way (no run found ⇒ FATAL timeout); CONFIRM on the first production run — a mismatch breaks the flow loudly, not silently | runbook first-run checklist |
| Inline trailing comments could in principle fake step-locating signatures in the invariant tests | LOW/INFO (accepted residual) | full-line stripping covers the realistic misorder; malicious edits are caught in review | known limitation, recorded |

Post-PR Codex review (P2, both accepted): (a) **same-day retry brick** — the
date-keyed asset/prefix collided with second-granularity `generated_at`, so a
retry after a partial R2 stage hit the immutable-prefix digest guard; fixed by
deriving `RESIGN_NOW` from the DATE ONLY (midnight UTC ⇒ byte-identical
same-day bytes) plus a byte-equal idempotent no-op in the SEC-F2b binding for
full-success retries. (b) **prune-before-upload** stranded the live origins
with no matching release asset on an upload failure; the attach step now
uploads first and prunes after.

## 5. M0-activation regression guards

- **Quoted allow-list token:** SHIPPED (PR #634, `assertEgressAllowListWellFormed`,
  mutation-proven). No further work.
- **Secret-name contract (PR M1-1, small):** extend `TestWorkflowInvariants` to pin
  the publisher’s exact secret/var reference sets: `secrets.{R2_S3_ENDPOINT,
  R2_S3_ACCESS_KEY_ID, R2_S3_SECRET_ACCESS_KEY, R2_BUCKET, CF_ZONE_ID,
  CF_CACHE_PURGE_TOKEN}` and `vars.{R2_PUBLISH_ENABLED, R2_PUBLIC_BASE}` — scan all
  `${{ secrets.* }}`/`${{ vars.* }}` references in `publish-catalog-r2.yml` and
  assert set-equality with the documented contract (drift in either direction
  fails), keeping the runbook table in lock-step.

## 6. PR plan (single-scope each)

| PR | Contents |
|---|---|
| M1-1 | Dual-publish verify job + secret-name-contract invariant |
| M1-2 | Refresh loop (`release_refresh.go`) + config + API/GUI surface + tests |
| M1-3 | Alerts + metrics + status fields + tests |
| M1-4 | Re-sign: scheduler workflow + ci.yml resign path + R2 publisher resign input + workflow-invariant extensions + gate tests |

Order: M1-1 → M1-2 → M1-3 → M1-4 (each from merged main; no stacking).

## 7. Invariants preserved (owner directives)

R2 publish path byte-unchanged except the additive resign input (M1-4); Pages
untouched; fail-closed everywhere; additive migration; all workflows idempotent;
production mutations recoverable (re-sign assets are versioned; live pointer
restorable by re-publish — proven in M0).

## 8. Open questions for design review

1. Slice A placement: job inside `publish-catalog-r2.yml` vs separate workflow
   (workflow_run timing vs permission isolation)?
2. Refresh default interval (6h?) and whether refresh-failure alerts need
   rate-limiting beyond the consecutive-failure threshold.
3. Resign staging prefix format (`<tag>-r<YYYYMMDD>`) — collision/ordering concerns?
   Idempotent same-day re-runs (create-only 412 + digest guard semantics)?
4. Should the weekly re-sign also re-dispatch Pages (recommended) — and does the
   Pages workflow’s newest-asset pick handle multiple `culvert-release-catalog-*`
   assets correctly?
5. `resign_created_at` source: read from the CURRENTLY SERVED index (R2) vs the
   release bundle’s index — which is authoritative for created_at preservation?
6. Does dispatching ci.yml at a tag with `resign=true` interact safely with the
   tag-path guards (`require-gate.sh` asserts on the tagged commit — re-runs should
   still pass) and the docker/auto-tag jobs (must be skipped on resign)?

## 9. Design-review findings & binding resolutions (v2)

Three independent reviews; every BLOCKING/HIGH/MED resolved below. These decisions
override §1–§4 where they differ.

### Slice D (re-sign) — GATED on SEC-F1 + SEC-F2

| Finding | Sev | Binding resolution |
|---|---|---|
| SEC-F1 — resign path signs content from a MUTABLE release asset (keyless signing oracle: attacker with contents:write swaps the bundle, cron signs it) | **BLOCKING** | The ci.yml resign job (1) verifies the downloaded bundle's EXISTING `index.json.sigstore` against the baked root + pinned identity (expiry-tolerant) BEFORE reading any field; (2) takes `version` from `github.ref_name` only; (3) keeps the `cosign verify` of the extracted `list_digest` vs `release_identity.env`. `resign_created_at` and all entry facts come ONLY from the signature-verified release bundle (never the served R2 index — OPS-F6 concurs: origin is untrusted transport). |
| SEC-F2 — old-tag re-sign = unbounded freshness extension / live pin (fresh prefix self-satisfies the digest guard; CI runner floor=0) | **BLOCKING** | (a) latest-tag enforcement INSIDE ci.yml's resign job: `fetch-depth:0`, assert `github.ref_name` == highest `v*` by `sort -V`, fail closed (holds even for old-tag dispatches); (b) publisher-side monotonic binding on the resign input: before promote, fetch LIVE `release-catalog/index.json` and require staged `catalog_version` ≥ live, and on equality identical entries + strictly newer `generated_at` (also closes OPS-F5's auto-tag race). |
| OPS-F1 — bare dispatch-at-tag re-runs the WHOLE pipeline (re-pushes image tags with a new digest; softprops OVERWRITES the original release asset) | HIGH | ci.yml fails fast on `workflow_dispatch` at a tag ref unless `resign == true`; resign uses a DEDICATED `catalog-resign` job with no `needs: [docker]` (no `if:` spaghetti on the release jobs); resign asset name stays distinct so softprops adds, never replaces. |
| OPS-F2 — multi-asset glob: 2nd resign picks the OLDEST resign; 1st resign bricks manual R2 republish of the original tag (glob → resign bundle → immutable-prefix digest-guard abort) | HIGH | Resign job PRUNES the superseded `-r*` asset (release carries exactly original + latest resign); ALL publish/verify paths select assets by EXACT name (`culvert-release-catalog-<tag>.tar.gz` for releases; `<tag>-r<YYYYMMDD>.tar.gz` passed as an explicit dispatch input for resigns). Closes open question 3. |
| OPS-F3 / open Q4 — Pages must be re-dispatched on resign or the dual-publish check goes permanently red | HIGH | Weekly flow re-dispatches Pages (workflow file itself untouched — M3 boundary intact; with pruning, its existing pick sees ≤2 assets). Slice A's expected digest = the LATEST bundle's. |
| OPS-F4 — resign CI completion triggers NEITHER publisher (`workflow_run.event=='push'` gates) | MED | The scheduler owns sequencing: dispatch ci.yml@tag → poll the created run (by ref+event+created_at) to SUCCESS (bounded, fail-closed, alert on timeout) → dispatch R2 (resign input, exact asset name) → dispatch Pages → trigger the Slice A verify. Publishers' workflow_run guards are NOT widened. |
| OPS-F6 — gate resign inputs: parse the bundle in Go; `EXPECT_DIGEST` unset silently disables the digest assert | MED | Extend `resolveGateSpec` to accept a bundle path (Go-side parse of the signature-verified bundle); resign asserts regenerated `list_digest` == source bundle's. |
| SEC-F4 — same-version replay between coexisting re-signs (>= floor is blind to it) | MED | Appliance ratchet extends to `(catalog_version, generated_at)` in `release_catalog_state.json`: equal version requires strictly newer `generated_at` to install. |
| SEC-F5 / OPS-F8 — silent re-sign failure invisible ~150d; "5 retries" is really ~4 | MED | Slice A weekly check also asserts live `generated_at` age ≤ 2× resign cadence (publish-side canary, red + alert on breach). Appliance stale alert stays as backstop. |
| SEC-F7 — v* tag CREATION restriction becomes load-bearing once tag-dispatch is a signing event | LOW | Owner action recorded as an M1-4 activation precondition: add `creation=true` + `bypass_actors` (actions bot) to the `v-tag-protection` ruleset. Documented in the M1-4 PR + runbook; not code. |

### Slices A–C

| Finding | Sev | Binding resolution |
|---|---|---|
| RT-H1 — loop-local failure state diverges from the manual endpoint (missed `recovered`, stale `/api/releases`) | HIGH | Shared `refreshStatus{lastAt,lastOK,lastErr,consecutiveFailures}` on `releaseManager` behind its OWN mutex, updated by one `rm.runRefresh(ctx, trigger)` wrapper used by BOTH the loop and `apiReleaseCatalogRefresh`; alert transitions computed there; stores only the redacted error string. |
| RT-H2 — stale alert re-fires every 6h (engine dedupe is 30s) | HIGH | Once-per-threshold-crossing latch in `refreshStatus` (fire on not-stale→stale transition); latch reset on restart accepted + documented. Refresh-failing alert likewise fires on the ≥N transition only, `recovered` on the first success after (answers open Q2; OPS-F8 concurs). |
| RT-M1 — background-services slice is the wrong home (runs before webhooks + rm exist) | MED | Loop starts from `loadReleaseManagement` (lifecycle ctx plumbed in); resolves the manager at tick time; first tick after one jittered interval (startup auto-seed covers t=0). |
| RT-M2 — "ETag 304 no-op" is false today (new provider per call) | MED | One long-lived `HTTPCatalogProvider` constructed in `loadReleaseManagement`; `rm.refresh` closes over it (real 304s; no per-tick catalog-dir rewrite). |
| RT-M3 — `rm.refresh` discards its context | MED | Thread caller ctx (`context.WithTimeout(ctx, httpCatalogDefaultTimeout)`); loop = `NewTimer` + `select {ctx.Done, timer.C}`, re-jittered per iteration. |
| RT-M4 — single-flight mutex ALREADY exists (`refreshMu` in the closure) | MED | No second mutex; loop just calls the wrapper. Manual endpoint may `TryLock` → "refresh already in progress" (nice-to-have). |
| RT-M5 / open Q6 — config-surface shape | MED | **Minimal-compliant for M1 (amended at M1-2 implementation):** read-once `CULVERT_RELEASE_REFRESH_INTERVAL` **env-only** — narrowed from "+YAML" to match the `CULVERT_RELEASE_*` family precedent exactly (every existing release env has no YAML counterpart; recorded GUI-parity deferral); cadence + shared `last_refresh` surfaced READ-ONLY on `/api/releases` (Release-panel field rides M1-3's status work). No AdminSettings field ⇒ no `configSurfaces` row, no `saveConfigVersion`. |
| RT-L1 — no Prometheus client lib | LOW | Hand-written exposition per metrics.go pattern: two atomic counters for `culvert_release_catalog_refresh_total{result}`; `culvert_release_catalog_expires_in_seconds` computed at scrape time from the holder. |
| RT-L2/L3/L4 | LOW | Gate the loop on `catalogURL != "" && VerifyEnforce`, tolerate `rm == nil` per tick; restart counter-reset documented in §3 + runbook; CP/DP posture: node-local by design for M1 (no ConfigSnapshot sync — keeps the DEBT-006 walls untouched), stated in §2. |
| OPS-F7 / SEC-F6c / open Q1 — Slice A placement | LOW | **Separate `workflow_run` verify workflow** (`verify-dual-publish.yml`): permission isolation (`contents: read`, NO secrets, NO id-token — pinned by an invariant test), scheduler-triggerable on resigns, and keeps `publish-catalog-r2.yml` byte-unchanged until M1-4's additive resign input (resolves the §7 inconsistency). Push-path trigger: workflow_run on the R2 publisher's completion + bounded Pages-lag retry (~10 min); resign-path: scheduler-sequenced, not timer-based. |

### PR plan (v2)

| PR | Contents |
|---|---|
| M1-1 | `verify-dual-publish.yml` (separate workflow) + secret-name-contract invariant + workflow-invariant extensions (verify workflow: no secrets/id-token) |
| M1-2 | Refresh loop (long-lived provider, ctx threading, `runRefresh` wrapper + `refreshStatus`) + config resolver + read-only API/panel surface + tests |
| M1-3 | Alert transitions/latches + metrics + status fields + tests |
| M1-4 | Re-sign: scheduler (poll/sequence) + ci.yml fail-fast + dedicated `catalog-resign` job (verify-before-resign, latest-tag assert, prune, exact names) + R2 resign input (monotonic live binding) + `(version, generated_at)` ratchet + gate resign envs + invariant extensions. **Declared: M1-4 also amends M1-1's verify workflow (resign asset selection + expected-digest definition).** Owner precondition: v* creation restriction (SEC-F7). |

## 10. Enforcement map — every BLOCKING/HIGH finding → permanent mechanism (owner rule)

> Rule: an accepted finding may not exist only as documentation. Each row names the
> mechanical enforcement and the PR that lands it. "Invariant" = a `TestWorkflowInvariants`-
> family assertion proven non-vacuous by mutation; "gate" = a step that turns a run RED.

| Finding | Sev | Permanent enforcement | Lands in |
|---|---|---|---|
| SEC-F1 — resign signing oracle (mutable asset) | BLOCKING | (1) **Go gate** `TestReleaseResignGate`: refuses to build a resign spec unless the source bundle's `index.json.sigstore` verified against the baked root + pinned identity (verify-before-read lives IN the gate binary, not shell); (2) **invariant**: the `catalog-resign` job's verify step precedes the sign step (existence + ordering, mutation-proven); (3) version-from-ref_name asserted in the gate (env `CULVERT_RELEASE_SPEC_VERSION` must equal the dispatch ref tag). | M1-4 |
| SEC-F2a — old-tag re-sign (freshness extension) | BLOCKING | **CI gate step** in `catalog-resign`: `sort -V` latest-tag assert, fail-closed; + **invariant**: the assert step EXISTS in the resign job (a deleted guard fails the test). | M1-4 |
| SEC-F2b / OPS-F5 — publisher must bind re-sign promote to the LIVE catalog (monotonic) | BLOCKING/MED | **Runtime assertion** in the R2 resign path: fetch live index; require staged `catalog_version` ≥ live, equality ⇒ identical entries + strictly newer `generated_at`; + **invariant**: the binding step exists BEFORE promote (ordering-pinned). | M1-4 |
| OPS-F1 — bare dispatch-at-tag re-runs the whole pipeline / overwrites the release asset | HIGH | **CI gate**: ci.yml fail-fast step (dispatch at `refs/tags/*` with `resign != true` ⇒ exit 1) + dedicated `catalog-resign` job (no `needs: [docker]`); + **invariant** on ci.yml: the fail-fast guard exists. | M1-4 |
| OPS-F2 — multi-asset glob pick (bricks original republish; 2nd resign picks oldest) | HIGH | (1) **Invariant** (M1-1): `verify-dual-publish.yml` selects assets by EXACT name — any `culvert-release-catalog-*` glob in it fails the test; (2) **invariant extended** (M1-4): same exact-name rule applied to `publish-catalog-r2.yml` when its resign input lands (the multi-asset hazard cannot exist before M1-4 — no resign assets are ever attached until then); (3) **CI gate step** in `catalog-resign`: prune the superseded `-r*` asset (release carries ≤2 catalog assets) + **invariant** that the prune step exists. | M1-1 + M1-4 |
| OPS-F3 — Pages re-dispatch on resign (else permanent dual-publish red) | HIGH | **CI gate**: `verify-dual-publish.yml` itself is the permanent detector (divergence = RED run — cannot be ignored without deleting the workflow, which D0-style route/count pins would surface); + **invariant** (M1-4): the scheduler contains the Pages dispatch step. | M1-1 + M1-4 |
| RT-H1 — refresh status shared between loop and manual endpoint | HIGH | **Automated test**: manual-endpoint failure advances `consecutiveFailures` and loop success emits `recovered` (unit test over the shared `runRefresh` wrapper; both callers exercised). | M1-2 |
| RT-H2 — stale alert must fire once per threshold crossing | HIGH | **Automated test**: two evaluations inside the stale window emit exactly one `release_catalog_stale`; crossing back + forth re-arms (unit test over the latch). | M1-3 |
| SEC-F4 — same-version replay between re-signs | MED | **Runtime assertion + test**: appliance ratchet extends to `(catalog_version, generated_at)`; unit test proves an equal-version/older-generated_at catalog is refused. | M1-4 |
| SEC-F5 — silent re-sign failure (~150d blind) | MED | **CI gate**: weekly verify asserts live `generated_at` age ≤ 2× resign cadence (RED on breach). | M1-4 |
| SEC-F7 — `v*` tag creation restriction (backstop once tag-dispatch signs) | LOW | **Documented owner prerequisite** (allowed category): ruleset gains `creation=true` + `bypass_actors`(actions bot) BEFORE M1-4 activation; listed in the M1-4 PR body + runbook as a hard precondition. | M1-4 (owner) |
| M1-1 baseline invariants | — | **Invariants** (mutation-proven): secret-name contract set-equality on `publish-catalog-r2.yml` (6 secrets + 2 vars, drift either direction fails); `verify-dual-publish.yml` is credential-free (zero `secrets.*` refs anywhere, no id-token at any level, `contents: read`). | M1-1 |


## 11. M1-2 product revision (owner, 2026-07-10): built-in default catalog origin

A normal customer must not configure `CULVERT_RELEASE_CATALOG_URL`. The appliance
bakes `defaultReleaseCatalogURL = https://catalog.culvertlabs.com/release-catalog`;
the env is an explicit override for air-gap / internal mirrors / staging /
regional distribution. Binding behaviors (all implemented + tested in M1-2):
unset⇒default; override wins; empty/whitespace⇒default; mirror URLs verbatim;
**trust is origin-independent** (verify mode + roots identical either way —
`TestCatalogURLSource_DoesNotAffectTrust`, plus the `TestServedVerify_*` suite as
the byte-level proof); effective origin surfaced read-only on `/api/releases`
(`catalog_origin` host + `catalog_url_source`; full URL only for the public
default — overrides may carry presigned credentials). Override stays read-only
(env) for M1. The refresh loop arms whenever release management is enabled in
enforce mode (the default origin makes `wantSeed` ≡ enforce). **Recorded
constraint:** the SSRF guard still rejects private-IP origins — an internal
mirror needs a publicly-resolving host, or a future explicit allowlist knob
(deferred, security-owner decision).

### 11.1 Security + admin-UX review (2026-07-10) — fixes folded in

An independent two-lens review (security + admin UX) graded the change
**yes-with-fixes**: trust is provably origin-independent (traced + pinned by
`TestCatalogURLSource_DoesNotAffectTrust` and the `TestServedVerify_*` byte-level
suite), but four items shipped before calling the experience done. Each accepted
finding maps to an enforcement mechanism per the §10 rule (no finding lives only
as prose):

| Finding | Severity | Fix | Enforcement |
| --- | --- | --- | --- |
| No trust-safe opt-out of the default fetch (the only silencing paths were firewalling or relaxing `CULVERT_RELEASE_CATALOG_VERIFY`, which weakens trust) | HIGH (sec) | `CULVERT_RELEASE_CATALOG_URL=off/none/disabled` ⇒ no fetch, trust posture unchanged, surfaced as `catalog_url_source:"disabled"` | **Test** `TestResolveCatalogURL_DisableSentinel` (sentinel ⇒ empty URL + disabled source + trust identical to default) |
| Startup seed failure invisible on the API/GUI for up to one refresh interval (~6h) — "hasn't tried" vs "tried and failed" indistinguishable without log access | HIGH (ux) | Fold the startup auto-seed outcome into the shared `refreshStatus` as trigger `"startup"`, immediately after wiring | **Test** `TestLoadReleaseManagement_StartupSeedFailureRecorded` (enforce + SSRF-rejected origin ⇒ `last_refresh` shows startup failure on `/api/releases`) |
| Override URL **path** segment (tokenized mirror secret) leaks to viewers via `last_error` and the audit ring — old redaction stripped only userinfo + query | MED (sec) | `redactSeedError` now collapses the embedded `*url.Error` URL to host-only and strips the configured path | **Test** `TestRedactSeedError_StripsOverridePath` |
| GUI Release panel rendered none of the new fields; refresh-button tooltip still said "configured origin (CULVERT_RELEASE_CATALOG_URL)" (misleading for the default case) | MED (ux) | `renderReleaseOrigin` shows origin + source + cadence + last-refresh outcome; tooltip corrected | GUI-parity convention (`static/index.html`) |
| New on-by-default egress ("phone-home") posture undocumented for operators | MED (sec) | Operator doc section: named host, cadence, override table, disable sentinel | `docs/operator/enterprise-release-catalog-plan.md` §Phase 5 |

**Deferred (recorded, not silently dropped):** (a) `next_refresh_at` and a
structured `last_refresh.error_kind` (transport/verify/reload) — LOW; the loop
timer is decoupled from `LastAt` so a derived next-tick would mislead, and error
classification belongs with M1-3's alerting where it drives latched transitions;
(b) running the startup seed **asynchronously** to remove the blocked-egress boot
delay (up to ~30s on a firewalled default appliance) — MED, deferred because it
reorders the M0 seed-before-publish contract and warrants its own scoped change;
the sync seed is preserved and its outcome is now recorded regardless.
