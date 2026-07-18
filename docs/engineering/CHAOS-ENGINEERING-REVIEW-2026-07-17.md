# Culvert Chaos Engineering Review — 2026-07-17

> **Owner:** Chaos Engineering routine · **Status:** Point-in-time review (repeatable)
> **Method:** Targeted-fix pass against the open-findings register as updated by the
> 2026-07-16 run B (`CHAOS-ENGINEERING-REVIEW-2026-07-16B.md`, which closed CHAOS-09
> and promoted CHAOS-23 to the top open item). The finding was re-verified live at
> HEAD (`061b518`) before any code was written. **Companion change:** one fix ships
> with this review (see "Fixed in this change").

---

## Executive Summary

This run closed **CHAOS-23 — freshness watchdog inert for disabled-fetch/permissive
deployments**, open since the 2026-07-10 release-platform review:

The 180-day catalog-freshness watchdog (`release_catalog_stale`, M1-3) was driven
*only* by the periodic refresh loop, and that loop starts only when a catalog origin
is configured in enforce mode (`wantSeed && refreshInterval > 0`,
`release_wiring.go`). The deployments that arguably need the watchdog **most** —
air-gapped appliances with outbound fetch explicitly disabled
(`CULVERT_RELEASE_CATALOG_URL=off`, `catalog_url_source=disabled`), where the
operator hand-installs the signed catalog and there is no re-sign pipeline quietly
keeping it fresh — evaluated staleness only at boot and on manual refresh. A
set-and-forget disabled-fetch appliance crossing the 30-day threshold at runtime
never fired `release_catalog_stale` until somebody restarted it: the exact silent
failure the watchdog exists to prevent. Break-glass permissive/disabled verify
modes had the same blind spot for expiry-carrying catalogs.

The fix gives the watchdog its own runtime driver when — and only when — the
refresh loop does not run: a standalone, detection-only ticker at the same
resolved cadence (`CULVERT_RELEASE_REFRESH_INTERVAL`, default 6h ±10% jitter)
that calls the existing `evaluateCatalogFreshness()` per tick. No fetch, no
reload, no trust logic, no new config surface: one holder read + RT-H2 latch
check per tick. Exactly one watchdog driver exists per process.

---

## Fixed in this change

### F1 — Freshness watchdog inert without the refresh loop (CHAOS-23) · MED

- **Was (re-verified at HEAD before writing code):**
  - `loadReleaseManagement` started `runCatalogRefreshLoop` only under
    `wantSeed && cfg.refreshInterval > 0` where
    `wantSeed = catalogURL != "" && verifyMode == VerifyEnforce`; no other
    runtime caller of `evaluateCatalogFreshness()` existed (callers: startup
    wiring once, `runRefresh` — loop + manual admin refresh only).
  - So for `catalog_url_source=disabled` (and permissive/disabled verify), the
    stale evaluation ran at boot and then never again. The boot-after-lapse and
    startup-stale alerts (07-xx M1-3 work) cover an appliance that *restarts*;
    a long-running one crossed the threshold silently. The scrape-time gauge
    (`culvert_release_catalog_expires_in_seconds`) kept exporting — but only an
    operator who built a Prometheus alert on it would notice, and the M1-3
    design point is that the *appliance* alerts.
- **Fix (`release_refresh.go`, `release_wiring.go`):**
  1. **`runCatalogStaleWatchdogLoop`** — same loop skeleton as the refresh loop
     (jittered timer, ctx-cancelled, per-tick panic containment carried over
     from CHAOS-R1 — in these deployments this loop is the SOLE runtime stale
     driver, so a panic must cost one tick, not the watchdog for the process
     lifetime). Each tick calls `evaluateCatalogFreshness()` on the
     late-resolved manager; nil manager and non-positive interval are
     tolerated (mirrors the refresh loop's contract).
  2. **`startReleaseDetectionLoop`** (extracted from the tail of
     `loadReleaseManagement`, keeping it under the cyclop budget) — starts
     exactly ONE driver: the refresh loop when `wantSeed` (unchanged
     behavior, `rm.refreshInterval` still set only on that path so
     `/api/releases` never advertises a fetch cadence that does not exist),
     else the standalone watchdog + one startup log line naming the
     deployment shape (`catalog_url_source`, `verify`) and cadence.
- **Cadence choice:** the same resolved `CULVERT_RELEASE_REFRESH_INTERVAL`
  (default 6h, min-clamped 1m, jittered). A 30-day threshold checked every 6h
  loses nothing, the existing fail-safe resolver semantics (typo ⇒ default,
  never disabled) carry over for free, and no new knob is introduced (the
  GUI-parity rule stays untriggered — this is not a config option).
- **Tests (`release_stale_watchdog_test.go`):**
  - `TestStaleWatchdogLoop_TicksLatchesAndStops` — per-tick evaluation, RT-H2
    latch holds across ticks (exactly one alert), prompt ctx-cancel exit.
  - `TestStaleWatchdogLoop_SurvivesTickPanic` — CHAOS-R1 contract: a panicking
    tick costs one tick; a later tick still fires (also proves the recovered
    panic cannot strand `statusMu`).
  - `TestStaleWatchdogLoop_ZeroIntervalAndNilManager` — bare configs start
    nothing; nil manager per tick tolerated.
  - `TestStaleWatchdog_WiringRunsWithoutRefreshLoop` — the regression pin
    through the REAL `loadReleaseManagement` with a signed 10-days-left
    catalog and `catalog_url_source=disabled`: boot fires once (pre-fix
    behavior ends there), latch re-armed, the runtime driver crosses it again
    — deleting the watchdog branch fails this test. Also pins
    `rm.refreshInterval == 0` (no phantom fetch cadence on `/api/releases`)
    and bounds the wiring goroutine to the test via the `appLifecycleCtx`
    swap precedent (`saas_feed_lifecycle_test.go`).
  - Uses a mutex-guarded alert recorder (the watchdog fires from its own
    goroutine; the existing unsynchronized `alertRecorder` would race under
    `-race`).
- **Accepted residuals:**
  (a) The watchdog rides the refresh-interval env var, so an operator who sets
  a long interval (say `24h`) also slows stale detection to that cadence —
  irrelevant against a 30-day threshold; the resolver's 1m clamp and
  typo⇒default fail-safe bound the other direction.
  (b) In break-glass `VerifyDisabled`/`VerifyPermissive` with a catalog that
  carries no `expires_at` (legacy/unsigned), the tick is a no-op by design
  (`evaluateCatalogFreshness` skips zero expiry — staleness of nothing is
  meaningless; the break-glass modes are explicit, logged, and temporary by
  contract).
  (c) Watchdog liveness itself is not surfaced on `/api/releases` (only the
  startup log line). The alert is the deliverable; adding an API field for
  "the thing that fires alerts is running" was judged surface growth without
  an operator decision it enables. Revisit if a deployment ever reports a
  wedged watchdog.

---

## Failure Scenarios examined (this run)

| Scenario | Behavior after this change |
|---|---|
| Air-gapped appliance (`CULVERT_RELEASE_CATALOG_URL=off`), operator-installed catalog crosses 30-day threshold at runtime | `release_catalog_stale` fires within one watchdog tick (≤ ~6.6h) of the crossing; latched once per crossing (RT-H2) |
| Same appliance, catalog fully lapses while running | Watchdog keeps evaluating the RAW published catalog (impl-review MED-1 posture) — the stale alert fired before lapse; gauge goes negative; API reports `expired` |
| Break-glass permissive deployment with an expiry-carrying catalog | Same runtime stale detection as enforce (detection never required trust) |
| Break-glass with a no-expiry catalog | Tick is a documented no-op (residual (b)) |
| Panic inside a watchdog tick | One tick lost; loop continues (CHAOS-R1 contract, pinned by test) |
| Normal enforce+origin deployment | Byte-identical: refresh loop path unchanged, watchdog never starts (single-driver invariant) |
| Shutdown | Watchdog parents on the app lifecycle context; exits with every other background store |

## Risk Matrix / Recovery Assessment (updates only)

| Scenario | Before | After |
|---|---|---|
| Disabled-fetch appliance, catalog staleness crossing at runtime (CHAOS-23) | ❌ silent until restart/manual refresh (alert path dead; only the Prometheus gauge moved) | ✅ alerts within one tick; once per crossing; recovery = operator installs a fresh signed catalog (manual by design — fetch is off) |
| Watchdog-driver panic | n/a (no driver) | ✅ one lost tick, loop survives (tested) |

## Operational / Security Impact

- **Operational:** zero new configuration. Disabled-fetch and break-glass
  deployments now get the same alert-driven staleness signal enforce+origin
  deployments always had. One new startup log line names the active driver.
- **Security:** positive, indirect — the freshness watchdog is the backstop
  that tells an operator their trust-anchored catalog is about to lapse
  (after which Release Management goes `available:false` and day-2 updates
  stop). Making it live for air-gapped postures shrinks the window in which a
  fleet quietly loses its update path. No new inputs, no new surface, no
  trust-logic change; the watchdog is read-only over already-verified state.

## Verification notes (re-checked at HEAD before acting)

- `evaluateCatalogFreshness` caller enumeration at HEAD: `runRefresh`
  (release_api.go:121), startup wiring (release_wiring.go:478), tests — no
  other runtime driver existed; the finding was still real.
- `resolveRefreshInterval` can never return ≤ 0 in production (unset/typo ⇒
  6h default, sub-minute ⇒ 1m clamp), so the standalone watchdog is
  unconditionally live for every real deployment where the refresh loop is
  not; the ≤ 0 guard exists for bare test-constructed configs only.
- Single-driver invariant: `startReleaseDetectionLoop` is the only caller of
  both loop starters; `wantSeed` picks exactly one branch.
- Suite: full `go test ./...` green; the new tests plus the whole
  `release_*` family pass under `-race -count=2`.

## Open-findings register — status after this run

Statuses relative to the 2026-07-16 run B table. Findings not listed are
unchanged; the 2026-07-05 review remains the authority for their detailed
write-ups.

| ID | Sev | Title | Status |
|---|---|---|---|
| CHAOS-23 | MED | Freshness watchdog inert for disabled-fetch/permissive deployments | **FIXED** (this change) — standalone detection-only ticker; residuals (a)–(c) documented above |
| CHAOS-10/17 | MED | Scan-error posture inconsistent (fail-open holes) | OPEN — **now the top open item** |
| CHAOS-05/07 | MED-HIGH | Corrupt state files | FIXED (07-12) — remainder: refuse-to-boot posture decision; lesser stores still silent-reset |
| CHAOS-06 | HIGH | Root-CA load failure → silent fail-open | MITIGATED (07-09); `inspection.required` fail-closed mode still open |
| CHAOS-11 | MED | Upstream-pool all-down fails open to direct | OPEN (posture decision required) |
| CHAOS-15/16 | MED | HMAC rotation no grace window; auth negative caching | OPEN |
| CHAOS-18 | MED | DP snapshot applied before local store inits | OPEN |
| CHAOS-08 | MED | No semantic floor on snapshots | OPEN (policy decision required) |
| CHAOS-28 | LOW-MED | Failed rotation-triggered renewal not retried until the 30-day window | OPEN |
| CHAOS-13/14 | MED-LOW | No jitter on legacy feed tickers; no gRPC keepalives on CP/DP channel | OPEN |
| CHAOS-24/25/26 | LOW | Release-platform delta lows | OPEN |
| CHAOS-27 | LOW-MED | Double write-block escapes the idle reaper | OPEN |
| CHAOS-19/20/21 | LOW-MED | Audit-write counter; feed staleness metrics; CA-rotation window race | OPEN |

## Suggested next-run targets (priority order)

1. **CHAOS-10/17** — `scan.on_error` posture config + `culvert_scan_errors_total`;
   align the plain-HTTP body-read-error path with the fail-closed inspect path.
2. **CHAOS-05/07 remainder** — refuse-to-boot posture decision (owner); extend
   `quarantineCorruptStateFile` to the lesser stores (mechanical).
3. **CHAOS-28** — retry the rotation-triggered renewal before the 30-day window
   (currently a failed rotation renewal on a fresh cert is silent until the window).
4. **CHAOS-27** — config-rollback partial-disk-failure surfacing
   (`applyConfigBackup` swallows `Save()` errors; T4 in the failure-injection plan).
5. **CHAOS-13/14** — jitter the legacy feed tickers; gRPC keepalives on the CP/DP
   channel (half-open-TCP class).
6. Deep-dive passes never yet done: maintenance-agent host-ops surface,
   `update_cluster.go` failure paths (RISK-011), SAML metadata refresh.

## Residual risk

- The watchdog and the refresh loop can never run together
  (`startReleaseDetectionLoop` picks one branch), so double evaluation — while
  harmless under the RT-H2 latch — is structurally excluded rather than merely
  latched away.
- The new goroutine is one timer parked at ~6h for the deployments it serves;
  it shares the lifecycle context every background store uses and is inert
  (nil-manager no-op) if Release Management is later torn down in tests.
- No existing test asserted the absence of a second background loop; the new
  wiring test pins the `refreshInterval == 0` API invariant from the watchdog
  side so the two paths cannot silently merge in a refactor.
