# Culvert Chaos Engineering Review — 2026-07-16 (run B)

> **Owner:** Chaos Engineering routine · **Status:** Point-in-time review (repeatable)
> **Method:** Targeted-fix pass against the open-findings register as updated by the
> same-day earlier run (PR #737, `CHAOS-ENGINEERING-REVIEW-2026-07-16.md`, which closed
> the CHAOS-12 remainder and promoted CHAOS-09 to the top open item). The finding was
> re-verified live at HEAD (`d5585d5`) before any code was written. **Companion
> change:** one fix ships with this review (see "Fixed in this change").

---

## Executive Summary

This run closed **CHAOS-09 — readiness blind to data-plane dependency health**, open
since the 2026-07-05 baseline review and the #1 ranked item after PR #737:

A data-plane node that lost its Control Plane keeps serving traffic on its
last-known-good config — the *correct* availability posture (HA-1) — but `/ready`
stayed green the whole time, so nothing downstream (load balancer, uptime monitor,
fleet dashboard scraping probes) could tell a healthy DP from one that had been
enforcing hours-old policy with a certificate quietly running out its renewal window.
The failure compounds: the CP outage that makes the config stale is the *same* outage
that makes cert renewal fail, and at cert expiry the node hard-drops off the cluster
(the brick the 07-11/07-16 CHAOS-12 fixes made recoverable — but recovery still needs
a human, and the human was never signaled at the probe layer).

The fix adds two DP-only rows to `/ready` and an opt-in strict verdict:

- **`cp_poll`** — fails once CP polling has been continuously failing for longer than
  a 5-minute grace window (10 poll intervals — a single missed 30s poll or a CP
  rolling restart must not flip fleet-wide probe rows).
- **`node_cert`** — fails while the node certificate is inside its renewal window (or
  expired) **and** renewal is failing; shows current days-left and the last RPC error.
- **`/ready?strict=1`** — opt-in probe URL on which **any** failing row (including the
  previously report-only `ca`, `policy_loaded`, `state_file_*` rows) gates the verdict
  to 503.

The **default verdict is deliberately unchanged** (report-only rows, the CHAOS-06
posture): gating the default `/ready` on CP-poll failure would let a CP outage eject
the **entire DP fleet** from the load balancer at once — turning a control-plane
outage into a data-plane outage, the exact inversion of Culvert's
availability-under-partition design. Operators who *want* dependency-degraded nodes
ejected point their LB probe at the strict URL; that choice is per-probe and explicit.

---

## Fixed in this change

### F1 — Readiness blind to CP-poll failure / imminent cert expiry (CHAOS-09) · MED

- **Was (re-verified at HEAD before writing code):**
  - `handleReady` (`healthcheck.go`) gated only on `session_secret` +
    `config_snapshot_validator`; `dpControlPlanePollFailing`
    (`controlplane_snapshot.go:302`) and DP cert expiry were consulted nowhere in the
    probe path. `/api/diagnostics` had a `dp_last_known_good_config` row
    (`diagnostics.go:179`) — but that surface is admin-authenticated JSON, not what an
    LB or uptime monitor consumes.
  - The CHAOS-12 machinery (07-11) tracks renewal failure only as a **latched alert**
    (`dpCertExpiryAlert`, fires once per escalation) — the right shape for paging, the
    wrong shape for a probe row that must reflect *current* state.
- **Fix (`readyz_dp_health.go`, hooks in `controlplane_client.go`,
  `dp_enrollment.go`, `healthcheck.go`):**
  1. **Failing-since tracking** — `dpMarkCPPollFailing()` stamps the healthy→failing
     transition time (CAS, first failure only); `dpMarkCPPollHealthy()` clears it.
     The poll loop's four `dpControlPlanePollFailing.Store` sites now route through
     these helpers; the flag itself is unchanged for existing readers
     (`diagnostics.go`, tests).
  2. **Probe-facing renewal state** — `recordDPCertRenewalFailure(days, err)` is
     written on every failed in-window renewal attempt (inside
     `alertDPCertRenewalFailure`, *before* the alert latch, so the row always carries
     current days-left + last error even when the alert is latched silent);
     `resetDPCertExpiryAlert` (called by `renewDPCert` on success) clears it. A
     rotation-triggered failure on a still-fresh cert stays log-only (no expiry clock
     — the CHAOS-12 contract), so the row stays ok there too.
  3. **Rows** — `appendDPHealthChecks` contributes `cp_poll` + `node_cert` **only
     when `audit.DPMode()`**: every CP/standalone probe consumer is byte-identical.
     Within the grace window (or when the failing flag has no transition stamp — a
     state only legacy direct writers can produce) `cp_poll` stays ok with an
     explanatory detail.
  4. **Strict verdict** — `/ready?strict=1` (or `strict=true`) scans all rows and
     503s on any `fail`. Nil-request tolerant (several existing tests call
     `handleReady(rr, nil)`).
- **Grace-window choice:** 5 minutes = 10 poll intervals. The DP's own failover logic
  waits 3 consecutive failures before trying a peer CP; a rolling CP update (drain +
  swap) completes well inside the window. The value is a named constant
  (`dpCPPollFailGrace`) with the rationale in-line.
- **Tests:** `readyz_dp_health_test.go` —
  `TestHandleReady_NonDPMode_NoDPRows` (rows absent outside DP mode even with the
  flag stuck on — CP/standalone unchanged);
  `TestHandleReady_CPPollFailingSustained_ReportOnlyFailRow` (fail row + default
  verdict provably still 200/ready);
  `TestHandleReady_CPPollFailingWithinGrace_OKRow` (grace window + stampless-flag
  fallback);
  `TestHandleReady_CPPollRecovers` (healthy clears row + detail; re-failure
  re-stamps);
  `TestHandleReady_NodeCertRenewalFailing_FailRowAndRecovery` (drives the REAL
  CHAOS-12 failure path with a PEM fixture: in-window fail row with days+error,
  expired-cert wording, cleared by the same reset the renewal success path calls);
  `TestHandleReady_RenewalFailureOutsideWindow_NoRow` (log-only contract preserved);
  `TestHandleReady_StrictGatesFailRows` (strict 503s on the same state the default
  probe reports 200 for; all-ok strict is 200).
  The pre-existing `/ready` suite (`misc_test.go`, `rootca_failure_visibility_test.go`,
  `state_corruption_test.go`) passes unmodified — the default posture is pinned from
  both sides.
- **Accepted residuals:**
  (a) **Strict mode gates *all* fail rows**, including `policy_loaded` on a fresh
  install (no rules yet) and a CP-wide `state_file_*` quarantine. That is the
  documented meaning of strict — "any failing check" — chosen over a bespoke
  row-subset because a probe contract an operator can state in one sentence is worth
  more than per-row tunability. An operator whose fleet boots empty-policy should not
  point the LB at strict until initial config lands.
  (b) **Strict + sustained CP outage ejects strict-probed DPs by design.** That is
  the operator's explicit opt-in; the default probe keeps the fleet serving.
  (c) The transition stamp is in-memory — a DP restart during a CP outage restarts
  the grace window (first poll failure re-stamps ~30s after boot; the row degrades
  ~5.5 min post-restart instead of immediately). Not worth persisting.
  (d) `/healthz` (liveness) is untouched — a degraded-dependency DP is alive by
  definition; conflating the two is how fleets get restart-looped.

---

## Failure Scenarios examined (this run)

| Scenario | Behavior after this change |
|---|---|
| CP unreachable > 5 min (partition/outage), DP serving last-known-good | Default `/ready`: 200 + `cp_poll:fail` row (visible to any probe scraper); strict probe: 503 → LB ejects if the operator chose that |
| Single missed poll / CP rolling restart (< 5 min) | `cp_poll` stays ok (grace) — no fleet-wide probe flap |
| CP outage spans renewal window; cert at 3 days | `node_cert:fail` with days-left + last RPC error, refreshed every 6h attempt; escalating `cert_expiry` alerts (07-11) still page |
| Cert renewal recovers (CP back) | `renewDPCert` success → latch reset → both probe rows recover on the same poll/renewal cycle that restored service |
| Rotation-triggered renewal failure, cert fresh | Log-only as before; `node_cert` ok (no expiry clock running) |
| CP or standalone node (not DP) | Probe output byte-identical — rows never appear |
| LB probes `/ready?strict=1` fleet-wide during CP outage | All strict-probed DPs eject after grace — documented opt-in consequence, not the default |

## Risk Matrix / Recovery Assessment (updates only)

| Scenario | Before | After |
|---|---|---|
| Degraded DP behind an LB (CHAOS-09 / F-08) | ❌ `/ready` green until hard failure; LB never ejects; no probe-layer signal at all | ✅ visible on the default probe (report-only rows); ejectable via opt-in strict probe; recovery automatic on CP/renewal recovery |
| CP outage → fleet ejection risk | n/a (nothing gated) | ✅ structurally impossible on the default probe; strict is per-probe opt-in |

## Operational / Security Impact

- **Operational:** monitors and dashboards that already scrape `/ready` JSON gain the
  two DP rows with zero config. The strict URL gives LB-level ejection semantics
  without a config flag, per probe target — a fleet can even mix postures (strict on
  the edge LB, default on the uptime monitor).
- **Security:** none negative — no new inputs are trusted (the query parameter only
  *narrows* the verdict from 200 to 503; an attacker who can hit the proxy port can
  learn dependency state, but `/ready` already exposed subsystem rows — `ca`,
  `clamav`, `state_file_*` — on the same unauthenticated surface, a recorded posture).
  Positive: a stale-policy DP (enforcing an hours-old allowlist/revocation view) is
  now flagged at the probe layer, shrinking the window in which that security
  degradation is invisible.

## Verification notes (re-checked at HEAD before acting)

- `dpControlPlanePollFailing` writer enumeration: exactly the four `Store` sites in
  `fetchAndApply` (all now via helpers) — `diagnostics.go:196` and the two test files
  only read/restore it. The bare-flag-no-stamp state remains reachable only by tests
  writing the atomic directly; the probe treats it as not-sustained (fail-safe
  against probe flap, covered by test).
- `resetDPCertExpiryAlert` caller enumeration: `renewDPCert` success only — so the
  probe row's lifecycle is exactly "failing attempt sets, successful renewal clears".
- `handleReady` callers: proxy-port mux (`main.go:886`) passes the live request;
  tests pass `nil` (guarded) — the signature change from `_` to `r` compiles both.
- `/ready` is on the proxy port's plain handler switch, NOT the admin-UI mux — no
  `uiRoutes` metadata entry required (C1 parity untouched, verified against
  `ui_routes_meta.go` scope).
- Suite: full `go test ./...` green; readiness/DP-cluster tests green with the new
  rows; existing `/ready` tests pass unmodified.

## Open-findings register — status after this run

Statuses relative to PR #737's 2026-07-16 table. Findings not listed are unchanged;
the 2026-07-05 review remains the authority for their detailed write-ups.

| ID | Sev | Title | Status |
|---|---|---|---|
| CHAOS-09 | MED | Readiness blind to CP-poll failure / cert expiry | **FIXED** (this change) — default report-only + opt-in `?strict=1`; residuals (a)–(d) documented above |
| CHAOS-23 | MED | Freshness watchdog inert for disabled-fetch/permissive deployments | OPEN — **now the top open item** |
| CHAOS-05/07 | MED-HIGH | Corrupt state files | FIXED (07-12) — remainder: refuse-to-boot posture decision; lesser stores still silent-reset |
| CHAOS-06 | HIGH | Root-CA load failure → silent fail-open | MITIGATED (07-09); `inspection.required` fail-closed mode still open |
| CHAOS-10/17 | MED | Scan-error posture inconsistent (fail-open holes) | OPEN |
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

1. **CHAOS-23** — decouple `evaluateCatalogFreshness()` from the fetch loop so
   disabled-fetch/permissive deployments still get the 180-day staleness watchdog.
2. **CHAOS-10/17** — `scan.on_error` posture config + `culvert_scan_errors_total`;
   align the plain-HTTP body-read-error path with the fail-closed inspect path.
3. **CHAOS-05/07 remainder** — refuse-to-boot posture decision (owner); extend
   `quarantineCorruptStateFile` to the lesser stores (mechanical).
4. **CHAOS-28** — retry the rotation-triggered renewal before the 30-day window
   (currently a failed rotation renewal on a fresh cert is silent until the window).
5. **CHAOS-27** — config-rollback partial-disk-failure surfacing
   (`applyConfigBackup` swallows `Save()` errors; T4 in the failure-injection plan).
6. Deep-dive passes never yet done: maintenance-agent host-ops surface,
   `update_cluster.go` failure paths (RISK-011), SAML metadata refresh.

## Residual risk

- The new rows are additive JSON keys; every existing `/ready` assertion in the suite
  is substring-based and DP-mode-gated rows never render outside DP mode, so no
  consumer of the current schema can break.
- The strict path only ever *narrows* (200 → 503); it cannot mask a failure the
  default verdict would have caught (`allOK` is only ever set false, never reset).
- `recordDPCertRenewalFailure` and the alert latch share one call site and one reset
  — they cannot drift apart silently; the test drives both through the real
  `alertDPCertRenewalFailure`/`resetDPCertExpiryAlert` pair rather than the setters.
- Probe state is process-local and volatile by design (mirrors
  `dpControlPlanePollFailing` itself); the only cost is the grace-window restart
  noted in residual (c).
