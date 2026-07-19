# Culvert Chaos Engineering Review — 2026-07-19

> **Owner:** Chaos Engineering routine · **Status:** Point-in-time review (repeatable)
> **Method:** Targeted-fix pass against the open-findings register as updated by the
> 2026-07-17 run (`CHAOS-ENGINEERING-REVIEW-2026-07-17.md`, which closed CHAOS-23 and
> promoted CHAOS-10/17 to the top open item). Both findings were re-verified live at
> HEAD (`6349722`) before any code was written. **Companion change:** two fixes ship
> with this review (see "Fixed in this change").

---

## Executive Summary

This run closed **CHAOS-10 and CHAOS-17 — the scan-error fail-open holes**, open since
the 2026-07-05 review and the register's #1 item after the 07-17 run:

- **CHAOS-10** — a ClamAV engine **error** mid-request (daemon crash mid-INSTREAM,
  socket reset) logged one line and fell through to a clean verdict. Re-verification at
  HEAD found it is **worse than registered**: the degraded run's clean verdict was
  **cached by SHA-256**, so any content that flowed during a clamd outage stayed
  "clean" for the full hash-cache TTL — the daemon recovering did *not* close the
  exposure for already-seen content. No counter, no alert; an operator watching the
  dashboard saw green while AV was dark. Meanwhile the *timeout* path in the same file
  fails closed and the *remote-scanner* path fails open **with** an alert and a counter
  — three postures for the same class of infrastructure failure.
- **CHAOS-17** — a body **read error** while buffering a plain-HTTP response for
  scanning returned "clean" and fell through. Because the buffered prefix was
  discarded, the client received a **truncated body missing its first bytes** with a
  200 status — corrupted content that had also bypassed ClamAV/YARA/DPI entirely. The
  SSL-inspect path fails the same event closed (`scanReadError` → tear down the
  exchange, deliberately hardened after the H2 silent-empty-200 bug); the plain-HTTP
  path was the last fail-open copy of that contract.

Posture decision (documented, deliberate): the ClamAV **error** path stays
**fail-open for availability** — matching the remote-scanner model
(`internal/secscan/remote.go`, the register's named template) rather than the timeout
path's fail-closed — but the failure is now *visible* (counter + webhook alert) and
*non-sticky* (clean verdicts from degraded runs are never cached). The read-error path
is *fail-closed* because there the alternative is not "content flows unscanned" but
"corrupted content flows unscanned" — availability is not being purchased, so nothing
justifies the open posture.

---

## Fixed in this change

### F1 — ClamAV engine error: visible, non-sticky fail-open (CHAOS-10) · MED-HIGH

- **Was (re-verified at HEAD before writing code):** `scanBodyInner`
  (`internal/secscan/secscan.go`) handled `clam.Scan` error with a single
  `obs.Printf` and continued; the fall-through then executed
  `ss.cache.Set(hash, ScanCacheResult{Clean: true})` — the **poisoned-cache**
  aggravation: content scanned during an outage was trusted after recovery until
  cache TTL/eviction. No counter existed (`CounterSnapshot` had `ScanTimeout`,
  `RemoteScanFail` — nothing for a local engine error); no alert event existed.
- **Fix (`internal/secscan/secscan.go`):**
  1. New package counter `statClamError` + `ClamError` in `CounterSnapshot` /
     `Counters()` — the same export path the existing scan counters use
     (Prometheus, OTLP, SSE, status APIs).
  2. On `clam.Scan` error: increment the counter, fire `scan_clam_error` through
     the `alerts` seam (async, engine-side 30s dedup on event+detail — the
     `remoteScanFail` pattern), log with the explicit posture in the message
     ("content forwarded without AV verdict (fail-open, not cached)"), and mark
     the run **degraded**.
  3. A degraded run **never caches a clean verdict** — the next request for the
     same content rescans, so recovery of the daemon closes the exposure
     immediately. Positive verdicts (a YARA hit on the same run) are still
     cached: a detection is trustworthy regardless of what ClamAV did.
- **Surfaces:** `culvert_clamav_scan_errors_total` on `/metrics` (next to
  `culvert_clamav_blocked_total`); `stat_clam_errors` in the
  `/api/scanning/status` map; `scan_clam_error` documented in the alerts event
  registry (`internal/alerts/store.go`). No new config option → no GUI-parity
  obligation (posture is a documented constant, as with the remote scanner).
- **Tests (`internal/secscan/secscan_chaos10_test.go`):**
  - `TestSecScanDI_ClamErrorDoesNotCacheClean` — the poisoned-cache regression
    pin: clamd errors on scan 1 (fail-open nil, counter moves), recovers with a
    detection on scan 2 of the *same bytes* → must block (pre-fix: cached clean
    served, engine never reran); scan 3 is cache-served (positive verdicts do
    cache).
  - `TestSecScanDI_ClamErrorStillCachesYARABlock` — degraded-run YARA hits
    remain cacheable (block verdicts are never weakened by this change).
  - `TestSecScanDI_ClamErrorFiresAlert` — `scan_clam_error` reaches the alerts
    sink with source + detail.
  - Existing `TestSecScanDI_ClamErrorFallsThroughToYARA` still green — the
    fall-through-to-YARA behavior is intentionally preserved.

### F2 — Plain-HTTP scan-buffer read error fails closed (CHAOS-17) · MED

- **Was (re-verified at HEAD):** `scanHTTPResponseBody` (`proxy_http.go`) on
  `io.ReadAll` error returned `false` without reassembling `resp.Body` — the
  caller streamed the *remainder* of a body whose already-consumed prefix was
  discarded: truncated/corrupted payload, 200 status, zero scanning. The
  inspect path classifies the same event `scanReadError` and fails the exchange
  (`proxy_tunnel.go`), a contract that file documents as deliberately
  fail-closed ("never let this surface as a clean, empty success").
- **Fix (`proxy_http.go`):** the read-error branch now logs (host sanitized,
  CWE-117) and answers **502 Bad Gateway**, returning `true` (handled).
  Nothing has been written to the client at that point (the scan pipeline runs
  before `copyHeaders`/`WriteHeader`), so the 502 is always deliverable — the
  exact analogue of the inspect path's exchange-fail. Function doc updated to
  state the fail-closed contract.
- **Tests (`proxy_http_chaos17_test.go`):**
  - `TestScanHTTPResponseBody_ReadErrorFailsClosed` — mid-stream transport
    error while buffering → handled=true + 502 (pre-fix: handled=false, the
    truncated-stream fall-through).
  - `TestScanHTTPResponseBody_CleanBodyStillStreams` — the clean path still
    reassembles and streams the body unhandled (no availability regression).

---

## Failure Scenarios examined (this run)

| Scenario | Behavior after this change |
|---|---|
| clamd crashes mid-INSTREAM under load | Content forwards (availability preserved), `culvert_clamav_scan_errors_total` moves, `scan_clam_error` webhook fires (30s dedup), verdict NOT cached |
| clamd recovers after an outage | First re-request of any content seen during the outage is fully rescanned — the outage window closes retroactively for cached content (pre-fix: cache TTL kept it "clean") |
| Malware fetched twice, once during outage once after | Blocked on the post-recovery fetch (regression-pinned) |
| YARA detects during a clamd outage | Blocked and cached, exactly as before |
| clamd flapping (error storms) | One alert per 30s per distinct error detail (engine-side dedup); counter tracks true magnitude |
| Origin RST/GOAWAY mid-body on plain HTTP with scanning active | Client gets 502 (pre-fix: truncated unscanned body with 200) |
| Origin RST mid-body on inspected HTTPS | Unchanged — already fail-closed (`scanReadError`) |
| Oversized body (> MaxBytes) on plain HTTP | Unchanged — skip-scan-and-stream (`scan_skipped` path, deliberate) |
| Scan timeout | Unchanged — fail-closed block, `scan_timeout` alert |
| Remote scan sidecar down | Unchanged — fail-open + `scan_svc_down` alert + counter (the model F1 now matches) |

## Risk Matrix / Recovery Assessment (updates only)

| Scenario | Before | After |
|---|---|---|
| ClamAV engine error mid-request (CHAOS-10) | ❌ silent fail-open + clean verdict cached (outage outlives itself) | ✅ fail-open with counter + alert; uncached → automatic retroactive recovery when clamd returns |
| Plain-HTTP scan-buffer read error (CHAOS-17) | ❌ truncated unscanned 200 | ✅ 502, logged; posture identical to inspect path |

## Operational / Security Impact

- **Operational:** zero new configuration. Two new read-only surfaces
  (`culvert_clamav_scan_errors_total`, `stat_clam_errors`) and one new webhook
  event (`scan_clam_error`) an admin can subscribe to alongside `scan_svc_down`
  / `scan_timeout`. Deployments with a healthy clamd see byte-identical
  behavior.
- **Security:** closes the register's last silent scan fail-open. The residual
  (documented) exposure is the fail-open window itself while clamd is down —
  now bounded to *first-sight* content during the outage (nothing persists past
  recovery) and always visible. Clients can no longer receive corrupted,
  unscanned bodies on the plain-HTTP path.
- **Compatibility note (F2):** an origin that resets mid-body on plain HTTP now
  yields a 502 instead of a truncated 200. This is the same trade the inspect
  path made deliberately; a truncated download was never usable, but any
  operator diagnosing new 502s will find the `HTTP scan: body read error`
  log line naming the host.

## Verification notes (re-checked at HEAD before acting)

- `scanBodyInner` error path enumeration at HEAD: single `obs.Printf`, no
  counter/alert callers; clean-verdict `cache.Set` ran unconditionally on the
  fall-through — the poisoned-cache aggravation was live, not historical.
- `scanHTTPResponseBody` read-error branch: `return false` with no body
  reassembly (the reassembly `io.MultiReader` runs only on the clean path) —
  the truncation side effect was confirmed by reading the caller
  (`handleHTTP` streams `resp.Body` directly after the `false` return).
- The inspect path (`scanInspectBody` → `scanReadError` → `exDeliverError`)
  and the H1/H2 handling were read to confirm the contract being mirrored.
- Suite: full `go test ./...` green including the five new regression tests;
  `gofmt` clean; no new config surface, so no `configSurfaces`/uiRoutes rows.

## Open-findings register — status after this run

Statuses relative to the 2026-07-17 table. Findings not listed are unchanged;
the 2026-07-05 review remains the authority for their detailed write-ups.

| ID | Sev | Title | Status |
|---|---|---|---|
| CHAOS-10/17 | MED | Scan-error posture inconsistent (fail-open holes) | **FIXED** (this change) — ClamAV errors visible + uncached; plain-HTTP read error fail-closed. Residual: posture is a documented constant, not admin-selectable (matches remote-scanner precedent; revisit only if an operator asks for `fail_closed`) |
| CHAOS-05/07 | MED-HIGH | Corrupt state files | FIXED (07-12) — remainder: refuse-to-boot posture decision; lesser stores still silent-reset |
| CHAOS-06 | HIGH | Root-CA load failure → silent fail-open | MITIGATED (07-09); `inspection.required` fail-closed mode still open — **now the top open item** |
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

1. **CHAOS-06 remainder** — `inspection.required` fail-closed mode (posture
   decision + config surface + GUI parity; the 07-09 mitigation added the alert
   and readiness signal, the enforcement mode is the missing half).
2. **CHAOS-05/07 remainder** — extend `quarantineCorruptStateFile` to the
   lesser stores (mechanical); refuse-to-boot posture decision (owner).
3. **CHAOS-28** — retry the rotation-triggered renewal before the 30-day window.
4. **CHAOS-27** — double write-block idle-reaper escape.
5. **CHAOS-13/14** — jitter the legacy feed tickers; gRPC keepalives on the
   CP/DP channel (half-open-TCP class).
6. Deep-dive passes never yet done: maintenance-agent host-ops surface,
   `update_cluster.go` failure paths (RISK-011), SAML metadata refresh.

## Residual risk

- The fail-open window during a clamd outage remains by design (availability
  posture, matching the remote scanner); the mitigation is the alert + counter
  + non-sticky cache, not elimination. A deployment that wants fail-closed AV
  can front the proxy with the remote scan sidecar in a fail-closed wrapper or
  request the posture toggle (recorded above as the deliberate deferral).
- The `scan_clam_error` alert inherits the engine-side 30s event+detail dedup:
  a flapping daemon emitting *distinct* error strings can still fire more than
  twice a minute; the webhook queue is bounded (500, drop-on-full) so this
  cannot back-pressure the request path.
- F2 changes user-visible behavior for mid-transfer origin failures on plain
  HTTP (502 instead of truncated 200). Judged strictly better — the truncated
  body was corrupt AND unscanned — but it is a behavior change worth one line
  in release notes.
