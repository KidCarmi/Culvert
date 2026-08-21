# Culvert Chaos Engineering Review — 2026-07-26

> **Owner:** Chaos Engineering routine · **Status:** Point-in-time review (repeatable)
> **Method:** Targeted-fix pass against the open-findings register as updated by the
> 2026-07-17 run (`CHAOS-ENGINEERING-REVIEW-2026-07-17.md`, which closed CHAOS-23 and
> promoted CHAOS-10/17 to the top open item). The finding was re-verified live at HEAD
> (`d06ff85`) before any code was written. **Companion change:** one fix ships with
> this review (see "Fixed in this change").

---

## Executive Summary

This run attacked **CHAOS-10/17 — scan-error posture inconsistent (fail-open
holes)**, the top open item since the 2026-07-05 sweep. Re-verification at HEAD
confirmed both halves were still live, and surfaced one aggravating behavior the
register had not recorded:

1. **CHAOS-17 (plain-HTTP body read error → forward unscanned + truncated).** A
   mid-buffer read error in `scanHTTPResponseBody` returned `false`, so
   `handleHTTP` streamed the *remainder* of a body whose already-consumed prefix
   was discarded — the client received unscanned, silently corrupted content.
   The SSL-inspect path had the opposite (correct) posture: `scanReadError`
   fails the exchange (H1 tears the tunnel down, H2 resets the stream).
   **FIXED — fail closed.**

2. **CHAOS-10 (ClamAV engine error mid-request → silent fail-open).** A daemon
   crash mid-stream logged one unthrottled line and fell through to a clean
   verdict — no counter, no alert, opposite of the same function's fail-closed
   *timeout* posture. **Aggravation found this run:** after the error the scan
   fell through to YARA and then **cached `Clean:true` for the content hash** —
   a verdict computed while the AV engine was dark. Because the hash cache is
   shared and TTL-bounded, one crash-window pass admitted that content *by
   hash* for every subsequent request, long after the daemon recovered.
   **MITIGATED — counted + alerted + cache-poisoning closed;** the per-request
   posture deliberately stays fail-open (see decision below).

---

## Fixed in this change

### F1 — Plain-HTTP scan read error fails closed (CHAOS-17) · MED

- **Was (re-verified at HEAD):** `proxy_http.go` `scanHTTPResponseBody` —
  `io.ReadAll` error → `return false` → caller streamed the un-reassembled
  remainder. Fail-open AND corrupting.
- **Fix:** the read-error branch now logs, serves `502 Bad Gateway`, and
  returns `true` (response handled). This is availability-free hardening:
  nothing has been written to the client at that point, and the origin read
  already failed mid-body — the response was doomed; the only question was
  whether the failure would be visible and scanned-or-nothing. Mirrors the
  inspect path's `scanReadError` contract (`proxy_tunnel.go`).
- **Tests:** `proxy_http_scanfail_test.go` —
  `TestScanHTTPResponseBody_ReadErrorFailsClosed` (erroring body → handled +
  502; fails on pre-fix code) and
  `TestScanHTTPResponseBody_CleanBodyReassembled` (clean path still reassembles
  the full body — pins the non-regression side).

### F2 — ClamAV mid-request error: visible + un-poisonable (CHAOS-10) · MED

- **Was (re-verified at HEAD):** `internal/secscan/secscan.go` `scanBodyInner`
  — `clam.Scan` error → log line, fall through to YARA, then
  `cache.Set(hash, Clean:true)`. No counter, no alert; poisoned clean verdict
  served from cache on every later occurrence of the same content.
- **Fix (`internal/secscan/secscan.go`):**
  1. `clamScanError(err)` helper — increments the new `statClamScanError`
     counter and fires a `scan_clam_error` webhook alert through the existing
     WK-10 delivery engine (30s dedup, bounded queue, never blocks the
     producer) — the exact model the remote sidecar's `remoteScanFail` already
     uses.
  2. The clean-verdict cache write is now gated on "ClamAV actually ran":
     a pass where the engine errored is a *partial* scan and is never cached,
     so the next occurrence of the content rescans. Blocked verdicts (from
     YARA on the same pass) still cache; genuinely clean error-free passes
     still cache (pinned by test).
- **Posture decision (recorded):** the per-request outcome stays **fail-open**
  (fall through to YARA, forward if nothing matches). Rationale: (a) parity —
  the remote scan sidecar, the other AV infrastructure-failure path, is
  fail-open-with-alert by design (WK-2), and hard-failing all body traffic on
  a clamd crash with no operator escape hatch is a self-inflicted outage; (b)
  the admin-selectable `scan.on_error = block|allow` from the register is a
  *config surface* — GUI-parity (admin API + UI panel + config-surfaces
  registry rows) makes it a deliberate product change, not a chaos fix. It
  stays open as the CHAOS-10 remainder. What this run removes is the
  *silence* and the *poisoning* — the two properties that made the fail-open
  window unbounded and invisible.
- **Visibility wiring:** `ClamScanError` in `secscan.CounterSnapshot` →
  `stat_clam_scan_error` on `/api/security-scan/status` (local mode) →
  `culvert_clam_scan_errors_total` on `/metrics` → "ClamAV scan errors" tile
  in the Security Scanning panel (warn at ≥1, crit at ≥10, same thresholds as
  the sidecar-fails tile) → `scan_clam_error` in the alerts store's supported
  events.
- **Tests (`internal/secscan/clam_error_test.go`):**
  - `TestClamError_CountedAlertedAndCleanNotCached` — error pass: fail-open
    result, counter +1, exactly one `scan_clam_error` alert, cache MISS for
    the hash.
  - `TestClamError_RecoveredDaemonRescansAndBlocks` — the poisoning
    regression pin: daemon down → pass; daemon recovers and detects → the
    SAME content now blocks (pre-fix: poisoned clean cache admitted it
    forever; `clam.calls` proves the engine was re-consulted).
  - `TestClamClean_VerdictStillCached` — error-free clean verdicts still
    cache (single engine call for a repeat scan).

---

## Failure Scenarios examined (this run)

| Scenario | Behavior after this change |
|---|---|
| Origin RST/timeout mid-body on a scanned plain-HTTP download | 502 to the client, `HTTP scan: body read error … failing closed` log; nothing unscanned forwarded (was: truncated + unscanned stream) |
| clamd crashes mid-INSTREAM | Request falls through to YARA (fail-open, unchanged); counter + deduped `scan_clam_error` webhook fire; verdict not cached |
| clamd crash-window content re-requested after daemon recovery | Rescanned and blocked if malicious (was: served from poisoned clean cache until TTL/restart) |
| clamd flapping under load | One alert per 30s dedup window (WK-10 engine), counter tracks true error volume, panel tile goes yellow/red |
| ClamAV disabled (no clam configured), YARA-only deployment | Byte-identical: `clamDark` never set, clean verdicts cache as before |
| Remote-scan (sidecar) mode | Untouched — already had the counter+alert model this run copied |
| Scan timeout | Untouched — still fail-closed (`statScanTimeout`, cached block) |

## Risk Matrix / Recovery Assessment (updates only)

| Scenario | Before | After |
|---|---|---|
| Plain-HTTP scan read error (CHAOS-17) | ❌ fail-open + truncated body, invisible | ✅ fail-closed 502, logged; recovery automatic (client retries; origin failure was the trigger) |
| ClamAV error mid-request (CHAOS-10) | ❌ silent fail-open + **durable cache poisoning** | ⚠️ fail-open bounded to the outage window, counted + alerted; no durable effect. Remainder: `scan.on_error=block` posture |

## Operational / Security Impact

- **Operational:** zero new configuration. Operators get a Prometheus counter,
  a status-API field, a panel tile, and a webhook alert for a security control
  that could previously go dark with a green dashboard — the review's headline
  "silent fail-open degradation" theme, applied to its last unalerted scan
  path.
- **Security:** the cache-poisoning closure is the substantive win: a
  transient clamd crash can no longer mint durable clean verdicts for
  attacker-supplied content. The CHAOS-17 fix removes a genuine bypass
  primitive (an attacker-adjacent origin that RSTs mid-body used to get its
  prefix bytes delivered unscanned).

## Verification notes (re-checked at HEAD before acting)

- `scanBodyInner` clam-error branch: log-and-continue, then unconditional
  `Clean:true` cache write — poisoning confirmed by reading the code path, then
  pinned by the (initially failing on pre-fix logic) recovery test.
- `scanHTTPResponseBody` readErr branch: `return false` with the prefix
  discarded; `handleHTTP` then `io.Copy`s the remainder — truncation confirmed.
- Inspect-path contrast (`proxy_tunnel.go` `scanReadError`, fail-the-exchange
  contract incl. the H2 empty-200 rationale) re-read to mirror its posture.
- No existing test pinned the old fail-open behaviors (the failure-injection
  plan's T10 listed them as RED-to-document); `TestSecScanDI_ClamErrorFallsThroughToYARA`
  (fall-through itself) still passes unchanged.
- Full `go test ./...` green at the companion commit.

## Open-findings register — status after this run

Statuses relative to the 2026-07-17 table. Findings not listed are unchanged;
the 2026-07-05 review remains the authority for their detailed write-ups.

| ID | Sev | Title | Status |
|---|---|---|---|
| CHAOS-17 | MED | Plain-HTTP body-scan read error fails open + truncates | **FIXED** (this change) — fail-closed 502, mirrors inspect path |
| CHAOS-10 | MED | ClamAV error mid-request fails open silently | **MITIGATED** (this change) — counter + alert + cache-poisoning closed; remainder: admin-selectable `scan.on_error=block` posture (GUI-parity surface, owner decision) |
| CHAOS-05/07 | MED-HIGH | Corrupt state files | FIXED (07-12) — remainder: refuse-to-boot posture decision; lesser stores still silent-reset |
| CHAOS-06 | HIGH | Root-CA load failure → silent fail-open | MITIGATED (07-09); `inspection.required` fail-closed mode still open |
| CHAOS-11 | MED | Upstream-pool all-down fails open to direct | OPEN — **now the top open item** (posture decision required; breaker is dead code, F-09) |
| CHAOS-15/16 | MED | HMAC rotation no grace window; auth negative caching | OPEN |
| CHAOS-18 | MED | DP snapshot applied before local store inits | OPEN |
| CHAOS-08 | MED | No semantic floor on snapshots | OPEN (policy decision required) |
| CHAOS-28 | LOW-MED | Failed rotation-triggered renewal not retried until the 30-day window | OPEN |
| CHAOS-13/14 | MED-LOW | No jitter on legacy feed tickers; no gRPC keepalives on CP/DP channel | OPEN |
| CHAOS-24/25/26 | LOW | Release-platform delta lows | OPEN |
| CHAOS-27 | LOW-MED | Double write-block escapes the idle reaper; config-rollback swallows Save errors | OPEN |
| CHAOS-19/20/21 | LOW-MED | Audit-write counter; feed staleness metrics; CA-rotation window race | OPEN |

## Suggested next-run targets (priority order)

1. **CHAOS-11 / F-09** — upstream-pool `fail_mode: open|closed` + pool-empty
   alert; the circuit breaker's `RecordFailure` is dead code (never trips on
   real request failures) — wire it through the transport path.
2. **CHAOS-10 remainder** — the `scan.on_error` posture config (admin API + UI
   + config-surfaces rows), now that the observability substrate exists.
3. **CHAOS-27 / F-12** — `applyConfigBackup` swallows every `.Save()` error →
   200 on partial-durability rollback (T4 in the failure-injection plan).
4. **CHAOS-16 / F-11** — stop caching LDAP/OIDC *error-path* negatives (denies
   valid creds for minutes past IdP recovery); bound post-dial LDAP ops.
5. **CHAOS-13/14** — jitter the legacy feed tickers; gRPC keepalives on the
   CP/DP channel (half-open-TCP class).
6. Deep-dive passes never yet done: maintenance-agent host-ops surface (F-05
   persisted op journal), `update_cluster.go` failure paths (RISK-011), SAML
   metadata refresh.

## Residual risk

- The ClamAV-error path remains fail-open per request until the posture config
  ships — but the window is now alarmed (webhook within one dedup interval),
  measured (counter), and non-durable (no cached verdicts). An operator who
  needs hard fail-closed today can deploy the remote scan sidecar and firewall
  it, or accept the documented posture.
- The `scan_clam_error` alert reuses the WK-10 dedup keyed on event+detail:
  distinct error strings within 30s each deliver once. A pathological daemon
  emitting unique error text per request could still fan out one webhook per
  30s per unique string — bounded by the store's 500-cap queue and 10-slot
  delivery semaphore (accepted; same exposure as `scan_svc_down`).
- `statClamScanError` is process-local and volatile like every other scan
  counter (resets on restart; per-node in a cluster) — consistent with the
  existing counter family, and the Prometheus rate() idiom is restart-tolerant.
