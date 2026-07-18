# Culvert Chaos Engineering Review — 2026-07-18

> **Owner:** Chaos Engineering routine · **Status:** Point-in-time review (repeatable)
> **Method:** Targeted-fix pass against the open-findings register from the 2026-07-17
> review (`CHAOS-ENGINEERING-REVIEW-2026-07-17.md`), acting on its #1 ranked next-run
> target. The finding was re-verified live at HEAD (`800e4c7`) before any code was
> written. **Companion change:** one fix ships with this review (see "Fixed in this
> change").

---

## Executive Summary

This run closed **CHAOS-10/17 — the inconsistent scan-failure posture — the #1
ranked open item after the 07-17 run**. The scanning pipeline had three
fail-open holes that contradicted its own fail-closed timeout path, and one of
them was worse than the register recorded:

1. **ClamAV daemon error mid-stream** (`internal/secscan/secscan.go`) logged and
   fell through to a clean verdict — and then **cached that verdict as clean**,
   so content that slipped past a crashed daemon stayed "clean" for the cache
   TTL even after the daemon recovered (poisoned-clean cache; not in the
   original write-up).
2. **Remote scan sidecar failure** (`internal/secscan/remote.go`) returned nil
   on all five failure paths — documented fail-open. The sidecar exists for
   process isolation against scanner crashes (catastrophic regex backtracking),
   which is precisely an attacker-inducible event: crash the sidecar, fetch the
   payload unscanned while it restarts.
3. **Plain-HTTP mid-body read error** (`proxy_http.go`) returned "not blocked"
   and streamed the truncated prefix as a cacheable 200 — unscanned content
   delivered, corrupt payload cacheable downstream, no signal anywhere — while
   the SSL-inspect path had an explicit `scanReadError` fail-the-exchange
   contract for the same event.

The fix is **one documented posture** for scanner-infrastructure failure:
`scan_on_error` = `fail_closed` (default) | `fail_open_with_alert`, mirroring
the YARA `on_timeout`/`on_saturation` precedent exactly (same vocabulary, same
secure default, same admin-tunable escape hatch, same D-sec exclusion from the
rollback surface). A real engine verdict still wins — on ClamAV error the
remaining engines run first and a YARA block is returned (and cached) as before;
only a no-verdict outcome is posture-decided, and **verdicts produced under a
failed scanner are never cached in either direction**. Every failure increments
`culvert_scan_errors_total` and fires a `scan_error` / `scan_svc_down` alert.
The read-error path is posture-independent: the content itself is gone, so the
exchange fails with a 502 exactly like the inspect path.

---

## Fixed in this change

### F1 — Scan-failure posture inconsistent: three silent fail-open holes (CHAOS-10/17) · MED

- **Was (re-verified at HEAD before writing code):**
  - `scanBodyInner`: ClamAV `Scan()` error → log line only, continue, and
    `cache.Set(clean)` at the end (secscan.go:508 + :527) — the poisoned-clean
    cache. Scan **timeout** blocked fail-closed (`:490-494`), so a *hung*
    daemon blocked everything while a *crashed* daemon passed everything.
  - `RemoteScanner.ScanBody`: five `return nil // fail-open` paths (request
    build, transport, non-200, response read, response parse), counter + alert
    but no block, no posture.
  - `scanHTTPResponseBody`: `readErr != nil → return false` (proxy_http.go:179)
    — caller streamed the partially-consumed body as a 200. The inspect path's
    `scanReadError` contract (proxy_tunnel.go:995, :1067-1074) explicitly names
    this class ("an origin reset mid-buffer became a cacheable success") but
    only covered decrypted tunnels.
- **Fix:**
  1. **Posture** (`internal/secscan`): `GetOnScanError`/`SetOnScanError`
     (atomic; `""` ⇒ `fail_closed`). ClamAV-error and all five sidecar-failure
     paths route through it. Fail-closed returns
     `Result{Source:"scan_error"}`; fail-open returns nil. Either way the
     event increments `statScanError` and fires the alert.
  2. **Engine ordering preserved**: on ClamAV error the YARA engine still runs
     first — a real verdict beats the generic error block, is cached, and the
     pre-existing `TestSecScanDI_ClamErrorFallsThroughToYARA` passes
     unmodified.
  3. **No caching under failure**: neither the fail-open "clean" nor the
     fail-closed error block is cached — a transient daemon failure can
     neither poison the cache with a false clean nor pin a hash as blocked
     after recovery. Next request re-consults the engine (self-healing).
  4. **Read-error alignment** (`proxy_http.go`): mid-body read error → counter +
     log + `502 Bad Gateway`, return blocked. Nothing had been written to the
     client at that point (verified: header copy happens after the scan call),
     so the 502 is clean. Posture-independent by design: the posture governs
     "scanner broken, content available"; a read error means the content
     itself is unavailable — same split the inspect path makes.
  5. **Full GUI parity** (per the project rule): `GET/PUT
     /api/security-scan/settings` (viewer/admin; audited; `adminSettingsSave`;
     deliberately NOT `saveConfigVersion` — the yara_* D-sec precedent that
     rollback must never un-harden a scanner posture), uiRoutes metadata +
     route-count locks 180→181, "Scanner Failure Posture" section in the
     Security Scanning panel with a fail-open warning banner (mirrors the YARA
     card), scan-errors stat tile, `scan_on_error` + `stat_scan_error` on the
     status API (local and remote mode), support-bundle scan section, and a
     `scan_error_posture` diagnostics WARN when fail-open is active.
  6. **Persistence**: `scan_on_error` in admin_settings.json (no sentinel —
     empty=default; invalid persisted values refused on load, keeping the
     fail-closed default), declared in the `configSurfaces` registry
     (AdminDurable-only, off rollback/export/CP→DP like the yara_* rows).
  7. **Observability**: `culvert_scan_errors_total` (+ `culvert_scan_timeouts_total`,
     `culvert_scan_skipped_total`, which existed only in the JSON status API).
     Webhook modal gains `scan_error` — and closes a pre-existing parity gap:
     `scan_timeout`, `scan_skipped`, `scan_svc_down`, `yara_degraded` have
     been firing since Tier 1.2/2.2 but were absent from the exact-name event
     list, so GUI-managed webhooks could never subscribe to them.
- **Behavior change (deliberate, documented):** a deployment whose configured
  ClamAV daemon or scan sidecar is down now **blocks scannable bodies by
  default** instead of silently passing them. This is the same posture the
  scan-timeout path has always had (a hung daemon already blocked everything),
  the same default YARA chose for timeout/saturation, and the Zero-Trust
  default-deny stance of the rest of the gateway. Operators who prefer
  availability flip `fail_open_with_alert` in the GUI — and now get a counter,
  an alert, and a diagnostics WARN instead of silence.
- **Tests:** `internal/secscan/secscan_onerror_test.go` (default blocks +
  never cached + counter; fail-open allows + never caches clean + re-scan;
  daemon recovery restores the real verdict; YARA verdict beats error block
  and caches; remote posture both ways), `proxy_http_scan_readerror_test.go`
  (502 + truncated prefix never reaches the client + counter; clean-body
  guard), `scan_settings_test.go` (API defaults / RBAC / validation /
  persistence round-trip incl. pre-feature file and hand-edited invalid
  value), `scan_svc_test.go::TestRemoteScanner_ScanBody_UnreachablePosture`
  (updated from the legacy fail-open pin — the one test that pinned the
  retired behavior).
- **Accepted residuals:**
  (a) **Per-request error logging is not rate-limited** while a daemon is down
  (one line per scanned request). The alert engine dedups (`dedupTTL` 30s), so
  webhook spam is bounded; log-volume hardening left open (register note).
  (b) The **inspect-path read error** (`scanReadError`) does not increment
  `statScanError` — it predates this change, already fails closed, and
  conflating upstream transport failures with scanner failures in one metric
  would blur the signal. Only the plain-HTTP read error counts (it had no
  signal at all before).
  (c) **DPI engine errors** are out of scope: the pure-Go regex DPI path has
  its own timeout/saturation posture (YARA vars) and no daemon to crash.
  (d) `scan_svc_down` keeps its historical alert name for sidecar failures
  (dashboards may filter on it); only the in-process ClamAV error uses the new
  `scan_error` name. Both are posture-stamped in the alert detail.

---

## Failure Scenarios examined (this run)

| Scenario | Behavior after this change |
|---|---|
| ClamAV daemon crashes mid-INSTREAM | Default: content blocked (`scan_error`), alert fired, counter++, verdict not cached; next request re-scans (self-heals on daemon recovery) |
| ClamAV down at startup (configured address, refused) | Every scannable body blocked by default until daemon returns — consistent with the hung-daemon (timeout) posture; fail-open opt-out available in GUI |
| Attacker crashes scan sidecar (regex backtracking), fetches malware during restart | Blocked by default (was: silent pass). Fail-open deployments get counter + `scan_svc_down` alert + diagnostics WARN |
| Malicious content scanned during daemon outage, daemon recovers, same content re-requested | Re-scanned and blocked (was: served from poisoned-clean cache until TTL) |
| Origin RST mid-body on plain-HTTP download | 502 to the client (was: truncated 200, unscanned, cacheable downstream) |
| YARA matches content while ClamAV is erroring | YARA block returned and cached — real verdicts unaffected by the failed engine |
| Operator flips fail_open_with_alert | Logged + audited (`security.scan_settings` diff), persisted, diagnostics WARN active, warning banner in GUI |
| Config rollback after tightening the posture | Posture untouched — off the rollback surface by design (yara_* precedent) |

## Risk Matrix / Recovery Assessment (updates only)

| Scenario | Before | After |
|---|---|---|
| ClamAV error mid-request | ❌ silent fail-open + clean verdict cached (durable bypass until TTL) | ✅ posture-governed (default block), never cached, counter + alert |
| Scan sidecar down | ❌ documented fail-open, counter+alert only | ✅ posture-governed (default block), same signals |
| Plain-HTTP mid-body read error | ❌ truncated 200, unscanned, silent | ✅ 502, counter, log; parity with inspect path |
| Scanner-degradation alert subscribability | ❌ scan_timeout/skipped/svc_down/yara_degraded missing from webhook modal | ✅ listed (exact-name filter class) + new scan_error |

## Operational / Security Impact

- **Operational:** one new admin control with a secure default; zero new
  config for deployments that never touch it. Monitoring gains
  `culvert_scan_errors_total` (plus the timeout/skipped counters that were
  JSON-only), a diagnostics posture row, and five newly subscribable alert
  events. The default change is visible, not silent: blocks carry
  `Source: scan_error` with the daemon error in the reason, and the status
  API/panel show the posture.
- **Security:** closes the last scanner fail-open holes. An attacker can no
  longer convert a scanner crash (inducible via malformed content or sidecar
  regex backtracking) into an unscanned window, and can no longer launder a
  payload into the clean-cache during an outage. Defense-in-depth unchanged
  elsewhere: timeout stays unconditionally fail-closed; YARA posture vars
  untouched.

## Verification notes (re-checked at HEAD before acting)

- Register status confirmed against the 07-17 table (`CHAOS-10/17` = top open
  item); code re-read at HEAD: the error branch at secscan.go:507 fell through
  to the unconditional `cache.Set(clean)` at :527 — the poisoned-clean cache is
  a finding upgrade over the 07-05 write-up.
- `scanHTTPResponseBody` caller order verified (proxy_http.go:111-118): the
  scan runs before `copyHeaders`/`WriteHeader`, so the 502 cannot follow
  written headers.
- One existing test pinned the retired fail-open contract
  (`TestRemoteScanner_ScanBody_FailOpen`) — updated to pin the posture both
  ways; `TestSecScanDI_ClamErrorFallsThroughToYARA` (engine-ordering) passes
  unmodified, proving real verdicts are unaffected.
- Suite: full `go test ./...` green; `-race -count=2 -shuffle=on` on
  `internal/secscan` green; race on the touched main-package tests green;
  `golangci-lint --new-from-rev` clean for all new lines (2 remaining findings
  are in files merged via #855/#856, untouched here).
- Route locks: 180→181 in both C1 and D0; C1/C1.5/C2 parity suites green.

## Open-findings register — status after this run

Statuses relative to the 2026-07-17 table. Findings not listed are unchanged;
the 2026-07-05 review remains the authority for their detailed write-ups.

| ID | Sev | Title | Status |
|---|---|---|---|
| CHAOS-10/17 | MED | Scan-error posture inconsistent (fail-open holes) | **FIXED** (this change) — residuals (a)–(d) documented above |
| CHAOS-05/07 | MED-HIGH | Corrupt state files | FIXED (07-12) — remainder: refuse-to-boot posture decision; lesser stores still silent-reset |
| CHAOS-06 | HIGH | Root-CA load failure → silent fail-open | MITIGATED (07-09); `inspection.required` fail-closed mode still open — **now the top open item** |
| CHAOS-11 | MED | Upstream-pool all-down fails open to direct | OPEN (posture decision required; natural follow-up — same fail-open class as this run, `scan_on_error` is the template) |
| CHAOS-15/16 | MED | HMAC rotation no grace window; auth negative caching | OPEN |
| CHAOS-18 | MED | DP snapshot applied before local store inits | OPEN |
| CHAOS-08 | MED | No semantic floor on snapshots | OPEN (policy decision required) |
| CHAOS-28 | LOW-MED | Failed rotation-triggered renewal not retried until the 30-day window | OPEN |
| CHAOS-13/14 | MED-LOW | No jitter on legacy feed tickers; no gRPC keepalives on CP/DP channel | OPEN |
| CHAOS-24/25/26 | LOW | Release-platform delta lows | OPEN |
| CHAOS-27 | LOW-MED | Double write-block escapes the idle reaper | OPEN |
| CHAOS-19/20/21 | LOW-MED | Audit-write counter; feed staleness metrics; CA-rotation window race | OPEN |

## Suggested next-run targets (priority order)

1. **CHAOS-11** — upstream-pool all-down currently falls back to DIRECT egress
   (`internal/upstream/upstream.go` `ProxyFunc` nil ⇒ direct). Same silent
   fail-open class as this run; `scan_on_error` is the design template
   (posture + counter + alert + GUI). Also close the CONNECT/SOCKS5
   pool-bypass gap noted in the 07-05 write-up.
2. **CHAOS-06 remainder** — `inspection.required` fail-closed mode for CA load
   failure (posture decision; the visibility half shipped 07-09).
3. **CHAOS-05/07 remainder** — refuse-to-boot posture decision (owner); extend
   `quarantineCorruptStateFile` to the lesser stores (mechanical).
4. **CHAOS-28** — retry the rotation-triggered renewal before the 30-day window.
5. **CHAOS-13/14** — jitter the legacy feed tickers; gRPC keepalives on the
   CP/DP channel (half-open-TCP class).
6. Deep-dive passes never yet done: maintenance-agent host-ops surface,
   `update_cluster.go` failure paths (RISK-011), SAML metadata refresh.

## Residual risk

- The posture gate sits strictly inside the previously-degrading branches
  (ClamAV error / sidecar failure / read error); the clean, blocked, timeout,
  cache-hit, exclusion, and size-skip paths are byte-identical — pinned by the
  pre-existing secscan/proxy tests passing unmodified.
- Fail-closed on a down scanner trades availability for containment by
  default. The blast radius is bounded to *scannable* bodies (hosts on the
  scan exclusion list, oversize responses, and non-buffered content types are
  unaffected), the GUI opt-out is one click, and the diagnostics WARN +
  alerts make either posture visible. This is the same trade the scan-timeout
  path has enforced since Zero-Trust hardening.
- The alert ride the existing webhook engine (dedup, retry, SSRF-guarded
  delivery) — no new delivery plumbing.
