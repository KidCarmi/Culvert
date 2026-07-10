# Culvert Chaos Engineering Review — 2026-07-10

> **Owner:** Chaos Engineering routine · **Status:** Point-in-time review (repeatable)
> **Method:** Delta pass over the tree at `8e88a40` against the open-findings register from
> the 2026-07-09 review (`CHAOS-ENGINEERING-REVIEW-2026-07-09.md`), plus a full failure-mode
> scan of the 58 commits merged since (dominated by release-platform M1: production catalog
> refresh loop, detection/canary/alerting, built-in default origin, legacy-fallback gate).
> Every finding acted on was re-verified live at HEAD before any code was written.
> **Companion change:** two fixes ship with this review (see "Fixed in this change").

---

## Executive Summary

This run closed **CHAOS-03 — the top open finding from the last two reviews**: no raw tunnel
relay (CONNECT bypass, WebSocket, SOCKS5, SSL-inspect non-TLS fallback, inspect WS-upgrade)
armed any deadline once streaming began, so a half-open peer (ACKs keepalives, never sends,
never FINs) pinned 2 goroutines + 2 FDs + a pooled 128 KB buffer **forever**. A flood of such
tunnels exhausts an in-line appliance with zero log signal. All five relay paths are now
idle-bounded through one shared helper, with regression tests for the reap, the
keep-alive-via-one-direction case, byte-accounting under deadline pops, and unchanged
graceful-EOF teardown.

The delta scan of the release-platform M1 window found the new trust plumbing **strongly
fail-closed** (dial-time SSRF guard, bounded bodies, two-phase validators, clean lock
hierarchy, atomic persistence — five POSITIVE findings below) but flagged that the new
refresh loop — the **sole runtime driver of both catalog refresh and the 180-day freshness
watchdog** — ran its tick body with no panic recovery: one panic anywhere in the
fetch/verify/reload path would silently kill refresh *and* stale-alerting until restart.
That is fixed this run (CHAOS-22), with a panic-injection regression test.

**Fixed in this change (with regression tests):**

1. **CHAOS-03 (HIGH)** — idle deadline on all raw tunnel relays. Half-open peers are now
   reaped after `tunnelIdleTimeout` (1 h) of silence in **both** directions; active tunnels
   — including one-way-active ones — are provably never reaped.
2. **CHAOS-22 (MED, new this run)** — the catalog refresh loop now recover-guards each tick,
   so a panic costs one tick instead of the freshness watchdog for the process lifetime.

**Top remaining risks (re-ranked):** CHAOS-12 (DP cert renewal inert until restart; expiry
during CP outage bricks the node), CHAOS-05/07 (corrupt `ui_users.json` / `cluster.json`
silently reset to empty, revoked certs revalidate), CHAOS-23 (freshness watchdog inert for
disabled-fetch/permissive deployments — boot-only evaluation), CHAOS-06 remainder
(`inspection.required` fail-closed mode).

---

## Fixed in this change

### F1 — No idle/half-open deadline on any raw relay (CHAOS-03) · HIGH

- **Was:** all five raw-relay paths ran `io.Copy`/`io.CopyBuffer` with no deadline of any
  kind: `bidiRelayCounted` (CONNECT bypass `proxy_tunnel.go` + WebSocket), the SSL-inspect
  non-TLS fallback and the inspect WS-upgrade inline relays (`proxy_tunnel.go`), and
  `socks5Relay` (`socks5.go`). net/http clears all conn deadlines on `Hijack()`, and both
  tunnel dialers set none, so nothing bounded a tunnel's lifetime. TCP keepalive does not
  help against the attack case — a peer that ACKs but never sends application bytes. Each
  such tunnel held 2 goroutines + 2 FDs (+ its conn-limiter slot, post-CHAOS-02) forever;
  `drainActiveTunnels` waits on CONNECT tunnels at shutdown, so leaked tunnels also extend
  the drain to its ceiling. Squid-class proxies reap idle tunnels by default; Culvert never
  did.
- **Fix:** one shared helper, `idleCopyCounted` (`proxy_tunnel.go`), now does every raw
  relay's copy. Design points, each load-bearing:
  - **Deadlines around `io.CopyBuffer`, not a reader wrapper.** The CONNECT-bypass hot path
    relays TCP↔TCP, where `CopyBuffer` takes the `ReaderFrom`/`WriterTo` kernel-splice fast
    path; wrapping the source reader would silently disable zero-copy for the majority of
    proxied bytes. Arming a read deadline on the source conn and resuming after a pop keeps
    splice intact.
  - **Read deadlines only.** Read-deadline timeouts are resumable on both `*net.TCPConn`
    and `*tls.Conn`; a *write* timeout corrupts TLS state permanently. The inspect-path
    relays run over `tls.Conn`, so the mechanism never arms write deadlines.
  - **Shared per-tunnel activity stamp, armed at half the window.** Both directions share
    one `atomic.Int64` last-activity stamp; a deadline pop re-arms and resumes unless the
    stamp is a full `tunnelIdleTimeout` stale. The stamp only refreshes when a copy call
    *returns* (a busy copy runs without returning), so deadlines are armed at
    `tunnelIdleTimeout/2`: an active direction refreshes the stamp at worst every
    half-window, giving the silent direction's staleness check a half-window scheduling
    margin — it can never reap a tunnel whose other direction is alive, even when both
    deadlines pop near-simultaneously. (The naive arm-at-full-window design has a real
    race here; the test suite pins the safe behavior.)
  - **Hard close of BOTH conns on idle, not CloseWrite.** Idle means both directions were
    silent, and the peer relay goroutine may be blocked in a deadline-less `Write` (a
    receiver that ACKs but never reads fills the TCP window) — only a close unblocks it.
    Without this, the write-blocked variant of the leak would survive the read-side fix,
    and `bidiRelayCounted`'s wait-for-both would pin the handler goroutine anyway.
  - **Conservative 1 h default.** Legitimate idle-but-alive tunnels (SSH, IMAP IDLE,
    WebSocket ping/pong) all move application bytes well inside an hour; only dead or
    abusive tunnels are reaped. Reap latency is 1–2× the window. `tunnelIdleTimeout` is a
    package var so tests shorten it; making it admin-configurable carries the GUI-parity
    obligation (config + API + UI panel) and is a **recorded deferral**, mirroring the
    M1-3 threshold-constants precedent.
  - SOCKS5's relay moves from bare `io.Copy` onto the shared pooled-buffer helper, making
    the CLAUDE.md "all relays use relayBufPool" claim true for the first time.
- **Tests:** `proxy_tunnel_idle_test.go` — half-open tunnel reaped within a bounded
  multiple of the window (pre-fix: blocks forever); one-direction traffic keeps the silent
  direction alive across many windows AND byte accounting is exact across deadline pops;
  graceful-EOF teardown with a long window completes promptly with exact counts over real
  TCP conns (CloseWrite + splice path); idle SOCKS5 relay reaped.
- **Accepted residuals:** (a) reap latency up to 2× the window (deliberate — avoids false
  positives); (b) idle reaps emit a log line but no dedicated metric/counter (the
  `TUNNEL_CLOSED` accounting entry carries host/bytes/duration); (c) `recordActiveConn`
  drain accounting still covers only CONNECT tunnels (PX-8, unchanged); (d) no *global*
  connection ceiling (CHAOS-02 residual, unchanged).

### F2 — Catalog refresh loop has no panic containment (CHAOS-22) · MED, new this run

- **Was:** `runCatalogRefreshLoop` (`release_refresh.go`, new in M1-2) ran
  `rm.runRefresh → rm.refresh → auto-seed + holder.Reload` bare in its tick. The loop is
  the **only** runtime driver of `evaluateCatalogFreshness()` (M1-3's stale watchdog runs
  inside `runRefresh`), so a single panic anywhere in the fetch/verify/reload path killed
  catalog refresh AND the 180-day staleness backstop for the process lifetime — silently
  (the goroutine dies; nothing observes loop liveness). This is the WK-8
  background-worker-panic class from the 2026-07-04 review applied to the newest worker;
  new code should meet the bar even while the codebase-wide `safeGo` supervisor remains
  open.
- **Fix:** each tick body is extracted into `refreshLoopTick` with a `recover()` guard: a
  panic is logged and costs exactly one tick — the existing catalog is untouched (the
  auto-seed path only swaps on full success) and the next tick runs normally.
  `runRefresh`'s lock releases are deferred, so recovery cannot strand
  `refreshRunMu`/`statusMu`.
- **Tests:** `TestRunCatalogRefreshLoop_SurvivesTickPanic` (`release_refresh_test.go`) —
  tick 1 panics; the loop must keep ticking (≥3 calls), the post-panic tick must still fold
  into the shared status (also proving no stranded lock — a stuck mutex would deadlock the
  later ticks), and the loop must still stop on context cancellation.

---

## Delta scan — release-platform M1 window (`209fb02..8e88a40`, 58 commits)

New findings are registered with fresh IDs (CHAOS-22 was fixed above).

| ID | Sev | Finding | Evidence |
|---|---|---|---|
| CHAOS-22 | MED | Refresh-loop tick had no panic recovery; one panic killed refresh + freshness watchdog until restart | **FIXED** (this change) |
| CHAOS-23 | MED | Runtime stale watchdog is **inert when outbound fetch is disabled or permissive**: the loop only starts when `catalogURL != "" && verifyMode == VerifyEnforce` (`release_wiring.go`), so a `catalog_url_source=disabled` appliance (local operator-managed catalog) evaluates staleness only at boot and on manual refresh. A set-and-forget disabled-fetch appliance crossing the 30-day threshold at runtime never fires `release_catalog_stale` until a restart. Remediation: drive `evaluateCatalogFreshness()` from a lightweight always-on ticker, or document the coupling. | `release_wiring.go` loop-start gate; `release_alerts.go` |
| CHAOS-24 | LOW | Runtime stale/expiry evaluation uses raw wall clock with no skew tolerance (`evalStale`, `isExpiredNow`); a backward clock jump can re-arm the stale latch and mask staleness. Serving stays fail-closed either way (`GetCatalog` hides an expired catalog) — detection-fidelity only. The load-time gate *does* apply `catalogClockSkew`; the runtime watchdog should too. | `release_alerts.go`, `release_catalog_holder.go` |
| CHAOS-25 | LOW | Failing-latch fires once per crossing and never re-alerts during a prolonged origin outage; restart re-fires once. Both documented as accepted in `release_alerts.go` — recorded here as residual, optional escalating re-alert. | `release_alerts.go` |
| CHAOS-26 | LOW | `stageVerified` bounds each fetched file but not the **number** of manifests / aggregate staged bytes. Mitigated: the index signature is verified before enumeration, so only a trusted signer can inflate the list. Optional belt-and-suspenders cap. | `release_catalog_http.go` |

**Positive findings (the new code already fails safely — cite-worthy models):**

- **Outbound fetch posture:** inline preflight (`url.Parse` + scheme + `isPrivateHost`)
  *plus* dial-time guard on the resolved IP (closing the DNS-rebind TOCTOU window),
  re-guarded redirects capped at 5 hops, 30 s client / 10 s dial / 10 s TLS timeouts,
  every body bounded via `io.LimitReader`, zero retries (the 6 h jittered cadence is the
  only repeat — no retry storm). `release_catalog_http.go`.
- **Fail-closed refresh with self-heal:** a rejected catalog leaves disk untouched AND
  invalidates conditional-request validators so the next tick re-downloads instead of
  304-ing into a false success; validators commit only after full success.
- **Concurrency:** no network I/O under `statusMu`; alert payloads computed under the lock,
  fired after unlock; status reads never block behind an in-flight fetch; catalog reads are
  lock-free atomic pointer loads.
- **Legacy GH-tags gate (M0-PR4):** enable-only-on-explicit-truthy — any typo stays OFF
  (fail-safe in the secure direction), primary Docker-registry recovery path unaffected,
  write-once `atomic.Bool`, state surfaced in `/api/update/status`.
- **Persistence:** no new state file bypasses `fileutil.AtomicWrite`; staging is
  temp-dir + atomic rename with cleanup on failure; corrupt/expired on-disk catalog is
  fail-closed `available:false`, never a crash-loop.

Previously-open findings **not** incidentally touched in the window (verified by diff):
CHAOS-03 (fixed here deliberately), CHAOS-12 (`dp_enrollment.go` untouched), CHAOS-05/07
(`store.go`/`enrollment.go` untouched).

---

## Open-findings register — status after this run

Statuses relative to the 2026-07-09 table. Findings not listed are unchanged (open); the
2026-07-05 review remains the authority for their detailed write-ups.

| ID | Sev | Title | Status |
|---|---|---|---|
| CHAOS-03 | HIGH | No idle/half-open deadline on any raw relay | **FIXED** (this change) |
| CHAOS-22 | MED | Refresh-loop tick panic kills freshness watchdog | **FIXED** (this change, new) |
| CHAOS-12 | MED-HIGH | DP cert renewal inert until restart; expiry brick | OPEN — now the top open finding |
| CHAOS-05/07 | MED-HIGH | Corrupt `ui_users.json` / `cluster.json` silently reset (revoked certs revalidate) | OPEN |
| CHAOS-23 | MED | Freshness watchdog inert for disabled-fetch/permissive deployments | OPEN (new) |
| CHAOS-06 | HIGH | Root-CA load failure → silent fail-open | MITIGATED (07-09); `inspection.required` fail-closed mode still open |
| CHAOS-09 | MED | Readiness blind to CP-poll failure / cert expiry | OPEN |
| CHAOS-10/17 | MED | Scan-error posture inconsistent (fail-open holes) | OPEN |
| CHAOS-11 | MED | Upstream-pool all-down fails open to direct | OPEN (posture decision required) |
| CHAOS-15/16 | MED | HMAC rotation no grace window; auth negative caching | OPEN |
| CHAOS-18 | MED | DP snapshot applied before local store inits | OPEN |
| CHAOS-08 | MED | No semantic floor on snapshots | OPEN (policy decision required) |
| CHAOS-13/14 | MED-LOW | No jitter on legacy feed tickers; no gRPC keepalives on CP/DP channel | OPEN (M1 refresh loop ships jitter — the model to copy) |
| CHAOS-24/25/26 | LOW | Release-platform delta lows (skew tolerance, latch re-alert, staged-bytes cap) | OPEN (new) |
| CHAOS-19/20/21 | LOW-MED | Audit-write counter; feed staleness metrics; CA-rotation window race | OPEN |

---

## Recovery assessment (updates only)

| Scenario | Before this change | After |
|---|---|---|
| Half-open peer on any raw tunnel (CONNECT/WS/SOCKS5/inspect-fallback) | ❌ goroutines + FDs + buffer + limiter slot pinned forever; silent | ✅ reaped 1–2× `tunnelIdleTimeout` after last byte; logged; accounting entry emitted |
| Peer that ACKs but never **reads** (write-side half-open) | ❌ relay blocked in deadline-less Write forever | ✅ idle teardown hard-closes both conns, unblocking the writer |
| Mass idle-tunnel flood | ❌ unbounded resource growth until FD exhaustion | ✅ bounded at (arrival rate × idle window); per-IP limiter (CHAOS-02) bounds per-source concurrency |
| Panic inside catalog refresh/verify/reload | ❌ refresh + 180-day stale watchdog silently dead until restart | ✅ one missed tick, logged; catalog untouched; loop continues |

---

## Required tests (shipped with this change)

- `proxy_tunnel_idle_test.go` — 4 tests: half-open reap (pre-fix: eternal block);
  one-direction-active keep-alive + exact byte accounting across deadline pops;
  graceful-EOF teardown unchanged (real TCP, CloseWrite + splice path); SOCKS5 reap.
- `release_refresh_test.go::TestRunCatalogRefreshLoop_SurvivesTickPanic` — panic costs one
  tick; later ticks run and record status (proves no stranded lock); cancellation still
  honored.

## Suggested next-run targets (priority order)

1. **CHAOS-12** — reconnect/hot-swap TLS after DP cert renewal; expiry-approaching alert
   while CP unreachable. Now the highest-value open item.
2. **CHAOS-05/07** — quarantine-don't-overwrite (`.corrupt.<ts>`) + alert on corrupt
   `ui_users.json` / `cluster.json`.
3. **CHAOS-23** — decouple `evaluateCatalogFreshness()` from the fetch loop (always-on
   ticker) so disabled-fetch appliances keep the stale backstop.
4. **CHAOS-06 (remainder)** — `inspection.required` fail-closed mode (config + API + UI
   panel per GUI-parity).
5. **WK-8 (2026-07-04 register)** — the codebase-wide `safeGo` panic supervisor; F2 fixed
   the newest worker, but threatfeed/feedsync/CDR-poller/SSE loops still run bare.
6. Deep-dive passes never yet done: maintenance-agent host-ops surface,
   `update_cluster.go` failure paths (RISK-011), SAML metadata refresh.

## Residual risk

- The CHAOS-03 fix alters relay behavior ONLY on tunnels silent in both directions for a
  full hour; the keep-alive test proves one-way-active tunnels survive arbitrarily many
  idle windows, and the EOF test proves graceful teardown is byte-identical. The hot-path
  cost is one `SetReadDeadline` (a runtime-timer update, no syscall) per copy resumption —
  twice per hour on an idle-ish tunnel, once per ~128 KB-buffer-drain interruption
  otherwise; the kernel-splice fast path is preserved by design.
- `tunnelIdleTimeout` configurability is deferred (GUI-parity obligation); 1 h is
  conservative. An operator-facing knob should arrive with the config surface done
  properly (registry row + snapshot/rollback classification per Finding 10.3).
- CHAOS-23/24/25/26 are detection-fidelity items in the release platform: serving remains
  fail-closed through `GetCatalog`'s use-time expiry hide in every analyzed failure mode.
- Everything else in the open table above is unchanged; the 2026-07-05 and 2026-07-04
  registers remain the authority for detailed write-ups.
