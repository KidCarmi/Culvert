# Culvert Chaos Engineering Review — 2026-07-26B

> **Owner:** Chaos Engineering routine · **Status:** Point-in-time review (repeatable)
> **Method:** Targeted-fix pass against the open-findings register as updated by the
> earlier 2026-07-26 run (`CHAOS-ENGINEERING-REVIEW-2026-07-26.md`, which closed
> CHAOS-17, mitigated CHAOS-10, and promoted **CHAOS-11 / F-09** to the top open
> item). The finding was re-verified live at HEAD (`67ab218`) before any code was
> written. **Companion change:** one fix ships with this review (see "Fixed in
> this change").

---

## Executive Summary

This run attacked **CHAOS-11 / F-09 — the parent-proxy chain's failure handling
is both blind and inert**, the top open item after the earlier run today.
Re-verification at HEAD confirmed two coupled defects:

1. **The circuit breaker was dead code on the request path.** `CircuitBreaker.
   RecordFailure`/`RecordSuccess` (`internal/upstream/upstream.go`) had **zero
   production callers** — only unit tests ever drove them. A broken parent
   proxy kept receiving (and failing) live traffic until the next health-check
   tick (default 30s, probing an external canary URL that can itself be
   unreachable in locked-down networks). The breaker state surfaced in the
   admin UI's Upstream panel could never move on real traffic — permanently
   "closed", failures permanently 0. The operator-facing circuit-breaker
   configuration (`upstream.circuit_breaker.threshold`/`timeout`) was
   effectively a no-op. **FIXED — real request outcomes now drive the
   breaker.**

2. **All-parents-down → direct egress was completely silent** (the register's
   PX-2). When `Pool.Next()` exhausted the pool it returned nil and the
   transport quietly egressed DIRECT — bypassing what is, in the deployments
   that configure it, a mandatory egress/DLP chokepoint. No log line, no
   alert, no counter, no API/UI/metric signal: an operator watching a green
   dashboard had no way to know the chain was bypassed. **FIXED —
   transition-edge log + `upstream_pool_down` webhook alert + per-request
   counter + API field + `/metrics` series + a red UI banner.** The fail-open
   *posture itself* is deliberately unchanged (see decision below).

---

## Fixed in this change

### F1 — Circuit breaker wired to real request outcomes (CHAOS-11a) · MED-HIGH

- **Was (re-verified at HEAD):** `grep -rn "RecordFailure" --include="*.go"`
  outside tests: only the definition. `Pool.ProxyFunc()` selected a proxy per
  request but nothing ever reported the request's outcome back.
- **Fix (`internal/upstream/upstream.go`, `proxy_http.go`):** a per-request
  **attribution slot** carried in the request context. `handleHTTP` attaches
  it (only when the pool is enabled — the disabled path allocates nothing),
  `ProxyFunc` records which proxy it selected, and after `client.Do` the
  outcome is fed back: success → `RecordSuccess` (closes/keeps closed),
  transport error → `RecordFailure` (threshold → open, with a one-per-trip
  log line naming the parent and the retry window).
- **Attribution policy (recorded):**
  - `context.Canceled` is **not** charged — it means *our* client went away
    mid-request, which says nothing about the parent's health; charging it
    would let a flaky client population trip breakers on a healthy chain.
  - `context.DeadlineExceeded` (the 30s client budget) **is** charged — a
    parent that cannot complete requests inside the budget is failing for our
    purposes. A slow *origin* through a healthy parent can be misattributed,
    but the blast radius is bounded by the consecutive-failure threshold
    (every success resets the count) and healed by the existing half-open
    probe after `timeout`; the periodic health check independently restores
    `Healthy`.
  - Plain-HTTP-via-parent semantics make transport errors a strong parent
    signal: an origin failure through a working parent surfaces as a
    proxy-generated 502/504 *response* (a transport-level success), not a
    transport error.
- **Scope note:** the CONNECT/WebSocket/SOCKS5 paths dial origins directly
  and never consult the pool (register PX-1, unchanged by this run) — the
  wiring covers the one path the pool actually serves.

### F2 — Direct-egress fallback made visible (CHAOS-11b) · HIGH (visibility)

- **Was (re-verified at HEAD):** `Next()`'s exhausted-pool branch:
  `return nil // all upstreams down — fall back to direct`. Nothing else.
- **Fix (`internal/upstream/upstream.go`):** the exhausted-pool branch now
  (a) increments a per-request fallback counter, and (b) on the transition
  INTO the fallback state fires one log line + one `upstream_pool_down`
  webhook alert through the existing WK-10 delivery engine (30s dedup,
  bounded queue, never blocks the producer). The first subsequent `Next()`
  that finds a usable parent clears the state and logs the recovery. The
  hot path stays read-only when not in fallback (Load-before-Swap), and an
  **empty pool never counts** — direct egress with no chain configured is the
  normal operating mode, not a failure.
- **Visibility wiring:** `Pool.DirectFallback()` → `direct_fallback
  {active,total}` on `GET /api/upstream` + `/api/upstream/settings` →
  `culvert_upstream_direct_fallback_active` gauge +
  `culvert_upstream_direct_fallback_total` counter on `/metrics` → a red
  "DIRECT FALLBACK ACTIVE" banner in the Upstream Proxies panel →
  `upstream_pool_down` in the webhook event picker + the alerts store's
  supported-events contract.
- **Posture decision (recorded):** the fail-open itself stays. Hard-failing
  all plain-HTTP egress when the chain is down is a self-inflicted outage
  with no operator escape hatch; the admin-selectable `upstream.fail_mode:
  open|closed` from the register is a *config surface* (GUI-parity: admin
  API + UI + config-surfaces registry rows + CP→DP sync semantics) and
  remains the CHAOS-11 remainder for an owner decision. What this run
  removes is the *silence* — the property that made the bypass unbounded and
  invisible — and the *inertness* — the property that kept a dead parent in
  rotation between probes.

### Tests

- `internal/upstream/breaker_wiring_test.go` —
  `TestAttribution_FailuresTripBreakerAndSuccessCloses` (threshold trips on
  attributed failures, pool falls back, attributed success closes),
  `TestAttribution_ClientCancelNotCharged` (wrapped `context.Canceled` never
  charges even at threshold 1; `DeadlineExceeded` does),
  `TestAttribution_NilSafety` (nil receiver / no-slot request / legacy
  `ProxyFunc(nil)` call shape),
  `TestNext_DirectFallbackCountsAndAlertsOncePerTransition` (counter per
  request; alert exactly once per transition, re-armed by recovery),
  `TestNext_EmptyPoolIsNotAFallback` (feature-off is not a failure).
- `proxy_http_upstream_breaker_test.go` —
  `TestHandleHTTP_BrokenParentProxyTripsBreakerThenDirectFallback`: end-to-end
  through the real `handleHTTP` + shared transport: two requests through a
  connection-refused parent → 502 + breaker `open` (impossible pre-fix), third
  request → DIRECT to a live origin (200) + `DirectFallback` active/counted.

---

## Failure Scenarios examined (this run)

| Scenario | Behavior after this change |
|---|---|
| Parent proxy hard-down (RST) | First `threshold` requests fail 502 and trip the breaker; subsequent requests fail over to the next parent (or direct if none), instead of failing until the next health probe |
| Parent accepts-then-stalls | 30s client budget → `DeadlineExceeded` → charged; breaker ejects the parent after `threshold` consecutive |
| All parents down | Direct egress (unchanged posture) + one alert per transition + counted per request + red panel banner + Prometheus gauge/counter |
| Health-probe canary (`detectportal.firefox.com`) unreachable from a locked-down network | Breaker now provides request-driven ejection/recovery independent of the probe path |
| Flaky clients aborting mid-request | `context.Canceled` not charged — healthy chain cannot be tripped by client churn |
| Slow origin through healthy parent | Worst case: one parent's breaker opens for `timeout` (default 60s), half-open probe + first success close it; health loop unaffected |
| Pool disabled (no parents configured) | Byte-identical hot path: no attribution allocation, no fallback accounting, no alerts |
| Breaker recovers (half-open probe succeeds) | First attributed success closes the circuit; recovery transition logged, fallback state cleared |

## Risk Matrix / Recovery Assessment (updates only)

| Scenario | Before | After |
|---|---|---|
| Broken parent proxy (CHAOS-11a) | ❌ breaker inert; traffic fails until the 30s external-canary probe notices (or forever if the canary is unreachable) | ✅ request-driven ejection after `threshold` consecutive failures; automatic half-open recovery |
| All-parents-down bypass (CHAOS-11b) | ❌ silent fail-open, invisible on every surface | ⚠️ fail-open bounded by alarm (webhook within one dedup window), measured (counter/gauge), visible (API/UI). Remainder: `fail_mode` posture config |

## Operational / Security Impact

- **Operational:** zero new configuration; the existing `circuit_breaker`
  YAML settings now actually govern live traffic. Operators get a Prometheus
  gauge+counter, API fields, a panel banner, and a webhook event for an
  egress control that could previously go dark with a green dashboard — the
  standing register's headline "silent fail-open degradation" theme applied
  to the parent-proxy chain.
- **Security:** in deployments where the parent chain is a mandatory
  egress/DLP chokepoint, the bypass window is now alarmed and measured. The
  breaker wiring also *shrinks* the failure window a broken parent inflicts
  on availability (fewer user-visible 502s between probes).

## Verification notes (re-checked at HEAD before acting)

- `RecordFailure`/`RecordSuccess` production call sites: none (grep, then
  confirmed by reading every `CB.` reference — `Allow` in `Next()`, display
  accessors in `List()`).
- The silent-fallback branch read directly (`upstream.go` `Next()`), and the
  transport wiring (`applyUpstreamProxy` → `ProxyFunc` → `Transport.Proxy`)
  traced to confirm plain-HTTP is the only pool consumer (PX-1 posture).
- `TestApplyUpstreamProxy_SetsTransportProxy` calls `Proxy(nil)` — the new
  `ProxyFunc` guards the nil-request shape (pinned in
  `TestAttribution_NilSafety`).
- Full `go test ./...` green at the companion commit; `go vet` clean.

## Open-findings register — status after this run

Statuses relative to the earlier 2026-07-26 table. Findings not listed are
unchanged; the 2026-07-05 review remains the authority for detailed write-ups.

| ID | Sev | Title | Status |
|---|---|---|---|
| CHAOS-11 | MED | Upstream-pool all-down fails open to direct; breaker dead code | **MITIGATED** (this change) — breaker wired to real outcomes; fallback alerted/counted/surfaced. Remainder: admin-selectable `upstream.fail_mode: open\|closed` (GUI-parity surface, owner decision) |
| CHAOS-10 | MED | ClamAV error mid-request fails open silently | MITIGATED (07-26) — remainder: `scan.on_error` posture config |
| CHAOS-27 | LOW-MED | Config-rollback swallows Save errors; double write-block escapes idle reaper | OPEN — **now the top open item** (T4 in the failure-injection plan) |
| CHAOS-15/16 | MED | HMAC rotation no grace window; auth negative caching | OPEN |
| CHAOS-18 | MED | DP snapshot applied before local store inits | OPEN |
| CHAOS-08 | MED | No semantic floor on snapshots | OPEN (policy decision required) |
| CHAOS-28 | LOW-MED | Failed rotation-triggered renewal not retried until the 30-day window | OPEN |
| CHAOS-13/14 | MED-LOW | No jitter on legacy feed tickers; no gRPC keepalives on CP/DP channel | OPEN |
| CHAOS-24/25/26 | LOW | Release-platform delta lows | OPEN |
| CHAOS-19/20/21 | LOW-MED | Audit-write counter; feed staleness metrics; CA-rotation window race | OPEN |

## Suggested next-run targets (priority order)

1. **CHAOS-27 / F-12** — `applyConfigBackup` swallows every `.Save()` error →
   rollback reports 200 while nothing survived the next restart; propagate and
   surface partial-durability.
2. **CHAOS-16 / F-11** — stop caching LDAP/OIDC *error-path* negatives
   (denies valid creds for minutes past IdP recovery); bound post-dial LDAP ops.
3. **CHAOS-11 remainder** — the `upstream.fail_mode` posture config (admin API
   + UI + config-surfaces rows), now that the observability substrate exists.
4. **CHAOS-13/14** — jitter the legacy feed tickers; gRPC keepalives on the
   CP/DP channel (half-open-TCP class).
5. Deep-dive passes never yet done: maintenance-agent host-ops surface (F-05
   persisted op journal), `update_cluster.go` failure paths (RISK-011), SAML
   metadata refresh.

## Residual risk

- The all-parents-down window remains fail-open per request until the
  `fail_mode` posture config ships — but it is now alarmed (webhook within
  one dedup interval), measured (gauge + counter), and visible (API + UI
  banner). An operator who needs hard fail-closed today can firewall direct
  egress at the network layer so the fallback fails at dial time.
- Slow-origin misattribution can transiently open one parent's breaker (60s
  default) even though the parent is healthy; bounded by consecutive-failure
  semantics, healed by half-open + the independent health probe. Accepted —
  identical trade-off to every consecutive-failure breaker.
- `fallbackTotal` is process-local and volatile (resets on restart; per-node
  in a cluster) — consistent with the existing counter family; the
  Prometheus `rate()` idiom is restart-tolerant.
- The `upstream_pool_down` alert fires from the request path's transition
  edge via the WK-10 engine (async, bounded, drop-on-full) — a flapping pool
  (parents oscillating each dedup window) delivers at most one webhook per
  transition per 30s dedup window (same exposure class as `scan_svc_down`).
