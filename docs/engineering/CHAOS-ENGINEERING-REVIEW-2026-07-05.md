# Culvert Chaos Engineering Review — 2026-07-05

> **Owner:** Chaos Engineering routine · **Status:** Point-in-time review (repeatable)
> **Method:** Four parallel failure-domain audits (proxy data path · storage/persistence ·
> external dependencies/background workers · cluster/HA/lifecycle), top findings
> hand-verified against the tree at `7e4e67f`. Findings already tracked in
> `TECHNICAL-RISK-REGISTER.md` or `roadmap/edge-case-audit.md` are not re-reported.
> **Companion change:** five fixes ship with this review (see "Fixed in this change").

---

## Executive Summary

Culvert's failure posture is strong where it has been deliberately engineered — the HA
fencing lease, the restore boot guard, the alert retry queue, the SSE hub, and the
`fileutil.AtomicWrite` migration all hold up under adversarial review (see "Verified
resilient"). The gaps this review found cluster in three themes:

1. **Silent fail-open on dependency failure.** The most severe: one threat-feed sync with
   both upstreams unreachable **wiped the entire threat-intel DB in memory and on disk**
   (fixed in this change). Same theme, still open: a ClamAV error mid-request forwards
   content unscanned with no counter (CHAOS-10); a CA-bundle load failure silently
   disables SSL inspection for the whole deployment (CHAOS-06).
2. **Durability and disk-failure blind spots.** The rotating log writer **destroyed the
   just-rotated audit archive** on a transient disk-full (fixed); six crown-jewel stores
   (admin users/TOTP, admin settings, session revocations, CDR policy, release-catalog
   anti-rollback floor, hit counters) used non-fsynced fixed-`.tmp` writes that torn-write
   under concurrent saves and revert under power loss (fixed).
3. **Cluster failure modes that no signal surfaces.** The worst open finding: a CP restart
   resets its in-memory config-version counter, so **every long-running DP silently
   ignores all post-restart config changes** — including new blocks — until the counter
   catches up (CHAOS-01). Readiness does not reflect CP-poll failure or cert expiry, so a
   load balancer never ejects the degraded node (CHAOS-09).

**Fixed in this change:** 5 defects (threat-feed wipe, syslog proxy-wide stall,
log-rotation archive destruction, non-atomic crown-jewel writes, unbounded DNS-blocked
goroutine fan-out), each with regression tests.
**Top remaining risks:** CHAOS-01 (CP version reset), CHAOS-02/03 (SOCKS5 + raw-relay
resource exhaustion), CHAOS-06 (CA load fail-open), CHAOS-12 (DP cert renewal inert +
expiry brick).

---

## Fixed in this change

### F1 — Threat feed wiped on transient double-fetch failure · HIGH
- **Was:** `internal/threatfeed/threatfeed.go` `Sync()` built fresh maps, fetched both
  feeds, then **unconditionally** replaced the in-memory tables and persisted them —
  even when every fetch failed. One sync with URLhaus + OpenPhish unreachable (shared
  egress path, DNS blip, abuse.ch maintenance) zeroed the DB for up to 6h; because the
  empty state was saved, a restart in the window reloaded the wipe (durable outage).
  `CheckURL`/`CheckDomain` then returned false for everything — threat blocking silently
  off.
- **Fix:** `applySync` carries forward the previous entries of any feed whose fetch
  failed (keyed on `entry.Source`), mirroring the last-known-good pattern
  `internal/feedsync` already uses. A feed that fetched cleanly is still fully replaced,
  so stale entries age out.
- **Tests:** `internal/threatfeed/sync_carryforward_test.go` — all-failed keeps
  last-known-good; one-failed carries forward only that feed; clean sync fully replaces.

### F2 — Stalled TCP syslog collector blocks the proxy indefinitely · HIGH
- **Was:** `internal/syslog/syslog.go` `writeMsg` held `s.mu` across an **unbounded**
  TCP write. A collector that accepts but stops draining (SIEM overload, half-open peer)
  fills the kernel send buffer; `fmt.Fprint` blocks forever; every
  `Write`/`WriteAudit`/`WriteRequest` caller then queues on the mutex — a proxy-wide
  stall. The code comment promised "syslog must never block the proxy"; nothing enforced
  it for the write.
- **Fix:** `SetWriteDeadline(now+5s)` before each write (initial and reconnect-retry
  paths). A stalled peer now surfaces as a write error → existing close/reconnect/backoff
  logic takes over.
- **Tests:** `internal/syslog/syslog_deadline_test.go` (fake conn pins that a deadline is
  set and sane before writing).

### F3 — Log rotation on a full disk destroyed the rotated archive · HIGH
- **Was:** `internal/fileutil/rotating.go` on rotation did close → remove `.1` → rename
  current→`.1` → reopen. If the reopen failed (disk full), the writer kept the closed
  handle and stale size, so the **next** write re-entered rotation and its
  `os.Remove(path+".1")` deleted the just-rotated archive — the only surviving copy of
  the audit/request/system log data. A transient disk-full plus continued writes lost
  already-persisted compliance data, silently.
- **Fix:** rotation and reopen are decoupled: a failed reopen leaves `r.file == nil`, and
  subsequent writes retry **only the reopen** (never re-entering the rotation branch), so
  the `.1` archive is preserved and the writer self-heals when space frees. `Close` is
  now nil-safe and mutex-guarded.
- **Tests:** `internal/fileutil/rotating_test.go` — rotation archives content; repeated
  failed reopens preserve the archive; recovery resumes writes with archive intact.

### F4 — Crown-jewel stores used non-atomic, non-fsynced writes · HIGH
- **Was:** six writers used the pre-Bucket-4 fixed-`.tmp` + rename pattern (no fsync,
  shared temp name): `SaveUIUsersFile` (admin creds/roles/TOTP — called concurrently
  from HTTP handlers), `SaveAdminSettings` (spawned as `go SaveAdminSettings()` per API
  mutation — two concurrent saves interleave into the **same** temp file and publish a
  torn result), `session.SaveRevocations` (a reverted file resurrects revoked sessions),
  CDR policy save, `writeVersionFloor` (a power-loss-reverted floor reopens the
  signed-catalog rollback window its fail-closed reader exists to close), and rule hit
  counters.
- **Fix:** all six now use `fileutil.AtomicWrite` (unique `CreateTemp` + fsync + rename +
  parent-dir fsync) — the helper the rest of the tree already standardized on.
- **Tests:** covered by existing persistence round-trip suites (unchanged, green);
  `AtomicWrite` itself is pinned by `internal/fileutil/fileutil_test.go`.

### F5 — Unbounded DNS-blocked goroutine fan-out per request · MEDIUM
- **Was:** `handleRequest` fired `go trackDestinationCountry(host)` per proxied request;
  each can block in uncached `net.LookupHost` for the full resolver timeout
  (`geoip.go:41`). During a resolver brownout — precisely when the proxy is already
  stressed — this piled up one blocked goroutine per request with no backpressure.
- **Fix:** a 256-slot semaphore bounds concurrent trackers (`proxy.go`); when saturated
  the dashboard sample is dropped (stats are best-effort).
- **Tests:** `proxy_geotrack_test.go` (saturated pool → immediate drop, no blocking).

---

## Open findings — Risk Matrix

| ID | Sev | Domain | Title | Verified |
|---|---|---|---|---|
| CHAOS-01 | HIGH | Cluster | CP restart resets in-memory config version; DPs silently ignore all post-restart config | HV |
| CHAOS-02 | HIGH | SOCKS5 | SOCKS5 has no per-IP connection limit (connlimit covers HTTP path only) | HV |
| CHAOS-03 | HIGH | Proxy | No idle/half-open deadline on any raw relay; idle tunnels pin connlimit slots forever | agent |
| CHAOS-06 | HIGH | CA | Root-CA load failure silently disables SSL inspection (fail-open on the core control) | agent |
| CHAOS-12 | MED-HIGH | Cluster | DP cert renewal writes to disk but never hot-reloads; expiry during CP outage bricks the node | agent |
| CHAOS-04 | MED-HIGH | OCSP | Transient responder outage cached as REVOKED for 1h (outage amplification) | agent |
| CHAOS-05 | MED-HIGH | Auth/Storage | Corrupt `ui_users.json` at boot → empty admin roster, then overwritten (permanent loss) | agent |
| CHAOS-07 | MED-HIGH | Cluster | Corrupt `cluster.json` → "starting fresh": revoked DP certs become valid again | agent |
| CHAOS-09 | MED | Health | `/readyz` ignores CP-poll failure and cert expiry; LB never ejects a degraded DP | agent |
| CHAOS-10 | MED | Scanning | ClamAV *error* mid-request fails open silently (timeout is fail-closed — inconsistent) | agent |
| CHAOS-11 | MED | Upstream | Upstream pool all-down fails OPEN to direct egress; CONNECT/SOCKS5 never traverse the pool | agent |
| CHAOS-15 | MED | Sessions | Session HMAC rotation has no dual-key grace window (fleet-wide logout + cross-node reject window) | agent |
| CHAOS-16 | MED | Auth | LDAP/OIDC negative results cached (5m/2m): transient IdP outage denies valid creds after recovery; no post-dial deadline (LDAP), no breaker (OIDC, 10s tail) | agent |
| CHAOS-17 | MED | Scanning | Plain-HTTP body-scan read error fails open silently + truncates response (inspect path is fail-closed) | agent |
| CHAOS-18 | MED | Startup | `initCluster` applies DP snapshot + starts poll loop before local store inits (clobber + `ipf` pointer race window) | agent |
| CHAOS-08 | MED | Cluster | No semantic sanity gate on snapshots: an empty-rules default-deny/allow snapshot propagates fleet-wide in one poll | agent |
| CHAOS-19 | MED | Audit | Audit persistence write errors swallowed (request log has a counter; audit does not) | agent |
| CHAOS-13 | MED-LOW | Cluster | DP reconnect backoff and 30s poll have no jitter (thundering herd on CP recovery) | agent |
| CHAOS-14 | MED-LOW | Cluster | No gRPC keepalives on CP/DP channel (half-open detection = 90s heartbeat staleness) | agent |
| CHAOS-20 | LOW-MED | Metrics | Threat-feed staleness/sync-failure not exposed to Prometheus (JSON status only) | agent |
| CHAOS-21 | LOW-MED | CA | CA-rotation window race: leaf can be signed before the secondary (overlap) CA is installed | agent |

`HV` = hand-verified this review; `agent` = domain-audit evidence with file:line, not independently re-verified.

---

## Detailed findings

### CHAOS-01 — CP restart poisons DP config sync · HIGH
- **Current behavior:** `ConfigStore.version` is in-memory only (`controlplane_snapshot.go:166`,
  incremented at `:187`; no load path). The DP applies a snapshot only when
  `snap.Version > c.lastVersion` (`controlplane_client.go:217`).
- **Failure mode:** CP at version 500 restarts → counter restarts at 0. Every long-running
  DP holds `lastVersion=500` and hits the "nothing changed" short-circuit for **all**
  subsequent config — new blocklist entries, policy rules, revocations — until >500 new
  edits occur. No log line fires; the DP believes it is up to date. Asymmetric: a DP
  restart self-heals (its counter resets), a CP restart poisons every running DP.
- **Recovery:** manual (restart every DP, or make 500+ dummy edits). Nothing automatic.
- **Expected behavior:** the version must survive CP restarts (persist it, or seed it from
  the durable config-version sequence in `configver`), and/or the DP gate should compare
  a content hash rather than a bare counter. The epoch fence (`dpObserveEpoch`) guards
  rollback by a *different* CP, not staleness from the *same* CP.
- **Visibility:** none today — no metric, no log, `/readyz` green (see CHAOS-09).

### CHAOS-02 — SOCKS5 uncovered by the connection limiter · HIGH
- **Current behavior:** `handleSOCKS5` checks the IP filter (`socks5.go:258`) and rate
  limiter (`:264`) but never calls `connLimiter.Acquire/Release`; the HTTP/CONNECT path
  does (`proxy.go:611-615`).
- **Failure mode:** one client IP opens thousands of concurrent SOCKS5 tunnels under the
  rate-limit burst budget; each holds 2 goroutines + 2 FDs indefinitely (no idle
  deadline, CHAOS-03). Single-IP resource exhaustion the HTTP listener is explicitly
  hardened against.
- **Expected:** `connLimiter.Acquire(clientIP)` at SOCKS5 accept, released at relay end —
  symmetric with `handleRequest`.

### CHAOS-03 — No idle deadline on raw relays; slots pinned forever · HIGH
- **Current behavior:** established relays (CONNECT bypass `proxy_tunnel.go:327`,
  WebSocket `:158`, SOCKS5 — which explicitly clears its handshake deadline at
  `socks5.go:340` — and the non-TLS/WS-in-inspect fallbacks `:543-557`, `:662-677`) have
  no read/idle deadline. Only the SSL-inspected HTTP loop has the 60s deadline.
- **Failure mode:** half-open TCP (client vanishes without FIN) or idle-forever peers
  leave both relay goroutines blocked in `io.Copy` permanently; OS TCP keepalive
  (hours) only reaps truly-dead peers. Because `connLimiter.Release` is deferred until
  the relay ends (`proxy.go:615`), 1024 idle tunnels from one IP permanently exhaust that
  IP's slots → every later connection from that (possibly NAT-shared) IP gets 503. There
  is also no **global** connection ceiling (`activeConns` is a gauge, not a limit).
- **Expected:** an application-level idle deadline re-armed on relay activity (the
  `stallDetectReadCloser` pattern already in-tree) across all four raw-relay paths, plus
  an optional global connection cap.
- **Note:** the SOCKS5 struct comment (`socks5.go:19-21`) claims in-flight tunnels keep
  "per-conn 30s deadlines" — false today; fix code or comment together.

### CHAOS-06 — Root-CA load failure silently disables SSL inspection · HIGH
- **Current behavior:** `rootca_startup.go:40-42` logs a warning on `LoadOrInitCA` error
  (wrong/missing `CULVERT_CA_PASSPHRASE`, corrupt bundle) and continues with inspection
  disabled. Correctly does NOT regenerate a CA (would break client trust).
- **Failure mode:** a passphrase drift or bundle corruption turns the gateway into a
  tunnel-only proxy: no MITM scanning, DLP, YARA, CDR on TLS traffic — indefinitely, on
  one log line. For a Zero-Trust SWG this is fail-open on the primary control.
- **Expected:** operator-selectable posture — at minimum a `cert_expiry`-class alert +
  `/readyz` signal; ideally a config flag (`inspection.required=true`) that refuses to
  serve TLS traffic in bypass when the CA was configured but failed to load.

### CHAOS-12 — DP cert renewal inert until restart; expiry brick · MED-HIGH
- **Current behavior:** `renewDPCert` (`dp_enrollment.go:362-408`) persists the new
  cert/key but the live gRPC client only reads TLS material in `connect()`
  (`controlplane_client.go:85-109`) — construction and failover only. Renewal requires a
  reachable CP; there is no offline grace, and a still-registered node cannot re-enroll
  (`controlplane_server.go:305-307`).
- **Failure mode:** (a) renewal "succeeds" but the connection keeps presenting the old
  cert; after CA-rotation cleanup the next reconnect fails despite a valid cert on disk —
  manual restart needed. (b) a CP outage spanning the 30-day renewal window bricks the DP
  at cert expiry (revoke + re-enroll to recover).
- **Expected:** reconnect (or hot-swap TLS config) after successful renewal; alert on
  approaching expiry while CP unreachable.

### CHAOS-04 — OCSP outage cached as revocation · MED-HIGH
- **Current behavior:** all-responders-unreachable returns "revoked" (fail-closed —
  correct posture) but then `cacheResult` stores that verdict for the full 1h TTL
  (`internal/ocsp/ocsp.go:153-154`, `cacheTTL` `:41`), identical to a genuine revocation.
- **Failure mode:** a seconds-long responder blip hard-fails all TLS to the affected
  upstream(s) for an hour after recovery.
- **Expected:** cache indeterminate (unreachable) verdicts with a short TTL (1-5 min) —
  still fail-closed, but recovery tracks the dependency, not the cache.

### CHAOS-05 / CHAOS-07 — Corrupt state files silently reset to empty · MED-HIGH
- **Current behavior:** a corrupt `ui_users.json` is logged and skipped
  (`auth_startup.go:39-43`) → empty roster (legacy/env fallback creds become live), and
  the next save overwrites the corrupt file — admin accounts + TOTP enrollments
  permanently lost. Same pattern for `cluster.json` (`cluster_startup.go:32-33`):
  "starting fresh" forgets enrolled nodes **and the revoked-cert list** (revoked DP certs
  validate again), then persists the empty state. Also (lower severity):
  `internal/nodegroup`, `admin_settings.go:139-142`, blocklist `.sources`, alert retry
  queue.
- **Expected:** for the two security-critical stores, fail-closed on
  present-but-corrupt (refuse to boot with actionable recovery moves — the
  `checkInterruptedRestore` pattern already in-tree), or at minimum quarantine the
  corrupt file (`.corrupt.<ts>`) instead of overwriting, and alert.
- **Note:** the F4 fix (fsynced atomic writes) removes the main *cause* of torn files;
  this finding is about the *response* to one.

### CHAOS-09 — Readiness blind to data-plane dependency health · MED
- **Current behavior:** `/healthz` always `ok` (`healthcheck.go:42-49`); `/readyz` gates
  only on session secret + snapshot-validator baseline (`:122-140`). CP-poll failure
  (`dpControlPlanePollFailing`) and node-cert expiry are not gates.
- **Failure mode:** a DP that lost its CP (stale config, CHAOS-01) with a nearly-expired
  cert keeps receiving LB traffic until it hard-fails.
- **Expected:** readiness (or at least a distinct `/readyz?strict=1` used by LBs) should
  degrade on sustained CP-poll failure and imminent cert expiry. Empty policy staying
  "ready" is correct (documented Zero-Trust posture) — this is about *dependency* health.

### CHAOS-10 / CHAOS-17 — Scan-failure posture inconsistent (fail-open holes) · MED
- **Current behavior:** ClamAV scan **timeout** blocks (fail-closed,
  `internal/secscan/secscan.go:490-494`) but a ClamAV **error** (daemon crash mid-stream)
  logs and continues to a clean verdict (`:505-514`) — content forwarded unscanned, no
  dedicated counter/alert, un-rate-limited error logging. On the plain-HTTP path a body
  read error during scanning returns "clean" silently and streams a truncated body
  (`proxy_http.go:178-181`), while the inspect path fails closed
  (`proxy_tunnel.go:817-822`).
- **Expected:** one documented posture (config: `scan.on_error = block|allow`), a
  `culvert_scan_errors_total` counter, and alignment of the plain-HTTP path with the
  inspect path.

### CHAOS-11 — Upstream-pool egress fails open · MED
- **Current behavior:** when every parent proxy is unhealthy/circuit-open, `Pool.Next()`
  returns nil and `ProxyFunc` maps that to a **direct** connection
  (`internal/upstream/upstream.go:240,262-268`). CONNECT/inspect and SOCKS5 dial the
  origin directly and never traverse the pool at all (`proxy_tunnel.go:270,472`,
  `socks5.go:331`).
- **Failure mode:** deployments whose egress/DLP contract depends on parent proxies
  silently bypass them during an upstream outage (HTTP), and always did for
  HTTPS/SOCKS5.
- **Expected:** a per-pool `fail_mode: open|closed` toggle; documentation that tunnel
  paths do not use the pool (or wire them through it).

### CHAOS-15 / CHAOS-16 — Auth-plane outage amplification · MED
- Session HMAC rotation is single-key (`internal/session/session.go:390-393,422-429`);
  cluster propagation is per-DP 30s polls → a rotation causes a cross-node rejection
  window plus a full fleet logout. **Expected:** accept-previous-key grace list.
- LDAP caches negative verify results for 5 min including dial/search failures
  (`auth_ldap.go:114-115,133-135`), and only the dial is deadline-bounded; OIDC
  introspection caches failures for the 2-min TTL and adds up to 10s request-path latency
  with no breaker, using `context.Background()` (`auth_oidc.go:122-160`). **Expected:**
  don't cache error-path negatives; bound post-dial LDAP ops; short-circuit breaker for a
  down IdP.

### CHAOS-18 — DP startup ordering: cluster snapshot vs. local store inits · MED
- **Current behavior:** `initCluster` (`main.go:194`) synchronously applies the last-good
  snapshot AND starts the poll loop (immediate `fetchAndApply` goroutine) before
  `initBlocklist`/`initPolicy`/`initURLCategories`/`initSSLBypassAndDPI`/… run
  (`main.go:196-202`). Later inits overwrite cluster-applied state until the next 30s
  poll; a fast first poll races plain global writes (e.g. `ipf = newIPF`,
  `controlplane_snapshot.go:292`) against the remaining init steps.
- **Expected:** apply the last-good snapshot and start the poll loop AFTER local store
  inits (a deliberate "cluster wins over local files" ordering), or gate the first apply
  on an "inits complete" latch.

### CHAOS-08 — No semantic floor on snapshots · MED (policy decision required)
- A structurally-valid snapshot with `DefaultAction:"deny"` (or `"allow"`) and empty
  non-nil `PolicyRules` propagates fleet-wide within one 30s poll
  (`controlplane_snapshot.go:311,316`); `validateConfigSnapshot` checks only upper caps.
  Empty policy is a *documented valid* Zero-Trust posture, so a hard gate is wrong — but
  a **diff-magnitude guard** (e.g. "rules went N→0 while default flipped" requires a
  `force` flag) or at minimum a loud log + alert would catch fat-finger fleet outages.

### Lower-severity observations
- **CHAOS-13:** no jitter in DP backoff (`controlplane_client.go:39-50`) or the 30s poll —
  synchronized re-poll spike at CP recovery. Add ±20% jitter.
- **CHAOS-14:** no gRPC keepalives on the CP/DP channel (the CDR client has them,
  `cdr.go:168-171`); half-open detection currently ≈90s heartbeat staleness.
- **CHAOS-19:** audit JSONL write errors ignored (`internal/audit/audit.go:131-135`);
  mirror the request-log failure counter (`internal/reqlog/reqlog.go:160-166`).
- **CHAOS-20:** `SyncStatus`/`SyncFailures` not exported to Prometheus — feed staleness
  invisible to metric-driven alerting (`metrics.go:354-360`).
- **CHAOS-21:** CA rotation installs the new CA and the secondary (overlap) CA in two
  separate critical sections (`ca.go:176-181` vs `:530-534`); a concurrent cache-miss
  leaf-sign in between emits a chain without the overlap cert — transient client cert
  errors at the rotation instant.
- `fetchAndApply` double-increments `failCount` (`controlplane_client.go:169` + `:40`),
  so failover trips after 2 real failures (documented: 3) and backoff ramps 2×.
- CP crash between token-consume and response mid-`Enroll` strands a registered node
  that can neither retry nor re-enroll (`controlplane_server.go:239,266,305-307`).
- Blocklist sibling files (`.mode`, `.manual`, `.exceptions`, `.sources`) are each atomic
  but not mutually consistent under a crash between writes.
- Enrollment RPC dials with `insecure.NewCredentials()` unconditionally
  (`dp_enrollment.go:134-146`) — the CA fingerprint verifies the *payload*, not the
  transport; the enrollment token travels cleartext on insecure-CP deployments. (Security
  review candidate; listed here because the failure mode is token theft during the
  enrollment window.)

---

## Recovery assessment

| Scenario | Automatic recovery | Manual recovery | Gap |
|---|---|---|---|
| Threat feeds unreachable | ✅ (after fix: last-known-good + next-cycle retry) | — | staleness metric (CHAOS-20) |
| Syslog collector stall | ✅ (after fix: 5s deadline → reconnect/backoff) | — | drop counter would help |
| Disk full during log rotation | ✅ (after fix: self-heals when space frees, archive intact) | — | audit-write failure counter (CHAOS-19) |
| Power loss during crown-jewel save | ✅ (after fix: fsynced atomic writes) | — | corrupt-load response still silent-reset (CHAOS-05/07) |
| CP restart | ❌ silent config staleness on all DPs (CHAOS-01) | restart every DP | no signal at all |
| CP long outage | DP serves last-known-good ✅ | — | cert expiry bricks node (CHAOS-12) |
| DP cert renewal | writes disk ✅ but inert until restart (CHAOS-12) | restart DP | hot-reload missing |
| OCSP responder blip | after 1h cache TTL (CHAOS-04) | flush via restart | indeterminate-verdict TTL |
| ClamAV daemon crash | ✅ reconnects when back | — | fail-open window uncounted (CHAOS-10) |
| Root CA unloadable | ❌ inspection off until fixed (CHAOS-06) | fix passphrase/bundle + restart | no alert, no readiness signal |
| Half-open tunnels / idle storms | ❌ (CHAOS-03) | restart proxy | idle deadlines missing |
| etcd (lease mode) outage | ✅ fail-closed leadership denial, resumes | — | verified resilient |
| Interrupted restore | ✅ boot guard refuses + prints moves | guided | verified resilient (RISK-005) |

## Operational / Security / Data-integrity impact

- **Customer impact concentrated in silent modes:** the fixed threat-feed wipe and the
  open CHAOS-01/06/10 all degrade *protection* while the proxy keeps serving — users see
  nothing; operators see green dashboards. These deserve priority over crash-loud bugs.
- **Security impact:** fail-open windows (scan errors, CA load, revoked-cert amnesia
  CHAOS-07, upstream-pool bypass CHAOS-11) and the enrollment-transport note. None are
  remotely *triggerable* at will except the resource-exhaustion set (CHAOS-02/03), which
  is a deliberate-DoS surface.
- **Data integrity:** F3/F4 fixes close the found loss paths (audit archive destruction,
  torn crown-jewel writes); the remaining integrity gap is the silent-reset-on-corrupt
  policy (CHAOS-05/07).
- **Monitoring:** the recurring theme is *no counter for the failure path* — scan errors,
  audit write failures, feed staleness, CP-poll failing (exists but not surfaced to
  readiness). Cheap, high-leverage additions.

---

## Verified resilient (chaos scenarios already handled correctly)

- **HA fencing lease (ADR-0005):** confirmed-loss self-fence; transport-unknown serves
  only within the last etcd-confirmed window minus margin, then fences
  (`ha_lease.go:154-186`); `WriteAllowed` fail-closed (`:229-239`); etcd down at startup =
  lazily denied leadership, not a boot crash; epoch ratchet runs before any DP mutation
  (`controlplane_client.go:214`, `controlplane_snapshot.go:239`).
- **DP autonomy:** boots and serves last-known-good config with CP down
  (`dp_enrollment.go:257`, lazy `grpc.NewClient`); heartbeat-"dead" nodes auto-recover on
  reconnect (`enrollment.go:628-646`).
- **Shutdown:** tunnel drain bounded 15s (`main_shutdown.go:123-144`); UI/SOCKS5
  sub-budgets bound their hooks. (Residual: early-phase `GracefulStop` has no budget —
  low risk, unary-only.)
- **SSE hub:** non-blocking broadcast evicts slow clients (`internal/sse/sse.go:66-78`);
  connection cap; per-frame write deadline (`events.go:204-212`).
- **Alert delivery:** bounded backoff (5/15/45s ×3), bounded persisted queue (500),
  async + semaphore-bounded, SSRF-guarded, dedup window (`internal/alerts/store.go`).
- **Slowloris:** proxy listener 30s ReadTimeout (`main.go:880`); SOCKS5 handshake single
  30s deadline (`socks5.go:253`); SSL-inspect inner loop 60s + stall detector
  (`proxy_tunnel.go:596`, `proxy_http.go:39-42`).
- **Durability layer:** `fileutil.AtomicWrite` (unique temp + fsync + dir fsync,
  `internal/fileutil/fileutil.go:19-71`) used by configver/blocklist/CA/alerts/threatfeed
  — and, after this change, by the six remaining stragglers.
- **Release catalog:** refresher keeps last-good on failure, single-flight, atomic
  install (`release_catalog_refresher.go:144-227`); floor reader fail-closed
  (`release_catalog_freshness.go:148-167`).
- **Restore safety:** `checkInterruptedRestore` boot guard (RISK-005, closed).
- **MITM ticket keys:** `rand` failure keeps existing keys; CA change ends the resumption
  epoch (`proxy_tunnel.go:411-421`, `ca.go:56,182-184`).
- **Remote scan sidecar:** every failure path counted AND alerted (dedup-suppressed)
  (`internal/secscan/remote.go:95-156`) — the model CHAOS-10 should copy.
- **TOTP:** ±1 step skew tolerance, replay-protected (`internal/totp/totp.go:73-88`).
- **Upstream health/CB:** race-safe half-open CAS, ctx-cancelled loops
  (`internal/upstream/upstream.go:79,329-336`).

---

## Suggested improvements (priority order)

1. **CHAOS-01** — persist/seed the CP `ConfigStore` version (or hash-gate DP applies). S-M.
2. **CHAOS-02** — `connLimiter.Acquire/Release` around SOCKS5 sessions. XS.
3. **CHAOS-03** — idle deadline (re-armed on activity) on all raw relays; fix the stale
   SOCKS5 comment; consider a global conn cap. M.
4. **CHAOS-06** — alert + readiness signal on CA-load failure; optional
   `inspection.required` fail-closed mode. S.
5. **CHAOS-12** — reconnect after successful DP cert renewal; expiry-approaching alert. S.
6. **CHAOS-04** — short TTL for indeterminate OCSP verdicts. XS.
7. **CHAOS-05/07** — quarantine-don't-overwrite + refuse-to-boot (or alert) on corrupt
   `ui_users.json` / `cluster.json`. S.
8. **CHAOS-09** — readiness degrades on sustained CP-poll failure + imminent cert expiry. S.
9. **CHAOS-10/17** — `scan.on_error` posture config + `culvert_scan_errors_total`;
   align plain-HTTP scan failure with inspect path. S.
10. **CHAOS-16** — don't cache auth error-path negatives; LDAP op deadlines; OIDC breaker. S.
11. **CHAOS-13/14** — backoff jitter + gRPC keepalives. XS.
12. **CHAOS-19/20** — audit-write failure counter; feed staleness gauges. XS.

## Required tests (for the follow-up fixes)

- CP restart + running-DP staleness regression (CHAOS-01): restart CP with lower version,
  assert DP still applies.
- SOCKS5 connlimit: N+1th concurrent session from one IP refused (CHAOS-02).
- Idle-relay reaper: half-open tunnel torn down after deadline; active tunnel survives
  (CHAOS-03).
- CA-load failure: alert fired + readiness reflects (CHAOS-06).
- Renewal hot-reload: renewed cert presented without restart (CHAOS-12).
- OCSP: unreachable-responder verdict expires on the short TTL (CHAOS-04).
- Corrupt-store boot: `ui_users.json`/`cluster.json` garbage → quarantine + refusal path
  (CHAOS-05/07).
- Fault-injection suite: the disk-full rotation test added in this change
  (`TestRotatingFile_ReopenFailureDoesNotDestroyArchive`) is the template — extend the
  pattern (EISDIR/ENOSPC simulation) to the audit and reqlog writers.

## Residual risk

- Findings marked `agent` carry file:line evidence but were not all independently
  re-verified this run; verify before acting (esp. CHAOS-08's interaction with the
  documented empty-policy posture, and CHAOS-21's exact interleaving).
- This review did not deep-dive: SAML metadata refresh, the OIDC browser flow
  (`auth_oidc_flow.go`), `update_cluster.go` failure paths (RISK-011 already OPEN), or
  the maintenance-agent host-ops surface. Natural next passes.
- The fixes in this change alter failure-path behavior only (carry-forward, deadlines,
  reopen-retry, atomic writes, sample dropping); happy paths are byte-equivalent. The
  full test suite was run before merge; per-file coverage floors are enforced by Lane A.
