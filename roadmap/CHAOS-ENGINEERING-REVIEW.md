# Culvert Chaos-Engineering / Failure-Mode Review

**Date:** 2026-07-04
**Scope:** Full failure-domain sweep across the proxy data path, CA/TLS/sessions, cluster/HA
(Control-Plane ↔ Data-Plane), storage/persistence, authentication/identity, and background
workers/feeds/scanning/alerting.
**Method:** Evidence-first source review. Every finding cites `file:line`. No behavior was
inferred without reading the code path. Failure modes were assessed against the project's stated
posture — **default deny, fail closed when recovery is impossible, graceful degradation otherwise.**

This document is a standing register. It records where Culvert already survives failure safely
(and *why*, by code path) and where it does not. The one code change shipped alongside this review
is a fail-closed fix for a latent nil-deref panic in the enrollment path (Finding HA-9); everything
else is triaged below with a suggested PR and required tests for follow-up.

---

## 1. Executive Summary

Culvert's resilience is **strong on the paths that were explicitly hardened** and **weakest where
a security control degrades silently.** The single most important cross-cutting theme:

> **Silent fail-open degradation.** Several security controls (SSL inspection, ClamAV scanning,
> threat-feed coverage, parent-proxy egress) turn *off* under infrastructure failure while the
> gateway keeps forwarding traffic — with only a log line, no alert, and often no metric. An
> operator watching a dashboard sees green while the control is dark.

The second theme is **background-goroutine fragility**: the long-lived feed/health/broadcast
workers run their loop bodies without `recover()`, so a single panic in any of them takes down an
in-line security appliance.

The third theme is **incomplete adoption of the durable-write primitive**: `fileutil.AtomicWrite`
(fsync + temp + rename + parent-dir fsync) exists and is excellent, but several hot state files
(`admin_settings.json`, `ui_users.json`, audit log) still write through non-atomic, non-fsync'd,
fixed-temp-filename paths — risking silent config/credential loss.

What is genuinely well-built and should be held up as the model for the rest: the **etcd fencing
lease** (split-brain is structurally impossible in lease mode, clock-skew-immune via monotonic
`time.Since` + etcd-as-clock), the **KEK-at-rest** handling (fails closed on every corruption/perm
error, never silently regenerates), the **webhook alert delivery** (bounded queue, bounded retry,
SSRF-guarded, never blocks the producer), and the **async history store** (drops-and-counts under
disk pressure, never stalls the request path).

### Severity tally

| Severity | Count | Headline items |
|----------|-------|----------------|
| Critical | 1 | Background workers have no panic recovery → one panic kills the proxy |
| High | 12 | Silent fail-open on ClamAV / SSL-inspect / threat feed / parent-proxy; expired-CA still signs; admin_settings & ui_users non-atomic writes; stale SSO after IdP delete; no global conn cap; unfenced resumed leader never recovers |
| Medium | 20 | Half-open tunnel leaks, no OCSP/handshake deadlines, syslog blocking on hot path, no ticker jitter, DP max-staleness, etc. |
| Low / Positive | 15+ | Confirmed-resilient paths, documented below with the code that provides the resilience |

---

## 2. Failure Scenarios by Domain

Severity key: **C**ritical / **H**igh / **M**edium / **L**ow / **✓** handled well (positive finding).

### 2.1 Proxy Data Path (HTTP / CONNECT / WebSocket / SOCKS5 / upstream)

| # | Scenario | Verdict | Sev | Evidence |
|---|----------|---------|-----|----------|
| PX-1 | HTTPS CONNECT, WebSocket, and SOCKS5 dial the origin **directly** — the upstream parent-proxy pool is only wired into the plain-HTTP transport. Parent-proxy chaining silently applies to HTTP only. | GAP | H | `proxy.go:1374,1466`, `socks5.go:320`; pool only via `applyUpstreamProxy`→`getUpstreamTransport()` in `handleHTTP` `proxy.go:928` |
| PX-2 | Circuit breaker / all-upstreams-down **fails open to direct** egress, bypassing the parent-proxy control. | GAP (by design, security-relevant) | H | `internal/upstream/upstream.go:240,267` (`// all upstreams down — fall back to direct`) |
| PX-3 | Raw relays (CONNECT bypass, WebSocket, non-TLS fallback) have **no idle/read deadline** — a half-open peer leaks a goroutine + FD + 128KB pooled buffer indefinitely. Only the SSL-inspect *request loop* arms a deadline. | GAP | H | `bidiRelayCounted` `proxy.go:1431,1262`; contrast deadline at `proxy.go:1621` |
| PX-4 | Spawned relay/async goroutines have **no `recover()`** — a panic in any propagates to the runtime and kills the process, dropping every in-flight tunnel. | GAP | M | `go relayCounted(...)` `proxy.go:1290`, inline relays `proxy.go:1565,1747`, `go trackDestinationCountry` `proxy.go:696` |
| PX-5 | SOCKS5 connections **bypass the per-IP connection limiter** entirely. | GAP | M | `handleSOCKS5` `socks5.go:251` never calls `connLimiter.Acquire`; HTTP path does at `proxy.go:627` |
| PX-6 | **No global connection cap**; per-IP map is unbounded in cardinality; limiter ships **disabled by default**. Distributed flood → FD/memory exhaustion. | GAP | H | `internal/connlimit/connlimit.go:12,67` (default disabled, `Acquire`→true when off) |
| PX-7 | Bandwidth/QoS token buckets are **never enforced on the data path** — `AllowBytes` has no call site in the relays. Configured QoS silently does nothing. | GAP (feature dead) | M | `internal/bandwidth` `AllowBytes` `bandwidth.go:261` — no caller in `proxy.go`/`socks5.go` |
| PX-8 | Shutdown drain only accounts for CONNECT tunnels — WebSocket, non-TLS-fallback, and SOCKS5 relays are invisible to `drainActiveTunnels`, so SIGTERM hard-kills them. | GAP | M | `recordActiveConn` only at `proxy.go:1410,1599`; `drainActiveTunnels` `main.go:1131` |
| PX-9 | Half-open circuit admits **all** concurrent requests, not a single probe → thundering herd on a recovering upstream. | GAP | L/M | `internal/upstream/upstream.go:83` (no single-flight gate) |
| PX-10 | Plain-HTTP `WriteTimeout: 30s` can truncate large/slow legitimate downloads (absolute deadline over `io.Copy`). | GAP | M | `main.go:894`, stream at `proxy.go:1045` |
| PX-11 | SSL-inspect slowloris protection: 60s read deadline + per-`Read` re-arming body-stall detector. | ✓ | — | `proxy.go:1621`, `stallDetectReadCloser` `proxy.go:884`; test `proxy_slowloris_body_test.go` |
| PX-12 | CONNECT/WS stranded-byte handling: hijack-before-200, prebuffer flush before relay (avoids first-byte deadlock). | ✓ | — | `proxy.go:1398-1427` |
| PX-13 | Relay teardown is race-free: `CloseWrite` unblocks peer, buffered `done` chan (cap 2) publishes byte counts via happens-before. | ✓ | — | `proxy.go:1272-1295`, `socks5.go:345-368` |
| PX-14 | Upstream transport swap is atomic (clone-on-write, `atomic.Pointer`); health loop exits on `ctx.Done()`, bounded 5s checks. | ✓ | — | `upstream_transport.go:88-103`, `internal/upstream/upstream.go:329-336` |
| PX-15 | Plain-HTTP request safety: 64MB body cap, 30s client timeout, DNS-fail → 502 + deduped alert. | ✓ | — | `proxy.go:904,932,936`; alert dedup `alerts.go:34` |

### 2.2 CA / Certificates / TLS / Sessions

| # | Scenario | Verdict | Sev | Evidence |
|---|----------|---------|-----|----------|
| CA-1 | **Expired Root CA keeps signing leaves** — no `time.Now().After(caCert.NotAfter)` guard on the sign path. Every inspected client then sees an opaque expired-issuer TLS error (site-wide inspected-HTTPS outage) with no fast-fail signal. | GAP | H | `internal/ca/ca.go:724-753` (`signLeaf`), `GetCert` `ca.go:639-695` |
| CA-2 | Rotation `SaveCA` failure (disk full / read-only) is **swallowed** — logged, still returns `true`, still fires the "rotated successfully" alert. New CA lives only in RAM; next restart reloads the old near-expiry bundle. | GAP | H | `internal/ca/ca.go:508-510,519-522` |
| CA-3 | Corrupt bundle / wrong `CULVERT_CA_PASSPHRASE` / expired-at-rest CA at startup → **fail OPEN**: inspection silently disabled, traffic falls through to SSL-bypass (no DPI/CDR/file-blocking). Log line only, no alert, no `ssl_inspection_ready` gauge. | GAP (silent) | H | `rootca_startup.go:40-44`; `handleTunnel` gate `proxy.go:1335`; `ImportBundle` `ca.go:286` |
| CA-4 | Auto-rotation loop: **no immediate startup check** (24h blind spot after boot), **no retry/backoff** on failure (waits a fixed 24h). | GAP | M/H | `internal/ca/ca.go:460,64-73` |
| CA-5 | `cert_expiry` alert only fires **on rotation**, not as an early warning — contract says "fired on startup if ≤30 days" but the only producer is the rotation observer. | GAP (contract mismatch) | M | producer `ca.go:45-53`; contract `internal/alerts/store.go:17` |
| CA-6 | OCSP fails **closed** when a cert lists responders and none answer; `VerifyConnection` re-checks resumed sessions. Caveats: nil-issuer → fail-open; OCSP client has no SSRF guard on the peer-controlled responder URL. | ✓ (+2 caveats) | L/M | `internal/ocsp/ocsp.go:177-181`, `ocsp.go:41-56`; caveats `ocsp.go:139-142,187-206` |
| CA-7 | KEK-at-rest: rejects too-permissive/wrong-size files (never chmod-fixes, never silently regenerates), uses `os.Link` EEXIST to avoid racing mints, fails closed on decrypt error. | ✓ | — | `kek.go:174-239`, `cluster_ca_keyatrest.go:95-181` |
| CA-8 | Session HMAC key is **random per-restart by default** (no env/config secret) → all admin sessions invalidated on every single-node restart. | GAP | M | `session.go:38-49`, `internal/session/session.go:80-86` |
| CA-9 | Session HMAC runtime rotation / cluster sync is race-safe (lock-guarded set/read, hex+len validation before install, redacted on export). | ✓ | — | `internal/session/session.go:51-55,422-429`, `controlplane.go:1848-1862` |
| CA-10 | Clock skew/rollback: sessions use wall-clock `time.Now()`; leaf certs backdate only 5 min (`ca.go:747`) vs the UI cert's 1h — >5 min skew makes fresh leaves "not yet valid" to clients. | GAP | M | `internal/session/session.go:408`, `internal/ca/ca.go:747` vs `internal/uitls/uitls.go:52` |
| CA-11 | Leaf-cert cache has **no single-flight** — N concurrent misses for one host each sign independently; TTL expiry is synchronized (thundering herd). | GAP | M | `internal/ca/ca.go:656-694,650-651` |
| CA-12 | Upstream & client MITM handshakes inherit only `r.Context()` (no explicit handshake deadline); a slowloris handshake ties up the goroutine. Good: uses `HandshakeContext`, not `Handshake()`. | GAP | M | `proxy.go:1503,1591` |
| CA-13 | Cluster CA rotation mirrors CA-2: every failure branch logs-and-returns with no alert/metric. Silent failure → cluster-wide enrollment break at expiry. | GAP | M | `enrollment.go:1189-1245` |
| CA-14 | Revocation persistence uses `os.WriteFile`+rename with **no fsync** (unlike the CA bundle's `AtomicWrite`) — a revoked token can be honored again after crash/disk-full. | GAP | L/M | `internal/session/session.go:272-276`, caller `session.go:106-108` |
| CA-15 | CA loader **accepts a plain-PEM bundle even when a passphrase is set** (magic absent) — a downgrade footgun; logged, not alerted/rejected. | GAP (minor) | L | `internal/ca/ca.go:221-229` |

### 2.3 Cluster / HA / Control-Plane ↔ Data-Plane

| # | Scenario | Verdict | Sev | Evidence |
|---|----------|---------|-----|----------|
| HA-1 | CP unavailable: DP serves last-good config **indefinitely** — no max-staleness ceiling. A partitioned DP can enforce hours-old policy (stale allowlist / stale revocation view). | GAP (by design) | M | `main.go:1762`, `loadDPLastGoodConfigSnapshot` `controlplane.go:1929`, `fetchAndApply` `controlplane.go:1369-1441` |
| HA-2 | etcd witness unreachable: leadership **lazily denied** (fail-closed) — cluster degrades read-only, not split-brain. Only malformed config is fatal. | ✓ | — | `cluster_startup.go:146-178`, `acquireLeaseForLeadership` `ha_lease.go:75-102` |
| HA-3 | Lease keepalive transport failure & clock skew: self-fence bounded by the etcd-confirmed window; `time.Since(confirmedAt)` monotonic → clock-jump-immune; cross-node absolute time never compared. | ✓ | — | `ha_lease.go:154-186`, `internal/halease/etcd.go:118-128`; tests `ha_lease_test.go:105,139` |
| HA-4 | Split brain **with** the fence: structurally impossible (single `CreateRevision==0` txn; promote re-checks Acquire; term = epoch). | ✓ | — | `ha.go:617-621,634`, `internal/halease/etcd.go:73-92`; test `ha_split_brain_failover_evidence_test.go:172` |
| HA-5 | Split brain **without** the fence (legacy 2-node `--ha-auto-failover`): restarted leader resumes with no peer probe, **no rejoin reconcile**. Documented RISK-001. | GAP (accepted) | H | `cluster_startup.go:101-111`; tests `ha_split_brain_failover_evidence_test.go:220,268` |
| HA-6 | Ghost lease on fast leader restart: `acquireLeaseForResume` distinguishes own-ghost (`Holder==id`, wait ≤45s) from a real denial (immediate false). | ✓ | — | `ha_failover.go:145-182` |
| HA-7 | **Unfenced resumed leader never re-acquires.** If etcd is briefly unreachable during a leader restart and there is no resync material, the node falls through to `role=leader, leaseEpoch=0` — permanently read-only (`WriteAllowed()==false`) with **no background retry** until an operator restarts it. | GAP | H | `ha.go:289-296`, `ha_failover.go:125-132`, keepalive no-op `ha_lease.go:108` |
| HA-8 | Stale/rolled-back ConfigSnapshot: `dpObserveEpoch` monotonic CAS ratchet + puller-side no-live-holder reject; runs before any mutation. Caveat: in-memory floor re-seeds from last-good on restart. | ✓ | L | `ha_fencing.go:119-137,73-103`, `controlplane.go:1424,1667` |
| HA-9 | **Enrollment token corrupt `AllowCIDR` → nil-deref panic** (`net.ParseCIDR` error discarded, `cidr.Contains` on nil). Otherwise replay/expiry/prefix/CIDR are atomically consumed under lock. **FIXED in this PR.** | GAP → fixed | L | `enrollment.go:273-279` (fix), consume-under-lock `enrollment.go:241-294` |
| HA-10 | DP node lost: heartbeat monitor flips connected→disconnected after 90s (3 missed polls), race-safe persist; nodes warned at 24h, never auto-revoked. | ✓ | L | `enrollment.go:627-646,619-624` |
| HA-11 | CP restart while DPs connected: exponential backoff 2s→64s, failover only after 3 consecutive failures. **No jitter** on the 30s poll ticker → fleet re-sync thundering herd. | ✓ (+jitter gap) | L | `controlplane.go:1249-1260,1354-1367` |
| HA-12 | Rolling update mid-canary: error-budget halt/rollback, explicit drain with clear-on-every-exit, crash recovery maps in-flight → terminal. Soft spot: `updating_cp` recovery **assumes success** without verifying the running image tag. | ✓ (+GAP 12A) | M | `update_cluster.go:761-800,869-951,1011-1076`; optimistic transition `update_cluster.go:1025-1030` |
| HA-13 | HA-aware CP update handoff uses a **fixed 15s sleep**, never confirms the standby actually promoted before taking the leader down → possible leaderless window; reports success regardless. | GAP | M | `update_cluster.go:593-598,706-746` |
| HA-14 | Session HMAC / secrets sync: fenced in-band (good), but `persistDPLastGoodConfigSnapshot` writes the whole snapshot **including `SessionHMAC`** as plaintext JSON (0600) — no envelope encryption like the CA key gets. | GAP (at-rest) | M | `controlplane.go:1979-1997,2058-2061` vs DP node-key encrypt `main.go:1757-1760` |
| HA-15 | Puller "no live holder" reject couples standby replication to a healthy leader lease — a witness outage stalls replication until a holder reappears (intended safety-over-availability; needs a runbook entry). | ✓ (documented) | L | `ha_fencing.go:94-97,83-85` |

### 2.4 Storage / Filesystem / Persistence / Configuration

| # | Scenario | Verdict | Sev | Evidence |
|---|----------|---------|-----|----------|
| ST-1 | `fileutil.AtomicWrite`: temp + fsync + rename + parent-dir fsync, tolerant of ENOTSUP, cleanup on every error. Adopted by blocklist, threatfeed, sslbypass, configver. | ✓ | — | `internal/fileutil/fileutil.go:19-71` |
| ST-2 | History store (Badger) non-blocking on the hot path: bounded `select … default → drop+count`, batched flush, disk-pressure `minimal` mode drops LOW-priority but keeps security events. | ✓ | — | `internal/logstore/logstore.go:328-401` |
| ST-3 | Config-version retention cap (50) enforced on every `Save`; serialized capture→save prevents stale-under-higher-version; corrupt snapshots → `ErrCorrupt`→HTTP 500, skipped in `List`. | ✓ | — | `internal/configver/configver.go:132-150`, `configversion.go:89-112,159-169` |
| ST-4 | SIGHUP reload fail-safe: bad YAML → "keeping current config"; blocklist swaps maps only after successful open+scan. | ✓ | — | `main.go:979-985,1938-1990`, `internal/blocklist/blocklist.go:188-202` |
| ST-5 | **`admin_settings.json`: concurrent goroutine writers to a fixed `.tmp`, no fsync.** `adminSettingsSave()` launches each save in a goroutine and releases the mutex before writing → interleaved bytes → corrupt JSON → next boot silently reverts **all** admin settings to defaults. | GAP | H | `admin_settings.go:407-421,327-329,132-134` |
| ST-6 | **`ui_users.json`: non-atomic write (no fsync) + fail-open-to-empty roster on corruption.** Power loss mid-save loses the entire admin roster + TOTP secrets + `default_auth_outcome`; loader starts empty with no quarantine → potential admin lockout. | GAP | H | `store.go:759-763,691-693`, `auth_startup.go:39-40` |
| ST-7 | Persistent request-log JSONL write is **synchronous + globally serialized** under one mutex on the hot path → slow disk collapses proxy throughput (head-of-line). Disk-*full* is handled (counted, once-logged). | GAP (slow-disk) | M | `internal/reqlog/reqlog.go:154-167`, `internal/fileutil/rotating.go:40-61` |
| ST-8 | Audit write **silently drops on I/O failure** (`//nolint:errcheck`, no counter) — compliance "who changed what" vanishes on full/RO disk; `GetPersistent` re-reads the whole file per query. | GAP | M/H | `internal/audit/audit.go:131-135,173-199` |
| ST-9 | Startup `logger.Fatalf` on blocklist/URL-category read errors (any non-`IsNotExist`) → **crash-loop** on permission/EIO faults. | GAP | M | `blocklist_startup.go:48-60`, `urlcategories_startup.go:22,46` |
| ST-10 | Backup is not a consistent cross-file snapshot (inputs read at different instants); residual non-atomic writers (`cdrpolicy.go:195`, `internal/scanexcl/scanexcl.go:93`, `update_cluster.go:193`). | GAP | L/M | backup pack loop `backup.go:~280`; flagged by `cluster_persistence_atomic_test.go:8` |
| ST-11 | RotatingFile keeps one archive; reopen failure after rename leaves logging wedged until restart (bounded-growth design otherwise correct). | ✓ (edge) | L | `internal/fileutil/rotating.go:44-56` |
| ST-12 | catdb corruption-recovery comment claims Badger truncate-on-corruption but `Open` sets no such option; a corrupt community DB is fatal via ST-9 coupling. | GAP (doc/behavior) | L | `internal/catdb/catdb.go:35-50`, `urlcategories_startup.go:46` |

### 2.5 Authentication / Identity / Sessions

| # | Scenario | Verdict | Sev | Evidence |
|---|----------|---------|-----|----------|
| AU-1 | Registry OIDC introspection has **no result cache** → one IdP round-trip per request, ×N providers, each 10s timeout. The legacy `OIDCAuth` *does* cache (2-min TTL); the newer registry path dropped it. | GAP | H | `auth_oidc_flow.go:344-363,608-627` (no cache field); loop `proxy.go:209-220`; contrast `auth_oidc.go:210-238` |
| AU-2 | In-flight SSO sessions **survive IdP deletion** — no `RevokeProvider`; cookies are self-contained and keep full access up to TTL (default 8h). User-delete *does* revoke. | GAP | H | `auth_idp.go:319-330`, `ui_auth.go:517-529` vs `ui_auth.go:245` |
| AU-3 | Proxy-path Basic-auth bcrypt is **not rate-limited** — correct-username + N wrong-passwords is a cache miss every time → full ~100ms bcrypt per request → CPU starvation. The `loginLimiter` guards only the admin UI. | GAP | M | `store.go:440-444`, limiter only at `ui_auth.go:48,116`, proxy call `proxy.go:223` |
| AU-4 | Lockout store is bounded + fail-closed, and TOTP failures now feed it. But it is **not persisted** (resets on restart) and **per-node** (attacker gets MaxAttempts per node in a cluster). | ✓ (+2 gaps) | M | `lockout.go:111-126,102-110`; per-node note `roadmap/edge-case-audit.md:138` |
| AU-5 | LDAP proxy auth fails closed, but the 10s timeout covers only the **dial** — `Bind`/`Search` have no per-op deadline, so a server that accepts then stalls hangs the request goroutine. | GAP | M | `auth_ldap.go:128-180` |
| AU-6 | SAML metadata & OIDC discovery fetched **once** at compile — no periodic refresh. IdP SAML signing-cert rotation breaks assertion validation until re-save/restart. (OIDC JWKs *do* auto-refresh every 15 min + serve-stale.) | GAP | M | `auth_saml.go:54-57,249-294`; JWKs OK `auth_oidc_flow.go:129-157` |
| AU-7 | IdP 5xx / network error / expired token all collapse to fail-closed "auth fail" — correct posture, but an IdP outage is indistinguishable from a brute-force spike (no distinct `idp.unreachable` metric). | ✓ (obs gap) | L | `auth_oidc.go:152-162`, `auth_oidc_flow.go:623-636` |
| AU-8 | Auth caches bounded at 5000 with eviction; HMAC-keyed keys (heap-dump safe); cached OK TTL capped at token `exp`. | ✓ | — | `store.go:236,241-258,268-285`, `auth_oidc.go:219-227` |
| AU-9 | Session HMAC key change / per-node divergence logs everyone out (fail-closed) — no rotation grace window; cluster without shared key needs affinity. | GAP | M | `session.go:390-393`, `InitRandomKey` `session.go:80-86` |
| AU-10 | TOTP: 30s step, ±1 window (~90s skew tolerance), replay closed via `counter <= lastCounter`, empty-secret fails closed. | ✓ | — | `totp.go:47-88` |
| AU-11 | Multi-IdP registry: compile is isolated (all-or-nothing staging swap; bad profile dropped, not fatal). But the **request-time provider loop is sequential and unguarded** — one slow IdP adds latency to every request that reaches it. | ✓ compile / GAP request | M | `auth_idp.go:159-165,354-376` vs loop `proxy.go:209-220` |
| AU-12 | All admin-configured IdP URLs dial through `ssrfSafeDialContext`; HTTPS+non-private pre-validated; response bodies `io.LimitReader`-capped. | ✓ | — | `auth_oidc_flow.go:64,300`, `auth_idp.go:556-565` |
| AU-13 | Registry introspection also lacks **negative caching / circuit breaker** — a permanently-invalid token amplifies one IdP call per provider per request forever. | GAP | M | `auth_oidc_flow.go:623-636`; breaker exists unused `internal/upstream/upstream.go:89-96` |

### 2.6 Background Workers / Feeds / Scanning / Alerting

| # | Scenario | Verdict | Sev | Evidence |
|---|----------|---------|-----|----------|
| WK-1 | **ClamAV daemon down → files pass UNSCANNED (fail-open), no alert/counter.** Contradicts the same file's *timeout* path, which fails **closed**. Two infra-failure modes, opposite postures. | GAP | H | `internal/secscan/secscan.go:499-514` vs timeout `secscan.go:490-495` |
| WK-2 | Remote scan sidecar down → fail-open, **but** alerted (`scan_svc_down`) + counted. Posture not admin-selectable; 30s per-request timeout stacks latency when hard-down. | ✓ (risky) | H | `internal/secscan/remote.go:95-155,84-90,105` |
| WK-3 | GeoIP cache-miss on the policy hot path fails **closed** (country allow-rule cannot match unknown country); `LookupCached` never blocks on DB/DNS. | ✓ | — | `policy.go:831-839`, `geoip.go:84-93`; tests `final_coverage_test.go:203` |
| WK-4 | GeoIP DB missing/corrupt: reader stays nil, feature degrades to "no country data" — safe, but **no staleness/health signal** (MMDBs expire silently). | GAP (obs) | M | `internal/geoip/geoip.go:23-36,71` |
| WK-5 | **Threat-feed timeout → stale-erase.** On partial failure `Sync` unconditionally replaces the maps with only what succeeded, discarding prior good entries; stamps `lastSync=now` even on failure; no backoff, no staleness alert → coverage silently shrinks for up to 6h. | GAP | H | `internal/threatfeed/threatfeed.go:150-183` |
| WK-6 | UT1 category feed failures counted but **never alerted**; fixed 24h retry, no backoff. Stale-serve is safe (last-good BadgerDB). | GAP (obs) | M | `internal/feedsync/feedsync.go:192-213,176` |
| WK-7 | Category DB (Badger) corruption: read errors → "not found" (fail-open for category-block, no crash); value-log truncate/replay on restart. | ✓ | — | `internal/catdb/catdb.go:37-50,84-100` |
| WK-8 | **Background workers have NO panic recovery.** `threatfeed.Start`, `feedsync.Start`, blocklistfeed scheduler, `startCDRHealthPoller`, `startAlertRetryLoop`, `sseBroadcaster.run` all run their loop body with no `recover()`. One panic (bad feed line, nil-map deref, a `.(time.Time)` assertion) **terminates the whole in-line proxy.** | GAP | **C** | `threatfeed.go:131-145`, `feedsync.go:171-187,224`, `cdr_health.go:65-80`, `alerts.go:46`→`store.go:511`, `events.go:75` (zero `recover()`) |
| WK-9 | Syslog on the hot path: `writeMsg` holds `s.mu` and does a **blocking 5s dial** while locked; TCP writes have **no write deadline** → a slow SIEM can stall proxy goroutines. UDP is non-blocking (acceptable). | GAP | M | `internal/syslog/syslog.go:117-146,68` |
| WK-10 | Webhook alert delivery: never blocks the producer, 30s dedup, bounded semaphore (10) → enqueue not spawn, bounded retry (3× exp backoff), 500-cap queue drop-on-full, SSRF-guarded, atomic persist. | ✓ | — | `internal/alerts/store.go:298-343,392-500` |
| WK-11 | SSE slow client: non-blocking `select … default → close+evict`, 256-client cap, runs off the request path. | ✓ | — | `internal/sse/sse.go:66-78,46` |
| WK-12 | YARA compile failure loads remaining rules (never disables engine); regex timeout + saturation cap with admin-selectable fail-closed/open posture + alerts. Residual: abandoned regex goroutines are counted but never cancelled (memory held until they finish). | ✓ (+leak caveat) | L/M | `internal/yara/yara.go:98-130,584-602,540` |
| WK-13 | Ticker loops have **no jitter** + immediate sync-on-boot → fleet-wide thundering herd against public feeds (URLhaus/OpenPhish/NethServer mirror) on rollout and every interval. | GAP | M | `threatfeed.go:132-135`, `feedsync.go:173-176`, blocklistfeed 60s / cdr_health 15s |
| WK-14 | Release-catalog autoseed: stage → read-only verify+freshness+rollback → atomic swap with move-aside `.bak` restore-on-failure; fail-closed, no unsigned auto-download. | ✓ | — | `release_autoseed.go:49-122,100-116` |

---

## 3. Risk Matrix (likelihood × impact)

| Risk ID | Finding | Likelihood | Impact | Priority |
|---------|---------|------------|--------|----------|
| R1 | WK-8 background-worker panic kills proxy | Medium | Critical (total outage of an in-line appliance) | **P0** |
| R2 | WK-1 ClamAV down → malware passes unscanned, silent | Medium (AV daemon flaps) | High (security control dark) | **P0** |
| R3 | WK-5 threat-feed stale-erase, silent | High (transient feed outage is routine) | High (coverage shrinks) | **P0** |
| R4 | ST-5 / ST-6 admin_settings / ui_users non-atomic → config/credential loss, admin lockout | Medium (rapid UI edits / power loss) | High | **P1** |
| R5 | CA-1 / CA-2 / CA-3 CA silent fail-open / expired-still-signs | Low-Medium | High (inspection dark / outage) | **P1** |
| R6 | AU-2 stale SSO after IdP delete | Low (deliberate deletes) | High (security: revoked IdP still admits) | **P1** |
| R7 | PX-3 half-open relay leak | Medium (mobile/flaky clients) | Medium-High (FD/goroutine exhaustion) | **P1** |
| R8 | HA-7 unfenced resumed leader never recovers | Low | High (indefinite write outage, manual fix) | **P1** |
| R9 | PX-6 no global conn cap / limiter off by default | Medium (flood) | High (FD exhaustion) | **P1** |
| R10 | AU-1 / AU-13 no OIDC introspection cache | High (every request) | Medium (latency + IdP amplification) | **P2** |
| R11 | WK-9 syslog blocking on hot path | Medium (slow SIEM) | Medium (latency) | **P2** |
| R12 | WK-13 / HA-11 no ticker jitter | Medium (rollout) | Medium (self-DDoS / herd) | **P2** |
| R13 | ST-8 silent audit-trail loss | Low | Medium-High (compliance) | **P2** |
| R14 | HA-9 enrollment nil-deref panic | Low (corrupted state) | Low (RPC-scoped) | **FIXED** |

---

## 4. Recovery Assessment

**Automatic recovery — present and correct:** upstream circuit breaker + health loop (PX-14),
lease keepalive/self-fence and epoch ratchet (HA-3/HA-8), rolling-update crash recovery to terminal
states (HA-12), webhook retry queue (WK-10), catalog autoseed atomic swap + restore (WK-14),
Badger value-log replay (WK-7), SIGHUP last-good fallback (ST-4).

**Automatic recovery — missing (manual intervention required):**
- **HA-7** — an unfenced resumed leader has no background re-acquire; a transient etcd blip during
  a restart becomes an indefinite write outage requiring an operator restart. *Highest-value
  recovery gap.*
- **CA-2 / CA-13** — a failed CA persist/rotation is never retried before the fixed 24h tick, and
  the failure is invisible.
- **WK-5** — a feed that fails during its sync window is not fast-retried; coverage stays degraded
  until the next 6h tick.
- **ST-5 / ST-6 / ST-9** — corrupted state files are not quarantined; recovery is a silent revert
  to defaults (ST-5/6) or a crash-loop (ST-9), both requiring human diagnosis.

**Manual recovery paths that exist:** admin lockout after ui_users loss is recoverable via the
legacy `-user/-pass` flags/env; a wedged rolling update halts to an operator-inspectable state;
config rollback offers versioned snapshots (skipping corrupt ones).

---

## 5. Operational Impact

The dominant operational hazard is **invisible degradation**. An operator cannot act on a control
they cannot see fail. Concretely, add alerts + metrics for:

- `culvert_ssl_inspection_ready` gauge (0 when CA-3 fires) and a `cert_expiry` **early-warning**
  independent of rotation (CA-5).
- `culvert_ca_persist_failures_total` + alert (CA-2, CA-13).
- ClamAV scan-error counter + `scan_svc_down`-style alert (WK-1), matching the remote-scanner path.
- Per-feed `last_success` + staleness alert at >2× interval (WK-5, WK-6).
- GeoIP DB load-failure / age alert (WK-4).
- `idp.unreachable` distinct from auth-failure (AU-7).
- Audit write-failure counter surfaced on `/healthz` (ST-8), matching reqlog.

Add **jitter** to every feed/poll ticker (WK-13, HA-11) to stop fleet self-DDoS on rollout.

---

## 6. Security Impact

Fail-open security controls are the headline:
- **WK-1** (ClamAV) and **CA-3** (SSL inspection) both silently *stop enforcing* under
  infrastructure failure — malware and un-inspected TLS flow with a green dashboard.
- **PX-2** (all-upstreams-down → direct) bypasses a mandatory egress/DLP chokepoint.
- **WK-5** shrinks threat-intel coverage silently.
- **AU-2** lets a deleted/compromised IdP's sessions keep full admin access up to the TTL.
- **AU-3** is a practical CPU-starvation DoS via un-rate-limited bcrypt on the proxy path.
- **CA-14** can resurrect a revoked session token after a crash.

Where the posture is *deliberately* fail-open for availability (PX-2, HA-1, WK-1/WK-2), it should
be an **admin-selectable** `fail_closed | fail_open_with_alert` toggle, not a hard-coded silent
default — mirroring the mature YARA posture model (WK-12).

Genuinely strong security-under-failure: the fencing lease (HA-2/3/4), KEK-at-rest (CA-7), SSRF
guards on all IdP/webhook egress (AU-12, WK-10), and geo fail-closed (WK-3).

---

## 7. Data-Integrity Impact

`fileutil.AtomicWrite` (ST-1) is the correct primitive and is used by the highest-churn stores.
The integrity gaps are the **files not yet migrated onto it**: `admin_settings.json` (ST-5),
`ui_users.json` (ST-6), the session revocation list (CA-14), and the residual `os.WriteFile`
writers (ST-10). The fix is largely mechanical: route every JSON state writer through
`fileutil.AtomicWrite` and hold the writer lock across the serialize+write. Backup consistency
(ST-10) additionally wants a quiesce or config-version snapshot as the atomic unit.

---

## 8. Suggested Improvements (ranked)

1. **P0 — `safeGo(name, fn)` supervisor for every background worker** (WK-8, PX-4): a shared
   wrapper that `recover()`s the loop body, logs + increments a `worker_panics_total{worker}`
   metric, and restarts with backoff. Route all `Start`/poller/relay goroutines through it. This
   single change removes the only *Critical* risk.
2. **P0 — ClamAV error posture** (WK-1): admin-selectable `clamav_on_error: fail_closed |
   fail_open_with_alert`, a `scan_clam_error` counter, and an alert — mirror the remote-scanner and
   YARA models.
3. **P0 — Threat-feed last-good retention** (WK-5): replace a feed's entries only on that feed's
   success; track per-feed `lastSuccess`; alert on staleness; fast-retry with backoff.
4. **P1 — Migrate `admin_settings.json` / `ui_users.json` / revocation list to
   `fileutil.AtomicWrite`** (ST-5, ST-6, CA-14) and hold the writer lock across the write; quarantine
   (`.corrupt`) instead of silent-revert on load failure.
5. **P1 — CA fail-closed observability** (CA-1, CA-2, CA-3, CA-5, CA-13): guard `signLeaf` against
   an expired CA; treat `SaveCA`/rotation failure as a first-class alert + metric; fire an early
   `cert_expiry` warning; expose an `ssl_inspection_ready` gauge; optional `--ca-required`
   fail-closed mode.
6. **P1 — `RevokeProvider(id)`** (AU-2) called from the IdP delete/disable path.
7. **P1 — Idle deadline on all raw relays** (PX-3): re-arming read deadline (reuse the
   `stallDetectReadCloser` pattern) so half-open peers can't leak.
8. **P1 — Background lease re-acquire** (HA-7) whenever `role==leader && lease!=nil &&
   leaseEpoch==0`.
9. **P1 — Global connection cap + enable the per-IP limiter by default + wire it into SOCKS5**
   (PX-5, PX-6).
10. **P2 — Registry OIDC introspection positive+negative cache + circuit breaker** (AU-1, AU-13);
    per-op LDAP deadline (AU-5); jitter on all feed/poll tickers (WK-13, HA-11); async/deadlined
    syslog (WK-9); confirm-before-handoff in `updateCPWithHA` (HA-13); verify running version on
    `updating_cp` recovery (HA-12A); encrypt secret fields of the DP last-good snapshot (HA-14).

---

## 9. Suggested PR (this PR)

This PR ships the review document plus **one contained, verified fail-closed fix**:

- **HA-9 — enrollment `AllowCIDR` nil-deref panic.** `ValidateAndConsumeToken` discarded the
  `net.ParseCIDR` error; a corrupted persisted `AllowCIDR` yielded a nil `*net.IPNet` and
  `cidr.Contains(ip)` panicked inside the enrollment RPC path. Now checks the error and fails
  closed (`enrollment.go`). Regression test `TestTokenValidate_CorruptedCIDR_FailsClosed`
  (`enrollment_test.go`) injects a malformed CIDR into the token map (bypassing the creation-time
  validation that `GenerateToken` already enforces) and asserts an error rather than a panic.

The larger remediations (§8) are intentionally *not* bundled here — each is its own reviewable
change with its own test surface, and several (safeGo, atomic-write migration, CA observability)
touch security-critical paths that warrant isolated review.

---

## 10. Required Tests (for the follow-up remediations)

| Finding | Test |
|---------|------|
| WK-8 / PX-4 | Inject a panicking collaborator into each worker's loop; assert the worker recovers, the ticker keeps running, and the process survives. |
| WK-1 | Fake `ClamScanner.Scan` returns an error; assert `ScanBody` blocks when posture=fail_closed and fires an alert. |
| WK-5 | Stub one feed source to fail; assert prior entries retained and `lastSuccess` not advanced. |
| ST-5 / ST-6 | Fire N concurrent saves; assert the file always parses to one committed state and no `.tmp` leftover; truncate mid-record → assert quarantine, not silent-empty. |
| CA-1 | Seed an expired CA via `SetCAForTest`; assert `GetCert` errors + alert. |
| CA-2 | Point `caPath` at a read-only dir; drive `RotateIfNeeded`; assert a failure alert (not a success alert). |
| AU-2 | Mint a session with `Provider:"idpA"`; delete idpA; assert the cookie now fails to decode. |
| AU-3 | Assert the Nth rapid wrong-password attempt for a valid user is rejected before bcrypt runs. |
| PX-3 | Open a tunnel, half-close the client without FIN; assert goroutine count returns to baseline within the idle window. |
| PX-6 | Global cap K; open K+1 conns across distinct IPs; assert rejection + stable FD count. |
| HA-7 | Resume denied → etcd becomes reachable → assert `WriteAllowed()` becomes true within a bounded time with no operator action. |
| HA-13 | Standby refuses to promote → assert the leader does NOT take itself down and the update aborts. |
| **HA-9** | **`TestTokenValidate_CorruptedCIDR_FailsClosed` — shipped in this PR (green).** |

---

## 11. Residual Risk

Even with §8 fully implemented, these remain by design and should be explicitly owned in the
operator runbook:

- **HA-1 / HA-15** — a long-partitioned DP enforces last-good policy (bounded only by an operator
  staleness ceiling if added); a lease-mode witness outage stalls replication *and* writes until
  etcd returns. This is deliberate safety-over-availability.
- **HA-5** — legacy 2-node `--ha-auto-failover` without a witness can dual-write on a partition
  (RISK-001). The remediation is organizational: steer operators to the fencing lease.
- **CA-10 / AU-9** — NTP is a hard dependency; large clock skew breaks fresh leaves and session
  windows, and a deliberate HMAC rotation is an instant mass-logout with no grace window.
- **AU-4** — per-node, non-persisted lockout means a cluster attacker gets `MaxAttempts` per node;
  gossiping the counters (using the revocation-list gossip as a template) is the fix but is not
  free.
- **PX-2 / WK-1 / WK-2** — where fail-open is chosen for availability, residual malware/egress
  exposure exists during the outage window; the mitigation is the alert + the admin fail-closed
  toggle, not elimination.

The bright spots — the fencing lease, KEK-at-rest, atomic-write foundation, bounded async
history/alert/SSE paths, and geo/OCSP fail-closed posture — show the codebase already knows how to
fail safely. The work ahead is applying that same discipline (alert + metric + fail-closed toggle +
atomic write + panic recovery) uniformly across the paths that still degrade in silence.
