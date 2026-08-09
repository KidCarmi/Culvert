# Culvert Chaos-Engineering / Failure-Mode Review

**Date:** 2026-07-04
**Scope:** Full failure-domain sweep across the proxy data path, CA/TLS/sessions, cluster/HA
(Control-Plane ↔ Data-Plane), storage/persistence, authentication/identity, and background
workers/feeds/scanning/alerting.
**Method:** Evidence-first source review. Every finding cites `file:line`. No behavior was
inferred without reading the code path. Failure modes were assessed against the project's stated
posture — **default deny, fail closed when recovery is impossible, graceful degradation otherwise.**

This document is a standing register. It records where Culvert already survives failure safely
(and *why*, by code path) and where it does not. The one code change shipped alongside the original
review is a fail-closed fix for a latent nil-deref panic in the enrollment path (Finding HA-9);
everything else is triaged below with a suggested PR and required tests for follow-up.

---

## 0. Revision log

**2026-08-09 — CHAOS-28 sweep (the Root CA across its lifecycle).**

The inspection CA is the one control whose failure produces no error anywhere INSIDE the
process. Row **CA-1** was still live on `main`, and worse than recorded: (1) `signLeaf` signed
with an expired CA because `x509.CreateCertificate` does not check the parent's validity and
nothing else did either — verified by running the new gate against the pre-fix engine, where
the sign SUCCEEDED — while `handleTunnel`'s `Ready()` gate (`caCert != nil`) admitted the
session, so every inspected client got a leaf chained to a dead issuer and `/healthz` reported
`ssl_inspection: ready` throughout; (2) leaf `NotAfter` was an unconditional `now+24h`, so
leaves minted in the CA's last day OUTLIVED their issuer; (3) **CA-2** — a rotation whose
`SaveCA` failed still logged and alerted success, so the only recovery path FS-1 has could
silently not persist and mint a different root on every boot; (4) **CA-4** — the rotation loop
made its FIRST check 24h after boot, i.e. never at the moment an operator restarts to recover;
and (5) newly found, unrecorded: `cacheOrder` was appended on every TTL REFRESH while the map
entry was overwritten, so the eviction branch (keyed on map length) never fired and the slice
grew unbounded behind a bounded map — a leak that scales with UPTIME on an ordinary steady
working set. All five fixed. The load-bearing decision was to fail **CLOSED** (502 before the
CONNECT 200) rather than fold expiry into `Ready()`: the one-word fix would have converted an
availability outage into a silent, fleet-wide UNINSPECTED-egress outage — the §1 theme — and is
now blocked by an executable negative assertion. See §16 and
`docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-08-09.md`.

**2026-08-07 — CHAOS-27 sweep (the alert plane under an alert storm).**

Row **WK-10** marked webhook delivery resilient, and every bound it cites is real — but all of
them bound *delivery*, and the two defects found here are in front of delivery. (1) The delivery
client was built **per attempt**, so every delivered alert abandoned an `http.Transport` holding
a keep-alive socket with a zero-value `IdleConnTimeout` (= never expires): one FD + two
goroutines leaked per alert, until the *receiver* closed. (2) The Q17 dedup map was unbounded on
an **attacker-controlled key space** (the key embeds the requested host) and fully rescanned
under a process-wide mutex on **every** dispatch — 230,603 ns/op of mutex-held work per alert at
the flood steady state, growing. Both amplify with the security controls working (more blocks →
more alerts), so the alerting plane degraded the gateway hardest while it was under attack, and
FS-1's terminal state is the *proxy* plane running out of descriptors. Both fixed with gates
proven to fail against the pre-fix code. See §15 and
`docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-08-07.md`.

**2026-08-06 — CHAOS-25 sweep (HA sync-loop + scanner-goroutine panic containment).**

Closes two of the three paths CHAOS-24 explicitly left unguarded (§12.6): the **HA standby sync
loop** and **`internal/yara`'s per-match goroutine**. Both needed the fail-closed analysis §12.2
demanded rather than a mechanical guard — and the HA one turned out to hold a **split-brain
hazard in the obvious fix**, in the mirror image of the lease-keepalive case. See §14. The MCP
runtime listener remains open and is re-scoped there.

**2026-08-04 — CHAOS-24 sweep (background-worker panic containment).**

Re-verified the standing register against current `main`. Several original findings have since
shipped and are marked **CLOSED** in place below (WK-5 threat-feed stale-erase, ST-5/ST-6 atomic
writes, ST-7 async request log, WK-9 async syslog, PX-3 idle-bounded relays, PX-2 observable
direct-egress fallback). The register's **only remaining Critical item — WK-8 — was still open**,
and this revision closes it. See §12 for the new finding, the split-brain hazard it uncovered in
the *obvious* fix, and what is deliberately left for follow-up.

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
| PX-2 | Circuit breaker / all-upstreams-down **fails open to direct** egress, bypassing the parent-proxy control. | GAP → **PARTLY CLOSED** (CHAOS-11: still fail-open by design, now counted + alerted + surfaced) | H | `internal/upstream/upstream.go:240,267` (`// all upstreams down — fall back to direct`) |
| PX-3 | Raw relays (CONNECT bypass, WebSocket, non-TLS fallback) have **no idle/read deadline** — a half-open peer leaks a goroutine + FD + 128KB pooled buffer indefinitely. Only the SSL-inspect *request loop* arms a deadline. | GAP → **CLOSED** (CHAOS-03 `idleCopyCounted`, `proxy_tunnel.go`) | H | `bidiRelayCounted` `proxy.go:1431,1262`; contrast deadline at `proxy.go:1621` |
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
| CA-1 | **Expired Root CA keeps signing leaves** — no `time.Now().After(caCert.NotAfter)` guard on the sign path. Every inspected client then sees an opaque expired-issuer TLS error (site-wide inspected-HTTPS outage) with no fast-fail signal. | GAP → **CLOSED** (CHAOS-28: fail-closed 502 at dispatch + `ErrCAUnusable` at the sign path + `culvert_ca_usable`/`_expires_in_seconds` + `ssl_inspection: expired`) | H | was: `internal/ca/ca.go` `signLeaf`; now `internal/ca/validity.go`, `proxy_tunnel.go` `failClosedUnusableCA` — see §16 |
| CA-1b | **Forged leaf `NotAfter` was not clamped to the issuer's** — leaves minted in the CA's final 24h claimed validity past their own issuer, the state that makes an expiry incident hardest to diagnose (leaf looks valid, only the chain fails). | GAP → **CLOSED** (CHAOS-28, `clampLeafValidity`, both ends) | M | was: `internal/ca/ca.go` `signLeaf` `NotAfter: now+24h`; see §16 |
| CA-2 | Rotation `SaveCA` failure (disk full / read-only) is **swallowed** — logged, still returns `true`, still fires the "rotated successfully" alert. New CA lives only in RAM; next restart reloads the old near-expiry bundle. | GAP → **CLOSED** (CHAOS-28, `RotationPersistFailureObserver` + distinct log wording + `culvert_ca_rotation_persist_failures_total` + CA-panel banner) | H | was: `internal/ca/ca.go` `RotateIfNeeded`; see §16 |
| CA-3 | Corrupt bundle / wrong `CULVERT_CA_PASSPHRASE` / expired-at-rest CA at startup → **fail OPEN**: inspection silently disabled, traffic falls through to SSL-bypass (no DPI/CDR/file-blocking). Log line only, no alert, no `ssl_inspection_ready` gauge. | GAP (silent) | H | `rootca_startup.go:40-44`; `handleTunnel` gate `proxy.go:1335`; `ImportBundle` `ca.go:286` |
| CA-4 | Auto-rotation loop: **no immediate startup check** (24h blind spot after boot), **no retry/backoff** on failure (waits a fixed 24h). | GAP → **PARTLY CLOSED** (CHAOS-28: the startup blind spot is closed — one guarded round runs before the ticker, sharing the CHAOS-24 guard. Retry/backoff on a FAILED rotation still waits the full 24h) | M/H | `ca.go` `StartCAAutoRotation`; see §16 |
| CA-5 | `cert_expiry` alert only fires **on rotation**, not as an early warning — contract says "fired on startup if ≤30 days" but the only producer is the rotation observer. | GAP (contract mismatch) | M | producer `ca.go:45-53`; contract `internal/alerts/store.go:17` |
| CA-6 | OCSP fails **closed** when a cert lists responders and none answer; `VerifyConnection` re-checks resumed sessions. Caveats: nil-issuer → fail-open; OCSP client has no SSRF guard on the peer-controlled responder URL. | ✓ (+2 caveats) | L/M | `internal/ocsp/ocsp.go:177-181`, `ocsp.go:41-56`; caveats `ocsp.go:139-142,187-206` |
| CA-7 | KEK-at-rest: rejects too-permissive/wrong-size files (never chmod-fixes, never silently regenerates), uses `os.Link` EEXIST to avoid racing mints, fails closed on decrypt error. | ✓ | — | `kek.go:174-239`, `cluster_ca_keyatrest.go:95-181` |
| CA-8 | Session HMAC key is **random per-restart by default** (no env/config secret) → all admin sessions invalidated on every single-node restart. | GAP | M | `session.go:38-49`, `internal/session/session.go:80-86` |
| CA-9 | Session HMAC runtime rotation / cluster sync is race-safe (lock-guarded set/read, hex+len validation before install, redacted on export). | ✓ | — | `internal/session/session.go:51-55,422-429`, `controlplane.go:1848-1862` |
| CA-10 | Clock skew/rollback: sessions use wall-clock `time.Now()`; leaf certs backdate only 5 min (`ca.go:747`) vs the UI cert's 1h — >5 min skew makes fresh leaves "not yet valid" to clients. | GAP | M | `internal/session/session.go:408`, `internal/ca/ca.go:747` vs `internal/uitls/uitls.go:52` |
| CA-11 | Leaf-cert cache has **no single-flight** — N concurrent misses for one host each sign independently; TTL expiry is synchronized (thundering herd). | GAP (re-scoped by CHAOS-28: the perf-F3 shared leaf key removed the dominant per-miss cost — P-256 keygen — so the herd is materially cheaper than when first recorded) | M → L/M | `internal/ca/ca.go` `GetCert` |
| CA-16 | Leaf-cache **`cacheOrder` slice grew on every TTL REFRESH** while the map entry was overwritten. `len(cache)` never changed, so the eviction branch never fired: an unbounded slice behind a bounded map, growing with UPTIME on an ordinary steady working set (W=5,000 hosts ⇒ ~120k strings/day). Invisible to `culvert_cert_cache_size`, which reports the bounded map. | NEW → **CLOSED** (CHAOS-28: append only for an untracked host; behavior-preserving for eviction — duplicate entries always resolved to "already gone") | M | was: `internal/ca/ca.go` `GetCert`; see §16 |
| CA-12 | Upstream & client MITM handshakes inherit only `r.Context()` (no explicit handshake deadline); a slowloris handshake ties up the goroutine. Good: uses `HandshakeContext`, not `Handshake()`. | GAP | M | `proxy.go:1503,1591` |
| CA-13 | Cluster CA rotation mirrors CA-2: every failure branch logs-and-returns with no alert/metric. Silent failure → cluster-wide enrollment break at expiry. | GAP (**next sweep** — CHAOS-28 closed the inspection-CA half as CA-2; this is the same defect class in the OTHER CA, with a different lifecycle and blast radius) | M | `enrollment.go:1189-1245` |
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
| ST-5 | **`admin_settings.json`: concurrent goroutine writers to a fixed `.tmp`, no fsync.** `adminSettingsSave()` launches each save in a goroutine and releases the mutex before writing → interleaved bytes → corrupt JSON → next boot silently reverts **all** admin settings to defaults. | GAP → **CLOSED** (`fileutil.AtomicWrite`, `admin_settings.go:660`) | H | `admin_settings.go:407-421,327-329,132-134` |
| ST-6 | **`ui_users.json`: non-atomic write (no fsync) + fail-open-to-empty roster on corruption.** Power loss mid-save loses the entire admin roster + TOTP secrets + `default_auth_outcome`; loader starts empty with no quarantine → potential admin lockout. | GAP → **CLOSED** (`fileutil.AtomicWrite`, `store.go:887`) | H | `store.go:759-763,691-693`, `auth_startup.go:39-40` |
| ST-7 | Persistent request-log JSONL write is **synchronous + globally serialized** under one mutex on the hot path → slow disk collapses proxy throughput (head-of-line). Disk-*full* is handled (counted, once-logged). | GAP → **CLOSED** (async bounded queue + single drainer, `internal/reqlog/persist.go`) | M | `internal/reqlog/reqlog.go:154-167`, `internal/fileutil/rotating.go:40-61` |
| ST-8 | Audit write **silently drops on I/O failure** (`//nolint:errcheck`, no counter) — compliance "who changed what" vanishes on full/RO disk; `GetPersistent` re-reads the whole file per query. | GAP → **CLOSED (silent-loss half)** — every lost entry counted (`audit.WriteErrors()`), first failure logged, wired into the storage-health plane (degraded contract row + `storage_write_failed` alert), surfaced on `/api/stats`, `/metrics`, `/healthz` and the dashboard. Residual: persistence stays best-effort (an admin change still succeeds over a failing disk) and the `GetPersistent` full-file re-read is untouched — see §13 | M/H | `internal/audit/audit.go` (`countWriteError`, `SetWriteFailureObserver`), `storage_health.go` init |
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
| WK-5 | **Threat-feed timeout → stale-erase.** On partial failure `Sync` unconditionally replaces the maps with only what succeeded, discarding prior good entries; stamps `lastSync=now` even on failure; no backoff, no staleness alert → coverage silently shrinks for up to 6h. | GAP → **CLOSED** (per-source `replacedSources` replacement, `threatfeed.go` `applySync`) | H | `internal/threatfeed/threatfeed.go:150-183` |
| WK-6 | UT1 category feed failures counted but **never alerted**; fixed 24h retry, no backoff. Stale-serve is safe (last-good BadgerDB). | GAP (obs) | M | `internal/feedsync/feedsync.go:192-213,176` |
| WK-7 | Category DB (Badger) corruption: read errors → "not found" (fail-open for category-block, no crash); value-log truncate/replay on restart. | ✓ | — | `internal/catdb/catdb.go:37-50,84-100` |
| WK-8 | **Background workers have NO panic recovery.** `threatfeed.Start`, `feedsync.Start`, blocklistfeed scheduler, `startCDRHealthPoller`, `startAlertRetryLoop` all run their loop body with no `recover()`. One panic (bad feed line, nil-map deref, a `.(time.Time)` assertion) **terminates the whole in-line proxy.** | GAP → **CLOSED (CHAOS-24)** | **C** | was: `threatfeed.go:131-145`, `feedsync.go:171-187`, `cdr_health.go:65-80`, `alerts.go:46`→`store.go:511`. Now guarded per ROUND — see §12 |
| WK-9 | Syslog on the hot path: `writeMsg` holds `s.mu` and does a **blocking 5s dial** while locked; TCP writes have **no write deadline** → a slow SIEM can stall proxy goroutines. UDP is non-blocking (acceptable). | GAP → **CLOSED** (async drain goroutine owns the socket, `internal/syslog`) | M | `internal/syslog/syslog.go:117-146,68` |
| WK-10 | Webhook alert delivery: never blocks the producer, 30s dedup, bounded semaphore (10) → enqueue not spawn, bounded retry (3× exp backoff), 500-cap queue drop-on-full, SSRF-guarded, atomic persist. | ✓ **for delivery**; the two bounds MISSING in front of delivery are CHAOS-27 → **CLOSED** (§15) | — | `internal/alerts/store.go` |
| WK-11 | Alert **socket** cost: the delivery client was built per attempt, abandoning an `http.Transport` whose zero-value `IdleConnTimeout` never expires — one FD + two goroutines leaked per delivered alert. The semaphore bounds concurrent deliveries, not cumulative sockets. Terminal state: `accept: too many open files` in the PROXY plane. | GAP → **CLOSED** (CHAOS-27, shared pooled `deliveryClient`) | **H** | was: `internal/alerts/store.go` `deliverAttempt`; see §15 |
| WK-12 | Alert **dedup bookkeeping**: unbounded map on an attacker-controlled key space (key embeds the requested host, same input `topHosts` is capped for), rescanned `O(n)` under a process-wide mutex on every dispatch (230,603 ns/op at the flood steady state, growing). Dedup runs *before* the semaphore and the retry queue, so neither bounds it. | GAP → **CLOSED** (CHAOS-27, 4096 cap + amortised prune + eviction counter) | **H** | was: `internal/alerts/store.go` `dedupSuppressed`; see §15 |
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
| R13 | ST-8 silent audit-trail loss | Low | Medium-High (compliance) | **CLOSED (silent-loss half)** — see §13 |
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
- ~~Audit write-failure counter surfaced on `/healthz` (ST-8), matching reqlog.~~ **Shipped — see §13.**

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

---

## 12. CHAOS-24 — Background-worker panic containment (fail-closed)

**Date:** 2026-08-04 · **Closes:** WK-8 / risk **R1**, the register's only Critical item.

### 12.1 Failure scenario

Go terminates the process on an unrecovered panic in **any** goroutine. Culvert is an in-line
security appliance, so a panic in a long-lived background worker is a **total gateway outage** —
every in-flight tunnel dropped — and several of those workers parse **third-party data the
operator does not control** (URLhaus/OpenPhish bodies, the UT1 tarball, operator-configured
blocklist feeds). A malformed feed row was a remote availability trigger.

The M1 crash plane (`crashguard.go`) already covered the proxy plane, the admin plane, and four
detached go-sites (`alert`, `geo`, `socks5`, relay). It did **not** reach the long-lived worker
loops, and `internal/*` leaf packages cannot import `package main` (ADR-0003), so the workers that
live in `internal/` had no way to reach the sink at all.

**Verified unguarded before this change** (zero `recover()` on the loop body):

| Worker | Consequence of the panic |
|--------|--------------------------|
| `internal/threatfeed` sync loop | process death, triggered by feed content |
| `internal/feedsync` UT1 sync loop | process death, triggered by remote tarball content |
| `internal/blocklistfeed` scheduler | process death, triggered by feed content |
| `internal/saasfeed` sync loop | process death |
| `internal/alerts` retry loop | process death; alert re-delivery stops |
| `internal/reqlog` drain goroutine | process death — **and see §12.3** |
| `internal/syslog` drain goroutine | process death over a SIEM write |
| `internal/upstream` health loop | process death; tripped breakers never close |
| `ca.go` CA auto-rotation | process death; CA silently never rotates again |
| `cdr_health.go` poller | process death; health snapshot freezes green |
| `dp_enrollment.go` cert renewal | process death; node's mTLS identity expires |
| `connlimit_startup.go` cleanup | process death; limiter maps grow unbounded |
| `logstore.go` retention janitor | process death; volume fills |
| `metrics.go` counter checkpoint | process death |
| `ha_lease.go` fencing keepalive | process death — **and see §12.2** |

### 12.2 The finding inside the finding: the obvious fix creates a split brain

The reflexive fix — `defer recover()` at the top of each worker goroutine — is **worse than the
bug** on two of these paths, because it converts a loud crash into a *silent permanent stall*
while the process keeps reporting healthy.

On the **fencing-lease keepalive** it is actively dangerous. If that goroutine returns, the node
keeps `role=leader` and `leaseEpoch != 0`, so `WriteAllowed()` stays **true** — but nothing renews
the etcd lease. The lease expires, a standby legitimately acquires it, and two nodes now believe
they hold write authority. Panic containment would have **manufactured the exact split brain
ADR-0005 exists to make impossible.** Swallow-and-retry is unsafe for the same reason: if the
panic is deterministic, every round dies *before* the validity-window check in `leaseRenewOnce`,
so the node holds authority forever on the strength of an ever-staler confirmation.

Adopted semantics: **guard the round, never the goroutine** — and where "keep going" is not the
safe answer, the caller branches on the panic and fails closed. `leaseRenewRound` treats a
panicking round as exactly what it is — a round that did **not** confirm the lease, the same
epistemic state as a transport failure — and charges it against the last etcd-confirmed validity
window (`fenceIfLeaseWindowElapsed`, including `haLeaseWriteMargin`). Containment therefore cannot
extend a node's write authority by even one tick.

### 12.3 Why the request-log drain is the other special case

`reqlog.Add` **blocks** the caller when the queue is full — the JSONL file is the durable audit
record, so a saturated queue parks the producer rather than discarding it. That makes the drain
goroutine load-bearing for the **proxy request path**, not just for logging. If it ever stops
consuming, every request goroutine eventually parks in `Add` and the gateway wedges: no crash, no
restart, no alert, just a proxy that stops answering. A goroutine-level guard there would trade a
recoverable crash for an unrecoverable hang. The guard is per round, and `drainRound`'s named
return keeps its zero value on panic so the loop always continues.

**Keeping the goroutine alive is necessary but not sufficient** (P1 from external review of the
first cut). `bufio.Writer.Flush` clears its buffer only *after* the underlying `Write` returns
(`b.n = 0` is its last statement), so a `Write` that **panics** unwinds with the batch still
buffered. Reusing that writer replays the poisoned bytes on every later flush — with a
deterministic, content-triggered fault the drain goroutine stays alive and healthy-looking while
**nothing ever reaches the durable audit file again.** That is the same silent-permanent-loss class
the guard exists to remove, just relocated. The recovery path therefore **discards** the batch
(`batch.discard`) and charges its records to `WriteErrors`, so the loss is bounded to one batch and
visible instead of unbounded and silent. Pinned by `TestDrain_PoisonedBufferIsDiscarded`, which
fails against the un-discarded version with *0 of 25* post-poison entries reaching the sink.

### 12.4 What shipped

- `internal/obs/guard.go` — `Guard` / `SafeCall` / `SetPanicSink`, mirroring the existing `SetSink`
  seam. `package main` publishes `recordCrash` as the sink (`crashguard.go` `init`), so a leaf
  worker panic lands in the **same** pipeline as a proxy/admin panic:
  `culvert_crash_records_total{component}`, the system-actor audit entry, the bounded redacted
  `lastCrash` record. **No new observability surface was introduced.**
- `crashguard.go` — `runGuarded(component, fn) (panicked bool)` for the `package main` loops. The
  bool exists for the fail-closed callers.
- Per-round guards applied to all 15 workers in the §12.1 table.
- `ha_lease.go` — `leaseRenewRound` + `fenceIfLeaseWindowElapsed` (fail-closed, §12.2).
- `internal/syslog` — guarded locally with a `panics` counter rather than importing `obs`: that
  package's header declares it a stdlib-only leaf, and a panicked line is counted as the drop it
  actually is.
- `dp_enrollment.go` — a panicking renewal round raises the **same operator alert** as a renewal
  error, because operationally it is one: the renewal did not happen. The panic *value* is never
  put in the alert (it can embed attacker-shaped text or a secret); `recordCrash` owns the bounded,
  redacted record.

### 12.5 Tests

| Gate | Test |
|------|------|
| Contained round is recorded, loop survives, panic text scrubbed (CWE-117) | `chaos_worker_panic_test.go` `TestChaos24_RunGuarded_*`, `TestChaos24_ContainedPanicTextIsScrubbedForLogInjection` |
| Leaf-package panic reaches main's crash pipeline (seam wiring) | `TestChaos24_ObsSeamRoutesLeafPanicsIntoTheCrashPipeline` |
| **Split-brain gate** — panicking keepalive self-fences, does not keep write authority | `TestChaos24_LeaseKeepalivePanic_FailsClosed` |
| Fail-closed is not trigger-happy — a panic inside a valid window does not fence | `TestChaos24_LeaseWindowStillValid_PanicDoesNotFence`, `TestChaos24_LeaseFenceRespectsWriteMargin` |
| **Anti-wedge gate** — drain keeps consuming; producers never block | `internal/reqlog/persist_panic_test.go` `TestDrain_*` |
| **Anti-poison gate** — a panicking flush discards its batch instead of replaying it forever | `TestDrain_PoisonedBufferIsDiscarded` |
| Primitive semantics, sink-panic containment, nil-sink cannot silence | `internal/obs/guard_test.go` |

Both regression gates were verified to **fail without the fix**: removing the drain guard
reproduces process death (`panic: simulated sink fault during flush`), and substituting the naive
swallow-and-retry keepalive guard trips the split-brain assertion.

### 12.6 Residual risk

- **Containment is not repair.** A worker whose round panics *every* tick is contained and counted
  but makes no progress — the feed goes stale, the CA does not rotate. The signal is
  `culvert_crash_records_total{component}` being non-zero, which is 0 in a healthy process; an
  alert rule on it is the operator-facing follow-up (not shipped here).
- **Deliberately still unguarded:** the HA standby/leader sync loops (`ha.go`), the MCP runtime
  listener, and `internal/yara`'s per-match goroutine. Each needs its own fail-closed analysis of
  the kind §12.2 required — they are *not* mechanical, and bundling them would have hidden the
  lease change in a large diff. Tracked as CHAOS-25. → **The HA sync loop and the YARA match
  goroutine are now CLOSED (CHAOS-25, §14)** — the HA one did indeed hold a split-brain hazard in
  the obvious fix, in the mirror image of §12.2. The MCP runtime listener remains open as
  **CHAOS-26** (§14.7).
- The `crashThrottleEvery` (1s per component) flood guard means a tight panic loop reports a
  fraction of its rounds to the SIEM. The unthrottled `culvert_crash_records_total` counter is the
  lossless signal, by design (anti-forensics-DoS trade-off inherited from M1).

---

## 13. ST-8 — Silent audit-trail loss on a failing volume

**Date:** 2026-08-05 · **Closes:** ST-8 / risk **R13** (silent-loss half). Found by the standing
security-regression review of the CHAOS-24 window.

### 13.1 Failure scenario

`audit.Add` persisted each admin-action entry to the JSONL file with
`f.Write(b) //nolint:errcheck` and discarded the result. That file is the **durable** compliance
record; the in-memory ring the admin UI renders from holds only the newest `MaxRing` (500) entries
and is wiped on every restart.

So on a full volume, a read-only remount, an EIO, or a failed post-rotation reopen
(`fileutil.RotatingFile.Write` returns the open error), every admin action was recorded **nowhere
durable**, with:

- no counter, no Prometheus series, no `/healthz` annotation,
- no alert (the audit log is an append-only `RotatingFile`, so it never passes through
  `fileutil.AtomicWrite` and the CHAOS-45 durable-write chokepoint observer never saw it),
- no log line,
- and an admin UI that kept rendering entries from the volatile ring, so the operator's own
  evidence said logging was fine.

A `json.Marshal` failure took the same silent path.

**Why this is a security finding, not only an observability one.** The audit trail is the control
that answers "who changed what". An attacker who can fill the data volume — directly, or by
driving request-log/history growth — can switch off durable audit logging, act, and then evict the
volatile 500-entry ring by generating further events or forcing a restart. Nothing in the product
would report the gap. CWE-778 (Insufficient Logging); OWASP **A09:2021 — Security Logging and
Monitoring Failures**.

**Why it surfaced now.** The CHAOS-24 sweep made the request-log drain (`internal/reqlog`,
`WriteErrors`/`Backpressure`) and the syslog drain (`internal/syslog`, `Drops`/`Panics`) count and
surface every lost record. That left the audit log — the most compliance-critical of the three
durable log planes — as the only one still discarding its error, an inconsistency an operator
would reasonably read the other way round.

### 13.2 Fix

Persistence stays **best-effort by design** — a failing disk must not make an admin configuration
change fail, which would turn a storage incident into an administrative lockout — but the loss is
no longer silent:

- `internal/audit` counts every entry that did not reach the file (write error, **short write with
  a nil error** — the truncated-JSON-line case — and the defensive marshal branch), logs only the
  first (a failing disk fails every write; the counter carries the magnitude), and exposes
  `WriteErrors()`. Contract mirrors `internal/reqlog` exactly.
- A `SetWriteFailureObserver` seam lets `package main` route the failure into the existing
  CHAOS-45 storage-health plane (`storage_health.go` init → `noteStorageWriteFailure`): degraded
  operator-contract row, rate-limited log, and the `storage_write_failed` alert, with the same
  path-redaction barrier. The observer is documented as **MUST NOT call `Add`** (unbounded
  recursion on a persistently failing disk); the production observer is audit-free by
  construction, and a panicking observer is contained so audit loss can never take down the admin
  plane it records.
- **The file's line boundary is repaired.** A PARTIAL write (bytes accepted, record incomplete) leaves a fragment with no terminating newline; appending the next record onto it yields one unparseable line that every reader skips, so TWO entries are lost while only the first was counted. `persistEntry` therefore opens a fresh line before the next record, leaving the fragment as its own already-charged invalid line. The pending repair is re-derived from the bytes that actually reached the file, so a zero-byte write hands it back instead of leaking it.
- **The SUCCESS half is wired too** (`SetWriteSuccessObserver` → `noteStorageWriteSuccess`). `storageDegraded()` clears only on an OBSERVED successful write ("silence is not recovery"), so a failure producer without a matching success producer would pin a node degraded forever after one transient blip — reproducible on a node whose only durable writes are audit entries.
- Surfaced on `GET /api/stats` (`auditLogWriteErrors`), `/metrics`
  (`culvert_audit_write_errors_total`), `/healthz` (`auditLogWriteErrors`, present only when
  non-zero so healthy probe bodies are unchanged, and never failing the probe), and the dashboard
  — where audit loss **outranks** request-log loss in the logging posture tile, because those
  entries are already gone for good.

### 13.3 Regression gates

| Property | Test |
|---|---|
| Every lost entry counted; ring still populated | `TestWriteErrors_CountedOnFailingSink` |
| Healthy sink never charges a loss | `TestWriteErrors_ZeroOnHealthySink` |
| Truncated line (short write, nil error) charged | `TestWriteErrors_ShortWriteIsCharged` |
| Unconfigured persistence is not a failure | `TestWriteErrors_NoSinkIsNotAFailure` |
| Observer gets the real path + cause | `TestWriteFailureObserver_ReceivesPathAndError` |
| Nil / panicking observer cannot silence or crash | `TestWriteFailureObserver_NilIsSafe`, `_PanicDoesNotPropagate` |
| Exactly-once accounting under concurrency (`-race`) | `TestWriteErrors_Concurrent` |
| Observer not called under the audit lock (deadlock guard) | `TestWriteErrors_ObserverIsNotCalledUnderTheRingLock` |
| Wiring reaches storage health + alert, path redacted | `TestAuditWriteFailure_ReachesStorageHealthPlane` |
| Healthy persist does not degrade the contract | `TestAuditWriteFailure_HealthyPersistDoesNotDegrade` |
| `/api/stats`, `/metrics`, `/healthz` surfaces | `TestAPIStats_SurfacesAuditWriteErrors`, `TestMetrics_ExposesAuditWriteErrors`, `TestHealthz_AnnotatesAuditWriteErrors` |
| Partial write does not corrupt the NEXT entry (counter stays truthful) | `TestPartialWrite_DoesNotCorruptTheNextEntry` |
| Pending boundary repair survives a zero-byte write | `TestPartialWrite_RepairSurvivesATotallyFailedWrite` |
| Repair is inert on a healthy node (no stray blank line) | `TestHealthyWrites_NeedNoRepair` |
| Success observer fires only on a COMPLETE write (recovery signal) | `TestWriteSuccessObserver_FiresOnlyOnACompleteWrite` |
| Nil / panicking success observer costs no record | `TestWriteSuccessObserver_NilAndPanicAreSafe` |

### 13.4 Residual risk

- **Best-effort persistence is unchanged.** An admin mutation still returns 200 while its audit
  entry is being lost. Making the admin API fail closed on audit-write failure is the stronger
  posture and is *deliberately not* taken here: it converts a storage incident into a total
  administrative outage, and it diverges from the sibling log planes. It should be a separate,
  explicitly opted-in control (`audit.fail_closed`), not a silent behavior change.
- **Rotation still destroys the older archive** (`os.Remove(path+".1")` at the 50 MB cap). Bounded
  by design; a high-churn CP can age entries out of the durable file faster than an operator ships
  them off-box. The SIEM forwarder is the intended durable sink for that case.
- **`GetPersistent` still re-reads the whole file per query** — the unchanged half of ST-8, an
  admin-plane DoS amplifier on a large audit file. Tracked separately.
- The counter is process-lifetime and resets on restart, matching `reqlog`. The alert and the
  degraded contract row are the durable signals.

---

## 14. CHAOS-25 — HA sync-loop and scanner-goroutine panic containment (fail-closed)

**Date:** 2026-08-06 · **Closes:** two of the three paths CHAOS-24 deferred in §12.6 (the HA
standby/leader sync loops, and `internal/yara`'s per-match goroutine). The MCP runtime listener
stays open — re-scoped in §14.6.

### 14.1 Failure scenario

CHAOS-24 guarded 15 background workers per round and stopped, deliberately, at three paths whose
containment semantics were not mechanical. Two of them are on the **critical path of an in-line
appliance** and both process input the operator does not control:

| Path | Input it parses | Consequence of a panic (before this change) |
|---|---|---|
| `standbyLoop` → `tick` → `syncFromLeader` → `applyHABundle` | the **leader-supplied HA state bundle** (cluster state, replicated CA PEM + wrapped key, full ConfigSnapshot) | process death on the standby CP — the node that exists to survive the leader's death |
| `matchRegexWithTimeout`'s match goroutine (`internal/yara`) | **attacker-supplied response bodies** on the SSL-inspected scan path | process death of the gateway, remotely triggerable per request |

The HA bundle is the larger hazard. It is decoded and applied on every 5s tick, so a panic anywhere
under `applyHABundle` — a nil map, a slice index, a type assertion in the config-apply tree — is
**deterministic and repeats forever**: crash, restart, re-enter standby, sync, crash. The standby is
in a crash-loop precisely while its whole reason for existing (being ready when the leader dies) is
unavailable.

### 14.2 The finding inside the finding: the obvious fix is a split brain (again)

§12.2 found that the reflexive `defer recover()` was *worse than the bug* on the lease keepalive.
The HA sync loop has the same shape, and then a second trap behind it.

**Trap 1 — goroutine-level containment kills failover silently.** If `standbyLoop` returns on a
panic, the node keeps `role="standby"` and a live process, but it has stopped replicating **and**
stopped watching the leader. `failCount` freezes, `onMaxFail` is never reached, and the leader can
die with nothing left to notice. HA is gone; `/api/cluster/ha` still says `standby`, `sync_fail_count: 0`.
That is the CHAOS-24 rule (guard the round, never the goroutine) applying unchanged.

**Trap 2 — the natural per-round guard promotes on this node's own fault.** Guard the round and the
obvious next step is to charge a panicking round as a failed sync, exactly as `ha_lease.go` charges
a panicking renew round. **Here that is inverted, and unsafe.** The lease keepalive charges a
panicking round because *failing to confirm* is the fail-closed reading — the round produced no
evidence that the node still holds authority. In the standby loop the streak drives the opposite
transition: it **acquires** authority. Three panicking rounds (15s) would auto-promote a standby
whose only problem is its own parser, against a leader that is alive, healthy, and still serving.
In legacy (`--ha-auto-failover`, no witness) mode nothing else stops it, so the containment would
manufacture a **remotely-triggerable split brain** — strictly worse than the crash it replaced,
because today's crash-loop is at least loud and single-writer.

The rule this PR adopts, stated once:

> **A contained panic is evidence that THIS node is broken, not that the leader is gone.**

So the guard wraps the whole round, which puts the unwind *before* `tick`'s
`setFail(failCount+1)`: the promotion streak is untouched by construction, and `guardedTick`
additionally refuses to report loop-exit on a panicking round. Ordering that matters is pinned by
test, not left to comment. A panic raised *later* — inside `promote()`, after a genuine sync
failure already advanced the streak — keeps that (correct) increment and just leaves the node a
standby, retryable next tick.

In **lease mode** the fence is the backstop: a live leader holds the lease, so `Acquire` denies the
promotion anyway. The rule is still enforced there (`TestChaos25_LeaseModePanicIsAlsoFenced`) as
defense in depth — the node must not even *attempt* leadership on the strength of its own fault.

### 14.3 What "not counting" costs, and how it is paid for

Suppressing the streak means a permanently panicking standby never escalates on its own. Left
there, containment would have traded a loud failure for a silent one — the exact class §13 was
about. It is paid for three ways, all pre-existing planes:

- **Crash plane** — `culvert_crash_records_total{component="ha-standby-sync"}` (and `"ha-promote"`),
  the system-actor audit entry, the bounded redacted `lastCrash`. No new observability surface.
- **Status** — `sync_panics` on `HAStatus` → `GET /api/cluster/ha` → a warn-coloured
  "Sync faults (contained)" row in the HA panel, next to the failure streak it is deliberately
  absent from.
- **Alert** — `ha_sync_panic`, fired **once per streak** and re-armed by the next healthy sync, so
  a later stall is not swallowed by the first. The cumulative counter never resets.

The lease-mode freshness gate composes correctly with no change: a stalled standby's `lastSyncOK`
ages out, and `leaseAutoPromote` already refuses to auto-promote on stale state while leaving
`PromoteManually` as the operator break-glass. That is the intended recovery path when the leader
really is down and this node cannot parse its bundle.

### 14.4 The scanner goroutine

`matchRegexWithTimeout` is a one-shot detached goroutine, not a loop, so there is no "next round" to
keep alive — the guard covers the whole body. The decision that mattered is what to hand the
caller: a contained panic yields **no verdict about the content**, which is exactly the epistemic
state a *timeout* leaves. So it resolves through the same admin-selectable posture
(`fail_closed` ⇒ block, `fail_open_with_alert` ⇒ allow) rather than defaulting to "clean", and it
answers **immediately** instead of letting the parent wait out the full timeout — the panic already
proved the match will never complete, and stalling every scan for the timeout window would turn a
contained fault into a throughput collapse. The deferred `yaraInflight.Add(-1)` still runs, so
containment cannot leak the saturation budget into a permanent degradation (pinned by test).

`internal/yara` already imports `obs`, so the panic lands in the same crash pipeline via the
CHAOS-24 seam. `MatchPanics()` is the local counter; non-zero means some verdicts were decided by
the posture rather than by the rule, which is a **correctness** signal, not only a liveness one.

### 14.5 What shipped

- `ha.go` — `guardedTick` / `guardedSyncOnce` (per-round, streak-preserving, exit-suppressing),
  `notePanicRound` / `clearSyncPanicAlert`, `syncPanics` + `SyncPanics` on `HAStatus`, and a
  `syncFn` seam so a round can be made to panic without standing up a gRPC leader.
- `ha.go` — `promote()`'s `onPromote` hook (CP gRPC server startup, reached from the sync loop, the
  planned handoff, **and** the admin `PromoteManually` API) is guarded and a panic is treated
  exactly like the error it already handles: reset the once-guard, stay standby, stay retryable.
- `internal/yara/yara.go` — per-match containment resolving through the on-timeout posture, plus
  `MatchPanics()` and the `yaraMatchFn` fault-injection seam.
- `internal/alerts/store.go`, `static/index.html` — the `ha_sync_panic` event and the contained-fault
  status row (GUI parity).

### 14.6 Tests

| Gate | Test |
|------|------|
| **Split-brain gate** — panicking rounds never promote, streak untouched | `TestChaos25_PanickingRoundsDoNotPromote` |
| Fence-mode defense in depth — no promote attempt even with a free lease | `TestChaos25_LeaseModePanicIsAlsoFenced` |
| Not trigger-happy — genuine leader silence still fails over | `TestChaos25_GenuineFailuresStillPromote` |
| Suppression is not a latch — panics then a real outage still fails over | `TestChaos25_PanicDoesNotMaskARealOutage` |
| Round contained, loop survives, attributed in the crash plane | `TestChaos25_PanickingRoundContained` |
| Startup try (cold local state, largest bundle) contained | `TestChaos25_ImmediateSyncPanicIsContained` |
| Fire-once alert re-arms; cumulative counter does not reset | `TestChaos25_SuccessRearmsThePanicAlert` |
| `onPromote` panic ⇒ stays standby, guard reset, retry succeeds | `TestChaos25_PromotePanicStaysStandby` |
| Failed/panicking promote keeps the loop alive (see §14.8) | `TestChaos25_FailedPromoteKeepsTheLoopAlive` |
| Scanner: contained panic fails CLOSED by default | `TestChaos25_MatchPanic_FailsClosedByDefault` |
| Scanner: honours the operator's fail-open posture | `TestChaos25_MatchPanic_HonoursFailOpenPosture` |
| Scanner: answers immediately, does not wait out the timeout | `TestChaos25_MatchPanic_AnswersImmediately` |
| Scanner: containment does not leak the saturation budget | `TestChaos25_MatchPanic_ReleasesTheInflightSlot` |
| Scanner: healthy matching byte-identical, charges no panic | `TestChaos25_HealthyMatchIsUnchanged` |

Both regression gates were verified to **fail without the fix**. Substituting the naive
count-the-panic-as-a-failure guard trips the split-brain assertion at round 2
(`contained panic promoted the standby — split brain against a live leader`), and removing the
scanner guard reproduces process death (`panic: simulated fault inside the regex match`, test
binary terminated).

### 14.7 Residual risk

- **Containment is still not repair.** A standby that panics every tick is contained, counted, and
  alerted, but replicates nothing. Its recovery path is an operator promoting it manually (if the
  leader is genuinely down) or fixing the fault. The alert says so explicitly.
- **Suppressing the streak is a deliberate availability trade.** If a standby's apply path breaks
  *and* the leader dies during the same window, no automatic failover happens. That is the intended
  ordering: an un-fenced promotion by a node that cannot parse the cluster's state is the worse
  outcome, and manual promotion remains one API call away.
- **A failed or panicking `promote()` leaves an unkept lease grant.** Pre-existing and already
  documented on the error branch (it expires after its TTL). Worth noting precisely: `WriteAllowed()`
  keys on the grant, not the role, so such a node reports write authority on `/healthz` and
  `diagnose` for the rest of the window. It is **cosmetic, not an authority leak** —
  `haIssuanceAllowed` gates on `Role == "leader"` first, so a standby holding a stale grant issues
  nothing, and the lease's exclusivity means no other node can promote during that window either.
  Zeroing the local epoch on a failed promote would tighten the reporting; it touches fence
  semantics and is deliberately **not** bundled into a panic-containment change (§12.2's own lesson).
- **Still unguarded: the MCP runtime listener** (`internal/mcp/runtime`). Left open on purpose: it
  is disabled-by-default with a different blast radius (its own listener, not the SWG request path),
  it spans 25 subpackages, and ADR-0024's rollout ladder means "contain and continue" has to be
  reconciled with the Observe/Shadow/Canary semantics before a guard is correct. Tracked as
  **CHAOS-26**.
- The `crashThrottleEvery` (1s per component) flood guard still means a tight panic loop reports a
  fraction of its rounds to the SIEM; the unthrottled counter is the lossless signal (inherited
  from M1).

### 14.8 Review follow-up — the silent stall one level up

External review of the first cut (Codex, PR #1066) found the containment could still be defeated
by the caller. `onMaxFail`'s legacy branch reported loop-exit **unconditionally** after calling
`promote()`:

```go
if s.h.autoFailoverEnabled() {
    s.h.promote("leader unreachable")
    return true          // <- regardless of whether promotion happened
}
```

`promote()` is not infallible, and now has two ways to decline: `onPromote` can return an error
(pre-existing) or panic and be contained (added by §14.5). Both reset the once-guard and leave the
node a **standby** — and `return true` then told `standbyLoop` to exit for good. The node stopped
replicating **and** stopped watching the leader while still reporting `role="standby"`: exactly the
Trap-1 silent stall of §14.2, reached one level above the guard that prevents it. The reset
once-guard was never retried, so recovery required an operator restart.

The lease branch immediately above already returns `leaseAutoPromote()` (→ `IsLeader()`), so the
fix is to make the legacy branch report the same fact: `return s.h.IsLeader()`. The loop then keeps
ticking and the next round retries the promotion, matching lease mode.

Worth recording that this was **pre-existing** — an `onPromote` error alone (a CP gRPC port already
in use, say) permanently ended a legacy standby's sync loop before this PR. The panic guard added a
second way in, and the review surfaced both. `TestChaos25_FailedPromoteKeepsTheLoopAlive` drives an
error, then a contained panic, then a success, and fails against the old code at round 2
(`loop exited before a promotion succeeded`).

---

## 15. CHAOS-27 — The alert plane under an alert storm

**Date:** 2026-08-07 · **Closes:** WK-11, WK-12 · **Detail:**
`docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-08-07.md`

### 15.1 The shape of the miss

WK-10 is not wrong. Webhook *delivery* is bounded four different ways — a 10-slot concurrency
semaphore, a 3-attempt retry with exponential backoff, a 500-cap drop-on-full retry queue, and
SSRF-guarded egress. What this pass asked is a different question: **what does the alert
subsystem cost the appliance when the thing it reports on is happening at volume?**

Two costs sat *in front of* every one of those bounds, so none of them applied.

### 15.2 WK-11 — one leaked FD + two goroutines per delivered alert

`deliverAttempt` constructed its client, and with it a fresh `http.Transport`, per attempt. On
success the keep-alive connection went back into *that* Transport's idle pool — a pool nothing
holds a reference to afterwards, that net/http does not finalize, and whose **zero-value
`IdleConnTimeout` means "never expire"** (unlike `http.DefaultTransport`, which sets 90s). The
`persistConn` read/write goroutines keep the Transport and the socket alive, so the connection
survives until the **receiver** closes it. Culvert had no timer that would ever reclaim it.

`webhookSem` does not bound this: it caps deliveries *in flight* (10), and says nothing about
the sockets those slots opened over the preceding hour.

The blast radius crosses planes. File descriptors are a process limit, so the alerting
subsystem exhausts the descriptors the **proxy** needs to `accept(2)`. A subsystem whose only
job is to report trouble becomes the cause of a data-plane outage, and the visible symptom
(proxy refusing connections) points the operator at the wrong subsystem.

Fixed with one shared pooled `deliveryClient` (`MaxIdleConns: 32`, `MaxIdleConnsPerHost: 4`,
`IdleConnTimeout: 90s`), matching the pooled-client idiom already used in
`internal/blocklistfeed` and `internal/otlp`. Per-attempt deadlines are unchanged.

**Reuse does not weaken the SSRF guard.** `ssrf.SafeDialContext` runs on every *dial*, and a
pooled connection is by definition one to an address that already passed `ssrf.Control`
immediately before `connect(2)`; reuse cannot reach an address that was never validated. What
it extends is how long a validated-then-rebound host stays reachable on an open socket —
bounded by `IdleConnTimeout`, and strictly better than the pre-fix state where an abandoned
pool's socket had *no* timeout at all.

### 15.3 WK-12 — unbounded dedup map, rescanned per dispatch

The Q17 dedup key is `event + ":" + detail`, and the request-path producers
(`threat_detected`, `policy_block`) put the **requested host** in `Detail`. So a scan across
50,000 hostnames produces 50,000 distinct keys that the window cannot suppress *by
construction* — the same attacker-controlled input that `topHosts` (store.go) is already
hard-capped at 10k for, with the same memory-DoS reasoning, unguarded here.

Worse, the expiry scan ran on **every** dispatch, `O(len(map))`, under the process-wide
`dedupMu`. Producers reach `Dispatch` via `go fireAlert(...)`, so a slow critical section does
not stall the request path directly — it piles up *goroutines* waiting on the mutex instead.

Measured at the flood steady state (`BenchmarkDedupSuppressedUnderFlood`, 4-core):
**230,603 ns/op → 745 ns/op**, ≈310×, and the pre-fix number *grows with the map* while the
post-fix number is flat. 0.23 ms of mutex-held work per alert is ~23% of a core serialized at
only 100 alerts/s.

Fixed with a 4096-key hard cap plus an amortised prune. The two costs are deliberately kept
apart: the `O(len)` expiry scan runs at most once per 256 inserts (`pruneExpiredLocked`), while
the cap is checked every insert but costs `O(entries over cap)` — one deletion at steady state
(`evictOverCapLocked`). Coupling the cap to the scan would have fixed memory while leaving the
CPU failure mode fully intact.

**Eviction fails toward MORE alerts, never fewer.** Dropping a live key costs at most one
duplicate delivery of an alert already firing, still bounded by the semaphore and the retry
queue. Silencing a real security alert to save memory is not on the table for a security
control.

### 15.4 The 2026-07-26 residual, revisited

That review already saw this trigger — a producer emitting unique `Detail` text per request —
and accepted it because *"bounded by the store's 500-cap queue and 10-slot delivery
semaphore."* That reasoning was correct about **delivery** and silently assumed the
bookkeeping in front of delivery inherited the same bounds. It did not. The note still stands
for delivery fan-out; the cost of the dedup pass is now bounded too, and counted.

### 15.5 Observability

Loss must not be silent: `dedup_evictions_total` + `dedup_tracked` on
`GET /api/alerts/webhooks/history`, `culvert_alert_dedup_evictions_total` (counter) +
`culvert_alert_dedup_tracked` (gauge) on `/metrics`, and an amber "dedup window saturated"
state on the webhook health line in Settings. Non-zero evictions are themselves a useful
signal: they are the signature of a scanning wave reaching the alert plane. OpenAPI
`AlertHistory` extended and the bundle regenerated.

WK-11 gets no counter by design — the leak is gone, and a gauge for a state that can no longer
occur is noise.

### 15.6 Regression gates (all verified to FAIL against the pre-fix code)

| Gate | Property |
|---|---|
| `TestChaos27_DeliveryReusesConnections` | N sequential deliveries open ≤2 sockets (pre-fix: 8 for 8) |
| `TestChaos27_DedupMapIsBounded` | 3× cap unique keys leave the map at ≤ cap (pre-fix: 12288), evictions counted |
| `TestChaos27_DedupPruneIsAmortised` | scans ≤ inserts/256 + 1 — the CPU half, invisible to the memory gate |
| `TestChaos27_DedupStillSuppressesDuplicates` | Q17 semantics intact |
| `TestChaos27_DedupPrunesExpiredEntries` | a key past `dedupTTL` fires again — the cap never silences permanently |

The connection-reuse gate builds its client through the **production constructor**
(`newDeliveryTransport`) with a plain dialer substituted, because `ssrf.SafeDialContext`
correctly refuses the loopback address an `httptest.Server` listens on. The pooling
configuration under test is production's; only the dial target differs.

### 15.7 Residual risk

- `maxDedupEntries` / `dedupPruneEvery` are compile-time constants (the `topHosts` precedent).
  Making them tunable would add a config surface, a durability row and a CP→DP question for a
  value nobody has had cause to change. Deliberate deferral.
- Eviction order is random (Go map iteration), not oldest-first. Under a flood every live entry
  is inside the same 30s window, so ordering buys nothing for its cost.
- Dedup is still keyed on `event:detail`, so a producer with unbounded `Detail` cardinality
  still defeats *suppression* by design. The cap bounds the **cost** of that, not the
  behaviour — now with an eviction counter that makes it visible.
- Other per-call `http.Transport` sites were audited: `auth_oidc_flow.go` (once per provider
  construction), `auth_saml.go` (metadata fetch), `internal/supportupload` (per upload), and
  `internal/blocklistfeed` (per fetch, but with a 90s `IdleConnTimeout`, so it self-heals).
  `internal/upstream`'s health check sets `DisableKeepAlives: true` and pools nothing. None is
  on an attacker-driven rate path, so none is a WK-11-class leak; the blocklistfeed shape is
  the one worth converging on the shared-client idiom opportunistically.
- `webhookSem` is package-global, so all Stores in a process share the 10 slots. Production has
  one Store; noted, not a defect.

### 15.8 Review follow-up — the phantom saturation signal

External review of the first cut (Codex, PR #1078) found a case where the two triggers disagree.
The expiry prune is scheduled by **inserts** (`dedupPruneEvery`), but entries expire with **time**
— and a quiet period has no inserts. So a flood that fills the map to the cap and then stops
leaves 4096 entirely stale keys sitting there. The next alert to arrive:

- finds the map over cap, and
- evicts a random key and **charges it to `dedupEvicted`** — even though every entry is dead and
  nothing is saturated. It could also evict the key it had just inserted, letting an immediate
  duplicate through.

That counter is monotonic and drives an amber "dedup window saturated" state in the admin UI, so
one flood followed by silence produced a **permanently sticky, false degradation indicator** —
defeating the exact observability contract §15.5 added it for. Worse than useless: it teaches the
operator to ignore the signal.

Fixed on both axes:

- **Time-based prune trigger** on the over-cap path (`dedupPruneMinInterval`, 1s), so a map full
  of stale keys is reclaimed before its size is read as saturation. Rate-limited, so a *sustained*
  flood — where the scan would find nothing to reclaim — still does not pay `O(len)` per alert
  (measured: 745 → 783 ns/op, still ~295× better than the 230,603 ns/op pre-fix baseline).
- **Expired keys are deleted but never charged** (`evictOverCapLocked` compares each key's stamp
  against `dedupTTL`). Dropping a dead key is reclamation, not saturation. This makes the counter
  exact even inside the ≤1s window between an entry expiring and the next prune reclaiming it,
  rather than merely approximately right.

`evictOverCapLocked` also now skips the key just inserted, so the alert that triggered the
eviction is never the one dropped.

`TestChaos27_QuietPeriodCountsNoPhantomEvictions` drives the exact sequence — fill to cap, let the
window pass, insert one key — and fails against the first cut (`charged 1 eviction(s) against a
map holding only EXPIRED keys`). It asserts three things: no eviction charged, the fresh key
survives, and the stale entries are actually reclaimed.

Worth recording the general shape, because it is the same lesson as §12.2 and §14.8: **a
correctness fix that is scheduled on one clock and validated on another will disagree with itself
at the boundary.** The memory bound was right, the CPU bound was right, and the counter that made
both observable was wrong in precisely the state — quiet after a storm — that an operator is most
likely to be looking at it.

---

## 16. CHAOS-28 — The Root CA across its lifecycle (fail-closed)

**Date:** 2026-08-09 · **Closes:** CA-1, CA-1b, CA-2, CA-16 · **Partly closes:** CA-4 ·
**Re-scopes:** CA-11 · **Hands off:** CA-13
**Full write-up:** `docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-08-09.md`

### 16.1 Why this domain

Every other security control in Culvert fails in a way the process can observe — a dial
fails, a scanner times out, a write returns `ENOSPC`. The inspection CA is the exception:
it expires, and *nothing inside the appliance changes*. The only entity that notices is
the client, which reports it as a per-site certificate warning that reads like a website
problem rather than a gateway problem. That is the definition of a silent failure, on the
component whose failure is the widest.

### 16.2 The five defects

1. **Expired CA kept signing.** `x509.CreateCertificate` does not check the parent's
   `NotBefore`/`NotAfter` — verified empirically by running the new gate against the
   pre-fix engine, where the sign succeeded. `handleTunnel` did not help either: its gate
   is `certMgr.Ready()`, which is `caCert != nil`, so an expired CA is "ready".
2. **Leaf validity was not clamped to the issuer's** (`NotAfter: now+24h`, unconditional).
3. **A rotation that could not persist reported success** (CA-2) — so the only recovery
   path defect 1 has could silently not survive a restart, minting a different root each boot.
4. **The rotation loop's first check was 24h after boot** (CA-4) — skipped precisely when
   an operator restarts to recover from the outage.
5. **`cacheOrder` grew on every TTL refresh** (CA-16, previously unrecorded) — an unbounded
   slice behind a bounded map, growing with uptime on an ordinary steady working set.

### 16.3 The decision that mattered: fail closed, not bypass

The tempting fix is one word — fold validity into `Ready()`. That routes an expired CA into
the existing `inspect_unavailable` **bypass** branch and keeps traffic flowing. It also means
that at the instant the CA expires, **the whole fleet silently stops inspecting**: DLP,
ClamAV, YARA, CDR, file-blocking and DPI all dark, at once, with the gateway reporting itself
healthy. That is trading an availability failure for a security-control failure, and it is the
exact §1 theme this register calls its worst.

The same reasoning rules out honouring a decryption profile's `OnInspectError=fail-open`. That
contract is scoped to **per-origin** incompatibility and gated behind a confirm-count of
distinct client evidence for exactly that reason. An expired CA is **host-independent**:
routing it through the learner would promote every host requested during the outage into a
durable bypass — poisoning the entire cache from one appliance-level fault.

So the unusable-CA path **never bypasses, never learns, never rescues**, and the negative
assertion is executable: `TestHandleTunnel_ExpiredCAFailsClosedNotBypass` fails if the session
is ever recorded as any flavour of bypass instead of
`failed`/`no_fail_open_502`/`client_hello`/`certificate`.

Failing closed costs no availability relative to the pre-fix state — a leaf chained to an
expired issuer already fails path validation in every mainstream client. The traffic was dead
either way. What changed is that the appliance now knows, says so, and names the remediation.

### 16.4 Observability added

| Surface | Signal |
|---|---|
| `/metrics` | `culvert_ca_usable`, `culvert_ca_expires_in_seconds` (omitted when no CA — 0 would read as "expires now"), `culvert_ca_sign_refused_total`, `culvert_ca_inspect_blocked_total`, `culvert_ca_rotation_persist_failures_total` |
| `/healthz` | `ssl_inspection: expired` (was `ready` throughout the outage) |
| `/readyz` | `ca` row → `fail`, **report-only** by default (an expired CA is fleet-wide; gating would eject every node at once and take working plain-HTTP/bypass traffic with it). `?strict=1` opts in. Fixed detail string — the surface is unauthenticated on the proxy port |
| Alerts | `cert_expiry`, rate-limited (5 min) on an independent gate from the log line, `HasSubscriber`-gated per the per-request producer contract |
| Admin API / GUI | `GET /api/ca/status` gains `usable` / `unusableReason` / `inspectBlocked` / `signRefused` / `rotationPersistFailures`; the CA panel gains a red outage banner and an amber not-persisted banner |

Recovery is reported on **evidence** (an observed usable verification via
`caInspectionUsable`), never on elapsed time — the `storage_health.go` contract, for the same
reason: a still-expired CA looks exactly like a healthy one if nothing happens to need a leaf.

### 16.5 What is deliberately left

- **CA-13** — cluster-CA rotation still logs-and-returns on every failure branch. Same defect
  class as CA-2 in the *other* CA; different lifecycle and blast radius (enrollment, not
  inspection). Suggested as the next sweep.
- **CA-11** — no single-flight on the leaf cache. Re-scoped down: the perf-F3 shared leaf key
  already removed the dominant per-miss cost (P-256 keygen), so the herd is much cheaper than
  when first recorded.
- **CA-4's retry half** — a rotation that FAILS still waits a full 24h before retrying.
- **Client trust redistribution stays manual.** Rotation restores the appliance's ability to
  inspect; it cannot make clients trust a new root. Nothing in-band can. That is why this
  change invests most heavily in making the condition visible *before* the cliff
  (`culvert_ca_expires_in_seconds`) rather than only at it.
