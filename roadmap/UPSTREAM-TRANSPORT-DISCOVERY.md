# P5.1 — Upstream Transport Mutation-Graph Discovery

**Status:** Discovery only. No production code change.
**Scope:** `upstreamTransport`, `upstreamPool`, `CircuitBreaker`, `UpstreamProxy.Healthy`, OCSP + mTLS overlay on the shared `*http.Transport`.
**SPOF target:** S6 (`upstreamTransport` shared mutation across `initUpstreamPool` + `initMTLSAndOCSP` + runtime admin-API paths).

---

## 0. Executive verdict

Phase 5 can continue with extraction-style work for **P5.1 (this report) and P5.2 (contract tests pinning the current ordering)**, but **P5.3 (single-constructor `upstreamTransport`) is not pure slice extraction** — it crosses the ownership boundary that the prior P4 slices preserved. The refactor must:

1. Change every reader from `upstreamTransport.<field>` to a load-from-pointer accessor (≥ 4 read sites on the hot path).
2. Move the two runtime admin-API mutators (`apiOCSPConfig`, `apiUpstreamProxies`, plus `applyHotReload`) onto the same atomic-swap contract.
3. Coordinate with the `applyUpstreamProxy()` helper, which itself writes `upstreamTransport.Proxy` at startup AND in two runtime paths.

P5.3 therefore remains correctly gated in the roadmap as **MEDIUM-HIGH risk, lab-required**. Nothing in this discovery upgrades or downgrades that gate. **`upstreamTransport` is the first true ownership-boundary refactor in the program**: prior phases wrapped callers without changing the surface that hot-path code reads from. P5.3 must change that surface.

What is **NOT** uncovered by this discovery:

- No undocumented cluster-sync writer (ConfigSnapshot does not carry upstream proxies or OCSP/mTLS state).
- No undocumented persistence path (upstream + OCSP + mTLS state is rebuilt from YAML on startup; not persisted to a sidecar file).
- No undocumented shutdown coupling beyond `appLifecycleCtx` cancelling the health-check goroutine.

---

## 1. Component inventory

### 1.1 `upstreamTransport` — the shared `*http.Transport`

Declared at `proxy.go:1024` as a package global. Initialised with static pool sizing + buffer sizing constants. **Mutated in place** by startup AND runtime paths.

| Field touched by mutators | Where read |
|---|---|
| `Proxy` (`func(*http.Request) (*url.URL, error)`) | Per-request, internally by `http.Transport.RoundTrip` |
| `TLSClientConfig` (`*tls.Config`) — assigned a new instance when nil | Per-TLS-handshake (every outbound HTTPS dial that misses the keepalive pool) |
| `TLSClientConfig.MinVersion` | Per-TLS-handshake |
| `TLSClientConfig.Certificates` (mTLS client cert) | Per-TLS-handshake |
| `TLSClientConfig.VerifyPeerCertificate` (OCSP verifier) | Per-TLS-handshake |
| `TLSClientConfig.VerifyConnection` (OCSP verifier for session resumption) | Per-TLS-handshake (resumed sessions) |

### 1.2 `upstreamPool` — `*UpstreamPool`

Declared at `upstream.go:126`. **Well-encapsulated.** Carries:

- `proxies []*UpstreamProxy` — protected by `sync.RWMutex` (held during `Configure` / `Enabled` / `List` / `HealthCheck`; the `Next`/`ProxyFunc` hot path takes the RLock to snapshot the slice header and releases it before iterating).
- `idx atomic.Int64` — round-robin counter.

### 1.3 `UpstreamProxy` — per-proxy struct

Declared at `upstream.go:113`. Carries:

- `URL *url.URL` — write-once at `Configure`; pointer is read by hot path.
- `Healthy atomic.Bool` — written by the health-check loop and `HealthCheck()`; read by `Next()` on the hot path.
- `CB *CircuitBreaker` — write-once at `Configure`; methods on `CB` are race-safe (atomics).

### 1.4 `CircuitBreaker` — per-proxy

Declared at `upstream.go:41`. All mutable state is `atomic.Int32`/`atomic.Int64`. No mutex. Race-free by construction.

### 1.5 `globalOCSP` — `*OCSPChecker`

Declared at `ocsp.go:42`. Carries:

- `enabled atomic.Bool` — toggled by `Enable()` / `Disable()`.
- `cache map[string]*ocspCacheEntry` — protected by internal `sync.RWMutex`.

`globalOCSP` itself is race-safe. The race lives in how `ConfigureTransportOCSP` *writes* `upstreamTransport.TLSClientConfig` — see §4.

---

## 2. Ownership graph (writers + readers)

### 2.1 Writers — startup phase (single-threaded, pre-listener-accept)

| Writer | Touches | Location | Order |
|---|---|---|---|
| `initUpstreamProxy` → `initUpstreamPool(s.fc)` | `upstreamPool.proxies`, then `upstreamTransport.Proxy` (via `applyUpstreamProxy`) | `main.go:944, 1733, 1734` | step 27 in startup |
| `loadMTLSAndOCSP(cfg)` (via `initMTLSAndOCSP` shim) | `upstreamTransport.TLSClientConfig{,.Certificates,.MinVersion,.VerifyPeerCertificate,.VerifyConnection}` | `mtls_ocsp_startup.go:21–32` | step 29 in startup, after step 27 |
| Health-check goroutine spawn | `go runUpstreamHealthCheckLoop(appLifecycleCtx, upstreamPool, d)` | `main.go:1749` | inside step 27 |

**Order dependency:** step 29 (mTLS/OCSP) writes `upstreamTransport.TLSClientConfig`; step 27 (pool) writes `upstreamTransport.Proxy`. They are disjoint fields, but **both reach into the same `*http.Transport`**. The order is enforced today only by the call sequence in `main()`. The order is also the reason `mtls_ocsp_startup_test.go:139` exists — it pins "preserves existing TLS config" so that step 27's pool-induced changes don't get clobbered if step 29 runs.

### 2.2 Writers — runtime phase (post-listener-accept; **concurrent with hot path**)

| Writer | Touches | Trigger | Synchronisation |
|---|---|---|---|
| `applyHotReload(fc)` | `upstreamPool.Configure` + `applyUpstreamProxy()` (writes `upstreamTransport.Proxy`) | SIGHUP | **None** — direct field write |
| `apiUpstreamProxies` POST | `upstreamPool.Configure` + `applyUpstreamProxy()` | Admin API | **None** |
| `apiRestoreBackup` (`ui_config.go:521`) | `upstreamPool.Configure` only (does NOT call `applyUpstreamProxy`) | Admin API | **None** — observable bug: a restore won't activate the pool until SIGHUP or a re-POST |
| `apiOCSPConfig` POST `Enabled=true` (`ui_security.go:1153`) | `ConfigureTransportOCSP(upstreamTransport)` — writes `TLSClientConfig{,.VerifyPeerCertificate,.VerifyConnection}` | Admin API | **None** |
| `apiOCSPConfig` POST `Enabled=false` | `globalOCSP.Disable()` only — does **not** clear the `VerifyPeerCertificate` / `VerifyConnection` callbacks on `upstreamTransport.TLSClientConfig` | Admin API | The callbacks remain wired; they no-op because `globalOCSP.enabled` is the atomic gate. Behaviour-preserving, but worth noting. |

### 2.3 Readers — proxy hot path (concurrent, every request)

| Reader | Reads | Location |
|---|---|---|
| `handleHTTP` per-request `http.Client` | `Transport: upstreamTransport` (pointer copy into the per-request client) | `proxy.go:672` |
| `http.Transport.RoundTrip` (called by the per-request client) | `upstreamTransport.Proxy`, `.MaxIdleConns`, `.IdleConnTimeout`, … | stdlib internals; readers observe whatever pointer values were stored at the moment of the request |
| TLS handshake (every outbound HTTPS that misses keepalive) | `upstreamTransport.TLSClientConfig.{Certificates, VerifyPeerCertificate, VerifyConnection, MinVersion}` | stdlib `crypto/tls` |
| `upstreamPool.Next()` (called from `Proxy` func) | `upstreamPool.proxies` (via RLock + snapshot), each `proxy.Healthy.Load()` (atomic), each `proxy.CB.Allow()` (atomic) | `upstream.go:158–175` |

### 2.4 Readers — admin UI / API (low-rate)

| Reader | Reads | Location |
|---|---|---|
| `apiUpstreamProxies` GET | `upstreamPool.Enabled()`, `upstreamPool.List()` | `ui_config.go:1043–1044` |
| `apiUpstreamHealthCheck` | `upstreamPool.HealthCheck()` then `upstreamPool.List()` | `ui_config.go:1056–1057` |
| Backup capture (`captureConfigBackup`) | `upstreamPool.List()` | `ui_config.go:324, 356` (indirect via backup snapshots) |
| Backup display | Same | Same |
| `apiOCSPConfig` GET | `globalOCSP.Enabled()`, `globalOCSP.CacheLen()` | `ui_security.go:1137–1138` |

---

## 3. Goroutine ownership / lifecycle

Two upstream-related goroutines exist; their cancellation is **already wired correctly** by the Phase 1 / Phase 2 work and is **not** part of P5's open scope.

| Goroutine | Parent ctx | Cancel mechanism | Health |
|---|---|---|---|
| `runUpstreamHealthCheckLoop(appLifecycleCtx, upstreamPool, interval)` | `appLifecycleCtx` | `appLifecycleCancel()` via `app-lifecycle-cancel` early shutdown hook (order 40) | ✅ Already cancellable. Pinned by `upstream_healthcheck_loop_test.go` (3 tests). |
| `upstreamPool.HealthCheck()` per-iteration HTTP clients | per-call `context.WithTimeout(context.Background(), 5*time.Second)` | Per-iteration `cancel()` in the iteration body | ✅ Already bounded per call. |

**No upstream-related goroutine is missing a cancellation path.** Phase 1 (P1.3 / S4.UpstreamHealth) closed that gap.

---

## 4. Mutation authority map

The **categorical** issue with `upstreamTransport` is that its fields have two distinct authority models that collide on the same memory:

### 4.1 Startup writers — "configuration phase, single-threaded"

- `initUpstreamPool` writes `upstreamTransport.Proxy` (indirectly via `applyUpstreamProxy()`).
- `loadMTLSAndOCSP` writes `upstreamTransport.TLSClientConfig{,...}`.

These are sequential during `main()` startup. **No race** because no other goroutine reads `upstreamTransport` yet — the proxy server is launched after `runProxyUntilShutdown` begins, which happens AFTER all `init*` functions return.

### 4.2 Runtime writers — "operator mutation, concurrent with hot path"

| Path | Writes | Live races against |
|---|---|---|
| `applyHotReload` → `applyUpstreamProxy` | `upstreamTransport.Proxy` | Every outbound HTTP/S request that hits `http.Transport.RoundTrip` (which reads `Transport.Proxy`) |
| `apiUpstreamProxies` POST | Same | Same |
| `apiOCSPConfig` POST `Enabled=true` | `upstreamTransport.TLSClientConfig` and its three fields | Every TLS handshake on every outbound HTTPS dial |

`http.Transport`'s docstring says "A Transport is safe for concurrent use by multiple goroutines" — meaning safe for concurrent **`RoundTrip`** calls. It does **not** promise safety for concurrent writes to its config fields. The `Transport` source confirms: fields like `Proxy`, `TLSClientConfig`, and the various TLS hooks are read without a lock from the dial path; mutating them while requests are in flight is a documented data race.

**Race detector observation:** the existing test suite does not interleave admin-API mutations with concurrent outbound-request traffic, so `-race` has never flagged this. It is correct as a finding to expose in discovery, not a regression introduced by recent work — this race has existed since `apiOCSPConfig` and `apiUpstreamProxies` were added.

### 4.3 Mutation authority matrix

| Mutator | `upstreamPool.proxies` | `upstreamTransport.Proxy` | `upstreamTransport.TLSClientConfig` | Synchronised? |
|---|---|---|---|---|
| Startup: `initUpstreamPool` | ✓ | ✓ (via `applyUpstreamProxy`) | – | N/A (single-threaded) |
| Startup: `loadMTLSAndOCSP` | – | – | ✓ | N/A (single-threaded) |
| SIGHUP: `applyHotReload` | ✓ | ✓ | – | **NO** |
| Admin: `apiUpstreamProxies` POST | ✓ | ✓ | – | **NO** |
| Admin: `apiRestoreBackup` | ✓ | – (bug: omitted) | – | **NO** |
| Admin: `apiOCSPConfig` POST `Enabled=true` | – | – | ✓ | **NO** |
| Hot path: per-request | – | reads `.Proxy` | reads `.TLSClientConfig.*` | RW race with the writers above |

`upstreamPool.Configure` itself is internally synchronised (it grabs `p.mu.Lock()`); the race is on `upstreamTransport` field writes outside that lock.

---

## 5. Persistence / reload interactions

### 5.1 Persistence

`upstreamTransport`, `upstreamPool`, `globalOCSP`, and the mTLS client-cert state are **NOT persisted to any sidecar file**. They are rebuilt from `fc.Upstream.*` / `fc.MTLSClientCert` / `fc.MTLSClientKey` / `fc.OCSPCheck` on startup.

The on-disk YAML config (`config.yaml`) is the canonical source. Reload semantics therefore reduce to: re-read YAML → call the same `Configure` paths the startup did.

### 5.2 SIGHUP / hot reload

`applyHotReload(fc)` at `main.go:2249–2258` re-runs `upstreamPool.Configure` + `applyUpstreamProxy()`. It does **NOT** re-run `loadMTLSAndOCSP` — meaning mTLS client-cert and OCSP enablement are **startup-only** at the YAML layer, and only mutable via the admin API at runtime. This is asymmetric: pool config is hot-reloadable, mTLS/OCSP is not. Worth noting in the report, but it's pre-existing behaviour, not a P5.1 finding.

### 5.3 Config-version rollback (`configversion.go`)

`captureConfigBackup` / `applyConfigBackup` (rollback) do **NOT** capture or restore `Upstream.Proxies` or OCSP state. A rollback from v3 to v2 will leave the operator's currently-set parent proxies in place, even if v2 had a different set. Pre-existing behaviour; out of P5.1 scope.

### 5.4 Cluster sync (`controlplane.go ConfigSnapshot`)

`ConfigSnapshot` (`controlplane.go:70`) does **NOT** carry:
- Upstream proxies (`fc.Upstream.Proxies`)
- Health-check interval
- Circuit-breaker thresholds
- mTLS client cert/key
- OCSP enable/disable

CP→DP sync therefore does not write `upstreamTransport` or `upstreamPool` on DP nodes. DP nodes configure upstream independently from their own local YAML. Pre-existing design; out of P5.1 scope.

---

## 6. Hot-path concurrency risks

| Risk | Severity | Description |
|---|---|---|
| **R-1**: `upstreamTransport.Proxy` write races with stdlib reads | MEDIUM (data race, rare trigger) | Admin/SIGHUP writes `.Proxy` while `http.Transport.RoundTrip` reads it. Today the trigger is "operator changes upstream config under load" — uncommon, but possible. Race detector would flag if interleaved in a test. |
| **R-2**: `upstreamTransport.TLSClientConfig` overwrite races with stdlib TLS dial | MEDIUM (data race, rare trigger) | Admin enabling OCSP rebuilds `TLSClientConfig` if nil, then sets two function fields. The struct is read field-by-field during TLS handshake; a torn read could produce a `tls.Config` with `Certificates` set but `VerifyPeerCertificate` nil (or vice versa). |
| **R-3**: `apiRestoreBackup` partial application | LOW (operator-visible quirk) | Restoring a backup re-`Configure`s the pool but does NOT call `applyUpstreamProxy()`. The pool has the new proxies, but `upstreamTransport.Proxy` still points at the old `ProxyFunc` closure — which captures `upstreamPool` by pointer, so the next call will use the new proxies. **Net effect:** R-3 is benign because `ProxyFunc()` is a closure over the pool pointer (`upstream.go:195–202`); the closure works against whatever proxies the pool currently holds. The asymmetry is cosmetic. |
| **R-4**: TLS-config write torn between two callbacks | MEDIUM (potentially security-relevant) | `ConfigureTransportOCSP` first writes `VerifyPeerCertificate`, then writes `VerifyConnection`. A concurrent TLS handshake landing between those two lines would have OCSP for non-resumed sessions only. Very narrow window. |
| **R-5**: `upstreamPool` snapshot in `Next()` operates on stale slice | LOW (benign) | `Next()` takes `p.mu.RLock()`, copies `proxies` slice header, releases the lock, then iterates. If `Configure` runs between the unlock and the iteration, the iteration uses the old slice — which is the correct snapshot behaviour. No race; documented design. |

**R-1, R-2, and R-4 are the structural reason P5.3 cannot be a slice-style extraction.** Fixing them requires either:

- **(a) Atomic pointer swap**: replace `var upstreamTransport = &http.Transport{...}` with `var upstreamTransportPtr atomic.Pointer[http.Transport]`. Every reader becomes `upstreamTransportPtr.Load()`. Every writer constructs a NEW `*http.Transport` and `Store`s it. ~4–6 reader sites + 4 writer sites.
- **(b) Builder + RWMutex on a holder type**: encapsulate `upstreamTransport` behind a `type upstreamTransportHolder struct { mu sync.RWMutex; t *http.Transport }` with `Get()` returning a snapshot. More code, same effect, slightly different read overhead.

Both are MEDIUM-HIGH risk because every outbound HTTP/S request goes through this path. A regression turns proxy traffic into a stall or a connection storm. **Lab-required** is the correct gate.

---

## 7. Shutdown interactions

- The health-check goroutine exits on `appLifecycleCtx.Done()` via the `app-lifecycle-cancel` early hook (order 40).
- `upstreamTransport.CloseIdleConnections()` is **NOT called by any shutdown hook**. Idle keepalive connections to parent proxies persist until OS process exit. **Pre-existing FD-cleanup gap; out of P5 scope.** (If the operator runs as a long-lived process, the OS reclaims FDs on exit; if running under a supervisor that signals SIGKILL after timeout, idle conns are torn down ungracefully — same as today, no regression.)
- No upstream-related shutdown ordering changes are needed for P5.2 (the contract-test slice). P5.3 may want to add an `upstream-transport-close-idle` hook **only if** it explicitly intends to drain in-flight requests through the transport before tearing it down — that decision belongs in P5.3's design, not in this discovery.

---

## 8. Cross-cut: existing test coverage

| File | Coverage |
|---|---|
| `upstream_test.go` (29 tests) | CB state transitions, pool round-robin, `Configure` replace, `ApplyUpstreamProxy` sets `Transport.Proxy`, concurrent CB / `Next` access, invalid-URL handling, CB-open-fallback. **No tests interleave runtime `Configure` with hot-path traffic.** |
| `upstream_healthcheck_loop_test.go` (3 tests) | Loop exits on ctx cancel; pre-cancelled ctx returns immediately; invalid inputs return without panic. |
| `mtls_ocsp_startup_test.go` (7 tests) | Resolver determinism; loader no-op on empty config; client-cert load + nil-TLS-config bootstrap; OCSP enable wiring; preserves existing TLS config when set. **Calls `ConfigureTransportOCSP` only in single-threaded test context — no concurrent reader present.** |

**Gap relevant to P5.2:** there is no contract test pinning the post-condition "after a successful startup, `upstreamTransport.TLSClientConfig` carries BOTH mTLS certs AND the OCSP verifier wrappers (when both are configured)." This is exactly the wrong-order regression P5.2 is designed to prevent. P5.2 should add:

```go
func TestUpstreamTransport_PostStartup_HasBothMTLSAndOCSP(t *testing.T) { … }
func TestUpstreamTransport_WrongOrder_ClobbersMTLS(t *testing.T) { t.Skip("informational; P5.3 will fix") }
```

(Per the P5.2 roadmap entry — no implementation needed in this discovery.)

---

## 9. Verdict on Phase 5 strategy

### 9.1 P5.1 — discovery
This document. **Complete.** No production code; no roadmap expansion; no speculative redesigns.

### 9.2 P5.2 — contract tests (recommended next PR)
Pure test-only addition. Pins the current `mTLS-then-OCSP` ordering and the post-condition. Cannot fail today (the ordering is correct in `main.go:195, 197`). Designed to fail loudly IF a future refactor reorders the calls. **Fits cleanly under the slice / contract-test convention used by P3 and P4.** No ownership boundary crossed.

### 9.3 P5.3 — single-constructor `upstreamTransport`
**This is the first true ownership-boundary refactor in the Runtime-Ownership program.** Reasons:

1. **Surface change at the reader side.** All prior slice work preserved the read surface (handlers continue to read `bl`, `connLimiter`, `ipf`, `rl`, `globalSyslog`, etc. by their original names). P5.3 must change how `upstreamTransport` is read — every hot-path access becomes a load through an atomic pointer or RWMutex-protected getter.
2. **Coordinated change across three runtime mutators.** `applyHotReload`, `apiUpstreamProxies`, `apiOCSPConfig` all need to switch from in-place mutation to "build a new transport + atomic swap." If any one is missed, the race persists for that path.
3. **Failure mode is silent.** A mishandled refactor produces intermittent TLS handshake failures or wrong-cert presentations under load — observable only with load testing in a lab.

This is consistent with the existing roadmap gating: P5.3 is already marked **lab-required**, **MEDIUM-HIGH**, gated on P5.1 + P5.2 + lab smoke. Nothing in this discovery changes those gates.

### 9.4 Beyond P5
The pattern observed here — "wrap a hot-path-read singleton with an atomic-pointer holder" — will likely recur for `caRuntime`, `certMgr` (Phase 6.3), and parts of the cluster store. P5.3 is the prototype for that pattern; the conclusions of its lab work should feed into Phase 6.

---

## 10. Findings worth filing as deferred follow-ups (NOT P5 scope)

These were uncovered during this discovery but are out of P5.1's scope. They are noted here so they aren't lost; they should be triaged separately and may belong in a different phase or in a future discovery cycle.

| ID | Finding | Pre-existing? |
|---|---|---|
| **U-1** | `apiRestoreBackup` runs `upstreamPool.Configure` without `applyUpstreamProxy()`. Cosmetic (the `ProxyFunc` closure captures the pool pointer, so the next call sees the new proxies), but operator-visible asymmetry vs. the other admin paths. | Yes |
| **U-2** | `apiOCSPConfig` POST `Enabled=false` does NOT clear `VerifyPeerCertificate` / `VerifyConnection` on `upstreamTransport.TLSClientConfig`. The callbacks no-op via `globalOCSP.enabled` atomic gate, so behaviour is correct; the asymmetry is cosmetic. | Yes |
| **U-3** | `upstreamTransport.CloseIdleConnections()` is never called during shutdown. FD-cleanup gap; benign in practice. | Yes |
| **U-4** | `applyHotReload` re-applies the upstream pool but NOT mTLS/OCSP. SIGHUP cannot rotate the client cert — the operator must restart. | Yes |
| **U-5** | `ConfigSnapshot` (CP→DP cluster sync) does not carry upstream proxies, OCSP, or mTLS state. DP nodes configure upstream independently from local YAML. | Yes (design decision) |
| **U-6** | `configversion.go` rollback does not restore upstream/OCSP/mTLS state. A rollback from v3→v2 leaves current upstream config in place. | Yes |

**None of U-1 through U-6 are required for P5.2 or P5.3 to proceed.** They are observability rather than blockers.

---

## 11. References

- `proxy.go:672, 1024, 1038–1042` — declaration, hot-path read, `applyUpstreamProxy`
- `upstream.go:1–319` — pool + circuit breaker + health check
- `ocsp.go:42, 217–238` — `globalOCSP`, `ConfigureTransportOCSP`
- `mtls_ocsp_startup.go:15–34` — startup-time mTLS + OCSP application
- `main.go:179, 195, 197, 940–946, 1039–1043, 1725–1750, 2249–2258` — startup wiring + hot-reload path
- `ui_config.go:521, 1014–1031, 1043–1057` — admin-API upstream paths
- `ui_security.go:1133–1158` — admin-API OCSP toggle
- `controlplane.go:70–`  — `ConfigSnapshot` definition (excludes upstream)
- `configversion.go` — `captureConfigBackup` / rollback (excludes upstream)
- `upstream_test.go`, `upstream_healthcheck_loop_test.go`, `mtls_ocsp_startup_test.go` — current test coverage
- `roadmap/ARCH_DISCOVERY.md:203–209, 448` — Risk #2 and the original S6 declaration
- `roadmap/RUNTIME-OWNERSHIP.md:280–296` — Phase 5 plan and P5.3 lab gate
