# P5.3 — Upstream Transport CI-Backed Lab Plan

**Status:** Docs only. No production code, no tests, no P5.3 implementation.
**Scope:** Specifies the CI-runnable tests that give P5.3 (single-constructor / atomic-swap `upstreamTransport`) refactor confidence without a physical lab.
**Sibling docs:** `roadmap/UPSTREAM-TRANSPORT-DISCOVERY.md` (P5.1).
**Pinned-behaviour artefact:** `upstream_transport_contract_test.go` (P5.2 / PR #234).

---

## 0. Context recap

P5.1 (PR #233) identified three live data-race surfaces on `upstreamTransport`:

- **R-1**: `upstreamTransport.Proxy` write vs stdlib `http.Transport.RoundTrip` read.
- **R-2**: `upstreamTransport.TLSClientConfig` rebuild vs TLS handshake field reads.
- **R-4**: Torn-write window in `ConfigureTransportOCSP` between `VerifyPeerCertificate = …` and `VerifyConnection = …`.

P5.2 (PR #234) pinned the post-startup composition contracts so a future refactor that drops mTLS / OCSP coexistence fails loudly.

P5.3 will:

1. Eliminate R-1, R-2, R-4 via an atomic-swap surface.
2. Update every reader (proxy hot path at `proxy.go:672`).
3. Update every writer (`applyHotReload`, `apiUpstreamProxies`, `apiOCSPConfig`, `applyUpstreamProxy`).

This document specifies the CI tests that prove correctness of that refactor **without a physical lab**. Real-lab criteria (performance, FD exhaustion, real upstream interaction) remain the rollout gate — see §3.

---

## 1. Test plan by category

### Category A — Concurrent mutation vs hot-path traffic (race-detector-driven)

These tests spin up httptest fixtures, drive HTTP/S requests in goroutines, and concurrently invoke the production mutation paths under `-race`. **All of Category A lands WITH P5.3** because they will trip the race detector on `main` today — the races already exist, and the tests are how we prove P5.3 fixed them.

#### A1 — `TestUpstreamTransport_ProxyMutationUnderTraffic`

| Aspect | Detail |
|---|---|
| **Scenario** | Two httptest parent-proxy servers `pp` and `pp2` (each forwarding to an httptest destination `dst`). Traffic goroutine fires up to 1000 HTTP GETs through `upstreamTransport` against `dst.URL`. Mutation goroutine alternates `upstreamPool.Configure([pp.URL], …) + applyUpstreamProxy()` then the same for `pp2`. |
| **Mutator exercised** | `applyUpstreamProxy()` — the byte-equivalent caller used by both `applyHotReload` and `apiUpstreamProxies`. |
| **What failure proves** | Race detector flags a write/read on `upstreamTransport.Proxy`, OR the traffic goroutine sees a torn-read symptom (nil-Proxy panic from stdlib). |
| **Lands** | **WITH P5.3.** Will fail under `-race` on main. |
| **Iteration bound** | Up to 1000 (lightweight HTTP — no TLS). |
| **Limitation vs lab** | Synthetic httptest proxies don't model real upstream latency / partial failures / Squid quirks. P99 latency under churn not measured. |

#### A2 — `TestUpstreamTransport_OCSPMutationUnderTLSTraffic`

| Aspect | Detail |
|---|---|
| **Scenario** | `httptest.NewTLSServer` as `dst`. Traffic goroutine: 100–250 HTTPS GETs through `upstreamTransport` (custom RootCAs pointing at `dst` cert). Mutation goroutine: 100+ iterations alternating `ConfigureTransportOCSP(upstreamTransport)` and clearing the verify callbacks. |
| **Mutator exercised** | `ConfigureTransportOCSP` — the byte-equivalent caller used by `apiOCSPConfig`. |
| **What failure proves** | Race detector flags writes/reads on `TLSClientConfig.VerifyPeerCertificate` / `VerifyConnection`, OR TLS handshake sees a torn read (one callback set, the other nil mid-write — exactly R-4). |
| **Lands** | **WITH P5.3.** |
| **Iteration bound** | 100–250 (heavier HTTPS handshake cost; keep CI runtime under control). |
| **Limitation vs lab** | Real OCSP responders aren't dialed; end-to-end OCSP correctness is owned by `ocsp_test.go`. We test only the field-write coherency. |

#### A3 — `TestUpstreamTransport_HotReloadProxyChurnUnderTraffic`

| Aspect | Detail |
|---|---|
| **Scenario** | Same httptest fixture as A1. Mutation goroutine calls `applyHotReload(fc)` directly with a `FileConfig` populated with rotating proxies. |
| **Mutator exercised** | `applyHotReload(fc)` — the SIGHUP-specific code path. |
| **What failure proves** | Same race surface as A1, but driven through the SIGHUP-only branch. Catches regressions where P5.3 misses `applyHotReload`. |
| **Lands** | **WITH P5.3.** |
| **Iteration bound** | Up to 1000 (lightweight HTTP path). |
| **Limitation vs lab** | Doesn't deliver real SIGHUP; calls `applyHotReload` directly. The signal-handler path is unchanged by P5.3. |

#### A4 — `TestUpstreamTransport_OCSPToggleViaAdminAPIUnderTraffic`

| Aspect | Detail |
|---|---|
| **Scenario** | Mutation goroutine invokes the `apiOCSPConfig` handler internally (httptest request → handler → `decodeJSON` → `globalOCSP.Enable` + `ConfigureTransportOCSP`). Traffic goroutine fires HTTPS concurrently as in A2. |
| **Mutator exercised** | The actual `apiOCSPConfig` admin-API handler (not just its helper). |
| **What failure proves** | Catches regressions where P5.3's swap covers the helper but not the admin-API handler. |
| **Lands** | **WITH P5.3.** |
| **Iteration bound** | 100–250 (HTTPS-bound). |
| **Limitation vs lab** | No real admin auth; handler called directly. Auth layer is independent. |

---

### Category B — Post-swap composition

Tests that exercise the **new P5.3 swap surface** (whatever its API is — likely `atomic.Pointer[http.Transport].Store(newTransport)` or a holder with `RWMutex`-protected setter). These can't exist before P5.3.

#### B1 — `TestUpstreamTransport_SwapPreservesMTLSAndOCSP`

| Aspect | Detail |
|---|---|
| **Scenario** | Configure mTLS + OCSP. Force a swap via the new P5.3 builder + atomic store. Assert post-swap state has `Certificates` len ≥ 1 AND both OCSP callbacks non-nil. |
| **What failure proves** | The new swap path loses state. Direct analogue of P5.2's `TestUpstreamTransport_PostStartup_HasBothMTLSAndOCSP` for the post-swap surface. |
| **Lands** | **WITH P5.3.** |
| **Limitation vs lab** | None — pure correctness test; CI is the right venue. |

#### B2 — `TestUpstreamTransport_ConcurrentSwapsAreConsistent`

| Aspect | Detail |
|---|---|
| **Scenario** | Drive 100+ concurrent swaps from multiple goroutines. Each swap installs a transport with a distinguishing sentinel (e.g. a unique `MaxIdleConns` value drawn from a per-goroutine counter). After barrier-sync, assert the final loaded transport matches **exactly one** of the inputs (no torn intermediate). |
| **What failure proves** | Atomic-swap implementation has a torn-write boundary. Specifically targets R-4-class scenarios at the swap point. |
| **Lands** | **WITH P5.3.** |
| **Iteration bound** | 100–250 swaps. |
| **Limitation vs lab** | Synthetic field used as the witness — doesn't test real upstream connection state survival across swaps. |

---

### Category C — Lifecycle / leak detection

#### C1 — `TestUpstreamTransport_SwapDoesNotLeakGoroutines`

| Aspect | Detail |
|---|---|
| **Scenario** | Capture `runtime.NumGoroutine()` before the test. Perform 20+ swaps with 5 requests each. Force GC + brief sleep. Capture again. Assert delta ≤ small threshold (e.g. 5). |
| **What failure proves** | P5.3's swap path leaks goroutines (forgotten timers, unbounded retry loops in the swapped-out transport). |
| **Lands** | **WITH P5.3.** |
| **Iteration bound** | 20 swaps × 5 requests = 100 ops. |
| **Limitation vs lab** | Goroutine count is a proxy for FD/resource leak. Doesn't catch slow leaks over hours. Lab soak test still required. |

#### C2 — `TestUpstreamTransport_OldTransportClosesIdleConns` (conditional)

| Aspect | Detail |
|---|---|
| **Scenario** | After a swap, call whatever P5.3 names the idle-close API on the previous transport. Verify it returns without panic. Confirm subsequent traffic uses the new transport (sentinel field check). |
| **What failure proves** | Swap leaves stale keepalive connections behind. |
| **Lands** | **WITH P5.3, ONLY IF** P5.3 introduces an explicit idle-close API or old-transport close behavior. If P5.3 chooses "let GC handle it" (acceptable for a transport-only refactor — `http.Transport` is GC-friendly), this test is omitted. **The choice is made at P5.3 design time, not now.** |

---

### Category D — Existing P5.2 contracts (no new tests)

The three contracts in `upstream_transport_contract_test.go` (PR #234) must still pass after P5.3:

- `TestUpstreamTransport_StartupComposition_PoolThenMTLSOCSP`
- `TestUpstreamTransport_PostStartup_HasBothMTLSAndOCSP`
- `TestUpstreamTransport_PreservesExistingTLSConfig_WithMTLSAndOCSP`

**Lands.** Already merged in PR #234.

**Rework risk during P5.3.** If P5.3 replaces the global `upstreamTransport` with an atomic-pointer holder, these tests' direct field reads (e.g. `upstreamTransport.TLSClientConfig`) become reads of the underlying transport — they may need a one-line update to `upstreamTransport.Load().TLSClientConfig` (or whatever the P5.3 surface is). **The test BEHAVIOUR must remain identical**; only the access syntax may change. This minimal rework is acceptable inside P5.3.

---

### Category E — Reader-surface migration sanity

#### E1 — `TestUpstreamTransport_GetterReturnsCurrentInstance`

| Aspect | Detail |
|---|---|
| **Scenario** | Call the new P5.3 reader twice without an intervening swap; assert same pointer. Swap; call reader; assert new pointer. Revert; assert original pointer. |
| **What failure proves** | Reader is reading from stale state — P5.3's reader doesn't actually consult the atomic pointer / holder. |
| **Lands** | **WITH P5.3.** |
| **Limitation vs lab** | None — pure surface correctness test. |

---

### Category F — Pre-P5.3 watcher tests

**Decision: SKIP for now.** F1 (`TestUpstreamTransport_SequentialMTLSPlusOCSPThenRequest`) was evaluated and consciously dropped — likely redundant with existing `proxy_test.go` coverage. Reconsider only if a concrete coverage gap is identified later.

---

## 2. Land-before-vs-with-P5.3 summary

| Test | When | Status |
|---|---|---|
| **A1** `ProxyMutationUnderTraffic` | WITH P5.3 | new |
| **A2** `OCSPMutationUnderTLSTraffic` | WITH P5.3 | new |
| **A3** `HotReloadProxyChurnUnderTraffic` | WITH P5.3 | new |
| **A4** `OCSPToggleViaAdminAPIUnderTraffic` | WITH P5.3 | new |
| **B1** `SwapPreservesMTLSAndOCSP` | WITH P5.3 | new |
| **B2** `ConcurrentSwapsAreConsistent` | WITH P5.3 | new |
| **C1** `SwapDoesNotLeakGoroutines` | WITH P5.3 | new |
| **C2** `OldTransportClosesIdleConns` | WITH P5.3 conditionally | conditional on P5.3 design |
| **D** existing P5.2 contracts | merged | possibly minor syntax rework in P5.3 |
| **E1** `GetterReturnsCurrentInstance` | WITH P5.3 | new |
| **F1** sequential pre-flight | SKIP | dropped per decision |

**P5.3 PR new-test budget: 8 (A1–A4, B1, B2, C1, E1) + optionally C2.**

---

## 3. Limitations vs a real lab — explicit gate

| Dimension | CI can test | Lab still needed |
|---|---|---|
| Correctness under concurrent mutation | ✅ Category A | – |
| Race-detector clean under load | ✅ All of A under `-race` | – |
| Atomic-swap consistency | ✅ B2 | – |
| Reader-surface correctness | ✅ E1 | – |
| Goroutine leak detection | ⚠ C1 (approximate, bounded duration) | ✅ Soak test over hours |
| FD exhaustion | ❌ | ✅ Production-scale OS limits |
| P99 latency under churn | ❌ | ✅ Load test |
| Real OCSP responder behaviour | ❌ | ✅ Real CA / responder |
| Failover under network partition | ❌ | ✅ Chaos test |
| Long-duration stability | ❌ | ✅ Multi-day soak |
| Real upstream proxy behaviour (Squid quirks) | ❌ | ✅ Real Squid / corporate proxy |

**Key gate.** CI tests give us **correctness** under concurrent access — the race detector + deterministic scenarios catch the categorical bugs P5.3 is trying to fix. The lab gates the **rollout** for performance, resource exhaustion, and real upstream interaction. They are **complementary, not substitutes**.

**Even with the full CI plan green, P5.3 remains `lab-required` per the existing roadmap gate.** CI-backed lab tests reduce risk; they do not replace real lab / soak validation.

---

## 4. Implementation guardrails (when P5.3 work begins)

These are concrete conventions the eventual P5.3 PR must follow. They are NOT speculative architecture — they pin the test layout that this plan assumes.

### 4.1 Test-file layout

| File | Purpose | Tests |
|---|---|---|
| `upstream_transport_contract_test.go` | P5.2 contract tests (already merged) | 3 contract tests; **no concurrency** |
| `upstream_transport_race_test.go` | P5.3 Category A — concurrent mutation vs traffic | A1, A2, A3, A4 |
| `upstream_transport_swap_test.go` | P5.3 Categories B / C / E — swap correctness + lifecycle | B1, B2, C1, (C2), E1 |

**Rationale.** The contract tests are pure post-condition assertions and run cheaply. The race + swap tests are stress-style and run under `-race`. Keeping them in separate files makes it obvious which suite is responsible for which property, and aligns with `runtime_shutdown_wiring_test.go` precedent.

### 4.2 Iteration counts

- **Heavy HTTPS / OCSP / TLS handshake tests:** 100–250 iterations.
- **Lightweight HTTP / proxy churn tests:** up to 1000.
- **Hard rule:** each new test is bounded and CI-friendly. Total `-race` suite wall-clock budget remains under the current ~3-minute envelope.

### 4.3 Test mechanics

- **No `t.Parallel()`.** Tests mutate `upstreamTransport` / `upstreamPool` / `globalOCSP` globals; parallelism would create cross-test interference.
- **Snapshot/restore globals.** Reuse `resetMTLSOCSPGlobals` + `snapshotUpstreamProxyAndPool` from P5.2; add equivalents for the new P5.3 holder.
- **Barriered sync.** Use `sync.WaitGroup` or `errgroup` for deterministic completion under `-shuffle=on` / `-count=2`.
- **Per-test wall-clock cap.** Each test ≤ 5s under `-race`. Existing race suite is ~3 minutes total; we have headroom but not unlimited.
- **No real network.** All servers via `httptest`; no external DNS or outbound dials.
- **No Docker dependency.** Pure Go test runtime.

---

## 5. Next step

**After this docs PR lands, the next step is P5.3 design discovery, not implementation.**

P5.3 must first choose the ownership model:

- **(a) `atomic.Pointer[http.Transport]`** — minimal surface change; every reader becomes `upstreamTransportPtr.Load()`; every writer builds a new `*http.Transport` and stores it.
- **(b) Holder type with `RWMutex` + getter/setter methods** — e.g. `type upstreamTransportHolder struct { mu sync.RWMutex; t *http.Transport }` with `Get()` and `Set(...)`. More code, same effect, slightly different read overhead and clearer audit trail at call sites.

**No code change for either alternative until the design is reviewed and approved.** Both options are well-understood and the choice is a tradeoff between minimal-diff (a) and explicit-API (b), not a correctness question.

---

## 6. References

- `roadmap/UPSTREAM-TRANSPORT-DISCOVERY.md` — P5.1 mutation-graph discovery; identifies R-1, R-2, R-4 and the writer/reader inventory.
- `upstream_transport_contract_test.go` (PR #234) — P5.2 post-startup composition contracts that P5.3 must preserve.
- `roadmap/RUNTIME-OWNERSHIP.md` §280–296 — P5.1 / P5.2 / P5.3 gate definitions; `lab-required` MEDIUM-HIGH risk on P5.3.
- `proxy.go:672, 1024, 1038–1042` — declaration, hot-path read, `applyUpstreamProxy`.
- `mtls_ocsp_startup.go:15–34` — startup-time mTLS + OCSP application.
- `ocsp.go:217–238` — `ConfigureTransportOCSP` — the R-4 torn-write site.
- `ui_security.go:1133–1158` — runtime OCSP-toggle admin handler.
- `ui_config.go:1014–1031, 1043–1057` — admin-API upstream paths.
- `main.go:2249–2258` — `applyHotReload` upstream branch.
