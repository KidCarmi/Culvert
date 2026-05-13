# P5.3 — Upstream Transport Ownership Model

**Status:** Design only. No production code, no tests, no benchmarks.
**Decision:** Approved.
**Inputs:** `roadmap/RUNTIME-OWNERSHIP.md`, `roadmap/UPSTREAM-TRANSPORT-DISCOVERY.md` (P5.1), `roadmap/UPSTREAM-TRANSPORT-LAB-PLAN.md` (P5.2.1), `upstream_transport_contract_test.go` (P5.2).

---

## 0. Chosen model

**Option A — `atomic.Pointer[http.Transport]` + package-level `sync.Mutex` for serializing writers + immutable-after-publish convention.**

In one sentence: the read/write asymmetry (every proxied request reads the transport; mutations happen ~1–10 times/day) plus the program-wide "correctness and ownership clarity first" criterion both point at atomic.Pointer, where the *type system itself* enforces the "you cannot modify a published transport, you can only publish a new one" rule.

**Immutable-after-publish semantics are mandatory.** That is the entire correctness argument. Direct field mutation on a loaded transport becomes a convention violation, easy to spot in code review and detectable by the P5.2 contract suite and the new P5.3 race tests.

---

## 1. Per-dimension comparison

### 1.1 Reader hot-path cost

| | Option A (atomic.Pointer) | Option B (RWMutex holder) |
|---|---|---|
| Read primitive | `upstreamTransportPtr.Load()` — single CPU instruction with acquire fence | `RLock()` + load + `RUnlock()` — typically 10–50 ns |
| Lock contention | None; readers never block readers or writers | Pending writer blocks new readers (Go's RWMutex starvation-prevention) |
| Cache friendliness | One pointer-sized load, branch-free | Atomic counter + state machine; more cache traffic |
| Behaviour under concurrency | Linear scaling | Latency tail at high reader rate during writer activity |

**Frequency context (`proxy.go:672`).** Every proxied HTTP/HTTPS request reads `upstreamTransport` to construct its per-request `http.Client`. Production deployments are likely in the hundreds-to-thousands req/s range sustained. A 10–50 ns per-read penalty under Option B is ~µs/s of CPU cost at 1000 req/s — not huge, but free CPU is better than spent CPU, and the latency-tail behaviour under load is the harder concern.

**Outcome.** Option A wins by orders of magnitude on read cost and contention.

### 1.2 Writer complexity

Current writers and their target fields:

| Writer | Touches | Trigger |
|---|---|---|
| `applyUpstreamProxy()` | `.Proxy` | Startup + `applyHotReload` + `apiUpstreamProxies` |
| `loadMTLSAndOCSP()` | `.TLSClientConfig`, `.Certificates`, `.MinVersion` | Startup |
| `ConfigureTransportOCSP()` | `.TLSClientConfig.VerifyPeerCertificate`, `.VerifyConnection` | Startup + `apiOCSPConfig` |
| `applyHotReload()` | calls `applyUpstreamProxy` | SIGHUP |
| `apiUpstreamProxies` POST | calls `applyUpstreamProxy` | Admin API |
| `apiOCSPConfig` POST | calls `ConfigureTransportOCSP` | Admin API |

Under **Option A** every writer routes through a single helper:

```go
swapUpstreamTransport(func(old *http.Transport) *http.Transport {
    new := cloneTransport(old)        // shallow copy of fields
    // apply this writer's specific delta:
    new.Proxy = upstreamPool.ProxyFunc()
    return new
})
```

`swapUpstreamTransport` takes a package-level `sync.Mutex`, calls Load, runs the updater, calls Store, calls `oldT.CloseIdleConnections()`. The write mutex serializes concurrent writers; readers never take it.

Under **Option B** the same builder closure exists via `holder.Update(fn)` which holds the write lock for the duration of the closure.

**Outcome.** Roughly equal writer ergonomics. Option B saves one mutex declaration; Option A's write surface is a textbook pattern.

### 1.3 TLS composition safety (the actual P5.3 problem)

This is the critical dimension — it is the entire reason P5.3 exists.

**R-4 (torn write in `ConfigureTransportOCSP`):**

Under **Option A**, the OCSP writer constructs a NEW `*http.Transport` with a fully-formed `*tls.Config` that has BOTH `VerifyPeerCertificate` and `VerifyConnection` set before publishing. The atomic Store makes the new transport visible to readers as a single memory-ordering event. No torn read possible.

Under **Option B** with naive `Set(t)`: same race as today's code. To fix, you must use `Update(fn)` and follow the same build-new-transport discipline. Direct mutation `t := holder.Get(); t.TLSClientConfig.X = …` is **still racy under Option B** because RLock protects the *pointer*, not the pointee.

Both options require build-new-transport semantics to fix R-4. **Option A makes that the only possible discipline; Option B requires the engineer to choose discipline.**

**mTLS + OCSP coexistence after swap.** Under Option A, the builder is the only place that composes both. The P5.2 contract `TestUpstreamTransport_PostStartup_HasBothMTLSAndOCSP` will keep proving correctness after each swap.

**Swap atomicity.** Both options publish atomically. Option A via `atomic.Pointer`; Option B via `RWMutex.Lock`. Both correct.

**Outcome.** Option A wins because it makes the safe path the *only* path.

### 1.4 Ownership clarity

| | Option A | Option B |
|---|---|---|
| Who owns transport creation | The builder helpers (`cloneTransport`, `newBaseUpstreamTransport`) | Same builders |
| Who is allowed to mutate transports | Nobody after Store; only builders | API surface allows `.Get()` users to mutate, **convention** forbids it |
| Direct field mutation outside builder | **Impossible by convention; API has no setter on the read surface** | Possible — `.Get()` returns a `*http.Transport` whose fields ARE writeable |
| Immutable-after-publish enforcement | Built into the read API (`Load()` returns a value treated as read-only by convention) | Requires social discipline OR deep-copy on `Get()` (impractical) |

**Outcome.** Option A wins decisively. This is the ownership story that justifies P5.3.

### 1.5 Lifecycle implications

**Old-transport cleanup.** When a swap publishes a new transport, the old transport's idle keepalive connections are released via `oldT.CloseIdleConnections()` called synchronously from inside the swap path. In-flight requests holding the old transport via their per-request `http.Client` are unaffected — they hold a strong reference; only IDLE conns are torn down.

**Synchronous vs deferred.** Synchronous from the caller's perspective. The actual TCP close happens in the transport's internal idle-conn manager — non-blocking.

**Goroutine implications.** `http.Transport` spawns internal goroutines for keepalive management. These exit when all conns close. `CloseIdleConnections()` accelerates this. Without it, idle conns stay open until OS-level keepalive times them out or GC collects the transport (which won't happen until all references — including in-flight ones — release).

**Outcome.** Both options handle lifecycle identically. The cleanup strategy is a design choice independent of A-vs-B. **Approved: synchronous `CloseIdleConnections()` inside the swap path.** This makes the `TestUpstreamTransport_OldTransportClosesIdleConns` (C2) lab test included in P5.3.

### 1.6 Testability

| | Option A | Option B |
|---|---|---|
| `-race` cleanliness | Intrinsically safe (atomic primitives) | Intrinsically safe (RWMutex primitives) |
| Deterministic swap testing | `oldPtr := upstreamTransportPtr.Load(); upstreamTransportPtr.Store(testT); t.Cleanup(...)` | `oldT := holder.Get(); holder.Set(testT); t.Cleanup(...)` |
| Snapshot/restore ergonomics | One-liner via Load/Store | One-liner via Get/Set |
| CI friendliness | Identical | Identical |

**Outcome.** Equal testability. The P5.2 contracts and the P5.3 lab plan apply to either model with minimal syntactic differences.

### 1.7 Migration complexity

**Production sites that need to change (from P5.1 discovery):**

| File:line | Current | Under A |
|---|---|---|
| `proxy.go:672` (hot read) | `Transport: upstreamTransport` | `Transport: getUpstreamTransport()` |
| `proxy.go:1040` (`applyUpstreamProxy`) | `upstreamTransport.Proxy = upstreamPool.ProxyFunc()` | `swapUpstreamTransport(func(old) *http.Transport { … })` |
| `mtls_ocsp_startup.go:21–24` | direct field writes | builder-based swap |
| `mtls_ocsp_startup.go:31` | `ConfigureTransportOCSP(upstreamTransport)` | called inside swap closure |
| `ui_security.go:1153` | same | same |
| `ConfigureTransportOCSP` (ocsp.go) | takes `*http.Transport` directly | unchanged signature; called inside swap closure |

**Test sites:**
- `upstream_transport_contract_test.go` — 3 tests with direct field reads. One-line updates to call `getUpstreamTransport()`.
- `mtls_ocsp_startup_test.go` — `resetMTLSOCSPGlobals` helper that snapshot/restores `upstreamTransport.TLSClientConfig`. Becomes "snapshot/restore the underlying transport via the new API."
- `upstream_test.go` `TestApplyUpstreamProxy_SetsTransportProxy` — one-line update.

**Risk of partial migration / hidden direct field writes:**

Under Option A: the global variable `upstreamTransport` is **removed**. Any code that referenced it gets a compile error. The compiler catches every site. There is no possible "hidden write" — direct field mutation requires `getUpstreamTransport().Proxy = …` which is syntactically obvious and reviewable. A grep for `getUpstreamTransport\(\)\.\w+\s*=` would catch any such write trivially.

**Outcome.** Option A's migration is compile-checked. Every miss surfaces at build time.

### 1.8 Future extensibility

| Feature | Option A | Option B |
|---|---|---|
| HTTP/2 tuning | Tunable via the builder; build-time choice each swap | Same |
| SOCKS5 support | Distinct dialer; same atomic-pointer pattern can hold a SOCKS5-enabled transport | Same |
| Per-policy upstreams | Generalizes to `map[policy]atomic.Pointer[http.Transport]` — clean | Generalizes to `map[policy]*upstreamTransportHolder` — clean |
| Dynamic trust stores | Build new transport with new RootCAs in builder, swap | Same |
| Transport layering (e.g. tracing wrappers) | Wrap in builder; published transport is the wrapped one | Same |

**Outcome.** Both options extend equally well. We do not over-rotate on hypothetical features — the choice is grounded in the **current** runtime mutation graph.

---

## 2. Approved ownership model

### 2.1 Concrete shape

```go
// upstream_transport.go (new file; declarations + helpers all live here)

var upstreamTransportPtr atomic.Pointer[http.Transport]

// Package-level mutex serializing writers. Readers do not take this.
var upstreamTransportWriteMu sync.Mutex

func init() {
    upstreamTransportPtr.Store(newBaseUpstreamTransport())
}

// getUpstreamTransport is the only public read API.
// The returned pointer MUST be treated as read-only.
func getUpstreamTransport() *http.Transport { return upstreamTransportPtr.Load() }

// swapUpstreamTransport is the only public write API.
// Serializes writers, applies the update via a builder closure,
// publishes the new transport, and synchronously closes idle conns
// on the old one.
func swapUpstreamTransport(update func(old *http.Transport) *http.Transport) {
    upstreamTransportWriteMu.Lock()
    defer upstreamTransportWriteMu.Unlock()
    old := upstreamTransportPtr.Load()
    new := update(old)
    if new == old {
        return // updater chose to no-op
    }
    upstreamTransportPtr.Store(new)
    old.CloseIdleConnections()
}
```

### 2.2 Approved mutation flow

Every existing mutator routes through `swapUpstreamTransport`:

```go
// applyUpstreamProxy
func applyUpstreamProxy() {
    if !upstreamPool.Enabled() { return }
    swapUpstreamTransport(func(old *http.Transport) *http.Transport {
        new := cloneTransport(old)
        new.Proxy = upstreamPool.ProxyFunc()
        return new
    })
}

// mTLS application
func applyMTLSToTransport(clientCert tls.Certificate) {
    swapUpstreamTransport(func(old *http.Transport) *http.Transport {
        new := cloneTransport(old)
        tlsCfg := cloneTLSConfig(new.TLSClientConfig) // or fresh if nil
        tlsCfg.Certificates = []tls.Certificate{clientCert}
        if tlsCfg.MinVersion == 0 { tlsCfg.MinVersion = tls.VersionTLS12 }
        new.TLSClientConfig = tlsCfg
        return new
    })
}

// OCSP application (replaces ConfigureTransportOCSP's in-place mutation)
func applyOCSPToTransport() {
    swapUpstreamTransport(func(old *http.Transport) *http.Transport {
        new := cloneTransport(old)
        tlsCfg := cloneTLSConfig(new.TLSClientConfig)
        tlsCfg.VerifyPeerCertificate = globalOCSP.VerifyPeerCertificate
        tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error { /* … */ }
        new.TLSClientConfig = tlsCfg
        return new
    })
}
```

`cloneTransport(old)` and `cloneTLSConfig(old)` are small, package-private helpers that produce a shallow-copy of the struct. They are the only approved way to seed a new transport from an existing one.

### 2.3 Approved cleanup model

- `swapUpstreamTransport` calls `old.CloseIdleConnections()` synchronously after Store.
- In-flight requests keep their strong reference to the old transport via the per-request `http.Client` they constructed — they are NOT interrupted.
- Only idle keepalive connections are torn down.
- No deferred cleanup, no goroutines.
- This contract enables the C2 lab test (`TestUpstreamTransport_OldTransportClosesIdleConns`) — included in the P5.3 implementation PR.

### 2.4 Approved ownership rules

1. `upstreamTransport` as a global variable is **removed**. Replaced by `upstreamTransportPtr atomic.Pointer[http.Transport]`.
2. Reads route through `getUpstreamTransport()` exclusively.
3. Writes route through `swapUpstreamTransport(update)` exclusively. `update` is a pure function that takes the current transport and returns a NEW transport. **It MUST NOT mutate the input.**
4. The returned `*http.Transport` from `getUpstreamTransport()` is **read-only by convention**. The convention is documented at the function's docstring, in CLAUDE.md (added in the P5.3 implementation PR), and reinforced by the absence of any setter on the read surface.
5. `cloneTransport(old)` and `cloneTLSConfig(old)` are the ONLY approved construction helpers for seeding a new transport from an existing one. They live alongside `swapUpstreamTransport` in the same file and are package-private.
6. Direct field assignment (e.g. `transport.Proxy = …` outside the update closure) is **forbidden**. Code review enforces this; the P5.2 contract tests detect post-condition violations.
7. `ConfigureTransportOCSP(t *http.Transport)` becomes an internal helper invoked from inside the OCSP swap closure. Its external signature can be retained for backward compatibility but its only call site is inside the swap.
8. Tests that snapshot/restore the transport do so via `Load()`/`Store()` on the atomic pointer — same one-liner as the production read/write paths.

### 2.5 Immutable-after-publish semantics — **mandatory**

The chosen model enforces immutability via:

- **API-level:** `atomic.Pointer`'s surface has no field-modify operation; only Load/Store. This makes the "right" path the natural path.
- **Convention-level:** the function docstring states "the returned pointer MUST be treated as read-only. To mutate, use `swapUpstreamTransport`."
- **CLAUDE.md (added in P5.3's PR, NOT in this docs PR):** one-line convention note — "upstreamTransport is read-only after publication; mutate via `swapUpstreamTransport` only."
- **Test-level:** the P5.2 contracts plus the new P5.3 race tests (Category A from the lab plan) verify post-condition + no torn writes.

---

## 3. Rejected: Option B (RWMutex holder)

**Reasons for rejection:**

1. **Does not protect the pointee.** `holder.Get()` returns a `*http.Transport` whose fields are publicly writeable. The lock protects the pointer slot only. A caller that holds the result can mutate it post-Get and produce exactly the same races we're trying to eliminate.
2. **Higher reader cost without compensating benefit.** RLock is 10–50 ns vs `atomic.Load`'s ~1 ns. For the proxy hot path this is paying for safety we don't get (per point 1) and lock contention we don't need.
3. **Latency tail under concurrency.** Go's RWMutex prefers writers to prevent starvation; a pending writer blocks new readers. Under sustained traffic with occasional admin-API writes, this produces brief latency spikes that don't exist under atomic.Pointer.
4. **Same builder discipline required.** To actually fix R-4 under Option B you still need `Update(fn)` with a build-new-transport closure. The "advantage" of being able to mutate in place is exactly what we don't want.
5. **Wider misuse surface in code review.** `holder.Get().X = y` looks innocent but is unambiguously wrong under the immutability convention. Option A makes that pattern more obviously a convention violation because the API surface invites a build-new pattern instead.

**Where Option B might have been better.** A write-heavy mutation pattern (dozens of writes per second) where the per-write build-clone cost mattered. Culvert is not that workload — admin-API writes are ~1–10/day.

---

## 4. Expected P5.3 implementation steps

This is the shape of the **next** PR. **Not part of this docs PR.**

1. **New file `upstream_transport.go`** with:
   - `var upstreamTransportPtr atomic.Pointer[http.Transport]`
   - `var upstreamTransportWriteMu sync.Mutex`
   - `getUpstreamTransport()`
   - `swapUpstreamTransport(update)`
   - `cloneTransport(old)`
   - `cloneTLSConfig(old)`
   - `newBaseUpstreamTransport()`
2. **Remove the old `var upstreamTransport = &http.Transport{...}`** in `proxy.go:1024`; move initialization into `newBaseUpstreamTransport()` called from `init()`.
3. **Update readers:**
   - `proxy.go:672` — one-line change to `getUpstreamTransport()`.
4. **Update writers — convert each to use `swapUpstreamTransport`:**
   - `proxy.go:1040` (`applyUpstreamProxy`).
   - `mtls_ocsp_startup.go:21–32` (`loadMTLSAndOCSP`).
   - `ocsp.go:217–238` (`ConfigureTransportOCSP`) — internal call site moves inside the swap closure.
   - `ui_security.go:1153` (apiOCSPConfig handler) — one-line change to call the new swap helper.
5. **Update tests:**
   - `upstream_transport_contract_test.go` — replace `upstreamTransport.X` reads with `getUpstreamTransport().X` reads (3 tests).
   - `mtls_ocsp_startup_test.go` — adapt `resetMTLSOCSPGlobals` to snapshot/restore via the pointer.
   - `upstream_test.go` `TestApplyUpstreamProxy_SetsTransportProxy` — one-line update.
6. **Add the lab tests** from `roadmap/UPSTREAM-TRANSPORT-LAB-PLAN.md`:
   - `upstream_transport_race_test.go` — A1, A2, A3, A4.
   - `upstream_transport_swap_test.go` — B1, B2, C1, **C2** (approved per §2.3), E1.
7. **Add the convention note to CLAUDE.md** — one line in Code Conventions: "upstreamTransport is read-only after publication; mutate via `swapUpstreamTransport` only."
8. **Update `roadmap/RUNTIME-OWNERSHIP.md`** to mark P5.3 complete.

**Estimated P5.3 PR size:** ~+450 / −80 across ~10 files. Larger than any prior P5 PR but bounded. P5.3 remains `lab-required` per the existing roadmap gate — CI tests reduce risk; the rollout still needs real-lab / soak validation.

---

## 5. Risk analysis

| Risk | Severity | Mitigation |
|---|---|---|
| Missed reader site (someone still reads via the old global name) | HIGH | Removing the `upstreamTransport` global causes a compile error at every missed site. No silent miss possible. |
| Missed writer site (someone still mutates fields directly) | MEDIUM | Compile error at the global; remaining sites caught by code review. P5.2 contract tests detect post-condition violations. |
| Subtle clone bug (`cloneTransport` misses a field) | MEDIUM | The `http.Transport` struct is well-documented; clone helper is small and unit-tested. Add a test that asserts every field of a cloned transport matches the input. |
| In-flight requests broken by transport swap | LOW | In-flight requests hold the old transport via their per-request `http.Client`. `CloseIdleConnections()` only closes IDLE conns; active conns survive. Verified by lab test A1. |
| `old.CloseIdleConnections()` blocks the swap path | LOW | Doc'd as non-blocking; only triggers immediate close on already-idle conns. If we observe blocking in lab, change to `go old.CloseIdleConnections()`. |
| Concurrent swap-and-restore in tests interleaves badly | LOW | Tests use `t.Cleanup` to restore; non-parallel by convention; snapshot/restore is a single Store. |
| Performance regression on read path | LOW | Atomic.Load is faster than the current direct-global-read in practice. Worst case: identical. Best case: better. |
| GC behaviour change | LOW | The swapped-out transport stays alive until in-flight requests release it. GC handles this correctly. |

**No risks classified as critical.** All identified risks have either compile-time enforcement (the strongest mitigation) or test coverage.

---

## 6. Approved sequencing

1. **This docs-only PR** (`docs(roadmap): choose upstream transport ownership model`) lands first.
2. **After it merges**, the P5.3 implementation PR proceeds with:
   - The mutation flow in §2.2.
   - The cleanup model in §2.3.
   - The migration steps in §4.
   - The CI lab tests **A1, A2, A3, A4, B1, B2, C1, C2, E1** from `roadmap/UPSTREAM-TRANSPORT-LAB-PLAN.md`.
   - The existing P5.2 contract tests must remain green (possibly with one-line syntactic updates to the new read API).
3. **P5.3 remains `lab-required`** per the roadmap gate. CI-backed lab tests are necessary but not sufficient for rollout.

---

## 7. References

- `roadmap/UPSTREAM-TRANSPORT-DISCOVERY.md` — P5.1 mutation-graph discovery; identifies R-1, R-2, R-4.
- `roadmap/UPSTREAM-TRANSPORT-LAB-PLAN.md` — P5.2.1 CI lab plan; 8 (+1 conditional) tests for P5.3 validation.
- `upstream_transport_contract_test.go` (PR #234) — P5.2 post-startup contracts that P5.3 must preserve.
- `roadmap/RUNTIME-OWNERSHIP.md` §280–296 — P5 gate definitions; lab-required MEDIUM-HIGH on P5.3.
- `proxy.go:672, 1024, 1038–1042` — declaration, hot-path read, `applyUpstreamProxy`.
- `mtls_ocsp_startup.go:15–34` — startup-time mTLS + OCSP application.
- `ocsp.go:217–238` — `ConfigureTransportOCSP` — the R-4 torn-write site.
- `ui_security.go:1133–1158` — runtime OCSP-toggle admin handler.
- `ui_config.go:1014–1031, 1043–1057` — admin-API upstream paths.
- `main.go:2249–2258` — `applyHotReload` upstream branch.
