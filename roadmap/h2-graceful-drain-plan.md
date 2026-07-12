# PR3d — Graceful GOAWAY-on-shutdown drain for inspected HTTP/2 tunnels

**Status:** PLAN (pre-implementation). This document is the hypothesis to be
validated by three independent reviewers before any code is written, mirroring the
Phase-1 review gate that preceded the native-H2 program (PR2/PR3).

**Scope discipline (carried from PR3):** correctness first, one inspection pipeline,
preserve every H1 and native-H2 invariant, no unrelated refactors. This PR touches
only the *client-facing* shutdown behavior of the native-H2 transport.

---

## 1. The gap (current state)

Native HTTP/2 inspection serves the client leg with `srv.ServeConn(clientTLS, …)`
(`proxy_tunnel_h2.go::handleInspectH2`). Today each call allocates its **own**
`&http2.Server{}` and `&http.Server{}` (BaseConfig) inline, and never calls
`http2.ConfigureServer`. Consequences on process shutdown:

- The inline `http2.Server` has `state == nil` (only `ConfigureServer` initializes
  it), so `serveConn`'s `s.state.registerConn(sc)` is a **no-op** — the tunnel's
  `serverConn` is not tracked for graceful shutdown.
- Nothing sends the client a **GOAWAY**. The inspected H2 tunnels *are* counted in
  `activeConns` (`recordActiveConn(±1)` wraps the dispatch in
  `handleInspectNativeALPN`), so `drainActiveTunnels` (shutdown order 100) *waits*
  up to 15s — but it only polls the counter; it neither notifies nor closes the
  tunnels. In-flight streams are therefore cut by process exit (a TCP FIN/RST),
  not a graceful GOAWAY.

This is the exact behavior the operator guide records under *Known limitations →
Graceful GOAWAY on shutdown* and the `proxy_tunnel_h2.go` header's PR3d deferral.

**Goal:** on shutdown, send each active inspected-H2 client a graceful GOAWAY so it
stops opening new streams and its in-flight streams finish within the drain window;
tunnels that finish drop out of `activeConns` and the existing drain observes them.
Streams still in flight past the drain window are cut exactly as today (no
regression) — with an OPTIONAL bounded hard-close backstop (§6, open decision).

---

## 2. Mechanism (verified against `golang.org/x/net@v0.56.0/http2` + `net/http`)

The idiomatic Go way to gracefully shut down hijacked/`ServeConn`-managed h2
connections — stated verbatim in `net/http`'s `Server.Shutdown` doc: *"Shutdown does
not attempt to close nor wait for hijacked connections… The caller should separately
notify such long-lived connections of shutdown… See `Server.RegisterOnShutdown`."*

Chain of facts (file:line in x/net@v0.56.0/http2/server.go):

1. `configureServer` (`:159`) sets `conf.state = &serverInternalState{activeConns: …}`
   and calls `s.RegisterOnShutdown(conf.state.startGracefulShutdown)` (`:173`) on the
   **base `*http.Server`**.
2. `serveConn` (`:260`) registers **every** connection it serves:
   `s.state.registerConn(sc)` (`:299`) / `defer s.state.unregisterConn(sc)` (`:300`).
   These are no-ops iff `state == nil` (i.e. `ConfigureServer` was not called).
3. `net/http.Server.Shutdown` (`server.go:3179`) fires each registered `onShutdown`
   via `go f()` **unconditionally** (independent of whether the base server ever
   `Serve`d), then polls `closeIdleConns()`. Our base server owns no listeners and no
   tracked conns, so `Shutdown` returns quickly after launching the trigger.
4. `serverInternalState.startGracefulShutdown` (`:123`) iterates `activeConns` and
   calls `sc.startGracefulShutdown()` (`:1315`) on each — which sends
   **GOAWAY(ErrCodeNo)** and, per its doc, *"The connection isn't closed until all
   current streams are done."* A true graceful drain (not the 1s `goAwayTimeout`
   error-close path — that is only for `goAway(errcode)`).

So: **configure one shared h2 server + base config via `ConfigureServer`; have every
inspected-H2 tunnel `ServeConn` on it; on shutdown call `base.Shutdown(ctx)` once →
every active tunnel GOAWAYs and drains.**

---

## 3. Design

### 3.1 One shared, ConfigureServer'd h2 server (lazily built, safely published)

Replace the per-tunnel inline servers with a single shared pair, built once:

```go
type h2InspectShared struct {
	srv  *http2.Server
	base *http.Server
}

var (
	h2InspectHolder atomic.Pointer[h2InspectShared] // published once; nil until first native-H2 tunnel
	h2InspectOnce   sync.Once
)

func getH2InspectShared() *h2InspectShared {
	h2InspectOnce.Do(func() {
		srv := &http2.Server{
			MaxConcurrentStreams: h2MaxConcurrentStreams,
			IdleTimeout:          tunnelIdleTimeout,
			WriteByteTimeout:     h2ConnWriteByteTimeout,
			MaxReadFrameSize:     h2MaxReadFrameSize,
		}
		base := &http.Server{MaxHeaderBytes: h2MaxHeaderBytes, ReadHeaderTimeout: h2ConnWriteByteTimeout}
		if err := http2.ConfigureServer(base, srv); err != nil {
			// Degrade gracefully: tunnels still work; only graceful GOAWAY is lost.
			logger.Printf("SSL_INSPECT(h2) ConfigureServer: %v — graceful shutdown disabled", err)
		}
		h2InspectHolder.Store(&h2InspectShared{srv: srv, base: base})
	})
	return h2InspectHolder.Load()
}
```

Why lazy + `atomic.Pointer`: zero cost when native H2 is never used; the shutdown
hook reads the holder without racing the first-tunnel initialization.

Why sharing one `*http2.Server` across all concurrent tunnels is correct: this is the
**normal** usage — a TLS server drives one `http2.Server` through many `ServeConn`
calls from `Serve`. The struct is read-only config plus the mutex-guarded
`serverInternalState.activeConns` map; per-conn state lives on each `serverConn`. All
our settings are compile-time constants, so a shared instance loses nothing.

### 3.2 `handleInspectH2` uses the shared server

```go
sh := getH2InspectShared()
sh.srv.ServeConn(clientTLS, &http2.ServeConnOpts{
	Context:    outer.Context(),
	Handler:    handler,
	BaseConfig: sh.base,
})
```

Everything else in `handleInspectH2`/`h2InspectStream` is unchanged: the upstream
`http2.Transport`/`ClientConn` (client side to the origin), the per-stream watchdog,
`runInspectExchange`, `h2CopyBody`, trailer forwarding. **One pipeline preserved.**

### 3.3 Shutdown hook: trigger GOAWAY before the drain

Add a late hook at a new order **between** proxy-server-shutdown (90) and
tunnel-drain (100):

```go
const shutdownOrderH2InspectGOAWAY = 95

// gracefulShutdownH2InspectTunnels sends GOAWAY to every active inspected H2 tunnel
// (no-op if native H2 never ran) so in-flight streams finish; the tunnel-drain hook
// (order 100) then waits on activeConns for them to complete.
func gracefulShutdownH2InspectTunnels(ctx context.Context) error {
	sh := h2InspectHolder.Load()
	if sh == nil {
		return nil // native H2 never used this run
	}
	goawayCtx, cancel := context.WithTimeout(ctx, 2*time.Second) // Shutdown returns fast; bound anyway
	defer cancel()
	_ = sh.base.Shutdown(goawayCtx) // fires RegisterOnShutdown → state.startGracefulShutdown
	return nil
}
```

Registered in `registerLateShutdownHooks`:
`reg.Register("h2-inspect-goaway", shutdownOrderH2InspectGOAWAY, gracefulShutdownH2InspectTunnels)`.

Ordering rationale: proxy-server-shutdown (90) closes the H1 CONNECT listener first,
so no new inspected-H2 tunnel can begin; then 95 GOAWAYs the established ones; then
100 waits on `activeConns` (now actually draining). No change to `drainActiveTunnels`
itself.

---

## 4. Exact code changes

| File | Change |
|---|---|
| `proxy_tunnel_h2.go` | Add `h2InspectShared`, `h2InspectHolder`, `h2InspectOnce`, `getH2InspectShared()`; rewrite `handleInspectH2` to `ServeConn` on the shared server; add `gracefulShutdownH2InspectTunnels`. Update the file-header PR3d note (GOAWAY-on-shutdown now shipped; note residuals). |
| `main_shutdown.go` | Add `shutdownOrderH2InspectGOAWAY = 95`; register the hook in `registerLateShutdownHooks`. |
| `inspect_h2_drain_test.go` (new) | Characterization tests (§7). |
| `docs/operator/http2-inspection.md` | Move "Graceful GOAWAY on shutdown" from *Known limitations* to *Security posture*; document the drain sequence + laggard behavior. |
| `proxy_tunnel_h2.go` header / RISK register | Note the closed deferral. |

No change to `runInspectExchange`, `h2CopyBody`, the watchdog, the H1 path, policy,
or config surfaces. No new CLI flag / config field (nothing operator-tunable is
introduced — the drain window reuses the existing 15s), so **no GUI-parity work**.

---

## 5. Invariants preserved

1. **One inspection pipeline (C5):** untouched — only client-leg connection
   lifecycle changes; per-stream request/response still flows through
   `runInspectExchange`.
2. **PR3 perf (zero-alloc `h2CopyBody`, adaptive flush):** untouched. The shared
   server actually *removes* the per-tunnel `http2.Server`/`http.Server` allocation
   (a small extra win, not the point).
3. **Per-stream inactivity watchdog:** untouched; still arms per stream in
   `h2InspectStream`.
4. **Truncation safety / block semantics / trailer forwarding:** untouched.
5. **H1 + strip path:** untouched (no `ConfigureServer`, no shared server on those
   paths).
6. **Security caps** (MaxConcurrentStreams=32, 1 MiB frame/header, Rapid-Reset,
   CONTINUATION-flood): all set on the shared `http2.Server` exactly as before —
   moved, not changed. **Verify** `ConfigureServer` does not silently reset any of
   them (it only *defaults* `IdleTimeout` when zero; ours is non-zero).

---

## 6. Edge cases & OPEN DECISIONS for reviewers

1. **Infinite / very-long in-flight streams (SSE, gRPC server-streaming, multi-GB
   download).** GOAWAY stops *new* streams but lets *existing* ones finish, so a
   conn with a never-ending stream will not close within the 15s drain; it is cut by
   process exit (unchanged from today).
   **OPEN DECISION A:** ship graceful-GOAWAY-only (laggards cut on exit, as now), or
   add a bounded hard-close backstop — after the drain window, close the still-open
   client conns so laggards get a definitive teardown instead of relying on process
   exit? A backstop needs a registry of live `clientTLS` conns (or reuse
   `ServeConnOpts.Context` cancellation). Recommendation: **ship graceful-only in
   PR3d** (minimal, matches Go server semantics) and track the backstop separately;
   invite reviewers to overrule if they consider exit-cut unacceptable.

2. **Tunnel that begins *after* the GOAWAY trigger.** Between listener-close (90) and
   the trigger (95) a CONNECT already accepted could still be handshaking and
   register into `activeConns`/`state` after `startGracefulShutdown` iterated. It
   would not receive a GOAWAY and would rely on the drain-window/exit cut. Narrow
   race; bounded. **Question:** acceptable, or should the trigger re-run / the
   holder refuse new `ServeConn` post-shutdown?

3. **`base.Shutdown` marks the base `inShutdown` permanently.** Fine at process
   shutdown (single-shot). Confirm no code path calls `getH2InspectShared()` and
   expects to serve *after* shutdown (there is none — shutdown is terminal).

4. **`ConfigureServer` mutates `base.TLSConfig`** (adds `h2` to NextProtos, installs
   `TLSNextProto["h2"]`). We never use `base` to terminate TLS (we hand `ServeConn`
   an already-handshaked `*tls.Conn`), so this is inert. Confirm no reviewer sees a
   surface where the mutated base TLSConfig leaks.

5. **`base.Shutdown` runs `onShutdown` as `go f()` (async).** The GOAWAY trigger is
   therefore asynchronous relative to `Shutdown` returning. The subsequent
   tunnel-drain polls `activeConns` for 15s, which comfortably covers the async
   GOAWAY dispatch. Confirm no ordering hazard.

6. **Upstream (origin-initiated) GOAWAY.** Out of scope here: when the *origin* sends
   GOAWAY, the pinned upstream `ClientConn`'s in-flight `RoundTrip`s already error and
   map to `exRoundTripError`→502 / `exDeliverError`→RST via `handleH2StreamOutcome`.
   No change needed; noted so reviewers can confirm it is genuinely already handled.

---

## 7. Characterization tests (`inspect_h2_drain_test.go`)

Reuse the existing native-H2 harness (`nativeH2ClientConn`, `connectTLSWithProto`
in `inspect_h2_e2e_test.go`).

1. **GOAWAY delivered + in-flight stream completes cleanly.** Establish an inspected
   H2 tunnel via the shared server; start a slow-but-steady response stream; call
   `gracefulShutdownH2InspectTunnels`; assert the client `http2.ClientConn` observes
   a GOAWAY (frame or `Shutdown`-style behavior) AND the in-flight stream reads to a
   clean EOF (not RST / not truncated), then `ServeConn` returns and `activeConns`
   returns to its pre-tunnel value.
2. **No active tunnels → fast no-op.** `gracefulShutdownH2InspectTunnels` with a nil
   holder (native H2 never used) returns nil immediately.
3. **New streams refused after GOAWAY.** After the trigger, a client attempt to open
   a *new* stream on the same conn fails (GOAWAY semantics), while the pre-existing
   stream still completes.
4. **Shared-server registration.** Assert that two concurrent inspected-H2 tunnels
   both register into the shared `serverInternalState` and both receive GOAWAY from a
   single trigger (evidence the sharing works). If `activeConns` reaches 0 within a
   bounded wait after trigger for both, the drain contract holds.
5. **Determinism / race.** All tests pass under `-race` and `-count=2 -shuffle=on`;
   timeouts generous (≥10× margin) per the determinism-gate lesson from PR3.

---

## 8. Validation gates

`gofmt` · `go vet ./...` · `go build ./...` · diff-scoped `golangci-lint`
(`--new-from-rev=origin/main`) · `go test -race` on the H2 surface ·
`-count=2 -shuffle=on` determinism on the new tests · full-package `go test`.
Keep the required **Fast PR Gate** and **Deep PR Gate** green.

---

## 9. Rollout / rollback

Low risk, opt-in surface: native H2 is off by default (`stripAlpn` absent ⇒ strip/
H1). Rollback = revert the commit; `handleInspectH2` returns to per-tunnel inline
servers with no schema/config/state migration. The shared server is process-local
runtime state only.

---

## 10. Explicit questions for reviewers

- **Q1 (design):** Is the shared-`ConfigureServer` + `base.Shutdown` trigger the
  right mechanism, or is a per-tunnel-registry of graceful triggers preferable? (I
  argue shared is idiomatic and lower-allocation; challenge if the single shared
  `http2.Server` across all tunnels has a downside I've missed.)
- **Q2 (scope):** OPEN DECISION A (§6.1) — graceful-only vs. add a bounded hard-close
  backstop for laggard streams in PR3d?
- **Q3 (ordering):** Is order 95 (after proxy-server-shutdown, before tunnel-drain)
  correct, and is the async `onShutdown` dispatch (§6.5) free of ordering hazards
  given the 15s drain?
- **Q4 (correctness):** Any way the GOAWAY path corrupts the shared upstream
  `ClientConn` teardown or the per-stream watchdog / `h2CopyBody` delivery for
  streams that ARE finishing during the drain?
- **Q5 (security):** Does moving the security caps onto a shared, `ConfigureServer`d
  server change any bound (Rapid-Reset effective cap, CONTINUATION-flood, frame/
  header sizes, IdleTimeout defaulting)?
- **Q6 (PAN-OS parity):** Is graceful GOAWAY-then-bounded-drain the posture a
  commercial decryption appliance ships for HA failover / config-push restarts, and
  is 15s the right drain envelope (reuse existing) or should inspected H2 get its
  own?
