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

---

## 11. Review consolidation (v2) — APPROVED WITH AMENDMENTS

Three independent reviewers — PAN-OS decryption/HA architect, HTTP/2 protocol
correctness, Go runtime/shutdown — all returned **APPROVE-WITH-AMENDMENTS**. The
core mechanism (shared `ConfigureServer`'d h2 server + `base.Shutdown` trigger +
existing counter drain) was **verified correct against the actually-vendored
`x/net@v0.57.0`** (registration gap real; `startGracefulShutdown` is the graceful
`ErrCodeNo` variant that lets in-flight streams finish and refuses new ones; sharing
one `*http2.Server` across conns is intended and race-free — per-conn config is a
returned value, only the mutex-guarded `activeConns` map is shared; caps preserved,
`IdleTimeout` only defaulted-when-zero; upstream `ClientConn` teardown independent).
The following amendments are **binding on implementation**.

### 11.1 OPEN DECISION A — SETTLED: ship the bounded hard-close backstop.
Both the PAN-OS (F1) and HTTP/2 (#2) reviewers independently require it. Rationale:
`base.Shutdown` here closes **nothing** (the base owns no conns); the per-conn
graceful path has no forced timeout, so an infinite in-flight stream (SSE, gRPC
server-streaming, multi-GB download) holds its conn — and thus `activeConns` —
open until process exit, which is **non-deterministic and defeated by the container
SIGKILL grace**. Graceful-only would help only short-request H2 (which already
drains). **Design:** GOAWAY first; at the 15s drain deadline, force-close the still-
open inspected-H2 client conns. Keep the **single 15s envelope** (no H2-specific
longer window — an unbounded H2 drain lets one stream pin a departing node). The
backstop is what makes 15s a real ceiling, not a lower bound.
- Mechanism: a `sync.Map` (or mutex+map) registry of live `*tls.Conn` client legs,
  populated on `handleInspectH2` entry, removed on exit; `forceCloseH2InspectTunnels`
  iterates and `Close()`s them at the deadline. **Close the `*tls.Conn` directly —
  `ServeConnOpts.Context` cancellation is NOT a reliable hard close** (PAN-OS F1).

### 11.2 Admission fence + late-registrant capture (PAN-OS F2, Go-runtime MAJOR#2, HTTP/2 #7).
Two windows leave a counted tunnel un-GOAWAY'd: (a) the publication/registration
race — `recordActiveConn(1)` (proxy_tunnel_h2.go:180) precedes holder build /
`ServeConn`'s `registerConn`, so a one-shot trigger's `activeConns` snapshot misses
it; (b) a CONNECT accepted before listener-close that `ServeConn`s after the trigger.
**Closed by three cheap changes:**
1. **Eager-init** the shared server once at startup (kills the nil-holder race; cost
   is two structs + one `ConfigureServer`, negligible, unconditional). This also
   **removes the `sync.Once`/`atomic.Pointer` dance** — a plain package var set
   during single-threaded startup wiring (happens-before serving) suffices.
2. **Admission fence:** a package `h2InspectShuttingDown atomic.Bool`, set by the
   trigger; `handleInspectH2` checks it at entry and, if set, refuses the new tunnel
   (immediate GOAWAY/close) rather than admitting a new decrypted flow onto a
   departing node.
3. **Re-fire on each drain tick:** `net/http.Server.Shutdown` re-dispatches **all**
   `onShutdown` funcs on **every** call, and `sc.startGracefulShutdown` is
   `shutdownOnce`-guarded (re-fire is a no-op for already-GOAWAY'd conns). So calling
   `base.Shutdown` on each `drainActiveTunnels` 500ms tick re-snapshots `activeConns`
   and GOAWAYs any late registrant. Converts §6.2's "narrow residual" into "actually
   drained."

### 11.3 `stop_grace_period` reconciliation (PAN-OS F3) — REQUIRED or the feature is cosmetic.
Confirmed: `docker-compose.yml` sets **no** `stop_grace_period`, so Docker's default
**10s** SIGKILLs the proxy mid-drain (the 15s tunnel-drain sits after hooks 55–90
inside the 30s late phase). In the primary production path — maintenance-agent
`docker compose` upgrade/restart — clients would get RST and the GOAWAY becomes
cosmetic. **Amendment:** set `stop_grace_period` on the `proxy` (and `cli` if it
serves) service to cover the **full** shutdown envelope (early phase + 30s late +
15s drain) — target **60s** — and document the coupling (the drain envelope must be
≤ the orchestrator grace). Verify the maintenance-agent restart path honors it.

### 11.4 HA scope statement (PAN-OS F4) — REQUIRED.
PR3d drains on **process shutdown only** (SIGTERM / compose-restart / maintenance-
agent upgrade). The **live** ADR-0005 transitions — `selfFence` / `enterStandbyResync`
on lease loss (ha_lease.go/ha_failover.go) and hot `applyConfigSnapshot` — are
in-process role/config changes that **never run these shutdown hooks**, so inspected
H2 flows are **not** drained on a live HA failover or hot config push. State this as
**by design**: the fencing lease governs CP write-authority, not DP proxying, so
in-flight decrypted flows on a demoting node are unaffected by lease loss and need no
drain there. Live-failover drain is explicitly out of scope, not an omission.

### 11.5 Observability (PAN-OS F5) — REQUIRED for operability.
`activeConns` conflates H1-inspect, H2-inspect, and raw-bypass tunnels, so the drain
log can't tell an operator whether H2 GOAWAY'd cleanly. Add to the `culvert_*`
namespace: a `culvert_h2_inspect_active` gauge (±1 in `handleInspectH2`),
`culvert_h2_inspect_drain_goaway_total`, and `culvert_h2_inspect_drain_forced_total`
(backstop closes); disambiguate the drain log line to report the H2-inspect subset
distinctly. (Metrics are `/metrics`-surfaced — no GUI-parity obligation.) Also
**state the invariant** that the drain waits on the `activeConns` superset while
GOAWAY touches only the h2 subset — "order-100 drains" does NOT mean "all were
GOAWAY'd" (Go-runtime note).

### 11.6 Test-plan corrections (HTTP/2 #1/#4/#5, Go-runtime MAJOR#1 + MINOR).
- **Test 1:** drop the un-assertable "client observes GOAWAY" via the x/net client
  API; assert the two real observables — the in-flight stream reads a **clean EOF**
  and a **new** stream on the same conn is **refused** — or drive the client with a
  raw `http2.Framer` and read the single GOAWAY frame.
- **Exactly one GOAWAY:** x/net's server emits a single `writeGoAway{maxStreamID,
  ErrCodeNo}` — no advisory-then-real double-GOAWAY. Tests assert one.
- **Budget waits > 1s:** after the last stream, `shutDownIn(goAwayTimeout=1s)` delays
  `ServeConn` return, so `activeConns→0` lags by ~1s/conn. Drain-completion asserts
  must budget > 1s (and stay ≥10× margin for the determinism gate).
- **Nil-case off the global:** extract a testable inner
  `gracefulShutdownH2InspectShared(sh *h2InspectShared, ctx)`; the nil test passes an
  explicit `nil`; real-server tests build a **local** `h2InspectShared`, never
  driving process-global state (avoids `-shuffle=on`/`-count=2` ordering flakes).
- **Barrier-based sequencing:** handlers signal "entered / headers written" over a
  channel and block on a release channel; the test waits on the signal, fires the
  trigger, then releases — no `time.Sleep` (which would flake AND non-deterministically
  exercise the §6.2 race).

### 11.7 Polish (all three).
- Re-cite **v0.57.0** with correct line refs (`configureServer :159`,
  `RegisterOnShutdown :173`, `registerConn :299`, `startGracefulShutdown :1315`,
  `startGracefulShutdownInternal :1338`, `goAwayTimeout :1336`).
- Fix the `ConfigureServer` degrade-path comment: `state` + `RegisterOnShutdown` are
  wired **before** its only error return (the TLS-1.2 cipher check), and our base has
  no `CipherSuites`, so the error is unreachable — don't claim "graceful disabled."
  With eager-init at startup, a `ConfigureServer` error is logged once at WARN.
- The 2s `context.WithTimeout` on `base.Shutdown` bounds nothing (Shutdown returns in
  µs; the drain does the waiting) — keep it but describe it honestly.

### 11.8 Net design delta from v1
Eager-init one shared `ConfigureServer`'d server at startup (plain package vars, no
Once/atomic); `handleInspectH2` gains an admission-fence check + live-conn registry
insert + an active gauge; a new order-95 hook sets the shutting-down flag and fires
the first GOAWAY; `drainActiveTunnels` re-fires the GOAWAY each tick and force-closes
the registered H2 conns at the 15s deadline (single envelope); `docker-compose.yml`
gains `stop_grace_period: 60s`; three `culvert_*` metrics; operator doc gains the
drain sequence + the HA-scope statement. Everything else in v1 stands.
