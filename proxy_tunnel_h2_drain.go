package main

// PR3d — graceful GOAWAY-on-shutdown drain for inspected HTTP/2 tunnels.
//
// The gap this closes: native-H2 inspection served each tunnel with a fresh,
// inline `&http2.Server{}` that never called http2.ConfigureServer, so its internal
// graceful-shutdown state was nil and the tunnel's serverConn was invisible to any
// GOAWAY trigger. On shutdown the client got a bare FIN/RST at process exit, not a
// graceful GOAWAY.
//
// Mechanism (verified against golang.org/x/net@v0.57.0/http2/server.go):
// http2.ConfigureServer(base, srv) initializes srv.state and registers
// base.RegisterOnShutdown(state.startGracefulShutdown) (:173). Every conn ServeConn
// serves then registers into state.activeConns (:299). net/http's Server.Shutdown
// re-dispatches every RegisterOnShutdown func on EVERY call, and
// serverConn.startGracefulShutdown sends a single GOAWAY(ErrCodeNo) (:1315) that
// lets in-flight streams finish and refuses new ones. So: one shared,
// ConfigureServer'd server for all inspected-H2 tunnels + base.Shutdown() at
// process shutdown = a GOAWAY to every active tunnel. Sharing one *http2.Server
// across conns is the library's intended usage (Serve drives one Server through
// many ServeConn calls); per-conn config is derived per call, only the
// mutex-guarded activeConns map is shared.
//
// Because base.Shutdown here closes nothing (the base owns no listeners/conns) and
// the per-conn graceful path has no forced timeout, a never-ending in-flight stream
// (SSE, gRPC server-streaming, multi-GB download) would hold its conn — and thus
// activeConns — open until process exit. So the drain adds a bounded HARD-CLOSE
// BACKSTOP: at the 15s drain deadline the still-open client legs are force-closed,
// giving laggards a deterministic teardown instead of relying on the container
// SIGKILL grace. Single 15s envelope, reused from drainActiveTunnels.

import (
	"context"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

// h2InspectShared holds the ONE http2.Server + base http.Server used by every
// inspected native-H2 tunnel. Built once at startup (initH2InspectServer) so it is
// never nil when a tunnel or the shutdown hook needs it.
type h2InspectShared struct {
	srv  *http2.Server
	base *http.Server
}

var (
	// h2InspectSrv is set once by initH2InspectServer during single-threaded startup
	// wiring (happens-before the proxy accepts any connection) and is read-only
	// thereafter — no Once/atomic needed.
	h2InspectSrv *h2InspectShared

	// h2InspectShuttingDown fences NEW inspected-H2 tunnels once the drain begins: we
	// don't start inspecting a new decrypted flow on a departing node.
	h2InspectShuttingDown atomic.Bool

	// h2InspectConns is the live client-leg registry for the hard-close backstop:
	// *tls.Conn -> struct{}. Populated on handleInspectH2 entry, removed on exit.
	h2InspectConns sync.Map

	// Observability (culvert_h2_inspect_* in metrics.go). activeConns (geoip.go) is a
	// SUPERSET of these — it also counts H1-inspect and raw-bypass tunnels — so the
	// drain waiting on activeConns does NOT imply everything it waits on was GOAWAY'd.
	statH2InspectActive int64 // gauge: currently-active inspected H2 tunnels
	statH2InspectGoaway int64 // counter: tunnels active at drain START (one-shot snapshot; excludes late registrants)
	statH2InspectForced int64 // counter: tunnels force-closed by the deadline backstop

	// h2InspectFallbackWarnOnce bounds the "shared server not initialized" warning to
	// one line even if many tunnels hit the (production-unreachable) fallback.
	h2InspectFallbackWarnOnce sync.Once
)

// warnH2InspectFallbackOnce logs (at most once) that handleInspectH2 built a per-conn
// server because the eager-init global was nil — a signal that init ordering
// regressed and graceful GOAWAY is unavailable for such tunnels. In tests (which
// never call initH2InspectServer) this fires once and is harmless.
func warnH2InspectFallbackOnce() {
	h2InspectFallbackWarnOnce.Do(func() {
		logger.Printf("SSL_INSPECT(h2) shared server not initialized — per-conn fallback in use; graceful GOAWAY-on-shutdown unavailable for these tunnels")
	})
}

// newH2InspectServer builds and ConfigureServer-wires a shared server. Split from
// initH2InspectServer so tests can build a LOCAL instance without driving the global.
func newH2InspectServer() *h2InspectShared {
	srv := &http2.Server{
		MaxConcurrentStreams: h2MaxConcurrentStreams,
		IdleTimeout:          tunnelIdleTimeout,
		WriteByteTimeout:     h2ConnWriteByteTimeout,
		MaxReadFrameSize:     h2MaxReadFrameSize,
	}
	base := &http.Server{MaxHeaderBytes: h2MaxHeaderBytes, ReadHeaderTimeout: h2ConnWriteByteTimeout}
	// ConfigureServer sets srv.state and wires base.RegisterOnShutdown ->
	// state.startGracefulShutdown BEFORE its only error return (a TLS-1.2 cipher
	// check that our CipherSuites-free base never trips), so graceful shutdown is
	// wired regardless; we log the (unreachable-for-us) error for completeness. It
	// preserves our non-zero caps and only defaults IdleTimeout when zero (ours is
	// tunnelIdleTimeout).
	if err := http2.ConfigureServer(base, srv); err != nil {
		logger.Printf("SSL_INSPECT(h2) ConfigureServer: %v", err)
	}
	return &h2InspectShared{srv: srv, base: base}
}

// initH2InspectServer eagerly builds the shared server at startup. Called once from
// the composition root; the cost (two structs + one ConfigureServer) is negligible
// even when native H2 is never used.
func initH2InspectServer() {
	if h2InspectSrv == nil {
		h2InspectSrv = newH2InspectServer()
	}
}

// registerH2InspectConn tracks a live client leg for the backstop and bumps the
// active gauge. unregisterH2InspectConn reverses both on tunnel exit. Typed net.Conn
// (the production client leg is a *tls.Conn, which satisfies it) so the registry and
// its force-close backstop are exercisable with any conn in tests.
func registerH2InspectConn(c net.Conn) {
	h2InspectConns.Store(c, struct{}{})
	atomic.AddInt64(&statH2InspectActive, 1)
}

func unregisterH2InspectConn(c net.Conn) {
	h2InspectConns.Delete(c)
	atomic.AddInt64(&statH2InspectActive, -1)
}

// beginH2InspectDrain is the order-95 shutdown hook: fence new tunnels, snapshot how
// many are draining (for the goaway metric), and fire the first GOAWAY wave. The
// order-100 tunnel drain then re-fires per tick and force-closes laggards.
//
// No-op when the shared server was never built (h2InspectSrv == nil): there are then
// no shared-server tunnels to drain, so there is no reason to raise the process-global
// fence. This is always true in production (initH2InspectServer eager-builds it at
// startup) and is what keeps shutdown-sequence tests that RunAll the late hooks
// without initializing native H2 from leaving the fence stuck true and poisoning
// later native-H2 tests.
func beginH2InspectDrain(ctx context.Context) error {
	if h2InspectSrv == nil {
		return nil
	}
	h2InspectShuttingDown.Store(true)
	atomic.AddInt64(&statH2InspectGoaway, atomic.LoadInt64(&statH2InspectActive))
	return gracefulShutdownH2InspectShared(h2InspectSrv, ctx)
}

// refireH2InspectGoaway re-sends GOAWAY to any tunnel that registered after the
// initial trigger (a late-accepted CONNECT still handshaking at order 95). Called on
// each drain tick. startGracefulShutdown is shutdownOnce-guarded, so already-GOAWAY'd
// conns are unaffected; no-op when native H2 was never used.
func refireH2InspectGoaway() error {
	return gracefulShutdownH2InspectShared(h2InspectSrv, context.Background())
}

// gracefulShutdownH2InspectShared fires GOAWAY on every active tunnel of sh by
// calling base.Shutdown, which re-dispatches the RegisterOnShutdown trigger on every
// call. The 2s bound guards against a surprise block; in practice Shutdown returns in
// microseconds (the base owns no listeners/conns — the real waiting is
// drainActiveTunnels). No-op on nil sh. Split out as the testable inner helper so the
// nil-case is exercised without driving process-global state.
func gracefulShutdownH2InspectShared(sh *h2InspectShared, ctx context.Context) error {
	if sh == nil {
		return nil
	}
	goawayCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_ = sh.base.Shutdown(goawayCtx) //nolint:errcheck // fires GOAWAY; drainActiveTunnels does the waiting
	return nil
}

// forceCloseH2InspectTunnels is the drain-deadline backstop: it hard-closes every
// still-registered client leg so an infinite in-flight stream cannot pin a departing
// node past the drain window. Closing the *tls.Conn (not cancelling a context)
// unblocks ServeConn deterministically. Returns the count force-closed.
func forceCloseH2InspectTunnels() int {
	n := 0
	h2InspectConns.Range(func(k, _ any) bool {
		if c, ok := k.(net.Conn); ok {
			_ = c.Close() //nolint:errcheck // backstop: force-unblock laggard ServeConn on deadline
			n++
		}
		return true
	})
	if n > 0 {
		atomic.AddInt64(&statH2InspectForced, int64(n))
	}
	return n
}
