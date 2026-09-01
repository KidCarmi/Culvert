package main

import (
	"context"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/audit"
	"github.com/KidCarmi/Culvert/internal/reqlog"
)

// shutdownBudget is the enforced shutdown envelope, in three parts. CHAOS-56.
//
// Before CHAOS-56 there was ONE number — a 30s "late budget" — and it bounded
// nothing:
//
//   - The early phase ran under context.Background(), documented as "not
//     subject to any shutdown timeout". Its first two hooks are HAState.Stop
//     (a WaitGroup join) and gRPC GracefulStop, which waits for every client
//     transport to close. A half-open DP connection never acks the GOAWAY
//     ping, so GracefulStop waits out the TCP retransmit budget (~15 min at
//     Linux defaults) or gRPC's 2h server keepalive.
//   - The late phase's ctx was advisory: shutdownRegistry ran every hook
//     regardless of whether it had expired, and the hooks that ignore ctx
//     (tunnel drain, syslog/badger/logstore/reqlog/audit/log closers) added
//     their own time on top of it. The tunnel drain's own comment says its
//     15s budget is "independent of the parent ctx" — so the real late worst
//     case was 30s + 15s + the closers, not 30s.
//
// docker-compose.yml sets stop_grace_period: 60s and its comment describes an
// envelope of "up to a 15s tunnel-drain window INSIDE the ~30s late-phase
// budget". No code enforced either half of that sentence. Past the grace the
// container gets SIGKILL, which skips every remaining hook: the cluster-store
// flush, the request-log queue drain, a clean badger close (an unclean one is
// exactly what CHAOS-50's boot-path quarantine had to be built for), and the
// log-sink flush — so the record of WHY shutdown stalled dies with the
// process that stalled.
//
// The three parts are a reserve model, not a subdivision of one timer:
//
//	Early — bounds the stop-accepting hooks (HA, gRPC, CDR, lifecycle cancel).
//	        Their work is best-effort: an interrupted GetConfig is re-fetched
//	        by the DP's own sync loop on reconnect. Sized above the gRPC
//	        server's own drain bound (cpGRPCGracefulStopBudget) so the inner,
//	        more informative force-close fires before the outer watchdog does.
//	Total — the whole envelope. The drain phase gets whatever is left of it
//	        after the early phase and the flush reserve.
//	Flush — carved out UP FRONT for the hooks above shutdownFlushBoundary, so
//	        a stuck drain cannot spend the durability budget.
//
// Worst case is Total + 2×shutdownHookGrace (one grace per late phase; the
// early phase's grace is charged inside Total by the drain phase's absolute
// deadline). At the shipped values that is 51s, inside the 60s compose grace
// with headroom — pinned as a cross-artifact contract by
// TestChaos56_EnvelopeFitsTheContainerStopGrace.
type shutdownBudget struct {
	Total time.Duration
	Early time.Duration
	Flush time.Duration
}

// defaultShutdownBudget is the shipped envelope. Total preserves the
// pre-CHAOS-56 INTENT exactly — 30s late + a 15s tunnel drain = 45s — so no
// drain gets less generous, only bounded. Early is sized for the stop-
// accepting hooks against a healthy peer (gRPC GracefulStop of unary RPCs is
// sub-second) and is short because everything it waits for is retried by the
// peer. Flush is sized for the durable closers, whose own internal bounds are
// already smaller (logsink Close/Sync is capped at 5s).
var defaultShutdownBudget = shutdownBudget{
	Total: 45 * time.Second,
	Early: 12 * time.Second,
	Flush: 10 * time.Second,
}

// runShutdownSequence runs the registered hooks in three bounded phases:
// early (stop accepting), drain (let in-flight work finish), and flush
// (durable closes). The late registry is split at shutdownFlushBoundary by
// partitionAt, so the flush hooks run under a reserve the drain phase cannot
// consume. Every phase's ctx carries a real deadline and shutdownRegistry
// watchdogs each hook against it. CHAOS-56.
//
// A zero Total means "no envelope" and reproduces the pre-CHAOS-56 shape for
// tests that assert on the un-budgeted behaviour; a zero Early or Flush means
// that phase inherits the remaining envelope rather than a reserve.
func runShutdownSequence(early, late *shutdownRegistry, budget shutdownBudget) {
	deadline := time.Time{}
	if budget.Total > 0 {
		deadline = time.Now().Add(budget.Total)
	}

	// Phase 1 — early. Bounded now: this is where an unbounded GracefulStop
	// used to hold the whole sequence open until the container was killed.
	runShutdownPhase(early, "early", phaseDeadline(deadline, budget.Early))

	// Phase 2/3 — the late registry, split so the durable closers get their
	// own reserve.
	drain, flush := late.partitionAt(shutdownFlushBoundary)

	drainEnd := deadline
	if !deadline.IsZero() && budget.Flush > 0 {
		drainEnd = deadline.Add(-budget.Flush)
	}
	runShutdownPhase(drain, "drain", drainEnd)

	// The flush deadline is computed from NOW, not from the envelope: if the
	// drain phase overran its own share (a hook the watchdog had to abandon
	// inside the grace window), the reserve is still the full reserve. That
	// is the whole point of reserving it — durability must not be charged for
	// a drain that misbehaved.
	flushEnd := time.Time{}
	if budget.Flush > 0 {
		flushEnd = time.Now().Add(budget.Flush)
	} else if !deadline.IsZero() {
		flushEnd = deadline
	}
	// Emit the completion line BEFORE the flush phase: the last flush hook
	// closes the log sink, and logsink.Writer.Write after Close enqueues into
	// a channel nobody drains — so a "Stopped." logged after this point is
	// silently swallowed and never reaches the log file the operator reads.
	logger.Println("Shutdown: drained; flushing durable state…")
	runShutdownPhase(flush, "flush", flushEnd)
}

// phaseDeadline returns the earlier of `share` from now and the overall
// envelope deadline. A zero share means the phase runs to the envelope; a
// zero envelope with a zero share means no deadline at all.
func phaseDeadline(envelope time.Time, share time.Duration) time.Time {
	if share <= 0 {
		return envelope
	}
	end := time.Now().Add(share)
	if !envelope.IsZero() && envelope.Before(end) {
		return envelope
	}
	return end
}

// runShutdownPhase runs one registry under `end`, logging any hook failures
// (including watchdog abandonment) with the phase name. A zero `end` runs the
// phase without a deadline.
func runShutdownPhase(reg *shutdownRegistry, name string, end time.Time) {
	ctx := context.Background()
	if !end.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, end)
		defer cancel()
	}
	if err := reg.RunAll(ctx); err != nil {
		logger.Printf("Shutdown (%s phase) error(s): %v", name, err)
	}
}

// shutdown hook order constants. Gaps of 10 leave room for future inserts
// without renumbering. Hooks at or below shutdownEarlyLateBoundary belong
// in registerEarlyShutdownHooks (no shutdown budget); hooks above it belong
// in registerLateShutdownHooks (under the 30s budget). P2.2 / S5.
const (
	shutdownOrderHAStop                 = 10
	shutdownOrderControlPlaneGRPCStop   = 20
	shutdownOrderCDRClientShutdown      = 30
	shutdownOrderAppLifecycleCancel     = 40
	shutdownOrderRateLimitCleanupCancel = 50

	// shutdownEarlyLateBoundary is the cut-line: orders <= this run in
	// the early phase (bg ctx, no budget); orders > this run in the late
	// phase (30s ctx). Encoded as a constant so the test suite can pin
	// the split structurally.
	shutdownEarlyLateBoundary = 50

	// shutdownOrderClusterStoreFlush runs first in the late phase. CL-2:
	// closes the heartbeat-throttle window. UpdateNodeSeen only persists
	// every 10th heartbeat (enrollment.go) and checkHeartbeats persists
	// only when liveness/GC change something. Anything mutated in-memory
	// since the last Save() is otherwise lost on shutdown. By this point
	// in the sequence the gRPC server has stopped (no new heartbeats) and
	// appLifecycleCancel has stopped the heartbeat monitor, so the Save
	// races with nothing.
	shutdownOrderClusterStoreFlush = 55
	shutdownOrderScanSvcShutdown   = 60
	// PR-5: stop the MCP listeners (drain-bounded) before the admin UI + proxy
	// drain. A disabled runtime makes this a no-op.
	shutdownOrderMCPRuntimeStop = 65
	// QUAL-3: drain + close the MCP telemetry spool/exporter AFTER the listeners stop
	// (so no new events are produced), before the admin UI. A no-op while disabled.
	shutdownOrderMCPTelemetryDrain = 66
	// ADR-0025 M1: flush the policy-learning session store (lazy-expiry flips)
	// before the admin plane quiesces. A nil singleton (disabled — the M1
	// production posture) makes this a no-op.
	shutdownOrderPolicyLearnFlush    = 67
	shutdownOrderAdminUIShutdown     = 70
	shutdownOrderSOCKS5ListenerStop  = 80
	shutdownOrderProxyServerShutdown = 90
	// PR3d: after the CONNECT listener is closed (no new inspected-H2 tunnels can
	// begin) and before the tunnel drain waits, fence new tunnels and send the first
	// GOAWAY wave to every active inspected-H2 tunnel.
	shutdownOrderH2InspectGOAWAY = 95
	shutdownOrderTunnelDrain     = 100

	// shutdownFlushBoundary is the second cut-line, inside the late phase.
	// Hooks at or below it are DRAIN hooks — stop accepting, let in-flight
	// work finish; abandoning one costs a retry. Hooks above it are FLUSH
	// hooks — they persist state and release handles, and abandoning one
	// costs durability or leaves a store the next boot has to quarantine.
	// runShutdownSequence splits the late registry here so the flush hooks
	// run under a reserve no drain can spend. CHAOS-56.
	shutdownFlushBoundary = 105

	shutdownOrderSyslogClose      = 110
	shutdownOrderCommunityDBClose = 120
	shutdownOrderLogStoreClose    = 125
	shutdownOrderRequestLogClose  = 130
	shutdownOrderAuditLogClose    = 135
	shutdownOrderLogCloser        = 140
)

// registerEarlyShutdownHooks registers the pre-budget shutdown hooks: HA,
// control-plane gRPC, CDR client, app lifecycle cancel, rate-limit cleanup
// cancel. These ran BEFORE the 30s ctx in the pre-P2.2 hand-ordered body
// and continue to run with context.Background() — they are not subject to
// any shutdown timeout. None of them observe ctx; they ignore the parameter.
// P2.2 / S5.
func registerEarlyShutdownHooks(reg *shutdownRegistry, s *startupState) {
	// Stop HA leader election and release lock before gRPC shutdown.
	reg.Register("ha-stop", shutdownOrderHAStop, func(context.Context) error {
		globalHA.Stop()
		return nil
	})
	// Gracefully stop gRPC server (drains in-flight RPCs).
	reg.Register("control-plane-grpc-stop", shutdownOrderControlPlaneGRPCStop, func(context.Context) error {
		StopControlPlaneGRPC()
		return nil
	})
	// Close the CDR client before cancelling lifecycle context so any
	// in-flight Sanitize streams get a clean tear-down rather than a
	// context-cancelled transport error.
	reg.Register("cdr-client-shutdown", shutdownOrderCDRClientShutdown, func(context.Context) error {
		shutdownCDRClient()
		return nil
	})
	// Cancel all background goroutines (feed syncers, CA rotation, health checks, etc.).
	reg.Register("app-lifecycle-cancel", shutdownOrderAppLifecycleCancel, func(context.Context) error {
		appLifecycleCancel()
		return nil
	})
	reg.Register("rate-limit-cleanup-cancel", shutdownOrderRateLimitCleanupCancel, func(context.Context) error {
		if s.rlCleanupCancel != nil {
			s.rlCleanupCancel()
		}
		return nil
	})
}

// tunnelDrainWindow caps how long the tunnel drain waits for hijacked
// CONNECT/WebSocket conns to finish. It is a CEILING, not a budget: CHAOS-56
// made the drain honour the phase deadline too, so the effective window is
// min(tunnelDrainWindow, time left in the drain phase).
// Var (not const) so a test can shorten it, matching tunnelIdleTimeout's
// convention; production never mutates it.
var tunnelDrainWindow = 15 * time.Second

// drainActiveTunnels drains in-flight CONNECT/WebSocket tunnels after the
// proxy server's HTTP listener has shut down. proxySrv.Shutdown only closes
// HTTP/1.x idle connections; hijacked tunnels need time to finish. Extracted
// as a named function (rather than an inline closure inside
// registerLateShutdownHooks) to keep the wiring function's cognitive
// complexity low. P2.2 / S5.
//
// CHAOS-56 — the 15s window used to be "independent of the parent ctx", so it
// was ADDED to the late-phase budget rather than spent inside it, and the
// compose file's stop_grace_period comment (which describes the drain as
// living "inside the ~30s late-phase budget") was describing an envelope
// nothing enforced. The window is now clamped to whatever the drain phase has
// left, and the force-close backstop fires on EITHER bound — so a laggard
// inspected-H2 tunnel still gets a deterministic teardown instead of being
// left to the container's SIGKILL.
func drainActiveTunnels(ctx context.Context) error {
	active := atomic.LoadInt64(&activeConns)
	if active <= 0 {
		return nil
	}
	// activeConns is a SUPERSET of inspected-H2 tunnels (it also counts H1-inspect and
	// raw-bypass tunnels), so "drained" here does not imply every waited-on conn was
	// GOAWAY'd — only the inspected-H2 subset is (PR3d).
	logger.Printf("Draining %d active tunnel(s) (%d inspected H2)…", active, atomic.LoadInt64(&statH2InspectActive))
	drainTimer := time.NewTimer(tunnelDrainWindow)
	defer drainTimer.Stop()
	drainDeadline := drainTimer.C
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// The drain phase's budget is gone. Fall through to the SAME
			// force-close backstop rather than returning quietly: a tunnel
			// abandoned here would otherwise survive until process exit, and
			// the flush hooks are waiting behind this one.
			//
			// CHAOS-57: no settle here. The settle exists to let severed relays
			// hand their TUNNEL_CLOSED entries to the request-log queue before the
			// flush hooks run, and it is clamped to the phase budget — which, on
			// this branch, is already spent. Lingering anyway would borrow time
			// from the hooks behind us; losing the accounting for those tunnels is
			// exactly the pre-change behaviour, never worse.
			forcedH2 := forceCloseH2InspectTunnels()
			forcedRaw, breakdown := forceCloseDrainableTunnels()
			logger.Printf("Drain budget exhausted: %d tunnel(s) still active (force-closed %d inspected H2, %d hijacked [%s])",
				atomic.LoadInt64(&activeConns), forcedH2, forcedRaw, breakdown)
			return nil
		case <-drainDeadline:
			// PR3d backstop: force-close inspected-H2 tunnels whose in-flight streams
			// did not finish within the window (infinite SSE/gRPC/large-download
			// streams keep the conn — and activeConns — open under a graceful GOAWAY),
			// so laggards get a deterministic teardown instead of relying on process
			// exit / the container SIGKILL grace.
			//
			// CHAOS-57 extends the same backstop to every OTHER hijacked-tunnel class
			// (CONNECT bypass/inspect, both non-TLS fallbacks, WebSocket, SOCKS5).
			// Those classes are long-lived BY DESIGN, so making the drain wait on them
			// without a way to end the wait would have bought the operator a guaranteed
			// 15 s shutdown and severed them anyway. Closing them here unblocks each
			// relay's io.Copy, so its parent runs recordTunnelClose* and the byte
			// accounting reaches the request-log queue while the flush hooks are still
			// ahead of us — which is what the bounded settle below guarantees rather
			// than leaves to luck.
			forcedH2 := forceCloseH2InspectTunnels()
			forcedRaw, breakdown := forceCloseDrainableTunnels()
			remaining := settleAfterForceClose(ctx)
			logger.Printf("Drain timeout: %d tunnel(s) still active (force-closed %d inspected H2, %d hijacked [%s])",
				remaining, forcedH2, forcedRaw, breakdown)
			return nil
		case <-ticker.C:
			// PR3d: re-fire the GOAWAY so any inspected-H2 tunnel that registered after
			// the initial order-95 trigger (a late-accepted CONNECT still handshaking)
			// is also signaled. startGracefulShutdown is shutdownOnce-guarded, so
			// already-GOAWAY'd conns are unaffected; no-op when native H2 was unused.
			_ = refireH2InspectGoaway()
			if atomic.LoadInt64(&activeConns) <= 0 {
				logger.Println("All tunnels drained")
				return nil
			}
		}
	}
}

// registerLateShutdownHooks registers the budget-bound shutdown hooks: scan
// service, Admin UI, SOCKS5 listener, proxy server, tunnel drain, syslog
// close, community DB close, request log close, log closer. These run under
// the 30s ctx that runShutdownSequence creates after the early phase
// completes; the ctx is observed by hooks that take it (scanSvc, adminUI,
// socks5, proxySrv) and ignored by io.Closer-style hooks.
//
// Per-hook log messages and best-effort error suppression are byte-
// equivalent to the previous hand-ordered body. Hooks return nil today;
// registry-level error aggregation is reserved for a future PR. P2.2 / S5.
func registerLateShutdownHooks(reg *shutdownRegistry, s *startupState, proxySrv *http.Server) {
	// CL-2: flush in-memory cluster state to disk once at shutdown so the
	// heartbeat-throttle gap (UpdateNodeSeen saves every 10th tick) cannot
	// drop LastSeen/Status mutations on a graceful stop. Save() is RLock +
	// atomicWriteFile; no path → no-op.
	reg.Register("cluster-store-flush", shutdownOrderClusterStoreFlush, func(context.Context) error {
		if globalClusterStore == nil {
			return nil
		}
		if err := globalClusterStore.Save(); err != nil {
			logger.Printf("Cluster store flush error: %v", err)
		}
		return nil
	})
	// Shut down scan microservice sidecar if running. Best-effort: error suppressed.
	reg.Register("scan-svc-shutdown", shutdownOrderScanSvcShutdown, func(ctx context.Context) error {
		if s.scanSvc != nil {
			_ = s.scanSvc.Shutdown(ctx)
		}
		return nil
	})
	// PR-5: stop the dedicated MCP listeners (Gateway + Management) before draining
	// the admin UI and proxy. No-op while the runtime is disabled (the default).
	reg.Register("mcp-runtime-stop", shutdownOrderMCPRuntimeStop, func(ctx context.Context) error {
		if err := shutdownMCPRuntime(ctx); err != nil {
			logger.Printf("MCP runtime shutdown error: %v", err)
		}
		return nil
	})
	reg.Register("mcp-telemetry-drain", shutdownOrderMCPTelemetryDrain, func(ctx context.Context) error {
		if err := shutdownMCPTelemetry(ctx); err != nil {
			logger.Printf("MCP telemetry shutdown error: %v", err)
		}
		return nil
	})
	// ADR-0025 M1: persist any lazily-flipped learning-session state. No-op on
	// the nil singleton (learning disabled — the M1 production posture).
	reg.Register("policy-learning-flush", shutdownOrderPolicyLearnFlush, func(context.Context) error {
		if eng := policyLearnEngine.Load(); eng != nil {
			if err := eng.Close(); err != nil {
				logger.Printf("Policy learning store flush error: %v", err)
			}
		}
		return nil
	})
	// P1.1 / S4.AdminUI: stop accepting new admin UI requests before draining
	// the proxy. shutdownAdminUI builds a 5s sub-context internally so an
	// active SSE stream cannot consume the entire shutdown budget.
	reg.Register("admin-ui-shutdown", shutdownOrderAdminUIShutdown, func(ctx context.Context) error {
		if err := shutdownAdminUI(ctx, s.adminUISrv); err != nil {
			logger.Printf("Admin UI shutdown error: %v", err)
		}
		return nil
	})
	// P1.5 / S4.SOCKS5: close the SOCKS5 listener. Bounded to 2s via a
	// sub-context. Does NOT drain in-flight SOCKS5 tunnels — they keep
	// their per-conn 30s deadlines (set in handleSOCKS5).
	reg.Register("socks5-listener-stop", shutdownOrderSOCKS5ListenerStop, func(ctx context.Context) error {
		if s.socks5Srv == nil {
			return nil
		}
		socksCtx, socksCancel := context.WithTimeout(ctx, 2*time.Second)
		defer socksCancel()
		if err := s.socks5Srv.Stop(socksCtx); err != nil {
			logger.Printf("SOCKS5 shutdown error: %v", err)
		}
		return nil
	})
	reg.Register("proxy-server-shutdown", shutdownOrderProxyServerShutdown, func(ctx context.Context) error {
		if err := proxySrv.Shutdown(ctx); err != nil {
			logger.Printf("Shutdown error: %v", err)
		}
		return nil
	})
	// PR3d: send the first GOAWAY wave to active inspected-H2 tunnels (and fence new
	// ones) before the drain waits on them. No-op when native H2 was never used.
	reg.Register("h2-inspect-goaway", shutdownOrderH2InspectGOAWAY, beginH2InspectDrain)
	// Drain active tunnels (CONNECT/WebSocket). proxySrv.Shutdown only
	// closes HTTP/1.x idle connections; hijacked tunnels need time to
	// finish. 15s drain budget is independent of the parent ctx, matching
	// the original behaviour exactly.
	reg.Register("tunnel-drain", shutdownOrderTunnelDrain, drainActiveTunnels)
	reg.Register("syslog-close", shutdownOrderSyslogClose, func(context.Context) error {
		if globalSyslog != nil {
			_ = globalSyslog.Close() // best-effort flush
		}
		return nil
	})
	reg.Register("community-db-close", shutdownOrderCommunityDBClose, func(context.Context) error {
		if communityDB != nil {
			if err := communityDB.Close(); err != nil {
				logger.Printf("CatFeedDB: close error: %v", err)
			}
		}
		return nil
	})
	reg.Register("log-store-close", shutdownOrderLogStoreClose, func(context.Context) error {
		if ls := globalLogStore.Load(); ls != nil {
			if err := ls.Close(); err != nil {
				logger.Printf("LogStore: close error: %v", err)
			}
		}
		return nil
	})
	reg.Register("request-log-close", shutdownOrderRequestLogClose, func(context.Context) error {
		_ = reqlog.Close() // best-effort flush; nil-safe
		return nil
	})
	// P3.3 / S7. Release the audit-log file descriptor. Writes are
	// synchronous, unbuffered, kernel-side already on disk — this closes
	// the OS handle to eliminate the FD leak flagged as Risk #6 in
	// ARCH_DISCOVERY. Best-effort, byte-equivalent to request-log-close.
	reg.Register("audit-log-close", shutdownOrderAuditLogClose, func(context.Context) error {
		_ = audit.Close() // best-effort FD release
		return nil
	})
	reg.Register("log-closer", shutdownOrderLogCloser, func(context.Context) error {
		if s.logCloser != nil {
			_ = s.logCloser.Close()
		}
		return nil
	})
}
