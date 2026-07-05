package main

import (
	"context"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/audit"
	"github.com/KidCarmi/Culvert/internal/reqlog"
)

// runShutdownSequence runs the early registry with context.Background()
// (no shutdown budget), then creates a fresh ctx with the supplied late
// budget and runs the late registry. The late ctx's cancel is deferred so
// it runs at function exit, mirroring the original
// `defer cancel()` placement in runProxyUntilShutdown.
//
// Extracted so the budget-vs-no-budget contract — the entire reason this
// PR splits into two registries — is unit-testable end to end without
// touching production globals. P2.2 / S5.
func runShutdownSequence(early, late *shutdownRegistry, lateBudget time.Duration) {
	if err := early.RunAll(context.Background()); err != nil {
		logger.Printf("Early shutdown error(s): %v", err)
	}

	// 30s shutdown budget begins HERE — same point as the original
	// `ctx, cancel := context.WithTimeout(...)` in the pre-P2.2 body,
	// after the rate-limit cleanup cancel and before scanSvc.Shutdown.
	ctx, cancel := context.WithTimeout(context.Background(), lateBudget)
	defer cancel()

	if err := late.RunAll(ctx); err != nil {
		// All late hooks currently log per-hook on failure and return nil,
		// so this branch is unreachable today. Kept as a backstop for
		// future hooks that opt into registry-level error aggregation.
		logger.Printf("Shutdown error(s): %v", err)
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
	shutdownOrderClusterStoreFlush   = 55
	shutdownOrderScanSvcShutdown     = 60
	shutdownOrderAdminUIShutdown     = 70
	shutdownOrderSOCKS5ListenerStop  = 80
	shutdownOrderProxyServerShutdown = 90
	shutdownOrderTunnelDrain         = 100
	shutdownOrderSyslogClose         = 110
	shutdownOrderCommunityDBClose    = 120
	shutdownOrderLogStoreClose       = 125
	shutdownOrderRequestLogClose     = 130
	shutdownOrderAuditLogClose       = 135
	shutdownOrderLogCloser           = 140
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

// drainActiveTunnels drains in-flight CONNECT/WebSocket tunnels after the
// proxy server's HTTP listener has shut down. proxySrv.Shutdown only closes
// HTTP/1.x idle connections; hijacked tunnels need time to finish. The 15s
// drain budget is independent of the parent ctx — extracted as a named
// function (rather than an inline closure inside registerLateShutdownHooks)
// to keep the wiring function's cognitive complexity low. P2.2 / S5.
func drainActiveTunnels(context.Context) error {
	active := atomic.LoadInt64(&activeConns)
	if active <= 0 {
		return nil
	}
	logger.Printf("Draining %d active tunnel(s)…", active)
	drainDeadline := time.After(15 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-drainDeadline:
			logger.Printf("Drain timeout: %d tunnel(s) still active", atomic.LoadInt64(&activeConns))
			return nil
		case <-ticker.C:
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
