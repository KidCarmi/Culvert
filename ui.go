package main

import (
	"context"
	"crypto/tls"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

// adminUIShutdownTimeout caps the admin UI graceful shutdown window so an
// active SSE stream (admin dashboard open during restart) cannot consume the
// entire parent shutdown budget before proxy drain. WriteTimeout=0 on the
// admin UI server (set in newAdminUIServer for SSE) means in-flight handlers
// would otherwise block Shutdown until the parent ctx expires. P1.1 / S4.AdminUI.
const adminUIShutdownTimeout = 5 * time.Second

// shutdownAdminUI gracefully shuts down the admin UI server, capped at
// adminUIShutdownTimeout via a sub-context derived from ctx. Returns nil if
// srv is nil (early-fail path that never assigned the handle). The returned
// error is the underlying http.Server.Shutdown error — typically nil on
// clean drain, or context.DeadlineExceeded if the cap fires. P1.1 / S4.AdminUI.
func shutdownAdminUI(ctx context.Context, srv *http.Server) error {
	// CHAOS-57: interrupt the rebind loop FIRST so a listener that is currently
	// sleeping out a backoff does not keep trying to bind behind the shutdown,
	// and does not have to be waited out. Ordered before the nil check because
	// the loop can be running on a boot that never assigned the handle.
	stopAdminUIListener()
	if srv == nil {
		return nil
	}
	uiCtx, cancel := context.WithTimeout(ctx, adminUIShutdownTimeout)
	defer cancel()
	return srv.Shutdown(uiCtx)
}

//go:embed static
var staticFiles embed.FS

// uiCfg* hold startup config values for read-only display in the admin UI.
// Set once in main() after config is loaded; safe to read without locks.
//
// Middleware (CSP nonce, IP guard, security headers, auth) lives in
// ui_middleware.go. Session cookie helpers live in ui_session.go. RBAC
// helpers live in ui_rbac.go. The SPA shell + cachedIndexHTML live in
// ui_static.go. CA rotation state (pendingCARotation) lives in
// ui_security.go.
var (
	uiCfgGeoIPDB   string
	uiCfgLogFile   string
	uiCfgLogMaxMB  int
	uiCfgLogFormat string
)

// uiTLSFallbackActive/uiTLSFallbackReason record whether startUI fell back to
// plain HTTP after a self-signed TLS certificate could not be generated — the
// admin panel, including login, is then served in cleartext with no other
// signal of this anywhere in the product (not logs-adjacent: the operator
// would otherwise only learn this by tailing the process log or noticing the
// browser shows no padlock). Set once at startup before the admin server
// starts accepting connections; read-only afterward via
// GET /api/settings/network. Never set when -ui-no-tls was explicitly
// requested (an intentional plaintext choice, not a degraded fallback).
//
// The two halves have DIFFERENT exposure: uiTLSFallbackActive is a fact the
// caller can already observe (it is reading this over plaintext), so it rides
// the public pre-auth surfaces to warn a browser before a password is
// submitted; uiTLSFallbackReason is a raw crypto/x509 error that can quote an
// operator-configured SAN or hostname, so it stays on the viewer-gated
// GET /api/settings/network and the process log. See jsonOKAuthStatus.
var (
	uiTLSFallbackActive bool
	uiTLSFallbackReason string
)

// newAdminUIServer constructs the admin UI *http.Server with the same mux,
// middleware chain, and timeouts that startUI uses, but without binding a
// listener. Extracted so tests can drive the same server against an explicit
// net.Listener (avoiding port-discovery TOCTOU) and so startUI can return a
// shutdown handle to runProxyUntilShutdown. P1.1 / S4.AdminUI.
// newAdminUIHandler builds the fully-composed admin-UI handler: the route mux
// wrapped in the canonical middleware chain (IP guard → security → auth → C2).
// Split out of newAdminUIServer so tests (e.g. the uie2e browser suite) can
// mount the REAL handler chain via httptest.NewServer without the port/TLS
// server wrapper. The middleware order here is the single source of truth and
// must not diverge between production and test.
func newAdminUIHandler() http.Handler { //nolint:funlen // route registration; each line is one endpoint
	sub, _ := fs.Sub(staticFiles, "static")

	// Pre-read index.html from embed for nonce injection.
	loadUIShell(sub)

	staticServer := http.FileServer(http.FS(sub))

	mux := http.NewServeMux()

	// ── Grouped route registrations ─────────────────────────────────────
	// Helpers live alongside their handler files. See docs/UI_REFACTOR_AUDIT.md.
	// Phase B1.
	registerStaticRoutes(mux, staticServer) // ui_static.go      —  1 route
	registerSetupRoutes(mux)                // ui_auth.go        —  2 routes
	registerAuthRoutes(mux)                 // ui_auth.go        — 12 routes
	registerDashboardRoutes(mux)            // ui_config.go      — 10 routes
	registerPolicyRoutes(mux)               // ui_policy.go      — 22 routes
	registerPACRoutes(mux)                  // pac.go            —  2 routes
	// Phase B2.
	registerSecurityRoutes(mux)         // ui_security.go    — 27 routes
	registerSettingsRoutes(mux)         // ui_config.go      — 18 routes (panel-grouped)
	registerClusterRoutes(mux)          // ui_cluster.go     — 21 routes
	registerCDRRoutes(mux)              // cdr_ui.go         —  7 routes
	registerObservabilityRoutes(mux)    // diagnostics.go    —  2 routes (incl. /healthz)
	registerGovernanceRoutes(mux)       // ui_governance.go  —  1 route  (C3, admin-only)
	registerReleaseRoutes(mux)          // release_api.go    —  5 routes (P1.6d-0, no GUI)
	registerSupportRoutes(mux)          // ui_support.go     —  2 routes (M1 Slice 1)
	registerBackupsRoutes(mux)          // backups_api.go    —  1 route  (backup-archive visibility)
	registerMaintAgentStatusRoutes(mux) // maint_agent_status_api.go — 1 route (maintenance-agent health visibility)
	registerDiagnoseRoutes(mux)         // diagnose.go       —  1 route  (M3 diagnose verbs)
	registerMCPRoutes(mux)              // ui_mcp.go         — 14 routes (PR-9 MCP admin API)
	registerPolicyLearningRoutes(mux)   // ui_policy_learning.go — 6 routes (ADR-0025 M5A)

	// FE-1B (ADR-FE-001): the NEW frontend's experimental /app preview +
	// /assets namespace. Registration is unconditional (C1/D0 walls stay
	// deterministic); the CULVERT_EXPERIMENTAL_UI default-off gate lives in
	// the handlers, and the embedded artifact is validated exactly once here.
	ensureFrontendV2(os.Getenv(frontendV2EnvVar))
	registerFrontendV2Routes(mux) // ui_frontend_v2.go — 3 routes (FE-1B, default-off)

	// ADMIN-plane panic backstop (outermost). The admin chain never hijacks, so a
	// clean 500 is valid when nothing was committed; trackedRW preserves
	// ResponseController + SSE Flusher. Registers no route (C1/D0 unaffected).
	return withAdminPanicRecovery(uiIPGuardMiddleware(securityMiddleware(uiAuthMiddleware(uiMetadataEnforcement(mux)))))
}

func newAdminUIServer(port int) *http.Server {
	return &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      newAdminUIHandler(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 0, // SSE (/api/events) requires long-lived write streams; no write deadline
		IdleTimeout:  60 * time.Second,
		ErrorLog:     log.New(&tlsErrorFilter{}, "", 0), // suppress noisy TLS handshake errors
	}
}

// startUI launches the admin UI HTTP server and returns the *http.Server
// handle so runProxyUntilShutdown can call Shutdown(ctx) on it. The actual
// listen goroutine is spawned internally; the returned server is the
// shutdown handle.
//
// CHAOS-57: a listen/serve failure is NEVER fatal. Until this change every
// error branch here called logFatalf, so an admin-plane fault — a port already
// bound, an unreadable custom certificate — terminated the PROXY DATA PLANE
// with it, asynchronously, against a process that had already announced itself
// as serving. The management plane may degrade without the enforcement plane
// going with it; never the reverse. See admin_ui_health.go for the full
// finding, the reproduction and the observability contract.
func startUI(port int, certFile, keyFile string, noTLS bool) *http.Server {
	srv := newAdminUIServer(port)
	noteAdminUIConfigured(port)

	// Auto self-signed TLS — only when explicitly requested, and only when no
	// operator-supplied pair was configured. Resolved ONCE here rather than per
	// attempt: a self-signed certificate is minted in memory, so re-minting it
	// on every rebind would hand a different certificate to the operator's
	// browser after each transient fault.
	if certFile == "" || keyFile == "" {
		if !noTLS {
			tlsCfg, err := selfSignedTLS()
			if err != nil {
				uiTLSFallbackActive = true
				uiTLSFallbackReason = err.Error()
				logger.Printf("TLS self-sign failed (%v), falling back to HTTP", err)
			} else {
				srv.TLSConfig = tlsCfg
			}
		}
	}

	go serveAdminUIWithRetry(srv, port, certFile, keyFile, armAdminUIStop())
	return srv
}

// The retry loop's interrupt channel, so the shutdown hook can wake it out of a
// backoff sleep.
//
// One dedicated mutex covers the channel AND the closed flag. A sync.Once plus
// an atomic.Pointer would be shorter, but the test reset has to re-arm both, and
// re-arming a Once is only safe under the same lock its reader takes — so the
// lock is the thing that actually makes reset correct, and adding the Once on
// top would just be a second, weaker guard over the same state.
var (
	adminUIStopMu     sync.Mutex
	adminUIStopCh     chan struct{}
	adminUIStopClosed bool
)

// armAdminUIStop creates the interrupt channel for a fresh listener.
func armAdminUIStop() <-chan struct{} {
	adminUIStopMu.Lock()
	defer adminUIStopMu.Unlock()
	adminUIStopCh = make(chan struct{})
	adminUIStopClosed = false
	return adminUIStopCh
}

// stopAdminUIListener interrupts the rebind loop. Idempotent, and safe to call
// when no UI was ever started.
func stopAdminUIListener() {
	adminUIStopMu.Lock()
	defer adminUIStopMu.Unlock()
	if adminUIStopCh != nil && !adminUIStopClosed {
		close(adminUIStopCh)
		adminUIStopClosed = true
	}
}

// resetAdminUIStopForTest re-arms the stop machinery between tests. Test
// isolation only; see resetAdminUIHealthForTest, which calls it.
func resetAdminUIStopForTest() {
	adminUIStopMu.Lock()
	defer adminUIStopMu.Unlock()
	adminUIStopCh = nil
	adminUIStopClosed = false
}

// serveAdminUIWithRetry binds and serves the admin UI, rebinding with a
// jittered, interruptible backoff for as long as the process lives.
//
// The bind is performed EXPLICITLY (net.Listen) rather than through
// ListenAndServe so the loop can tell a successful bind from a serve that
// ended — which is what makes "recovery is declared on observed evidence, never
// on elapsed time" implementable here at all.
//
// The rate is bounded; the attempt count deliberately is not. See the
// adminUIListenBackoff* commentary in admin_ui_health.go.
func serveAdminUIWithRetry(srv *http.Server, port int, certFile, keyFile string, stop <-chan struct{}) {
	defer recoverGoroutine("admin-ui-listener")

	addr := fmt.Sprintf(":%d", port)
	backoff := adminUIListenBackoffInitial

	for {
		select {
		case <-stop:
			noteAdminUIStopped()
			return
		default:
		}

		err := adminUIServeOnce(srv, addr, certFile, keyFile)
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			// Shutdown/Close — the only clean exit. Never a fault, never an alert.
			noteAdminUIStopped()
			return
		}

		reason := classifyAdminUIListenError(err)
		wait := jitterDuration(backoff, adminUIListenJitter)
		if noteAdminUIListenFailure(reason, backoff, time.Now()) {
			// The FULL error goes here and nowhere else: the contract row, the
			// alert and the readiness detail all carry the bounded class only.
			// logErrorf applies sanitizeLog (CWE-117) to the whole line.
			logErrorf("admin UI listener on port %d unavailable (%s): %v — retrying in %s; "+
				"the proxy data plane is unaffected and is still enforcing policy",
				port, reason, err, wait.Round(time.Millisecond))
		}

		if !haSleepInterruptible(stop, wait) {
			noteAdminUIStopped()
			return
		}
		if backoff *= 2; backoff > adminUIListenBackoffMax {
			backoff = adminUIListenBackoffMax
		}
	}
}

// adminUIBeforeServeTLS is a test seam run immediately before a custom-cert
// ServeTLS call; it lets a gate rotate the pair on disk inside the window that
// used to separate the recorded certificate from the served one. No-op in
// production.
var adminUIBeforeServeTLS = func() {}

// adminUIServeOnce performs one bind-and-serve attempt. It returns
// http.ErrServerClosed once the server has been Shutdown/Closed, and any other
// error for a fault the caller should retry.
//
// The operator-supplied certificate is re-read on EVERY attempt, which is what
// makes a rotation that briefly leaves the pair unreadable self-healing: the
// attempt that runs after the rotation completes picks up the new material with
// no restart.
func adminUIServeOnce(srv *http.Server, addr, certFile, keyFile string) error {
	// Load the operator-supplied pair BEFORE binding, for two reasons.
	//
	//  1. http.Server.ServeTLS returns a certificate error WITHOUT closing the
	//     listener it was handed, so a bind-first loop would leak one socket per
	//     attempt against a persistently bad certificate — turning a recoverable
	//     config fault into descriptor exhaustion.
	//  2. It is what lets the failure be classified as `tls_certificate` rather
	//     than matching on crypto/tls error text.
	//
	// The loaded pair is then the one SERVED: it is installed into the server's
	// TLS config and ServeTLS is called with empty paths, so the files are read
	// exactly once per attempt. Re-reading them inside ServeTLS (the previous
	// shape) let a rotation landing between the two reads serve the new pair
	// while the expiry surface reported the old one until restart. ServeTLS is
	// still the entry point because it calls setupHTTP2_ServeTLS, which
	// srv.Serve(tls.NewListener(...)) does not — hand-rolling the TLS listener
	// here would silently drop ALPN h2 from the admin UI.
	customTLS := certFile != "" && keyFile != ""
	var customCert tls.Certificate
	if customTLS {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return fmt.Errorf("%w: %w", errAdminUITLSMaterial, err)
		}
		customCert = cert
	}

	lc := &net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		return err
	}
	// Record the serving certificate's expiry only once the port is actually
	// held: a pair that failed to bind is not being served, and recording it
	// would also overwrite the expiry of the last pair that was.
	if customTLS {
		noteAdminUITLSCertExpiry(customCert)
	}

	// The bind is the EVIDENCE. Announce only now: the pre-change code logged
	// "UIHTTP: http://localhost:%d" before attempting to bind, so the process
	// log actively claimed the admin UI was listening on a port it had never
	// acquired.
	if suppressed := noteAdminUIServing(); suppressed > 0 {
		logger.Printf("admin UI listener recovered on %s (%d further failure log lines were suppressed while it was down)",
			addr, suppressed)
	}
	switch {
	case customTLS:
		logger.Printf("UITLS: https://localhost%s (custom cert)", addr)
	case srv.TLSConfig != nil:
		logger.Printf("UITLS: https://localhost%s (self-signed)", addr)
	default:
		logger.Printf("UIHTTP: http://localhost%s", addr)
	}

	// Serve closes ln on return; the extra Close is a deterministic backstop for
	// the ServeTLS path, which can return a certificate error without closing
	// the listener it was handed (see the pre-validation above — this covers the
	// residual race in which the pair is broken between validating and serving).
	defer ln.Close() //nolint:errcheck // idempotent teardown; Serve has normally closed it already

	if customTLS {
		adminUIBeforeServeTLS()
		// Serve the pair recorded above, never a second read of the files.
		// A config left by an earlier attempt (net/http's HTTP/2 setup may
		// initialise one) is cloned rather than discarded.
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if srv.TLSConfig != nil {
			cfg = srv.TLSConfig.Clone()
		}
		cfg.Certificates = []tls.Certificate{customCert}
		srv.TLSConfig = cfg
		return srv.ServeTLS(ln, "", "")
	}
	if srv.TLSConfig != nil {
		return srv.ServeTLS(ln, "", "")
	}
	return srv.Serve(ln)
}
