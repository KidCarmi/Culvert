package main

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
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
	registerPolicyRoutes(mux)               // ui_policy.go      — 19 routes
	registerPACRoutes(mux)                  // pac.go            —  2 routes
	// Phase B2.
	registerSecurityRoutes(mux)      // ui_security.go    — 27 routes
	registerSettingsRoutes(mux)      // ui_config.go      — 18 routes (panel-grouped)
	registerClusterRoutes(mux)       // ui_cluster.go     — 21 routes
	registerCDRRoutes(mux)           // cdr_ui.go         —  7 routes
	registerObservabilityRoutes(mux) // diagnostics.go    —  2 routes (incl. /healthz)
	registerGovernanceRoutes(mux)    // ui_governance.go  —  1 route  (C3, admin-only)
	registerReleaseRoutes(mux)       // release_api.go    —  5 routes (P1.6d-0, no GUI)

	return uiIPGuardMiddleware(securityMiddleware(uiAuthMiddleware(uiMetadataEnforcement(mux))))
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
// shutdown handle. Errors from ListenAndServe* that are not http.ErrServerClosed
// remain fatal — only the clean-shutdown sentinel is filtered.
func startUI(port int, certFile, keyFile string, noTLS bool) *http.Server {
	srv := newAdminUIServer(port)

	if certFile != "" && keyFile != "" {
		logger.Printf("UITLS: https://localhost:%d (custom cert)", port)
		go func() {
			if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Fatalf("UI TLS error: %v", err)
			}
		}()
		return srv
	}

	// Auto self-signed TLS — only when explicitly requested.
	if !noTLS {
		tlsCfg, err := selfSignedTLS()
		if err != nil {
			logger.Printf("TLS self-sign failed (%v), falling back to HTTP", err)
		} else {
			srv.TLSConfig = tlsCfg
			logger.Printf("UITLS: https://localhost:%d (self-signed)", port)
			go func() {
				if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
					logger.Fatalf("UI TLS error: %v", err)
				}
			}()
			return srv
		}
	}

	logger.Printf("UIHTTP: http://localhost:%d", port)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("UI server error: %v", err)
		}
	}()
	return srv
}
