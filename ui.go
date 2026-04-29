package main

import (
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"time"
)

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

func startUI(port int, certFile, keyFile string, noTLS bool) { //nolint:funlen // route registration; each line is one endpoint
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
	registerPolicyRoutes(mux)               // ui_policy.go      — 18 routes
	registerPACRoutes(mux)                  // pac.go            —  2 routes
	// Phase B2.
	registerSecurityRoutes(mux)      // ui_security.go    — 27 routes
	registerSettingsRoutes(mux)      // ui_config.go      — 18 routes (panel-grouped)
	registerClusterRoutes(mux)       // ui_cluster.go     — 21 routes
	registerUpdateRoutes(mux)        // update.go         — 11 routes
	registerCDRRoutes(mux)           // cdr_ui.go         —  7 routes
	registerObservabilityRoutes(mux) // diagnostics.go    —  2 routes (incl. /healthz)

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      uiIPGuardMiddleware(securityMiddleware(uiAuthMiddleware(uiMetadataEnforcement(mux)))),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 0, // SSE (/api/events) requires long-lived write streams; no write deadline
		IdleTimeout:  60 * time.Second,
		ErrorLog:     log.New(&tlsErrorFilter{}, "", 0), // suppress noisy TLS handshake errors
	}

	if certFile != "" && keyFile != "" {
		logger.Printf("UITLS: https://localhost:%d (custom cert)", port)
		if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil {
			logger.Fatalf("UI TLS error: %v", err)
		}
		return
	}

	// Auto self-signed TLS — only when explicitly requested.
	if !noTLS {
		tlsCfg, err := selfSignedTLS()
		if err != nil {
			logger.Printf("TLS self-sign failed (%v), falling back to HTTP", err)
		} else {
			srv.TLSConfig = tlsCfg
			logger.Printf("UITLS: https://localhost:%d (self-signed)", port)
			if err := srv.ListenAndServeTLS("", ""); err != nil {
				logger.Fatalf("UI TLS error: %v", err)
			}
			return
		}
	}

	logger.Printf("UIHTTP: http://localhost:%d", port)
	if err := srv.ListenAndServe(); err != nil {
		logger.Fatalf("UI server error: %v", err)
	}
}
