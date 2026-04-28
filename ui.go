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

	// ── Phase B1: grouped registrations ─────────────────────────────────
	// Helpers live alongside their handler files. See docs/UI_REFACTOR_AUDIT.md.
	registerStaticRoutes(mux, staticServer) // ui_static.go
	registerSetupRoutes(mux)                // ui_auth.go
	registerAuthRoutes(mux)                 // ui_auth.go
	registerDashboardRoutes(mux)            // ui_config.go
	registerPolicyRoutes(mux)               // ui_policy.go
	registerPACRoutes(mux)                  // pac.go

	// ── Phase B2 (pending): the routes below remain flat for now and will
	// be grouped into register*Routes helpers in the next refactor PR.
	// ────────────────────────────────────────────────────────────────────
	mux.HandleFunc("/api/settings", apiSettings)
	mux.HandleFunc("/api/security", apiSecurity)
	mux.HandleFunc("/api/export", apiExport)

	// CDR (Sluice) integration — Phase 2c admin API.
	mux.HandleFunc("/api/cdr/config", apiCDRConfig)
	mux.HandleFunc("/api/cdr/instances", apiCDRInstances)
	mux.HandleFunc("/api/cdr/instances/enroll", apiCDREnroll)
	mux.HandleFunc("/api/cdr/instances/revoke", apiCDRRevokeRPC)
	mux.HandleFunc("/api/cdr/policies", apiCDRPolicies)
	mux.HandleFunc("/api/cdr/health", apiCDRHealth)
	mux.HandleFunc("/api/cdr/test", apiCDRTest)
	mux.HandleFunc("/api/ca-cert", apiCACert)
	mux.HandleFunc("/api/certs/upload", apiCertsUpload)
	mux.HandleFunc("/api/ssl-bypass", apiSSLBypass)
	mux.HandleFunc("/api/content-scan", apiContentScan)
	mux.HandleFunc("/api/config/export", apiConfigExport)       // GET — download backup JSON
	mux.HandleFunc("/api/config/import", apiConfigImport)       // POST — restore from backup JSON
	mux.HandleFunc("/api/settings/unauth-mode", apiUnauthMode)  // PUT — toggle proxy auth requirement
	mux.HandleFunc("/api/settings/log-level", apiLogLevel)      // GET/PUT runtime log level
	mux.HandleFunc("/api/settings/network", apiNetworkSettings) // GET/POST network & TLS settings
	mux.HandleFunc("/api/session-timeout", apiSessionTimeout)   // GET/POST session TTL (hours)
	mux.HandleFunc("/api/session-secret", apiSessionSecret)     // GET/POST shared signing key
	mux.HandleFunc("/api/ui-allow-ips", apiUIAllowIPs)          // GET/POST UI access IP allowlist
	mux.HandleFunc("/api/syslog", apiSyslogConfig)              // GET/POST syslog forwarding
	mux.HandleFunc("/api/syslog/test", apiSyslogTest)           // POST syslog test message

	// ── Security scanning (ClamAV / YARA / Threat Feeds) ─────────────────
	mux.HandleFunc("/api/security-scan/status", apiSecScanStatus)                   // GET
	mux.HandleFunc("/api/security-scan/feeds/sync", apiSecFeedsSync)                // POST — force immediate sync
	mux.HandleFunc("/api/security-scan/feeds/domain-allowlist", apiDomainAllowlist) // GET/PUT — threat feed domain allowlist
	mux.HandleFunc("/api/security-scan/yara/reload", apiSecYARAReload)              // POST — reload YARA rules from dir
	mux.HandleFunc("/api/security-scan/yara/rules", apiSecYARARules)                // GET/POST/PUT/DELETE — list / CRUD YARA rule files
	mux.HandleFunc("/api/security-scan/yara/rules/", apiSecYARARules)               // PUT/DELETE /api/security-scan/yara/rules/{name}
	mux.HandleFunc("/api/security-scan/yara/validate", apiSecYARAValidate)          // POST — dry-run validate a YARA rule source
	mux.HandleFunc("/api/security-scan/yara/settings", apiSecYARASettings)          // GET/PUT — YARA engine runtime config
	mux.HandleFunc("/api/security-scan/exclusions", apiSecScanExclusions)           // GET/PUT — scan exclusion hashes/hosts
	mux.HandleFunc("/api/security-scan/svc", apiScanSvcConfig)                      // GET — scan service mode info
	mux.HandleFunc("/api/security-scan/cache", apiScanCache)                        // GET/DELETE — scan hash cache stats & purge
	mux.HandleFunc("/api/content-scan/bypass", apiContentScanBypass)                // GET/PUT — DPI bypass host list

	// ── Alert webhooks ───────────────────────────────────────────────────
	mux.HandleFunc("/api/alerts/webhooks", apiAlertsWebhooks)             // GET list / POST create
	mux.HandleFunc("/api/alerts/webhooks/test", apiAlertsWebhookTest)     // POST — test-fire
	mux.HandleFunc("/api/alerts/webhooks/history", apiAlertsDeliveryHist) // GET — delivery history (Finding 8.1)

	// ── Updates ──────────────────────────────────────────────────────────
	mux.HandleFunc("/api/update/status", apiUpdateStatus)                  // GET — version info
	mux.HandleFunc("/api/update/check", apiUpdateCheck)                    // POST — trigger version check
	mux.HandleFunc("/api/update/apply", apiUpdateApply)                    // POST — apply update (SSE)
	mux.HandleFunc("/api/update/preview", apiUpdatePreview)                // POST — config diff preview
	mux.HandleFunc("/api/update/reports", apiUpdateReports)                // GET — list/download reports
	mux.HandleFunc("/api/update/rollback", apiUpdateRollback)              // POST — rollback
	mux.HandleFunc("/api/update/rollback/status", apiUpdateRollbackStatus) // GET — rollback availability
	mux.HandleFunc("/api/update/session", apiUpdateSession)                // GET — active update session (SSE re-attach)
	mux.HandleFunc("/api/update/cluster", apiClusterUpdate)                // POST — start rolling update
	mux.HandleFunc("/api/update/cluster/status", apiClusterUpdateStatus)   // GET — rolling update progress
	mux.HandleFunc("/api/update/registry", apiRegistrySettings)            // GET/POST — registry settings

	// ── Config versioning ────────────────────────────────────────────────
	mux.HandleFunc("/api/config/versions", apiConfigVersions) // GET list / POST rollback
	mux.HandleFunc("/api/config/diff", apiConfigDiff)         // GET diff between versions

	// ── CA management ────────────────────────────────────────────────────
	mux.HandleFunc("/api/ca/status", apiCAStatus)            // GET — CA info + cache + rotation + dual-CA
	mux.HandleFunc("/api/ca/key-provider", apiCAKeyProvider) // GET key provider status
	mux.HandleFunc("/api/ca/download", apiCADownload)        // GET — PEM download
	mux.HandleFunc("/api/ca/cache-clear", apiCACacheClear)   // POST — clear leaf cert cache
	mux.HandleFunc("/api/ca/rotate", apiCARotate)            // POST — force CA rotation

	// ── OCSP management ─────────────────────────────────────────────────
	mux.HandleFunc("/api/ocsp", apiOCSPConfig) // GET status / POST toggle

	// ── GeoIP status ────────────────────────────────────────────────────
	mux.HandleFunc("/api/geoip", apiGeoIPConfig)

	// ── Logger config ───────────────────────────────────────────────────
	mux.HandleFunc("/api/logger", apiLoggerConfig)

	// ── Metrics config ──────────────────────────────────────────────────
	mux.HandleFunc("/api/metrics-config", apiMetricsConfig)
	mux.HandleFunc("/api/otlp", apiOTLPConfig)

	// ── Connection limit ─────────────────────────────────────────────────
	mux.HandleFunc("/api/connlimit", apiConnLimit) // GET status / POST update

	// ── Upstream proxy chaining ──────────────────────────────────────────
	mux.HandleFunc("/api/upstream", apiUpstream)                  // GET list / POST add
	mux.HandleFunc("/api/upstream/settings", apiUpstreamSettings) // GET/PUT circuit breaker
	mux.HandleFunc("/api/upstream/health", apiUpstreamHealth)     // POST force health check

	// ── Cluster / multi-node ─────────────────────────────────────────────
	mux.HandleFunc("/api/cluster/status", apiClusterStatus)                       // GET this node + connected nodes
	mux.HandleFunc("/api/cluster/mode", apiClusterMode)                           // POST enable control-plane mode
	mux.HandleFunc("/api/cluster/tokens", apiClusterTokens)                       // GET list / POST create / DELETE remove
	mux.HandleFunc("/api/cluster/nodes", apiClusterNodes)                         // GET enrolled nodes
	mux.HandleFunc("/api/cluster/revoke", apiClusterRevoke)                       // POST revoke a node
	mux.HandleFunc("/api/cluster/labels", apiClusterLabels)                       // POST set node labels
	mux.HandleFunc("/api/cluster/node-groups", apiNodeGroups)                     // GET list / POST create / DELETE remove
	mux.HandleFunc("/api/cluster/node-groups/membership", apiNodeGroupMembership) // GET group membership (F9)
	mux.HandleFunc("/api/cluster/drain", apiClusterDrain)                         // POST toggle node drain mode
	mux.HandleFunc("/api/cluster/metrics", apiClusterMetrics)                     // GET aggregated cluster metrics
	mux.HandleFunc("/api/cluster/ca", apiClusterCA)                               // GET info / POST import cluster CA
	mux.HandleFunc("/api/cluster/rate-limits", apiClusterRateLimits)              // GET distributed RL status
	mux.HandleFunc("/api/cluster/audit", apiClusterAudit)                         // GET centralized audit log
	mux.HandleFunc("/api/cluster/revocations", apiClusterRevocations)             // GET revocation sync status
	mux.HandleFunc("/api/cluster/rotation", apiClusterRotation)                   // GET CA rotation progress
	mux.HandleFunc("/api/cluster/ha", apiClusterHA)                               // GET HA status
	mux.HandleFunc("/api/cluster/bandwidth", apiBandwidthPolicies)                // GET/POST/DELETE bandwidth QoS policies
	mux.HandleFunc("/api/cluster/bootstrap/", apiBootstrapRouter)                 // GET bootstrap script/compose (token-authed)
	mux.HandleFunc("/healthz", apiHealthz)                                        // GET unauthenticated health check (LB probe)

	// ── Operator diagnostics ────────────────────────────────────────────
	mux.HandleFunc("/api/diagnostics", apiDiagnostics) // GET — aggregated operator contract (viewer)

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      uiIPGuardMiddleware(securityMiddleware(uiAuthMiddleware(mux))),
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
