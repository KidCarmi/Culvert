package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"html"
	"io/fs"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed static
var staticFiles embed.FS

// uiCfg* hold startup config values for read-only display in the admin UI.
// Set once in main() after config is loaded; safe to read without locks.
var (
	uiCfgGeoIPDB   string
	uiCfgLogFile   string
	uiCfgLogMaxMB  int
	uiCfgLogFormat string
)

// pendingCARotation holds a confirmation token for the two-step CA rotation flow.
// An admin must first request rotation (receives a token), then confirm with that token.
var pendingCARotation struct {
	sync.Mutex
	token   string
	expires time.Time
}

// cachedIndexHTML holds the embedded index.html template with __CSP_NONCE__
// placeholders. Read once at startup to avoid re-reading the embed on every
// page load.
//
// Middleware (CSP nonce, IP guard, security headers, auth) lives in
// ui_middleware.go. Session cookie helpers live in ui_session.go. RBAC
// helpers live in ui_rbac.go.
var cachedIndexHTML []byte

func startUI(port int, certFile, keyFile string, noTLS bool) { //nolint:funlen // route registration; each line is one endpoint
	sub, _ := fs.Sub(staticFiles, "static")

	// Pre-read index.html from embed for nonce injection.
	if data, err := fs.ReadFile(sub, "index.html"); err == nil {
		cachedIndexHTML = data
	}

	staticServer := http.FileServer(http.FS(sub))

	mux := http.NewServeMux()
	// Serve index.html with per-request CSP nonce injection; all other
	// static assets (logo.png, etc.) are served directly from the embed.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/index.html" {
			staticServer.ServeHTTP(w, r)
			return
		}
		// Read nonce from context (set by securityMiddleware).
		nonce, _ := r.Context().Value(cspNonceKey{}).(string)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		body := strings.ReplaceAll(string(cachedIndexHTML), "__CSP_NONCE__", html.EscapeString(nonce))
		w.Write([]byte(body)) //nolint:errcheck
	})
	mux.HandleFunc("/api/setup/status", apiSetupStatus)
	mux.HandleFunc("/api/setup/complete", apiSetupComplete)
	mux.HandleFunc("/api/stats", apiStats)
	mux.HandleFunc("/api/dashboard/health", apiDashboardHealth)
	mux.HandleFunc("/api/dashboard/threats", apiDashboardThreats)
	mux.HandleFunc("/api/dashboard/top-rules", apiDashboardTopRules)
	mux.HandleFunc("/api/timeseries", apiTimeseries)
	mux.HandleFunc("/api/logs", apiLogs)
	mux.HandleFunc("/api/top-hosts", apiTopHosts)
	mux.HandleFunc("/api/blocklist", apiBlocklist)
	mux.HandleFunc("/api/fileblock", apiFileblock)
	mux.HandleFunc("/api/fileblock/profiles", apiFileblockProfiles)
	mux.HandleFunc("/api/settings", apiSettings)
	mux.HandleFunc("/api/security", apiSecurity)
	mux.HandleFunc("/api/export", apiExport)
	mux.HandleFunc("/api/rewrite", apiRewrite)
	mux.HandleFunc("/api/policy", apiPolicy)
	mux.HandleFunc("/api/policy/reorder", apiPolicyReorder)
	mux.HandleFunc("/api/policy/move", apiPolicyMove)
	mux.HandleFunc("/api/policy/test", apiPolicyTest)

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
	mux.HandleFunc("/api/audit", apiAudit)
	mux.HandleFunc("/api/events", apiEvents) // SSE live dashboard
	mux.HandleFunc("/api/country-traffic", apiCountryTraffic)
	mux.HandleFunc("/api/default-action", apiDefaultAction)
	mux.HandleFunc("/api/blocklist/mode", apiBlocklistMode)             // GET/POST blocklist mode
	mux.HandleFunc("/api/blocklist/feed", apiBlocklistFeed)             // GET/POST feed URL+interval
	mux.HandleFunc("/api/blocklist/feed/sync", apiBlocklistFeedSync)    // POST force-sync
	mux.HandleFunc("/api/blocklist/exceptions", apiBlocklistExceptions) // GET/POST/DELETE
	mux.HandleFunc("/api/config/export", apiConfigExport)               // GET — download backup JSON
	mux.HandleFunc("/api/config/import", apiConfigImport)               // POST — restore from backup JSON
	mux.HandleFunc("/api/settings/unauth-mode", apiUnauthMode)          // PUT — toggle proxy auth requirement
	mux.HandleFunc("/api/settings/log-level", apiLogLevel)              // GET/PUT runtime log level
	mux.HandleFunc("/api/settings/network", apiNetworkSettings)         // GET/POST network & TLS settings
	mux.HandleFunc("/api/session-timeout", apiSessionTimeout)           // GET/POST session TTL (hours)
	mux.HandleFunc("/api/session-secret", apiSessionSecret)             // GET/POST shared signing key
	mux.HandleFunc("/api/ui-allow-ips", apiUIAllowIPs)                  // GET/POST UI access IP allowlist
	mux.HandleFunc("/api/syslog", apiSyslogConfig)                      // GET/POST syslog forwarding
	mux.HandleFunc("/api/syslog/test", apiSyslogTest)                   // POST syslog test message

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

	// ── URL Categories (dynamic host-list management) ─────────────────────
	mux.HandleFunc("/api/category-groups", apiCategoryGroups) // GET/POST/PUT/DELETE category groups
	mux.HandleFunc("/api/urlcat", apiURLCat)                  // GET/POST/PUT/DELETE categories
	mux.HandleFunc("/api/urlcat/host", apiURLCatHost)         // POST/DELETE individual hosts
	mux.HandleFunc("/api/urlcat/lookup", apiURLCatLookup)     // GET — resolve a domain to its category

	// ── Admin session auth ────────────────────────────────────────────────
	mux.HandleFunc("/api/auth/login", apiAuthLogin)
	mux.HandleFunc("/api/auth/status", apiAuthStatus)
	mux.HandleFunc("/api/auth/logout", apiAuthLogout)
	mux.HandleFunc("/api/auth/users", apiAuthUsers)                    // RBAC user management (admin only)
	mux.HandleFunc("/api/auth/change-password", apiAuthChangePassword) // self-service password change (any role)

	// ── Generic IdP Framework ─────────────────────────────────────────────
	mux.HandleFunc("/api/idp", apiIdPList)              // GET list / POST create
	mux.HandleFunc("/api/idp/discover", apiIdPDiscover) // POST: run OIDC discovery (must be before /api/idp/)
	mux.HandleFunc("/api/idp/", apiIdPRouter)           // GET|PUT|DELETE /api/idp/{id} + /api/idp/{id}/groups

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

	// ── Block page template ──────────────────────────────────────────────
	mux.HandleFunc("/api/blockpage", apiBlockPage) // GET template / PUT update

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

	// ── PAC file ─────────────────────────────────────────────────────────
	mux.HandleFunc("/proxy.pac", servePACFile) // served on the UI port
	mux.HandleFunc("/api/pac-config", apiPACConfig)

	// ── Auth callbacks (not behind UI auth middleware) ────────────────────
	// These are reached by browser redirects from IdPs (not admin UI calls).
	// They are registered on the same UI port; the proxy port handles traffic.
	mux.HandleFunc("/auth/oidc/callback", authOIDCCallback)
	mux.HandleFunc("/auth/saml/callback", authSAMLCallback)
	mux.HandleFunc("/auth/select", authSelectProvider) // IdP selection screen
	mux.HandleFunc("/auth/logout", authLogout)

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

// auditEvent records a configuration change to the audit ring buffer.
// It extracts the caller's IP from the HTTP request as the actor identity.
// action follows "resource.verb" e.g. "policy.add", "blocklist.remove".
// Credentials must NEVER appear in object or detail.
func auditEvent(r *http.Request, action, object, detail string) {
	auditEventDiff(r, action, object, detail, nil, nil)
}

// auditEventDiff records an audit event with optional before/after JSON snapshots.
func auditEventDiff(r *http.Request, action, object, detail string, before, after any) {
	actor, _, _ := net.SplitHostPort(r.RemoteAddr)
	if actor == "" {
		actor = r.RemoteAddr
	}
	// Enrich actor with authenticated admin identity from session cookie.
	// The IP is always kept for accountability; the username adds readability.
	if sess, err := readSessionCookie(r); err == nil && sess != nil {
		name := sess.Sub
		if name == "" {
			name = sess.Email
		}
		if name != "" {
			actor = name + "@" + actor
		}
	}
	entry := AuditEntry{
		TS:     time.Now().UnixMilli(),
		Time:   time.Now().Format("2006-01-02 15:04:05"),
		Actor:  actor,
		Action: action,
		Object: object,
		Detail: detail,
	}
	if before != nil {
		if b, err := json.Marshal(before); err == nil {
			entry.Before = string(b)
		}
	}
	if after != nil {
		if a, err := json.Marshal(after); err == nil {
			entry.After = string(a)
		}
	}
	auditAdd(entry)
}

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// Response headers already sent; can't write an HTTP error at this point.
		logger.Printf("ERROR: jsonOK encode failed: %v", err)
	}
}

// isValidBlocklistWildcard checks that a wildcard blocklist entry uses only the
// allowed *.example.com format. Rejects **.example.com, *.*.example.com,
// *example.com (no dot after star), and any other non-standard wildcard usage.
func isValidBlocklistWildcard(h string) bool {
	// Only a single leading "*." prefix is allowed.
	if !strings.HasPrefix(h, "*.") {
		return false // e.g. *example.com (no dot after star)
	}
	rest := h[2:] // everything after "*."
	if rest == "" {
		return false // "*." alone is not a valid domain
	}
	// No additional wildcards anywhere in the remainder.
	if strings.Contains(rest, "*") {
		return false // e.g. *.*.example.com or **.example.com
	}
	return true
}

// validatePolicyRule checks that a rule has a valid action, a non-empty name,
// a safe redirect URL when required, a parseable timezone, and name uniqueness.
// existingRules is the current rule set; editPriority is the priority of the rule
// being edited (use -1 when adding a new rule) so its own name is not flagged as
// a duplicate.
func validatePolicyRule(rule PolicyRule, existingRules []PolicyRule, editPriority int) error {
	if rule.Name == "" {
		return fmt.Errorf("name is required")
	}
	// Duplicate name check (Finding 2.2).
	for i := range existingRules {
		if strings.EqualFold(existingRules[i].Name, rule.Name) && existingRules[i].Priority != editPriority {
			return fmt.Errorf("rule name already exists")
		}
	}
	validActions := map[PolicyAction]bool{
		ActionAllow: true, ActionDrop: true,
		ActionBlockPage: true, ActionRedirect: true,
	}
	if !validActions[rule.Action] {
		return fmt.Errorf("action must be Allow, Drop, Block_Page, or Redirect")
	}
	if rule.Action == ActionRedirect {
		if rule.RedirectURL == "" {
			return fmt.Errorf("redirectURL is required when action is Redirect")
		}
		if !isSafeRedirectURL(rule.RedirectURL) {
			return fmt.Errorf("redirectURL must be an absolute http/https URL")
		}
	}
	if rule.Schedule != nil && rule.Schedule.Timezone != "" {
		if _, err := time.LoadLocation(rule.Schedule.Timezone); err != nil {
			return fmt.Errorf("invalid schedule timezone: %s", strings.ReplaceAll(rule.Schedule.Timezone, "\n", ""))
		}
	}
	return nil
}

// decodeJSON decodes the request body into v using strict mode:
// unknown fields are rejected (prevents payload-inflation / field confusion).
func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func parseTimestampParam(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	// Try Unix timestamp (integer seconds) first.
	if ts, err := strconv.ParseInt(s, 10, 64); err == nil {
		return ts, nil
	}
	// Try ISO 8601 / RFC 3339.
	t, err := time.Parse(time.RFC3339, s)
	if err == nil {
		return t.Unix(), nil
	}
	// Try RFC 3339 without timezone (assume UTC).
	t, err = time.Parse("2006-01-02T15:04:05", s)
	if err == nil {
		return t.UTC().Unix(), nil
	}
	// Try date-only format.
	t, err = time.Parse("2006-01-02", s)
	if err == nil {
		return t.UTC().Unix(), nil
	}
	return 0, fmt.Errorf("unrecognized timestamp format: %s", s)
}
