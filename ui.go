package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"embed"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"net/url"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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

// tlsErrorFilter is an io.Writer that suppresses noisy TLS handshake errors
// from Go's http.Server.ErrorLog. These are expected when clients connect to
// a self-signed admin UI and reject the certificate.
type tlsErrorFilter struct{}

func (f *tlsErrorFilter) Write(p []byte) (int, error) {
	if strings.Contains(string(p), "TLS handshake error") {
		return len(p), nil // silently discard
	}
	// Forward non-TLS errors to the application logger.
	logger.Printf("HTTP: %s", strings.TrimSpace(string(p)))
	return len(p), nil
}

func startUI(port int, certFile, keyFile string, noTLS bool) { //nolint:funlen // route registration; each line is one endpoint
	sub, _ := fs.Sub(staticFiles, "static")

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(sub)))
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
	mux.HandleFunc("/api/policy/test", apiPolicyTest)
	mux.HandleFunc("/api/ca-cert", apiCACert)
	mux.HandleFunc("/api/certs/upload", apiCertsUpload)
	mux.HandleFunc("/api/ssl-bypass", apiSSLBypass)
	mux.HandleFunc("/api/content-scan", apiContentScan)
	mux.HandleFunc("/api/audit", apiAudit)
	mux.HandleFunc("/api/events", apiEvents) // SSE live dashboard
	mux.HandleFunc("/api/country-traffic", apiCountryTraffic)
	mux.HandleFunc("/api/default-action", apiDefaultAction)
	mux.HandleFunc("/api/blocklist/mode", apiBlocklistMode)         // GET/POST blocklist mode
	mux.HandleFunc("/api/blocklist/feed", apiBlocklistFeed)         // GET/POST feed URL+interval
	mux.HandleFunc("/api/blocklist/feed/sync", apiBlocklistFeedSync) // POST force-sync
	mux.HandleFunc("/api/blocklist/exceptions", apiBlocklistExceptions) // GET/POST/DELETE
	mux.HandleFunc("/api/config/export", apiConfigExport)      // GET — download backup JSON
	mux.HandleFunc("/api/config/import", apiConfigImport)      // POST — restore from backup JSON
	mux.HandleFunc("/api/settings/unauth-mode", apiUnauthMode) // PUT — toggle proxy auth requirement
	mux.HandleFunc("/api/settings/log-level", apiLogLevel)     // GET/PUT runtime log level
	mux.HandleFunc("/api/settings/network", apiNetworkSettings) // GET/POST network & TLS settings
	mux.HandleFunc("/api/session-timeout", apiSessionTimeout)  // GET/POST session TTL (hours)
	mux.HandleFunc("/api/session-secret", apiSessionSecret)    // GET/POST shared signing key
	mux.HandleFunc("/api/ui-allow-ips", apiUIAllowIPs)         // GET/POST UI access IP allowlist
	mux.HandleFunc("/api/syslog", apiSyslogConfig)             // GET/POST syslog forwarding

	// ── Security scanning (ClamAV / YARA / Threat Feeds) ─────────────────
	mux.HandleFunc("/api/security-scan/status", apiSecScanStatus)      // GET
	mux.HandleFunc("/api/security-scan/feeds/sync", apiSecFeedsSync)             // POST — force immediate sync
	mux.HandleFunc("/api/security-scan/feeds/domain-allowlist", apiDomainAllowlist) // GET/PUT — threat feed domain allowlist
	mux.HandleFunc("/api/security-scan/yara/reload", apiSecYARAReload)            // POST — reload YARA rules from dir
	mux.HandleFunc("/api/security-scan/svc", apiScanSvcConfig)                   // GET — scan service mode info
	mux.HandleFunc("/api/security-scan/cache", apiScanCache)                    // GET/DELETE — scan hash cache stats & purge

	// ── URL Categories (dynamic host-list management) ─────────────────────
	mux.HandleFunc("/api/urlcat", apiURLCat)            // GET/POST/PUT/DELETE categories
	mux.HandleFunc("/api/urlcat/host", apiURLCatHost)   // POST/DELETE individual hosts
	mux.HandleFunc("/api/urlcat/lookup", apiURLCatLookup) // GET — resolve a domain to its category

	// ── Admin session auth ────────────────────────────────────────────────
	mux.HandleFunc("/api/auth/login", apiAuthLogin)
	mux.HandleFunc("/api/auth/status", apiAuthStatus)
	mux.HandleFunc("/api/auth/logout", apiAuthLogout)
	mux.HandleFunc("/api/auth/users", apiAuthUsers)             // RBAC user management (admin only)
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
	mux.HandleFunc("/api/update/status", apiUpdateStatus)                   // GET — version info
	mux.HandleFunc("/api/update/check", apiUpdateCheck)                     // POST — trigger version check
	mux.HandleFunc("/api/update/apply", apiUpdateApply)                     // POST — apply update (SSE)
	mux.HandleFunc("/api/update/preview", apiUpdatePreview)                 // POST — config diff preview
	mux.HandleFunc("/api/update/reports", apiUpdateReports)                 // GET — list/download reports
	mux.HandleFunc("/api/update/rollback", apiUpdateRollback)               // POST — rollback
	mux.HandleFunc("/api/update/rollback/status", apiUpdateRollbackStatus)  // GET — rollback availability
	mux.HandleFunc("/api/update/cluster", apiClusterUpdate)                 // POST — start rolling update
	mux.HandleFunc("/api/update/cluster/status", apiClusterUpdateStatus)    // GET — rolling update progress
	mux.HandleFunc("/api/update/registry", apiRegistrySettings)             // GET/POST — registry settings

	// ── Config versioning ────────────────────────────────────────────────
	mux.HandleFunc("/api/config/versions", apiConfigVersions) // GET list / POST rollback
	mux.HandleFunc("/api/config/diff", apiConfigDiff)         // GET diff between versions

	// ── CA management ────────────────────────────────────────────────────
	mux.HandleFunc("/api/ca/status", apiCAStatus)           // GET — CA info + cache + rotation + dual-CA
	mux.HandleFunc("/api/ca/key-provider", apiCAKeyProvider) // GET key provider status
	mux.HandleFunc("/api/ca/download", apiCADownload)       // GET — PEM download
	mux.HandleFunc("/api/ca/cache-clear", apiCACacheClear)  // POST — clear leaf cert cache
	mux.HandleFunc("/api/ca/rotate", apiCARotate)           // POST — force CA rotation

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
	mux.HandleFunc("/api/upstream", apiUpstream)              // GET list / POST add
	mux.HandleFunc("/api/upstream/settings", apiUpstreamSettings) // GET/PUT circuit breaker
	mux.HandleFunc("/api/upstream/health", apiUpstreamHealth)     // POST force health check

	// ── Cluster / multi-node ─────────────────────────────────────────────
	mux.HandleFunc("/api/cluster/status", apiClusterStatus)   // GET this node + connected nodes
	mux.HandleFunc("/api/cluster/mode", apiClusterMode)       // POST enable control-plane mode
	mux.HandleFunc("/api/cluster/tokens", apiClusterTokens)   // GET list / POST create / DELETE remove
	mux.HandleFunc("/api/cluster/nodes", apiClusterNodes)       // GET enrolled nodes
	mux.HandleFunc("/api/cluster/revoke", apiClusterRevoke)     // POST revoke a node
	mux.HandleFunc("/api/cluster/labels", apiClusterLabels)           // POST set node labels
	mux.HandleFunc("/api/cluster/node-groups", apiNodeGroups)        // GET list / POST create / DELETE remove
	mux.HandleFunc("/api/cluster/node-groups/membership", apiNodeGroupMembership) // GET group membership (F9)
	mux.HandleFunc("/api/cluster/drain", apiClusterDrain)       // POST toggle node drain mode
	mux.HandleFunc("/api/cluster/metrics", apiClusterMetrics)   // GET aggregated cluster metrics
	mux.HandleFunc("/api/cluster/ca", apiClusterCA)                   // GET info / POST import cluster CA
	mux.HandleFunc("/api/cluster/rate-limits", apiClusterRateLimits)   // GET distributed RL status
	mux.HandleFunc("/api/cluster/audit", apiClusterAudit)             // GET centralized audit log
	mux.HandleFunc("/api/cluster/revocations", apiClusterRevocations) // GET revocation sync status
	mux.HandleFunc("/api/cluster/rotation", apiClusterRotation)       // GET CA rotation progress
	mux.HandleFunc("/api/cluster/ha", apiClusterHA)                   // GET HA status
	mux.HandleFunc("/api/cluster/bandwidth", apiBandwidthPolicies)   // GET/POST/DELETE bandwidth QoS policies
	mux.HandleFunc("/api/cluster/bootstrap/", apiBootstrapRouter)    // GET bootstrap script/compose (token-authed)
	mux.HandleFunc("/healthz", apiHealthz)                            // GET unauthenticated health check (LB probe)

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

// uiAllowedNets is the optional allowlist for admin panel access.
// Empty = allow from any IP. Populated via -ui-allow-ip flag or /api/ui-allow-ips.
var (
	uiAllowedNetsMu sync.RWMutex
	uiAllowedNets   []*net.IPNet
)

// AddUIAllowedCIDR adds a CIDR to the UI access allowlist.
func AddUIAllowedCIDR(cidr string) error {
	_, n, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		// Try as bare IP.
		ip := net.ParseIP(strings.TrimSpace(cidr))
		if ip == nil {
			return fmt.Errorf("invalid IP/CIDR: %s", cidr)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		n = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
	}
	uiAllowedNetsMu.Lock()
	uiAllowedNets = append(uiAllowedNets, n)
	uiAllowedNetsMu.Unlock()
	return nil
}

// SetUIAllowedCIDRs replaces the full allowlist.
func SetUIAllowedCIDRs(cidrs []string) error {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			ip := net.ParseIP(c)
			if ip == nil {
				return fmt.Errorf("invalid IP/CIDR: %s", c)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			n = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
		}
		nets = append(nets, n)
	}
	uiAllowedNetsMu.Lock()
	uiAllowedNets = nets
	uiAllowedNetsMu.Unlock()
	return nil
}

// ListUIAllowedCIDRs returns the current allowlist as strings.
func ListUIAllowedCIDRs() []string {
	uiAllowedNetsMu.RLock()
	defer uiAllowedNetsMu.RUnlock()
	out := make([]string, len(uiAllowedNets))
	for i, n := range uiAllowedNets {
		out[i] = n.String()
	}
	return out
}

// uiIPGuardMiddleware blocks requests from IPs not in uiAllowedNets.
// When the allowlist is empty all IPs are permitted (default behaviour).
func uiIPGuardMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uiAllowedNetsMu.RLock()
		allowed := uiAllowedNets
		uiAllowedNetsMu.RUnlock()
		if len(allowed) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		ip := net.ParseIP(host)
		for _, cidr := range allowed {
			if ip != nil && cidr.Contains(ip) {
				next.ServeHTTP(w, r)
				return
			}
		}
		http.Error(w, "Forbidden: admin panel access restricted by IP", http.StatusForbidden)
	})
}

// securityMiddleware sets restrictive CORS and security headers.
// CSRF protection is based on same-origin check (Origin == Host), not
// localhost-only, so the UI works from any IP the admin uses.
func securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// ── Security headers ─────────────────────────────────────────────────
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; frame-ancestors 'none'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://flagcdn.com; connect-src 'self'")

		// ── CORS: allow same-origin requests (reflect the origin back) ───────
		origin := r.Header.Get("Origin")
		if origin != "" && isSameOrigin(r, origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Access-Control-Max-Age", "86400")
			w.Header().Set("Vary", "Origin")
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// ── CSRF: reject state-changing requests from a foreign origin ────────
		// Browsers send Origin on cross-site requests; if it's present and
		// doesn't match our Host header it's a cross-site forgery attempt.
		// Requests without Origin (curl, API clients) are allowed through.
		isMutating := r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete
		if origin != "" && !isSameOrigin(r, origin) && isMutating {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// ── Body size limit on mutating requests ─────────────────────────────
		if isMutating {
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MiB
		}

		// ── API rate limit on mutating requests ──────────────────────────────
		if isMutating && strings.HasPrefix(r.URL.Path, "/api/") {
			ip, _, _ := net.SplitHostPort(r.RemoteAddr)
			if ip == "" {
				ip = r.RemoteAddr
			}
			if !apiLimiter.Allow(ip) {
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// isSameOrigin returns true when the Origin header matches the request's Host.
// This is the correct CSRF protection for single-origin admin UIs: any IP is
// fine as long as the request comes from the same scheme+host+port as the UI.
// When Culvert sits behind a reverse proxy, X-Forwarded-Host carries the
// original Host header — we accept that as an alternative match target.
func isSameOrigin(r *http.Request, origin string) bool {
	if origin == "" {
		return true // no Origin = direct tool access — not a browser cross-site request
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	originHost := u.Host
	if strings.EqualFold(originHost, r.Host) {
		return true
	}
	// Behind a reverse proxy the original Host is forwarded as X-Forwarded-Host.
	if fwd := r.Header.Get("X-Forwarded-Host"); fwd != "" && strings.EqualFold(originHost, fwd) {
		return true
	}
	return false
}

// uiRoleKey is the context key used to propagate the authenticated UI role.
type uiRoleKey struct{}

// uiRole extracts the UI role injected by uiAuthMiddleware.
// Returns RoleViewer when no role is in context (safe default).
func uiRole(r *http.Request) UIRole {
	if role, ok := r.Context().Value(uiRoleKey{}).(UIRole); ok && role != "" {
		return role
	}
	return RoleViewer
}

// sessionAdmin returns the authenticated admin username from the session cookie.
// Falls back to "unknown" if no session is found.
func sessionAdmin(r *http.Request) string {
	sess, err := readSessionCookie(r)
	if err != nil || sess == nil {
		return "unknown"
	}
	if sess.Sub != "" {
		return sess.Sub
	}
	if sess.Email != "" {
		return sess.Email
	}
	return "unknown"
}

// requireRole returns true when the current session has at least minRole.
// Writes HTTP 403 and returns false when the check fails.
func requireRole(w http.ResponseWriter, r *http.Request, minRole UIRole) bool {
	if uiRole(r).HasRole(minRole) {
		return true
	}
	http.Error(w, "Forbidden: insufficient role", http.StatusForbidden)
	return false
}

// uiAuthMiddleware gates /api/ endpoints with session-cookie auth and injects
// the authenticated user's UIRole into the request context for RBAC checks.
// Static assets (/) and bootstrap + auth endpoints are always public.
// HTTP Basic Auth is accepted as a fallback for CLI / API clients.
func uiAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always public: setup bootstrap, specific auth endpoints (login/logout/status),
		// IdP callbacks, and /proxy.pac (Windows clients need it without credentials).
		// NOTE: /api/auth/users is intentionally NOT in this list — it requires admin role.
		if strings.HasPrefix(r.URL.Path, "/api/setup") ||
			r.URL.Path == "/api/auth/login" ||
			r.URL.Path == "/api/auth/logout" ||
			r.URL.Path == "/api/auth/status" ||
			strings.HasPrefix(r.URL.Path, "/api/auth/totp") ||
			strings.HasPrefix(r.URL.Path, "/auth/") ||
			r.URL.Path == "/proxy.pac" {
			next.ServeHTTP(w, r)
			return
		}
		// Auth not yet configured — first-time or intentionally disabled.
		if !cfg.AuthEnabled() {
			ctx := context.WithValue(r.Context(), uiRoleKey{}, RoleAdmin)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		// Gate only /api/ endpoints; static assets are always public.
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		// Check session cookie (browser login via login overlay).
		sess, err := readUISessionCookie(r)
		if err == nil && sess != nil {
			// Reject sessions for deleted users (Finding 5.2).
			if sess.Provider == "local" && !cfg.UIUserExists(sess.Sub) {
				clearUISessionCookie(w, r)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			role := UIRole(sess.Role)
			if !role.HasRole(RoleViewer) {
				role = RoleAdmin // backwards compat: sessions without role = admin
			}
			ctx := context.WithValue(r.Context(), uiRoleKey{}, role)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		// Fallback: HTTP Basic Auth for programmatic / CLI access.
		user, pass, ok := r.BasicAuth()
		if ok {
			if role, valid := cfg.VerifyUIUser(user, pass); valid {
				ctx := context.WithValue(r.Context(), uiRoleKey{}, role)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}
		// No valid auth — 401 without WWW-Authenticate: Basic so the browser
		// does NOT show its native credential dialog.
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}

// ── UI admin session cookie ───────────────────────────────────────────────
// Separate from the proxy-user ps_session cookie; same HMAC encoding.

const uiSessionCookieName = "ps_ui_session"

func isSecureRequest(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}

func setUISessionCookie(w http.ResponseWriter, r *http.Request, username string, role UIRole) error {
	s := &Session{
		Sub:      username,
		Provider: "local",
		Role:     string(role),
		Exp:      time.Now().Add(getSessionTTL()).Unix(),
	}
	value, err := encodeSession(s)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure is set dynamically via isSecureRequest; HttpOnly+SameSiteStrict+HMAC-signed value are in place
		Name:     uiSessionCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   int(getSessionTTL().Seconds()),
		HttpOnly: true,
		Secure:   isSecureRequest(r),
		SameSite: http.SameSiteStrictMode,
	})
	return nil
}

func readUISessionCookie(r *http.Request) (*Session, error) {
	c, err := r.Cookie(uiSessionCookieName)
	if err == http.ErrNoCookie {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return decodeSession(c.Value)
}

func clearUISessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure is set dynamically via isSecureRequest; HttpOnly+SameSiteStrict are in place
		Name:     uiSessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isSecureRequest(r),
		SameSite: http.SameSiteStrictMode,
	})
}

// POST /api/auth/login — validate admin credentials, set session cookie.
// When TOTP is enrolled for the user, a first-pass response of {"totp_required":true}
// is returned (HTTP 200, no cookie); the client must re-POST with the totp field set.
func apiAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		User string `json:"user"`
		Pass string `json:"pass"`
		TOTP string `json:"totp"` // 6-digit code or backup code; empty on first step
	}
	if err := decodeJSON(r, &body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	// Account lockout check — before any credential verification.
	if locked, secs := loginLimiter.Check(body.User); locked {
		auditEvent(r, "auth.lockout", body.User, fmt.Sprintf("blocked — %ds remaining", secs))
		go fireAlert("auth_lockout", AlertPayload{
			Actor:  body.User,
			Detail: fmt.Sprintf("account locked for %ds", secs),
			Source: "auth",
		})
		http.Error(w, LockoutMsg(secs), http.StatusTooManyRequests)
		return
	}

	role, ok := cfg.VerifyUIUser(body.User, body.Pass)
	if !cfg.AuthEnabled() {
		role, ok = RoleAdmin, true
	}
	if ok {
		// Credentials valid — check TOTP if enrolled.
		if cfg.UserHasTOTP(body.User) {
			if body.TOTP == "" {
				// First step: tell the client TOTP is required (no session yet).
				jsonOK(w, map[string]any{"totp_required": true})
				return
			}
			secret := cfg.GetTOTPSecret(body.User)
			if !verifyTOTP(secret, body.TOTP) {
				// Try backup codes.
				if !cfg.ConsumeBackupCode(body.User, body.TOTP) {
					cfg.SaveUIUsersFile() //nolint:errcheck — best-effort persist
					time.Sleep(300 * time.Millisecond)
					http.Error(w, "Invalid TOTP code", http.StatusUnauthorized)
					return
				}
				// Backup code consumed — persist removal.
				cfg.SaveUIUsersFile() //nolint:errcheck
			}
		}
		loginLimiter.RecordSuccess(body.User)
		// Clear any pre-existing session cookie before issuing a new one
		// to prevent session fixation attacks (defense-in-depth).
		clearUISessionCookie(w, r)
		if err := setUISessionCookie(w, r, body.User, role); err != nil {
			http.Error(w, "session error", http.StatusInternalServerError)
			return
		}
		auditEvent(r, "auth.login", body.User, fmt.Sprintf("admin UI login role=%s", role))
		jsonOK(w, map[string]any{"ok": true, "user": body.User, "role": role})
		return
	}
	nowLocked := loginLimiter.RecordFailure(body.User)
	auditEvent(r, "auth.login.fail", body.User,
		fmt.Sprintf("invalid credentials, locked=%v, attempts_left=%d",
			nowLocked, loginLimiter.AttemptsLeft(body.User)))
	time.Sleep(300 * time.Millisecond) // slow down brute-force
	if nowLocked {
		_, secs := loginLimiter.Check(body.User)
		http.Error(w, LockoutMsg(secs), http.StatusTooManyRequests)
		return
	}
	http.Error(w, "Invalid credentials", http.StatusUnauthorized)
}

// GET /api/auth/status — return whether the current request has a valid session.
func apiAuthStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !cfg.AuthEnabled() {
		jsonOK(w, map[string]any{"loggedIn": true, "user": "", "role": RoleAdmin})
		return
	}
	sess, err := readUISessionCookie(r)
	if err == nil && sess != nil {
		role := UIRole(sess.Role)
		if !role.HasRole(RoleViewer) {
			role = RoleAdmin
		}
		jsonOK(w, map[string]any{"loggedIn": true, "user": sess.Sub, "role": role})
		return
	}
	// Accept Basic Auth header for CLI/API callers.
	user, pass, ok := r.BasicAuth()
	if ok {
		if role, valid := cfg.VerifyUIUser(user, pass); valid {
			jsonOK(w, map[string]any{"loggedIn": true, "user": user, "role": role})
			return
		}
	}
	jsonOK(w, map[string]any{"loggedIn": false})
}

// POST /api/auth/logout — clear the admin session cookie.
func apiAuthLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sess, _ := readUISessionCookie(r)
	if sess != nil {
		auditEvent(r, "auth.logout", sess.Sub, "admin UI logout")
	}
	// Revoke the session token so it cannot be reused even if the cookie is
	// replayed before it naturally expires.
	revokeSessionCookie(uiSessionCookieName, r)
	clearUISessionCookie(w, r)
	jsonOK(w, map[string]any{"ok": true})
}

// GET/POST/DELETE /api/auth/users — RBAC user management (admin only).
//
//	GET    → list all UI admin users (without passwords)
//	POST   → create or update a user: {"username":"…","password":"…","role":"admin|operator|viewer"}
//	DELETE → remove a user: ?username=…
func apiAuthUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		jsonOK(w, map[string]any{"users": cfg.ListUIUsers()})

	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Role     string `json:"role"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		body.Username = strings.TrimSpace(body.Username)
		if len(body.Username) < 1 || len(body.Username) > 64 {
			http.Error(w, "username must be 1-64 characters", http.StatusBadRequest)
			return
		}
		if body.Password != "" && len(body.Password) < 8 {
			http.Error(w, "password must be at least 8 characters", http.StatusBadRequest)
			return
		}
		role := UIRole(body.Role)
		if !role.HasRole(RoleViewer) {
			http.Error(w, "role must be admin, operator, or viewer", http.StatusBadRequest)
			return
		}
		if err := cfg.SetUIUser(body.Username, body.Password, role); err != nil {
			http.Error(w, "internal error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if err := cfg.SaveUIUsersFile(); err != nil {
			logger.Printf("UIUsers: failed to persist: %v", err)
		}
		auditEvent(r, "auth.users.set", body.Username, fmt.Sprintf("role=%s", role))
		jsonOK(w, map[string]any{"ok": true})

	case http.MethodDelete:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		username := strings.TrimSpace(r.URL.Query().Get("username"))
		if username == "" {
			http.Error(w, "missing username param", http.StatusBadRequest)
			return
		}
		if err := cfg.DeleteUIUser(username); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		if err := cfg.SaveUIUsersFile(); err != nil {
			logger.Printf("UIUsers: failed to persist: %v", err)
		}
		// Revoke all active sessions for the deleted user (Finding 5.2).
		sessionRevoked.RevokeUser(username)
		auditEvent(r, "auth.users.delete", username, "")
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// POST /api/auth/change-password — self-service password change for any authenticated user.
// Body: {"current_password": "...", "new_password": "..."}
// Verifies the current password before accepting the change.
func apiAuthChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	username := sessionAdmin(r)
	if username == "" || username == "unknown" {
		http.Error(w, "Unauthorized: no valid session", http.StatusUnauthorized)
		return
	}
	var body struct {
		CurrentPass string `json:"current_password"`
		NewPass     string `json:"new_password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if body.CurrentPass == "" || body.NewPass == "" {
		http.Error(w, "current_password and new_password are required", http.StatusBadRequest)
		return
	}
	// Verify current password.
	if _, ok := cfg.VerifyUIUser(username, body.CurrentPass); !ok {
		http.Error(w, "current password is incorrect", http.StatusForbidden)
		return
	}
	if len(body.NewPass) < 8 {
		http.Error(w, "password must be at least 8 characters", http.StatusBadRequest)
		return
	}
	// Preserve existing role when changing password.
	users := cfg.ListUIUsers()
	var role UIRole
	for _, u := range users {
		if u.Username == username {
			role = u.Role
			break
		}
	}
	if role == "" {
		role = RoleAdmin // legacy single-user fallback
	}
	if err := cfg.SetUIUser(username, body.NewPass, role); err != nil {
		http.Error(w, "internal error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := cfg.SaveUIUsersFile(); err != nil {
		logger.Printf("UIUsers: failed to persist after password change: %v", err)
	}
	auditEvent(r, "auth.password_change", username, "self-service password change")
	saveConfigVersion(sessionAdmin(r), "auth.password_change")
	jsonOK(w, map[string]any{"ok": true})
}

// GET /api/setup/status — reports whether first-time setup is still needed.
// Always public so the browser can decide whether to show the setup wizard.
func apiSetupStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	jsonOK(w, map[string]any{"needsSetup": !cfg.AuthEnabled()})
}

// POST /api/setup/complete — sets the initial admin credential or enables unauth mode.
// Only callable once; returns 403 if auth is already configured.
// Body (with credentials): {"user": "...", "pass": "..."}
// Body (open/unauth mode):  {"unauth": true}
// Password must be at least 8 characters to enforce minimum hygiene.
func apiSetupComplete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// S4: Rate-limit setup endpoint to prevent brute-force race during initial setup window.
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip == "" {
		ip = r.RemoteAddr
	}
	setupKey := "setup:" + ip
	if locked, secs := loginLimiter.Check(setupKey); locked {
		http.Error(w, fmt.Sprintf("too many attempts, locked for %ds", secs), http.StatusTooManyRequests)
		return
	}
	if cfg.AuthEnabled() {
		http.Error(w, "setup already complete", http.StatusForbidden)
		return
	}
	var body struct {
		User   string `json:"user"`
		Pass   string `json:"pass"`
		Unauth bool   `json:"unauth"`
	}
	if err := decodeJSON(r, &body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	// Unauth (open proxy) mode — skip credential requirements.
	if body.Unauth {
		cfg.SetUnauthMode(true)
		auditEvent(r, "setup.complete", "system", "unauth mode enabled — proxy requires no credentials")
		jsonOK(w, map[string]any{"ok": true, "unauth": true})
		return
	}

	body.User = strings.TrimSpace(body.User)
	if len(body.User) < 1 || len(body.User) > 64 {
		loginLimiter.RecordFailure(setupKey)
		http.Error(w, "username must be 1-64 characters", http.StatusBadRequest)
		return
	}
	if len(body.Pass) < 8 {
		loginLimiter.RecordFailure(setupKey)
		http.Error(w, "password must be at least 8 characters", http.StatusBadRequest)
		return
	}
	if err := cfg.SetAuth(body.User, body.Pass); err != nil {
		http.Error(w, "internal error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := cfg.SaveUIUsersFile(); err != nil {
		logger.Printf("UIUsers: failed to persist: %v", err)
	}
	// Auto-login after setup so the user lands directly in the dashboard.
	_ = setUISessionCookie(w, r, body.User, RoleAdmin)
	auditEvent(r, "setup.complete", body.User, "first-time admin password configured")
	logger.Printf("First-time setup: admin user %q created", body.User)
	jsonOK(w, map[string]any{"ok": true})
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

// GET /api/audit — return configuration-change audit entries (newest first).
// Supports pagination via ?offset=N&limit=M (default: offset=0, limit=500).
// Supports date filtering via ?from=UNIX_MS&to=UNIX_MS.
// Use ?source=file to read from the persistent JSONL audit log file instead of
// the in-memory ring buffer (default: memory for backwards compat) (Finding 6.2).
func apiAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	q := r.URL.Query()
	offset, _ := strconv.Atoi(q.Get("offset"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	fromTS, _ := strconv.ParseInt(q.Get("from"), 10, 64)
	toTS, _ := strconv.ParseInt(q.Get("to"), 10, 64)
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 || limit > 10000 {
		limit = 500
	}
	var entries []AuditEntry
	var total int
	if q.Get("source") == "file" {
		entries, total = auditGetPersistent(offset, limit, fromTS, toTS)
	} else {
		entries, total = auditGetMemory(offset, limit, fromTS, toTS)
	}
	jsonOK(w, map[string]any{"entries": entries, "count": len(entries), "total": total, "offset": offset, "limit": limit})
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

// GET /api/stats
func apiStats(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleViewer) {
		return
	}
	total := atomic.LoadInt64(&statTotal)
	blocked := atomic.LoadInt64(&statBlocked)
	authFail := atomic.LoadInt64(&statAuthFail)
	allowed := total - blocked - authFail
	if allowed < 0 {
		allowed = 0
	}
	jsonOK(w, map[string]any{
		"total":       total,
		"allowed":     allowed,
		"blocked":     blocked,
		"authFail":    authFail,
		"blocklistSz": bl.Count(),
		"uptime":      uptime(),
		"proxyPort":   cfg.ProxyPort,
		"uiPort":      cfg.UIPort,
		"authEnabled": cfg.AuthEnabled(),
		"serverTime":  time.Now().Format("2006-01-02 15:04:05"),
	})
}

// GET /api/dashboard/health — System health data
func apiDashboardHealth(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleViewer) {
		return
	}
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	jsonOK(w, map[string]any{
		"memAllocMB":    float64(mem.Alloc) / 1024 / 1024,
		"memSysMB":      float64(mem.Sys) / 1024 / 1024,
		"goroutines":    runtime.NumGoroutine(),
		"numGC":         mem.NumGC,
		"sseClients":    hub.ClientCount(),
		"blocklistSize": bl.Count(),
	})
}

// GET /api/dashboard/threats — Threat engine breakdown
func apiDashboardThreats(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleViewer) {
		return
	}
	jsonOK(w, map[string]any{
		"clamav":     atomic.LoadInt64(&statClamBlocked),
		"yara":       atomic.LoadInt64(&statYARABlocked),
		"dpi":        atomic.LoadInt64(&statDPIBlocked),
		"threatFeed": atomic.LoadInt64(&statThreatFeedBlocked),
	})
}

// GET /api/dashboard/top-rules — Top policy rules by hit count
func apiDashboardTopRules(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleViewer) {
		return
	}
	rules := policyStore.List()
	// Sort by HitCount descending, take top 10
	sort.Slice(rules, func(i, j int) bool { return rules[i].HitCount > rules[j].HitCount })
	if len(rules) > 10 {
		rules = rules[:10]
	}
	type ruleHit struct {
		Name   string `json:"name"`
		Action string `json:"action"`
		Hits   int64  `json:"hits"`
	}
	result := make([]ruleHit, 0, len(rules))
	for i := range rules {
		if rules[i].HitCount > 0 {
			name := rules[i].Name
			if name == "" {
				name = fmt.Sprintf("Rule #%d", rules[i].Priority)
			}
			result = append(result, ruleHit{Name: name, Action: string(rules[i].Action), Hits: rules[i].HitCount})
		}
	}
	jsonOK(w, map[string]any{"rules": result})
}

// GET /api/timeseries
func apiTimeseries(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleViewer) {
		return
	}
	total, allowed, blocked := tsGet()
	jsonOK(w, map[string]any{"data": total, "allowed": allowed, "blocked": blocked})
}

// GET /api/logs?filter=...&status=...&level=...&method=...&from=...&to=...
// from/to accept Unix timestamps (seconds) or ISO 8601 (RFC 3339) strings.
func apiLogs(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleViewer) {
		return
	}
	all := logGet()
	filterHost := strings.ToLower(r.URL.Query().Get("filter"))
	filterStatus := strings.ToUpper(r.URL.Query().Get("status"))
	filterLevel := strings.ToUpper(r.URL.Query().Get("level"))
	filterMethod := strings.ToUpper(r.URL.Query().Get("method"))
	filterIdentity := strings.ToLower(r.URL.Query().Get("identity"))

	// Date range filtering (Finding 6.3).
	fromTS, fromErr := parseTimestampParam(r.URL.Query().Get("from"))
	toTS, toErr := parseTimestampParam(r.URL.Query().Get("to"))
	if fromErr != nil {
		http.Error(w, "invalid 'from' parameter: use Unix timestamp or ISO 8601", http.StatusBadRequest)
		return
	}
	if toErr != nil {
		http.Error(w, "invalid 'to' parameter: use Unix timestamp or ISO 8601", http.StatusBadRequest)
		return
	}

	filtered := all[:0:0]
	for _, e := range all {
		if fromTS != 0 && e.TS < fromTS {
			continue
		}
		if toTS != 0 && e.TS > toTS {
			continue
		}
		if filterHost != "" && !strings.Contains(strings.ToLower(e.Host), filterHost) &&
			!strings.Contains(strings.ToLower(e.IP), filterHost) {
			continue
		}
		if filterStatus != "" && e.Status != filterStatus {
			continue
		}
		if filterLevel != "" && e.Level != filterLevel {
			continue
		}
		if filterMethod != "" && e.Method != filterMethod {
			continue
		}
		if filterIdentity != "" && !strings.Contains(strings.ToLower(e.Identity), filterIdentity) {
			continue
		}
		filtered = append(filtered, e)
	}
	jsonOK(w, map[string]any{"logs": filtered, "total": len(filtered)})
}

// parseTimestampParam parses a timestamp string that is either a Unix timestamp
// (integer seconds) or an ISO 8601 / RFC 3339 datetime string.
// Returns (0, nil) for empty input, (unix, nil) on success, or (0, err) on failure.
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

// GET /api/top-hosts?n=20
func apiTopHosts(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleViewer) {
		return
	}
	n := 20
	if s := r.URL.Query().Get("n"); s != "" {
		if v, err := fmt.Sscanf(s, "%d", &n); v == 0 || err != nil {
			n = 20
		}
	}
	if n <= 0 || n > 100 {
		n = 20
	}
	jsonOK(w, map[string]any{"hosts": topHosts.Top(n)})
}

// GET/POST/DELETE /api/blocklist
func apiBlocklist(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		entries := bl.ListWithSource()
		// Sort by host for stable output.
		sort.Slice(entries, func(i, j int) bool { return entries[i].Host < entries[j].Host })

		// Optional filters: ?q=keyword&source=manual|feed&limit=N&offset=N
		q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
		sourceFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("source")))
		limitStr := r.URL.Query().Get("limit")
		offsetStr := r.URL.Query().Get("offset")

		// Apply filters.
		filtered := entries
		if q != "" || sourceFilter != "" {
			filtered = make([]BlocklistEntry, 0, 64)
			for _, e := range entries {
				if q != "" && !strings.Contains(e.Host, q) {
					continue
				}
				if sourceFilter != "" && e.Source != sourceFilter {
					continue
				}
				filtered = append(filtered, e)
			}
		}
		total := len(filtered)

		// Apply offset.
		offset := 0
		if offsetStr != "" {
			if v, err := strconv.Atoi(offsetStr); err == nil && v > 0 {
				offset = v
			}
		}
		if offset > total {
			offset = total
		}
		filtered = filtered[offset:]

		// Apply limit (default: all, for backward-compat with export/import).
		limit := total
		if limitStr != "" {
			if v, err := strconv.Atoi(limitStr); err == nil && v > 0 && v < limit {
				limit = v
			}
		}

		jsonOK(w, map[string]any{
			"entries": filtered[:limit],
			"count":   total,
			"offset":  offset,
			"limit":   limit,
		})

	case http.MethodPost:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		var body struct {
			Hosts []string `json:"hosts"` // support bulk add
			Host  string   `json:"host"`  // single add
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		added := 0
		if body.Host != "" {
			body.Hosts = append(body.Hosts, body.Host)
		}
		for _, h := range body.Hosts {
			h = strings.TrimSpace(h)
			if h == "" {
				continue
			}
			if len(h) > 253 {
				logger.Printf("UI: blocklist entry too long, skipped: %q…", sanitizeLog(h[:50]))
				continue
			}
			// Validate wildcard patterns (Finding 1.3).
			if strings.Contains(h, "*") {
				if !isValidBlocklistWildcard(h) {
					http.Error(w, fmt.Sprintf("invalid wildcard pattern %q: only *.example.com format is allowed", sanitizeLog(h)), http.StatusBadRequest)
					return
				}
			}
			bl.AddManual(h)
			logger.Printf("UI: blocked %q", sanitizeLog(h))
			added++
		}
		bl.Save()
		auditEvent(r, "blocklist.add", fmt.Sprintf("%d host(s)", added), strings.Join(body.Hosts, ", "))
		saveConfigVersion(sessionAdmin(r), "blocklist.add")
		jsonOK(w, map[string]any{"added": added})

	case http.MethodDelete:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		host := strings.TrimSpace(r.URL.Query().Get("host"))
		// F19: support bulk delete via JSON body with hosts array.
		if host == "" {
			var body struct {
				Hosts []string `json:"hosts"`
			}
			if err := decodeJSON(r, &body); err == nil && len(body.Hosts) > 0 {
				removed := 0
				for _, h := range body.Hosts {
					h = strings.TrimSpace(h)
					if h == "" {
						continue
					}
					bl.Remove(h)
					removed++
				}
				bl.Save()
				logger.Printf("UI: bulk unblocked %d host(s)", removed)
				auditEvent(r, "blocklist.bulk_remove", fmt.Sprintf("%d host(s)", removed), "")
				saveConfigVersion(sessionAdmin(r), "blocklist.bulk_remove")
				jsonOK(w, map[string]any{"removed": removed})
				return
			}
			http.Error(w, "missing host param or hosts body", http.StatusBadRequest)
			return
		}
		bl.Remove(host)
		bl.Save()
		logger.Printf("UI: unblocked %q", sanitizeLog(host))
		auditEvent(r, "blocklist.remove", host, "")
		saveConfigVersion(sessionAdmin(r), "blocklist.remove")
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// GET/POST /api/blocklist/mode — switch between "block" and "allow" modes.
func apiBlocklistMode(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		jsonOK(w, map[string]string{"mode": bl.Mode()})

	case http.MethodPost:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		var body struct {
			Mode string `json:"mode"` // "block" or "allow"
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if body.Mode != "block" && body.Mode != "allow" {
			http.Error(w, `mode must be "block" or "allow"`, http.StatusBadRequest)
			return
		}
		bl.SetMode(body.Mode)
		auditEvent(r, "blocklist.mode", body.Mode, "")
		jsonOK(w, map[string]string{"mode": bl.Mode()})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ── Blocklist Feed ─────────────────────────────────────────────────────────

// GET  /api/blocklist/feed  → current feed config + status
// POST /api/blocklist/feed  → update feed URL and interval
func apiBlocklistFeed(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		url, lastSync, count, interval := blFeedSyncer.Stats()
		lastSyncStr := ""
		if !lastSync.IsZero() {
			lastSyncStr = lastSync.UTC().Format(time.RFC3339)
		}
		jsonOK(w, map[string]any{
			"url":            url,
			"interval":       interval.String(),
			"last_sync":      lastSyncStr,
			"imported_count": count,
		})

	case http.MethodPost:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		var body struct {
			URL      string `json:"url"`
			Interval string `json:"interval"` // e.g. "24h"
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if body.URL != "" && !strings.HasPrefix(body.URL, "http://") && !strings.HasPrefix(body.URL, "https://") {
			http.Error(w, "feed URL must use http:// or https://", http.StatusBadRequest)
			return
		}
		// SSRF guard: reject URLs pointing at private/loopback addresses.
		if body.URL != "" {
			u, err := url.Parse(body.URL)
			if err != nil {
				http.Error(w, "invalid feed URL", http.StatusBadRequest)
				return
			}
			host := u.Hostname()
			if err := isPrivateHost(host); err != nil {
				http.Error(w, "feed URL must not point to private/loopback addresses", http.StatusBadRequest)
				return
			}
		}
		var interval time.Duration
		if body.Interval == "" || body.Interval == "off" {
			interval = 0 // disabled
		} else if d, err := time.ParseDuration(body.Interval); err == nil && d > 0 {
			interval = d
		} else {
			interval = blFeedDefaultInterval
		}
		blFeedSyncer.SetFeed(body.URL, interval)
		auditEvent(r, "blocklist.feed.set", body.URL, "")
		jsonOK(w, map[string]any{"ok": true, "url": body.URL, "interval": interval.String()})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// POST /api/blocklist/feed/sync → trigger immediate sync
func apiBlocklistFeedSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleOperator) {
		return
	}
	go blFeedSyncer.Sync()
	auditEvent(r, "blocklist.feed.sync", "", "")
	jsonOK(w, map[string]any{"ok": true})
}

// GET /api/blocklist/exceptions        → list all exception hosts
// POST /api/blocklist/exceptions       → add exception(s)  body: {host} or {hosts:[]}
// DELETE /api/blocklist/exceptions?host=X → remove one exception
func apiBlocklistExceptions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		hosts := bl.ListExceptions()
		jsonOK(w, map[string]any{"hosts": hosts, "count": len(hosts)})

	case http.MethodPost:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		var body struct {
			Host  string   `json:"host"`
			Hosts []string `json:"hosts"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if body.Host != "" {
			body.Hosts = append(body.Hosts, body.Host)
		}
		added := 0
		for _, h := range body.Hosts {
			h = strings.TrimSpace(h)
			if h == "" {
				continue
			}
			if len(h) > 253 {
				logger.Printf("UI: exception entry too long, skipped: %q…", sanitizeLog(h[:50]))
				continue
			}
			bl.AddException(h)
			logger.Printf("UI: blocklist exception added %q", sanitizeLog(h))
			added++
		}
		auditEvent(r, "blocklist.exception.add", fmt.Sprintf("%d host(s)", added), strings.Join(body.Hosts, ", "))
		jsonOK(w, map[string]any{"ok": true, "added": added})

	case http.MethodDelete:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		host := strings.TrimSpace(r.URL.Query().Get("host"))
		if host == "" {
			http.Error(w, "host required", http.StatusBadRequest)
			return
		}
		bl.RemoveException(host)
		logger.Printf("UI: blocklist exception removed %q", sanitizeLog(host))
		auditEvent(r, "blocklist.exception.remove", host, "")
		jsonOK(w, map[string]any{"ok": true})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ── Alert Webhooks ─────────────────────────────────────────────────────────

// GET  /api/alerts/webhooks      → list webhooks (secrets redacted)
// POST /api/alerts/webhooks      → create webhook
// PUT  /api/alerts/webhooks?id=X → update webhook
// DELETE /api/alerts/webhooks?id=X → delete webhook
func apiAlertsWebhooks(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		jsonOK(w, map[string]any{"webhooks": globalAlertStore.List()})

	case http.MethodPost:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		var h AlertWebhook
		if err := decodeJSON(r, &h); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if h.URL == "" {
			http.Error(w, "url required", http.StatusBadRequest)
			return
		}
		if err := validateWebhookURL(h.URL); err != nil {
			http.Error(w, "invalid webhook URL: "+err.Error(), http.StatusBadRequest)
			return
		}
		h.Enabled = true
		created := globalAlertStore.Add(h)
		auditEvent(r, "alert.webhook.create", created.ID, h.URL)
		jsonOK(w, created)

	case http.MethodPut:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "id required", http.StatusBadRequest)
			return
		}
		var h AlertWebhook
		if err := decodeJSON(r, &h); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if h.URL != "" {
			if err := validateWebhookURL(h.URL); err != nil {
				http.Error(w, "invalid webhook URL: "+err.Error(), http.StatusBadRequest)
				return
			}
		}
		if !globalAlertStore.Update(id, h) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		auditEvent(r, "alert.webhook.update", id, "")
		jsonOK(w, map[string]any{"ok": true})

	case http.MethodDelete:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "id required", http.StatusBadRequest)
			return
		}
		if !globalAlertStore.Delete(id) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		auditEvent(r, "alert.webhook.delete", id, "")
		jsonOK(w, map[string]any{"ok": true})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// POST /api/alerts/webhooks/test?id=X → fire a test payload to the webhook
func apiAlertsWebhookTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleOperator) {
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}
	h, ok := globalAlertStore.GetByID(id)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	// Finding 8.2: deliver synchronously so the UI gets actual result feedback.
	payload := AlertPayload{
		Event:     "test",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Actor:     "culvert",
		Host:      "test",
		Detail:    "This is a test alert from Culvert",
		Source:    "test",
	}
	ok2 := deliverWebhook(globalAlertStore, h, payload)
	jsonOK(w, map[string]any{"ok": ok2, "delivered": ok2})
}

// GET /api/alerts/webhooks/history — delivery history (Finding 8.1).
func apiAlertsDeliveryHist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	jsonOK(w, map[string]any{"deliveries": globalAlertStore.DeliveryHistory()})
}

// ── URL Categories ─────────────────────────────────────────────────────────

// GET/POST/PUT/DELETE /api/urlcat
func apiURLCat(w http.ResponseWriter, r *http.Request) { //nolint:cyclop,funlen // CRUD handler: one branch per HTTP method is intentional
	switch r.Method {
	case http.MethodGet:
		jsonOK(w, catStore.All())

	case http.MethodPost:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		var body struct {
			Name  string   `json:"name"`
			Hosts []string `json:"hosts"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if body.Name == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
			return
		}
		if len(body.Name) > 256 {
			http.Error(w, "name must be 256 characters or fewer", http.StatusBadRequest)
			return
		}
		if len(body.Hosts) > 10000 {
			http.Error(w, "category cannot contain more than 10000 hosts", http.StatusBadRequest)
			return
		}
		if err := catStore.Set(body.Name, body.Hosts, false); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		auditEvent(r, "urlcat.create", body.Name, fmt.Sprintf("%d host(s)", len(body.Hosts)))
		jsonOK(w, map[string]string{"name": body.Name})

	case http.MethodPut:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, "name query param required", http.StatusBadRequest)
			return
		}
		var body struct {
			Hosts []string `json:"hosts"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		// Preserve builtIn flag when updating.
		all := catStore.All()
		builtIn := false
		for _, e := range all {
			if strings.EqualFold(e.Name, name) {
				builtIn = e.BuiltIn
				break
			}
		}
		if err := catStore.Set(name, body.Hosts, builtIn); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		auditEvent(r, "urlcat.update", name, fmt.Sprintf("%d host(s)", len(body.Hosts)))
		jsonOK(w, map[string]string{"name": name})

	case http.MethodDelete:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, "name query param required", http.StatusBadRequest)
			return
		}
		if err := catStore.Delete(name); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		auditEvent(r, "urlcat.delete", name, "")
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// POST/DELETE /api/urlcat/host — add or remove a single host from a category.
func apiURLCatHost(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		var body struct {
			Category string `json:"category"`
			Host     string `json:"host"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if body.Category == "" || body.Host == "" {
			http.Error(w, "category and host are required", http.StatusBadRequest)
			return
		}
		if err := catStore.AddHost(body.Category, body.Host); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		auditEvent(r, "urlcat.host.add", body.Category, body.Host)
		jsonOK(w, map[string]string{"category": body.Category, "host": body.Host})

	case http.MethodDelete:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		category := r.URL.Query().Get("category")
		host := r.URL.Query().Get("host")
		if category == "" || host == "" {
			http.Error(w, "category and host query params required", http.StatusBadRequest)
			return
		}
		if err := catStore.RemoveHost(category, host); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		auditEvent(r, "urlcat.host.remove", category, host)
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// GET /api/urlcat/lookup?host=example.com
// Resolves a hostname to its URL category AND checks the blocklist.
// Response: {"host":"…","category":"…","tier":"admin"|"community"|"none","matchedBy":"…","blocked":true|false,"blockSource":"manual"|"feed"|""}
func apiURLCatLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	host := r.URL.Query().Get("host")
	if host == "" {
		http.Error(w, "host query param required", http.StatusBadRequest)
		return
	}
	category, tier, matchedBy := lookupHostCategory(host)
	// Also check the blocklist so the lookup tool gives a complete picture.
	blocked := bl.IsBlocked(host)
	blockSource := ""
	if blocked {
		blockSource = "blocklist"
	}
	jsonOK(w, map[string]any{
		"host":        host,
		"category":    category,
		"tier":        tier,
		"matchedBy":   matchedBy,
		"blocked":     blocked,
		"blockSource": blockSource,
	})
}

// configBackup is the portable JSON snapshot of all non-secret configuration.
type configBackup struct {
	Version             int           `json:"version"`
	ExportedAt          string        `json:"exportedAt"`
	BlocklistMode       string        `json:"blocklistMode"`
	Blocklist           []string      `json:"blocklist"`
	PolicyRules         []PolicyRule  `json:"policyRules"`
	DefaultAction       string        `json:"defaultAction"`
	RewriteRules        []RewriteRule `json:"rewriteRules"`
	SSLBypass           []string      `json:"sslBypass"`
	ContentScanPatterns []string      `json:"contentScanPatterns"`
	FileBlockExtensions []string      `json:"fileBlockExtensions"`
	IPFilterMode        string        `json:"ipFilterMode"`
	IPList              []string      `json:"ipList"`
	RateLimitRPM        int           `json:"rateLimitRPM"`
	RateLimitExempt     []string      `json:"rateLimitExempt,omitempty"`
	PACProxyHost        string        `json:"pacProxyHost,omitempty"`
	PACProxyPort        int           `json:"pacProxyPort,omitempty"`
	PACExclusions       []string      `json:"pacExclusions,omitempty"`
	AlertWebhooks       []AlertWebhook  `json:"alertWebhooks,omitempty"`       // Finding 10.3
	BlockPageHTML       string          `json:"blockPageHTML,omitempty"`        // Finding 10.3
	UpstreamProxies     []UpstreamEntry `json:"upstreamProxies,omitempty"`     // Finding 10.3
	ConnLimitEnabled    bool            `json:"connLimitEnabled,omitempty"`    // Finding 10.3
	ConnLimitMaxPerIP   int             `json:"connLimitMaxPerIP,omitempty"`   // Finding 10.3
}

// GET /api/config/export — download a full configuration backup as JSON.
func apiConfigExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}

	// F30: Section-specific export via ?section= query parameter.
	// Supported: blocklist, policy, rewrite, sslbypass, fileblock, ipfilter, all (default).
	section := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("section")))

	b := configBackup{
		Version:    1,
		ExportedAt: time.Now().UTC().Format(time.RFC3339),
	}
	filename := "culvert-backup"

	switch section {
	case "blocklist":
		b.BlocklistMode = bl.Mode()
		b.Blocklist = bl.List()
		filename = "culvert-blocklist"
	case "policy":
		b.PolicyRules = policyStore.List()
		b.DefaultAction = defaultPolicyAction()
		filename = "culvert-policy"
	case "rewrite":
		b.RewriteRules = rewriter.List()
		filename = "culvert-rewrite"
	case "sslbypass":
		b.SSLBypass = sslBypass.List()
		filename = "culvert-sslbypass"
	case "fileblock":
		b.FileBlockExtensions = fileBlocker.List()
		filename = "culvert-fileblock"
	case "ipfilter":
		b.IPFilterMode = ipf.Mode()
		b.IPList = ipf.List()
		filename = "culvert-ipfilter"
	case "pac":
		pc := pacStore.Get()
		b.PACProxyHost = pc.ProxyHost
		b.PACProxyPort = pc.ProxyPort
		b.PACExclusions = pc.Exclusions
		filename = "culvert-pac"
	case "alerts":
		b.AlertWebhooks = globalAlertStore.List()
		filename = "culvert-alerts"
	case "blockpage":
		b.BlockPageHTML = getBlockPageHTML()
		filename = "culvert-blockpage"
	case "upstream":
		for _, us := range upstreamPool.List() {
			b.UpstreamProxies = append(b.UpstreamProxies, UpstreamEntry{URL: us.URL})
		}
		filename = "culvert-upstream"
	case "connlimit":
		b.ConnLimitEnabled = connLimiter.enabled.Load()
		b.ConnLimitMaxPerIP = connLimiter.MaxPerIP()
		filename = "culvert-connlimit"
	default: // "all" or empty — full export
		b.BlocklistMode = bl.Mode()
		b.Blocklist = bl.List()
		b.PolicyRules = policyStore.List()
		b.DefaultAction = defaultPolicyAction()
		b.RewriteRules = rewriter.List()
		b.SSLBypass = sslBypass.List()
		b.ContentScanPatterns = dpiScanner.List()
		b.FileBlockExtensions = fileBlocker.List()
		b.IPFilterMode = ipf.Mode()
		b.IPList = ipf.List()
		b.RateLimitRPM = rl.Limit()
		b.RateLimitExempt = rl.ListExemptions()
		pc := pacStore.Get()
		b.PACProxyHost = pc.ProxyHost
		b.PACProxyPort = pc.ProxyPort
		b.PACExclusions = pc.Exclusions
		// Alert webhooks (secrets excluded by List()).
		b.AlertWebhooks = globalAlertStore.List()
		// Block page template.
		if html := getBlockPageHTML(); html != "" {
			b.BlockPageHTML = html
		}
		// Upstream proxies.
		for _, us := range upstreamPool.List() {
			b.UpstreamProxies = append(b.UpstreamProxies, UpstreamEntry{URL: us.URL})
		}
		// Connection limits.
		b.ConnLimitEnabled = connLimiter.enabled.Load()
		b.ConnLimitMaxPerIP = connLimiter.MaxPerIP()
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.json"`, filename))
	json.NewEncoder(w).Encode(b) //nolint:errcheck
	auditEvent(r, "config.export", filename, fmt.Sprintf("section=%s exported at %s", section, b.ExportedAt))
}

// POST /api/config/import — restore configuration from a backup JSON.
// Each section is applied atomically; partial failures are logged but do not abort.
func apiConfigImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	var b configBackup
	if err := decodeJSON(r, &b); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if b.Version != 1 {
		http.Error(w, "unsupported backup version", http.StatusBadRequest)
		return
	}

	// Import mode: "replace" clears existing state before importing;
	// "merge" (default) appends to existing state.
	replaceMode := r.URL.Query().Get("mode") == "replace"

	// Blocklist.
	if replaceMode && len(b.Blocklist) > 0 {
		bl.ClearAll()
	}
	for _, h := range b.Blocklist {
		bl.Add(h)
	}
	bl.Save()
	if b.BlocklistMode == "allow" || b.BlocklistMode == "block" {
		bl.SetMode(b.BlocklistMode)
	}

	// Policy rules — validate each before importing.
	if replaceMode && len(b.PolicyRules) > 0 {
		policyStore.ReplaceAll(b.PolicyRules)
	} else {
		for _, rule := range b.PolicyRules {
			if err := validatePolicyRule(rule, policyStore.List(), -1); err != nil {
				logger.Printf("ConfigImport: skipping rule %q: %s", sanitizeLog(rule.Name), strings.ReplaceAll(err.Error(), "\n", ""))
				continue
			}
			policyStore.Add(rule)
		}
	}
	policyStore.Save()
	if b.DefaultAction == "allow" || b.DefaultAction == "deny" {
		setDefaultPolicyAction(b.DefaultAction)
	}

	// Rewrite rules.
	if replaceMode && len(b.RewriteRules) > 0 {
		rewriter.SetRules(b.RewriteRules)
	} else {
		for _, rule := range b.RewriteRules {
			rewriter.Add(rule)
		}
	}

	// SSL bypass.
	if replaceMode && len(b.SSLBypass) > 0 {
		_ = sslBypass.Set(b.SSLBypass)
	} else {
		for _, p := range b.SSLBypass {
			_ = sslBypass.Add(p)
		}
	}
	sslBypass.Save()

	// Content scan patterns.
	if replaceMode && len(b.ContentScanPatterns) > 0 {
		_ = dpiScanner.Set(b.ContentScanPatterns)
	} else {
		for _, p := range b.ContentScanPatterns {
			_ = dpiScanner.Add(p)
		}
	}
	dpiScanner.Save()

	// File block extensions.
	if replaceMode && len(b.FileBlockExtensions) > 0 {
		fileBlocker.ClearAll()
	}
	for _, ext := range b.FileBlockExtensions {
		fileBlocker.Add(ext)
	}

	// Security.
	if b.IPFilterMode != "" {
		ipf.SetMode(b.IPFilterMode)
	}
	if replaceMode && len(b.IPList) > 0 {
		ipf.ClearAll()
	}
	for _, ip := range b.IPList {
		_ = ipf.Add(ip)
	}
	if b.RateLimitRPM > 0 {
		rl.Configure(b.RateLimitRPM, time.Minute)
	}
	for _, ex := range b.RateLimitExempt {
		_ = rl.AddExemption(ex)
	}

	// PAC configuration.
	if b.PACProxyHost != "" || b.PACProxyPort != 0 || len(b.PACExclusions) > 0 {
		pc := pacStore.Get()
		if replaceMode {
			pc = PACConfig{}
		}
		if b.PACProxyHost != "" {
			pc.ProxyHost = b.PACProxyHost
		}
		if b.PACProxyPort != 0 {
			pc.ProxyPort = b.PACProxyPort
		}
		if len(b.PACExclusions) > 0 {
			if replaceMode {
				pc.Exclusions = b.PACExclusions
			} else {
				pc.Exclusions = append(pc.Exclusions, b.PACExclusions...)
			}
		}
		_ = pacStore.Set(pc)
	}

	// Alert webhooks (Finding 10.3).
	if len(b.AlertWebhooks) > 0 {
		if replaceMode {
			// Clear existing webhooks before importing.
			for _, wh := range globalAlertStore.List() {
				globalAlertStore.Delete(wh.ID)
			}
		}
		for _, wh := range b.AlertWebhooks {
			globalAlertStore.Add(wh)
		}
	}

	// Block page template (Finding 10.3).
	if b.BlockPageHTML != "" {
		if err := setBlockPageHTML(b.BlockPageHTML); err != nil {
			logger.Printf("ConfigImport: block page template error: %s", strings.ReplaceAll(err.Error(), "\n", ""))
		}
	}

	// Upstream proxies (Finding 10.3).
	if len(b.UpstreamProxies) > 0 {
		upstreamPool.Configure(b.UpstreamProxies, 5, 60*time.Second)
	}

	// Connection limits (Finding 10.3).
	if b.ConnLimitMaxPerIP > 0 {
		if b.ConnLimitEnabled {
			connLimiter.Enable(b.ConnLimitMaxPerIP)
		} else {
			connLimiter.Disable()
		}
	}

	importMode := "merge"
	if replaceMode {
		importMode = "replace"
	}
	auditEvent(r, "config.import", importMode, fmt.Sprintf("from backup exported %s", b.ExportedAt))
	saveConfigVersion(sessionAdmin(r), "config.import")
	jsonOK(w, map[string]any{"ok": true, "mode": importMode, "exportedAt": b.ExportedAt})
}

// GET/POST /api/session-secret — shared session signing key management.
func apiSessionSecret(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		shared := os.Getenv("CULVERT_SESSION_SECRET") != ""
		jsonOK(w, map[string]any{"shared": shared})
	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			Secret string `json:"secret"` // hex-encoded, ≥64 chars (32 bytes)
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if body.Secret == "" {
			http.Error(w, "secret is required (64+ hex chars)", http.StatusBadRequest)
			return
		}
		key, err := hex.DecodeString(body.Secret)
		if err != nil || len(key) < 32 {
			http.Error(w, "secret must be ≥32 bytes of hex (64 hex chars)", http.StatusBadRequest)
			return
		}
		sessionSecret = key
		auditEvent(r, "settings.session_secret", "rotated", "shared session key updated via GUI")
		jsonOK(w, map[string]any{"ok": true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// GET/POST /api/session-timeout — read or change the UI session lifetime.
func apiSessionTimeout(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		jsonOK(w, map[string]any{"hours": int(getSessionTTL().Hours())})
	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			Hours int `json:"hours"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if body.Hours < 1 || body.Hours > 168 {
			http.Error(w, "hours must be 1–168", http.StatusBadRequest)
			return
		}
		SetSessionTTL(time.Duration(body.Hours) * time.Hour)
		auditEvent(r, "settings.session_timeout", fmt.Sprintf("%dh", body.Hours), "")
		jsonOK(w, map[string]any{"ok": true, "hours": body.Hours})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// GET/POST /api/ui-allow-ips — manage the admin panel IP access allowlist.
// GET    → returns current list (empty = all IPs allowed).
// POST   → {"ips": ["10.0.0.0/8", "192.168.1.5"]} — replaces the full list.
//
//	Send empty array [] to remove all restrictions.
func apiUIAllowIPs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		jsonOK(w, map[string]any{"ips": ListUIAllowedCIDRs()})
	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			IPs []string `json:"ips"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if err := SetUIAllowedCIDRs(body.IPs); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		auditEvent(r, "settings.ui_allow_ips", fmt.Sprintf("%d entries", len(body.IPs)), strings.Join(body.IPs, ", "))
		jsonOK(w, map[string]any{"ok": true, "ips": ListUIAllowedCIDRs()})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// syslogConfigured tracks whether syslog was initialised so the UI can reflect it.
var syslogConfigured string // the addr string, empty = not configured

// GET/POST /api/syslog — configure remote syslog/SIEM forwarding at runtime.
// GET  → returns current syslog address and format.
// POST → {"addr": "udp://10.0.0.1:514", "format": "rfc5424"} — reconnects immediately.
//
//	Send addr="" to disable forwarding.
func apiSyslogConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		format := "rfc3164"
		if globalSyslog != nil {
			format = globalSyslog.Format()
		}
		jsonOK(w, map[string]any{"addr": syslogConfigured, "format": format})
	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			Addr   string `json:"addr"`
			Format string `json:"format"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		body.Addr = strings.TrimSpace(body.Addr)
		body.Format = strings.TrimSpace(body.Format)
		if body.Format != "" && body.Format != "rfc3164" && body.Format != "rfc5424" {
			http.Error(w, "format must be \"rfc3164\" or \"rfc5424\"", http.StatusBadRequest)
			return
		}
		if body.Addr == "" {
			// Disable syslog.
			if globalSyslog != nil {
				globalSyslog.Close()
				globalSyslog = nil
			}
			syslogConfigured = ""
			auditEvent(r, "settings.syslog", "disabled", "")
			jsonOK(w, map[string]any{"ok": true, "addr": "", "format": "rfc3164"})
			return
		}
		if err := InitSyslog(body.Addr, body.Format); err != nil {
			http.Error(w, "syslog connect error: "+err.Error(), http.StatusBadRequest)
			return
		}
		syslogConfigured = body.Addr
		auditEvent(r, "settings.syslog", body.Addr, "syslog forwarding enabled (format="+globalSyslog.Format()+")")
		jsonOK(w, map[string]any{"ok": true, "addr": body.Addr, "format": globalSyslog.Format()})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// GET/POST /api/security — IP filter + rate limiter config
func apiSecurity(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		jsonOK(w, map[string]any{
			"ipFilterMode":       ipf.Mode(),
			"ipList":             ipf.List(),
			"rateLimitRPM":       rl.Limit(),
			"rateLimitOn":        rl.Enabled(),
			"rateLimitExempt":    rl.ListExemptions(),
		})

	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			IPFilterMode       string   `json:"ipFilterMode"` // "allow"|"block"|""
			IPAdd              string   `json:"ipAdd"`
			IPRemove           string   `json:"ipRemove"`
			RateLimitRPM       int      `json:"rateLimitRPM"`       // 0 = disable
			IPList             []string `json:"ipList"`             // full replace
			RateLimitExemptAdd string   `json:"rateLimitExemptAdd"` // IP or CIDR to exempt
			RateLimitExemptDel string   `json:"rateLimitExemptDel"` // IP or CIDR to un-exempt
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if body.IPFilterMode != "" {
			if body.IPFilterMode != "allow" && body.IPFilterMode != "block" {
				http.Error(w, `ipFilterMode must be "allow" or "block"`, http.StatusBadRequest)
				return
			}
			ipf.SetMode(body.IPFilterMode)
		}
		if body.IPAdd != "" {
			if err := ipf.Add(body.IPAdd); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		if body.IPRemove != "" {
			ipf.Remove(body.IPRemove)
		}
		if body.RateLimitRPM >= 0 {
			rl.Configure(body.RateLimitRPM, time.Minute)
		}
		if body.RateLimitExemptAdd != "" {
			if err := rl.AddExemption(body.RateLimitExemptAdd); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		if body.RateLimitExemptDel != "" {
			rl.RemoveExemption(body.RateLimitExemptDel)
		}
		logMode := strings.ReplaceAll(strings.ReplaceAll(ipf.Mode(), "\n", "_"), "\r", "_")
		logRPM := strings.ReplaceAll(fmt.Sprintf("%d", rl.Limit()), "\n", "_")
		logger.Printf("UI: security config updated (ipMode=%q rateRPM=%s)", logMode, logRPM)
		auditEvent(r, "security.update", "ip_filter+rate_limit",
			fmt.Sprintf("mode=%s rpm=%d", ipf.Mode(), rl.Limit()))
		saveConfigVersion(sessionAdmin(r), "security.update")
		jsonOK(w, map[string]any{"ok": true})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// GET/POST /api/settings
func apiSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		jsonOK(w, map[string]any{
			"authEnabled": cfg.AuthEnabled(),
			"user":        cfg.GetUser(), // password is NEVER returned
			"proxyPort":   cfg.ProxyPort,
			"uiPort":      cfg.UIPort,
			"unauthMode":  cfg.UnauthMode(),
		})

	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			User string `json:"user"`
			Pass string `json:"pass"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if err := cfg.SetAuth(body.User, body.Pass); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		logger.Printf("UI: auth settings updated (user=%q)", sanitizeLog(body.User))
		auditEvent(r, "settings.update", "auth", fmt.Sprintf("user=%s", body.User))
		jsonOK(w, map[string]any{"ok": true})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// PUT /api/settings/unauth-mode — toggle proxy authentication requirement
func apiUnauthMode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeJSON(r, &body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	cfg.SetUnauthMode(body.Enabled)
	if body.Enabled {
		auditEvent(r, "settings.update", "unauthMode", "enabled — proxy accepts unauthenticated traffic; policy rules govern access")
		logger.Printf("UI: unauth mode enabled — proxy accepts traffic without credentials")
	} else {
		auditEvent(r, "settings.update", "unauthMode", "disabled — proxy requires credentials")
		logger.Printf("UI: unauth mode disabled — proxy requires credentials")
	}
	jsonOK(w, map[string]any{"ok": true, "unauthMode": body.Enabled})
}

// GET/PUT /api/settings/log-level — view/change runtime log level.
func apiLogLevel(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		jsonOK(w, map[string]string{"level": GetLogLevel().String()})
	case http.MethodPut:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			Level string `json:"level"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		upper := strings.ToUpper(strings.TrimSpace(body.Level))
		if upper != "DEBUG" && upper != "INFO" && upper != "WARN" && upper != "ERROR" {
			http.Error(w, "level must be DEBUG/INFO/WARN/ERROR", http.StatusBadRequest)
			return
		}
		SetLogLevel(ParseLogLevel(upper))
		logger.Printf("UI: log level changed to %s", strings.ReplaceAll(upper, "\n", ""))
		auditEvent(r, "settings.log_level", upper, "")
		jsonOK(w, map[string]string{"level": upper})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// GET/POST /api/settings/network — network & TLS settings (base_url, ui_sans, trust_forwarded_headers).
func apiNetworkSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		jsonOK(w, map[string]any{
			"base_url":                  proxyExternalBaseURL,
			"ui_sans":                   uiExtraSANs,
			"trust_forwarded_headers":   trustForwardedHeaders,
		})
	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			BaseURL              string   `json:"base_url"`
			UISANs               []string `json:"ui_sans"`
			TrustForwardedHeaders bool    `json:"trust_forwarded_headers"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		SetProxyBaseURL(body.BaseURL)
		uiExtraSANs = body.UISANs
		trustForwardedHeaders = body.TrustForwardedHeaders
		safeSANs := make([]string, len(body.UISANs))
		for i, s := range body.UISANs {
			safeSANs[i] = strings.ReplaceAll(strings.ReplaceAll(s, "\n", ""), "\r", "")
		}
		safeTrustFwd := strings.ReplaceAll(fmt.Sprintf("%v", body.TrustForwardedHeaders), "\n", "")
		logger.Printf("UI: network settings updated (base_url=%q, ui_sans=%v, trust_fwd=%s)",
			sanitizeLog(body.BaseURL), safeSANs, safeTrustFwd)
		auditEvent(r, "settings.network", "updated", fmt.Sprintf("base_url=%s trust_fwd=%s sans=%v",
			strings.ReplaceAll(body.BaseURL, "\n", ""), safeTrustFwd, safeSANs))
		saveConfigVersion(sessionAdmin(r), "settings.network")
		jsonOK(w, map[string]string{"status": "ok"})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// GET/POST/DELETE /api/rewrite — manage header rewrite rules
func apiRewrite(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rules := rewriter.List()
		jsonOK(w, map[string]any{"rules": rules, "count": len(rules)})

	case http.MethodPost:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		var rule RewriteRule
		if err := decodeJSON(r, &rule); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		added := rewriter.Add(rule)
		logger.Printf("UI: rewrite rule added id=%d host=%q", added.ID, sanitizeLog(added.Host))
		auditEvent(r, "rewrite.add", fmt.Sprintf("id=%d host=%s", added.ID, added.Host), "")
		saveConfigVersion(sessionAdmin(r), "rewrite.add")
		jsonOK(w, added)

	case http.MethodDelete:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		idStr := strings.TrimSpace(r.URL.Query().Get("id"))
		var id int
		if _, err := fmt.Sscanf(idStr, "%d", &id); err != nil {
			http.Error(w, "missing or invalid id param", http.StatusBadRequest)
			return
		}
		if !rewriter.RemoveByID(id) {
			http.Error(w, "rule not found", http.StatusNotFound)
			return
		}
		logger.Printf("UI: rewrite rule removed id=%d", id)
		auditEvent(r, "rewrite.remove", fmt.Sprintf("id=%d", id), "")
		saveConfigVersion(sessionAdmin(r), "rewrite.remove")
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ─── Policy API ───────────────────────────────────────────────────────────────

// GET/POST/PUT/DELETE /api/policy — manage PBAC policy rules
func apiPolicy(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rules := policyStore.List()
		ver, updatedAt := policyStore.policyVersion()
		jsonOK(w, map[string]any{
			"rules":     rules,
			"count":     len(rules),
			"version":   ver,
			"updatedAt": updatedAt,
		})

	case http.MethodPost:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		var rule PolicyRule
		if err := decodeJSON(r, &rule); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if rule.Name == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
			return
		}
		if err := validatePolicyRule(rule, policyStore.List(), -1); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		added := policyStore.Add(rule)
		policyStore.Save()
		logName := strings.ReplaceAll(strings.ReplaceAll(added.Name, "\n", "_"), "\r", "_")
		logAction := strings.ReplaceAll(strings.ReplaceAll(string(added.Action), "\n", "_"), "\r", "_")
		logPriority := strings.ReplaceAll(fmt.Sprintf("%d", added.Priority), "\n", "_")
		logger.Printf("UI: policy rule added priority=%s name=%q action=%q", logPriority, logName, logAction)
		auditEventDiff(r, "policy.add", added.Name,
			fmt.Sprintf("priority=%d action=%s", added.Priority, added.Action), nil, added)
		saveConfigVersion(sessionAdmin(r), "policy.add")
		jsonOK(w, added)

	case http.MethodPut:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		priorityStr := strings.TrimSpace(r.URL.Query().Get("priority"))
		var priority int
		if _, err := fmt.Sscanf(priorityStr, "%d", &priority); err != nil {
			http.Error(w, "missing or invalid priority param", http.StatusBadRequest)
			return
		}
		// Snapshot before state for diff.
		var beforeRule *PolicyRule
		for _, existing := range policyStore.List() {
			if existing.Priority == priority {
				r2 := existing
				beforeRule = &r2
				break
			}
		}
		var rule PolicyRule
		if err := decodeJSON(r, &rule); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if err := validatePolicyRule(rule, policyStore.List(), priority); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !policyStore.Update(priority, rule) {
			http.Error(w, "rule not found", http.StatusNotFound)
			return
		}
		policyStore.Save()
		logger.Printf("UI: policy rule updated priority=%d name=%q", priority, sanitizeLog(rule.Name))
		auditEventDiff(r, "policy.update", rule.Name,
			fmt.Sprintf("priority=%d action=%s", priority, rule.Action), beforeRule, rule)
		saveConfigVersion(sessionAdmin(r), "policy.update")
		jsonOK(w, map[string]any{"ok": true})

	case http.MethodDelete:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		priorityStr := strings.TrimSpace(r.URL.Query().Get("priority"))
		// F19: support bulk delete via JSON body with priorities array.
		if priorityStr == "" {
			var body struct {
				Priorities []int `json:"priorities"`
			}
			if err := decodeJSON(r, &body); err == nil && len(body.Priorities) > 0 {
				deleted := 0
				for _, p := range body.Priorities {
					if policyStore.Delete(p) {
						deleted++
					}
				}
				policyStore.Save()
				logger.Printf("UI: bulk policy delete %d rule(s)", deleted)
				auditEvent(r, "policy.bulk_delete", fmt.Sprintf("%d rule(s)", deleted), "")
				saveConfigVersion(sessionAdmin(r), "policy.bulk_delete")
				jsonOK(w, map[string]any{"deleted": deleted})
				return
			}
			http.Error(w, "missing priority param or priorities body", http.StatusBadRequest)
			return
		}
		var priority int
		if _, err := fmt.Sscanf(priorityStr, "%d", &priority); err != nil {
			http.Error(w, "missing or invalid priority param", http.StatusBadRequest)
			return
		}
		// Snapshot before deletion.
		var beforeRule *PolicyRule
		for _, existing := range policyStore.List() {
			if existing.Priority == priority {
				r2 := existing
				beforeRule = &r2
				break
			}
		}
		if !policyStore.Delete(priority) {
			http.Error(w, "rule not found", http.StatusNotFound)
			return
		}
		policyStore.Save()
		name := fmt.Sprintf("priority=%d", priority)
		if beforeRule != nil {
			name = beforeRule.Name
		}
		logger.Printf("UI: policy rule deleted priority=%d", priority)
		auditEventDiff(r, "policy.delete", name, "", beforeRule, nil)
		saveConfigVersion(sessionAdmin(r), "policy.delete")
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// POST /api/policy/reorder — drag-and-drop priority reordering
// Body: {"priorities": [3,1,2]} — ordered list of old priorities (new order)
func apiPolicyReorder(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleOperator) {
		return
	}
	var body struct {
		Priorities []int `json:"priorities"`
	}
	if err := decodeJSON(r, &body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if !policyStore.Reorder(body.Priorities) {
		http.Error(w, "priority list length mismatch or unknown priority", http.StatusBadRequest)
		return
	}
	policyStore.Save()
	logger.Printf("UI: policy rules reordered (%d rules)", len(body.Priorities))
	auditEvent(r, "policy.reorder", fmt.Sprintf("%d rules", len(body.Priorities)), "")
	saveConfigVersion(sessionAdmin(r), "policy.reorder")
	jsonOK(w, map[string]any{"ok": true})
}

// POST /api/policy/test — evaluate policy rules against hypothetical inputs.
// Useful for debugging: returns the first matching rule (or no-match) without
// side-effects (hit counts are NOT incremented).
// Body: {"sourceIP":"…","identity":"…","authSource":"…","groups":["…"],"host":"…"}
func apiPolicyTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	var body struct {
		SourceIP   string   `json:"sourceIP"`
		Identity   string   `json:"identity"`
		AuthSource string   `json:"authSource"`
		Groups     []string `json:"groups"`
		Host       string   `json:"host"`
	}
	if err := decodeJSON(r, &body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if body.Host == "" {
		http.Error(w, "host is required", http.StatusBadRequest)
		return
	}
	if body.AuthSource == "" {
		body.AuthSource = "unauth"
	}

	// Walk rules manually without incrementing hit counts.
	rules := policyStore.List()
	type ruleTrace struct {
		Priority   int    `json:"priority"`
		Name       string `json:"name"`
		SkipReason string `json:"skipReason,omitempty"` // why this rule was skipped
	}
	var trace []ruleTrace
	var matched *PolicyRule

	for _, rule := range rules {
		r2 := rule // copy
		skip := ""
		if !matchSource(&r2, body.SourceIP, body.Identity, body.AuthSource, body.Groups) {
			skip = "source mismatch"
		} else if !matchSchedule(r2.Schedule) {
			skip = "schedule inactive"
		} else if !matchDest(&r2, body.Host) {
			skip = "destination mismatch"
		}
		trace = append(trace, ruleTrace{Priority: r2.Priority, Name: r2.Name, SkipReason: skip})
		if skip == "" {
			matched = &r2
			break
		}
	}

	// Enrich with category lookup so the admin can see how the host was categorised.
	catName, catTier, catMatchedBy := lookupHostCategory(body.Host)
	hostCategory := map[string]string{
		"category":  catName,
		"tier":      catTier,
		"matchedBy": catMatchedBy,
	}

	if matched == nil {
		defAction := defaultPolicyAction()
		jsonOK(w, map[string]any{
			"matched":       false,
			"defaultAction": defAction,
			"trace":         trace,
			"hostCategory":  hostCategory,
		})
		return
	}
	jsonOK(w, map[string]any{
		"matched":      true,
		"rule":         matched,
		"action":       matched.Action,
		"trace":        trace,
		"hostCategory": hostCategory,
	})
}

// GET /api/ca-cert — download the Root CA certificate (PEM) for browser/OS import.
// Also returns metadata: subject, expiry, SHA256 fingerprint.
func apiCACert(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		pem := certMgr.CACertPEM()
		if pem == nil {
			http.Error(w, "CA not initialised", http.StatusServiceUnavailable)
			return
		}
		// Return JSON metadata or raw PEM depending on Accept header.
		if strings.Contains(r.Header.Get("Accept"), "application/json") {
			info := certMgr.CACertInfo()
			jsonOK(w, info)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", `attachment; filename="culvert-ca.pem"`)
		w.Write(pem) //nolint:errcheck // HTTP response write
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// POST /api/certs/upload — upload a custom TLS certificate+key for the UI or MITM engine.
// Body: multipart/form-data with fields: "cert" (PEM), "key" (PEM), "target" ("ui"|"mitm")
func apiCertsUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // enforce 1 MB limit before parsing
	if err := r.ParseMultipartForm(1 << 20); err != nil { // #nosec G120 -- body already bounded by MaxBytesReader(1 MiB) on the line above
		http.Error(w, "failed to parse form", http.StatusBadRequest)
		return
	}
	target := r.FormValue("target")
	if target != "ui" && target != "mitm" {
		http.Error(w, `target must be "ui" or "mitm"`, http.StatusBadRequest)
		return
	}
	certPEM := []byte(r.FormValue("cert"))
	keyPEM := []byte(r.FormValue("key"))
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		http.Error(w, "cert and key are required", http.StatusBadRequest)
		return
	}
	if target == "mitm" {
		if err := certMgr.LoadCustomCA(certPEM, keyPEM); err != nil {
			logger.Printf("certs upload MITM: %v", err)
			http.Error(w, "invalid CA cert/key pair", http.StatusBadRequest)
			return
		}
		auditEvent(r, "certs.upload_mitm", "custom MITM CA", "")
		jsonOK(w, map[string]string{"status": "ok", "target": "mitm"})
		return
	}
	// UI cert — validate only; actual rotation requires restart.
	if _, err := certMgr.ParseTLSPair(certPEM, keyPEM); err != nil {
		logger.Printf("certs upload UI: %v", err)
		http.Error(w, "invalid cert/key pair", http.StatusBadRequest)
		return
	}
	auditEvent(r, "certs.upload_ui", "custom UI cert (requires restart)", "")
	jsonOK(w, map[string]string{"status": "ok", "target": "ui", "note": "restart required to activate"})
}

// GET/POST /api/default-action — read or update the default policy action at runtime.
func apiDefaultAction(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		jsonOK(w, map[string]string{"defaultAction": defaultPolicyAction()})
	case http.MethodPost:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		var body struct {
			Action string `json:"action"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if body.Action != "allow" && body.Action != "deny" {
			http.Error(w, `action must be "allow" or "deny"`, http.StatusBadRequest)
			return
		}
		setDefaultPolicyAction(body.Action)
		auditEvent(r, "policy.default_action", body.Action, "")
		saveConfigVersion(sessionAdmin(r), "policy.default_action")
		logger.Printf("UI: default policy action set to %q", body.Action)
		jsonOK(w, map[string]string{"defaultAction": defaultPolicyAction()})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// GET /api/export?format=json|csv — download all logs
func apiExport(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleViewer) {
		return
	}
	entries := logGet()
	format := r.URL.Query().Get("format")
	ts := time.Now().Format("20060102-150405")

	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="culvert-%s.csv"`, ts))
		cw := csv.NewWriter(w)
		cw.Write([]string{"timestamp", "time", "ip", "identity", "method", "host", "status", "level", "rule_matched", "action_taken", "bytes_sent", "bytes_recv", "ssl_action"}) //nolint:errcheck // CSV write
		for i := range entries {
			e := &entries[i]
			cw.Write([]string{ //nolint:errcheck // CSV write
				fmt.Sprintf("%d", e.TS),
				e.Time, e.IP, e.Identity, e.Method, e.Host, e.Status, e.Level,
				e.RuleMatched, e.ActionTaken,
				fmt.Sprintf("%d", e.BytesSent), fmt.Sprintf("%d", e.BytesRecv),
				e.SSLAction,
			})
		}
		cw.Flush()

	default: // json
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="culvert-%s.json"`, ts))
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck // HTTP response write
			"exported": ts,
			"count":    len(entries),
			"logs":     entries,
		})
	}
}

// GET/POST/DELETE /api/ssl-bypass — manage the dynamic SSL bypass pattern list.
//
// Patterns are persisted to the file configured via ssl_bypass_file in
// config.yaml (or -ssl-bypass-file flag). Changes take effect immediately
// without a proxy restart.
//
//	GET    → {"patterns": [...], "count": N}
//	POST   → {"pattern": "*.co.il"} or {"patterns": ["*.co.il","~^.*\.gov\.il$"]}
//	DELETE → ?pattern=*.co.il
func apiSSLBypass(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		patterns := sslBypass.List()
		jsonOK(w, map[string]any{"patterns": patterns, "count": len(patterns)})

	case http.MethodPost:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		var body struct {
			Pattern  string   `json:"pattern"`
			Patterns []string `json:"patterns"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if body.Pattern != "" {
			body.Patterns = append(body.Patterns, body.Pattern)
		}
		added := 0
		for _, p := range body.Patterns {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if err := sslBypass.Add(p); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			logger.Printf("UI: ssl bypass added %q", p)
			added++
		}
		sslBypass.Save()
		auditEvent(r, "ssl_bypass.add", fmt.Sprintf("%d pattern(s)", added),
			strings.Join(body.Patterns, ", "))
		saveConfigVersion(sessionAdmin(r), "ssl_bypass.add")
		jsonOK(w, map[string]any{"added": added})

	case http.MethodDelete:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		pattern := strings.TrimSpace(r.URL.Query().Get("pattern"))
		if pattern == "" {
			http.Error(w, "missing pattern param", http.StatusBadRequest)
			return
		}
		sslBypass.Remove(pattern)
		sslBypass.Save()
		logger.Printf("UI: ssl bypass removed %q", pattern)
		auditEvent(r, "ssl_bypass.remove", pattern, "")
		saveConfigVersion(sessionAdmin(r), "ssl_bypass.remove")
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// GET/POST/DELETE /api/content-scan — manage DPI signature patterns
//
// These regex patterns are matched against decrypted HTTP response bodies
// flowing through SSL Inspect tunnels.  Only text/* and application/json
// responses are scanned; binary content is passed through unscanned.
//
//	GET    → {"patterns": [...], "count": N, "blocked_total": N}
//	POST   → {"pattern": "evil-keyword"} or {"patterns": ["p1","p2"]}
//	DELETE → ?pattern=evil-keyword
func apiContentScan(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		patterns := dpiScanner.List()
		jsonOK(w, map[string]any{
			"patterns":      patterns,
			"count":         len(patterns),
			"blocked_total": statDPIBlocked,
		})

	case http.MethodPost:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		var body struct {
			Pattern  string   `json:"pattern"`
			Patterns []string `json:"patterns"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if body.Pattern != "" {
			body.Patterns = append(body.Patterns, body.Pattern)
		}
		added := 0
		for _, p := range body.Patterns {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if err := dpiScanner.Add(p); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			logger.Printf("UI: content-scan pattern added %q", p)
			added++
		}
		dpiScanner.Save()
		auditEvent(r, "content_scan.add", fmt.Sprintf("%d pattern(s)", added),
			strings.Join(body.Patterns, ", "))
		saveConfigVersion(sessionAdmin(r), "content_scan.add")
		jsonOK(w, map[string]any{"added": added})

	case http.MethodDelete:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		pattern := strings.TrimSpace(r.URL.Query().Get("pattern"))
		if pattern == "" {
			http.Error(w, "missing pattern param", http.StatusBadRequest)
			return
		}
		dpiScanner.Remove(pattern)
		dpiScanner.Save()
		logger.Printf("UI: content-scan pattern removed %q", pattern)
		auditEvent(r, "content_scan.remove", pattern, "")
		saveConfigVersion(sessionAdmin(r), "content_scan.remove")
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// GET/POST/DELETE /api/fileblock — manage the file-extension block profile
func apiFileblock(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		exts := fileBlocker.List()
		sort.Strings(exts)
		jsonOK(w, map[string]any{"extensions": exts, "count": len(exts)})

	case http.MethodPost:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		var body struct {
			Extensions []string `json:"extensions"` // bulk add
			Extension  string   `json:"extension"`  // single add
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if body.Extension != "" {
			body.Extensions = append(body.Extensions, body.Extension)
		}
		added := 0
		for _, ext := range body.Extensions {
			ext = strings.TrimSpace(ext)
			if ext != "" {
				fileBlocker.Add(ext)
				logger.Printf("UI: file block extension added %q", sanitizeLog(ext))
				added++
			}
		}
		auditEvent(r, "fileblock.add", fmt.Sprintf("%d extension(s)", added), "")
		saveConfigVersion(sessionAdmin(r), "fileblock.add")
		jsonOK(w, map[string]any{"added": added})

	case http.MethodDelete:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		ext := strings.TrimSpace(r.URL.Query().Get("ext"))
		if ext == "" {
			http.Error(w, "missing ext param", http.StatusBadRequest)
			return
		}
		fileBlocker.Remove(ext)
		logger.Printf("UI: file block extension removed %q", sanitizeLog(ext))
		auditEvent(r, "fileblock.remove", ext, "")
		saveConfigVersion(sessionAdmin(r), "fileblock.remove")
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ── File Extension Profiles API ───────────────────────────────────────────────
//
// GET    /api/fileblock/profiles          → list all profiles
// POST   /api/fileblock/profiles          → create profile {name, extensions[]}
// PUT    /api/fileblock/profiles?id=X     → update profile
// DELETE /api/fileblock/profiles?id=X     → delete profile
func apiFileblockProfiles(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		jsonOK(w, globalProfileStore.List())

	case http.MethodPost:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		var body struct {
			Name       string   `json:"name"`
			Extensions []string `json:"extensions"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		prof, err := globalProfileStore.Create(body.Name, body.Extensions)
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		auditEvent(r, "fileprofile.create", prof.Name, fmt.Sprintf("%d extensions", len(prof.Extensions)))
		jsonOK(w, prof)

	case http.MethodPut:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if id == "" {
			http.Error(w, "missing id param", http.StatusBadRequest)
			return
		}
		var body struct {
			Name       string   `json:"name"`
			Extensions []string `json:"extensions"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if err := globalProfileStore.Update(id, body.Name, body.Extensions); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		auditEvent(r, "fileprofile.update", body.Name, fmt.Sprintf("%d extensions", len(body.Extensions)))
		jsonOK(w, map[string]any{"ok": true})

	case http.MethodDelete:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if id == "" {
			http.Error(w, "missing id param", http.StatusBadRequest)
			return
		}
		if err := globalProfileStore.Delete(id); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		auditEvent(r, "fileprofile.delete", id, "")
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ── Generic IdP Framework API ────────────────────────────────────────────────

// GET /api/idp          — list all profiles
// POST /api/idp         — create a new profile
func apiIdPList(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		jsonOK(w, idpRegistry.All())
	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var p IdPProfile
		if err := decodeJSON(r, &p); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		p.ID = "" // force generation of new ID
		if err := idpRegistry.Upsert(&p); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		auditEventDiff(r, "idp.create", p.ID, p.Name, nil, &p)
		logger.Printf("UI: IdP profile created id=%q name=%q type=%q", sanitizeLog(p.ID), sanitizeLog(p.Name), sanitizeLog(string(p.Type)))
		jsonOK(w, &p)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// GET /api/idp/{id}     — get profile
// PUT /api/idp/{id}     — update profile
// DELETE /api/idp/{id}  — delete profile
// apiIdPRouter dispatches /api/idp/{id} and /api/idp/{id}/groups.
func apiIdPRouter(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/idp/")
	if strings.HasSuffix(rest, "/groups") {
		id := strings.TrimSuffix(rest, "/groups")
		apiIdPGroups(w, r, id)
		return
	}
	apiIdPItem(w, r, rest)
}

func apiIdPItem(w http.ResponseWriter, r *http.Request, id string) {
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		p := idpRegistry.Get(id)
		if p == nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		jsonOK(w, p)
	case http.MethodPut:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		before := idpRegistry.Get(id)
		var p IdPProfile
		if err := decodeJSON(r, &p); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		p.ID = id
		if err := idpRegistry.Upsert(&p); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		auditEventDiff(r, "idp.update", id, p.Name, before, &p)
		logger.Printf("UI: IdP profile updated id=%q name=%q", sanitizeLog(id), sanitizeLog(p.Name))
		jsonOK(w, &p)
	case http.MethodDelete:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		p := idpRegistry.Get(id)
		if err := idpRegistry.Delete(id); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		auditEventDiff(r, "idp.delete", id, "", p, nil)
		logger.Printf("UI: IdP profile deleted id=%q", sanitizeLog(id))
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// GET /api/idp/{id}/groups — returns the known-groups list for the profile.
func apiIdPGroups(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	p := idpRegistry.Get(id)
	if p == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	groups := p.KnownGroups
	if groups == nil {
		groups = []string{}
	}
	jsonOK(w, groups)
}

// POST /api/idp/discover — run OIDC discovery for a given issuer URL and
// return the discovered endpoints without saving anything.
// Requires Admin: this endpoint makes outbound HTTP requests based on user input.
func apiIdPDiscover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	var body struct {
		Issuer string `json:"issuer"`
	}
	if err := decodeJSON(r, &body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if err := validateExternalURL(body.Issuer); err != nil {
		http.Error(w, "issuer: "+err.Error(), http.StatusBadRequest)
		return
	}
	doc, err := fetchOIDCDiscovery(body.Issuer)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	jsonOK(w, doc)
}

// ── Auth callbacks ───────────────────────────────────────────────────────────

// GET /auth/oidc/callback?code=...&state=...
// Called by the IdP after the user authenticates (Authorization Code flow).
func authOIDCCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		http.Error(w, "missing code or state", http.StatusBadRequest)
		return
	}
	// Find provider by state (providerID is stored inside the PKCE entry).
	entry, ok := globalPKCEStore.peek(state)
	if !ok {
		http.Error(w, "invalid or expired state", http.StatusBadRequest)
		return
	}
	prov, ok := idpRegistry.LiveProvider(entry.providerID)
	if !ok {
		http.Error(w, "provider not found", http.StatusInternalServerError)
		return
	}
	oidcProv, ok := prov.(*OIDCFlowProvider)
	if !ok {
		http.Error(w, "provider is not OIDC", http.StatusInternalServerError)
		return
	}
	id, err := oidcProv.ExchangeCode(r, code, state)
	if err != nil {
		logger.Printf("OIDC callback error: %v", err)
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}
	if err := setSessionCookie(w, r, id); err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	// Redirect to the original URL the user was trying to reach.
	relayURL := entry.relayURL
	if relayURL == "" || !isSafeRedirectURL(relayURL) {
		relayURL = "/"
	}
	logger.Printf("OIDC login OK: user=%q email=%q provider=%q", sanitizeLog(id.Sub), sanitizeLog(id.Email), sanitizeLog(id.Provider))
	http.Redirect(w, r, relayURL, http.StatusFound)
}

// POST /auth/saml/callback
// Called by the IdP's POST binding after SAML authentication.
func authSAMLCallback(w http.ResponseWriter, r *http.Request) {
	// Determine which SAML provider this response belongs to.
	// We try all enabled SAML providers and use the one that validates cleanly.
	for _, prov := range idpRegistry.EnabledProviders() {
		samlProv, ok := prov.(*SAMLProvider)
		if !ok {
			continue
		}
		id, relayURL, err := samlProv.ExchangeAssertion(r)
		if err != nil {
			continue // try next provider
		}
		if err := setSessionCookie(w, r, id); err != nil {
			http.Error(w, "session error", http.StatusInternalServerError)
			return
		}
		safeRelay := "/"
		if relayURL != "" && isSafeRedirectURL(relayURL) {
			safeRelay = relayURL
		}
		logger.Printf("SAML login OK: user=%q email=%q provider=%q", sanitizeLog(id.Sub), sanitizeLog(id.Email), sanitizeLog(id.Provider))
		http.Redirect(w, r, safeRelay, http.StatusFound)
		return
	}
	http.Error(w, "SAML authentication failed", http.StatusUnauthorized)
}

// GET /auth/select?relay=...  — IdP selection screen for multi-tenancy.
// Renders a minimal HTML page listing all enabled providers.
func authSelectProvider(w http.ResponseWriter, r *http.Request) {
	relay := r.URL.Query().Get("relay")
	if relay == "" {
		relay = "/"
	}
	providers := idpRegistry.EnabledProviders()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html><html><head>
<meta charset="utf-8"><title>Culvert — Sign In</title>
<style>body{font-family:sans-serif;max-width:400px;margin:80px auto;padding:0 16px}
h1{font-size:1.4rem}a.btn{display:block;padding:12px 16px;margin:8px 0;border-radius:6px;
background:#2563eb;color:#fff;text-decoration:none;text-align:center}a.btn:hover{background:#1d4ed8}
</style></head><body><h1>Sign in to Culvert</h1>`)
	for _, p := range providers {
		loginURL := p.CaptiveLoginURL(relay, r)
		if loginURL == "" {
			continue
		}
		fmt.Fprintf(w, `<a class="btn" href="%s">Continue with %s</a>`,
			html.EscapeString(loginURL), html.EscapeString(p.Name()))
	}
	if len(providers) == 0 {
		fmt.Fprintf(w, `<p>No identity providers are configured.</p>`)
	}
	fmt.Fprintf(w, `</body></html>`)
}

// POST /auth/logout — clear session cookie.
func authLogout(w http.ResponseWriter, r *http.Request) {
	clearSessionCookie(w, r)
	http.Redirect(w, r, "/", http.StatusFound)
}

// ── Security scan API ─────────────────────────────────────────────────────────

// GET /api/security-scan/status — returns ClamAV connectivity, YARA rule count,
// threat feed statistics, and hash cache metrics.
func apiSecScanStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	jsonOK(w, secScanStatusMap())
}

// POST /api/security-scan/feeds/sync — trigger an immediate threat feed sync.
// Returns the updated status after the sync completes.
func apiSecFeedsSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	if !globalThreatFeed.Enabled() {
		http.Error(w, "threat feeds not enabled", http.StatusServiceUnavailable)
		return
	}
	// Run the sync synchronously so the response reflects the updated data.
	globalThreatFeed.Sync()
	jsonOK(w, secScanStatusMap())
}

// GET /api/security-scan/feeds/domain-allowlist — list domains exempt from
// domain-level threat feed blocking (URL-level blocking still applies).
// PUT /api/security-scan/feeds/domain-allowlist — replace the allowlist.
func apiDomainAllowlist(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		list := globalThreatFeed.DomainAllowlist()
		if list == nil {
			list = []string{}
		}
		jsonOK(w, map[string]any{"domains": list})
	case http.MethodPut:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			Domains []string `json:"domains"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		globalThreatFeed.SetDomainAllowlist(body.Domains)
		logger.Printf("ThreatFeed: domain allowlist updated (%d entries)", len(body.Domains))
		jsonOK(w, map[string]any{"ok": true, "count": len(body.Domains)})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// POST /api/security-scan/yara/reload — reload YARA rules from the configured
// directory without restarting the proxy.
func apiSecYARAReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	globalYARA.mu.RLock()
	dir := globalYARA.dir
	globalYARA.mu.RUnlock()

	if dir == "" {
		http.Error(w, "no YARA rules directory configured", http.StatusServiceUnavailable)
		return
	}
	if err := globalYARA.LoadDir(dir); err != nil {
		http.Error(w, "YARA reload failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{
		"yara_rules": globalYARA.Count(),
		"directory":  dir,
	})
}

// GET /api/security-scan/svc — returns scan microservice configuration.
func apiScanSvcConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	resp := map[string]interface{}{
		"remote_enabled": globalRemoteScanner.Enabled(),
		"remote_url":     globalRemoteScanner.URL(),
	}
	if globalRemoteScanner.Enabled() {
		if err := globalRemoteScanner.Health(); err != nil {
			resp["remote_status"] = "unreachable: " + err.Error()
		} else {
			resp["remote_status"] = "connected"
		}
	}
	jsonOK(w, resp)
}

// GET    /api/security-scan/cache          — return cache stats (hits, misses, size).
// DELETE /api/security-scan/cache          — clear entire scan hash cache.
// DELETE /api/security-scan/cache?hash=xxx — evict a single hash from the cache.
func apiScanCache(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		if globalSecScanner == nil || globalSecScanner.cache == nil {
			jsonOK(w, map[string]any{"enabled": false})
			return
		}
		hits, misses, size := globalSecScanner.cache.Stats()
		jsonOK(w, map[string]any{
			"enabled":      true,
			"cache_hits":   hits,
			"cache_misses": misses,
			"cache_size":   size,
		})

	case http.MethodDelete:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		if globalSecScanner == nil || globalSecScanner.cache == nil {
			http.Error(w, "scan cache not enabled", http.StatusServiceUnavailable)
			return
		}
		hash := r.URL.Query().Get("hash")
		if hash != "" {
			found := globalSecScanner.cache.Evict(hash)
			auditEvent(r, "scan_cache.evict", sanitizeLog(hash), "")
			jsonOK(w, map[string]any{"evicted": found, "hash": hash})
		} else {
			globalSecScanner.cache.Clear()
			auditEvent(r, "scan_cache.clear", "all", "")
			jsonOK(w, map[string]any{"cleared": true})
		}

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CA Management API
// ═══════════════════════════════════════════════════════════════════════════════

func apiCAStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	info := certMgr.CACertInfo()
	info["cacheSize"] = certMgr.CertCacheLen()
	info["cacheMax"] = 10_000
	info["cacheTTL"] = "1h"
	info["leafValidity"] = "24h"
	info["autoRotation"] = true
	info["rotationOverlapDays"] = 30
	info["keyProvider"] = certMgr.KeyProviderName()
	expiry := certMgr.CAExpiry()
	if !expiry.IsZero() {
		info["expiresIn"] = time.Until(expiry).Round(time.Hour).String()
	}
	// Dual-CA overlap status.
	info["dualCAActive"] = certMgr.SecondaryCAActive()
	if secInfo := certMgr.SecondaryCAInfo(); secInfo != nil {
		info["secondaryCA"] = secInfo
	}
	jsonOK(w, info)
}

func apiCADownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	pem := certMgr.CACertPEM()
	if pem == nil {
		http.Error(w, "CA not initialised", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="culvert-ca.pem"`)
	w.Write(pem) //nolint:errcheck
}

func apiCACacheClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	certMgr.ClearCache()
	auditEvent(r, "ca.cache_clear", "leaf_cert_cache", "")
	jsonOK(w, map[string]any{"ok": true})
}

func apiCARotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}

	// Parse request body for two-step confirmation flow.
	var req struct {
		Confirm bool   `json:"confirm"`
		Token   string `json:"confirmation_token"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck // empty body is valid (step 1)
	}

	if !req.Confirm {
		// Step 1: generate confirmation token and return warning.
		var tokenBytes [16]byte
		if _, err := rand.Read(tokenBytes[:]); err != nil {
			http.Error(w, "failed to generate confirmation token", http.StatusInternalServerError)
			return
		}
		token := hex.EncodeToString(tokenBytes[:])

		pendingCARotation.Lock()
		pendingCARotation.token = token
		pendingCARotation.expires = time.Now().Add(60 * time.Second)
		pendingCARotation.Unlock()

		auditEvent(r, "ca.rotate_requested", "root_ca", "rotation confirmation token issued")
		jsonOK(w, map[string]any{
			"status":             "pending_confirmation",
			"confirmation_token": token,
			"expires_in_seconds": 60,
			"warning":            "Rotating the Root CA will invalidate all existing leaf certificates and the current CA trust chain. All client workstations and devices will need to trust the new CA certificate. This action cannot be undone.",
		})
		return
	}

	// Step 2: verify confirmation token and perform rotation.
	pendingCARotation.Lock()
	storedToken := pendingCARotation.token
	expires := pendingCARotation.expires
	pendingCARotation.token = ""
	pendingCARotation.expires = time.Time{}
	pendingCARotation.Unlock()

	if storedToken == "" || time.Now().After(expires) {
		http.Error(w, "confirmation token expired or not found — please request rotation again", http.StatusBadRequest)
		return
	}
	if req.Token != storedToken {
		http.Error(w, "invalid confirmation token", http.StatusForbidden)
		return
	}

	if err := certMgr.InitCA(); err != nil {
		http.Error(w, "rotation failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if caRuntime.path != "" {
		if err := certMgr.SaveCA(caRuntime.path, caRuntime.passphrase); err != nil {
			logger.Printf("CA force-rotate: save failed: %v", err)
		}
	}
	auditEvent(r, "ca.rotate", "root_ca", "force rotation via admin API (confirmed)")
	jsonOK(w, certMgr.CACertInfo())
}

// apiCAKeyProvider returns the current key provider status for HSM/KMS UI.
func apiCAKeyProvider(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	providerName := certMgr.KeyProviderName()
	jsonOK(w, map[string]any{
		"provider":     providerName,
		"isExternal":   providerName != "local",
		"caReady":      certMgr.Ready(),
		"dualCAActive": certMgr.SecondaryCAActive(),
	})
}

// ═══════════════════════════════════════════════════════════════════════════════
// OCSP Management API
// ═══════════════════════════════════════════════════════════════════════════════

func apiOCSPConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		jsonOK(w, map[string]any{
			"enabled":  globalOCSP.Enabled(),
			"cacheLen": globalOCSP.CacheLen(),
		})
	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			Enabled bool `json:"enabled"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if body.Enabled {
			globalOCSP.Enable()
			ConfigureTransportOCSP(upstreamTransport)
		} else {
			globalOCSP.Disable()
		}
		auditEvent(r, "ocsp.toggle", fmt.Sprintf("enabled=%v", body.Enabled), "")
		jsonOK(w, map[string]any{"ok": true, "enabled": globalOCSP.Enabled()})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// GeoIP Config API
// ═══════════════════════════════════════════════════════════════════════════════

func apiGeoIPConfig(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleViewer) {
		return
	}
	jsonOK(w, map[string]any{
		"enabled": geoEnabled(),
		"dbPath":  uiCfgGeoIPDB,
	})
}

// ═══════════════════════════════════════════════════════════════════════════════
// Logger Config API
// ═══════════════════════════════════════════════════════════════════════════════

func apiLoggerConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		jsonOK(w, map[string]any{
			"logFile":   uiCfgLogFile,
			"logMaxMB":  uiCfgLogMaxMB,
			"logFormat": uiCfgLogFormat,
		})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Metrics Config API
// ═══════════════════════════════════════════════════════════════════════════════

func apiMetricsConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		jsonOK(w, map[string]any{
			"tokenSet": metricsToken != "",
			"path":     "/metrics",
		})
	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			Token string `json:"token"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		metricsToken = body.Token
		auditEvent(r, "settings.metrics_token", "updated", "")
		jsonOK(w, map[string]any{"ok": true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Connection Limit API
// ═══════════════════════════════════════════════════════════════════════════════

func apiConnLimit(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		jsonOK(w, map[string]any{
			"enabled":   connLimiter.enabled.Load(),
			"maxPerIP":  connLimiter.MaxPerIP(),
			"activeIPs": connLimiter.ActiveIPs(),
		})
	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			Enabled  *bool `json:"enabled"`
			MaxPerIP int   `json:"maxPerIP"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if body.Enabled != nil && !*body.Enabled {
			connLimiter.Disable()
		} else if body.MaxPerIP > 0 {
			connLimiter.Enable(body.MaxPerIP)
		}
		auditEvent(r, "connlimit.update", fmt.Sprintf("enabled=%v max=%d", connLimiter.enabled.Load(), connLimiter.MaxPerIP()), "")
		jsonOK(w, map[string]any{"ok": true, "enabled": connLimiter.enabled.Load(), "maxPerIP": connLimiter.MaxPerIP()})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Block Page Template API
// ═══════════════════════════════════════════════════════════════════════════════

func apiBlockPage(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		jsonOK(w, map[string]any{"html": getBlockPageHTML()})
	case http.MethodPut:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			HTML string `json:"html"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if body.HTML == "" {
			http.Error(w, "html is required", http.StatusBadRequest)
			return
		}
		if err := setBlockPageHTML(body.HTML); err != nil {
			http.Error(w, "invalid template: "+err.Error(), http.StatusBadRequest)
			return
		}
		auditEvent(r, "blockpage.update", "block_page_template", "")
		jsonOK(w, map[string]any{"ok": true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Upstream Proxy Chaining API
// ═══════════════════════════════════════════════════════════════════════════════

func apiUpstream(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		jsonOK(w, map[string]any{
			"enabled": upstreamPool.Enabled(),
			"proxies": upstreamPool.List(),
		})
	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			Proxies []UpstreamEntry `json:"proxies"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		upstreamPool.Configure(body.Proxies, 5, 60*time.Second)
		applyUpstreamProxy()
		auditEvent(r, "upstream.update", fmt.Sprintf("%d proxies", len(body.Proxies)), "")
		jsonOK(w, map[string]any{"ok": true, "proxies": upstreamPool.List()})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func apiUpstreamSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	jsonOK(w, map[string]any{
		"enabled": upstreamPool.Enabled(),
		"proxies": upstreamPool.List(),
	})
}

func apiUpstreamHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	upstreamPool.HealthCheck()
	jsonOK(w, map[string]any{"ok": true, "proxies": upstreamPool.List()})
}

// ═══════════════════════════════════════════════════════════════════════════════
// Cluster / Multi-Node API
// ═══════════════════════════════════════════════════════════════════════════════

func apiClusterStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	result := map[string]any{
		"role":           clusterRole.role,
		"nodeID":         clusterRole.nodeID,
		"grpcAddr":       clusterRole.grpcAddr,
		"uptime":         time.Since(startTime).Round(time.Second).String(),
		"enrollEnabled":  globalClusterCA.Ready(),
		"caFingerprint":  globalClusterCA.CACertFingerprint(),
		"ha":             globalHA.Status(),
	}
	if clusterRole.role == "control-plane" {
		result["nodes"] = NodeMetricsList()
		result["enrolledNodes"] = globalClusterStore.ListNodes()
		result["activeTokens"] = countActiveTokens()
	}
	jsonOK(w, result)
}

func countActiveTokens() int {
	count := 0
	for _, t := range globalClusterStore.ListTokens() {
		if !t.Used && time.Now().Before(t.ExpiresAt) {
			count++
		}
	}
	return count
}

// apiClusterMode enables Control Plane mode at runtime from the admin GUI.
func apiClusterMode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}

	var req struct {
		GRPCAddr string `json:"grpc_addr"`
		CertFile string `json:"cert_file"`
		KeyFile  string `json:"key_file"`
		CAFile   string `json:"ca_file"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.GRPCAddr == "" {
		http.Error(w, "grpc_addr is required (e.g. \":50051\")", http.StatusBadRequest)
		return
	}
	// Validate gRPC address format.
	if _, _, err := net.SplitHostPort(req.GRPCAddr); err != nil {
		http.Error(w, fmt.Sprintf("grpc_addr must be a valid host:port (e.g. \":50051\"): %v", err), http.StatusBadRequest)
		return
	}
	// Reject path traversal in file paths (CWE-22). Only allow simple file names.
	for _, p := range []string{req.CertFile, req.KeyFile, req.CAFile} {
		if p == "" {
			continue
		}
		if strings.Contains(p, "..") || strings.Contains(p, "/") || strings.Contains(p, "\\") {
			http.Error(w, "invalid certificate path", http.StatusBadRequest)
			return
		}
	}

	if err := enableControlPlane(req.GRPCAddr, req.CertFile, req.KeyFile, req.CAFile, clusterDBPathGlobal); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	auditAdd(AuditEntry{
		TS:     time.Now().UnixMilli(),
		Time:   time.Now().Format("2006-01-02 15:04:05"),
		Actor:  sessionAdmin(r),
		Action: "cluster.enable-cp",
		Object: req.GRPCAddr,
		Detail: "Control Plane enabled via GUI",
	})
	jsonOK(w, map[string]any{"ok": true, "role": "control-plane", "grpcAddr": req.GRPCAddr})
}

// apiClusterTokens handles enrollment token CRUD.
func apiClusterTokens(w http.ResponseWriter, r *http.Request) { //nolint:cyclop // split into sub-handlers
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		tokens := globalClusterStore.ListTokens()
		jsonOK(w, map[string]any{"tokens": tokens})

	case http.MethodPost:
		apiClusterTokenCreate(w, r)

	case http.MethodDelete:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		tokenHash := r.URL.Query().Get("hash")
		if tokenHash == "" {
			http.Error(w, "hash parameter required", http.StatusBadRequest)
			return
		}
		if !globalClusterStore.DeleteToken(tokenHash) {
			http.Error(w, "token not found", http.StatusNotFound)
			return
		}
		if err := globalClusterStore.Save(); err != nil {
			logger.Printf("ClusterDB save error: %v", err)
			http.Error(w, "failed to persist token deletion", http.StatusInternalServerError)
			return
		}
		jsonOK(w, map[string]any{"ok": true})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func apiClusterTokenCreate(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	if clusterRole.role != "control-plane" {
		http.Error(w, "enrollment only available on Control Plane", http.StatusBadRequest)
		return
	}
	if !globalClusterCA.Ready() {
		http.Error(w, "cluster CA not initialized", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		NodePrefix string `json:"node_prefix"`
		AllowCIDR  string `json:"allow_cidr"`
		TTLHours   int    `json:"ttl_hours"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate node_prefix: alphanumeric + _- only, max 255 chars.
	if req.NodePrefix != "" {
		if len(req.NodePrefix) > 255 {
			http.Error(w, "node_prefix must be <= 255 characters", http.StatusBadRequest)
			return
		}
		for _, c := range req.NodePrefix {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
				http.Error(w, "node_prefix must contain only alphanumeric characters, underscores, and dashes", http.StatusBadRequest)
				return
			}
		}
	}

	// Cap TTL at 8760 hours (1 year).
	const maxTTLHours = 8760
	ttl := 24 * time.Hour
	if req.TTLHours > 0 {
		if req.TTLHours > maxTTLHours {
			http.Error(w, fmt.Sprintf("ttl_hours must be <= %d (1 year)", maxTTLHours), http.StatusBadRequest)
			return
		}
		ttl = time.Duration(req.TTLHours) * time.Hour
	}

	admin := sessionAdmin(r)
	plaintext, err := globalClusterStore.GenerateToken(req.NodePrefix, req.AllowCIDR, admin, ttl)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Build enrollment URL.
	cpAddr := clusterRole.grpcAddr
	caFP := globalClusterCA.CACertFingerprint()
	enrollURL := fmt.Sprintf("culvert://enroll/%s/%s?ca-fp=sha256:%s", cpAddr, plaintext, caFP)

	// Build bootstrap command (curl | bash).
	cpBase := cpBaseURL(r)
	bootstrapCmd := fmt.Sprintf("curl -fsSL -k %s/api/cluster/bootstrap/%s | sudo bash", cpBase, plaintext)
	enrollCmd := fmt.Sprintf("./culvert -enroll %q", enrollURL)

	auditEvent(r, "enrollment.token_created", sanitizeLog(req.NodePrefix),
		fmt.Sprintf("cidr=%s ttl=%dh", sanitizeLog(req.AllowCIDR), int(ttl.Hours())))

	jsonOK(w, map[string]any{
		"token":         plaintext,
		"enroll_url":    enrollURL,
		"enroll_cmd":    enrollCmd,
		"bootstrap_cmd": bootstrapCmd,
		"expires_at":    time.Now().Add(ttl).Format(time.RFC3339),
	})
}

// apiClusterNodes returns enrolled nodes with their status.
func apiClusterNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	nodes := globalClusterStore.ListNodes()
	jsonOK(w, map[string]any{"nodes": nodes})
}

// apiClusterRevoke revokes an enrolled node.
func apiClusterRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	var req struct {
		NodeID string `json:"node_id"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.NodeID == "" {
		http.Error(w, "node_id required", http.StatusBadRequest)
		return
	}
	if len(req.Reason) > 1000 {
		http.Error(w, "reason must be <= 1000 characters", http.StatusBadRequest)
		return
	}

	admin := sessionAdmin(r)
	if err := globalClusterStore.RevokeNode(req.NodeID, admin, req.Reason); err != nil {
		// RevokeNode calls Save() internally. Distinguish persistence errors
		// (500) from logical errors like "not found" or "already revoked" (400).
		if strings.Contains(err.Error(), "persist") {
			http.Error(w, "failed to persist node revocation", http.StatusInternalServerError)
		} else {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
		return
	}

	auditEvent(r, "enrollment.node_revoked", sanitizeLog(req.NodeID),
		fmt.Sprintf("reason=%s", sanitizeLog(req.Reason)))

	logger.Printf("Enrollment: node %q revoked by %s (reason: %s)", sanitizeLog(req.NodeID), sanitizeLog(admin), sanitizeLog(req.Reason))
	jsonOK(w, map[string]any{"ok": true})
}

// apiClusterCA returns cluster CA info (GET) or imports a custom CA (POST).
func apiClusterCA(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		jsonOK(w, globalClusterCA.Info())
	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			Cert string `json:"cert"`
			Key  string `json:"key"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if body.Cert == "" || body.Key == "" {
			http.Error(w, "cert and key are required", http.StatusBadRequest)
			return
		}
		// Pre-validate PEM format and cert:key match before importing.
		cert, err := parseAndValidateCACert([]byte(body.Cert))
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid certificate: %v", err), http.StatusBadRequest)
			return
		}
		ecPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			http.Error(w, "certificate must use an ECDSA key", http.StatusBadRequest)
			return
		}
		if _, err := parseAndValidateCAKey([]byte(body.Key), ecPub); err != nil {
			http.Error(w, fmt.Sprintf("invalid key: %v", err), http.StatusBadRequest)
			return
		}
		if err := globalClusterCA.ImportCA([]byte(body.Cert), []byte(body.Key)); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		auditEvent(r, "cluster.ca", "imported", "Custom cluster CA imported")
		jsonOK(w, globalClusterCA.Info())
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// apiClusterRateLimits returns distributed rate limiting status.
// Shows whether gossip is active, how many nodes are syncing, and hot IP count.
func apiClusterRateLimits(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	nodes, hotIPs := globalRLAggregator.Stats()
	jsonOK(w, map[string]any{
		"enabled":        clusterRateLimitEnabled.Load(),
		"syncing_nodes":  nodes,
		"hot_ips":        hotIPs,
		"remote_ips":     clusterCounts.Count(),
		"rate_limit_rpm": rl.Limit(),
		"threshold_pct":  hotThresholdPct,
	})
}

// apiClusterAudit returns the centralized audit log from all Data Plane nodes.
func apiClusterAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	entries := globalClusterAudit.Recent(200)
	jsonOK(w, map[string]any{"entries": entries, "total": globalClusterAudit.Count()})
}

// apiClusterRevocations returns distributed session revocation sync status.
func apiClusterRevocations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	jsonOK(w, map[string]any{
		"local_revoked":  sessionRevoked.Count(),
		"cluster_mode":   clusterRoleIsDP.Load() || clusterRole.role == "control-plane",
	})
}

// GET /api/cluster/rotation — CA rotation progress.
func apiClusterRotation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	rot := globalClusterStore.CARotationStatus()
	if rot == nil {
		jsonOK(w, map[string]any{"active": false})
		return
	}

	// Build list of pending nodes.
	pending := []string{}
	for _, n := range globalClusterStore.ListNodes() {
		if n.Status == "revoked" {
			continue
		}
		if _, ok := rot.RenewedNodes[n.NodeID]; !ok {
			pending = append(pending, n.NodeID)
		}
	}

	jsonOK(w, map[string]any{
		"active":          true,
		"started_at":      rot.StartedAt,
		"new_fingerprint": rot.NewFingerprint,
		"old_fingerprint": rot.OldFingerprint,
		"old_expires":     rot.OldExpires,
		"total_nodes":     rot.TotalNodes,
		"renewed_count":   len(rot.RenewedNodes),
		"renewed_nodes":   rot.RenewedNodes,
		"pending_nodes":   pending,
		"complete":        len(rot.RenewedNodes) >= rot.TotalNodes,
	})
}

// POST /api/cluster/labels — set labels on a node.
func apiClusterLabels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	var req struct {
		NodeID string            `json:"node_id"`
		Labels map[string]string `json:"labels"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.NodeID == "" {
		http.Error(w, "node_id is required", http.StatusBadRequest)
		return
	}
	// Validate label keys/values.
	for k, v := range req.Labels {
		if len(k) > 63 || len(v) > 255 {
			http.Error(w, "label key max 63 chars, value max 255 chars", http.StatusBadRequest)
			return
		}
	}
	if err := globalClusterStore.SetNodeLabels(req.NodeID, req.Labels); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	auditEvent(r, "cluster.labels", sanitizeLog(req.NodeID), fmt.Sprintf("labels updated (%d keys)", len(req.Labels)))
	jsonOK(w, map[string]any{"ok": true})
}

// POST /api/cluster/drain — toggle node drain/maintenance mode.
func apiClusterDrain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	var req struct {
		NodeID   string `json:"node_id"`
		Draining bool   `json:"draining"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.NodeID == "" {
		http.Error(w, "node_id is required", http.StatusBadRequest)
		return
	}
	if err := globalClusterStore.SetNodeDraining(req.NodeID, req.Draining); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	action := "cluster.drain"
	detail := "node set to draining (maintenance mode)"
	if !req.Draining {
		action = "cluster.undrain"
		detail = "node returned to active service"
	}
	auditEvent(r, action, sanitizeLog(req.NodeID), detail)
	jsonOK(w, map[string]any{"ok": true})
}

// GET /api/cluster/metrics — aggregated cluster-wide metrics.
func apiClusterMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	nodeMetricsMu.RLock()
	var totalReqs, totalBlocked, totalAuthFail int64
	nodes := make([]map[string]any, 0, len(nodeMetrics))
	for nid, m := range nodeMetrics {
		totalReqs += m.Total
		totalBlocked += m.Blocked
		totalAuthFail += m.AuthFail
		nodes = append(nodes, map[string]any{
			"node_id":   nid,
			"total":     m.Total,
			"blocked":   m.Blocked,
			"auth_fail": m.AuthFail,
			"uptime":    m.Uptime,
		})
	}
	nodeMetricsMu.RUnlock()

	jsonOK(w, map[string]any{
		"cluster_total":     totalReqs,
		"cluster_blocked":   totalBlocked,
		"cluster_auth_fail": totalAuthFail,
		"node_count":        len(nodes),
		"nodes":             nodes,
	})
}

// GET/POST /api/otlp — configure OpenTelemetry OTLP/HTTP metrics export.
func apiOTLPConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		jsonOK(w, map[string]any{
			"enabled":  globalOTLP.Enabled(),
			"endpoint": globalOTLP.Endpoint(),
		})
	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			Endpoint string `json:"endpoint"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		body.Endpoint = strings.TrimSpace(body.Endpoint)
		if body.Endpoint == "" {
			globalOTLP.Stop()
			auditEvent(r, "settings.otlp", "disabled", "")
			jsonOK(w, map[string]any{"ok": true, "enabled": false})
			return
		}
		// Inline SSRF guard: validate scheme + reject private hosts (CodeQL CWE-918).
		epURL, err := url.Parse(body.Endpoint)
		if err != nil || (epURL.Scheme != "http" && epURL.Scheme != "https") {
			http.Error(w, "endpoint must use http or https scheme", http.StatusBadRequest)
			return
		}
		if err := isPrivateHost(epURL.Hostname()); err != nil {
			http.Error(w, "endpoint must not resolve to a private network", http.StatusBadRequest)
			return
		}
		globalOTLP.Configure(body.Endpoint, nil)
		auditEvent(r, "settings.otlp", sanitizeLog(body.Endpoint), "OTLP export enabled")
		jsonOK(w, map[string]any{"ok": true, "enabled": true, "endpoint": body.Endpoint})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
