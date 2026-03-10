package main

import (
	"context"
	"encoding/csv"
	"embed"
	"encoding/json"
	"fmt"
	"html"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed static
var staticFiles embed.FS

func startUI(port int, certFile, keyFile string) {
	sub, _ := fs.Sub(staticFiles, "static")

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(sub)))
	mux.HandleFunc("/api/setup/status", apiSetupStatus)
	mux.HandleFunc("/api/setup/complete", apiSetupComplete)
	mux.HandleFunc("/api/stats", apiStats)
	mux.HandleFunc("/api/timeseries", apiTimeseries)
	mux.HandleFunc("/api/logs", apiLogs)
	mux.HandleFunc("/api/top-hosts", apiTopHosts)
	mux.HandleFunc("/api/blocklist", apiBlocklist)
	mux.HandleFunc("/api/fileblock", apiFileblock)
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
	mux.HandleFunc("/api/events", apiEvents)           // SSE live dashboard
	mux.HandleFunc("/api/country-traffic", apiCountryTraffic)
	mux.HandleFunc("/api/default-action", apiDefaultAction)
	mux.HandleFunc("/api/blocklist/mode", apiBlocklistMode)   // GET/POST blocklist mode
	mux.HandleFunc("/api/config/export", apiConfigExport)    // GET — download backup JSON
	mux.HandleFunc("/api/config/import", apiConfigImport)    // POST — restore from backup JSON
	mux.HandleFunc("/api/session-timeout", apiSessionTimeout) // GET/POST session TTL (hours)
	mux.HandleFunc("/api/ui-allow-ips", apiUIAllowIPs)        // GET/POST UI access IP allowlist
	mux.HandleFunc("/api/syslog", apiSyslogConfig)            // GET/POST syslog forwarding

	// ── Admin session auth ────────────────────────────────────────────────
	mux.HandleFunc("/api/auth/login", apiAuthLogin)
	mux.HandleFunc("/api/auth/status", apiAuthStatus)
	mux.HandleFunc("/api/auth/logout", apiAuthLogout)
	mux.HandleFunc("/api/auth/users", apiAuthUsers) // RBAC user management (admin only)

	// ── Generic IdP Framework ─────────────────────────────────────────────
	mux.HandleFunc("/api/idp", apiIdPList)              // GET list / POST create
	mux.HandleFunc("/api/idp/discover", apiIdPDiscover) // POST: run OIDC discovery (must be before /api/idp/)
	mux.HandleFunc("/api/idp/", apiIdPRouter)           // GET|PUT|DELETE /api/idp/{id} + /api/idp/{id}/groups

	// ── PAC file ─────────────────────────────────────────────────────────
	mux.HandleFunc("/proxy.pac", servePACFile)    // served on the UI port
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
	}

	if certFile != "" && keyFile != "" {
		logger.Printf("UI TLS  → https://localhost:%d (custom cert)", port)
		if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil {
			logger.Fatalf("UI TLS error: %v", err)
		}
		return
	}

	// Auto self-signed TLS.
	tlsCfg, err := selfSignedTLS()
	if err != nil {
		logger.Printf("TLS self-sign failed (%v), falling back to HTTP", err)
	} else {
		srv.TLSConfig = tlsCfg
		logger.Printf("UI TLS  → https://localhost:%d (self-signed)", port)
		if err := srv.ListenAndServeTLS("", ""); err != nil {
			logger.Fatalf("UI TLS error: %v", err)
		}
		return
	}

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
			"default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://flagcdn.com; connect-src 'self'")

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

		next.ServeHTTP(w, r)
	})
}

// isSameOrigin returns true when the Origin header matches the request's Host.
// This is the correct CSRF protection for single-origin admin UIs: any IP is
// fine as long as the request comes from the same scheme+host+port as the UI.
func isSameOrigin(r *http.Request, origin string) bool {
	if origin == "" {
		return true // no Origin = direct tool access — not a browser cross-site request
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
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
		// Always public: setup bootstrap, auth endpoints, IdP callbacks,
		// and /proxy.pac (Windows clients need it without credentials).
		if strings.HasPrefix(r.URL.Path, "/api/setup") ||
			strings.HasPrefix(r.URL.Path, "/api/auth/") ||
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

func setUISessionCookie(w http.ResponseWriter, username string, role UIRole) error {
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
	http.SetCookie(w, &http.Cookie{
		Name:     uiSessionCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   int(getSessionTTL().Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
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

func clearUISessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     uiSessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// POST /api/auth/login — validate admin credentials, set session cookie.
func apiAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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
	// Account lockout check — before any credential verification.
	if locked, secs := loginLimiter.Check(body.User); locked {
		auditEvent(r, "auth.lockout", body.User, fmt.Sprintf("blocked — %ds remaining", secs))
		http.Error(w, LockoutMsg(secs), http.StatusTooManyRequests)
		return
	}

	role, ok := cfg.VerifyUIUser(body.User, body.Pass)
	if !cfg.AuthEnabled() {
		role, ok = RoleAdmin, true
	}
	if ok {
		loginLimiter.RecordSuccess(body.User)
		if err := setUISessionCookie(w, body.User, role); err != nil {
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
	clearUISessionCookie(w)
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
		auditEvent(r, "auth.users.delete", username, "")
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
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
		http.Error(w, "username must be 1-64 characters", http.StatusBadRequest)
		return
	}
	if len(body.Pass) < 8 {
		http.Error(w, "password must be at least 8 characters", http.StatusBadRequest)
		return
	}
	if err := cfg.SetAuth(body.User, body.Pass); err != nil {
		http.Error(w, "internal error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Auto-login after setup so the user lands directly in the dashboard.
	_ = setUISessionCookie(w, body.User, RoleAdmin)
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
	// Do NOT trust client-supplied headers for the audit actor identity;
	// the remote IP is the only trustworthy identity at this layer.
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

// GET /api/audit — return recent configuration-change audit entries (newest first).
func apiAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	entries := auditGet()
	jsonOK(w, map[string]any{"entries": entries, "count": len(entries)})
}

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
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

// GET /api/timeseries
func apiTimeseries(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleViewer) {
		return
	}
	jsonOK(w, map[string]any{"data": tsGet()})
}

// GET /api/logs?filter=...&status=...&level=...&method=...
func apiLogs(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleViewer) {
		return
	}
	all := logGet()
	filterHost   := strings.ToLower(r.URL.Query().Get("filter"))
	filterStatus := strings.ToUpper(r.URL.Query().Get("status"))
	filterLevel  := strings.ToUpper(r.URL.Query().Get("level"))
	filterMethod := strings.ToUpper(r.URL.Query().Get("method"))

	filtered := all[:0:0]
	for _, e := range all {
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
		filtered = append(filtered, e)
	}
	jsonOK(w, map[string]any{"logs": filtered, "total": len(filtered)})
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
		hosts := bl.List()
		sort.Strings(hosts)
		jsonOK(w, map[string]any{"hosts": hosts, "count": len(hosts)})

	case http.MethodPost:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		var body struct {
			Hosts []string `json:"hosts"` // support bulk add
			Host  string   `json:"host"`  // single add
		}
		if err := decodeJSON(r,&body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		added := 0
		if body.Host != "" {
			body.Hosts = append(body.Hosts, body.Host)
		}
		for _, h := range body.Hosts {
			h = strings.TrimSpace(h)
			if h != "" {
				bl.Add(h)
				logger.Printf("UI: blocked %s", h)
				added++
			}
		}
		bl.Save()
		auditEvent(r, "blocklist.add", fmt.Sprintf("%d host(s)", added), strings.Join(body.Hosts, ", "))
		jsonOK(w, map[string]any{"added": added})

	case http.MethodDelete:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		host := strings.TrimSpace(r.URL.Query().Get("host"))
		if host == "" {
			http.Error(w, "missing host param", http.StatusBadRequest)
			return
		}
		bl.Remove(host)
		bl.Save()
		logger.Printf("UI: unblocked %s", host)
		auditEvent(r, "blocklist.remove", host, "")
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

// configBackup is the portable JSON snapshot of all non-secret configuration.
type configBackup struct {
	Version              int               `json:"version"`
	ExportedAt           string            `json:"exportedAt"`
	BlocklistMode        string            `json:"blocklistMode"`
	Blocklist            []string          `json:"blocklist"`
	PolicyRules          []PolicyRule      `json:"policyRules"`
	DefaultAction        string            `json:"defaultAction"`
	RewriteRules         []RewriteRule     `json:"rewriteRules"`
	SSLBypass            []string          `json:"sslBypass"`
	ContentScanPatterns  []string          `json:"contentScanPatterns"`
	FileBlockExtensions  []string          `json:"fileBlockExtensions"`
	IPFilterMode         string            `json:"ipFilterMode"`
	IPList               []string          `json:"ipList"`
	RateLimitRPM         int               `json:"rateLimitRPM"`
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
	b := configBackup{
		Version:             1,
		ExportedAt:          time.Now().UTC().Format(time.RFC3339),
		BlocklistMode:       bl.Mode(),
		Blocklist:           bl.List(),
		PolicyRules:         policyStore.List(),
		DefaultAction:       defaultPolicyAction(),
		RewriteRules:        rewriter.List(),
		SSLBypass:           sslBypass.List(),
		ContentScanPatterns: dpiScanner.List(),
		FileBlockExtensions: fileBlocker.List(),
		IPFilterMode:        ipf.Mode(),
		IPList:              ipf.List(),
		RateLimitRPM:        rl.Limit(),
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="proxyshield-backup.json"`)
	json.NewEncoder(w).Encode(b) //nolint:errcheck
	auditEvent(r, "config.export", "backup", fmt.Sprintf("exported at %s", b.ExportedAt))
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

	// Blocklist.
	for _, h := range b.Blocklist {
		bl.Add(h)
	}
	bl.Save()
	if b.BlocklistMode == "allow" || b.BlocklistMode == "block" {
		bl.SetMode(b.BlocklistMode)
	}

	// Policy rules.
	for _, rule := range b.PolicyRules {
		policyStore.Add(rule)
	}
	policyStore.Save()
	if b.DefaultAction == "allow" || b.DefaultAction == "deny" {
		setDefaultPolicyAction(b.DefaultAction)
	}

	// Rewrite rules.
	for _, rule := range b.RewriteRules {
		rewriter.Add(rule)
	}

	// SSL bypass.
	for _, p := range b.SSLBypass {
		_ = sslBypass.Add(p)
	}
	sslBypass.Save()

	// Content scan patterns.
	for _, p := range b.ContentScanPatterns {
		_ = dpiScanner.Add(p)
	}
	dpiScanner.Save()

	// File block extensions.
	for _, ext := range b.FileBlockExtensions {
		fileBlocker.Add(ext)
	}

	// Security.
	if b.IPFilterMode != "" {
		ipf.SetMode(b.IPFilterMode)
	}
	for _, ip := range b.IPList {
		_ = ipf.Add(ip)
	}
	if b.RateLimitRPM > 0 {
		rl.Configure(b.RateLimitRPM, time.Minute)
	}

	auditEvent(r, "config.import", "restore", fmt.Sprintf("from backup exported %s", b.ExportedAt))
	jsonOK(w, map[string]any{"ok": true, "exportedAt": b.ExportedAt})
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
//          Send empty array [] to remove all restrictions.
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
// GET  → returns current syslog address (empty string = disabled).
// POST → {"addr": "udp://10.0.0.1:514"} — reconnects immediately.
//         Send addr="" to disable forwarding.
func apiSyslogConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		jsonOK(w, map[string]any{"addr": syslogConfigured})
	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			Addr string `json:"addr"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		body.Addr = strings.TrimSpace(body.Addr)
		if body.Addr == "" {
			// Disable syslog.
			if globalSyslog != nil {
				globalSyslog.Close()
				globalSyslog = nil
			}
			syslogConfigured = ""
			auditEvent(r, "settings.syslog", "disabled", "")
			jsonOK(w, map[string]any{"ok": true, "addr": ""})
			return
		}
		if err := InitSyslog(body.Addr); err != nil {
			http.Error(w, "syslog connect error: "+err.Error(), http.StatusBadRequest)
			return
		}
		syslogConfigured = body.Addr
		auditEvent(r, "settings.syslog", body.Addr, "syslog forwarding enabled")
		jsonOK(w, map[string]any{"ok": true, "addr": body.Addr})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// GET/POST /api/security — IP filter + rate limiter config
func apiSecurity(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		jsonOK(w, map[string]any{
			"ipFilterMode": ipf.Mode(),
			"ipList":       ipf.List(),
			"rateLimitRPM": rl.Limit(),
			"rateLimitOn":  rl.Enabled(),
		})

	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			IPFilterMode string   `json:"ipFilterMode"` // "allow"|"block"|""
			IPAdd        string   `json:"ipAdd"`
			IPRemove     string   `json:"ipRemove"`
			RateLimitRPM int      `json:"rateLimitRPM"` // 0 = disable
			IPList       []string `json:"ipList"`       // full replace
		}
		if err := decodeJSON(r,&body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if body.IPFilterMode != "" {
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
		logger.Printf("UI: security config updated (ipMode=%s rateRPM=%d)", ipf.Mode(), rl.Limit())
		auditEvent(r, "security.update", "ip_filter+rate_limit",
			fmt.Sprintf("mode=%s rpm=%d", ipf.Mode(), rl.Limit()))
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
		})

	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			User string `json:"user"`
			Pass string `json:"pass"`
		}
		if err := decodeJSON(r,&body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if err := cfg.SetAuth(body.User, body.Pass); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		logger.Printf("UI: auth settings updated (user=%s)", body.User)
		auditEvent(r, "settings.update", "auth", fmt.Sprintf("user=%s", body.User))
		jsonOK(w, map[string]any{"ok": true})

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
		if err := decodeJSON(r,&rule); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		added := rewriter.Add(rule)
		logger.Printf("UI: rewrite rule added id=%d host=%q", added.ID, added.Host)
		auditEvent(r, "rewrite.add", fmt.Sprintf("id=%d host=%s", added.ID, added.Host), "")
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
		if err := decodeJSON(r,&rule); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if rule.Name == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
			return
		}
		if rule.Action == "" {
			http.Error(w, "action is required", http.StatusBadRequest)
			return
		}
		if rule.Schedule != nil && rule.Schedule.Timezone != "" {
			if _, err := time.LoadLocation(rule.Schedule.Timezone); err != nil {
				http.Error(w, "invalid schedule timezone: "+rule.Schedule.Timezone, http.StatusBadRequest)
				return
			}
		}
		added := policyStore.Add(rule)
		policyStore.Save()
		logger.Printf("UI: policy rule added priority=%d name=%q action=%s", added.Priority, added.Name, added.Action)
		auditEventDiff(r, "policy.add", added.Name,
			fmt.Sprintf("priority=%d action=%s", added.Priority, added.Action), nil, added)
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
		if err := decodeJSON(r,&rule); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if rule.Schedule != nil && rule.Schedule.Timezone != "" {
			if _, err := time.LoadLocation(rule.Schedule.Timezone); err != nil {
				http.Error(w, "invalid schedule timezone: "+rule.Schedule.Timezone, http.StatusBadRequest)
				return
			}
		}
		if !policyStore.Update(priority, rule) {
			http.Error(w, "rule not found", http.StatusNotFound)
			return
		}
		policyStore.Save()
		logger.Printf("UI: policy rule updated priority=%d name=%q", priority, rule.Name)
		auditEventDiff(r, "policy.update", rule.Name,
			fmt.Sprintf("priority=%d action=%s", priority, rule.Action), beforeRule, rule)
		jsonOK(w, map[string]any{"ok": true})

	case http.MethodDelete:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		priorityStr := strings.TrimSpace(r.URL.Query().Get("priority"))
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
	if err := decodeJSON(r,&body); err != nil {
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

	if matched == nil {
		defAction := defaultPolicyAction()
		jsonOK(w, map[string]any{
			"matched":       false,
			"defaultAction": defAction,
			"trace":         trace,
		})
		return
	}
	jsonOK(w, map[string]any{
		"matched": true,
		"rule":    matched,
		"action":  matched.Action,
		"trace":   trace,
	})
}

// GET /api/ca-cert — download the Root CA certificate (PEM) for browser/OS import.
// Also returns metadata: subject, expiry, SHA256 fingerprint.
func apiCACert(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
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
		w.Header().Set("Content-Disposition", `attachment; filename="proxyshield-ca.pem"`)
		w.Write(pem)
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
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // enforce 1 MB limit before parsing (G120)
	if err := r.ParseMultipartForm(1 << 20); err != nil {
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
			http.Error(w, "invalid CA cert/key: "+err.Error(), http.StatusBadRequest)
			return
		}
		auditEvent(r, "certs.upload_mitm", "custom MITM CA", "")
		jsonOK(w, map[string]string{"status": "ok", "target": "mitm"})
		return
	}
	// UI cert — validate only; actual rotation requires restart.
	if _, err := certMgr.ParseTLSPair(certPEM, keyPEM); err != nil {
		http.Error(w, "invalid cert/key pair: "+err.Error(), http.StatusBadRequest)
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
		logger.Printf("UI: default policy action set to %q", body.Action)
		jsonOK(w, map[string]string{"defaultAction": defaultPolicyAction()})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// GET /api/export?format=json|csv — download all logs
func apiExport(w http.ResponseWriter, r *http.Request) {
	entries := logGet()
	format := r.URL.Query().Get("format")
	ts := time.Now().Format("20060102-150405")

	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="proxyshield-%s.csv"`, ts))
		cw := csv.NewWriter(w)
		cw.Write([]string{"timestamp", "time", "ip", "method", "host", "status"})
		for _, e := range entries {
			cw.Write([]string{
				fmt.Sprintf("%d", e.TS),
				e.Time, e.IP, e.Method, e.Host, e.Status,
			})
		}
		cw.Flush()

	default: // json
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="proxyshield-%s.json"`, ts))
		json.NewEncoder(w).Encode(map[string]any{
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
//   GET    → {"patterns": [...], "count": N}
//   POST   → {"pattern": "*.co.il"} or {"patterns": ["*.co.il","~^.*\.gov\.il$"]}
//   DELETE → ?pattern=*.co.il
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
//   GET    → {"patterns": [...], "count": N, "blocked_total": N}
//   POST   → {"pattern": "evil-keyword"} or {"patterns": ["p1","p2"]}
//   DELETE → ?pattern=evil-keyword
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
		if err := decodeJSON(r,&body); err != nil {
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
				logger.Printf("UI: file block extension added %s", ext)
				added++
			}
		}
		auditEvent(r, "fileblock.add", fmt.Sprintf("%d extension(s)", added), "")
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
		logger.Printf("UI: file block extension removed %s", ext)
		auditEvent(r, "fileblock.remove", ext, "")
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
		logger.Printf("UI: IdP profile created id=%s name=%q type=%s", p.ID, p.Name, p.Type)
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
		logger.Printf("UI: IdP profile updated id=%s name=%q", id, p.Name)
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
		logger.Printf("UI: IdP profile deleted id=%s", id)
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
	id, err := oidcProv.ExchangeCode(code, state)
	if err != nil {
		logger.Printf("OIDC callback error: %v", err)
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}
	if err := setSessionCookie(w, id); err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	// Redirect to the original URL the user was trying to reach.
	relayURL := entry.relayURL
	if relayURL == "" || !isSafeRedirectURL(relayURL) {
		relayURL = "/"
	}
	logger.Printf("OIDC login OK: user=%s email=%s provider=%s", id.Sub, id.Email, id.Provider)
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
		if err := setSessionCookie(w, id); err != nil {
			http.Error(w, "session error", http.StatusInternalServerError)
			return
		}
		if relayURL == "" || !isSafeRedirectURL(relayURL) {
			relayURL = "/"
		}
		logger.Printf("SAML login OK: user=%s email=%s provider=%s", id.Sub, id.Email, id.Provider)
		http.Redirect(w, r, relayURL, http.StatusFound)
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
<meta charset="utf-8"><title>ProxyShield — Sign In</title>
<style>body{font-family:sans-serif;max-width:400px;margin:80px auto;padding:0 16px}
h1{font-size:1.4rem}a.btn{display:block;padding:12px 16px;margin:8px 0;border-radius:6px;
background:#2563eb;color:#fff;text-decoration:none;text-align:center}a.btn:hover{background:#1d4ed8}
</style></head><body><h1>Sign in to ProxyShield</h1>`)
	for _, p := range providers {
		loginURL := p.CaptiveLoginURL(relay)
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
	clearSessionCookie(w)
	http.Redirect(w, r, "/", http.StatusFound)
}
