package main

import (
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
	mux.HandleFunc("/api/ca-cert", apiCACert)
	mux.HandleFunc("/api/certs/upload", apiCertsUpload)
	mux.HandleFunc("/api/ssl-bypass", apiSSLBypass)
	mux.HandleFunc("/api/content-scan", apiContentScan)
	mux.HandleFunc("/api/audit", apiAudit)
	mux.HandleFunc("/api/events", apiEvents)           // SSE live dashboard
	mux.HandleFunc("/api/country-traffic", apiCountryTraffic)
	mux.HandleFunc("/api/default-action", apiDefaultAction)

	// ── Admin session auth ────────────────────────────────────────────────
	mux.HandleFunc("/api/auth/login", apiAuthLogin)
	mux.HandleFunc("/api/auth/status", apiAuthStatus)
	mux.HandleFunc("/api/auth/logout", apiAuthLogout)

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
		Handler:      securityMiddleware(uiAuthMiddleware(mux)),
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

// uiAuthMiddleware gates /api/ endpoints with session-cookie auth.
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
			next.ServeHTTP(w, r)
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
			next.ServeHTTP(w, r)
			return
		}
		// Fallback: HTTP Basic Auth for programmatic / CLI access.
		user, pass, ok := r.BasicAuth()
		if ok && cfg.VerifyAuth(user, pass) {
			next.ServeHTTP(w, r)
			return
		}
		// No valid auth — 401 without WWW-Authenticate: Basic so the browser
		// does NOT show its native credential dialog.
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}

// ── UI admin session cookie ───────────────────────────────────────────────
// Separate from the proxy-user ps_session cookie; same HMAC encoding.

const uiSessionCookieName = "ps_ui_session"

func setUISessionCookie(w http.ResponseWriter, username string) error {
	s := &Session{
		Sub:      username,
		Provider: "local",
		Exp:      time.Now().Add(sessionTTL).Unix(),
	}
	value, err := encodeSession(s)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     uiSessionCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   int(sessionTTL.Seconds()),
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
	if !cfg.AuthEnabled() || cfg.VerifyAuth(body.User, body.Pass) {
		if err := setUISessionCookie(w, body.User); err != nil {
			http.Error(w, "session error", http.StatusInternalServerError)
			return
		}
		auditEvent(r, "auth.login", body.User, "admin UI login")
		jsonOK(w, map[string]any{"ok": true, "user": body.User})
		return
	}
	time.Sleep(300 * time.Millisecond) // slow down brute-force
	http.Error(w, "Invalid credentials", http.StatusUnauthorized)
}

// GET /api/auth/status — return whether the current request has a valid session.
func apiAuthStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !cfg.AuthEnabled() {
		jsonOK(w, map[string]any{"loggedIn": true, "user": ""})
		return
	}
	sess, err := readUISessionCookie(r)
	if err == nil && sess != nil {
		jsonOK(w, map[string]any{"loggedIn": true, "user": sess.Sub})
		return
	}
	// Accept Basic Auth header for CLI/API callers.
	user, pass, ok := r.BasicAuth()
	if ok && cfg.VerifyAuth(user, pass) {
		jsonOK(w, map[string]any{"loggedIn": true, "user": user})
		return
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
	clearUISessionCookie(w)
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

// POST /api/setup/complete — sets the initial admin credential.
// Only callable once; returns 403 if auth is already configured.
// Body: {"user": "...", "pass": "..."}
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
		User string `json:"user"`
		Pass string `json:"pass"`
	}
	if err := decodeJSON(r, &body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
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
	_ = setUISessionCookie(w, body.User)
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
	jsonOK(w, map[string]any{"data": tsGet()})
}

// GET /api/logs?filter=...&status=...&level=...&method=...
func apiLogs(w http.ResponseWriter, r *http.Request) {
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
		added := policyStore.Add(rule)
		policyStore.Save()
		logger.Printf("UI: policy rule added priority=%d name=%q action=%s", added.Priority, added.Name, added.Action)
		auditEventDiff(r, "policy.add", added.Name,
			fmt.Sprintf("priority=%d action=%s", added.Priority, added.Action), nil, added)
		jsonOK(w, added)

	case http.MethodPut:
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
		jsonOK(w, idpRegistry.All())
	case http.MethodPost:
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
		p := idpRegistry.Get(id)
		if p == nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		jsonOK(w, p)
	case http.MethodPut:
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
func apiIdPDiscover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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
