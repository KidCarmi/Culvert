package main

import (
	"encoding/csv"
	"embed"
	"encoding/json"
	"fmt"
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

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler:      securityMiddleware(uiAuthMiddleware(mux)),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
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
// CORS: only localhost origins are permitted — the UI is an admin panel and
// must never be reachable from arbitrary third-party sites.
func securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// ── Security headers ─────────────────────────────────────────────────
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; img-src 'self' data:")

		// ── CORS: allow only localhost origins (explicit allowlist) ──────────
		origin := r.Header.Get("Origin")
		if isLocalOrigin(origin) {
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

		// ── CSRF: reject state-changing requests that carry a non-local Origin.
		// Browsers always send Origin on cross-site requests; if it's present and
		// not localhost the request is a cross-site forgery attempt.
		// Requests without Origin (same-origin browser navigation, server-side
		// tools, curl) are allowed — they cannot be cross-site browser requests.
		isMutating := r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete
		if origin != "" && !isLocalOrigin(origin) && isMutating {
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

// isLocalOrigin returns true only for loopback-host origins (http or https),
// preventing cross-site requests from arbitrary external domains.
func isLocalOrigin(origin string) bool {
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	h := u.Hostname()
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

// uiAuthMiddleware enforces Basic Auth for all /api/ endpoints when auth is
// enabled.  The /api/setup/* bootstrap endpoints are always accessible so
// that a brand-new deployment can complete first-time setup without a
// chicken-and-egg problem.  Static assets (/) are never gated.
func uiAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Setup bootstrap — always public.
		if strings.HasPrefix(r.URL.Path, "/api/setup") {
			next.ServeHTTP(w, r)
			return
		}
		// Auth not yet configured (first-time or intentionally disabled).
		if !cfg.AuthEnabled() {
			next.ServeHTTP(w, r)
			return
		}
		// Enforce Basic Auth for all API requests.
		if strings.HasPrefix(r.URL.Path, "/api/") {
			user, pass, ok := r.BasicAuth()
			if !ok || !cfg.VerifyAuth(user, pass) {
				w.Header().Set("WWW-Authenticate", `Basic realm="ProxyShield"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
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
	// Use authenticated username from UI session if available.
	if u := r.Header.Get("X-UI-User"); u != "" {
		actor = u
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
		if body.IPFilterMode != "" || body.IPFilterMode == "" {
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
		jsonOK(w, map[string]any{"rules": rules, "count": len(rules)})

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
		jsonOK(w, map[string]string{"defaultAction": defaultPolicyAction})
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
		jsonOK(w, map[string]string{"defaultAction": defaultPolicyAction})
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
