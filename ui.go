package main

import (
	"encoding/csv"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
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
	mux.HandleFunc("/api/stats", apiStats)
	mux.HandleFunc("/api/timeseries", apiTimeseries)
	mux.HandleFunc("/api/logs", apiLogs)
	mux.HandleFunc("/api/top-hosts", apiTopHosts)
	mux.HandleFunc("/api/blocklist", apiBlocklist)
	mux.HandleFunc("/api/settings", apiSettings)
	mux.HandleFunc("/api/security", apiSecurity)
	mux.HandleFunc("/api/export", apiExport)
	mux.HandleFunc("/api/rewrite", apiRewrite)

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler:      securityMiddleware(mux),
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
// CORS: only the same origin the browser loaded the UI from is allowed
// (no wildcard *). Preflight requests are answered with the caller's origin.
func securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// ── Security headers ─────────────────────────────────────────────────
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; img-src 'self' data:")

		// ── CORS: reflect the request origin only (no wildcard) ──────────────
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Access-Control-Max-Age", "86400")
			w.Header().Set("Vary", "Origin")
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
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
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
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
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
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
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if err := cfg.SetAuth(body.User, body.Pass); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		logger.Printf("UI: auth settings updated (user=%s)", body.User)
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
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		added := rewriter.Add(rule)
		logger.Printf("UI: rewrite rule added id=%d host=%q", added.ID, added.Host)
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
		w.WriteHeader(http.StatusNoContent)

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
