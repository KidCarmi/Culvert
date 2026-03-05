package main

import (
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
	mux.HandleFunc("/api/blocklist", apiBlocklist)
	mux.HandleFunc("/api/settings", apiSettings)
	mux.HandleFunc("/api/security", apiSecurity)

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: corsMiddleware(mux),
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

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
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

// GET /api/logs?limit=N&filter=...&status=...
func apiLogs(w http.ResponseWriter, r *http.Request) {
	all := logGet()
	filterHost := strings.ToLower(r.URL.Query().Get("filter"))
	filterStatus := strings.ToUpper(r.URL.Query().Get("status"))

	filtered := all[:0:0]
	for _, e := range all {
		if filterHost != "" && !strings.Contains(strings.ToLower(e.Host), filterHost) &&
			!strings.Contains(strings.ToLower(e.IP), filterHost) {
			continue
		}
		if filterStatus != "" && e.Status != filterStatus {
			continue
		}
		filtered = append(filtered, e)
	}
	jsonOK(w, map[string]any{"logs": filtered, "total": len(filtered)})
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
		u, _ := cfg.GetAuth()
		jsonOK(w, map[string]any{
			"authEnabled": cfg.AuthEnabled(),
			"user":        u,
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
		cfg.SetAuth(body.User, body.Pass)
		logger.Printf("UI: auth settings updated (user=%s)", body.User)
		jsonOK(w, map[string]any{"ok": true})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
