package main

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
)

// handleMetrics serves Prometheus-compatible text metrics on GET /metrics.
// No external library needed — Prometheus text format is simple.
func handleMetrics(w http.ResponseWriter, r *http.Request) {
	total   := atomic.LoadInt64(&statTotal)
	blocked := atomic.LoadInt64(&statBlocked)
	authFail := atomic.LoadInt64(&statAuthFail)
	allowed := total - blocked - authFail
	if allowed < 0 {
		allowed = 0
	}

	rlLimit := int64(rl.Limit())
	rlEnabled := int64(0)
	if rl.Enabled() {
		rlEnabled = 1
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprintf(w, `# HELP proxyshield_requests_total Total proxy requests
# TYPE proxyshield_requests_total counter
proxyshield_requests_total %d

# HELP proxyshield_requests_allowed Total allowed requests
# TYPE proxyshield_requests_allowed counter
proxyshield_requests_allowed %d

# HELP proxyshield_requests_blocked Total blocked requests (domain + IP)
# TYPE proxyshield_requests_blocked counter
proxyshield_requests_blocked %d

# HELP proxyshield_requests_auth_fail Total auth failures
# TYPE proxyshield_requests_auth_fail counter
proxyshield_requests_auth_fail %d

# HELP proxyshield_blocklist_size Current number of blocked domains
# TYPE proxyshield_blocklist_size gauge
proxyshield_blocklist_size %d

# HELP proxyshield_uptime_seconds Proxy uptime in seconds
# TYPE proxyshield_uptime_seconds gauge
proxyshield_uptime_seconds %.0f

# HELP proxyshield_rate_limit_rpm Configured rate limit (requests per minute, 0=disabled)
# TYPE proxyshield_rate_limit_rpm gauge
proxyshield_rate_limit_rpm %d

# HELP proxyshield_rate_limit_enabled Whether rate limiting is active
# TYPE proxyshield_rate_limit_enabled gauge
proxyshield_rate_limit_enabled %d
`,
		total, allowed, blocked, authFail,
		int64(bl.Count()),
		time.Since(startTime).Seconds(),
		rlLimit, rlEnabled,
	)
}
