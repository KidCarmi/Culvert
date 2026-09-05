package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/alerts"
	"github.com/KidCarmi/Culvert/internal/logstore"
	"github.com/KidCarmi/Culvert/internal/reqlog"
	"github.com/KidCarmi/Culvert/internal/secscan"
	"github.com/KidCarmi/Culvert/internal/sse"
)

// hub manages the Server-Sent Events (SSE) connections for the live
// dashboard. Clients connect to /api/events and receive JSON stats every
// second. The hub engine (registration cap, slow-client eviction, counters)
// lives in internal/sse (ADR-0002); this file keeps the broadcaster (which
// assembles the payload from main's stats), the handler, and the /metrics
// exposition.
var hub = sse.NewHub()

// sseWriteTimeout bounds each SSE frame write. The dashboard ticks every 1 s,
// so a healthy client drains well within this window; a half-open TCP peer
// (client gone, no RST — and SSE runs with WriteTimeout 0) would otherwise
// block the handler goroutine forever on a full socket buffer.
const sseWriteTimeout = 10 * time.Second

// DashboardPayload is sent to SSE clients every second.
type DashboardPayload struct {
	ActiveConns       int64          `json:"activeConns"`
	TotalRequests     int64          `json:"totalRequests"`
	Blocked           int64          `json:"blocked"`
	AuthFail          int64          `json:"authFail"`
	RPS               float64        `json:"rps"` // requests per second (1-min avg)
	TopCountries      []CountryCount `json:"topCountries"`
	UptimeSec         int64          `json:"uptimeSec"`
	ClamBlocked       int64          `json:"clamBlocked"`
	YARABlocked       int64          `json:"yaraBlocked"`
	DPIBlocked        int64          `json:"dpiBlocked"`
	ThreatFeedBlocked int64          `json:"threatFeedBlocked"`
}

// sseBroadcaster owns the live-dashboard ticker that pushes DashboardPayload
// updates to the global SSE hub. The goroutine exits when its context is
// cancelled — which is the only stop signal in production (appLifecycleCtx
// is cancelled by runProxyUntilShutdown). P1.2 / S4.SSE.
type sseBroadcaster struct {
	interval time.Duration
	done     chan struct{}
}

// newSSEBroadcaster returns a broadcaster that ticks at the given interval.
// Production callers use time.Second; tests pass a smaller interval to keep
// cancellation tests fast without changing production behaviour.
func newSSEBroadcaster(interval time.Duration) *sseBroadcaster {
	return &sseBroadcaster{
		interval: interval,
		done:     make(chan struct{}),
	}
}

// Done returns a channel that is closed after run returns. Because
// ticker.Stop is deferred before close(done) (defers run in LIFO order),
// the implementation stops the ticker before Done closes.
func (b *sseBroadcaster) Done() <-chan struct{} { return b.done }

// run blocks until ctx is cancelled. Stops the underlying ticker and closes
// b.done on exit. Must not be called more than once on the same broadcaster.
func (b *sseBroadcaster) run(ctx context.Context) {
	defer close(b.done)
	ticker := time.NewTicker(b.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.tick()
		}
	}
}

// tick assembles one DashboardPayload and broadcasts it to the SSE hub.
// Skipped silently when no clients are connected. Body is byte-equivalent
// to the original startSSEBroadcaster ticker body — payload schema, hub
// behaviour, and dashboard contract are unchanged.
func (b *sseBroadcaster) tick() {
	if hub.ClientCount() == 0 {
		return
	}
	series, _, _ := tsGet()
	var sum int64
	for _, v := range series {
		sum += v
	}
	rps := float64(sum) / 60.0

	scanCounters := secscan.Counters()
	payload := DashboardPayload{
		ActiveConns:       getActiveConns(),
		TotalRequests:     atomic.LoadInt64(&statTotal),
		Blocked:           atomic.LoadInt64(&statBlocked),
		AuthFail:          atomic.LoadInt64(&statAuthFail),
		RPS:               rps,
		TopCountries:      countryTraffic.Top(15),
		UptimeSec:         int64(time.Since(startTime).Seconds()),
		ClamBlocked:       scanCounters.ClamBlocked,
		YARABlocked:       scanCounters.YARABlocked,
		DPIBlocked:        atomic.LoadInt64(&statDPIBlocked),
		ThreatFeedBlocked: scanCounters.ThreatFeedBlocked,
	}
	data, _ := json.Marshal(payload)
	hub.Broadcast(data)
}

// startSSEBroadcaster spawns the live-dashboard broadcaster goroutine
// parented to ctx. Production interval is 1 s. Returns the *sseBroadcaster
// so tests (and, eventually, the Phase 2 shutdown registry) can wait on
// Done(). The production caller in initBackgroundServices discards the
// handle; the goroutine exits when appLifecycleCtx is cancelled.
func startSSEBroadcaster(ctx context.Context) *sseBroadcaster {
	b := newSSEBroadcaster(time.Second)
	go b.run(ctx)
	return b
}

// sseRevalidateEvery is the number of received broadcast messages (~seconds at
// the 1 s production tick) between mid-stream auth re-checks in apiEvents.
const sseRevalidateEvery = 60

// sseAuthStillValid re-checks the caller's credentials mid-stream. An SSE
// connection outlives the connect-time requireRole check, so a revoked or
// expired session (or a deleted user) must terminate the stream instead of
// receiving live telemetry until it disconnects on its own.
func sseAuthStillValid(r *http.Request) bool {
	if !cfg.AuthEnabled() {
		return true
	}
	sess, err := readUISessionCookie(r)
	if err != nil {
		return false // revoked, expired, or tampered session
	}
	if sess != nil {
		if sess.Provider == "local" && !cfg.UIUserExists(sess.Sub) {
			return false
		}
		return true
	}
	// No session cookie — the connection was authenticated via HTTP Basic Auth.
	if user, pass, ok := r.BasicAuth(); ok {
		_, valid := cfg.VerifyUIUser(user, pass)
		return valid
	}
	return false
}

// apiEvents is the SSE endpoint. Clients connect and receive live dashboard data.
func apiEvents(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleViewer) {
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	ch := make(chan []byte, 4)
	if !hub.Register(ch) {
		hub.AddRejected()
		w.Header().Set("Retry-After", "30")
		http.Error(w, "too many live dashboard connections", http.StatusServiceUnavailable)
		return
	}
	defer hub.Unregister(ch)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// Disable proxy buffering (nginx et al.) so frames stream in real time
	// instead of being held back until an upstream buffer fills.
	w.Header().Set("X-Accel-Buffering", "no")
	// Restrict SSE to same-origin requests only (no CORS wildcard).
	// The dashboard is served from the same origin, so no CORS header is needed.

	// writeFrame writes one SSE frame under a per-write deadline and reports
	// whether the client is still healthy. A failed/timed-out write means the
	// peer is gone, so the caller returns and the deferred unregister runs.
	// SetWriteDeadline is best-effort: writers that don't support it (e.g. the
	// httptest recorder) return an error we intentionally ignore.
	rc := http.NewResponseController(w)
	writeFrame := func(s string) bool {
		_ = rc.SetWriteDeadline(time.Now().Add(sseWriteTimeout))
		if _, err := w.Write([]byte(s)); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}

	// Send an initial ping so the client knows we're connected.
	if !writeFrame("event: connected\ndata: {}\n\n") {
		return
	}

	msgs := 0
	for {
		select {
		case msg, open := <-ch:
			if !open {
				// Evicted by the hub as a slow client. End the stream so the
				// browser reconnects — receiving from the closed channel would
				// otherwise busy-spin and flood the peer with empty frames.
				return
			}
			if !writeFrame("data: " + string(msg) + "\n\n") {
				return
			}
			msgs++
			if msgs >= sseRevalidateEvery {
				msgs = 0
				if !sseAuthStillValid(r) {
					return
				}
			}
		case <-r.Context().Done():
			return
		}
	}
}

// liveFeedWritePrometheus appends live-feed observability metrics (SSE hub +
// persistent request log) to the /metrics exposition.
func liveFeedWritePrometheus(w *strings.Builder) {
	fmt.Fprintf(w, "\n# HELP culvert_sse_clients Currently connected SSE dashboard clients\n")
	fmt.Fprintf(w, "# TYPE culvert_sse_clients gauge\nculvert_sse_clients %d\n", hub.ClientCount())
	fmt.Fprintf(w, "\n# HELP culvert_sse_evictions_total SSE clients evicted for falling behind the broadcast\n")
	fmt.Fprintf(w, "# TYPE culvert_sse_evictions_total counter\nculvert_sse_evictions_total %d\n", hub.Evicted())
	fmt.Fprintf(w, "\n# HELP culvert_sse_rejected_total SSE connections rejected at the client cap\n")
	fmt.Fprintf(w, "# TYPE culvert_sse_rejected_total counter\nculvert_sse_rejected_total %d\n", hub.Rejected())
	fmt.Fprintf(w, "\n# HELP culvert_reqlog_write_errors_total Persistent request-log write or marshal failures (e.g. disk full)\n")
	fmt.Fprintf(w, "# TYPE culvert_reqlog_write_errors_total counter\nculvert_reqlog_write_errors_total %d\n", reqlog.WriteErrors())
	fmt.Fprintf(w, "\n# HELP culvert_reqlog_backpressure_total Request-log entries that had to wait for room in the async persistence queue (JSONL sink not keeping up)\n")
	fmt.Fprintf(w, "# TYPE culvert_reqlog_backpressure_total counter\nculvert_reqlog_backpressure_total %d\n", reqlog.Backpressure())
	fmt.Fprintf(w, "\n# HELP culvert_reqlog_skipped_lines_total Corrupt JSONL lines skipped while reading the persistent request log\n")
	fmt.Fprintf(w, "# TYPE culvert_reqlog_skipped_lines_total counter\nculvert_reqlog_skipped_lines_total %d\n", reqlog.SkippedLines())
	fmt.Fprintf(w, "\n# HELP culvert_audit_write_errors_total Admin-action audit entries that never reached the persistent JSONL file (disk full, read-only volume, failed reopen). Non-zero means the durable compliance record is incomplete\n")
	fmt.Fprintf(w, "# TYPE culvert_audit_write_errors_total counter\nculvert_audit_write_errors_total %d\n", auditWriteErrors())
	fmt.Fprintf(w, "\n# HELP culvert_logstore_dropped_total History-store entries dropped because the async write queue was full\n")
	fmt.Fprintf(w, "# TYPE culvert_logstore_dropped_total counter\nculvert_logstore_dropped_total %d\n", logstore.Dropped())
	fmt.Fprintf(w, "\n# HELP culvert_logstore_pruned_total History-store entries deleted by the size-retention janitor\n")
	fmt.Fprintf(w, "# TYPE culvert_logstore_pruned_total counter\nculvert_logstore_pruned_total %d\n", logstore.Pruned())
	fmt.Fprintf(w, "\n# HELP culvert_logsink_backpressure_total Process-log lines that had to wait for room in the async log queue (stdout/log file not keeping up, so request latency is coupled to it again)\n")
	fmt.Fprintf(w, "# TYPE culvert_logsink_backpressure_total counter\nculvert_logsink_backpressure_total %d\n", logSinkBackpressure())
	fmt.Fprintf(w, "\n# HELP culvert_logsink_write_errors_total Process-log lines (console + process log file, e.g. POLICY_ALLOW/BLOCK/DROP entries) that never reached their destination writer. Non-zero means the process-log record is incomplete\n")
	fmt.Fprintf(w, "# TYPE culvert_logsink_write_errors_total counter\nculvert_logsink_write_errors_total %d\n", logSinkWriteErrors())
	fmt.Fprintf(w, "\n# HELP culvert_alert_dedup_evictions_total Alert dedup keys evicted at the cap (CHAOS-27). Non-zero means the alert key space is being flooded with unique details (scanning wave) and duplicate suppression is degraded — alerts may deliver more than once per window, never fewer\n")
	fmt.Fprintf(w, "# TYPE culvert_alert_dedup_evictions_total counter\nculvert_alert_dedup_evictions_total %d\n", alerts.DedupEvictionsTotal())
	fmt.Fprintf(w, "\n# HELP culvert_alert_dedup_tracked Alert dedup keys currently tracked inside the suppression window (bounded by the cap)\n")
	fmt.Fprintf(w, "# TYPE culvert_alert_dedup_tracked gauge\nculvert_alert_dedup_tracked %d\n", globalAlertStore.DedupTracked())

	// Interactive-login state stores (OIDC PKCE / SAML AuthnRequest). These are
	// populated by UNAUTHENTICATED requests, so a rising eviction counter is the
	// operator's signal that in-flight login state is being displaced before it
	// can be redeemed — either the cap is too small for the deployment, or
	// something is flooding the captive-portal path. Fair-share eviction keeps a
	// single flooding source evicting only itself (internal/authstate), so a
	// climbing counter alongside a low client count localises the source.
	fmt.Fprintf(w, "\n# HELP culvert_login_state_entries In-flight interactive-login callback state currently held, by store\n")
	fmt.Fprintf(w, "# TYPE culvert_login_state_entries gauge\nculvert_login_state_entries{store=\"oidc_pkce\"} %d\nculvert_login_state_entries{store=\"saml\"} %d\n",
		globalPKCEStore.Len(), globalSAMLStateStore.Len())
	fmt.Fprintf(w, "\n# HELP culvert_login_state_clients Distinct client keys currently holding interactive-login callback state, by store\n")
	fmt.Fprintf(w, "# TYPE culvert_login_state_clients gauge\nculvert_login_state_clients{store=\"oidc_pkce\"} %d\nculvert_login_state_clients{store=\"saml\"} %d\n",
		globalPKCEStore.Clients(), globalSAMLStateStore.Clients())
	fmt.Fprintf(w, "\n# HELP culvert_login_state_evictions_total Interactive-login callback state dropped at the cap before it could be redeemed. Non-zero means some SSO logins failed with \"invalid or expired state\"\n")
	fmt.Fprintf(w, "# TYPE culvert_login_state_evictions_total counter\nculvert_login_state_evictions_total{store=\"oidc_pkce\"} %d\nculvert_login_state_evictions_total{store=\"saml\"} %d\n",
		globalPKCEStore.Evictions(), globalSAMLStateStore.Evictions())

	// CHAOS-58: admin logins refused for an over-long username. The admin login
	// endpoint is public, and an unbounded username there was an unauthenticated
	// write amplifier into the lockout maps and the durable audit log. The
	// rejection is otherwise invisible (the caller gets a 400), so a climbing
	// counter is the operator's only signal that a source is probing it.
	fmt.Fprintf(w, "\n# HELP culvert_login_oversize_rejected_total Admin login attempts refused because the submitted username exceeded the byte limit. Sustained growth means an unauthenticated source is probing /api/auth/login\n")
	fmt.Fprintf(w, "# TYPE culvert_login_oversize_rejected_total counter\nculvert_login_oversize_rejected_total %d\n",
		loginOversizeRejected.Load())
}

// apiCountryTraffic returns the top destination countries for the dashboard.
func apiCountryTraffic(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleViewer) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(countryTraffic.Top(20))
}
