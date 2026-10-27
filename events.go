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
	"github.com/KidCarmi/Culvert/internal/session"
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
		// The SAME admission decision the connect-time gate made
		// (classifyUISession, SEC-UISESS-1), not a restatement of it: a
		// deleted user, a foreign-provider token or a role this build does
		// not enroll ends the stream.
		_, verdict := classifyUISession(sess)
		return verdict == uiSessionValid
	}
	// No session cookie — the connection was authenticated via HTTP Basic Auth.
	if user, pass, ok := r.BasicAuth(); ok {
		// SEC-BASIC-1: same refusals as every other admin-plane Basic site.
		// SEC-BASICAUTH-5 (RISK-032): through the LIVENESS wrapper, which
		// refuses exactly as the submission path does but reserves no per-IP
		// budget and records nothing against the lockout. These headers were
		// captured when the stream was established and cannot change, so a
		// re-check is never a new guess. See revalidateUIBasicAuth.
		_, valid := revalidateUIBasicAuth(r, user, pass)
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
	fmt.Fprintf(w, "\n# HELP culvert_audit_cluster_push_drops_total Audit entries discarded from the Data Plane→Control Plane push queue at its cap (Control Plane unreachable). Non-zero means the CENTRALIZED audit trail is incomplete; the local JSONL file on this node is unaffected\n")
	fmt.Fprintf(w, "# TYPE culvert_audit_cluster_push_drops_total counter\nculvert_audit_cluster_push_drops_total %d\n", auditPendingDrops())
	fmt.Fprintf(w, "\n# HELP culvert_admin_roster_role_clamped_total Admin roster records whose persisted role this build does not enroll, clamped to viewer at load (SEC-RBAC-ROLE-1). Non-zero means ui_users.json names a role this binary cannot grant — a restore from a newer build, or a hand-edited/corrupt roster\n")
	rosterRoleClamps := RosterRoleClampCount()
	fmt.Fprintf(w, "# TYPE culvert_admin_roster_role_clamped_total counter\nculvert_admin_roster_role_clamped_total %d\n", rosterRoleClamps)
	// Pre-T-64 name, shipped since v1.0.252: kept as a deprecated alias for one
	// release window so existing dashboards and alert rules keep the series.
	fmt.Fprintf(w, "\n# HELP culvert_ui_roster_role_clamped_total Deprecated alias of culvert_admin_roster_role_clamped_total (T-64); same value, removed after one release window\n")
	fmt.Fprintf(w, "# TYPE culvert_ui_roster_role_clamped_total counter\nculvert_ui_roster_role_clamped_total %d\n", rosterRoleClamps)
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

	// CHAOS-63: admin logins refused for an over-long username. The admin login
	// endpoint is public, and an unbounded username there was an unauthenticated
	// write amplifier into the lockout maps and the durable audit log. The
	// rejection is otherwise invisible (the caller gets a 400), so a climbing
	// counter is the operator's only signal that a source is probing it.
	fmt.Fprintf(w, "\n# HELP culvert_login_oversize_rejected_total Admin login attempts refused because the submitted username exceeded the byte limit. Sustained growth means an unauthenticated source is probing /api/auth/login\n")
	fmt.Fprintf(w, "# TYPE culvert_login_oversize_rejected_total counter\nculvert_login_oversize_rejected_total %d\n",
		loginOversizeRejected.Load())

	// CHAOS-69: proxied requests refused for an over-long destination
	// authority. Unlike the login counter above this one is ALWAYS emitted —
	// there is no configuration to gate it on (every build bounds the
	// authority), so a flat zero means "nothing has been probed", never "the
	// feature is off". The caller gets a 400 (or a SOCKS5 failure reply) and
	// nothing else moves, so a climbing counter is the operator's only signal
	// that a client is sending authorities no resolver could answer for — the
	// shape of a CPU-exhaustion probe against the proxy port.
	fmt.Fprintf(w, "\n# HELP culvert_proxy_oversize_host_rejected_total Requests refused because the client-supplied destination authority exceeded the byte limit. Sustained growth means a client is probing the proxy port with unresolvable oversize hosts\n")
	fmt.Fprintf(w, "# TYPE culvert_proxy_oversize_host_rejected_total counter\nculvert_proxy_oversize_host_rejected_total %d\n",
		proxyOversizeHostRejected.Load())

	// Inner requests on a TLS-inspected tunnel whose Host/:authority did not
	// name the CONNECT target policy authorized. Always emitted, for the same
	// reason as the counter above: the pin is unconditional in every build, so a
	// flat zero means "no client has done this", never "the gate is off". A
	// conforming client cannot trip it — the forged leaf names exactly one host
	// — so sustained growth is a client reusing an authorized tunnel to reach a
	// destination the policy engine never evaluated.
	fmt.Fprintf(w, "\n# HELP culvert_proxy_inner_host_mismatch_blocked_total Inner requests on an inspected tunnel refused because their Host/:authority did not match the authorized CONNECT destination. A conforming client cannot trip this; sustained growth means tunnel reuse against an unevaluated destination\n")
	fmt.Fprintf(w, "# TYPE culvert_proxy_inner_host_mismatch_blocked_total counter\nculvert_proxy_inner_host_mismatch_blocked_total %d\n",
		proxyInnerHostMismatchBlocked.Load())

	// CHAOS-70: admin-roster durability. These are deliberately distinct from
	// the storage plane's generic storage_write_failed, which says only that
	// SOME durable write failed; these say WHICH administrative decision was
	// affected and therefore what the operator must redo.
	//
	// Both are emitted unconditionally: unlike the gauges elsewhere in this
	// file, a flat zero here is the healthy steady state for every appliance
	// (no roster write has failed), not an ambiguous "feature not configured".
	fmt.Fprintf(w, "\n# HELP culvert_admin_roster_persist_failures_total Admin-roster changes REFUSED and rolled back because ui_users.json could not be written. Non-zero means an operator's account/role/password change did not take effect and must be retried once the data volume is writable\n")
	fmt.Fprintf(w, "# TYPE culvert_admin_roster_persist_failures_total counter\nculvert_admin_roster_persist_failures_total %d\n",
		rosterPersistRefused.Load())
	fmt.Fprintf(w, "\n# HELP culvert_admin_roster_persist_degraded_total Login-path admin-roster writes that failed while the login was allowed to proceed (TOTP replay counter, backup-code consumption). Non-zero means a single-use credential or replay counter may not survive a restart\n")
	fmt.Fprintf(w, "# TYPE culvert_admin_roster_persist_degraded_total counter\nculvert_admin_roster_persist_degraded_total %d\n",
		rosterPersistBestEffort.Load())

	// CHAOS-73: the session-revocation plane. `/api/auth/logout` is PUBLIC by
	// design, and it used to insert whatever cookie it was handed into the
	// revocation list — key bytes, key length and expiry all chosen by an
	// unauthenticated caller, then persisted and gossiped fleet-wide. The
	// cookie must now carry a valid HMAC; a refusal is otherwise INVISIBLE
	// (the caller still gets its 200 and its cleared cookie, because a
	// refusal must not tell a prober whether the cookie was genuine), so
	// this counter is the operator's only signal that the endpoint is being
	// probed.
	//
	// Always emitted: there is no configuration to gate it on, so a flat zero
	// means "nothing has been probed" and never "the feature is off" — the
	// same rule as culvert_proxy_oversize_host_rejected_total above, and the
	// inverse of the armed-only gauges elsewhere in this file.
	writeSessionRevokeMetrics(w)
	fmt.Fprintf(w, "\n# HELP culvert_session_revocations_tracked Session revocation entries currently held. Bounded by real logins inside one session TTL; a value tracking request rate rather than login rate means something is inserting entries that are not sessions\n")
	fmt.Fprintf(w, "# TYPE culvert_session_revocations_tracked gauge\nculvert_session_revocations_tracked %d\n", sessionRevoked.Tracked())
	fmt.Fprintf(w, "\n# HELP culvert_cluster_revocation_drops_total Revocation entries the Control Plane refused to retain from a Data Plane node (over-long key, or past the per-node cap). Non-zero means a session an operator revoked may still authenticate on other nodes\n")
	fmt.Fprintf(w, "# TYPE culvert_cluster_revocation_drops_total counter\nculvert_cluster_revocation_drops_total %d\n", clusterRevocationDropTotal())
	writeRevocationSyncDeferredMetrics(w)

	// SEC-REQID-1: client-supplied tracing headers replaced because they were
	// over-long or carried bytes that must not reach a log line. The request
	// still proceeds — only the correlation id is ours instead of theirs — so
	// this counter is the operator's ONLY signal that a source is feeding the
	// data plane hostile tracing headers. Two fixed series, never a label
	// derived from the rejected value.
	fmt.Fprintf(w, "\n# HELP culvert_tracing_header_rejected_total Client-supplied tracing headers replaced with a generated value because they exceeded the byte limit or carried non-visible-ASCII bytes. Sustained growth means a source is attempting log forgery or log-write amplification through the proxy data plane\n")
	fmt.Fprintf(w, "# TYPE culvert_tracing_header_rejected_total counter\nculvert_tracing_header_rejected_total{header=\"x_request_id\"} %d\nculvert_tracing_header_rejected_total{header=\"traceparent\"} %d\n",
		requestIDRejected.Load(), traceparentRejected.Load())

	// CHAOS-92: client-supplied request paths clamped before being retained in
	// the process log, a block page or the request-log URI. Always emitted, for
	// the same reason as the oversize-host counter above: the clamp is
	// unconditional in every build, so a flat zero means "no client has sent a
	// path over the limit", never "the bound is off". The request itself is
	// unaffected — enforcement still sees the whole path — so this counter is
	// the operator's only aggregate signal that a source is attempting
	// log-write and response-body amplification through the proxy data plane.
	// The truncation is also visible inline, in the record it happened to.
	fmt.Fprintf(w, "\n# HELP culvert_retained_path_truncated_total Client-supplied request paths clamped before being retained in a log line, a block page or the request-log URI. Sustained growth means a source is attempting write amplification through the proxy data plane\n")
	fmt.Fprintf(w, "# TYPE culvert_retained_path_truncated_total counter\nculvert_retained_path_truncated_total %d\n",
		retainedPathTruncated.Load())

	// AU-17b: the live size of the admin credential lockout state. Its keys
	// are usernames an UNAUTHENTICATED caller chooses (the public GET on
	// /api/auth/status accepts Basic), so the entry count is a security
	// observable: the per-IP Basic failure budget bounds how fast one source
	// can grow it, and this gauge is how an operator sees a source cycling
	// usernames rather than guessing passwords.
	fmt.Fprintf(w, "\n# HELP culvert_login_limiter_entries Live tier-1 (IP, username) pair plus tier-2 account entries held by the admin credential lockout\n")
	fmt.Fprintf(w, "# TYPE culvert_login_limiter_entries gauge\nculvert_login_limiter_entries %d\n",
		loginLimiter.EntryCount())
}

// apiCountryTraffic returns the top destination countries for the dashboard.
func apiCountryTraffic(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleViewer) {
		return
	}
	jsonOK(w, countryTraffic.Top(20))
}

// sessionRevokeReasons is the fixed, bounded label set of the per-reason
// refusal series. It never grows from caller input (WK-12/RS-5).
var sessionRevokeReasons = [...]session.RevokeReason{
	session.RevokeUnsigned, session.RevokeMalformed, session.RevokeExpired,
	session.RevokeOversize, session.RevokeCapacity, session.RevokeFarFuture,
}

// Session-revocation refusal metric names (T-70, 2026-10-25 terminology review).
//
// The released names shipped in v1.0.340 and keep emitting, unchanged in name,
// labels and meaning, as deprecated aliases until v1.1.0:
//
//   - culvert_session_revoke_refused_total (UNLABELED) is the logout-cookie
//     "could not verify" counter. Canonical: culvert_session_revoke_unverifiable_total.
//   - culvert_session_revoke_rejected_total{reason} is the per-reason series.
//     Canonical: culvert_session_revoke_refusals_total{reason}.
//
// Neither released name may ever be reassigned to another meaning. In
// particular culvert_session_revoke_refused_total must never become a labeled
// per-reason series: an existing alert on it would keep evaluating, silently,
// against a different quantity. TestT70_SessionRevokeMetricAliases pins this.
const (
	sessionRevokeUnverifiableMetric       = "culvert_session_revoke_unverifiable_total"
	sessionRevokeRefusalsMetric           = "culvert_session_revoke_refusals_total"
	sessionRevokeRefusedDeprecatedMetric  = "culvert_session_revoke_refused_total"
	sessionRevokeRejectedDeprecatedMetric = "culvert_session_revoke_rejected_total"

	sessionRevokeUnverifiableHelp = "Logout requests whose session cookie was refused before anything was retained because this appliance could not verify it (bad signature or malformed). A genuine expired cookie and a replayed logout are excluded, but a cookie signed under a PREVIOUS session secret is not: after a key rotation or a restart with a fresh random key, ordinary browsers produce this until they re-authenticate. Sustained growth with no recent key change means an unauthenticated source is probing /api/auth/logout"
	sessionRevokeRefusalsHelp     = "Revocation entries refused by reason. unsigned/malformed/expired are the public logout endpoint; oversize/capacity/far_future are the UNTRUSTED-origin paths (cluster gossip, the on-disk revocations file); oversize/capacity mean cluster-wide revocation is incomplete on this node, far_future means an entry claimed an expiry no session this appliance issues can have"
)

// writeSessionRevokeMetrics emits the CHAOS-73 refusal counters under their
// canonical names and, from the SAME snapshot, under the deprecated released
// names, so a scrape never shows the two names disagreeing.
func writeSessionRevokeMetrics(w *strings.Builder) {
	unverifiable := sessionRevocationRefusedTotal()
	var byReason [len(sessionRevokeReasons)]int64
	for i, reason := range sessionRevokeReasons {
		byReason[i] = session.Refused(reason)
	}
	writeRevokeCounter := func(name, help string) {
		fmt.Fprintf(w, "\n# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, unverifiable)
	}
	writeRevokeByReason := func(name, help string) {
		fmt.Fprintf(w, "\n# HELP %s %s\n# TYPE %s counter\n", name, help, name)
		for i, reason := range sessionRevokeReasons {
			fmt.Fprintf(w, "%s{reason=%q} %d\n", name, string(reason), byReason[i])
		}
	}
	writeRevokeCounter(sessionRevokeUnverifiableMetric, sessionRevokeUnverifiableHelp)
	writeRevokeByReason(sessionRevokeRefusalsMetric, sessionRevokeRefusalsHelp)
	writeRevokeCounter(sessionRevokeRefusedDeprecatedMetric,
		"DEPRECATED alias of "+sessionRevokeUnverifiableMetric+" (T-70): same series and value, removed in v1.1.0. "+sessionRevokeUnverifiableHelp)
	writeRevokeByReason(sessionRevokeRejectedDeprecatedMetric,
		"DEPRECATED alias of "+sessionRevokeRefusalsMetric+" (T-70): same labels and values, removed in v1.1.0. "+sessionRevokeRefusalsHelp)
}
