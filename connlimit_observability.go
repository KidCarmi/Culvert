package main

// connlimit_observability.go — CHAOS-112, the second half.
//
// The per-IP connection-limit refusal was the only front-door gate in
// handleRequest that wrote NOTHING anywhere:
//
//	if !connLimiter.Acquire(clientIP) {
//	        http.Error(w, "Too Many Connections", http.StatusServiceUnavailable)
//	        return
//	}
//
// No request-history row, no statBlocked, no log line, no metric. Compare the
// two gates immediately below it — IP_BLOCKED and RATE_LIMITED each write a
// row, a line and (the first) the blocked counter — and compare its own SOCKS5
// twin, whose comment claims symmetry with this path and which writes both a
// row and a line (socks5.go). The only trace was
// ConnLimiter.rejected, surfaced as a process-lifetime, unattributed
// `rejectedTotal` on the viewer-gated GET /api/connlimit. Nothing in /metrics,
// nothing in /healthz, nothing to key an alert to: the PX-18 shape, one
// subsystem over.
//
// That silence is why CHAOS-112's first half could run on a whole fleet. A
// Data Plane that had been handed a cap nobody configured refused the 1025th
// concurrent request from one source with a bare 503, and the refusal appeared
// in no request history, no counter and no log — so the only way to discover
// the cap existed was to poll that one node's /api/connlimit and notice it
// disagreed with the Control Plane.
//
// WHY THE LOG LINE IS RATE LIMITED AND THE ROW IS NOT.
//
// The SOCKS5 twin logs one line per refusal. That is tolerable there because it
// fires once per SESSION; handleRequest fires once per REQUEST, and the
// register is explicit about what an unbounded per-request line costs on this
// path: `internal/logsink`'s bounded queue BLOCKS the caller when full (X-2),
// so a line per refused request converts a per-IP cap into proxy-wide latency
// — and CHAOS-54 measured that shape at 7.68 M attempts / 300 ms with one line
// each, ~40 MB/s into a 50 MB rotating log that erased its own diagnostic
// history in seconds. CHAOS-111 reached the same conclusion for its own
// omission line and rate-limited it for the same reason.
//
// The request-history row has no such hazard: it lands in a bounded ring
// (reqlog.MaxRing) at the same cost as every other blocked request's row, and
// it is the half that carries ATTRIBUTION — which source IP was capped — which
// the aggregate counter cannot. So the row is written for every refusal and the
// narrative line is written at most once per connLimitRefusalLogInterval,
// carrying the number suppressed since the last one so the magnitude is not
// lost with the lines.

import (
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// connLimitRefusalLogInterval bounds how often the refusal narrative reaches
// the process log. One line per minute at most, never one per request.
//
// A var, not a const, so the rate-limit gate can be exercised without spending
// a real minute; production never writes it.
var connLimitRefusalLogInterval = time.Minute

// connLimitRefusalLogState is the rate-limit gate for the refusal line.
//
// The stamp is a monoNanos reading, not a wall-clock instant: this is an
// elapsed-time suppression gate, and CHAOS-83/CHAOS-84 record what a backwards
// wall-clock step does to one — it stays latched for as long as the step was
// large, so a cap that starts firing during an NTP correction logs nothing at
// all. 0 is the "never stamped" sentinel, which monoNanos's strictly-positive
// contract keeps unreachable.
//
// The suppressed count is carried INSIDE the mutex with the stamp so the number
// a line reports is exactly the number of refusals since the previous line —
// two independent atomics would let a concurrent refusal be counted against
// the wrong line.
var connLimitRefusalLogState struct {
	mu         sync.Mutex
	lastStamp  int64
	suppressed int64
}

// connLimitRefusedTotal counts refusals this process has charged to the HTTP
// path. It is NOT the limiter's own rejected counter: that one also counts
// SOCKS5 refusals, and /metrics exposes it separately. This one exists so the
// log gate's suppression can be reconciled against the real total.
var connLimitRefusedTotal atomic.Int64

// noteConnLimitRefusal records one per-IP connection-limit refusal on the
// HTTP/CONNECT path: the blocked counter, the attributed request-history row,
// and — at most once per interval — the narrative log line.
//
// clientIP is the resolved client address, already canonical (realClientIP) and
// not client-chosen text, so it needs no sanitizeLog barrier of its own; the
// line still routes it through sanitizeLog because a log value derived from a
// request must not depend on a caller's promise to have canonicalized it.
func noteConnLimitRefusal(clientIP, reqID string) {
	connLimitRefusedTotal.Add(1)
	atomic.AddInt64(&statBlocked, 1)
	recordRequest(clientIP, "CONNLIMIT", "", "CONN_LIMITED", "", "", "", "")

	suppressed, emit := connLimitRefusalLogDue()
	if !emit {
		return
	}
	if suppressed > 0 {
		logger.Printf("CONN_LIMITED %q {req_id=%s action=block max_per_ip=%d suppressed=%d}",
			sanitizeLog(clientIP), reqID, connLimiter.MaxPerIP(), suppressed)
		return
	}
	logger.Printf("CONN_LIMITED %q {req_id=%s action=block max_per_ip=%d}",
		sanitizeLog(clientIP), reqID, connLimiter.MaxPerIP())
}

// connLimitRefusalLogDue reports whether this refusal may write a line, and
// how many were suppressed since the previous one. The first refusal after a
// quiet period always writes: an operator must learn that a cap started firing
// without waiting out an interval.
func connLimitRefusalLogDue() (suppressed int64, emit bool) {
	connLimitRefusalLogState.mu.Lock()
	defer connLimitRefusalLogState.mu.Unlock()
	if last := connLimitRefusalLogState.lastStamp; last != 0 &&
		monoSince(last) < connLimitRefusalLogInterval {
		connLimitRefusalLogState.suppressed++
		return 0, false
	}
	suppressed = connLimitRefusalLogState.suppressed
	connLimitRefusalLogState.suppressed = 0
	connLimitRefusalLogState.lastStamp = monoNanos()
	return suppressed, true
}

// resetConnLimitRefusalStateForTest clears this file's process-wide gate and
// counter. Both are shared, so a test asserting on either must isolate them —
// the resetOversizeHostStateForTest pattern (proxy_path_bounds.go).
func resetConnLimitRefusalStateForTest() {
	connLimitRefusalLogState.mu.Lock()
	connLimitRefusalLogState.lastStamp = 0
	connLimitRefusalLogState.suppressed = 0
	connLimitRefusalLogState.mu.Unlock()
	connLimitRefusedTotal.Store(0)
	connLimitRefusalLogInterval = time.Minute
}

// connLimitWritePrometheus appends the per-IP connection limiter's POSTURE and
// its refusals to the /metrics body.
//
// It is its own function rather than a block inside handleMetrics for the
// reason conventions.md records: cyclop/gocognit/funlen attribute to a
// function's DECLARATION line, so --new-from-rev cannot see a function a change
// made more complex. handleMetrics is already over the gocognit threshold at
// 45, and inlining this block measured it at 46 — a regression the diff-scoped
// lint reported as zero issues. Measured again after the extraction: 45,
// unchanged from the base.
//
// Takes an io.Writer rather than the ResponseWriter so the exposition can be
// rendered into a buffer by a test, matching liveFeedWritePrometheus.
func connLimitWritePrometheus(w io.Writer) {
	// CHAOS-112: the per-IP connection limiter's POSTURE, not just its
	// refusals. The posture gauges are the half that matters: this limiter
	// ships disabled (PX-6) and its enablement is node-local, so "is any node
	// in the fleet enforcing a per-IP connection cap, and at what value?" had
	// no fleet-wide answer at all — the only surface was a viewer-gated
	// GET /api/connlimit, one node at a time. `rejected_total` is the
	// limiter's own counter and spans BOTH protocol paths; `refused_total` is
	// the HTTP/CONNECT path's own charge, so the two can be reconciled (a
	// gap between them is SOCKS5 refusals).
	connLimEnabledVal := 0
	if connLimiter.Enabled() {
		connLimEnabledVal = 1
	}
	_, _ = fmt.Fprintf(w, `# HELP culvert_connlimit_enabled 1 while per-source-IP connection limiting is enforcing on this node; 0 while it is off (node-local, never set by a Control Plane snapshot)
# TYPE culvert_connlimit_enabled gauge
culvert_connlimit_enabled %d

# HELP culvert_connlimit_max_per_ip The per-source-IP concurrency cap this node holds — reported whether or not limiting is enabled, so a cluster-synced cap is visible before an operator enables it locally
# TYPE culvert_connlimit_max_per_ip gauge
culvert_connlimit_max_per_ip %d

# HELP culvert_connlimit_active_ips Source IPs currently holding at least one counted connection
# TYPE culvert_connlimit_active_ips gauge
culvert_connlimit_active_ips %d

# HELP culvert_connlimit_rejected_total Connections refused over the per-IP cap since boot, across the HTTP/CONNECT and SOCKS5 paths
# TYPE culvert_connlimit_rejected_total counter
culvert_connlimit_rejected_total %d

# HELP culvert_connlimit_http_refused_total Requests refused over the per-IP cap on the HTTP/CONNECT path since boot
# TYPE culvert_connlimit_http_refused_total counter
culvert_connlimit_http_refused_total %d
`,
		connLimEnabledVal,
		connLimiter.MaxPerIP(),
		connLimiter.ActiveIPs(),
		connLimiter.Rejected(),
		connLimitRefusedTotal.Load(),
	)
}
