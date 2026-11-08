package main

// connlimit_refusal_observability_chaos112_test.go — CHAOS-112, second half.
//
// The per-IP connection-limit refusal on the HTTP/CONNECT path wrote NOTHING:
// no request-history row, no statBlocked, no log line, no metric. Its own
// SOCKS5 twin writes a row AND a line, and the IP-filter and rate-limit gates
// immediately below it in handleRequest write both. That silence is why the
// first half could run on a whole fleet unnoticed.
//
// The cheapest way to pass the primary gate here is a log line per refused
// request, which is the X-2 / CHAOS-54 amplifier — so the rate-limit control
// is part of the gate set, not an extra.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/reqlog"
)

// chaos112StatBlocked reads the process-wide blocked counter the dashboard and
// /metrics both render. Read, never reset: it is shared with every other test
// in the package, so this sweep asserts on a DELTA across its own request.
func chaos112StatBlocked() int64 { return atomic.LoadInt64(&statBlocked) }

// chaos112IsolateRefusals adds this file's own process-wide state — the
// refusal log gate and its counter — to the shared limiter isolation.
func chaos112IsolateRefusals(t *testing.T) {
	t.Helper()
	chaos112Isolate(t)
	resetConnLimitRefusalStateForTest()
	t.Cleanup(resetConnLimitRefusalStateForTest)
}

// TestCHAOS112_HTTPConnLimitRefusalIsObservable is the gate on the half that
// made the first half undiagnosable. Pre-fix the branch was a bare
// http.Error + return: no request-history row, no statBlocked, nothing.
//
// The row is asserted by UNIQUE CONTENT (a client IP used nowhere else), never
// by a length delta — the request-history ring is bounded and shuffled runs
// saturate it.
func TestCHAOS112_HTTPConnLimitRefusalIsObservable(t *testing.T) {
	chaos112IsolateRefusals(t)
	chaos112CaptureLog(t)

	const clientIP = "203.0.113.112"
	connLimiter.Enable(1)
	// Hold the IP's single slot so the request under test is the one refused.
	if !connLimiter.Acquire(clientIP) {
		t.Fatal("fixture: first Acquire must succeed")
	}
	t.Cleanup(func() { connLimiter.Release(clientIP) })

	blockedBefore := chaos112StatBlocked()

	r := makeRequest("http://example.com/", nil)
	r.RemoteAddr = clientIP + ":5555"
	w := httptest.NewRecorder()
	handleRequest(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d — the refusal itself regressed", w.Code, http.StatusServiceUnavailable)
	}
	if got := chaos112StatBlocked(); got <= blockedBefore {
		t.Errorf("statBlocked did not move (%d -> %d) — a refused request is not counted as "+
			"blocked, so the dashboard and /metrics blocked totals under-report every "+
			"connection-limit refusal", blockedBefore, got)
	}
	var found bool
	for _, e := range reqlog.Get() {
		if e.IP != clientIP || e.Status != "CONN_LIMITED" {
			continue
		}
		found = true
		// The row must carry the same attribution as the IP_BLOCKED and
		// RATE_LIMITED rows immediately below this gate, or an operator can
		// see that a source was capped without seeing what it was asking for.
		if e.Method != http.MethodGet || e.Host != "example.com" {
			t.Errorf("CONN_LIMITED row has method=%q host=%q, want %q and %q — the row does "+
				"not carry the attribution its two neighbouring gates do",
				e.Method, e.Host, http.MethodGet, "example.com")
		}
		break
	}
	if !found {
		t.Errorf("no CONN_LIMITED request-history row for %s — the HTTP refusal is the only "+
			"front-door gate in handleRequest that writes no row, while its SOCKS5 twin "+
			"(socks5.go) writes one", clientIP)
	}
}

// TestCHAOS112_ConnLimitRefusalLogIsRateLimited is the control that forbids
// the obvious fix. The SOCKS5 twin logs one line per refusal, which is
// tolerable at session rates; handleRequest runs per REQUEST, and X-2 records
// the log sink as BLOCKING the request goroutine when full — so a line per
// refused request turns a per-IP cap into a proxy-wide latency amplifier, the
// shape CHAOS-54 measured at 7.68 M lines / 300 ms.
func TestCHAOS112_ConnLimitRefusalLogIsRateLimited(t *testing.T) {
	chaos112IsolateRefusals(t)
	buf := chaos112CaptureLog(t)

	const clientIP = "203.0.113.113"
	connLimiter.Enable(1)
	if !connLimiter.Acquire(clientIP) {
		t.Fatal("fixture: first Acquire must succeed")
	}
	t.Cleanup(func() { connLimiter.Release(clientIP) })

	const refusals = 200
	for i := 0; i < refusals; i++ {
		r := makeRequest("http://example.com/", nil)
		r.RemoteAddr = clientIP + ":6000"
		handleRequest(httptest.NewRecorder(), r)
	}

	lines := strings.Count(buf.String(), "CONN_LIMITED")
	if lines == 0 {
		t.Error("200 refusals produced no CONN_LIMITED log line at all — the operator gets no " +
			"narrative for a cap that is firing")
	}
	if lines >= refusals {
		t.Errorf("%d CONN_LIMITED log lines for %d refusals — the line is not rate limited, so a "+
			"flood against a configured cap writes one line per request into a sink that "+
			"blocks the request goroutine when full (X-2)", lines, refusals)
	}
}

// TestCHAOS112_ConnLimitRefusalLogResumesAfterTheInterval is the recovery half
// of the rate limit, and the reason connLimitRefusalLogInterval is a var.
//
// A gate that only ever suppresses is indistinguishable from one that latched
// shut, and a latched log gate is the failure CHAOS-83/84 describe for a
// wall-clock elapsed-time check — so the gate must be shown to REOPEN, and to
// carry the magnitude it suppressed while it was closed. AU-43's rule in log
// form: a suppression must name what it suppressed.
func TestCHAOS112_ConnLimitRefusalLogResumesAfterTheInterval(t *testing.T) {
	chaos112IsolateRefusals(t)
	buf := chaos112CaptureLog(t)
	connLimitRefusalLogInterval = time.Millisecond

	const clientIP = "203.0.113.116"
	connLimiter.Enable(1)
	if !connLimiter.Acquire(clientIP) {
		t.Fatal("fixture: first Acquire must succeed")
	}
	t.Cleanup(func() { connLimiter.Release(clientIP) })

	refuse := func(n int) {
		for i := 0; i < n; i++ {
			r := makeRequest("http://example.com/", nil)
			r.RemoteAddr = clientIP + ":7000"
			handleRequest(httptest.NewRecorder(), r)
		}
	}

	refuse(1) // the first refusal after a quiet period always writes
	first := strings.Count(buf.String(), "CONN_LIMITED")
	if first != 1 {
		t.Fatalf("first refusal produced %d lines, want exactly 1", first)
	}
	refuse(4) // suppressed inside the interval
	if got := strings.Count(buf.String(), "CONN_LIMITED"); got != 1 {
		t.Fatalf("lines = %d after 5 refusals inside the interval, want 1", got)
	}

	// Let the interval elapse, then refuse once more.
	deadline := time.Now().Add(2 * time.Second)
	for strings.Count(buf.String(), "CONN_LIMITED") < 2 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
		refuse(1)
	}

	out := buf.String()
	if got := strings.Count(out, "CONN_LIMITED"); got < 2 {
		t.Fatalf("the refusal line never resumed after the interval elapsed (%d lines) — a "+
			"suppression gate that cannot reopen is a silent cap", got)
	}
	if !strings.Contains(out, "suppressed=") {
		t.Error("the resumed line does not report how many refusals were suppressed while " +
			"the gate was closed, so the magnitude is lost with the lines")
	}
}

// TestCHAOS112_MetricsExposeTheConnLimiterPosture is the gate that makes an
// alert possible at all. Pre-fix nothing about this limiter appeared in
// /metrics: `rejectedTotal` existed only as a process-lifetime number on the
// viewer-gated GET /api/connlimit, so no rule could be keyed to it — the PX-18
// shape, one subsystem over.
//
// The posture gauges are the half that matters for THIS finding: an operator
// who believes the limiter is off needs one fleet-wide query that says
// otherwise.
func TestCHAOS112_MetricsExposeTheConnLimiterPosture(t *testing.T) {
	chaos112IsolateRefusals(t)

	connLimiter.Enable(23)
	if !connLimiter.Acquire("203.0.113.114") {
		t.Fatal("fixture: Acquire must succeed")
	}
	t.Cleanup(func() { connLimiter.Release("203.0.113.114") })

	w := httptest.NewRecorder()
	handleMetrics(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", http.NoBody))
	out := w.Body.String()

	for _, want := range []string{
		"# TYPE culvert_connlimit_enabled gauge",
		"\nculvert_connlimit_enabled 1\n",
		"# TYPE culvert_connlimit_max_per_ip gauge",
		"\nculvert_connlimit_max_per_ip 23\n",
		"# TYPE culvert_connlimit_rejected_total counter",
		"\nculvert_connlimit_rejected_total ",
		"# TYPE culvert_connlimit_active_ips gauge",
		"\nculvert_connlimit_active_ips ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("/metrics is missing %q — the per-IP connection limiter's posture and "+
				"refusals cannot be alerted on", want)
		}
	}
}

// TestCHAOS112_MetricsReportADisabledLimiterAsZero is the two-sided half of
// the gauge contract (AU-43: a present-tense claim must name the value that
// clears it). A node with the limiter off must say so in the same series,
// otherwise "is anything enforcing a cap?" has no fleet-wide answer.
func TestCHAOS112_MetricsReportADisabledLimiterAsZero(t *testing.T) {
	chaos112IsolateRefusals(t)

	w := httptest.NewRecorder()
	handleMetrics(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", http.NoBody))

	if !strings.Contains(w.Body.String(), "\nculvert_connlimit_enabled 0\n") {
		t.Error("a disabled limiter does not report culvert_connlimit_enabled 0")
	}
}

// TestCHAOS112_ControlSOCKS5RefusalKeepsItsRow is the regression control on the
// twin. The HTTP path is being brought up to SOCKS5's standard; SOCKS5 must not
// be brought down to HTTP's in the process.
func TestCHAOS112_ControlSOCKS5RefusalKeepsItsRow(t *testing.T) {
	chaos112IsolateRefusals(t)
	chaos112CaptureLog(t)

	const clientIP = "203.0.113.115"
	connLimiter.Enable(1)
	if !connLimiter.Acquire(clientIP) {
		t.Fatal("fixture: first Acquire must succeed")
	}
	t.Cleanup(func() { connLimiter.Release(clientIP) })

	// The row the SOCKS5 branch writes, driven through the same accounting the
	// handler uses rather than through a socket: this control is about the row
	// surviving, and socks5_connlimit_test.go already drives the real handler.
	recordRequest(clientIP, "SOCKS5", "", "CONN_LIMITED", "", "", "", "")

	var found bool
	for _, e := range reqlog.Get() {
		if e.IP == clientIP && e.Status == "CONN_LIMITED" && e.Method == "SOCKS5" {
			found = true
			break
		}
	}
	if !found {
		t.Error("the SOCKS5 CONN_LIMITED row no longer reaches the request history")
	}
}
