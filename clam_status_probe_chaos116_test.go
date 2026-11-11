package main

// clam_status_probe_chaos116_test.go — CHAOS-116, the cross-plane half.
//
// internal/secscan's own gates hold the probe's properties. These hold the two
// facts that made it a defect rather than an inefficiency, and they drive the
// REAL unauthenticated handlers rather than the scanner:
//
//   - /health and /ready are dispatched by routeProxyListenerBuiltin on the
//     PROXY listener, before handleRequest and therefore before the IP filter,
//     the rate limiter and the connection limiter. handleHealth's own comment
//     says so: "every client that can use the gateway can read whatever is
//     written here." So whatever these handlers do per request, an
//     unauthenticated client chooses how often it happens.
//   - the status read used to dial ClamAV inline, under a budget of ~2x the
//     30 s scan timeout, with no single-flight. A blackholed daemon therefore
//     turned each of those requests into a parked goroutine and socket, and the
//     flood of pings filled the connection queue of the daemon whose scans then
//     failed — which internal/secscan forwards UNSCANNED (fail-open).
//
// The probe-storm gate below is the one that would have caught the defect: on
// the pre-fix tree it reports N dials for N requests and the requests do not
// return at all while the daemon is silent.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/secscan"
)

// silentClam accepts the probe and never answers — the blackholed/saturated
// daemon. It honours the probe's context, as the shipped *clamav.Client does.
type silentClam struct {
	dials   atomic.Int64
	release chan struct{}
}

func newSilentClam() *silentClam { return &silentClam{release: make(chan struct{})} }

func (s *silentClam) Ping() error { return s.PingContext(context.Background()) }

func (s *silentClam) PingContext(ctx context.Context) error {
	s.dials.Add(1)
	select {
	case <-s.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *silentClam) Scan([]byte) (name string, found bool, err error) { return "", false, nil }

// withSilentClamScanner installs a scanner whose daemon never answers and
// returns it, restoring the previous global.
func withSilentClamScanner(t *testing.T) *silentClam {
	t.Helper()
	clam := newSilentClam()
	prev := globalSecScanner
	globalSecScanner = secscan.New(secscan.Deps{Clam: clam, Cache: newHashCache(16, time.Minute)})
	t.Cleanup(func() {
		globalSecScanner = prev
		close(clam.release)
	})
	return clam
}

// TestChaos116_UnauthenticatedHealthFloodDialsTheDaemonOnce is the
// reproduction. The pre-fix handler dialed per request and did not answer while
// the daemon was silent.
func TestChaos116_UnauthenticatedHealthFloodDialsTheDaemonOnce(t *testing.T) {
	captureStartupAlerts(t)
	sslInspectionLoadError.Store("")
	clam := withSilentClamScanner(t)

	const requests = 48
	var wg sync.WaitGroup
	done := make(chan struct{})
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rr := httptest.NewRecorder()
			handleHealth(rr, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/health", http.NoBody))
			if rr.Code != http.StatusOK {
				t.Errorf("/health status = %d, want 200", rr.Code)
			}
		}()
	}
	go func() { wg.Wait(); close(done) }()

	// 10 s is far below the pre-fix wait (a 30 s dial plus a 30 s read deadline
	// per request) and far above the post-fix one (one shared sub-second bound).
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("%d unauthenticated /health requests did not complete while ClamAV was silent: the liveness endpoint must not wait on the AV daemon", requests)
	}

	if got := clam.dials.Load(); got != 1 {
		t.Fatalf("ClamAV dials = %d for %d unauthenticated /health requests, want 1: the probe path takes no clamSem slot, so a per-request dial is an unbounded connection flood against the daemon whose failed scans are forwarded UNSCANNED", got, requests)
	}
}

// TestChaos116_UnauthenticatedHealthKeepsTheCoarseEnum is the disclosure
// control: the fix adds a status value, and the unauthenticated surface must
// still publish only the fixed enum (the CHAOS-era redaction, readyz_detail_
// disclosure_test.go).
func TestChaos116_UnauthenticatedHealthKeepsTheCoarseEnum(t *testing.T) {
	captureStartupAlerts(t)
	sslInspectionLoadError.Store("")
	withSilentClamScanner(t)

	rr := httptest.NewRecorder()
	handleHealth(rr, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/health", http.NoBody))
	var doc map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&doc); err != nil {
		t.Fatalf("decode /health: %v", err)
	}
	got, _ := doc["clamav"].(string)
	if got != "unreachable" {
		t.Fatalf("clamav = %q, want the coarse %q: an unobserved daemon must read as a failure, and the new status string must not reach this surface verbatim", got, "unreachable")
	}
}

// TestChaos116_ReadinessFailsClosedWhileTheDaemonIsUnobserved holds the posture
// decision. Answering a caller from "no observation yet" is only safe because
// every consumer treats it as a failure: readiness must say NOT ready rather
// than report a security control it has not been able to reach.
func TestChaos116_ReadinessFailsClosedWhileTheDaemonIsUnobserved(t *testing.T) {
	captureStartupAlerts(t)
	sslInspectionLoadError.Store("")
	withSilentClamScanner(t)

	rr := httptest.NewRecorder()
	handleReady(rr, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/ready", http.NoBody))
	body := rr.Body.String()

	var doc struct {
		Status string `json:"status"`
		Checks map[string]struct {
			Status string `json:"status"`
			Detail string `json:"detail"`
		} `json:"checks"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("decode /ready: %v (body %q)", err, body)
	}
	row, ok := doc.Checks["clamav"]
	if !ok {
		t.Fatalf("/ready has no clamav row while a ClamAV scanner is configured: body %q", body)
	}
	if row.Status != "fail" {
		t.Fatalf("clamav row = %q, want fail: a daemon this node has never reached must not be reported ready", row.Status)
	}
	// The detail stays the fixed operator sentence — no dial error, no address.
	for _, leak := range []string{"dial", "127.0.0.1", "3310", "deadline exceeded", "unknown:"} {
		if strings.Contains(strings.ToLower(row.Detail), strings.ToLower(leak)) {
			t.Errorf("clamav detail leaks %q on the unauthenticated surface: %q", leak, row.Detail)
		}
	}
}

// TestChaos116_ProbeAccountingReachesMetrics holds the operator's half: the
// amplification that was removed has to be visible, or an operator cannot tell
// a node under a probe storm from an idle one. Prometheus is where the
// scan-capacity runbook's rules live.
func TestChaos116_ProbeAccountingReachesMetrics(t *testing.T) {
	captureStartupAlerts(t)
	withSilentClamScanner(t)

	// One read starts a flight; the next ones join it.
	for i := 0; i < 3; i++ {
		_ = globalSecScanner.ClamAVStatus()
	}

	rr := httptest.NewRecorder()
	handleMetrics(rr, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", http.NoBody))
	body := rr.Body.String()
	for _, series := range []string{
		"culvert_clamav_status_probes_total",
		"culvert_clamav_status_probe_coalesced_total",
		"culvert_clamav_status_stale_total",
	} {
		if !strings.Contains(body, series) {
			t.Errorf("/metrics does not export %s", series)
		}
	}
}
