package main

// Live-feed quick-win regression tests:
//   - apiEvents must END the stream when the hub evicts it as a slow client
//     (receiving from the closed channel used to busy-spin at 100% CPU).
//   - apiEvents must reject new connections at the hub connection cap.
//   - broadcast evictions are counted (culvert_sse_evictions_total).
//   - /api/logs clamps the limit query parameter.
//   - persistent request-log write failures and corrupt lines are counted.
//   - the persistent-log read cache collapses repeat polls within its TTL.
//   - mid-stream auth re-validation (sseAuthStillValid) basics.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/reqlog"
)

// isolateLogRing swaps the in-memory request-log ring for an empty one and
// restores it on cleanup so logAdd side-effects don't leak across tests.
//
// It first waits (bounded) for every in-flight HIJACKED tunnel to finish. A
// tunnel's close accounting writes a request-log entry from the relay
// goroutine, and httptest.Server.Close does not wait for hijacked
// connections, so a CONNECT/WebSocket/SOCKS5 test that returns as soon as it
// has its 200 leaves that write in flight — on a loaded runner it landed in
// the NEXT test's freshly swapped ring (Deep determinism, seed
// 1791014615135233342: "seeded ring holds 61 entries, want 60", the
// straggler a `tunnel-allow` CONNECT from TestObservationE2E_CONNECTTunnel).
// Every such tunnel is registered in activeConns and its accounting lands
// BEFORE the deferred release (handleTunnelBypass etc.), so activeConns
// reaching zero proves no straggler can still write. The wait is bounded and
// does not fail the caller: a gauge held by a genuinely stuck tunnel is the
// leaking test's defect, reported here, not this test's.
func isolateLogRing(t *testing.T) {
	t.Helper()
	if !waitTunnelsQuiescent(isolateLogRingTunnelWait) {
		t.Logf("isolateLogRing: %d hijacked tunnel(s) still open after %s — a previous test leaked one; its accounting may still land in this ring", getActiveConns(), isolateLogRingTunnelWait)
	}
	t.Cleanup(reqlog.SwapRingForTest())
}

// isolateLogRingTunnelWait bounds isolateLogRing's wait. A leaked tunnel whose
// client and target are both closed drains in microseconds; the bound only
// matters for one that never ends.
const isolateLogRingTunnelWait = 5 * time.Second

// waitTunnelsQuiescent polls until no hijacked tunnel is registered, or the
// bound passes. Unlike waitForActiveConnsZero it needs no *testing.T, so the
// helper above can call it before deciding how to report.
func waitTunnelsQuiescent(within time.Duration) bool {
	deadline := time.Now().Add(within)
	for {
		if getActiveConns() <= 0 {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// resetRequestLogState unwires the persistent request log engine state so
// tests can safely re-init without leaking file handles or paths across
// tests. Safe to call whether or not persistence was initialised.
func resetRequestLogState() { reqlog.ResetForTest() }

func TestApiEvents_EvictedClientEndsStream(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Snapshot pre-existing hub clients so we only touch the one this test adds.
	before := make(map[chan []byte]struct{})
	for _, ch := range hub.ClientsForTest() {
		before[ch] = struct{}{}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/events", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { apiEvents(rec, req); close(done) }()

	// Wait for the handler to register its channel with the hub.
	var target chan []byte
	deadline := time.Now().Add(2 * time.Second)
	for target == nil && time.Now().Before(deadline) {
		for _, ch := range hub.ClientsForTest() {
			if _, ok := before[ch]; !ok {
				target = ch
				break
			}
		}
		if target == nil {
			time.Sleep(5 * time.Millisecond)
		}
	}
	if target == nil {
		t.Fatal("apiEvents never registered a channel with the hub")
	}

	// Simulate the hub evicting this client as too slow (Broadcast's B21 path).
	hub.EvictForTest(target)

	select {
	case <-done:
		// Handler exited cleanly instead of spinning on the closed channel.
	case <-time.After(2 * time.Second):
		t.Fatal("apiEvents did not return after its channel was closed (busy-spin regression)")
	}
	if !strings.Contains(rec.Body.String(), "event: connected") {
		t.Errorf("stream missing initial connected event; body=%q", rec.Body.String())
	}
}

// failingFlushWriter is an http.ResponseWriter+Flusher whose Write always
// fails, simulating a dead/half-open client connection.
type failingFlushWriter struct{ header http.Header }

func (f *failingFlushWriter) Header() http.Header {
	if f.header == nil {
		f.header = make(http.Header)
	}
	return f.header
}
func (f *failingFlushWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }
func (f *failingFlushWriter) WriteHeader(int)           {}
func (f *failingFlushWriter) Flush()                    {}

func TestApiEvents_WriteErrorEndsStream(t *testing.T) {
	// Plain (non-deadline) context: the only thing that should end the stream
	// is the failed write. If the handler ignored write errors it would block
	// in its select loop forever and the assertion below would fire.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/events", nil).WithContext(ctx)

	done := make(chan struct{})
	go func() { apiEvents(&failingFlushWriter{}, req); close(done) }()

	select {
	case <-done:
		// Failed connected-frame write → handler returned instead of looping
		// forever on a half-open connection.
	case <-time.After(2 * time.Second):
		t.Fatal("apiEvents did not return after a failed write (half-open connection leak regression)")
	}
}

func TestApiEvents_ClientCapRejects(t *testing.T) {
	// Occupy one slot so the cap (set to current occupancy) is already full.
	dummy := make(chan []byte, 1)
	if !hub.Register(dummy) {
		t.Fatal("dummy register failed")
	}
	t.Cleanup(func() { hub.Unregister(dummy) })

	oldMax := hub.MaxClients()
	hub.SetMaxClients(int64(hub.ClientCount()))
	t.Cleanup(func() { hub.SetMaxClients(oldMax) })

	// Bounded context: if the cap fails to reject, the handler streams until
	// the deadline instead of hanging the test forever.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/events", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	apiEvents(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("apiEvents at cap returned %d, want 503; body=%q", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("503 cap rejection should carry a Retry-After header")
	}
}

func TestSSEAuthStillValid(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/events", nil)

	// Auth disabled → stream stays valid.
	if cfg.AuthEnabled() {
		t.Skip("auth unexpectedly configured in test environment")
	}
	if !sseAuthStillValid(r) {
		t.Error("sseAuthStillValid = false with auth disabled, want true")
	}

	// Auth enabled + no cookie + no basic auth → stream must terminate.
	cfg.mu.Lock()
	oldUser := cfg.user
	cfg.user = "admin"
	cfg.mu.Unlock()
	t.Cleanup(func() {
		cfg.mu.Lock()
		cfg.user = oldUser
		cfg.mu.Unlock()
	})
	if sseAuthStillValid(r) {
		t.Error("sseAuthStillValid = true for unauthenticated request with auth enabled, want false")
	}
}

func TestApiLogs_LimitClamped(t *testing.T) {
	t.Cleanup(resetRequestLogState)
	isolateLogRing(t)

	dir := t.TempDir()
	if err := initRequestLog(filepath.Join(dir, "request.jsonl"), 200); err != nil {
		t.Fatalf("initRequestLog: %v", err)
	}
	// 6000 entries on disk — above the 5000 clamp, below the 20000 read cap.
	for i := 0; i < 6000; i++ {
		logAdd(LogEntry{TS: int64(i), Method: "GET", Host: "h.example.com", Status: "OK", Level: "INFO"})
	}

	req := httptest.NewRequest(http.MethodGet, "/api/logs?source=file&limit=999999999", nil)
	rec := httptest.NewRecorder()
	apiLogs(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("apiLogs status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Logs  []LogEntry `json:"logs"`
		Total int        `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Total != 6000 {
		t.Errorf("total = %d, want 6000", resp.Total)
	}
	if len(resp.Logs) != 5000 {
		t.Errorf("returned %d entries, want 5000 (limit clamp)", len(resp.Logs))
	}
}

// The write-error / corrupt-line counter tests and the TTL read-cache test
// moved to internal/reqlog (ADR-0002, store.go decomposition Phase C) — they
// exercise engine internals through the package's named test seams.

func TestMetrics_LiveFeedExposition(t *testing.T) {
	oldToken := metricsToken
	metricsToken = ""
	t.Cleanup(func() { metricsToken = oldToken })

	rec := httptest.NewRecorder()
	handleMetrics(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("handleMetrics status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, m := range []string{
		"culvert_sse_clients",
		"culvert_sse_evictions_total",
		"culvert_sse_rejected_total",
		"culvert_reqlog_write_errors_total",
		"culvert_reqlog_skipped_lines_total",
	} {
		if !strings.Contains(body, m) {
			t.Errorf("/metrics output missing %s", m)
		}
	}
}
