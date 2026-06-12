package main

// Live-feed quick-win regression tests:
//   - apiEvents must END the stream when the hub evicts it as a slow client
//     (receiving from the closed channel used to busy-spin at 100% CPU).
//   - apiEvents must reject new connections at the sseMaxClients cap.
//   - broadcast evictions are counted (culvert_sse_evictions_total).
//   - /api/logs clamps the limit query parameter.
//   - persistent request-log write failures and corrupt lines are counted.
//   - the persistent-log read cache collapses repeat polls within its TTL.
//   - mid-stream auth re-validation (sseAuthStillValid) basics.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// isolateLogRing swaps the in-memory request-log ring for an empty one and
// restores it on cleanup so logAdd side-effects don't leak across tests.
func isolateLogRing(t *testing.T) {
	t.Helper()
	logsMu.Lock()
	oldLogs := logs
	logs = nil
	logsMu.Unlock()
	t.Cleanup(func() {
		logsMu.Lock()
		logs = oldLogs
		logsMu.Unlock()
	})
}

func TestApiEvents_EvictedClientEndsStream(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Snapshot pre-existing hub clients so we only touch the one this test adds.
	hub.mu.Lock()
	before := make(map[chan []byte]struct{}, len(hub.clients))
	for ch := range hub.clients {
		before[ch] = struct{}{}
	}
	hub.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/api/events", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { apiEvents(rec, req); close(done) }()

	// Wait for the handler to register its channel with the hub.
	var target chan []byte
	deadline := time.Now().Add(2 * time.Second)
	for target == nil && time.Now().Before(deadline) {
		hub.mu.Lock()
		for ch := range hub.clients {
			if _, ok := before[ch]; !ok {
				target = ch
				break
			}
		}
		hub.mu.Unlock()
		if target == nil {
			time.Sleep(5 * time.Millisecond)
		}
	}
	if target == nil {
		t.Fatal("apiEvents never registered a channel with the hub")
	}

	// Simulate the hub evicting this client as too slow (broadcast's B21 path).
	hub.mu.Lock()
	close(target)
	delete(hub.clients, target)
	hub.mu.Unlock()

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

func TestApiEvents_ClientCapRejects(t *testing.T) {
	// Occupy one slot so the cap (set to current occupancy) is already full.
	dummy := make(chan []byte, 1)
	if !hub.register(dummy) {
		t.Fatal("dummy register failed")
	}
	t.Cleanup(func() { hub.unregister(dummy) })

	oldMax := sseMaxClients
	sseMaxClients = hub.ClientCount()
	t.Cleanup(func() { sseMaxClients = oldMax })

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

func TestSSEHub_Broadcast_EvictionCounted(t *testing.T) {
	h := &sseHub{clients: make(map[chan []byte]struct{})}
	ch := make(chan []byte) // unbuffered — always "full", triggers eviction
	h.register(ch)

	before := atomic.LoadInt64(&statSSEEvicted)
	h.broadcast([]byte("x"))
	if got := atomic.LoadInt64(&statSSEEvicted); got != before+1 {
		t.Errorf("statSSEEvicted = %d, want %d", got, before+1)
	}
	if h.ClientCount() != 0 {
		t.Error("evicted client should be removed from the hub")
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

type failingLogWriter struct{}

func (failingLogWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestLogAdd_CountsWriteErrors(t *testing.T) {
	isolateLogRing(t)
	oldWriter := requestLogWriter
	requestLogWriter = failingLogWriter{}
	t.Cleanup(func() { requestLogWriter = oldWriter })

	before := atomic.LoadInt64(&statReqLogWriteErrors)
	logAdd(LogEntry{TS: 1, Method: "GET", Host: "x.example.com", Status: "OK"})
	if got := atomic.LoadInt64(&statReqLogWriteErrors); got != before+1 {
		t.Errorf("statReqLogWriteErrors = %d, want %d", got, before+1)
	}
}

func TestRequestLogReadPersistent_CountsCorruptLines(t *testing.T) {
	t.Cleanup(resetRequestLogState)

	good1, _ := json.Marshal(LogEntry{TS: 1, Host: "a.example.com", Status: "OK"})
	good2, _ := json.Marshal(LogEntry{TS: 2, Host: "b.example.com", Status: "OK"})
	content := bytes.Join([][]byte{good1, []byte("{corrupt-not-json"), good2, nil}, []byte("\n"))

	path := filepath.Join(t.TempDir(), "request.jsonl")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	requestLogFilePath = path

	before := atomic.LoadInt64(&statReqLogSkippedLines)
	entries, err := requestLogReadPersistent()
	if err != nil {
		t.Fatalf("requestLogReadPersistent: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("parsed %d entries, want 2 (corrupt line skipped)", len(entries))
	}
	if got := atomic.LoadInt64(&statReqLogSkippedLines); got != before+1 {
		t.Errorf("statReqLogSkippedLines = %d, want %d", got, before+1)
	}
}

func TestRequestLogReadPersistent_CachedWithinTTL(t *testing.T) {
	t.Cleanup(resetRequestLogState)
	isolateLogRing(t)

	dir := t.TempDir()
	if err := initRequestLog(filepath.Join(dir, "request.jsonl"), 10); err != nil {
		t.Fatalf("initRequestLog: %v", err)
	}
	logAdd(LogEntry{TS: 1, Host: "a.example.com", Status: "OK"})

	first, err := requestLogReadPersistent()
	if err != nil || len(first) != 1 {
		t.Fatalf("first read: entries=%d err=%v, want 1 entry", len(first), err)
	}

	// A write inside the TTL window is intentionally not visible yet.
	logAdd(LogEntry{TS: 2, Host: "b.example.com", Status: "OK"})
	cached, err := requestLogReadPersistent()
	if err != nil {
		t.Fatalf("cached read: %v", err)
	}
	if len(cached) != 1 {
		t.Fatalf("cached read returned %d entries, want 1 (TTL cache)", len(cached))
	}

	// Expire the cache → fresh parse sees both entries.
	reqLogReadCache.mu.Lock()
	reqLogReadCache.expires = time.Time{}
	reqLogReadCache.mu.Unlock()
	fresh, err := requestLogReadPersistent()
	if err != nil {
		t.Fatalf("fresh read: %v", err)
	}
	if len(fresh) != 2 {
		t.Fatalf("fresh read returned %d entries, want 2 after cache expiry", len(fresh))
	}
}

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
