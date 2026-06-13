package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// drainLogStore waits until the async writer has persisted at least want
// entries (via a query), or fails after a short deadline. The store batches
// writes on a 500ms timer, so tests must not assume synchronous persistence.
func drainLogStore(t *testing.T, s *logStore, fromMs, toMs int64, want int) []LogEntry {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got, total, err := s.Query(fromMs, toMs, 0, 100000, nil)
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if total >= want {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d entries; have %d", want, total)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestLogStore_WriteQueryNewestFirst(t *testing.T) {
	s, err := openLogStoreTTL(t.TempDir(), 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	base := time.Now().UnixMilli()
	for i := 0; i < 50; i++ {
		s.Add(LogEntry{TS: base + int64(i), Host: "h.example.com", Status: "OK"})
	}
	got := drainLogStore(t, s, 0, 0, 50)
	if len(got) < 50 {
		t.Fatalf("got %d entries, want >=50", len(got))
	}
	// Newest-first.
	for i := 1; i < len(got); i++ {
		if got[i-1].TS < got[i].TS {
			t.Fatalf("not newest-first at %d: %d < %d", i, got[i-1].TS, got[i].TS)
		}
	}
	if got[0].TS != base+49 {
		t.Errorf("newest TS = %d, want %d", got[0].TS, base+49)
	}
}

func TestLogStore_OffsetPagination(t *testing.T) {
	s, err := openLogStoreTTL(t.TempDir(), 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	base := time.Now().UnixMilli()
	for i := 0; i < 100; i++ {
		s.Add(LogEntry{TS: base + int64(i), Host: "h", Status: "OK"})
	}
	drainLogStore(t, s, 0, 0, 100)

	// Two non-overlapping pages of 10 over a frozen window.
	page1, total, _ := s.Query(0, 0, 0, 10, nil)
	page2, _, _ := s.Query(0, 0, 10, 10, nil)
	if total != 100 {
		t.Errorf("total = %d, want 100", total)
	}
	if len(page1) != 10 || len(page2) != 10 {
		t.Fatalf("page sizes = %d,%d, want 10,10", len(page1), len(page2))
	}
	// page1 newest (base+99..base+90), page2 next (base+89..base+80).
	if page1[0].TS != base+99 {
		t.Errorf("page1[0].TS = %d, want %d", page1[0].TS, base+99)
	}
	if page2[0].TS != base+89 {
		t.Errorf("page2[0].TS = %d, want %d", page2[0].TS, base+89)
	}
}

func TestLogStore_FilterAndTimeRange(t *testing.T) {
	s, err := openLogStoreTTL(t.TempDir(), 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	base := time.Now().UnixMilli()
	for i := 0; i < 30; i++ {
		host := "good.example.com"
		if i%3 == 0 {
			host = "bad.example.com"
		}
		s.Add(LogEntry{TS: base + int64(i), Host: host, Status: "OK"})
	}
	drainLogStore(t, s, 0, 0, 30)

	// Host filter.
	_, total, _ := s.Query(0, 0, 0, 1000, func(e *LogEntry) bool { return e.Host == "bad.example.com" })
	if total != 10 {
		t.Errorf("filtered total = %d, want 10", total)
	}

	// Time-range slice: only entries with TS in [base+10, base+19].
	_, rngTotal, _ := s.Query(base+10, base+19, 0, 1000, nil)
	if rngTotal != 10 {
		t.Errorf("range total = %d, want 10", rngTotal)
	}
}

func TestLogStore_AgeRetentionTTL(t *testing.T) {
	// 1-second TTL: entries must be gone from reads shortly after expiry.
	s, err := openLogStoreTTL(t.TempDir(), 1*time.Second, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	base := time.Now().UnixMilli()
	for i := 0; i < 20; i++ {
		s.Add(LogEntry{TS: base + int64(i), Host: "h", Status: "OK"})
	}
	drainLogStore(t, s, 0, 0, 20)

	time.Sleep(1500 * time.Millisecond)
	_, total, err := s.Query(0, 0, 0, 1000, nil)
	if err != nil {
		t.Fatalf("Query after expiry: %v", err)
	}
	if total != 0 {
		t.Errorf("after TTL expiry total = %d, want 0", total)
	}
}

func TestLogStore_SizeRetentionPrunesOldest(t *testing.T) {
	// maxBytes=1 forces the janitor to prune on every pass; a small batch makes
	// the prune partial so we can prove it drops the OLDEST entries first.
	old := logStorePruneBatch
	logStorePruneBatch = 10
	defer func() { logStorePruneBatch = old }()

	s, err := openLogStoreTTL(t.TempDir(), 0, 1)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	base := time.Now().UnixMilli()
	for i := 0; i < 50; i++ {
		s.Add(LogEntry{TS: base + int64(i), Host: "h", Status: "OK"})
	}
	drainLogStore(t, s, 0, 0, 50)

	before := atomic.LoadInt64(&statLogStorePruned)
	s.RunRetention()
	if got := atomic.LoadInt64(&statLogStorePruned); got != before+10 {
		t.Errorf("pruned counter delta = %d, want 10", got-before)
	}

	got, total, _ := s.Query(0, 0, 0, 1000, nil)
	if total != 40 {
		t.Errorf("after prune total = %d, want 40", total)
	}
	// The 10 oldest (base..base+9) should be gone; oldest remaining is base+10.
	if len(got) > 0 && got[len(got)-1].TS != base+10 {
		t.Errorf("oldest remaining TS = %d, want %d (oldest pruned first)", got[len(got)-1].TS, base+10)
	}
}

func TestLogStore_Stats(t *testing.T) {
	s, err := openLogStoreTTL(t.TempDir(), 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	base := time.Now().UnixMilli()
	for i := 0; i < 25; i++ {
		s.Add(LogEntry{TS: base + int64(i), Host: "h", Status: "OK"})
	}
	drainLogStore(t, s, 0, 0, 25)

	st := s.Stats()
	if st.Count != 25 {
		t.Errorf("Stats.Count = %d, want 25", st.Count)
	}
	if st.OldestMs != base {
		t.Errorf("Stats.OldestMs = %d, want %d", st.OldestMs, base)
	}
}

func TestApiLogs_SourceStore(t *testing.T) {
	isolateLogRing(t)
	s, err := openLogStoreTTL(t.TempDir(), 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	old := globalLogStore
	globalLogStore = s
	t.Cleanup(func() { globalLogStore = old; s.Close() })

	base := time.Now().UnixMilli()
	for i := 0; i < 20; i++ {
		host, status := "ok.example.com", "OK"
		if i%4 == 0 {
			host, status = "bad.example.com", "BLOCKED"
		}
		logAdd(LogEntry{TS: base + int64(i), IP: "10.0.0.1", Method: "GET", Host: host, Status: status, Level: "INFO"})
	}
	drainLogStore(t, s, 0, 0, 20)

	req := httptest.NewRequest(http.MethodGet, "/api/logs?source=store&filter=bad.example.com", nil)
	rec := httptest.NewRecorder()
	apiLogs(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Logs    []LogEntry `json:"logs"`
		Total   int        `json:"total"`
		History bool       `json:"history"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !resp.History {
		t.Error("history flag should be true when store enabled")
	}
	if resp.Total != 5 {
		t.Errorf("filtered total = %d, want 5", resp.Total)
	}
	for _, e := range resp.Logs {
		if e.Host != "bad.example.com" {
			t.Errorf("unexpected host in filtered result: %q", e.Host)
		}
	}
}

func TestApiLogs_SourceStore_Disabled(t *testing.T) {
	old := globalLogStore
	globalLogStore = nil
	t.Cleanup(func() { globalLogStore = old })

	req := httptest.NewRequest(http.MethodGet, "/api/logs?source=store", nil)
	rec := httptest.NewRecorder()
	apiLogs(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var resp struct {
		Total   int  `json:"total"`
		History bool `json:"history"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.History || resp.Total != 0 {
		t.Errorf("disabled store should return history:false total:0, got %+v", resp)
	}
}

func TestLogStore_NilSafe(t *testing.T) {
	var s *logStore
	s.Add(LogEntry{TS: 1})
	s.RunRetention()
	if _, total, err := s.Query(0, 0, 0, 10, nil); err != nil || total != 0 {
		t.Errorf("nil Query = (%d,%v), want (0,nil)", total, err)
	}
	if st := s.Stats(); st.Bytes != 0 || st.Count != 0 {
		t.Errorf("nil Stats = %+v, want zero", st)
	}
	if err := s.Close(); err != nil {
		t.Errorf("nil Close = %v", err)
	}
}
