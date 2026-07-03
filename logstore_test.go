package main

// logstore_test.go — lifecycle (enable/disable/purge) and API-handler tests
// for the request-log history. The engine tests moved in-package to
// internal/logstore with the extraction (ADR-0002).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/logstore"
)

// adminReq returns a request whose context carries the admin role, so handlers
// gated by requireRole(RoleAdmin) pass without the full middleware chain.
func adminReq(method, target, body string) *http.Request {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, http.NoBody)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	}
	return r.WithContext(context.WithValue(r.Context(), uiRoleKey{}, RoleAdmin))
}

// drainLogStore waits until the async writer has persisted at least want
// entries (via a query), or fails after a short deadline. The store batches
// writes on a 500ms timer, so tests must not assume synchronous persistence.
func drainLogStore(t *testing.T, s *logStore, want int) []LogEntry {
	t.Helper()
	// Generous deadline: Add() is async (buffered channel → background writer
	// goroutine → Badger), and under the shuffled determinism gate's CPU
	// saturation that writer can be starved for several seconds before it
	// flushes, so reads transiently see fewer than `want` entries.
	deadline := time.Now().Add(15 * time.Second)
	for {
		got, total, err := s.Query(0, 0, 0, 100000, nil)
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

func TestEnableDisablePurgeLogStore(t *testing.T) {
	isolateLogRing(t)
	old := globalLogStore.Swap(nil)
	oldDir := logStoreDir
	t.Cleanup(func() { disableLogStore(); globalLogStore.Store(old); logStoreDir = oldDir })

	dir := t.TempDir()
	logStoreDir = dir
	if err := enableLogStore(context.Background(), dir, 0, 0); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if globalLogStore.Load() == nil {
		t.Fatal("store should be enabled")
	}
	logAdd(LogEntry{TS: time.Now().UnixMilli(), Host: "h.example.com", Status: "OK"})
	drainLogStore(t, globalLogStore.Load(), 1)

	if err := purgeLogStore(); err != nil {
		t.Fatalf("purge: %v", err)
	}
	if _, total, _ := globalLogStore.Load().Query(0, 0, 0, 100, nil); total != 0 {
		t.Errorf("after purge total = %d, want 0", total)
	}

	disableLogStore()
	if globalLogStore.Load() != nil {
		t.Error("store should be disabled after disableLogStore")
	}
}

func TestPurgeLogStore_OfflineReset(t *testing.T) {
	old := globalLogStore.Swap(nil)
	oldDir := logStoreDir
	dir := t.TempDir()
	logStoreDir = dir
	t.Cleanup(func() { disableLogStore(); globalLogStore.Store(old); logStoreDir = oldDir })

	// Create a plaintext store on disk, then disable (data kept).
	if err := enableLogStore(context.Background(), dir, 0, 0); err != nil {
		t.Fatalf("enable: %v", err)
	}
	disableLogStore()
	// Drop a salt sidecar to confirm it's removed too.
	_ = os.WriteFile(dir+".salt", []byte("x"), 0o600)

	// Purge while OFF resets the on-disk dir (migration path).
	if err := purgeLogStore(); err != nil {
		t.Fatalf("offline purge: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("store dir should be removed after offline purge, stat err=%v", err)
	}
	if _, err := os.Stat(dir + ".salt"); !os.IsNotExist(err) {
		t.Error("salt sidecar should be removed after offline purge")
	}
}

// TestEnableLogStore_ConcurrentSafe exercises the lifecycle mutex: many
// concurrent enables must publish exactly one store (no double-open, no orphan,
// no panic) — verified under -race.
func TestEnableLogStore_ConcurrentSafe(t *testing.T) {
	old := globalLogStore.Swap(nil)
	oldDir := logStoreDir
	dir := t.TempDir()
	logStoreDir = dir
	t.Cleanup(func() { disableLogStore(); globalLogStore.Store(old); logStoreDir = oldDir })

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = enableLogStore(context.Background(), dir, 7, 1) }()
	}
	wg.Wait()

	ls := globalLogStore.Load()
	if ls == nil {
		t.Fatal("store should be enabled after concurrent enables")
	}
	if ls.RetentionDays() != 7 {
		t.Errorf("RetentionDays = %d, want 7", ls.RetentionDays())
	}
}

func TestApiLogsRetention_EnableDisable(t *testing.T) {
	old := globalLogStore.Swap(nil)
	oldDir := logStoreDir
	logStoreDir = t.TempDir()
	t.Cleanup(func() { disableLogStore(); globalLogStore.Store(old); logStoreDir = oldDir })

	rec := httptest.NewRecorder()
	apiLogsRetention(rec, adminReq(http.MethodPut, "/api/logs/retention", `{"enabled":true,"retentionDays":7,"retentionMaxGB":2}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("enable PUT %d: %s", rec.Code, rec.Body.String())
	}
	ls := globalLogStore.Load()
	if ls == nil {
		t.Fatal("store should be enabled after PUT enabled:true")
	}
	if ls.RetentionDays() != 7 {
		t.Errorf("RetentionDays = %d, want 7", ls.RetentionDays())
	}

	rec = httptest.NewRecorder()
	apiLogsRetention(rec, adminReq(http.MethodPut, "/api/logs/retention", `{"enabled":false}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("disable PUT %d", rec.Code)
	}
	if globalLogStore.Load() != nil {
		t.Error("store should be disabled after PUT enabled:false")
	}
}

func TestLogStoreDiskEstimate(t *testing.T) {
	est := logStoreDiskEstimate()
	if v, _ := est["avgEntryBytes"].(int64); v <= 0 {
		t.Errorf("avgEntryBytes = %v, want > 0", est["avgEntryBytes"])
	}
	for _, k := range []string{"bytesPerDay", "bytesPerWeek", "bytesPerMonth", "reqPerMin"} {
		if _, ok := est[k]; !ok {
			t.Errorf("estimate missing key %q", k)
		}
	}
}

func TestApiLogs_SourceStore(t *testing.T) {
	isolateLogRing(t)
	s, err := logstore.OpenTTL(t.TempDir(), 0, 0, nil, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	old := globalLogStore.Load()
	globalLogStore.Store(s)
	t.Cleanup(func() { globalLogStore.Store(old); _ = s.Close() })

	base := time.Now().UnixMilli()
	for i := 0; i < 20; i++ {
		host, status := "ok.example.com", "OK"
		if i%4 == 0 {
			host, status = "bad.example.com", "BLOCKED"
		}
		logAdd(LogEntry{TS: base + int64(i), IP: "10.0.0.1", Method: "GET", Host: host, Status: status, Level: "INFO"})
	}
	drainLogStore(t, s, 20)

	req := httptest.NewRequest(http.MethodGet, "/api/logs?source=store&filter=bad.example.com", http.NoBody)
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
	old := globalLogStore.Load()
	globalLogStore.Store(nil)
	t.Cleanup(func() { globalLogStore.Store(old) })

	req := httptest.NewRequest(http.MethodGet, "/api/logs?source=store", http.NoBody)
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

func TestApiLogsRetention_GetPut(t *testing.T) {
	s, err := logstore.OpenTTL(t.TempDir(), 7*24*time.Hour, 2<<30, nil, nil) // 7 days, 2 GB
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	old := globalLogStore.Load()
	globalLogStore.Store(s)
	t.Cleanup(func() { globalLogStore.Store(old); _ = s.Close() })

	// GET reports the current policy.
	rec := httptest.NewRecorder()
	apiLogsRetention(rec, httptest.NewRequest(http.MethodGet, "/api/logs/retention", http.NoBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status %d: %s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["enabled"] != true {
		t.Errorf("enabled = %v, want true", got["enabled"])
	}
	if d, _ := got["retentionDays"].(float64); d != 7 {
		t.Errorf("retentionDays = %v, want 7", got["retentionDays"])
	}

	// PUT updates the live store (admin role required).
	rec = httptest.NewRecorder()
	apiLogsRetention(rec, adminReq(http.MethodPut, "/api/logs/retention", `{"retentionDays":30,"retentionMaxGB":5}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT status %d: %s", rec.Code, rec.Body.String())
	}
	if s.RetentionDays() != 30 {
		t.Errorf("after PUT RetentionDays = %d, want 30", s.RetentionDays())
	}
	if s.RetentionMaxGB() != 5 {
		t.Errorf("after PUT RetentionMaxGB = %v, want 5", s.RetentionMaxGB())
	}

	// Out-of-range value is rejected.
	rec = httptest.NewRecorder()
	apiLogsRetention(rec, adminReq(http.MethodPut, "/api/logs/retention", `{"retentionDays":99999}`))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("out-of-range PUT status %d, want 400", rec.Code)
	}
}

// TestApiLogs_TimeRangeMemory locks the from/to units fix: parseTimestampParam
// returns Unix seconds while LogEntry.TS is millis, so apiLogs must convert
// before comparing. Without the fix the range filter matched nothing/everything.
func TestApiLogs_TimeRangeMemory(t *testing.T) {
	isolateLogRing(t)
	oldLS := globalLogStore.Load()
	globalLogStore.Store(nil)
	t.Cleanup(func() { globalLogStore.Store(oldLS) })

	mid := time.Now().Unix()
	add := func(sec int64, host string) {
		logAdd(LogEntry{TS: sec * 1000, IP: "1.1.1.1", Method: "GET", Host: host, Status: "OK", Level: "INFO"})
	}
	add(mid-3600, "old.example.com")
	add(mid, "mid.example.com")
	add(mid+3600, "new.example.com")

	url := fmt.Sprintf("/api/logs?from=%d&to=%d", mid-1, mid+1)
	rec := httptest.NewRecorder()
	apiLogs(rec, httptest.NewRequest(http.MethodGet, url, http.NoBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Logs  []LogEntry `json:"logs"`
		Total int        `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Total != 1 {
		t.Fatalf("time-range total = %d, want 1 (only the mid entry)", resp.Total)
	}
	if resp.Logs[0].Host != "mid.example.com" {
		t.Errorf("matched host = %q, want mid.example.com", resp.Logs[0].Host)
	}
}

func TestApiLogsRetention_ViewerForbidden(t *testing.T) {
	s, err := logstore.OpenTTL(t.TempDir(), 0, 0, nil, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	old := globalLogStore.Load()
	globalLogStore.Store(s)
	t.Cleanup(func() { globalLogStore.Store(old); _ = s.Close() })

	// No admin role on the context → uiRole defaults to viewer → PUT must 403.
	rec := httptest.NewRecorder()
	apiLogsRetention(rec, httptest.NewRequest(http.MethodPut, "/api/logs/retention", strings.NewReader(`{"retentionDays":30}`)))
	if rec.Code != http.StatusForbidden {
		t.Errorf("viewer PUT status = %d, want 403", rec.Code)
	}
}

func TestApiLogsRetention_DisabledConflict(t *testing.T) {
	old := globalLogStore.Load()
	globalLogStore.Store(nil)
	t.Cleanup(func() { globalLogStore.Store(old) })

	rec := httptest.NewRecorder()
	apiLogsRetention(rec, adminReq(http.MethodPut, "/api/logs/retention", `{"retentionDays":30}`))
	if rec.Code != http.StatusConflict {
		t.Errorf("disabled PUT status %d, want 409", rec.Code)
	}
}
