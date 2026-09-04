package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/blocklist"
)

// ── configversion.go coverage ────────────────────────────────────────────────

func TestDiffConfigs_ScalarChanges(t *testing.T) {
	a := &configBackup{DefaultAction: "allow", BlocklistMode: "block", IPFilterMode: "block", RateLimitRPM: 100}
	b := &configBackup{DefaultAction: "block", BlocklistMode: "allow", IPFilterMode: "allow", RateLimitRPM: 200}
	changes := diffConfigs(a, b)
	if len(changes) != 4 {
		t.Fatalf("expected 4 scalar changes, got %d: %+v", len(changes), changes)
	}
}

func TestDiffConfigs_NoChanges(t *testing.T) {
	a := &configBackup{DefaultAction: "allow"}
	changes := diffConfigs(a, a)
	if len(changes) != 0 {
		t.Fatalf("expected 0 changes for identical configs, got %d", len(changes))
	}
}

func TestDiffStringList(t *testing.T) {
	var changes []configChange
	diffStringList("test", []string{"a", "b", "c"}, []string{"b", "c", "d"}, &changes)
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(changes))
	}
	if changes[0].Field != "test" {
		t.Errorf("field = %q, want test", changes[0].Field)
	}
}

func TestDiffStringList_NoDiff(t *testing.T) {
	var changes []configChange
	diffStringList("test", []string{"a", "b"}, []string{"a", "b"}, &changes)
	if len(changes) != 0 {
		t.Fatalf("expected 0 changes for identical lists, got %d", len(changes))
	}
}

func TestDiffPolicyRules(t *testing.T) {
	a := []PolicyRule{{Priority: 1, Name: "r1"}, {Priority: 2, Name: "r2"}}
	b := []PolicyRule{{Priority: 1, Name: "r1"}, {Priority: 3, Name: "r3"}}
	var changes []configChange
	diffPolicyRules(a, b, &changes)
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(changes))
	}
}

func TestDiffPolicyRules_Renamed(t *testing.T) {
	a := []PolicyRule{{Priority: 1, Name: "old"}}
	b := []PolicyRule{{Priority: 1, Name: "new"}}
	var changes []configChange
	diffPolicyRules(a, b, &changes)
	if len(changes) != 1 {
		t.Fatalf("expected 1 change for renamed rule, got %d", len(changes))
	}
}

func TestDiffRewriteRules(t *testing.T) {
	a := []RewriteRule{{Host: "a.com"}, {Host: "b.com"}}
	b := []RewriteRule{{Host: "b.com"}, {Host: "c.com"}}
	var changes []configChange
	diffRewriteRules(a, b, &changes)
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(changes))
	}
}

func TestDiffRewriteRules_NoDiff(t *testing.T) {
	a := []RewriteRule{{Host: "a.com"}}
	var changes []configChange
	diffRewriteRules(a, a, &changes)
	if len(changes) != 0 {
		t.Fatalf("expected 0 changes, got %d", len(changes))
	}
}

func TestValidateConfigBackup_Valid(t *testing.T) {
	b := &configBackup{
		BlocklistMode: "block",
		DefaultAction: "allow",
		IPFilterMode:  "block",
		RateLimitRPM:  100,
	}
	warnings := validateConfigBackup(b)
	if len(warnings) != 0 {
		t.Fatalf("expected 0 warnings for valid config, got %v", warnings)
	}
}

func TestValidateConfigBackup_InvalidMode(t *testing.T) {
	b := &configBackup{
		BlocklistMode: "invalid",
		DefaultAction: "maybe",
		IPFilterMode:  "neither",
		RateLimitRPM:  -1,
	}
	warnings := validateConfigBackup(b)
	if len(warnings) != 4 {
		t.Fatalf("expected 4 warnings, got %d: %v", len(warnings), warnings)
	}
}

func TestValidateConfigBackup_InvalidRules(t *testing.T) {
	b := &configBackup{
		PolicyRules: []PolicyRule{
			{Priority: 1, Name: "valid", Action: "Allow", DestFQDN: "*"},
			{Priority: 0, Name: "", Action: ""},
		},
	}
	warnings := validateConfigBackup(b)
	found := false
	for _, w := range warnings {
		if len(w) > 0 {
			found = true
		}
	}
	if !found {
		t.Fatal("expected warning about invalid rules")
	}
}

func TestCaptureConfigBackup(t *testing.T) {
	snap := captureConfigBackup()
	if snap == nil {
		t.Fatal("captureConfigBackup returned nil")
	}
	if snap.Version != configBackupVersion {
		t.Errorf("version = %d, want %d", snap.Version, configBackupVersion)
	}
	if snap.ExportedAt == "" {
		t.Error("exportedAt should not be empty")
	}
}

// ── bandwidth.go coverage ────────────────────────────────────────────────────

func TestNodeGroupStore_Get(t *testing.T) {
	dir := t.TempDir()
	s := NewNodeGroupStore(filepath.Join(dir, "ng.json"))

	_, ok := s.Get("nonexistent")
	if ok {
		t.Error("Get should return false for nonexistent group")
	}

	s.Add(NodeGroup{Name: "test-group", LabelSelector: map[string]string{"env": "prod"}})
	g, ok := s.Get("test-group")
	if !ok {
		t.Fatal("Get should return true for existing group")
	}
	if g.Name != "test-group" {
		t.Errorf("name = %q, want test-group", g.Name)
	}
}

// ── alerts.go coverage — the F16 retry-queue tests moved in-package to
// internal/alerts/retry_test.go with the delivery-engine extraction
// (ADR-0002).

// ── configversion.go load/save coverage ─────────────────────────────────────

func TestLoadConfigVersion_NotFound(t *testing.T) {
	_, err := loadConfigVersion(99999)
	if err == nil {
		t.Error("expected error for nonexistent version")
	}
}

func TestDiffConfigs_ListChanges(t *testing.T) {
	a := &configBackup{
		Blocklist:           []string{"a.com", "b.com"},
		SSLBypass:           []string{"ssl.com"},
		ContentScanPatterns: []string{"pat1"},
		FileBlockExtensions: []string{".exe"},
		IPList:              []string{"10.0.0.1"},
		PolicyRules:         []PolicyRule{{Priority: 1, Name: "r1"}},
		RewriteRules:        []RewriteRule{{Host: "h1.com"}},
	}
	b := &configBackup{
		Blocklist:           []string{"b.com", "c.com"},
		SSLBypass:           []string{"ssl2.com"},
		ContentScanPatterns: []string{"pat2"},
		FileBlockExtensions: []string{".dll"},
		IPList:              []string{"10.0.0.2"},
		PolicyRules:         []PolicyRule{{Priority: 2, Name: "r2"}},
		RewriteRules:        []RewriteRule{{Host: "h2.com"}},
	}
	changes := diffConfigs(a, b)
	if len(changes) < 5 {
		t.Errorf("expected at least 5 list-level changes, got %d", len(changes))
	}
}

// ── blockpage.go coverage ────────────────────────────────────────────────────

func TestNodeGroupStore_Save(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ng.json")
	s := NewNodeGroupStore(path)

	s.Add(NodeGroup{Name: "g1", LabelSelector: map[string]string{"a": "b"}})
	s.Save()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read saved file: %v", err)
	}
	if len(data) == 0 {
		t.Error("saved file should not be empty")
	}
}

func TestBandwidthManager_Save(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bw.json")
	m := NewBandwidthManager(path)

	m.Add(BandwidthPolicy{Name: "p1", MaxBytesPerSec: 100, Priority: 1})
	m.Save()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read saved file: %v", err)
	}
	if len(data) == 0 {
		t.Error("saved file should not be empty")
	}
}

func TestBandwidthConflictDetection(t *testing.T) {
	dir := t.TempDir()
	m := NewBandwidthManager(filepath.Join(dir, "bw.json"))

	_, err := m.Add(BandwidthPolicy{Name: "a", MaxBytesPerSec: 100, Priority: 1,
		LabelSelector: map[string]string{"env": "prod"}})
	if err != nil {
		t.Fatalf("first add failed: %v", err)
	}

	// Same priority + overlapping selector should fail.
	_, err = m.Add(BandwidthPolicy{Name: "b", MaxBytesPerSec: 200, Priority: 1,
		LabelSelector: map[string]string{"env": "prod"}})
	if err == nil {
		t.Error("expected conflict error for same priority + overlapping selector")
	}

	// Different priority should succeed.
	_, err = m.Add(BandwidthPolicy{Name: "c", MaxBytesPerSec: 200, Priority: 2,
		LabelSelector: map[string]string{"env": "prod"}})
	if err != nil {
		t.Fatalf("different priority should not conflict: %v", err)
	}

	// Disjoint selector at same priority should succeed.
	_, err = m.Add(BandwidthPolicy{Name: "d", MaxBytesPerSec: 200, Priority: 1,
		LabelSelector: map[string]string{"env": "staging"}})
	if err != nil {
		t.Fatalf("disjoint selector should not conflict: %v", err)
	}
}

// cleanupRuleMet removes entries from the global ruleMet to avoid test interaction.
// Must remove from both hits map AND order slice to prevent nil pointer in otlpRuleMetrics.
func cleanupRuleMet(names ...string) {
	ruleMet.mu.Lock()
	defer ruleMet.mu.Unlock()
	for _, name := range names {
		delete(ruleMet.hits, name)
		delete(ruleMet.last, name)
	}
	// Rebuild order without the deleted names.
	nameSet := make(map[string]bool, len(names))
	for _, n := range names {
		nameSet[n] = true
	}
	clean := ruleMet.order[:0]
	for _, n := range ruleMet.order {
		if !nameSet[n] {
			clean = append(clean, n)
		}
	}
	ruleMet.order = clean
}

// ── Hit counter persistence (metrics.go) ────────────────────────────────────

func TestSaveAndLoadHitCounters(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hit_counters.json")

	// saveHitCounters treats the live policy store as authoritative and only falls
	// back to persisting the raw ruleMet counters when policyStore is EMPTY. This
	// test drives that fallback path with synthetic rule names that exist only in
	// ruleMet, so it must run against an empty policy store. Otherwise an unrelated
	// test that leaves rules in the global store (test ordering under -shuffle or
	// the default registration order) makes saveHitCounters skip the fallback and
	// the synthetic counters are never persisted — an order-dependent flake.
	// Isolate the global store for the duration of the test and restore it after.
	savedRules := policyStore.List()
	policyStore.ReplaceAll(nil)
	t.Cleanup(func() { policyStore.ReplaceAll(savedRules) })

	// Use unique rule names to avoid polluting other tests.
	ruleMet.RecordHit("test-save-alpha")
	ruleMet.RecordHit("test-save-alpha")
	ruleMet.RecordHit("test-save-beta")
	defer cleanupRuleMet("test-save-alpha", "test-save-beta")

	saveHitCounters(path)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var counts map[string]persistedRuleCounter
	if err := json.Unmarshal(data, &counts); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if counts["test-save-alpha"].Hits < 2 {
		t.Errorf("test-save-alpha count = %d, want >= 2", counts["test-save-alpha"].Hits)
	}

	// Clear in-memory and restore.
	cleanupRuleMet("test-save-alpha", "test-save-beta")

	loadHitCounters(path)

	ruleMet.mu.RLock()
	alphaPtr := ruleMet.hits["test-save-alpha"]
	betaPtr := ruleMet.hits["test-save-beta"]
	ruleMet.mu.RUnlock()

	if alphaPtr == nil {
		t.Fatal("test-save-alpha not restored")
	}
	if atomic.LoadInt64(alphaPtr) < 2 {
		t.Errorf("restored test-save-alpha = %d, want >= 2", atomic.LoadInt64(alphaPtr))
	}
	if betaPtr == nil || atomic.LoadInt64(betaPtr) < 1 {
		t.Error("test-save-beta not restored or count < 1")
	}
}

func TestLoadHitCounters_MissingFile(t *testing.T) {
	loadHitCounters("/nonexistent/path/counters.json")
}

func TestLoadHitCounters_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	os.WriteFile(path, []byte("{invalid"), 0o600)
	loadHitCounters(path)
}

func TestStartHitCounterPersistence_SaveOnShutdown(t *testing.T) {
	withEmptyPolicyStore(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "counters.json")

	// Pre-record a hit so there's something to save.
	ruleMet.RecordHit("test-shutdown-save")
	defer cleanupRuleMet("test-shutdown-save")

	// saveHitCounters is what startHitCounterPersistence calls on shutdown.
	saveHitCounters(path)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var counts map[string]persistedRuleCounter
	if err := json.Unmarshal(data, &counts); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if counts["test-shutdown-save"].Hits < 1 {
		t.Error("test-shutdown-save not saved")
	}
}

// ── Password complexity (store.go) ──────────────────────────────────────────

func TestValidatePasswordComplexity(t *testing.T) {
	tests := []struct {
		pass string
		ok   bool
	}{
		{"Abcdef1!", true},
		{"Password1", true},
		{"Ab1cdefg", true},
		{"short1A", false},
		{"abcdefgh1", false},
		{"ABCDEFGH1", false},
		{"Abcdefghi", false},
		{"12345678", false},
		{"", false},
		{"Aa1" + strings.Repeat("x", 69), true},  // 72 bytes — bcrypt's max, must still pass
		{"Aa1" + strings.Repeat("x", 70), false}, // 73 bytes — over bcrypt's hard limit
	}
	for _, tt := range tests {
		err := validatePasswordComplexity(tt.pass)
		if (err == nil) != tt.ok {
			t.Errorf("validatePasswordComplexity(%q) err=%v, wantOK=%v", tt.pass, err, tt.ok)
		}
	}
}

// ── DNS error detection (proxy.go) ──────────────────────────────────────────

func TestIsDNSError(t *testing.T) {
	dnsErr := &net.DNSError{Err: "no such host", Name: "bad.example.com"}
	if !isDNSError(dnsErr) {
		t.Error("expected isDNSError true for *net.DNSError")
	}
	if isDNSError(net.UnknownNetworkError("tcp")) {
		t.Error("expected isDNSError false for non-DNS error")
	}
	if isDNSError(nil) {
		t.Error("expected isDNSError false for nil")
	}
}

// ── Request log persistence ─────────────────────────────────────────────────
// The Init + persistent-read (H1) engine tests moved to internal/reqlog
// (ADR-0002, store.go decomposition Phase C). resetRequestLogState lives in
// events_livefeed_test.go as a thin wrapper over reqlog.ResetForTest.

// TestApiLogs_SourceFile exercises the new ?source=file branch end-to-end:
// entries on disk should be returned via the API in newest-first order,
// filtered by host, and paginated — exactly like the in-memory path.
func TestApiLogs_SourceFile(t *testing.T) {
	t.Cleanup(resetRequestLogState)

	// Isolate global in-memory log state so logAdd side-effects here don't
	// leak into other tests that inspect the ring buffer.
	isolateLogRing(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "request.jsonl")
	if err := initRequestLog(path, 10); err != nil {
		t.Fatalf("initRequestLog: %v", err)
	}

	base := time.Now().UnixMilli()
	for i := 0; i < 30; i++ {
		host := "good.example.com"
		status := "OK"
		if i%3 == 0 {
			host = "bad.example.com"
			status = "BLOCKED"
		}
		logAdd(LogEntry{
			TS:     base + int64(i),
			Time:   "12:00:00",
			IP:     "10.0.0.1",
			Method: "GET",
			Host:   host,
			Status: status,
			Level:  "INFO",
		})
	}

	// Issue an HTTP request against apiLogs with ?source=file&filter=bad.
	// uiRole() defaults to RoleViewer when no session is on the context, so
	// requireRole(RoleViewer) passes without any auth setup — matches the
	// existing TestAPILogs_Pagination pattern a few tests below.
	req := httptest.NewRequest(http.MethodGet, "/api/logs?source=file&filter=bad.example.com", nil)
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
		t.Fatalf("unmarshal response: %v; body=%s", err, rec.Body.String())
	}
	// 30 entries, 1 in 3 is bad → 10 matches.
	if resp.Total != 10 {
		t.Errorf("filtered total = %d, want 10", resp.Total)
	}
	for _, e := range resp.Logs {
		if e.Host != "bad.example.com" {
			t.Errorf("unexpected host in filtered result: %q", e.Host)
		}
	}
	// Newest-first.
	for i := 1; i < len(resp.Logs); i++ {
		if resp.Logs[i-1].TS < resp.Logs[i].TS {
			t.Errorf("apiLogs file result not newest-first at idx %d", i)
			break
		}
	}
}

// ── Syslog test endpoint (ui.go) ────────────────────────────────────────────

func TestAPISyslogTest_NotConfigured(t *testing.T) {
	oldSyslog := globalSyslog
	globalSyslog = nil
	defer func() { globalSyslog = oldSyslog }()

	req := httptest.NewRequest(http.MethodPost, "/api/syslog/test", nil)
	w := httptest.NewRecorder()
	apiSyslogTest(w, req)
	// Without auth session, returns 403; without syslog configured, returns 503.
	// Both are acceptable — the endpoint is reachable and functional.
	if w.Code != http.StatusServiceUnavailable && w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 503 or 403", w.Code)
	}
}

func TestAPISyslogTest_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/syslog/test", nil)
	w := httptest.NewRecorder()
	apiSyslogTest(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

// ── Syslog WriteRequest (syslog.go) ─────────────────────────────────────────

func TestSyslogWriter_WriteRequest(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer conn.Close()

	sw, err := newSyslogWriter("udp", conn.LocalAddr().String(), "rfc3164")
	if err != nil {
		t.Fatalf("newSyslogWriter: %v", err)
	}
	defer sw.Close()

	sw.WriteRequest(LogEntry{
		TS: time.Now().UnixMilli(), Time: "12:34:56",
		IP: "10.0.0.1", Method: "GET", Host: "example.com", Status: "OK", Level: "INFO",
	})

	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if n == 0 {
		t.Error("no syslog message received")
	}
}

// ── Blocklist feed Sync (blocklist_feed.go) ─────────────────────────────────

func TestBlocklistSyncer_Sync_BadURL(t *testing.T) {
	testBL := blocklist.New()
	bs := newBlocklistSyncer(testBL)
	bs.SetFeed("http://127.0.0.1:1/nonexistent", 24*time.Hour)
	count, err := bs.SyncAll()
	if err == nil {
		t.Error("expected error for bad URL")
	}
	if count != 0 {
		t.Errorf("count = %d, want 0", count)
	}
	feeds := bs.Feeds()
	if len(feeds) != 1 || feeds[0].LastError == "" {
		t.Errorf("feed should record LastError; got %+v", feeds)
	}
}

// ── Log pagination (ui.go apiLogs) ──────────────────────────────────────────

func TestAPILogs_Pagination(t *testing.T) {
	isolateLogRing(t)

	for i := 0; i < 10; i++ {
		logAdd(LogEntry{
			TS: time.Now().UnixMilli() + int64(i), Method: "GET",
			Host: "test.com", Status: "OK", Level: "INFO",
		})
	}

	req := httptest.NewRequest(http.MethodGet, "/api/logs?limit=3&offset=0", nil)
	w := httptest.NewRecorder()
	apiLogs(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var resp struct {
		Logs  []LogEntry `json:"logs"`
		Total int        `json:"total"`
	}
	json.NewDecoder(w.Body).Decode(&resp)
	if len(resp.Logs) != 3 {
		t.Errorf("got %d logs, want 3", len(resp.Logs))
	}
	if resp.Total != 10 {
		t.Errorf("total = %d, want 10", resp.Total)
	}
}
