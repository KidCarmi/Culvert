package main

import (
	"os"
	"path/filepath"
	"testing"
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
	if snap.Version != 1 {
		t.Errorf("version = %d, want 1", snap.Version)
	}
	if snap.ExportedAt == "" {
		t.Error("exportedAt should not be empty")
	}
}

// ── bandwidth.go coverage ────────────────────────────────────────────────────

func TestSelectorsOverlap_BothEmpty(t *testing.T) {
	if !selectorsOverlap(nil, nil) {
		t.Error("empty selectors should overlap")
	}
}

func TestSelectorsOverlap_OneEmpty(t *testing.T) {
	if !selectorsOverlap(map[string]string{"env": "prod"}, nil) {
		t.Error("empty selector overlaps with everything")
	}
}

func TestSelectorsOverlap_Disjoint(t *testing.T) {
	a := map[string]string{"env": "prod"}
	b := map[string]string{"env": "staging"}
	if selectorsOverlap(a, b) {
		t.Error("disjoint selectors should not overlap")
	}
}

func TestSelectorsOverlap_Overlapping(t *testing.T) {
	a := map[string]string{"env": "prod", "region": "us"}
	b := map[string]string{"env": "prod", "tier": "web"}
	if !selectorsOverlap(a, b) {
		t.Error("selectors with compatible shared keys should overlap")
	}
}

func TestSelectorsOverlap_Subset(t *testing.T) {
	a := map[string]string{"env": "prod"}
	b := map[string]string{"env": "prod", "region": "eu"}
	if !selectorsOverlap(a, b) {
		t.Error("subset selector should overlap with superset")
	}
}

// ── nodegroup.go coverage ────────────────────────────────────────────────────

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

// ── alerts.go coverage ──────────────────────────────────────────────────────

func TestEnqueueRetry_MaxAttempts(t *testing.T) {
	alertRetryMu.Lock()
	orig := alertRetryQueue
	alertRetryQueue = nil
	alertRetryMu.Unlock()
	defer func() {
		alertRetryMu.Lock()
		alertRetryQueue = orig
		alertRetryMu.Unlock()
	}()

	// Should not enqueue when attempt >= max.
	enqueueRetry("hook-1", AlertPayload{Event: "test"}, alertRetryMax)
	alertRetryMu.Lock()
	count := len(alertRetryQueue)
	alertRetryMu.Unlock()
	if count != 0 {
		t.Errorf("expected 0 entries after max attempts, got %d", count)
	}
}

func TestEnqueueRetry_Success(t *testing.T) {
	alertRetryMu.Lock()
	orig := alertRetryQueue
	alertRetryQueue = nil
	alertRetryMu.Unlock()
	defer func() {
		alertRetryMu.Lock()
		alertRetryQueue = orig
		alertRetryMu.Unlock()
	}()

	enqueueRetry("hook-1", AlertPayload{Event: "test"}, 0)
	alertRetryMu.Lock()
	count := len(alertRetryQueue)
	alertRetryMu.Unlock()
	if count != 1 {
		t.Errorf("expected 1 entry, got %d", count)
	}
}

func TestProcessRetryQueue_Empty(t *testing.T) {
	alertRetryMu.Lock()
	orig := alertRetryQueue
	alertRetryQueue = nil
	alertRetryMu.Unlock()
	defer func() {
		alertRetryMu.Lock()
		alertRetryQueue = orig
		alertRetryMu.Unlock()
	}()

	// Should not panic on empty queue.
	processRetryQueue()
}

func TestSaveAlertRetryQueueLocked(t *testing.T) {
	alertRetryMu.Lock()
	orig := alertRetryQueue
	alertRetryQueue = []retryEntry{{WebhookID: "test", Attempt: 0}}
	alertRetryMu.Unlock()
	defer func() {
		alertRetryMu.Lock()
		alertRetryQueue = orig
		alertRetryMu.Unlock()
	}()

	// Should not panic.
	alertRetryMu.Lock()
	saveAlertRetryQueueLocked()
	alertRetryMu.Unlock()
}

// ── update.go coverage ──────────────────────────────────────────────────────

func TestValidateUpdaterURL(t *testing.T) {
	tests := []struct {
		url     string
		wantErr bool
	}{
		{"http://culvert-updater:7123", false},
		{"https://updater.internal:7123", false},
		{"http://127.0.0.1:7123", false},        // loopback allowed
		{"ftp://updater:21", true},               // bad scheme
		{"://bad", true},                         // unparseable
		{"http://169.254.169.254/latest", true},  // metadata endpoint
		{"http://", true},                        // empty host
	}
	for _, tc := range tests {
		err := validateUpdaterURL(tc.url)
		if (err != nil) != tc.wantErr {
			t.Errorf("validateUpdaterURL(%q) = %v, wantErr=%v", tc.url, err, tc.wantErr)
		}
	}
}

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

// ── update_cluster.go coverage ──────────────────────────────────────────────

func TestClusterUpdateState_Snapshot(t *testing.T) {
	snap := clusterUpdateState.snapshot()
	if snap.Phase == "" && snap.Active {
		t.Error("active state should have a phase")
	}
}

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
