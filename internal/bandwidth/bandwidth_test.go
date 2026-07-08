package bandwidth

// Engine tests moved from package main's bandwidth_test.go during the
// ADR-0002 extraction (whitebox: newTokenBucket, Manager internals). The
// admin-API handler tests stayed in main.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// assertNoTmpLeak fails if dir contains leftover .tmp files (local copy of the
// package-main test helper, as with the fileblock extraction).
func assertNoTmpLeak(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir %s: %v", dir, err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Errorf("tmp file leaked: %s", e.Name())
		}
	}
}

// ─── Token bucket tests ────────────────────────────────────────────────────

func TestTokenBucket_BasicConsume(t *testing.T) {
	tb := newTokenBucket(1000) // 1000 bytes/sec
	// Fresh bucket should have 1000 tokens.
	if !tb.consume(500) {
		t.Fatal("consume(500) should succeed on a fresh 1000 token bucket")
	}
	if !tb.consume(500) {
		t.Fatal("consume(500) should succeed — 500 remaining")
	}
}

func TestTokenBucket_Overdraft(t *testing.T) {
	tb := newTokenBucket(100) // 100 bytes/sec
	// Drain the bucket.
	if !tb.consume(100) {
		t.Fatal("consume(100) should succeed on a fresh 100 token bucket")
	}
	// Now the bucket is empty — any positive consume should fail.
	if tb.consume(1) {
		t.Fatal("consume(1) should fail on an empty bucket")
	}
}

func TestTokenBucket_Refill(t *testing.T) {
	tb := newTokenBucket(1000) // 1000 tokens/sec
	// Drain the bucket.
	if !tb.consume(1000) {
		t.Fatal("drain should succeed")
	}
	if tb.consume(1) {
		t.Fatal("should be empty after drain")
	}

	// Simulate time passing by manually adjusting lastRefill.
	tb.mu.Lock()
	tb.lastRefill = time.Now().Add(-500 * time.Millisecond) // pretend 500ms passed
	tb.mu.Unlock()

	// After 500ms at 1000 tokens/sec, ~500 tokens should be available.
	if !tb.consume(400) {
		t.Fatal("consume(400) should succeed after 500ms refill at 1000/sec")
	}
}

// ─── BandwidthManager tests ────────────────────────────────────────────────

func TestBandwidthManager_AddListDelete(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(filepath.Join(dir, "bw.json"))

	// Initially empty.
	if got := m.List(); len(got) != 0 {
		t.Fatalf("expected 0 policies, got %d", len(got))
	}

	// Add a policy.
	p, err := m.Add(Policy{
		Name:           "test-policy",
		LabelSelector:  map[string]string{"region": "us-east"},
		MaxBytesPerSec: 1024 * 1024, // 1 MB/s
		Priority:       10,
	})
	if err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	if p.Name != "test-policy" {
		t.Fatalf("Name = %q, want %q", p.Name, "test-policy")
	}
	if p.CreatedAt == "" {
		t.Fatal("CreatedAt should be set automatically")
	}

	// List should show it.
	policies := m.List()
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(policies))
	}
	if policies[0].Name != "test-policy" {
		t.Fatalf("listed policy Name = %q, want %q", policies[0].Name, "test-policy")
	}

	// Duplicate name should fail.
	_, err = m.Add(Policy{Name: "test-policy"})
	if err == nil {
		t.Fatal("adding duplicate name should fail")
	}

	// Empty name should fail.
	_, err = m.Add(Policy{Name: ""})
	if err == nil {
		t.Fatal("adding empty name should fail")
	}

	// Negative max_bytes_per_sec should fail.
	_, err = m.Add(Policy{Name: "bad", MaxBytesPerSec: -1})
	if err == nil {
		t.Fatal("adding negative rate should fail")
	}

	// Delete.
	if !m.Delete("test-policy") {
		t.Fatal("Delete should return true for existing policy")
	}
	if m.Delete("test-policy") {
		t.Fatal("Delete should return false for non-existent policy")
	}
	if got := m.List(); len(got) != 0 {
		t.Fatalf("expected 0 policies after delete, got %d", len(got))
	}
}

func TestBandwidthManager_FindPolicy(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(filepath.Join(dir, "bw.json"))

	// Add two policies with different priorities.
	_, _ = m.Add(Policy{
		Name:           "low-priority",
		LabelSelector:  map[string]string{"env": "prod"},
		MaxBytesPerSec: 1024,
		Priority:       1,
	})
	_, _ = m.Add(Policy{
		Name:           "high-priority",
		LabelSelector:  map[string]string{"env": "prod"},
		MaxBytesPerSec: 2048,
		Priority:       100,
	})
	_, _ = m.Add(Policy{
		Name:           "dev-only",
		LabelSelector:  map[string]string{"env": "dev"},
		MaxBytesPerSec: 512,
		Priority:       50,
	})

	// Matching "env=prod" should return highest-priority.
	found := m.FindPolicy(map[string]string{"env": "prod", "region": "us"})
	if found == nil {
		t.Fatal("FindPolicy should find a match for env=prod")
	}
	if found.Name != "high-priority" {
		t.Fatalf("FindPolicy returned %q, want %q", found.Name, "high-priority")
	}

	// Matching "env=dev" should return dev-only.
	found = m.FindPolicy(map[string]string{"env": "dev"})
	if found == nil {
		t.Fatal("FindPolicy should find a match for env=dev")
	}
	if found.Name != "dev-only" {
		t.Fatalf("FindPolicy returned %q, want %q", found.Name, "dev-only")
	}

	// No match.
	found = m.FindPolicy(map[string]string{"env": "staging"})
	if found != nil {
		t.Fatalf("FindPolicy should return nil for unmatched labels, got %q", found.Name)
	}

	// Empty selector matches everything — add one and verify.
	_, _ = m.Add(Policy{
		Name:           "catch-all",
		LabelSelector:  map[string]string{},
		MaxBytesPerSec: 0,
		Priority:       0,
	})
	found = m.FindPolicy(map[string]string{"anything": "goes"})
	if found == nil {
		t.Fatal("empty label selector should match any labels")
	}
	// But if env=prod labels are given, the high-priority (100) should win over catch-all (0).
	found = m.FindPolicy(map[string]string{"env": "prod"})
	if found.Name != "high-priority" {
		t.Fatalf("FindPolicy should prefer high-priority over catch-all, got %q", found.Name)
	}
}

func TestBandwidthManager_Persistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bw.json")

	// Create manager and add a policy.
	m1 := NewManager(path)
	_, err := m1.Add(Policy{
		Name:           "persist-test",
		LabelSelector:  map[string]string{"dc": "us-west-2"},
		MaxBytesPerSec: 10 * 1024 * 1024,
		Priority:       5,
	})
	if err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	// Verify file exists.
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("JSON file should exist after Add")
	}

	// Create a new manager from the same path — it should load the persisted data.
	m2 := NewManager(path)
	policies := m2.List()
	if len(policies) != 1 {
		t.Fatalf("expected 1 persisted policy, got %d", len(policies))
	}
	if policies[0].Name != "persist-test" {
		t.Fatalf("persisted policy Name = %q, want %q", policies[0].Name, "persist-test")
	}
	if policies[0].MaxBytesPerSec != 10*1024*1024 {
		t.Fatalf("persisted MaxBytesPerSec = %d, want %d", policies[0].MaxBytesPerSec, 10*1024*1024)
	}
}

// TestBandwidthManager_Save_NoTmpLeak verifies that the converted writer
// (atomicWriteFile) does not leave orphaned *.tmp.* files in the parent
// directory after a successful Save. Regression guard for D1.1b.
func TestBandwidthManager_Save_NoTmpLeak(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(filepath.Join(dir, "bw.json"))
	if _, err := m.Add(Policy{
		Name:           "tmpleak-test",
		LabelSelector:  map[string]string{"role": "edge"},
		MaxBytesPerSec: 1024,
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	// Add() persists internally via Save(); call Save() again to be explicit.
	m.Save()
	assertNoTmpLeak(t, dir)
}

func TestBandwidthManager_AllowBytes(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(filepath.Join(dir, "bw.json"))

	// Unknown policy = unlimited.
	if !m.AllowBytes("nonexistent", 999999) {
		t.Fatal("AllowBytes for unknown policy should return true")
	}

	// Add policy with 0 rate (unlimited) — no limiter created.
	_, _ = m.Add(Policy{Name: "unlimited", MaxBytesPerSec: 0, Priority: 1})
	if !m.AllowBytes("unlimited", 999999) {
		t.Fatal("AllowBytes for unlimited policy should return true")
	}

	// Add policy with a small rate. Drain bucket fully, then request more
	// than could refill in the few microseconds between calls.
	_, err := m.Add(Policy{Name: "limited", MaxBytesPerSec: 10, Priority: 2})
	if err != nil {
		t.Fatalf("Add limited policy failed: %v", err)
	}
	if !m.AllowBytes("limited", 10) {
		t.Fatal("AllowBytes(10) should succeed — bucket starts full at 10")
	}
	// Even if ~1ms elapses at 10 B/s, that's ~0.01 tokens — not enough for 5.
	if m.AllowBytes("limited", 5) {
		t.Fatal("AllowBytes(5) should fail — bucket just drained, refill too slow")
	}
}

func TestBandwidthManager_ReplaceAll(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(filepath.Join(dir, "bw.json"))

	_, _ = m.Add(Policy{Name: "old", MaxBytesPerSec: 100})

	// Replace with a new set.
	m.ReplaceAll([]Policy{
		{Name: "new-a", MaxBytesPerSec: 200, Priority: 1},
		{Name: "new-b", MaxBytesPerSec: 300, Priority: 2},
	})

	policies := m.List()
	if len(policies) != 2 {
		t.Fatalf("expected 2 policies after ReplaceAll, got %d", len(policies))
	}
	names := map[string]bool{}
	for _, p := range policies {
		names[p.Name] = true
	}
	if !names["new-a"] || !names["new-b"] {
		t.Fatalf("unexpected policy names: %v", names)
	}
	if names["old"] {
		t.Fatal("old policy should be gone after ReplaceAll")
	}
}

// ─── humanRate tests ───────────────────────────────────────────────────────

func TestHumanRate(t *testing.T) {
	tests := []struct {
		input int64
		want  string
	}{
		{0, "unlimited"},
		{-1, "unlimited"},
		{512, "512 B/s"},
		{1024, "1 KB/s"},
		{10 * 1024, "10 KB/s"},
		{1536, "1.5 KB/s"},
		{1024 * 1024, "1 MB/s"},
		{10 * 1024 * 1024, "10 MB/s"},
		{1024 * 1024 * 1024, "1 GB/s"},
		{2 * 1024 * 1024 * 1024, "2 GB/s"},
	}
	for _, tt := range tests {
		got := HumanRate(tt.input)
		if got != tt.want {
			t.Errorf("HumanRate(%d) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ─── API handler tests ─────────────────────────────────────────────────────

// selectorsOverlap tests moved from package main's coverage_boost_test.go
// during the ADR-0002 extraction (unexported helper).
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
