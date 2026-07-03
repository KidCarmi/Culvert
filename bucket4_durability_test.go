package main

// bucket4_durability_test.go — focused tests for the five Save paths
// hardened by the Bucket-4 durability sweep.
//
// Pre-Bucket-4 each of these Save methods used os.WriteFile to a
// tmp file + os.Rename — atomic-via-rename but **not** fsynced. The
// rows in roadmap/CLUSTER-RUNTIME-DISCOVERY.md §8.1 bucket 4 (P3.4
// scope) flagged them as blocking P3.4's caller-side Save hooks
// because adding `.Save()` after `ReplaceAll`/`Set` would amplify
// the non-fsync gap on every cluster sync.
//
// This PR routes each through atomicWriteFile (unique tmp + chmod +
// fsync(file) + rename + best-effort fsync(parent dir)) so a follow-
// up PR can safely install the caller-side hooks.
//
// Test pattern (mirror of CL-7 / cluster_persistence_atomic_test.go):
//   - construct a tempdir-scoped instance of the store
//   - populate it with a known fixture
//   - call the Save method
//   - assert the result file exists with mode 0o600
//   - assert no `.tmp.*` leftovers remain in the dir (atomicWriteFile
//     cleans up on both the success and the error paths)
//   - round-trip the content where the store has a public Load API
//
// The tests verify call-site wiring (Bucket-4 stores now route through
// atomicWriteFile), not fsync itself — atomicWriteFile has its own
// existing tests at main.go:2093+ and was exercised end-to-end by
// CL-7 / PR #244.
//
// Out of scope (per the user brief):
//   - bl (Blocklist.Save) — separate path-ownership problem (apply
//     path replaces bl wholesale, losing the path)
//   - any applyConfigSnapshot caller-side Save hooks
//   - HA / runClusterUpdate / config-versioning / metrics

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/threatfeed"
)

// ─── catStore (CategoryStore) ───────────────────────────────────────

// TestBucket4_CategoryStore_Save_AtomicWriteFile verifies that
// CategoryStore.Save now routes through atomicWriteFile (was plain
// os.WriteFile+os.Rename without fsync per P6.1 UC-1).
func TestBucket4_CategoryStore_Save_AtomicWriteFile(t *testing.T) {
	ensureClusterPersistTestLogger(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "categories.json")

	cs := newCategoryStore(nil)
	cs.path = path
	if err := cs.Set("bucket4-test-cat", []string{"example.com", "test.com"}, false); err != nil {
		t.Fatalf("seed Set: %v", err)
	}
	cs.Save()

	assertFileMode0600(t, path)
	assertNoTmpLeftovers(t, dir)

	// Round-trip via a fresh store + Load.
	fresh := &CategoryStore{}
	if err := fresh.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	entries := fresh.All()
	if len(entries) != 1 {
		t.Fatalf("loaded %d entries, want 1", len(entries))
	}
	if entries[0].Name != "bucket4-test-cat" {
		t.Errorf("entries[0].Name = %q, want bucket4-test-cat", entries[0].Name)
	}
	if len(entries[0].Hosts) != 2 {
		t.Errorf("entries[0].Hosts len = %d, want 2", len(entries[0].Hosts))
	}
}

// ─── globalCategoryGroups (CategoryGroupStore) ──────────────────────

// TestBucket4_CategoryGroupStore_Save_AtomicWriteFile verifies that
// CategoryGroupStore.Save now routes through atomicWriteFile (was
// plain os.WriteFile+os.Rename without fsync per P6.1 UC-1).
func TestBucket4_CategoryGroupStore_Save_AtomicWriteFile(t *testing.T) {
	ensureClusterPersistTestLogger(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "category_groups.json")

	s := &CategoryGroupStore{
		groups: make(map[string]*CategoryGroup),
		path:   path,
	}
	if _, err := s.Add("bucket4-test-group", []string{"Adult", "Gambling"}); err != nil {
		t.Fatalf("seed Add: %v", err)
	}
	s.Save()

	assertFileMode0600(t, path)
	assertNoTmpLeftovers(t, dir)

	// Round-trip via Load on a fresh store.
	fresh := &CategoryGroupStore{groups: make(map[string]*CategoryGroup)}
	if err := fresh.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	groups := fresh.List()
	if len(groups) != 1 {
		t.Fatalf("loaded %d groups, want 1", len(groups))
	}
	if groups[0].Name != "bucket4-test-group" {
		t.Errorf("groups[0].Name = %q, want bucket4-test-group", groups[0].Name)
	}
	if len(groups[0].Categories) != 2 {
		t.Errorf("groups[0].Categories len = %d, want 2", len(groups[0].Categories))
	}
}

// ─── sslBypass (SSLBypassMatcher) ───────────────────────────────────

// TestBucket4_SSLBypassMatcher_Save_AtomicWriteFile verifies that
// SSLBypassMatcher.Save now routes through atomicWriteFile (was
// plain os.WriteFile+os.Rename without fsync).
func TestBucket4_SSLBypassMatcher_Save_AtomicWriteFile(t *testing.T) {
	ensureClusterPersistTestLogger(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "ssl_bypass.json")

	m := &SSLBypassMatcher{path: path}
	if err := m.Set([]string{"*.bank.example", "*.payments.example"}); err != nil {
		t.Fatalf("seed Set: %v", err)
	}
	m.Save()

	assertFileMode0600(t, path)
	assertNoTmpLeftovers(t, dir)

	// Round-trip via Load on a fresh matcher.
	fresh := &SSLBypassMatcher{}
	if err := fresh.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	patterns := fresh.List()
	if len(patterns) != 2 {
		t.Fatalf("loaded %d patterns, want 2", len(patterns))
	}
}

// ─── dpiScanner (ContentScanner) ────────────────────────────────────

// TestBucket4_ContentScanner_Save_AtomicWriteFile verifies that
// ContentScanner.Save now routes through atomicWriteFile (was plain
// os.WriteFile+os.Rename without fsync per P6.2 SC-4).
func TestBucket4_ContentScanner_Save_AtomicWriteFile(t *testing.T) {
	ensureClusterPersistTestLogger(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "dpi_patterns.json")

	s := newContentScanner(1 << 20)
	s.SetPath(path)
	if err := s.Set([]string{`bucket4-dpi-test-regex`}); err != nil {
		t.Fatalf("seed Set: %v", err)
	}
	s.Save()

	assertFileMode0600(t, path)
	assertNoTmpLeftovers(t, dir)

	// Round-trip via Load on a fresh scanner.
	fresh := newContentScanner(0)
	if err := fresh.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := len(fresh.List()); got != 1 {
		t.Fatalf("loaded %d patterns, want 1", got)
	}
	if fresh.List()[0] != "bucket4-dpi-test-regex" {
		t.Errorf("fresh.List()[0] = %q, want bucket4-dpi-test-regex", fresh.List()[0])
	}
}

// ─── globalThreatFeed (ThreatFeed.saveToDisk) ───────────────────────

// TestBucket4_ThreatFeed_SaveToDisk_AtomicWriteFile verifies that
// ThreatFeed persistence routes through the durable atomic writer (was
// plain os.WriteFile+os.Rename without fsync per P6.2 SC-4).
//
// Driven through the public API since the extraction to
// internal/threatfeed (ADR-0002): Save() wraps the internal saveToDisk;
// SetDomainAllowlist auto-persists. The durability properties under
// test — file mode 0600, no tmp leftovers, snake_case feedDB shape —
// are all observable on disk.
func TestBucket4_ThreatFeed_SaveToDisk_AtomicWriteFile(t *testing.T) {
	ensureClusterPersistTestLogger(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "threatfeed.json")

	tf := threatfeed.New()
	tf.Init(path, time.Hour) // missing file → load no-op; enables persistence
	tf.SeedForTest(
		map[string]string{"http://bucket4-test.example/x": "test"},
		map[string]string{"bucket4-test.example": "test"},
	)
	tf.SetDomainAllowlist([]string{"trusted-bucket4.example"})
	tf.Save()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("Save did not persist: %v", err)
	}

	assertFileMode0600(t, path)
	assertNoTmpLeftovers(t, dir)

	// Round-trip the JSON to confirm content survives. The on-disk
	// shape is the unexported `feedDB` struct (threatfeed.go:423–428);
	// we partially decode via a structural map and assert key fields.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// feedDB JSON tags are snake_case (threatfeed.go:42–47).
	if _, ok := decoded["urls"]; !ok {
		t.Error("on-disk feedDB missing urls field")
	}
	if _, ok := decoded["domains"]; !ok {
		t.Error("on-disk feedDB missing domains field")
	}
	if _, ok := decoded["domain_allowlist"]; !ok {
		t.Error("on-disk feedDB missing domain_allowlist field")
	}
}
