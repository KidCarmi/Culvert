package main

// blocklist_apply_persist_test.go — P3.4 / CL-1 Blocklist ownership
// investigation + (after the fix in this same PR) regression guard.
//
// Lifecycle traced before fixing (recorded for the PR's investigation
// section):
//
//   1. init (store.go:538): `var bl = &Blocklist{...}` with
//      pre-allocated maps and zero-value path/mode.
//   2. boot load: bl.Load(path) at store.go:572 sets b.path = path
//      AND loads the main file + .mode/.manual/.exceptions sidecars.
//   3. Save (store.go:645): early-returns when b.path == "".
//   4. apply (controlplane.go:1471–1480): `newBL := &Blocklist{...};
//      bl = newBL` — the new instance has empty path/mode and empty
//      manual/exceptions maps. The old instance's persistence path
//      is unreachable from `bl` afterward.
//   5. restart: bl.Load(path) re-reads disk. The on-disk file was
//      whatever was written at boot — never updated post-apply.
//
// The persistence loss this PR fixes
// ===================================
// Pre-fix behaviour:
//   - applyConfigSnapshot mutates bl in memory only.
//   - bl.path is lost on the wholesale replacement, so any caller-
//     side bl.Save() call (with or without this PR's fix) is a no-op.
//   - On DP restart bl.Load(path) reads STALE on-disk data
//     (whatever was written at boot — not the most-recently-applied
//     cluster snapshot). Stale window: until next heartbeat (~30s).
//
// Post-fix behaviour (this PR):
//   - Blocklist.Save is hardened to atomicWriteFile (Bucket-4
//     alignment).
//   - A new Blocklist.ReplaceFeedEntries([]string) method mutates
//     the feed-only fields (exact + wildcards) in place under
//     b.mu.Lock, leaving b.path / b.mode / b.manual / b.exceptions
//     intact.
//   - applyConfigSnapshot calls bl.ReplaceFeedEntries(...) +
//     bl.Save() instead of the wholesale-replacement pattern.
//
// As a side benefit the fix also closes the related ownership
// defect where b.mode / b.manual / b.exceptions were being
// zeroed in memory on every snapshot apply (they survived restart
// because the sidecar files remained on disk, but they vanished
// during the active session). That property is verified by the
// secondary test below.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// snapshotBL captures and restores the package-global bl pointer
// for the duration of the test. Mirrors the PR #241 / #245
// whitebox snapshot+restore idiom used elsewhere in this package.
func snapshotBL(t *testing.T) {
	t.Helper()
	orig := bl
	t.Cleanup(func() { bl = orig })
}

// TestApplyConfigSnapshot_BlocklistPersist exercises the
// caller-side persistence claim: applying a cluster snapshot with
// BlockedHosts should update the on-disk blocklist file so a DP
// restart reads the latest state.
//
// Pre-fix: this test FAILS because (a) bl is wholesale-replaced
// with a fresh instance whose .path == "" (controlplane.go:1471–
// 1480 pre-fix), (b) Blocklist.Save then early-returns when path
// is empty (store.go:646), and (c) even if Save were called with
// the path preserved, the pre-fix Save used os.Rename without
// fsync. The fix in this PR closes all three.
func TestApplyConfigSnapshot_BlocklistPersist(t *testing.T) {
	ensureClusterPersistTestLogger(t)
	snapshotBL(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "blocklist.txt")

	// Seed an initial file so bl.Load succeeds and bl.path is set
	// to the tempdir path. The initial host represents whatever was
	// on disk at boot.
	if err := os.WriteFile(path, []byte("boot-time-host.example\n"), 0o600); err != nil {
		t.Fatalf("seed write: %v", err)
	}

	bl = &Blocklist{
		exact:      map[string]bool{},
		wildcards:  map[string]bool{},
		manual:     map[string]bool{},
		exceptions: map[string]bool{},
	}
	if err := bl.Load(path); err != nil {
		t.Fatalf("bl.Load: %v", err)
	}
	if bl.path == "" {
		t.Fatal("invariant: bl.path should be set after Load")
	}
	if !bl.IsBlocked("boot-time-host.example") {
		t.Fatal("invariant: initial host should be blocked after Load")
	}

	// Apply a snapshot containing a NEW host (replacing the feed).
	snap := ConfigSnapshot{
		Version:      1,
		BlockedHosts: []string{"cluster-pushed-host.example"},
	}
	applyConfigSnapshot(snap)

	// In-memory: the new host should be blocked, and the old
	// boot-time host should NOT be (the snapshot is the source of
	// truth for the feed).
	if !bl.IsBlocked("cluster-pushed-host.example") {
		t.Error("post-apply: cluster-pushed-host.example not in memory")
	}
	if bl.IsBlocked("boot-time-host.example") {
		t.Error("post-apply: boot-time-host.example should have been replaced")
	}

	// On-disk: the cluster-pushed snapshot should be persisted so a
	// DP restart reloads the most-recently-applied state. This is
	// the actual P3.4 / CL-1 claim under test.
	diskContent, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read disk after apply: %v", err)
	}
	got := string(diskContent)
	if !strings.Contains(got, "cluster-pushed-host.example") {
		t.Fatalf("disk does not contain cluster-pushed-host.example after apply (persistence loss); content:\n%s", got)
	}
	if strings.Contains(got, "boot-time-host.example") {
		t.Fatalf("disk still contains boot-time-host.example after apply (stale data not replaced); content:\n%s", got)
	}
}

// TestApplyConfigSnapshot_BlocklistPreservesLocalState verifies the
// secondary property of the fix: applyConfigSnapshot must NOT zero
// the DP-local fields (mode, manual, exceptions) that are not part
// of the cluster snapshot. Pre-fix the wholesale replacement
// silently lost these in memory until next restart.
//
// This test passes once the fix replaces `bl = newBL` with an
// in-place ReplaceFeedEntries that touches only exact + wildcards.
func TestApplyConfigSnapshot_BlocklistPreservesLocalState(t *testing.T) {
	ensureClusterPersistTestLogger(t)
	snapshotBL(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "blocklist.txt")

	if err := os.WriteFile(path, []byte("initial-feed.example\n"), 0o600); err != nil {
		t.Fatalf("seed main: %v", err)
	}
	// Seed sidecars so bl.Load sets mode / manual / exceptions.
	if err := os.WriteFile(path+".mode", []byte("allow"), 0o600); err != nil {
		t.Fatalf("seed mode: %v", err)
	}
	if err := os.WriteFile(path+".manual", []byte("admin-added.example\n"), 0o600); err != nil {
		t.Fatalf("seed manual: %v", err)
	}
	if err := os.WriteFile(path+".exceptions", []byte("never-block.example\n"), 0o600); err != nil {
		t.Fatalf("seed exceptions: %v", err)
	}

	bl = &Blocklist{
		exact:      map[string]bool{},
		wildcards:  map[string]bool{},
		manual:     map[string]bool{},
		exceptions: map[string]bool{},
	}
	if err := bl.Load(path); err != nil {
		t.Fatalf("bl.Load: %v", err)
	}

	// Invariants from the load.
	if bl.Mode() != "allow" {
		t.Fatalf("invariant: bl.Mode() = %q, want allow (after sidecar load)", bl.Mode())
	}
	gotExceptions := bl.ListExceptions()
	if len(gotExceptions) != 1 || gotExceptions[0] != "never-block.example" {
		t.Fatalf("invariant: exceptions = %v, want [never-block.example]", gotExceptions)
	}

	// Apply a snapshot — the cluster snapshot has no fields for
	// mode/manual/exceptions, so those must survive untouched.
	snap := ConfigSnapshot{
		Version:      1,
		BlockedHosts: []string{"cluster-pushed.example"},
	}
	applyConfigSnapshot(snap)

	// Post-apply: mode / manual / exceptions must all still be present.
	if bl.Mode() != "allow" {
		t.Errorf("post-apply: bl.Mode() = %q, want allow (mode was zeroed by wholesale replacement)", bl.Mode())
	}
	gotExceptions = bl.ListExceptions()
	if len(gotExceptions) != 1 || gotExceptions[0] != "never-block.example" {
		t.Errorf("post-apply: exceptions = %v, want [never-block.example] (exceptions zeroed by wholesale replacement)", gotExceptions)
	}
	// Manual hosts are tracked by bl.manual map; List() returns
	// every blocked host (exact ∪ wildcards), so manual entries
	// appear there if they were pre-loaded. Check via IsBlocked.
	if !bl.IsBlocked("admin-added.example") {
		// admin-added was loaded into b.manual but not into b.exact
		// (load semantics — manual is a tag-set, not an entry-set).
		// IsBlocked may not reflect it; instead assert b.manual is
		// non-empty via a direct whitebox check.
		bl.mu.RLock()
		hasAdminAdded := bl.manual["admin-added.example"]
		bl.mu.RUnlock()
		if !hasAdminAdded {
			t.Errorf("post-apply: bl.manual lost admin-added.example (wholesale replacement zeroed manual map)")
		}
	}
}
