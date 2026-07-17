package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/support"
)

// mkBundles creates n bundles and returns their ids newest-last (creation order).
func mkBundles(t *testing.T, n int) []string {
	t.Helper()
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		res, err := createSupportBundle(context.Background(), "standard", support.L1, "")
		if err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
		ids = append(ids, res.BundleID)
	}
	return ids
}

func liveBundleCount(t *testing.T) int {
	t.Helper()
	return len(listSupportBundles())
}

// TestRetention_CountCap keeps only the newest `keep` bundles (age disabled).
func TestRetention_CountCap(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	mkBundles(t, 3)
	// createSupportBundle already prunes at supportRetentionKeep (10), so all 3
	// remain; now force a tight count cap with age disabled.
	pruneSupportBundlesAt(1, 0, time.Now())
	if got := liveBundleCount(t); got != 1 {
		t.Fatalf("after count cap keep=1: %d bundles remain, want 1", got)
	}
}

// TestRetention_AgeCap evicts bundles older than maxAge even with count headroom.
func TestRetention_AgeCap(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	mkBundles(t, 3)

	// With plenty of count headroom and a real 30-day age at the real clock, all
	// three (just created) survive.
	pruneSupportBundlesAt(100, supportRetentionMaxAge, time.Now())
	if got := liveBundleCount(t); got != 3 {
		t.Fatalf("recent bundles evicted by age: %d remain, want 3", got)
	}

	// Advance the clock an hour and use a 1-second age cap: every bundle is now
	// "too old" and is age-evicted despite the count headroom.
	pruneSupportBundlesAt(100, time.Second, time.Now().Add(time.Hour))
	if got := liveBundleCount(t); got != 0 {
		t.Fatalf("age cap did not evict stale bundles: %d remain, want 0", got)
	}
}

// TestRetention_AgeDisabledKeepsAll proves maxAge<=0 disables the age sweep.
func TestRetention_AgeDisabledKeepsAll(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	mkBundles(t, 2)
	// Far-future now, but age disabled → nothing evicted (count has headroom).
	pruneSupportBundlesAt(100, 0, time.Now().Add(365*24*time.Hour))
	if got := liveBundleCount(t); got != 2 {
		t.Fatalf("age-disabled prune evicted bundles: %d remain, want 2", got)
	}
}

// TestRetention_EvictionAudited confirms an age eviction leaves an audit trail.
func TestRetention_EvictionAudited(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	ids := mkBundles(t, 1)
	baseline := time.Now()
	pruneSupportBundlesAt(100, time.Second, time.Now().Add(time.Hour))
	if _, err := os.Stat(supportBundlesDir() + "/" + ids[0]); !os.IsNotExist(err) {
		t.Fatalf("bundle not evicted (err=%v)", err)
	}
	var found bool
	for _, e := range auditGet() {
		if e.Action == "support.bundle.expire" && e.Object == ids[0] && e.TS >= baseline.UnixMilli()-1000 {
			found = true
		}
	}
	if !found {
		t.Fatalf("no support.bundle.expire audit for evicted bundle %s", ids[0])
	}
}

// TestSupportRetentionJanitor_BootSweep proves the background janitor enforces the
// age cap independently of bundle creation (Codex #791): a pre-existing stale
// bundle is evicted at boot even though createSupportBundle is never called.
func TestSupportRetentionJanitor_BootSweep(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	// Seed a stale (40-day-old) bundle directly on disk — no create path involved.
	id := "csb_aaaaaaaaaaaaaaaaaaaaaaaaaa"
	dir := filepath.Join(supportBundlesDir(), id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	old := time.Now().Add(-40 * 24 * time.Hour).UTC().Format(time.RFC3339)
	man := support.SupportBundleManifest{BundleID: id, Format: "csb/1", CreatedAt: old}
	b, _ := json.Marshal(man)
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), b, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if n := liveBundleCount(t); n != 1 {
		t.Fatalf("seed not listed: %d", n)
	}

	// An already-cancelled context: the boot sweep runs, then the loop returns.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	startSupportRetentionJanitor(ctx)

	if n := liveBundleCount(t); n != 0 {
		t.Fatalf("boot sweep did not evict the stale bundle: %d remain", n)
	}
}
