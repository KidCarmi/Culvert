package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/support"
)

func writeFakeBundle(t *testing.T, id, createdAt string) {
	t.Helper()
	dir := filepath.Join(supportBundlesDir(), id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	man := support.SupportBundleManifest{Format: support.BundleFormat, BundleID: id, CreatedAt: createdAt}
	b, err := json.Marshal(man)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), b, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
}

func bundleDirExists(id string) bool {
	_, err := os.Stat(filepath.Join(supportBundlesDir(), id))
	return err == nil
}

// TestPruneSupportBundlesByAge proves the age sweep evicts bundles older than the
// max age, keeps recent ones, and — critically — KEEPS a bundle whose timestamp is
// unparseable (a parse failure must never trigger an eviction).
func TestPruneSupportBundlesByAge(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	now := time.Unix(1_800_000_000, 0).UTC()
	const (
		oldID = "csb_oldretentionaaaa234567abcd"
		newID = "csb_newretentionaaaa234567abcd"
		badID = "csb_badtimeretentionn234567abc"
	)
	writeFakeBundle(t, oldID, now.Add(-60*24*time.Hour).Format(time.RFC3339)) // > 30d → evict
	writeFakeBundle(t, newID, now.Add(-1*24*time.Hour).Format(time.RFC3339))  // < 30d → keep
	writeFakeBundle(t, badID, "not-a-timestamp")                              // unparseable → keep

	pruneSupportBundlesByAge(now, supportRetentionMaxAge)

	if bundleDirExists(oldID) {
		t.Error("bundle older than max age was not evicted")
	}
	if !bundleDirExists(newID) {
		t.Error("recent bundle was wrongly evicted")
	}
	if !bundleDirExists(badID) {
		t.Error("bundle with unparseable timestamp was evicted (fail-safe violated)")
	}

	// maxAge <= 0 is a no-op (never evicts).
	writeFakeBundle(t, oldID, now.Add(-60*24*time.Hour).Format(time.RFC3339))
	pruneSupportBundlesByAge(now, 0)
	if !bundleDirExists(oldID) {
		t.Error("maxAge=0 must be a no-op but evicted a bundle")
	}
}
