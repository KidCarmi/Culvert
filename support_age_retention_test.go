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
	writeFakeBundleManifestID(t, id, id, createdAt)
}

// writeFakeBundleManifestID writes a bundle whose ON-DISK directory name (dirID)
// and manifest bundle_id (manID) can DIVERGE — the corrupt/hand-copied-manifest
// case: a filesystem eviction must target the directory, never the manifest id.
func writeFakeBundleManifestID(t *testing.T, dirID, manID, createdAt string) {
	t.Helper()
	dir := filepath.Join(supportBundlesDir(), dirID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	man := support.SupportBundleManifest{Format: support.BundleFormat, BundleID: manID, CreatedAt: createdAt}
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

// TestPruneSupportBundlesByAge_ManifestIDDivergence proves the sweep evicts the
// ON-DISK directory it scanned, never the (possibly different) bundle_id inside
// the manifest. A corrupt/hand-copied manifest naming a different valid bundle
// must not cause that OTHER bundle to be deleted while the stale one survives.
func TestPruneSupportBundlesByAge_ManifestIDDivergence(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	now := time.Unix(1_800_000_000, 0).UTC()
	const (
		staleDir  = "csb_stalediraaaaaaaa234567abcd" // old, but its manifest lies…
		victimDir = "csb_victimbundleaaaa234567abcd" // …naming THIS recent, valid bundle
	)
	// staleDir is old AND its manifest's bundle_id points at victimDir.
	writeFakeBundleManifestID(t, staleDir, victimDir, now.Add(-60*24*time.Hour).Format(time.RFC3339))
	// victimDir is a recent, healthy bundle that must NOT be touched.
	writeFakeBundle(t, victimDir, now.Add(-1*24*time.Hour).Format(time.RFC3339))

	pruneSupportBundlesByAge(now, supportRetentionMaxAge)

	if bundleDirExists(staleDir) {
		t.Error("the stale on-disk directory was not evicted")
	}
	if !bundleDirExists(victimDir) {
		t.Error("a recent bundle named only by the stale manifest's bundle_id was wrongly deleted")
	}
}
