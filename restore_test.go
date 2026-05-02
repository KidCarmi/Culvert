package main

// D1.3b.1 — restore dry-run validation tests.
//
// Coverage matches the scope decision in the PR: 11 cases covering each
// validation rule + a positive case + a no-write assertion.

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ── helpers ─────────────────────────────────────────────────────────

// makeValidBackup builds a known-good tarball using the D1.3a pack
// path, seeded with minimal Tier-1 content so most rules have something
// to chew on.
func makeValidBackup(t *testing.T) string {
	t.Helper()
	dataDir := t.TempDir()
	seedFile(t, dataDir, "ui_users.json", []byte(`{"users":[{"username":"admin","role":"admin","pass_hash":"deadbeef"}]}`), 0o600)
	seedFile(t, dataDir, "cluster.json", []byte(`{"nodes":{}}`), 0o600)
	seedFile(t, dataDir, "config_versions/v1.json", []byte(`{"meta":{"version":1}}`), 0o600)

	out := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := runBackup(out, dataDir); err != nil {
		t.Fatalf("makeValidBackup: %v", err)
	}
	return out
}

// repackTarball reads srcPath, applies transform to the file map +
// header order, then writes destPath. Manifest re-serialization is the
// caller's responsibility (most tests want a stale manifest to trigger
// validation failures).
func repackTarball(t *testing.T, srcPath, destPath string, transform func(files map[string][]byte, order *[]string)) {
	t.Helper()
	files, order, err := readTarball(srcPath)
	if err != nil {
		t.Fatalf("repack: read %s: %v", srcPath, err)
	}
	transform(files, &order)

	out, err := os.Create(destPath) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatalf("repack: create dest: %v", err)
	}
	defer func() { _ = out.Close() }()
	gz := gzip.NewWriter(out)
	defer func() { _ = gz.Close() }()
	tw := tar.NewWriter(gz)
	defer func() { _ = tw.Close() }()

	for _, name := range order {
		body, ok := files[name]
		if !ok {
			continue
		}
		hdr := &tar.Header{
			Name:     name,
			Mode:     0o600,
			Size:     int64(len(body)),
			Typeflag: tar.TypeReg,
			ModTime:  time.Now().UTC(),
		}
		if werr := tw.WriteHeader(hdr); werr != nil {
			t.Fatalf("repack: write header %s: %v", name, werr)
		}
		if _, werr := tw.Write(body); werr != nil {
			t.Fatalf("repack: write body %s: %v", name, werr)
		}
	}
}

// rebuildManifest rewrites manifest.json bytes inside files to reflect
// the current set of files (every entry except manifest.json itself).
// Used by tests that mutate the file set and want a self-consistent
// tarball that fails on a *different* rule than presence.
func rebuildManifest(t *testing.T, files map[string][]byte, order []string) {
	t.Helper()
	var entries []backupManifestFile
	for _, name := range order {
		if name == "manifest.json" {
			continue
		}
		body, ok := files[name]
		if !ok {
			continue
		}
		sum := sha256.Sum256(body)
		entries = append(entries, backupManifestFile{
			Path:     name,
			Size:     int64(len(body)),
			SHA256:   hex.EncodeToString(sum[:]),
			Mode:     "0600",
			Required: strings.HasPrefix(name, "data/ui_users.json") || strings.HasPrefix(name, "data/cluster"),
		})
	}
	manifest := backupManifest{
		SchemaVersion:  backupSchemaVersion,
		CreatedAt:      time.Now().UTC().Format(time.RFC3339),
		CulvertVersion: "test",
		Files:          entries,
	}
	body, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("rebuildManifest: marshal: %v", err)
	}
	files["manifest.json"] = body
}

// assertNoDataMutation asserts dataDir contents are byte-identical
// before/after a runRestoreDryRun call.
func assertNoDataMutation(t *testing.T, dataDir string) {
	t.Helper()
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		t.Fatalf("read dataDir after dry-run: %v", err)
	}
	if len(entries) != 0 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("dry-run must not write to /data; found %d entries: %v", len(entries), names)
	}
}

// ── 1. Valid backup dry-run succeeds and writes nothing ─────────────

func TestRestore_DryRun_ValidBackup(t *testing.T) {
	src := makeValidBackup(t)
	dataDir := t.TempDir()
	if err := runRestoreDryRun(src, dataDir, ""); err != nil {
		t.Fatalf("dry-run on valid backup: %v", err)
	}
	assertNoDataMutation(t, dataDir)
}

// ── 2. Manifest missing / malformed ─────────────────────────────────

func TestRestore_DryRun_ManifestMissing(t *testing.T) {
	src := makeValidBackup(t)
	dest := filepath.Join(t.TempDir(), "no-manifest.tar.gz")
	repackTarball(t, src, dest, func(files map[string][]byte, order *[]string) {
		delete(files, "manifest.json")
		// drop from order
		newOrder := (*order)[:0]
		for _, n := range *order {
			if n != "manifest.json" {
				newOrder = append(newOrder, n)
			}
		}
		*order = newOrder
	})
	dataDir := t.TempDir()
	err := runRestoreDryRun(dest, dataDir, "")
	if err == nil || !strings.Contains(err.Error(), "manifest.json missing") {
		t.Errorf("expected manifest-missing error, got: %v", err)
	}
	assertNoDataMutation(t, dataDir)
}

func TestRestore_DryRun_ManifestMalformed(t *testing.T) {
	src := makeValidBackup(t)
	dest := filepath.Join(t.TempDir(), "bad-manifest.tar.gz")
	repackTarball(t, src, dest, func(files map[string][]byte, _ *[]string) {
		files["manifest.json"] = []byte("this is not json")
	})
	dataDir := t.TempDir()
	err := runRestoreDryRun(dest, dataDir, "")
	if err == nil || !strings.Contains(err.Error(), "manifest unmarshal") {
		t.Errorf("expected manifest-unmarshal error, got: %v", err)
	}
	assertNoDataMutation(t, dataDir)
}

// ── 3. Schema version unsupported ───────────────────────────────────

func TestRestore_DryRun_UnsupportedSchemaVersion(t *testing.T) {
	src := makeValidBackup(t)
	dest := filepath.Join(t.TempDir(), "bad-schema.tar.gz")
	repackTarball(t, src, dest, func(files map[string][]byte, _ *[]string) {
		var m backupManifest
		_ = json.Unmarshal(files["manifest.json"], &m)
		m.SchemaVersion = 99
		body, _ := json.MarshalIndent(m, "", "  ")
		files["manifest.json"] = body
	})
	dataDir := t.TempDir()
	err := runRestoreDryRun(dest, dataDir, "")
	if err == nil || !strings.Contains(err.Error(), "schema_version 99") {
		t.Errorf("expected schema-version error, got: %v", err)
	}
	assertNoDataMutation(t, dataDir)
}

// ── 4. Manifest references file missing from tarball ────────────────

func TestRestore_DryRun_ManifestReferencesMissingFile(t *testing.T) {
	src := makeValidBackup(t)
	dest := filepath.Join(t.TempDir(), "missing-ref.tar.gz")
	repackTarball(t, src, dest, func(files map[string][]byte, order *[]string) {
		// Add a fake manifest entry pointing at a path the tarball
		// does not contain.
		var m backupManifest
		_ = json.Unmarshal(files["manifest.json"], &m)
		fakeBody := []byte("nothing")
		fakeSum := sha256.Sum256(fakeBody)
		m.Files = append(m.Files, backupManifestFile{
			Path:   "data/ghost.json",
			Size:   int64(len(fakeBody)),
			SHA256: hex.EncodeToString(fakeSum[:]),
			Mode:   "0600",
		})
		body, _ := json.MarshalIndent(m, "", "  ")
		files["manifest.json"] = body
	})
	dataDir := t.TempDir()
	err := runRestoreDryRun(dest, dataDir, "")
	if err == nil || !strings.Contains(err.Error(), "missing from tarball") {
		t.Errorf("expected missing-from-tarball error, got: %v", err)
	}
	assertNoDataMutation(t, dataDir)
}

// ── 5. Tar entry not referenced by manifest ─────────────────────────

func TestRestore_DryRun_TarEntryNotInManifest(t *testing.T) {
	src := makeValidBackup(t)
	dest := filepath.Join(t.TempDir(), "extra-entry.tar.gz")
	repackTarball(t, src, dest, func(files map[string][]byte, order *[]string) {
		// Add a tarball entry that the manifest does not list.
		files["data/extra.json"] = []byte(`{"smuggled":true}`)
		*order = append(*order, "data/extra.json")
	})
	dataDir := t.TempDir()
	err := runRestoreDryRun(dest, dataDir, "")
	if err == nil || !strings.Contains(err.Error(), "not referenced by manifest") {
		t.Errorf("expected not-in-manifest error, got: %v", err)
	}
	assertNoDataMutation(t, dataDir)
}

// ── 6. Duplicate path in manifest ───────────────────────────────────

func TestRestore_DryRun_DuplicateManifestPath(t *testing.T) {
	src := makeValidBackup(t)
	dest := filepath.Join(t.TempDir(), "dup-path.tar.gz")
	repackTarball(t, src, dest, func(files map[string][]byte, _ *[]string) {
		var m backupManifest
		_ = json.Unmarshal(files["manifest.json"], &m)
		// Duplicate the first entry.
		if len(m.Files) > 0 {
			m.Files = append(m.Files, m.Files[0])
		}
		body, _ := json.MarshalIndent(m, "", "  ")
		files["manifest.json"] = body
	})
	dataDir := t.TempDir()
	err := runRestoreDryRun(dest, dataDir, "")
	if err == nil || !strings.Contains(err.Error(), "duplicate manifest path") {
		t.Errorf("expected duplicate-path error, got: %v", err)
	}
	assertNoDataMutation(t, dataDir)
}

// ── 7. SHA-256 mismatch ─────────────────────────────────────────────

func TestRestore_DryRun_Sha256Mismatch(t *testing.T) {
	src := makeValidBackup(t)
	dest := filepath.Join(t.TempDir(), "bad-sha.tar.gz")
	repackTarball(t, src, dest, func(files map[string][]byte, _ *[]string) {
		// Mutate ui_users.json body without updating manifest sha.
		// Original is 67 bytes; replacement body is also 67 bytes so the
		// size check passes and the test exercises the sha256 rule
		// specifically.
		newBody := []byte(`{"users":[{"username":"admin","role":"admin","pass_hash":"01234567"}]}`)
		files["data/ui_users.json"] = newBody
	})
	dataDir := t.TempDir()
	err := runRestoreDryRun(dest, dataDir, "")
	if err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Errorf("expected sha256-mismatch error, got: %v", err)
	}
	assertNoDataMutation(t, dataDir)
}

// ── 8. Corrupt Tier 1 artifact ──────────────────────────────────────

func TestRestore_DryRun_CorruptTier1ClusterJSON(t *testing.T) {
	src := makeValidBackup(t)
	dest := filepath.Join(t.TempDir(), "corrupt-cluster.tar.gz")
	repackTarball(t, src, dest, func(files map[string][]byte, order *[]string) {
		files["data/cluster.json"] = []byte("not json")
		rebuildManifest(t, files, *order) // keep sha consistent so we hit parse, not sha
	})
	dataDir := t.TempDir()
	err := runRestoreDryRun(dest, dataDir, "")
	if err == nil || !strings.Contains(err.Error(), "cluster.json") {
		t.Errorf("expected cluster.json parse error, got: %v", err)
	}
	assertNoDataMutation(t, dataDir)
}

// ── 9. Cluster CA cert/key mismatched ───────────────────────────────

func TestRestore_DryRun_ClusterCAMismatch(t *testing.T) {
	// Make a backup that includes both files, then swap one to be from
	// a different CA so loadFromPEM's cross-validation rejects.
	dataDir1 := t.TempDir()
	if err := (&clusterCA{}).InitOrLoad(dataDir1); err != nil {
		t.Fatalf("seed CA1: %v", err)
	}
	seedFile(t, dataDir1, "ui_users.json", []byte(`{"users":[]}`), 0o600)

	dataDir2 := t.TempDir()
	if err := (&clusterCA{}).InitOrLoad(dataDir2); err != nil {
		t.Fatalf("seed CA2: %v", err)
	}

	// Swap dataDir1's cluster-ca.key for dataDir2's key (mismatched pair).
	keyB, err := os.ReadFile(filepath.Join(dataDir2, "cluster-ca.key"))
	if err != nil {
		t.Fatalf("read CA2 key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir1, "cluster-ca.key"), keyB, 0o600); err != nil {
		t.Fatalf("swap key: %v", err)
	}

	out := filepath.Join(t.TempDir(), "ca-mismatch.tar.gz")
	if err := runBackup(out, dataDir1); err != nil {
		t.Fatalf("backup with swapped key: %v", err)
	}

	restoreDataDir := t.TempDir()
	err = runRestoreDryRun(out, restoreDataDir, "")
	if err == nil || !strings.Contains(err.Error(), "cluster CA pair") {
		t.Errorf("expected cluster CA pair error, got: %v", err)
	}
	assertNoDataMutation(t, restoreDataDir)
}

// ── 10. Encrypted ca.bundle without passphrase ──────────────────────

func TestRestore_DryRun_EncryptedBundleWithoutPassphrase(t *testing.T) {
	dataDir := t.TempDir()
	cm := makeInitedCertManager(t)
	if err := cm.SaveCA(filepath.Join(dataDir, "ca.bundle"), "real-passphrase"); err != nil {
		t.Fatalf("SaveCA encrypted: %v", err)
	}
	seedFile(t, dataDir, "ui_users.json", []byte(`{"users":[]}`), 0o600)

	out := filepath.Join(t.TempDir(), "enc-bundle.tar.gz")
	if err := runBackup(out, dataDir); err != nil {
		t.Fatalf("backup: %v", err)
	}

	restoreDataDir := t.TempDir()
	err := runRestoreDryRun(out, restoreDataDir, "")
	if err == nil || !strings.Contains(err.Error(), "passphrase") {
		t.Errorf("expected passphrase error, got: %v", err)
	}
	assertNoDataMutation(t, restoreDataDir)
}

// ── 11. Dry-run does not create .bak or modify /data ────────────────

func TestRestore_DryRun_NoBakOrDataModification(t *testing.T) {
	src := makeValidBackup(t)
	dataDir := t.TempDir()
	parent := filepath.Dir(dataDir)

	if err := runRestoreDryRun(src, dataDir, ""); err != nil {
		t.Fatalf("dry-run: %v", err)
	}

	// dataDir itself must be empty (covered by assertNoDataMutation).
	assertNoDataMutation(t, dataDir)

	// No .bak.* sibling created next to dataDir.
	siblings, err := os.ReadDir(parent)
	if err != nil {
		t.Fatalf("read parent: %v", err)
	}
	for _, s := range siblings {
		if strings.Contains(s.Name(), ".bak.") {
			t.Errorf("dry-run created %s next to dataDir; must not happen", s.Name())
		}
	}
}

// ── 12. Absolute path in tarball entry rejected ─────────────────────

func TestRestore_DryRun_AbsoluteTarPathRejected(t *testing.T) {
	src := makeValidBackup(t)
	dest := filepath.Join(t.TempDir(), "absolute-path.tar.gz")
	repackTarball(t, src, dest, func(files map[string][]byte, order *[]string) {
		// Inject a tarball entry whose name is an absolute path.
		// Such a name would, on careless extraction, write outside the
		// destination root.
		files["/etc/passwd"] = []byte("smuggled")
		*order = append(*order, "/etc/passwd")
	})
	dataDir := t.TempDir()
	err := runRestoreDryRun(dest, dataDir, "")
	if err == nil || !strings.Contains(err.Error(), "absolute path") {
		t.Errorf("expected absolute-path error, got: %v", err)
	}
	assertNoDataMutation(t, dataDir)
}

// ── 13. Duplicate tar entry name rejected ───────────────────────────

func TestRestore_DryRun_DuplicateTarEntryRejected(t *testing.T) {
	src := makeValidBackup(t)
	dest := filepath.Join(t.TempDir(), "duplicate-entry.tar.gz")
	repackTarball(t, src, dest, func(files map[string][]byte, order *[]string) {
		// Append the same name a second time — repackTarball writes one
		// tar header per entry in `order`, so this produces two headers
		// with identical Name fields. A map-based reader would silently
		// overwrite the first; D1.3b.1's guard must fail closed.
		*order = append(*order, "data/ui_users.json")
	})
	dataDir := t.TempDir()
	err := runRestoreDryRun(dest, dataDir, "")
	if err == nil || !strings.Contains(err.Error(), "duplicate tarball entry") {
		t.Errorf("expected duplicate-tarball-entry error, got: %v", err)
	}
	assertNoDataMutation(t, dataDir)
}

// ── 14. Empty manifest rejected ─────────────────────────────────────

func TestRestore_DryRun_EmptyManifestRejected(t *testing.T) {
	src := makeValidBackup(t)
	dest := filepath.Join(t.TempDir(), "empty-manifest.tar.gz")
	repackTarball(t, src, dest, func(files map[string][]byte, order *[]string) {
		// Drop every non-manifest entry, then rewrite manifest.json with
		// an empty files slice. This isolates the empty-manifest rule
		// from rule 2 (reverse presence) which would otherwise fire on
		// the leftover tarball entries.
		newOrder := []string{}
		for _, n := range *order {
			if n == "manifest.json" {
				newOrder = append(newOrder, n)
				continue
			}
			delete(files, n)
		}
		*order = newOrder

		var m backupManifest
		_ = json.Unmarshal(files["manifest.json"], &m)
		m.Files = nil
		body, _ := json.MarshalIndent(m, "", "  ")
		files["manifest.json"] = body
	})
	dataDir := t.TempDir()
	err := runRestoreDryRun(dest, dataDir, "")
	if err == nil || !strings.Contains(err.Error(), "no files") {
		t.Errorf("expected empty-manifest error, got: %v", err)
	}
	assertNoDataMutation(t, dataDir)
}
