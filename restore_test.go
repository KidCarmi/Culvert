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
	"fmt"
	"io"
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
	files, order, err := readTarball(srcPath, "")
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
	if err := runRestoreDryRun(src, dataDir, "", restoreOpts{}); err != nil {
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
	err := runRestoreDryRun(dest, dataDir, "", restoreOpts{})
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
	err := runRestoreDryRun(dest, dataDir, "", restoreOpts{})
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
	err := runRestoreDryRun(dest, dataDir, "", restoreOpts{})
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
	err := runRestoreDryRun(dest, dataDir, "", restoreOpts{})
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
	err := runRestoreDryRun(dest, dataDir, "", restoreOpts{})
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
	err := runRestoreDryRun(dest, dataDir, "", restoreOpts{})
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
	err := runRestoreDryRun(dest, dataDir, "", restoreOpts{})
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
	err := runRestoreDryRun(dest, dataDir, "", restoreOpts{})
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
	err = runRestoreDryRun(out, restoreDataDir, "", restoreOpts{})
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
	err := runRestoreDryRun(out, restoreDataDir, "", restoreOpts{})
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

	if err := runRestoreDryRun(src, dataDir, "", restoreOpts{}); err != nil {
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
	err := runRestoreDryRun(dest, dataDir, "", restoreOpts{})
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
	err := runRestoreDryRun(dest, dataDir, "", restoreOpts{})
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
	err := runRestoreDryRun(dest, dataDir, "", restoreOpts{})
	if err == nil || !strings.Contains(err.Error(), "no files") {
		t.Errorf("expected empty-manifest error, got: %v", err)
	}
	assertNoDataMutation(t, dataDir)
}

// ── D1.3b.2a: analyzer + mode + guards ───────────────────────────────

// captureStdout swaps os.Stdout for a pipe during fn, returns captured
// output. Used to assert on the dry-run summary printed by
// runRestoreDryRun.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = orig })

	errCh := make(chan error, 1)
	go func() {
		errCh <- fn()
		_ = w.Close()
	}()

	out, _ := io.ReadAll(r)
	return string(out), <-errCh
}

// makeBackupWithRealCA bootstraps a real cluster CA + ui_users.json
// + cluster.json into a temp dir and packs it. Returns (tarballPath,
// caFingerprint).
func makeBackupWithRealCA(t *testing.T, users []uiUserRecord, enrolledNodes int) (string, string) {
	t.Helper()
	dataDir := t.TempDir()
	ca := &clusterCA{}
	if err := ca.InitOrLoad(dataDir); err != nil {
		t.Fatalf("InitOrLoad: %v", err)
	}
	caFP := ""
	if cert := ca.cert; cert != nil {
		sum := sha256.Sum256(cert.Raw)
		caFP = "sha256:" + hex.EncodeToString(sum[:])
	}

	// ui_users.json envelope.
	env := uiUsersFileEnvelope{Users: users}
	body, _ := json.Marshal(env)
	seedFile(t, dataDir, "ui_users.json", body, 0o600)

	// cluster.json with optional enrolled nodes.
	state := struct {
		Nodes map[string]any `json:"nodes"`
	}{Nodes: map[string]any{}}
	for i := 0; i < enrolledNodes; i++ {
		state.Nodes[fmt.Sprintf("dp-%d", i)] = map[string]any{"node_id": fmt.Sprintf("dp-%d", i)}
	}
	clusterBody, _ := json.Marshal(state)
	seedFile(t, dataDir, "cluster.json", clusterBody, 0o600)

	out := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := runBackup(out, dataDir); err != nil {
		t.Fatalf("backup: %v", err)
	}
	return out, caFP
}

// seedCurrentDataDir writes a minimal current /data with optional
// cluster CA, ui_users, and enrolled nodes — used for analyzer tests
// that compare backup state to current state.
func seedCurrentDataDir(t *testing.T, withCA bool, users []uiUserRecord, enrolledNodes int) string {
	t.Helper()
	dir := t.TempDir()
	if withCA {
		if err := (&clusterCA{}).InitOrLoad(dir); err != nil {
			t.Fatalf("InitOrLoad current: %v", err)
		}
	}
	if users != nil {
		env := uiUsersFileEnvelope{Users: users}
		body, _ := json.Marshal(env)
		seedFile(t, dir, "ui_users.json", body, 0o600)
	}
	if enrolledNodes > 0 {
		state := struct {
			Nodes map[string]any `json:"nodes"`
		}{Nodes: map[string]any{}}
		for i := 0; i < enrolledNodes; i++ {
			state.Nodes[fmt.Sprintf("dp-%d", i)] = map[string]any{"node_id": fmt.Sprintf("dp-%d", i)}
		}
		body, _ := json.Marshal(state)
		seedFile(t, dir, "cluster.json", body, 0o600)
	}
	return dir
}

// ── 15. Mode summary: full ───────────────────────────────────────────

func TestRestore_DryRun_ModeFull_Summary(t *testing.T) {
	src, _ := makeBackupWithRealCA(t, []uiUserRecord{{Username: "alice", Role: RoleAdmin}}, 0)
	currentDir := t.TempDir()

	out, err := captureStdout(t, func() error {
		return runRestoreDryRun(src, currentDir, "", restoreOpts{Mode: modeFull})
	})
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if !strings.Contains(out, "--mode=full") {
		t.Errorf("summary should mention --mode=full, got:\n%s", out)
	}
	if !strings.Contains(out, "From tarball:") {
		t.Errorf("summary should include merge counts, got:\n%s", out)
	}
	assertNoDataMutation(t, currentDir)
}

// ── 16. Mode summary: trust-root-only ────────────────────────────────

func TestRestore_DryRun_ModeTrustRootOnly_Summary(t *testing.T) {
	src, _ := makeBackupWithRealCA(t, []uiUserRecord{{Username: "alice", Role: RoleAdmin}}, 0)
	currentDir := seedCurrentDataDir(t, true, []uiUserRecord{{Username: "bob", Role: RoleAdmin}}, 0)

	out, err := captureStdout(t, func() error {
		return runRestoreDryRun(src, currentDir, "", restoreOpts{Mode: modeTrustRootOnly})
	})
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if !strings.Contains(out, "--mode=trust-root-only") {
		t.Errorf("summary should mention --mode=trust-root-only, got:\n%s", out)
	}
	// Trust-root-only preserves ui_users.json from current → restored
	// summary should list bob (current's user), not alice (tarball's user).
	if !strings.Contains(out, "bob") {
		t.Errorf("trust-root-only mode preserves current ui_users; expected bob in summary, got:\n%s", out)
	}
	if strings.Contains(out, "alice") {
		t.Errorf("trust-root-only mode preserves current ui_users; alice (tarball-only) should not appear, got:\n%s", out)
	}
}

// ── 17. Mode summary: state-only ─────────────────────────────────────

func TestRestore_DryRun_ModeStateOnly_Summary(t *testing.T) {
	src, _ := makeBackupWithRealCA(t, []uiUserRecord{{Username: "alice", Role: RoleAdmin}}, 0)
	currentDir := seedCurrentDataDir(t, true, []uiUserRecord{{Username: "bob", Role: RoleAdmin}}, 0)

	out, err := captureStdout(t, func() error {
		return runRestoreDryRun(src, currentDir, "", restoreOpts{Mode: modeStateOnly})
	})
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if !strings.Contains(out, "--mode=state-only") {
		t.Errorf("summary should mention --mode=state-only, got:\n%s", out)
	}
	// State-only preserves CA from current. Both backups bootstrapped
	// their own CA so fingerprints differ; preserving current means
	// the restored fingerprint should equal the current fingerprint.
	if !strings.Contains(out, "CA fingerprint unchanged") {
		t.Errorf("state-only mode preserves current CA; expected fingerprint-unchanged line, got:\n%s", out)
	}
	// State-only restores ui_users from tarball → alice should appear.
	if !strings.Contains(out, "alice") {
		t.Errorf("state-only mode restores ui_users from tarball; expected alice in summary, got:\n%s", out)
	}
}

// ── 18. DP re-enrollment guard detected ──────────────────────────────

func TestRestore_DryRun_DPReenrollmentGuard_Detected(t *testing.T) {
	// Backup has a different CA than current /data, AND current /data
	// has enrolled DPs → DP guard fires.
	src, _ := makeBackupWithRealCA(t, []uiUserRecord{{Username: "alice", Role: RoleAdmin}}, 0)
	currentDir := seedCurrentDataDir(t, true, nil, 3) // 3 enrolled DPs in current

	// Without --accept-dp-reenrollment.
	out, err := captureStdout(t, func() error {
		return runRestoreDryRun(src, currentDir, "", restoreOpts{Mode: modeFull})
	})
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if !strings.Contains(out, "DP re-enrollment required") {
		t.Errorf("expected DP-guard warning, got:\n%s", out)
	}
	if !strings.Contains(out, "--accept-dp-reenrollment") {
		t.Errorf("warning should name the flag operators must pass for D1.3b.2b commit, got:\n%s", out)
	}

	// With --accept-dp-reenrollment.
	out, err = captureStdout(t, func() error {
		return runRestoreDryRun(src, currentDir, "", restoreOpts{Mode: modeFull, AcceptDPReenrollment: true})
	})
	if err != nil {
		t.Fatalf("dry-run with accept flag: %v", err)
	}
	if !strings.Contains(out, "DP re-enrollment accepted") {
		t.Errorf("expected accepted-flag line, got:\n%s", out)
	}
}

// ── 19. TOTP rollback detected ───────────────────────────────────────

func TestRestore_DryRun_TOTPRollbackGuard_Detected(t *testing.T) {
	// Backup has alice with counter=5; current has alice with counter=10
	// → restoring would roll alice's counter back to 5.
	src, _ := makeBackupWithRealCA(t, []uiUserRecord{{Username: "alice", Role: RoleAdmin, TOTPLastCounter: 5}}, 0)
	currentDir := seedCurrentDataDir(t, false, []uiUserRecord{{Username: "alice", Role: RoleAdmin, TOTPLastCounter: 10}}, 0)

	// Without --allow-counter-rollback.
	out, err := captureStdout(t, func() error {
		return runRestoreDryRun(src, currentDir, "", restoreOpts{Mode: modeFull})
	})
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if !strings.Contains(out, "TOTP counter roll back") {
		t.Errorf("expected TOTP rollback warning, got:\n%s", out)
	}
	if !strings.Contains(out, "alice") {
		t.Errorf("warning should name affected user, got:\n%s", out)
	}
	if !strings.Contains(out, "--allow-counter-rollback") {
		t.Errorf("warning should name the flag operators must pass for D1.3b.2b commit, got:\n%s", out)
	}

	// With --allow-counter-rollback.
	out, err = captureStdout(t, func() error {
		return runRestoreDryRun(src, currentDir, "", restoreOpts{Mode: modeFull, AllowCounterRollback: true})
	})
	if err != nil {
		t.Fatalf("dry-run with allow flag: %v", err)
	}
	if !strings.Contains(out, "accepted TOTP counter rollback") {
		t.Errorf("expected accepted-flag line, got:\n%s", out)
	}
}

// ── 20. Users removed listed ─────────────────────────────────────────

func TestRestore_DryRun_UsersRemoved_Listed(t *testing.T) {
	// Backup has alice; current has alice + dave → restoring removes dave.
	src, _ := makeBackupWithRealCA(t, []uiUserRecord{{Username: "alice", Role: RoleAdmin}}, 0)
	currentDir := seedCurrentDataDir(t, false,
		[]uiUserRecord{{Username: "alice", Role: RoleAdmin}, {Username: "dave", Role: RoleAdmin}}, 0)

	out, err := captureStdout(t, func() error {
		return runRestoreDryRun(src, currentDir, "", restoreOpts{Mode: modeFull})
	})
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if !strings.Contains(out, "Will be removed:") {
		t.Errorf("expected 'Will be removed:' line, got:\n%s", out)
	}
	if !strings.Contains(out, "dave") {
		t.Errorf("removed-user line should name dave, got:\n%s", out)
	}
}

// ── 21. Dry-run does not modify /data (mode-aware) ───────────────────

func TestRestore_DryRun_AnalyzerDoesNotMutateData(t *testing.T) {
	src, _ := makeBackupWithRealCA(t, []uiUserRecord{{Username: "alice", Role: RoleAdmin}}, 0)
	currentDir := seedCurrentDataDir(t, true, []uiUserRecord{{Username: "bob", Role: RoleAdmin}}, 2)

	// Snapshot current /data contents.
	before, err := snapshotDir(t, currentDir)
	if err != nil {
		t.Fatalf("snapshot before: %v", err)
	}

	for _, mode := range []restoreMode{modeFull, modeTrustRootOnly, modeStateOnly} {
		_, err := captureStdout(t, func() error {
			return runRestoreDryRun(src, currentDir, "", restoreOpts{Mode: mode})
		})
		if err != nil {
			t.Fatalf("dry-run mode=%s: %v", mode, err)
		}
	}

	after, err := snapshotDir(t, currentDir)
	if err != nil {
		t.Fatalf("snapshot after: %v", err)
	}
	if !equalSnapshots(before, after) {
		t.Errorf("analyzer mutated /data; before=%v after=%v", before, after)
	}
}

// snapshotDir returns map[relPath] -> sha256 hex of body for every file
// under dir. Used to prove dry-run leaves /data byte-identical.
func snapshotDir(t *testing.T, dir string) (map[string]string, error) {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		body, err := os.ReadFile(path) // #nosec G304 -- test-controlled path
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		sum := sha256.Sum256(body)
		out[rel] = hex.EncodeToString(sum[:])
		return nil
	})
	return out, err
}

func equalSnapshots(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, va := range a {
		if vb, ok := b[k]; !ok || vb != va {
			return false
		}
	}
	return true
}

// ─── D1.3b.2b: destructive commit path tests ────────────────────────────────

// readBak finds the .bak.<timestamp> sibling created by a successful
// restore commit. Test-only convenience.
func readBak(t *testing.T, dataDir string) (string, bool) {
	t.Helper()
	parent := filepath.Dir(dataDir)
	base := filepath.Base(dataDir)
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatalf("readdir parent: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), base+".bak.") {
			return filepath.Join(parent, e.Name()), true
		}
	}
	return "", false
}

// stagingExists returns true if any .staging.<suffix> sibling of
// dataDir is on disk. Should be false after success or atomic-failure
// scenarios.
func stagingExists(t *testing.T, dataDir string) bool {
	t.Helper()
	parent := filepath.Dir(dataDir)
	base := filepath.Base(dataDir)
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatalf("readdir parent: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), base+".staging.") {
			return true
		}
	}
	return false
}

// fileSHA returns hex sha256 of a file body, or "" if missing.
func fileSHA(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// makeCommitFixture builds a backup tarball and a separate "current
// /data" dir suitable for end-to-end commit tests. Both have a real
// cluster CA (different from each other) so DP-fingerprint guard
// scenarios can be triggered when wanted.
//
// Returns: (tarballPath, dataDir, backupCAFingerprint, currentCAFingerprint)
func makeCommitFixture(t *testing.T, currentEnrolledNodes int) (string, string, string, string) {
	t.Helper()
	// Backup source: bootstrap CA + minimal Tier 1 content.
	backupSrc, backupFP := makeBackupWithRealCA(t,
		[]uiUserRecord{{Username: "alice", Role: RoleAdmin, TOTPLastCounter: 5}}, 0)

	// Current /data: distinct CA + distinct user roster.
	currentDir := seedCurrentDataDir(t, true,
		[]uiUserRecord{{Username: "bob", Role: RoleAdmin, TOTPLastCounter: 3}}, currentEnrolledNodes)
	currentFP := currentCAFingerprint(currentDir)

	return backupSrc, currentDir, backupFP, currentFP
}

// commitOptsFull is the most common test combo.
func commitOptsFull() restoreOpts { return restoreOpts{Mode: modeFull} }

// ── 23. Full restore round-trip ──────────────────────────────────────

func TestRestoreCommit_ModeFull_RoundTrip(t *testing.T) {
	src, currentDir, _, _ := makeCommitFixture(t, 0)

	out, err := captureStdout(t, func() error {
		return runRestoreCommit(src, currentDir, "",
			restoreOpts{Mode: modeFull, AcceptDPReenrollment: true})
	})
	if err != nil {
		t.Fatalf("commit: %v\nstdout: %s", err, out)
	}

	// /data now reflects backup: alice in ui_users.json (not bob).
	body, err := os.ReadFile(filepath.Join(currentDir, "ui_users.json"))
	if err != nil {
		t.Fatalf("read ui_users.json: %v", err)
	}
	if !strings.Contains(string(body), "alice") {
		t.Errorf("after full commit, ui_users should contain alice; got %s", body)
	}
	if strings.Contains(string(body), "bob") {
		t.Errorf("after full commit, ui_users should NOT contain bob; got %s", body)
	}

	// .bak preserved with prior content.
	bakPath, ok := readBak(t, currentDir)
	if !ok {
		t.Fatal(".bak should exist after successful commit")
	}
	bakBody, _ := os.ReadFile(filepath.Join(bakPath, "ui_users.json"))
	if !strings.Contains(string(bakBody), "bob") {
		t.Errorf(".bak ui_users should contain bob (pre-restore state); got %s", bakBody)
	}

	// Staging dir gone.
	if stagingExists(t, currentDir) {
		t.Error("staging dir should not remain after successful commit")
	}
}

// ── 24. Trust-root-only preserves state ──────────────────────────────

func TestRestoreCommit_ModeTrustRootOnly_PreservesState(t *testing.T) {
	src, currentDir, backupFP, _ := makeCommitFixture(t, 0)

	preBody, _ := os.ReadFile(filepath.Join(currentDir, "ui_users.json"))

	_, err := captureStdout(t, func() error {
		return runRestoreCommit(src, currentDir, "",
			restoreOpts{Mode: modeTrustRootOnly, AcceptDPReenrollment: true})
	})
	if err != nil {
		t.Fatalf("commit: %v", err)
	}

	// CA artifacts should match the backup (replaced).
	currentFPAfter := currentCAFingerprint(currentDir)
	if currentFPAfter != backupFP {
		t.Errorf("trust-root-only: CA fingerprint = %s, want backup's %s", currentFPAfter, backupFP)
	}

	// ui_users.json should be byte-identical to pre-restore (preserved).
	postBody, _ := os.ReadFile(filepath.Join(currentDir, "ui_users.json"))
	if string(postBody) != string(preBody) {
		t.Errorf("trust-root-only should preserve ui_users; pre=%s post=%s", preBody, postBody)
	}
}

// ── 25. State-only preserves CA ──────────────────────────────────────

func TestRestoreCommit_ModeStateOnly_PreservesCA(t *testing.T) {
	src, currentDir, _, originalCurrentFP := makeCommitFixture(t, 0)

	// Snapshot the current cluster-ca.crt body for byte-comparison after.
	preCASha := fileSHA(t, filepath.Join(currentDir, "cluster-ca.crt"))

	_, err := captureStdout(t, func() error {
		return runRestoreCommit(src, currentDir, "",
			restoreOpts{Mode: modeStateOnly})
	})
	if err != nil {
		t.Fatalf("commit: %v", err)
	}

	// CA fingerprint should still match pre-restore (preserved).
	postFP := currentCAFingerprint(currentDir)
	if postFP != originalCurrentFP {
		t.Errorf("state-only: CA fingerprint = %s, want preserved %s", postFP, originalCurrentFP)
	}
	if fileSHA(t, filepath.Join(currentDir, "cluster-ca.crt")) != preCASha {
		t.Error("state-only: cluster-ca.crt body should be byte-identical to pre-restore")
	}

	// ui_users should be from backup (alice, not bob).
	body, _ := os.ReadFile(filepath.Join(currentDir, "ui_users.json"))
	if !strings.Contains(string(body), "alice") {
		t.Errorf("state-only: ui_users should contain alice (from backup); got %s", body)
	}
}

// ── 26. Validation failure → no swap ─────────────────────────────────

func TestRestoreCommit_ValidationFailure_NoSwap(t *testing.T) {
	// Build a backup, then corrupt the manifest sha so validation fails.
	src := makeValidBackup(t)
	dest := filepath.Join(t.TempDir(), "bad-sha.tar.gz")
	repackTarball(t, src, dest, func(files map[string][]byte, _ *[]string) {
		files["data/ui_users.json"] = []byte(`{"users":[{"username":"x","role":"admin","pass_hash":"01234567"}]}`)
	})
	currentDir := seedCurrentDataDir(t, true, []uiUserRecord{{Username: "bob", Role: RoleAdmin}}, 0)
	preCASha := fileSHA(t, filepath.Join(currentDir, "cluster-ca.crt"))

	_, err := captureStdout(t, func() error {
		return runRestoreCommit(dest, currentDir, "", commitOptsFull())
	})
	if err == nil {
		t.Fatal("expected validation error")
	}

	// /data unchanged: cluster-ca.crt body unchanged.
	if fileSHA(t, filepath.Join(currentDir, "cluster-ca.crt")) != preCASha {
		t.Error("/data should be untouched on validation failure")
	}
	// No .bak, no staging.
	if _, ok := readBak(t, currentDir); ok {
		t.Error(".bak should not exist after validation failure")
	}
	if stagingExists(t, currentDir) {
		t.Error("staging should not exist after validation failure")
	}
}

// ── 27. DP guard blocks without flag ─────────────────────────────────

func TestRestoreCommit_DPGuard_BlocksWithoutFlag(t *testing.T) {
	src, currentDir, _, _ := makeCommitFixture(t, 3) // 3 enrolled nodes
	preCASha := fileSHA(t, filepath.Join(currentDir, "cluster-ca.crt"))

	_, err := captureStdout(t, func() error {
		return runRestoreCommit(src, currentDir, "", commitOptsFull())
	})
	if err == nil {
		t.Fatal("expected DP guard error")
	}
	if !strings.Contains(err.Error(), "--accept-dp-reenrollment") {
		t.Errorf("error should name the required flag, got: %v", err)
	}

	if fileSHA(t, filepath.Join(currentDir, "cluster-ca.crt")) != preCASha {
		t.Error("/data should be untouched when DP guard fires")
	}
	if _, ok := readBak(t, currentDir); ok {
		t.Error(".bak should not exist when DP guard fires")
	}
	if stagingExists(t, currentDir) {
		t.Error("staging should not exist when DP guard fires")
	}
}

// ── 28. DP guard allows with flag ────────────────────────────────────

func TestRestoreCommit_DPGuard_AllowsWithFlag(t *testing.T) {
	src, currentDir, _, _ := makeCommitFixture(t, 3)

	_, err := captureStdout(t, func() error {
		return runRestoreCommit(src, currentDir, "",
			restoreOpts{Mode: modeFull, AcceptDPReenrollment: true})
	})
	if err != nil {
		t.Fatalf("commit with flag should succeed: %v", err)
	}
	if _, ok := readBak(t, currentDir); !ok {
		t.Error(".bak should exist after successful commit")
	}
}

// ── 29. TOTP guard blocks without flag ───────────────────────────────

func TestRestoreCommit_TOTPGuard_BlocksWithoutFlag(t *testing.T) {
	// Backup has alice counter=5; current has alice counter=10 → rollback.
	src, _ := makeBackupWithRealCA(t,
		[]uiUserRecord{{Username: "alice", Role: RoleAdmin, TOTPLastCounter: 5}}, 0)
	currentDir := seedCurrentDataDir(t, false,
		[]uiUserRecord{{Username: "alice", Role: RoleAdmin, TOTPLastCounter: 10}}, 0)

	_, err := captureStdout(t, func() error {
		return runRestoreCommit(src, currentDir, "", commitOptsFull())
	})
	if err == nil {
		t.Fatal("expected TOTP guard error")
	}
	if !strings.Contains(err.Error(), "--allow-counter-rollback") {
		t.Errorf("error should name the required flag, got: %v", err)
	}
	if !strings.Contains(err.Error(), "alice") {
		t.Errorf("error should name the affected user, got: %v", err)
	}
	if _, ok := readBak(t, currentDir); ok {
		t.Error(".bak should not exist when TOTP guard fires")
	}
}

// ── 30. TOTP guard allows with flag ──────────────────────────────────

func TestRestoreCommit_TOTPGuard_AllowsWithFlag(t *testing.T) {
	src, _ := makeBackupWithRealCA(t,
		[]uiUserRecord{{Username: "alice", Role: RoleAdmin, TOTPLastCounter: 5}}, 0)
	currentDir := seedCurrentDataDir(t, false,
		[]uiUserRecord{{Username: "alice", Role: RoleAdmin, TOTPLastCounter: 10}}, 0)

	_, err := captureStdout(t, func() error {
		return runRestoreCommit(src, currentDir, "",
			restoreOpts{Mode: modeFull, AllowCounterRollback: true})
	})
	if err != nil {
		t.Fatalf("commit with flag should succeed: %v", err)
	}
}

// ── 31. Injection between renames emits recovery command ─────────────

func TestRestoreCommit_InjectionBetweenRenames_RecoveryMessage(t *testing.T) {
	src, currentDir, _, _ := makeCommitFixture(t, 0)

	commitInjectBetweenRenames = func() error { return fmt.Errorf("simulated kill") }
	t.Cleanup(func() { commitInjectBetweenRenames = nil })

	_, err := captureStdout(t, func() error {
		return runRestoreCommit(src, currentDir, "",
			restoreOpts{Mode: modeFull, AcceptDPReenrollment: true})
	})
	if err == nil {
		t.Fatal("expected interruption error")
	}
	if !strings.Contains(err.Error(), "COMMIT INTERRUPTED") {
		t.Errorf("error should mention COMMIT INTERRUPTED, got: %v", err)
	}

	// Recovery instruction must contain the exact .bak path so the
	// operator can copy/paste.
	bakPath, ok := readBak(t, currentDir)
	if !ok {
		t.Fatal(".bak should exist after interrupted commit (rename A succeeded)")
	}
	wantMV := fmt.Sprintf("mv %s %s", bakPath, currentDir)
	if !strings.Contains(err.Error(), wantMV) {
		t.Errorf("error should contain recovery command %q, got: %v", wantMV, err)
	}

	// Staging dir must be cleaned even on between-renames failure, so
	// the operator's only recovery path is the .bak (no ambiguity).
	if stagingExists(t, currentDir) {
		t.Error("staging dir should be cleaned even on between-renames failure")
	}

	// Cleanup: do the manual recovery so test directories stay tidy.
	if rerr := os.Rename(bakPath, currentDir); rerr != nil {
		t.Logf("post-test cleanup mv: %v", rerr)
	}
}

// ── 32. .bak preserved (not auto-deleted) ────────────────────────────

func TestRestoreCommit_BakPreservedNotAutoDeleted(t *testing.T) {
	src, currentDir, _, _ := makeCommitFixture(t, 0)
	_, err := captureStdout(t, func() error {
		return runRestoreCommit(src, currentDir, "",
			restoreOpts{Mode: modeFull, AcceptDPReenrollment: true})
	})
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	bakPath, ok := readBak(t, currentDir)
	if !ok {
		t.Fatal(".bak should exist after successful commit")
	}
	// .bak still readable (i.e. real directory).
	entries, err := os.ReadDir(bakPath)
	if err != nil {
		t.Fatalf(".bak should be a real directory: %v", err)
	}
	if len(entries) == 0 {
		t.Error(".bak should contain prior /data content")
	}
}

// ── 33. Dry-run without --confirm still non-destructive ──────────────

func TestRestoreCommit_NoConfirm_StillDryRun(t *testing.T) {
	// runRestoreDryRun is the no-confirm path; tests that it does not
	// touch /data even when runRestoreCommit exists in the same package.
	src, currentDir, _, _ := makeCommitFixture(t, 0)
	preCASha := fileSHA(t, filepath.Join(currentDir, "cluster-ca.crt"))

	_, err := captureStdout(t, func() error {
		return runRestoreDryRun(src, currentDir, "",
			restoreOpts{Mode: modeFull, AcceptDPReenrollment: true})
	})
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if fileSHA(t, filepath.Join(currentDir, "cluster-ca.crt")) != preCASha {
		t.Error("dry-run must not modify /data")
	}
	if _, ok := readBak(t, currentDir); ok {
		t.Error("dry-run must not create .bak")
	}
	if stagingExists(t, currentDir) {
		t.Error("dry-run must not create staging")
	}
}

// ── 34. Current-only files preserved in non-full modes ───────────────
//
// Pins the PR #194 review note: the stager must walk live /data, not
// just manifest paths. Otherwise files present in current /data but
// absent from the backup would be lost in trust-root-only / state-only.
func TestRestoreCommit_TrustRootOnly_PreservesCurrentOnlyFiles(t *testing.T) {
	src, currentDir, _, _ := makeCommitFixture(t, 0)

	// Add a "current-only" file that does not exist in the backup.
	currentOnlyPath := filepath.Join(currentDir, "extra-feature.json")
	currentOnlyBody := []byte(`{"added_after_backup_snapshot":true}`)
	if err := os.WriteFile(currentOnlyPath, currentOnlyBody, 0o600); err != nil {
		t.Fatalf("write current-only file: %v", err)
	}

	_, err := captureStdout(t, func() error {
		return runRestoreCommit(src, currentDir, "",
			restoreOpts{Mode: modeTrustRootOnly, AcceptDPReenrollment: true})
	})
	if err != nil {
		t.Fatalf("commit: %v", err)
	}

	// extra-feature.json should still be there (preserved by pass-2 walk).
	body, err := os.ReadFile(filepath.Join(currentDir, "extra-feature.json"))
	if err != nil {
		t.Fatalf("current-only file should be preserved by trust-root-only mode: %v", err)
	}
	if string(body) != string(currentOnlyBody) {
		t.Errorf("current-only file content changed: got %s, want %s", body, currentOnlyBody)
	}
}

// ── 35. Tar entry outside data/ namespace rejected ───────────────────

func TestRestore_DryRun_TarEntryOutsideDataNamespace_Rejected(t *testing.T) {
	src := makeValidBackup(t)
	dest := filepath.Join(t.TempDir(), "outside-namespace.tar.gz")
	repackTarball(t, src, dest, func(files map[string][]byte, order *[]string) {
		// Inject an entry whose path doesn't start with "data/" and
		// isn't manifest.json. A naive extractor could write it
		// outside the intended /data tree on commit.
		files["outside.json"] = []byte(`{"smuggled":true}`)
		*order = append(*order, "outside.json")
	})
	dataDir := t.TempDir()
	err := runRestoreDryRun(dest, dataDir, "", restoreOpts{})
	if err == nil || !strings.Contains(err.Error(), "outside data/ namespace") {
		t.Errorf("expected outside-namespace error, got: %v", err)
	}
	assertNoDataMutation(t, dataDir)
}

// ── 36. Manifest path outside data/ namespace rejected ───────────────
//
// (both inject a fake manifest entry via repackTarball) but tests a
// different rule (namespace vs presence). Refactoring to a shared
// helper would obscure which rule each case isolates.
//
//nolint:dupl // Structurally similar to TestRestore_DryRun_ManifestReferencesMissingFile
func TestRestore_DryRun_ManifestPathOutsideDataNamespace_Rejected(t *testing.T) {
	src := makeValidBackup(t)
	dest := filepath.Join(t.TempDir(), "manifest-outside-namespace.tar.gz")
	repackTarball(t, src, dest, func(files map[string][]byte, _ *[]string) {
		// Rewrite the manifest to claim a path that doesn't start
		// with "data/". Don't put a corresponding tar entry — the
		// namespace check should fire BEFORE bidirectional presence,
		// so the test isolates the manifest-namespace rule.
		var m backupManifest
		_ = json.Unmarshal(files["manifest.json"], &m)
		fakeBody := []byte(`{"smuggled":true}`)
		fakeSum := sha256.Sum256(fakeBody)
		m.Files = append(m.Files, backupManifestFile{
			Path:   "outside/path.json",
			Size:   int64(len(fakeBody)),
			SHA256: hex.EncodeToString(fakeSum[:]),
			Mode:   "0600",
		})
		body, _ := json.MarshalIndent(m, "", "  ")
		files["manifest.json"] = body
	})
	dataDir := t.TempDir()
	err := runRestoreDryRun(dest, dataDir, "", restoreOpts{})
	if err == nil || !strings.Contains(err.Error(), "manifest path outside data/ namespace") {
		t.Errorf("expected manifest-namespace error, got: %v", err)
	}
	assertNoDataMutation(t, dataDir)
}

// ── 37. Tarball-sourced restore preserves manifest mode ──────────────

func TestRestoreCommit_PreservesManifestMode(t *testing.T) {
	// Build a backup whose ui_users.json was on disk with mode 0o640
	// (non-default). The restore must produce 0o640 in /data, not the
	// previous hardcoded 0o600.
	dataDir := t.TempDir()
	seedFile(t, dataDir, "ui_users.json",
		[]byte(`{"users":[{"username":"alice","role":"admin","pass_hash":"deadbeef"}]}`),
		0o640)
	out := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := runBackup(out, dataDir); err != nil {
		t.Fatalf("backup: %v", err)
	}

	restoreDataDir := t.TempDir()
	_, err := captureStdout(t, func() error {
		return runRestoreCommit(out, restoreDataDir, "",
			restoreOpts{Mode: modeFull, AcceptDPReenrollment: true})
	})
	if err != nil {
		t.Fatalf("commit: %v", err)
	}

	info, err := os.Stat(filepath.Join(restoreDataDir, "ui_users.json"))
	if err != nil {
		t.Fatalf("stat restored: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o640 {
		t.Errorf("restored ui_users.json mode = %o, want 0640 (preserved from manifest)", got)
	}
}

// ── 38. Preserve-from-current restore preserves current mode ─────────

func TestRestoreCommit_TrustRootOnly_PreservesCurrentMode(t *testing.T) {
	// Backup has CA + ui_users (0o600). Current /data has ui_users
	// at mode 0o644. Trust-root-only mode preserves current ui_users,
	// so the restored mode must be 0o644 (current's), not 0o600 (the
	// previous hardcoded value).
	src, _ := makeBackupWithRealCA(t,
		[]uiUserRecord{{Username: "alice", Role: RoleAdmin}}, 0)

	currentDir := t.TempDir()
	if err := (&clusterCA{}).InitOrLoad(currentDir); err != nil {
		t.Fatalf("InitOrLoad current: %v", err)
	}
	bobBody := []byte(`{"users":[{"username":"bob","role":"admin","pass_hash":"abc"}]}`)
	// #nosec G306 -- 0o644 is the explicit subject of this test (mode preservation across restore)
	if err := os.WriteFile(filepath.Join(currentDir, "ui_users.json"), bobBody, 0o644); err != nil {
		t.Fatalf("write current ui_users 0o644: %v", err)
	}

	_, err := captureStdout(t, func() error {
		return runRestoreCommit(src, currentDir, "",
			restoreOpts{Mode: modeTrustRootOnly, AcceptDPReenrollment: true})
	})
	if err != nil {
		t.Fatalf("commit: %v", err)
	}

	info, err := os.Stat(filepath.Join(currentDir, "ui_users.json"))
	if err != nil {
		t.Fatalf("stat restored: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Errorf("restored ui_users.json mode = %o, want 0644 (preserved from current /data)", got)
	}
}

// ── 39. Pre-existing staging dir aborts before /data is touched ──────

func TestRestoreCommit_PreExistingStagingDir_AbortsBeforeDataTouched(t *testing.T) {
	src, currentDir, _, _ := makeCommitFixture(t, 0)

	// Pre-create the staging dir at the path runRestoreCommit will
	// derive (timestamp+pid). Since we can't predict timestamp here,
	// we pre-create EVERY .staging.* path by precomputing the suffix.
	// Simpler: pre-create ALL siblings matching the expected glob.
	// Even simpler: make every possible derivation collide by creating
	// the exact path the function will produce — we know it uses
	// time.Now + os.Getpid, so create one matching that.
	suffix := fmt.Sprintf("%s-%d",
		time.Now().UTC().Format("20060102T150405Z"), os.Getpid())
	stagingDir := currentDir + ".staging." + suffix
	if err := os.Mkdir(stagingDir, 0o700); err != nil {
		t.Fatalf("pre-create staging: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(stagingDir) })

	// Mark the pre-existing dir with a sentinel file so we can prove
	// it was NOT touched (i.e. no stale reuse).
	sentinel := filepath.Join(stagingDir, "sentinel.txt")
	if err := os.WriteFile(sentinel, []byte("pre-existing"), 0o600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}

	preCASha := fileSHA(t, filepath.Join(currentDir, "cluster-ca.crt"))

	_, err := captureStdout(t, func() error {
		return runRestoreCommit(src, currentDir, "",
			restoreOpts{Mode: modeFull, AcceptDPReenrollment: true})
	})
	if err == nil {
		t.Fatal("expected staging-collision error")
	}
	if !strings.Contains(err.Error(), "staging path") || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error should mention staging-path collision, got: %v", err)
	}

	// /data must be untouched (commit never started).
	if fileSHA(t, filepath.Join(currentDir, "cluster-ca.crt")) != preCASha {
		t.Error("/data should not be touched on staging collision")
	}
	// No .bak should exist.
	if _, ok := readBak(t, currentDir); ok {
		t.Error(".bak should not exist on staging collision")
	}
	// Sentinel must be intact — proves no stale reuse.
	body, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatalf("sentinel should still exist: %v", err)
	}
	if string(body) != "pre-existing" {
		t.Errorf("sentinel body changed; restore reused stale staging dir")
	}
}

// ── 40. Pre-existing bak dir aborts before /data is touched ──────────

func TestRestoreCommit_PreExistingBakDir_AbortsBeforeDataTouched(t *testing.T) {
	src, currentDir, _, _ := makeCommitFixture(t, 0)

	// Pin the clock so the bak path the test pre-creates matches the one
	// runRestoreCommit derives — otherwise a second-boundary race between
	// the two independent time reads makes this test flaky.
	fixedNow := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	origNow := restoreNow
	restoreNow = func() time.Time { return fixedNow }
	t.Cleanup(func() { restoreNow = origNow })

	// Pre-create the bak dir at the path runRestoreCommit will derive.
	suffix := fmt.Sprintf("%s-%d",
		fixedNow.UTC().Format("20060102T150405Z"), os.Getpid())
	bakPath := currentDir + ".bak." + suffix
	if err := os.Mkdir(bakPath, 0o700); err != nil {
		t.Fatalf("pre-create bak: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(bakPath) })

	preCASha := fileSHA(t, filepath.Join(currentDir, "cluster-ca.crt"))

	_, err := captureStdout(t, func() error {
		return runRestoreCommit(src, currentDir, "",
			restoreOpts{Mode: modeFull, AcceptDPReenrollment: true})
	})
	if err == nil {
		t.Fatal("expected bak-collision error")
	}
	if !strings.Contains(err.Error(), "backup path") || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error should mention backup-path collision, got: %v", err)
	}

	// /data must be untouched (commit never started).
	if fileSHA(t, filepath.Join(currentDir, "cluster-ca.crt")) != preCASha {
		t.Error("/data should not be touched on bak collision")
	}
	// No staging dir should be created.
	if stagingExists(t, currentDir) {
		t.Error("staging dir should not be created when bak collision detected first")
	}
}

// ── 41. No stale staging content is reused (race-condition guard) ────
//
// Even if the pre-check missed a same-instant creation between Stat
// and Mkdir (TOCTOU), the os.Mkdir (not MkdirAll) call inside
// stageArtifacts must still fail closed. Simulates this by skipping
// the runRestoreCommit pre-check (calling stageArtifacts directly
// against a pre-created staging dir).
func TestRestoreCommit_StageArtifacts_RefusesPreExistingStagingDir(t *testing.T) {
	currentDir := t.TempDir()
	stagingDir := currentDir + ".staging.test"
	if err := os.Mkdir(stagingDir, 0o700); err != nil {
		t.Fatalf("pre-create staging: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(stagingDir) })

	// Minimal manifest (zero entries OK for this test — we never get
	// past the staging-root mkdir).
	manifest := &backupManifest{SchemaVersion: 1, Files: nil}
	files := map[string][]byte{}

	err := stageArtifacts(stagingDir, currentDir, files, manifest, modeFull)
	if err == nil {
		t.Fatal("stageArtifacts should fail when staging root already exists")
	}
	if !strings.Contains(err.Error(), "exclusive") {
		t.Errorf("error should mention exclusive mkdir, got: %v", err)
	}
}

// TestGuardWithinDir pins the defense-in-depth zip-slip guard used by
// stageArtifacts. readTarball already rejects ".." components, but the
// local guard at the write site is what CodeQL actually traces.
func TestGuardWithinDir(t *testing.T) {
	base := t.TempDir()
	cases := []struct {
		name    string
		target  string
		wantErr bool
	}{
		{"inside", filepath.Join(base, "foo"), false},
		{"nested inside", filepath.Join(base, "a", "b", "c"), false},
		{"equals base", base, false},
		{"escape via dotdot", filepath.Join(base, "..", "evil"), true},
		{"escape via deep dotdot", filepath.Join(base, "a", "..", "..", "evil"), true},
		{"absolute outside", "/etc/passwd", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := guardWithinDir(base, tc.target)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for %q, got nil", tc.target)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error for %q, got %v", tc.target, err)
			}
		})
	}
}
