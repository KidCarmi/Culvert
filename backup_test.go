package main

// D1.3a — backup/export tests.
//
// Coverage matches the scope decision in this PR:
//   - tarball contains manifest.json
//   - required Tier 1 files included when present
//   - optional Tier 2 files included only if present
//   - excluded (Tier 3) files are not included
//   - sha256 / mode / size in manifest match tar contents
//   - missing required artifact produces a clear error,
//     unless it is explicitly first-run/bootstrap-optional
//   - config_versions/ included recursively

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// readBackupTarball reads outPath, gunzips, and returns:
//   - the parsed manifest
//   - a map from tarPath to body bytes for every file in the archive
//   - the order of file headers as they appeared in the tarball
func readBackupTarball(t *testing.T, outPath string) (backupManifest, map[string][]byte, []string) {
	t.Helper()
	f, err := os.Open(outPath)
	if err != nil {
		t.Fatalf("open backup: %v", err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gunzip: %v", err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	files := map[string][]byte{}
	var order []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar.Next: %v", err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read %s: %v", hdr.Name, err)
		}
		files[hdr.Name] = body
		order = append(order, hdr.Name)
	}

	manifestBytes, ok := files["manifest.json"]
	if !ok {
		t.Fatal("tarball missing manifest.json")
	}
	var m backupManifest
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	return m, files, order
}

// seedFile writes a file with body and perm under dir.
func seedFile(t *testing.T, dir, rel string, body []byte, perm os.FileMode) {
	t.Helper()
	full := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		t.Fatalf("mkdir parent of %s: %v", rel, err)
	}
	if err := os.WriteFile(full, body, perm); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

// ── 1. Manifest is present and well-formed ──────────────────────────

func TestBackup_Manifest_PresentAndFirst(t *testing.T) {
	dataDir := t.TempDir()
	seedFile(t, dataDir, "ui_users.json", []byte(`{"users":[]}`), 0o600)
	out := filepath.Join(t.TempDir(), "backup.tar.gz")

	if err := runBackup(out, dataDir); err != nil {
		t.Fatalf("runBackup: %v", err)
	}

	m, _, order := readBackupTarball(t, out)
	if len(order) == 0 || order[0] != "manifest.json" {
		t.Errorf("expected manifest.json as first entry, got %v", order)
	}
	if m.SchemaVersion != backupSchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", m.SchemaVersion, backupSchemaVersion)
	}
	if m.CreatedAt == "" {
		t.Error("CreatedAt should be non-empty")
	}
	if m.CulvertVersion == "" {
		t.Error("CulvertVersion should be non-empty")
	}
	if len(m.Files) == 0 {
		t.Error("Files should not be empty when ui_users.json present")
	}
}

// ── 2. Required Tier 1 files included when present ──────────────────

func TestBackup_Tier1_IncludedWhenPresent(t *testing.T) {
	dataDir := t.TempDir()
	// Seed every Tier-1 artifact with distinct content.
	tier1 := []struct {
		rel  string
		body []byte
	}{
		{"ui_users.json", []byte(`{"users":[{"username":"a"}]}`)},
		{"ca.bundle", []byte("PEM placeholder")},
		{"cluster-ca.crt", []byte("CERT placeholder")},
		{"cluster-ca.key", []byte("KEY placeholder")},
		{"cluster.json", []byte(`{"nodes":{}}`)},
		// config_versions/ — see dedicated test for recursion semantics
		{"config_versions/v1.json", []byte(`{"meta":{"version":1}}`)},
	}
	for _, t1 := range tier1 {
		seedFile(t, dataDir, t1.rel, t1.body, 0o600)
	}
	out := filepath.Join(t.TempDir(), "backup.tar.gz")

	if err := runBackup(out, dataDir); err != nil {
		t.Fatalf("runBackup: %v", err)
	}
	_, files, _ := readBackupTarball(t, out)

	want := []string{
		"data/ui_users.json",
		"data/ca.bundle",
		"data/cluster-ca.crt",
		"data/cluster-ca.key",
		"data/cluster.json",
		"data/config_versions/v1.json",
	}
	for _, w := range want {
		if _, ok := files[w]; !ok {
			t.Errorf("expected %q in tarball, got %v", w, sortedNames(files))
		}
	}
}

// ── 3. Optional Tier 2 files included only if present ───────────────

func TestBackup_Tier2_OnlyIncludedIfPresent(t *testing.T) {
	dataDir := t.TempDir()
	// Tier 1 (required) — minimal seed so backup proceeds.
	seedFile(t, dataDir, "ui_users.json", []byte(`{}`), 0o600)
	// Tier 2 — seed only some of them.
	seedFile(t, dataDir, "policy.json", []byte(`[]`), 0o600)
	seedFile(t, dataDir, "bandwidth.json", []byte(`[]`), 0o600)
	// node_groups.json, categories.json, blocklist.txt etc. NOT seeded.

	out := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := runBackup(out, dataDir); err != nil {
		t.Fatalf("runBackup: %v", err)
	}
	_, files, _ := readBackupTarball(t, out)

	if _, ok := files["data/policy.json"]; !ok {
		t.Errorf("expected data/policy.json in tarball")
	}
	if _, ok := files["data/bandwidth.json"]; !ok {
		t.Errorf("expected data/bandwidth.json in tarball")
	}
	for _, absent := range []string{
		"data/node_groups.json",
		"data/categories.json",
		"data/blocklist.txt",
		"data/pac_config.json",
		"data/scan_exclusions.json",
		"data/alert_settings.json",
		"data/admin_settings.json",
		"data/ssl_bypass.json",
		"data/dpi_patterns.json",
		"data/category_groups.json",
	} {
		if _, ok := files[absent]; ok {
			t.Errorf("did not expect %q in tarball, but it is present", absent)
		}
	}
}

// ── 4. Tier 3 (excluded) files are not included ─────────────────────

func TestBackup_Tier3_NeverIncluded(t *testing.T) {
	dataDir := t.TempDir()
	seedFile(t, dataDir, "ui_users.json", []byte(`{}`), 0o600)
	// Tier-3 artifacts that should be excluded by default — they
	// physically exist on disk but must not appear in the tarball.
	tier3 := []string{
		"threat_feed.json",
		"hit_counters.json",
		"alert_retry_queue.json",
		"updater_token.txt",
		"version.txt",
		"cluster_update.json",
		"culvert.log",
		"audit.log",
		"hashcache.json",
	}
	for _, rel := range tier3 {
		seedFile(t, dataDir, rel, []byte("should not be in backup"), 0o600)
	}

	out := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := runBackup(out, dataDir); err != nil {
		t.Fatalf("runBackup: %v", err)
	}
	_, files, _ := readBackupTarball(t, out)

	for _, rel := range tier3 {
		if _, ok := files["data/"+rel]; ok {
			t.Errorf("Tier-3 artifact %q must not appear in backup tarball", rel)
		}
	}
}

// ── 5. Manifest sha256 / size / mode match tar contents ─────────────

func TestBackup_Manifest_ChecksumsMatchTarContents(t *testing.T) {
	dataDir := t.TempDir()
	body1 := []byte("first body")
	body2 := []byte(`{"users":[{"username":"admin"}]}`)
	seedFile(t, dataDir, "ui_users.json", body2, 0o640)
	seedFile(t, dataDir, "ca.bundle", body1, 0o600)

	out := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := runBackup(out, dataDir); err != nil {
		t.Fatalf("runBackup: %v", err)
	}

	m, files, _ := readBackupTarball(t, out)
	for _, mf := range m.Files {
		body, ok := files[mf.Path]
		if !ok {
			t.Errorf("manifest references %q but tarball has no such entry", mf.Path)
			continue
		}
		if int64(len(body)) != mf.Size {
			t.Errorf("%s: size in manifest = %d, in tarball = %d", mf.Path, mf.Size, len(body))
		}
		sum := sha256.Sum256(body)
		if hex.EncodeToString(sum[:]) != mf.SHA256 {
			t.Errorf("%s: sha256 in manifest = %s, computed from tarball = %s",
				mf.Path, mf.SHA256, hex.EncodeToString(sum[:]))
		}
	}

	// Spot-check that mode is the octal string we expect.
	for _, mf := range m.Files {
		if mf.Path == "data/ui_users.json" && mf.Mode != "0640" {
			t.Errorf("ui_users.json mode = %q, want 0640", mf.Mode)
		}
		if mf.Path == "data/ca.bundle" && mf.Mode != "0600" {
			t.Errorf("ca.bundle mode = %q, want 0600", mf.Mode)
		}
	}
}

// ── 6. Missing required artifact: error vs first-run-optional ───────

func TestBackup_MissingRequired_FirstRunOptional_NoError(t *testing.T) {
	dataDir := t.TempDir() // entirely empty
	out := filepath.Join(t.TempDir(), "backup.tar.gz")

	// All Tier-1 artifacts are first-run-optional → no error, just an
	// empty-but-valid tarball with manifest.
	if err := runBackup(out, dataDir); err != nil {
		t.Fatalf("runBackup on empty dataDir should succeed (first-run case): %v", err)
	}

	m, files, _ := readBackupTarball(t, out)
	if len(m.Files) != 0 {
		t.Errorf("manifest should list 0 files for empty dataDir, got %d", len(m.Files))
	}
	// Manifest itself must still be present.
	if _, ok := files["manifest.json"]; !ok {
		t.Error("manifest.json must be present even when dataDir is empty")
	}
}

func TestBackup_MissingRequired_NotFirstRunOptional_Errors(t *testing.T) {
	// Synthetic artifact set: one required + NOT first-run-optional.
	// Confirms the error path the user requested.
	dataDir := t.TempDir()
	out := filepath.Join(t.TempDir(), "backup.tar.gz")

	artifacts := []backupArtifact{
		{
			SrcPath:          filepath.Join(dataDir, "synthetic-required.bin"),
			TarPath:          "data/synthetic-required.bin",
			Required:         true,
			OptionalFirstRun: false,
		},
	}

	err := runBackupWith(out, artifacts, "")
	if err == nil {
		t.Fatal("expected error on missing strict-required artifact, got nil")
	}
	if !strings.Contains(err.Error(), "required artifact") {
		t.Errorf("error should mention required artifact, got: %v", err)
	}
	if !strings.Contains(err.Error(), "synthetic-required.bin") {
		t.Errorf("error should name the missing artifact, got: %v", err)
	}
	// Output file should NOT exist on error (atomic-write semantics).
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Errorf("output should not exist on error; stat err = %v", statErr)
	}
}

// ── 7. config_versions/ recursive ───────────────────────────────────

func TestBackup_ConfigVersionsRecursive(t *testing.T) {
	dataDir := t.TempDir()
	seedFile(t, dataDir, "ui_users.json", []byte(`{}`), 0o600)
	seedFile(t, dataDir, "config_versions/v1.json", []byte(`{"meta":{"version":1}}`), 0o600)
	seedFile(t, dataDir, "config_versions/v2.json", []byte(`{"meta":{"version":2}}`), 0o600)
	seedFile(t, dataDir, "config_versions/v3.json", []byte(`{"meta":{"version":3}}`), 0o600)

	out := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := runBackup(out, dataDir); err != nil {
		t.Fatalf("runBackup: %v", err)
	}
	_, files, _ := readBackupTarball(t, out)

	for _, want := range []string{
		"data/config_versions/v1.json",
		"data/config_versions/v2.json",
		"data/config_versions/v3.json",
	} {
		if _, ok := files[want]; !ok {
			t.Errorf("expected %q in tarball, got %v", want, sortedNames(files))
		}
	}
}

// ── 8. Symlink top-level artifact is skipped ────────────────────────

// TestBackup_SymlinkTopLevelSkipped verifies the Lstat guard added in
// the pre-merge audit: if a top-level artifact is a symlink (e.g. an
// attacker replaced /data/ca.bundle with a link to /etc/passwd),
// packOne refuses to follow it and the file is omitted from the
// tarball. Pinned to prove that the Lstat path matches the
// filepath.Walk path's symlink semantics.
func TestBackup_SymlinkTopLevelSkipped(t *testing.T) {
	dataDir := t.TempDir()
	// A real file the symlink will point at.
	target := filepath.Join(t.TempDir(), "secret-target")
	if err := os.WriteFile(target, []byte("would-be-leaked"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	// /data/ca.bundle is a symlink to that file.
	if err := os.Symlink(target, filepath.Join(dataDir, "ca.bundle")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	// And a normal file so the backup has at least one entry.
	seedFile(t, dataDir, "ui_users.json", []byte(`{}`), 0o600)

	out := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := runBackup(out, dataDir); err != nil {
		t.Fatalf("runBackup: %v", err)
	}
	_, files, _ := readBackupTarball(t, out)

	if _, ok := files["data/ca.bundle"]; ok {
		t.Errorf("symlinked top-level artifact must be skipped; got data/ca.bundle in tarball")
	}
}

// sortedNames returns a sorted slice of keys for friendlier error output.
func sortedNames(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ── PAC config backup round-trip (PR "pac foundation hardening") ────
//
// Regression pin for the pre-existing backup gap: the artifact list used to
// reference data/pac.json while the store persisted pac_config.json in the
// process CWD, so PAC config was silently absent from every backup. The store
// now lives at <dataDir>/pac_config.json and must round-trip.

func TestBackup_PACConfig_IncludedWithContent(t *testing.T) {
	dataDir := t.TempDir()
	seedFile(t, dataDir, "ui_users.json", []byte(`{}`), 0o600)
	pacBody := []byte(`{"proxyHost":"proxy.corp.example","proxyPort":3128,"exclusions":["corp.local","10.0.0.0/8"]}`)
	seedFile(t, dataDir, "pac_config.json", pacBody, 0o600)

	out := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := runBackup(out, dataDir); err != nil {
		t.Fatalf("runBackup: %v", err)
	}
	manifest, files, _ := readBackupTarball(t, out)

	got, ok := files["data/pac_config.json"]
	if !ok {
		t.Fatalf("data/pac_config.json missing from tarball: %v", sortedNames(files))
	}
	if !bytes.Equal(got, pacBody) {
		t.Errorf("PAC config content mismatch in backup:\n got: %s\nwant: %s", got, pacBody)
	}
	found := false
	for _, e := range manifest.Files {
		if e.Path == "data/pac_config.json" {
			found = true
		}
	}
	if !found {
		t.Error("data/pac_config.json missing from backup manifest")
	}
}

func TestBackup_PACProfiles_IncludedWithContent(t *testing.T) {
	dataDir := t.TempDir()
	seedFile(t, dataDir, "ui_users.json", []byte(`{}`), 0o600)
	body := []byte(`{"profiles":[{"id":"hq","name":"HQ","enabled":true,"poolId":"p1","privateNetworks":"direct","availabilityMode":"secure","revision":1}],"pools":[{"id":"p1","name":"P1","endpoints":[{"host":"proxy.example","port":8080}]}]}`)
	seedFile(t, dataDir, "pac_profiles.json", body, 0o600)

	out := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := runBackup(out, dataDir); err != nil {
		t.Fatalf("runBackup: %v", err)
	}
	_, files, _ := readBackupTarball(t, out)
	got, ok := files["data/pac_profiles.json"]
	if !ok {
		t.Fatalf("data/pac_profiles.json missing from tarball: %v", sortedNames(files))
	}
	if !bytes.Equal(got, body) {
		t.Errorf("pac_profiles.json content mismatch in backup")
	}
}

func TestBackup_PACProfilesLifecycle_IncludedWithContent(t *testing.T) {
	dataDir := t.TempDir()
	seedFile(t, dataDir, "ui_users.json", []byte(`{}`), 0o600)
	body := []byte(`{"profiles":{"hq":{"profileId":"hq","activeN":2,"revisions":[{"n":1,"actor":"admin","ts":"2026-07-17T00:00:00Z"},{"n":2,"actor":"admin","ts":"2026-07-17T01:00:00Z"}]}}}`)
	seedFile(t, dataDir, "pac_profiles_lifecycle.json", body, 0o600)

	out := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := runBackup(out, dataDir); err != nil {
		t.Fatalf("runBackup: %v", err)
	}
	_, files, _ := readBackupTarball(t, out)
	got, ok := files["data/pac_profiles_lifecycle.json"]
	if !ok {
		t.Fatalf("data/pac_profiles_lifecycle.json missing from tarball: %v", sortedNames(files))
	}
	if !bytes.Equal(got, body) {
		t.Errorf("pac_profiles_lifecycle.json content mismatch in backup")
	}
}

func TestBackup_PACExceptions_IncludedWithContent(t *testing.T) {
	dataDir := t.TempDir()
	seedFile(t, dataDir, "ui_users.json", []byte(`{}`), 0o600)
	body := []byte(`{"hq":{"profileId":"hq","owner":"neteng","reason":"vendor SaaS bypass","expiresAt":"2026-12-31T00:00:00Z","reviewCadenceDays":90}}`)
	seedFile(t, dataDir, "pac_exceptions.json", body, 0o600)

	out := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := runBackup(out, dataDir); err != nil {
		t.Fatalf("runBackup: %v", err)
	}
	_, files, _ := readBackupTarball(t, out)
	got, ok := files["data/pac_exceptions.json"]
	if !ok {
		t.Fatalf("data/pac_exceptions.json missing from tarball: %v", sortedNames(files))
	}
	if !bytes.Equal(got, body) {
		t.Errorf("pac_exceptions.json content mismatch in backup")
	}
}

// ── Nightly QA: persisted, admin-configurable stores missing from the
// backup surface ─────────────────────────────────────────────────────
//
// defaultBackupArtifacts() drifted from the actual set of files the running
// proxy persists under dataDir: decryption_profiles.json (named SSL-inspect
// profiles, internal/decryptprofile), alert_webhooks.json (alert webhook
// endpoints incl. RISK-003-encrypted secrets), fileblock.json (file
// extension block profiles), and saas_feed/overrides.json (admin category
// overrides for the signed SaaS URL-category feed) are all admin-configurable
// via their own API endpoints and persisted to dataDir, exactly like
// policy.json/bandwidth.json/pac_config.json above — but were never added to
// the artifact list, so a backup taken today silently has no way to ever
// restore them (e.g. after reinstalling onto a fresh volume, or restoring
// onto a replacement host).
func TestBackup_DecryptionProfiles_IncludedWithContent(t *testing.T) {
	dataDir := t.TempDir()
	seedFile(t, dataDir, "ui_users.json", []byte(`{}`), 0o600)
	body := []byte(`{"profiles":[{"id":"p1","name":"Fail-Open Guest Wifi","onInspectError":"fail-open"}]}`)
	seedFile(t, dataDir, "decryption_profiles.json", body, 0o600)

	out := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := runBackup(out, dataDir); err != nil {
		t.Fatalf("runBackup: %v", err)
	}
	_, files, _ := readBackupTarball(t, out)
	got, ok := files["data/decryption_profiles.json"]
	if !ok {
		t.Fatalf("data/decryption_profiles.json missing from tarball: %v", sortedNames(files))
	}
	if !bytes.Equal(got, body) {
		t.Errorf("decryption_profiles.json content mismatch in backup")
	}
}

func TestBackup_AlertWebhooks_IncludedWithContent(t *testing.T) {
	dataDir := t.TempDir()
	seedFile(t, dataDir, "ui_users.json", []byte(`{}`), 0o600)
	body := []byte(`{"webhooks":[{"id":"w1","url":"https://hooks.example.com/culvert","events":["threat_detected"]}]}`)
	seedFile(t, dataDir, "alert_webhooks.json", body, 0o600)

	out := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := runBackup(out, dataDir); err != nil {
		t.Fatalf("runBackup: %v", err)
	}
	_, files, _ := readBackupTarball(t, out)
	got, ok := files["data/alert_webhooks.json"]
	if !ok {
		t.Fatalf("data/alert_webhooks.json missing from tarball: %v", sortedNames(files))
	}
	if !bytes.Equal(got, body) {
		t.Errorf("alert_webhooks.json content mismatch in backup")
	}
}

func TestBackup_FileBlockProfiles_IncludedWithContent(t *testing.T) {
	dataDir := t.TempDir()
	seedFile(t, dataDir, "ui_users.json", []byte(`{}`), 0o600)
	body := []byte(`{"profiles":[{"name":"Executables","extensions":[".exe",".bat"]}]}`)
	seedFile(t, dataDir, "fileblock.json", body, 0o600)

	out := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := runBackup(out, dataDir); err != nil {
		t.Fatalf("runBackup: %v", err)
	}
	_, files, _ := readBackupTarball(t, out)
	got, ok := files["data/fileblock.json"]
	if !ok {
		t.Fatalf("data/fileblock.json missing from tarball: %v", sortedNames(files))
	}
	if !bytes.Equal(got, body) {
		t.Errorf("fileblock.json content mismatch in backup")
	}
}

func TestBackup_SaaSFeedOverrides_IncludedWithContent(t *testing.T) {
	dataDir := t.TempDir()
	seedFile(t, dataDir, "ui_users.json", []byte(`{}`), 0o600)
	body := []byte(`{"overrides":[{"host":"internal.example.com","category":"Business"}]}`)
	seedFile(t, dataDir, filepath.Join("saas_feed", "overrides.json"), body, 0o600)

	out := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := runBackup(out, dataDir); err != nil {
		t.Fatalf("runBackup: %v", err)
	}
	_, files, _ := readBackupTarball(t, out)
	got, ok := files["data/saas_feed/overrides.json"]
	if !ok {
		t.Fatalf("data/saas_feed/overrides.json missing from tarball: %v", sortedNames(files))
	}
	if !bytes.Equal(got, body) {
		t.Errorf("saas_feed/overrides.json content mismatch in backup")
	}
}

// TestBackup_FileProfiles_IncludedWithContent guards against the same drift
// class as the four tests above, for a store the earlier pass still missed:
// globalProfileStore (internal/fileblock.FileProfileStore) is the named
// file-type profile set (e.g. a custom "Executables" profile) that policy
// rules reference by name via FileProfile (policy.go's
// globalProfileStore.GetByName). It is admin-configurable via its own API
// (ui_security.go Create/Update/Delete), is a first-class config_surfaces.go
// entry ("file_profiles"), and is CP->DP synced — exactly the bar the other
// four stores were added at — but is persisted to a SEPARATE file from
// fileblock.json (the plain extension-list store, which IS backed up):
// fileprofiles.json, the default path resolveFileBlockStartupConfig falls
// back to when neither the --fileprofiles-file CLI flag nor
// proxy.fileprofiles_file in config.yaml is set, and the exact path the
// shipped docker-compose.yml wires via "-fileprofiles-file"
// "/data/fileprofiles.json". A backup taken today silently drops any custom
// file-type profile, so restoring onto a fresh volume/host leaves policy
// rules referencing it unable to resolve the named profile.
func TestBackup_FileProfiles_IncludedWithContent(t *testing.T) {
	dataDir := t.TempDir()
	seedFile(t, dataDir, "ui_users.json", []byte(`{}`), 0o600)
	body := []byte(`{"profiles":[{"id":"p1","name":"Executables","extensions":[".exe",".bat"]}]}`)
	seedFile(t, dataDir, "fileprofiles.json", body, 0o600)

	out := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := runBackup(out, dataDir); err != nil {
		t.Fatalf("runBackup: %v", err)
	}
	_, files, _ := readBackupTarball(t, out)
	got, ok := files["data/fileprofiles.json"]
	if !ok {
		t.Fatalf("data/fileprofiles.json missing from tarball: %v", sortedNames(files))
	}
	if !bytes.Equal(got, body) {
		t.Errorf("fileprofiles.json content mismatch in backup")
	}
}
