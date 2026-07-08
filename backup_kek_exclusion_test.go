package main

// CA-3 PR4 — backup/DR and KEK exclusion tests.
//
// Verifies that local KEK files are never packed into a backup archive (even
// alongside the encrypted keys they wrap), that no KEK bytes leak into the
// tarball, and that restore validation accepts an encrypted (PSCA) cluster CA
// key without requiring a plaintext PEM parse while still rejecting malformed
// key material. t.TempDir; no sleeps/retries.

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/KidCarmi/Culvert/internal/ca"
)

// kekMarker is a recognizable byte string written into seeded KEK files so a
// test can assert it never appears anywhere in the produced archive.
var kekMarker = []byte("CA3-KEK-SECRET-MARKER-DO-NOT-PACK")

// TestBackup_ExcludesKEKBesideEncryptedKey: when cluster-ca.key is backed up,
// its sibling cluster-ca.kek must NOT be packed.
func TestBackup_ExcludesKEKBesideEncryptedKey(t *testing.T) {
	dataDir := t.TempDir()
	seedFile(t, dataDir, "ui_users.json", []byte(`{}`), 0o600)
	// An encrypted cluster CA key (PSCA envelope) plus its local KEK sibling.
	seedFile(t, dataDir, "cluster-ca.crt", []byte("-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n"), 0o600)
	seedFile(t, dataDir, "cluster-ca.key", append(ca.Magic(), []byte("ciphertext")...), 0o600)
	seedFile(t, dataDir, "cluster-ca.kek", kekMarker, 0o600)

	out := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := runBackup(out, dataDir); err != nil {
		t.Fatalf("runBackup: %v", err)
	}
	_, files, _ := readBackupTarball(t, out)

	// The encrypted key IS backed up.
	if _, ok := files["data/cluster-ca.key"]; !ok {
		t.Fatal("encrypted cluster-ca.key should be in the backup")
	}
	// The KEK is NOT.
	if _, ok := files["data/cluster-ca.kek"]; ok {
		t.Fatal("cluster-ca.kek must NOT be in the backup archive")
	}
}

// TestBackup_ExcludesKEKInWalkedDir: a .kek that somehow lands inside the
// recursively-walked config_versions/ dir must still be excluded.
func TestBackup_ExcludesKEKInWalkedDir(t *testing.T) {
	dataDir := t.TempDir()
	seedFile(t, dataDir, "ui_users.json", []byte(`{}`), 0o600)
	seedFile(t, dataDir, "config_versions/v1.json", []byte(`{"meta":{"version":1}}`), 0o600)
	seedFile(t, dataDir, "config_versions/stray.kek", kekMarker, 0o600)

	out := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := runBackup(out, dataDir); err != nil {
		t.Fatalf("runBackup: %v", err)
	}
	_, files, _ := readBackupTarball(t, out)

	if _, ok := files["data/config_versions/v1.json"]; !ok {
		t.Fatal("config_versions/v1.json should be backed up")
	}
	if _, ok := files["data/config_versions/stray.kek"]; ok {
		t.Fatal("a .kek inside config_versions/ must NOT be packed")
	}
}

// TestBackup_NoKEKBytesInArchive: the raw KEK marker bytes must not appear
// anywhere in the produced tarball (manifest or any file body).
func TestBackup_NoKEKBytesInArchive(t *testing.T) {
	dataDir := t.TempDir()
	seedFile(t, dataDir, "ui_users.json", []byte(`{}`), 0o600)
	seedFile(t, dataDir, "cluster-ca.key", append(ca.Magic(), []byte("ct")...), 0o600)
	seedFile(t, dataDir, "cluster-ca.kek", kekMarker, 0o600)
	seedFile(t, dataDir, "config_versions/other.kek", kekMarker, 0o600)

	out := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := runBackup(out, dataDir); err != nil {
		t.Fatalf("runBackup: %v", err)
	}
	_, files, _ := readBackupTarball(t, out)
	for name, body := range files {
		if bytes.Contains(body, kekMarker) {
			t.Fatalf("KEK marker bytes leaked into archive entry %q", name)
		}
	}
}

// TestIsKEKArtifactPath: the suffix detector recognizes every CA-3 KEK file
// name and nothing else.
func TestIsKEKArtifactPath(t *testing.T) {
	kek := []string{
		"data/cluster-ca.kek",
		"data/dp-node.kek",
		"/data/integrations/sluice/inst/client.key.kek",
		"cluster-ca.kek",
	}
	notKEK := []string{
		"data/cluster-ca.key",
		"data/cluster-ca.crt",
		"data/ca.bundle",
		"data/config_versions/v1.json",
		"data/kektest.json", // contains "kek" but not the suffix
	}
	for _, p := range kek {
		if !isKEKArtifactPath(p) {
			t.Errorf("isKEKArtifactPath(%q) = false, want true", p)
		}
	}
	for _, p := range notKEK {
		if isKEKArtifactPath(p) {
			t.Errorf("isKEKArtifactPath(%q) = true, want false", p)
		}
	}
}

// TestBackup_DPAndCDRKeysNotInAllowlist pins the DR-doc claim (§ 9.4): only the
// cluster CA key is in the backup allowlist. dp-node.key (CWD-relative) and CDR
// client keys (under /data/integrations/sluice) are NOT archived by --backup, so
// the doc must not tell operators to "back them up". If a future change adds
// either to defaultBackupArtifacts, this test fails and the doc must be updated.
func TestBackup_DPAndCDRKeysNotInAllowlist(t *testing.T) {
	arts := defaultBackupArtifacts("/data")
	for _, a := range arts {
		base := filepath.Base(a.SrcPath)
		if base == "dp-node.key" {
			t.Error("dp-node.key must not be in defaultBackupArtifacts (DR doc § 9.4 says it is re-enrolled, not backed up)")
		}
		if base == "client.key" || filepath.Dir(a.SrcPath) == "/data/integrations/sluice" {
			t.Errorf("CDR client key path %q must not be in defaultBackupArtifacts", a.SrcPath)
		}
	}
	// Sanity: the cluster CA key IS in the allowlist (the one key that is).
	var hasClusterCAKey bool
	for _, a := range arts {
		if filepath.Base(a.SrcPath) == "cluster-ca.key" {
			hasClusterCAKey = true
		}
	}
	if !hasClusterCAKey {
		t.Error("cluster-ca.key should be in defaultBackupArtifacts")
	}
}

// TestRestore_ValidatesEncryptedClusterCAKey: restore validation accepts an
// encrypted (PSCA) cluster-ca.key by validating the cert alone (no PEM key
// parse, no KEK needed), and still rejects a malformed/non-PSCA non-PEM key.
func TestRestore_ValidatesEncryptedClusterCAKey(t *testing.T) {
	// A real cert from the cluster CA bootstrap (plaintext), with an encrypted
	// key envelope substituted.
	t.Setenv(clusterCAEncryptEnvVar, "true")
	t.Setenv(envKEKName, "")
	dir := t.TempDir()
	if err := (&clusterCA{}).InitOrLoad(dir); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	certBody := readFile(t, filepath.Join(dir, "cluster-ca.crt"))
	encKey := readFile(t, filepath.Join(dir, "cluster-ca.key"))
	if !isEncryptedKeyFile(encKey) {
		t.Fatal("precondition: key should be encrypted")
	}

	// Encrypted key → validates on cert alone.
	var sum restoreSummary
	if err := validateTier1Artifacts(map[string][]byte{
		"data/cluster-ca.crt": certBody,
		"data/cluster-ca.key": encKey,
	}, "", &sum); err != nil {
		t.Fatalf("validate encrypted key: %v", err)
	}
	if sum.CAFingerprint == "" {
		t.Fatal("expected CA fingerprint from cert")
	}

	// Malformed non-PSCA, non-PEM key → still rejected (plaintext path).
	var sum2 restoreSummary
	err := validateTier1Artifacts(map[string][]byte{
		"data/cluster-ca.crt": certBody,
		"data/cluster-ca.key": []byte("not a pem key and not a PSCA envelope"),
	}, "", &sum2)
	if err == nil {
		t.Fatal("expected rejection of malformed key material")
	}
}
