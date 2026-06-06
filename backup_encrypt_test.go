package main

// D1.4 — backup encryption tests.
//
// Coverage maps to the design's seven required cases plus three edge
// cases:
//   1.  encrypted round-trip
//   2.  wrong passphrase fails (dry-run)
//   3.  tampered ciphertext fails
//   4.  missing passphrase fails
//   5.  legacy unencrypted backup still restores
//   6.  dry-run with encrypted backup
//   7.  no decrypted temp file left behind
//   8.  truncated ciphertext fails
//   9.  tampered header (magic / iters)
//   10. AAD binding — header swap between backups fails authentication
//   11. refuses to overwrite an existing output path
//   12. on-disk blob carries the encrypted magic

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testBackupPassphrase = "correct-horse-battery-staple"

// ── helpers ─────────────────────────────────────────────────────────

// makeEncryptedBackup writes a small valid /data layout, runs
// runBackupEncrypted with the canonical test passphrase, and returns
// the encrypted file path.
func makeEncryptedBackup(t *testing.T) string {
	t.Helper()
	dataDir := t.TempDir()
	seedFile(t, dataDir, "ui_users.json",
		[]byte(`{"users":[{"username":"admin","role":"admin","pass_hash":"deadbeef"}]}`), 0o600)
	seedFile(t, dataDir, "cluster.json", []byte(`{"nodes":{}}`), 0o600)
	seedFile(t, dataDir, "config_versions/v1.json", []byte(`{"meta":{"version":1}}`), 0o600)

	out := filepath.Join(t.TempDir(), "backup.tar.gz.enc")
	if err := runBackupEncrypted(out, dataDir, testBackupPassphrase); err != nil {
		t.Fatalf("runBackupEncrypted: %v", err)
	}
	return out
}

// snapshotFiles returns the set of regular files under dir, recursively.
func snapshotFiles(t *testing.T, dir string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			out[p] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot %s: %v", dir, err)
	}
	return out
}

// ── tests ───────────────────────────────────────────────────────────

func TestBackupEncrypt_BlobIsEncrypted(t *testing.T) {
	out := makeEncryptedBackup(t)
	body, err := os.ReadFile(out) // #nosec G304 G703 -- test temp path under t.TempDir()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !isEncryptedBackupBlob(body) {
		t.Fatalf("blob does not start with encrypted magic; got %q", body[:8])
	}
	// Defense in depth: must NOT be a gzip stream.
	if len(body) >= 2 && body[0] == 0x1F && body[1] == 0x8B {
		t.Fatalf("blob looks like gzip — encryption did not run")
	}
}

func TestBackupEncrypt_RoundTripDryRun(t *testing.T) {
	out := makeEncryptedBackup(t)
	dataDir := t.TempDir()

	// captureStdout is defined in restore_test.go.
	if _, err := captureStdout(t, func() error {
		return runRestoreDryRun(out, dataDir, "", restoreOpts{
			Mode:             modeFull,
			BackupPassphrase: testBackupPassphrase,
		})
	}); err != nil {
		t.Fatalf("dry-run with correct passphrase: %v", err)
	}
}

func TestBackupEncrypt_WrongPassphraseFailsDryRun(t *testing.T) {
	out := makeEncryptedBackup(t)
	dataDir := t.TempDir()
	_, err := captureStdout(t, func() error {
		return runRestoreDryRun(out, dataDir, "", restoreOpts{
			Mode:             modeFull,
			BackupPassphrase: "the-wrong-passphrase",
		})
	})
	if err == nil {
		t.Fatal("expected error for wrong passphrase")
	}
	// Opaque message — must not distinguish wrong-key from tamper.
	if !strings.Contains(err.Error(), "decrypt failed") {
		t.Fatalf("error should be the opaque decrypt message, got: %v", err)
	}
}

func TestBackupEncrypt_MissingPassphraseFails(t *testing.T) {
	out := makeEncryptedBackup(t)
	dataDir := t.TempDir()
	_, err := captureStdout(t, func() error {
		return runRestoreDryRun(out, dataDir, "", restoreOpts{
			Mode:             modeFull,
			BackupPassphrase: "",
		})
	})
	if err == nil {
		t.Fatal("expected error for missing passphrase")
	}
	// Specific (non-opaque) error: header-level "encryption detected, no passphrase set"
	// cannot leak passphrase info, so it can name the env var.
	if !strings.Contains(err.Error(), backupPassphraseEnv) {
		t.Fatalf("error should name the env var %q, got: %v", backupPassphraseEnv, err)
	}
}

func TestBackupEncrypt_TamperedCiphertext(t *testing.T) {
	out := makeEncryptedBackup(t)
	body, err := os.ReadFile(out) // #nosec G304 G703 -- test temp path under t.TempDir()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// Flip a byte well past the header so the change lands in ciphertext.
	idx := backupEncHdrLen + 8
	if idx >= len(body) {
		t.Fatalf("backup too short (%d bytes) for ciphertext-tamper test", len(body))
	}
	body[idx] ^= 0xFF
	if err := os.WriteFile(out, body, 0o600); err != nil { // #nosec G304 G703 -- test temp path under t.TempDir()
		t.Fatalf("write: %v", err)
	}

	dataDir := t.TempDir()
	_, err = captureStdout(t, func() error {
		return runRestoreDryRun(out, dataDir, "", restoreOpts{
			Mode:             modeFull,
			BackupPassphrase: testBackupPassphrase,
		})
	})
	if err == nil {
		t.Fatal("expected GCM authentication failure on tampered ciphertext")
	}
	if !strings.Contains(err.Error(), "decrypt failed") {
		t.Fatalf("expected opaque decrypt error, got: %v", err)
	}
}

func TestBackupEncrypt_TruncatedCiphertext(t *testing.T) {
	out := makeEncryptedBackup(t)
	body, err := os.ReadFile(out) // #nosec G304 G703 -- test temp path under t.TempDir()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// Drop the last byte → GCM tag check fails.
	if err := os.WriteFile(out, body[:len(body)-1], 0o600); err != nil { // #nosec G304 G703 -- test temp path under t.TempDir()
		t.Fatalf("write: %v", err)
	}
	dataDir := t.TempDir()
	_, err = captureStdout(t, func() error {
		return runRestoreDryRun(out, dataDir, "", restoreOpts{
			Mode:             modeFull,
			BackupPassphrase: testBackupPassphrase,
		})
	})
	if err == nil {
		t.Fatal("expected error on truncated ciphertext")
	}
	if !strings.Contains(err.Error(), "decrypt failed") {
		t.Fatalf("expected opaque decrypt error, got: %v", err)
	}
}

func TestBackupEncrypt_TamperedMagic(t *testing.T) {
	out := makeEncryptedBackup(t)
	body, err := os.ReadFile(out) // #nosec G304 G703 -- test temp path under t.TempDir()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	body[0] ^= 0xFF                                        // break the magic
	if err := os.WriteFile(out, body, 0o600); err != nil { // #nosec G304 G703 -- test temp path under t.TempDir()
		t.Fatalf("write: %v", err)
	}
	dataDir := t.TempDir()
	_, err = captureStdout(t, func() error {
		return runRestoreDryRun(out, dataDir, "", restoreOpts{
			Mode:             modeFull,
			BackupPassphrase: testBackupPassphrase,
		})
	})
	if err == nil {
		t.Fatal("expected error on tampered magic")
	}
	// First-bytes path: with magic broken, the file looks like neither
	// gzip nor encrypted — gzip reader fails. The exact message comes
	// from the gunzip path.
	if !strings.Contains(err.Error(), "gunzip") && !strings.Contains(err.Error(), "tarball") {
		t.Fatalf("expected gunzip/tarball error after magic break, got: %v", err)
	}
}

func TestBackupEncrypt_TamperedHeaderItersFailsAAD(t *testing.T) {
	out := makeEncryptedBackup(t)
	body, err := os.ReadFile(out) // #nosec G304 G703 -- test temp path under t.TempDir()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// Change one of the iterations bytes (offsets 10..13). Stays above
	// the 100k floor (so we exercise the AAD path, not the floor check).
	body[12] ^= 0x01
	if err := os.WriteFile(out, body, 0o600); err != nil { // #nosec G304 G703 -- test temp path under t.TempDir()
		t.Fatalf("write: %v", err)
	}
	dataDir := t.TempDir()
	_, err = captureStdout(t, func() error {
		return runRestoreDryRun(out, dataDir, "", restoreOpts{
			Mode:             modeFull,
			BackupPassphrase: testBackupPassphrase,
		})
	})
	if err == nil {
		t.Fatal("expected AAD authentication failure on tampered iters")
	}
	if !strings.Contains(err.Error(), "decrypt failed") {
		t.Fatalf("expected opaque decrypt error (AAD), got: %v", err)
	}
}

func TestBackupEncrypt_HeaderAADCrossSwap(t *testing.T) {
	// Two encrypted backups under the SAME passphrase. Swap headers.
	// AAD binding must reject the cross-headered blob.
	a := makeEncryptedBackup(t)
	b := makeEncryptedBackup(t)

	bodyA, err := os.ReadFile(a) // #nosec G304 G703 -- test temp path under t.TempDir()
	if err != nil {
		t.Fatalf("read a: %v", err)
	}
	bodyB, err := os.ReadFile(b) // #nosec G304 G703 -- test temp path under t.TempDir()
	if err != nil {
		t.Fatalf("read b: %v", err)
	}

	// New blob: header from A, ciphertext from B.
	swapped := append([]byte{}, bodyA[:backupEncHdrLen]...)
	swapped = append(swapped, bodyB[backupEncHdrLen:]...)

	swappedPath := filepath.Join(t.TempDir(), "swapped.tar.gz.enc")
	if err := os.WriteFile(swappedPath, swapped, 0o600); err != nil { // #nosec G304 G703 -- test temp path under t.TempDir()
		t.Fatalf("write swapped: %v", err)
	}

	dataDir := t.TempDir()
	_, err = captureStdout(t, func() error {
		return runRestoreDryRun(swappedPath, dataDir, "", restoreOpts{
			Mode:             modeFull,
			BackupPassphrase: testBackupPassphrase,
		})
	})
	if err == nil {
		t.Fatal("expected AAD authentication failure on header swap")
	}
	if !strings.Contains(err.Error(), "decrypt failed") {
		t.Fatalf("expected opaque decrypt error, got: %v", err)
	}
}

func TestBackupEncrypt_LegacyUnencryptedRestores(t *testing.T) {
	// A D1.3a (unencrypted) backup must still validate end-to-end with
	// the new readTarball path. opts.BackupPassphrase is unset and
	// must be ignored because magic-byte sniffing falls through to gzip.
	dataDir := t.TempDir()
	seedFile(t, dataDir, "ui_users.json",
		[]byte(`{"users":[{"username":"admin","role":"admin","pass_hash":"deadbeef"}]}`), 0o600)
	seedFile(t, dataDir, "cluster.json", []byte(`{"nodes":{}}`), 0o600)
	seedFile(t, dataDir, "config_versions/v1.json", []byte(`{"meta":{"version":1}}`), 0o600)

	out := filepath.Join(t.TempDir(), "legacy.tar.gz")
	if err := runBackup(out, dataDir); err != nil {
		t.Fatalf("legacy backup: %v", err)
	}
	body, err := os.ReadFile(out) // #nosec G304 G703 -- test temp path under t.TempDir()
	if err != nil {
		t.Fatalf("read legacy: %v", err)
	}
	// Sanity: starts with gzip magic, NOT the encrypted magic.
	if isEncryptedBackupBlob(body) {
		t.Fatal("legacy backup unexpectedly carries the encrypted magic")
	}
	if len(body) < 2 || body[0] != 0x1F || body[1] != 0x8B {
		t.Fatalf("legacy backup is not gzip; got %x %x", body[0], body[1])
	}

	restoreDir := t.TempDir()
	if _, err := captureStdout(t, func() error {
		return runRestoreDryRun(out, restoreDir, "", restoreOpts{Mode: modeFull})
	}); err != nil {
		t.Fatalf("legacy restore dry-run: %v", err)
	}
}

func TestBackupEncrypt_NoDecryptedTempFile(t *testing.T) {
	out := makeEncryptedBackup(t)
	parent := filepath.Dir(out)

	// Snapshot the backup's parent dir before the dry-run. A naïve
	// "decrypt-to-temp" implementation would drop a .dec / .plain
	// sibling here, which the after-snapshot would catch.
	beforeParent := snapshotFiles(t, parent)

	dataDir := t.TempDir()
	if _, err := captureStdout(t, func() error {
		return runRestoreDryRun(out, dataDir, "", restoreOpts{
			Mode:             modeFull,
			BackupPassphrase: testBackupPassphrase,
		})
	}); err != nil {
		t.Fatalf("dry-run: %v", err)
	}

	afterParent := snapshotFiles(t, parent)
	for p := range afterParent {
		if !beforeParent[p] {
			t.Errorf("new file appeared in backup's parent dir during dry-run: %s", p)
		}
	}
	// Note: we deliberately do NOT walk os.TempDir() here. CI runners
	// keep unrelated, unreadable files there (other workflows, runner
	// scratch, etc.) which would race our Lstat. The implementation's
	// no-plaintext-on-disk guarantee is sourced in code (decryption
	// runs entirely on []byte; no os.Create / os.WriteFile is reachable
	// in the decrypt path) and exercised by the parent-dir check above.
}

func TestBackupEncrypt_RefusesOverwrite(t *testing.T) {
	dataDir := t.TempDir()
	seedFile(t, dataDir, "ui_users.json",
		[]byte(`{"users":[{"username":"admin","role":"admin","pass_hash":"deadbeef"}]}`), 0o600)
	seedFile(t, dataDir, "cluster.json", []byte(`{"nodes":{}}`), 0o600)
	seedFile(t, dataDir, "config_versions/v1.json", []byte(`{"meta":{"version":1}}`), 0o600)

	out := filepath.Join(t.TempDir(), "exists.tar.gz.enc")
	if err := os.WriteFile(out, []byte("preexisting"), 0o600); err != nil { // #nosec G304 G703 -- test temp path under t.TempDir()
		t.Fatalf("seed exists: %v", err)
	}

	err := runBackupEncrypted(out, dataDir, testBackupPassphrase)
	if err == nil {
		t.Fatal("expected runBackupEncrypted to refuse overwrite")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected 'already exists' error, got: %v", err)
	}
	// Pre-existing file body untouched.
	body, _ := os.ReadFile(out) // #nosec G304 G703 -- test temp path under t.TempDir()
	if string(body) != "preexisting" {
		t.Fatalf("pre-existing file was overwritten: %q", string(body))
	}
}

// ── unit tests for the crypto layer ─────────────────────────────────

func TestEncryptBackupBlob_RoundTrip(t *testing.T) {
	plaintext := bytes.Repeat([]byte("hello-D1.4-encryption "), 100)
	blob, err := encryptBackupBlob(plaintext, testBackupPassphrase)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !isEncryptedBackupBlob(blob) {
		t.Fatal("encrypted blob does not carry magic")
	}
	got, err := decryptBackupBlob(blob, testBackupPassphrase)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("plaintext mismatch after round-trip")
	}
}

func TestDecryptBackupBlob_OpaqueOnWrongKey(t *testing.T) {
	plaintext := []byte("payload")
	blob, err := encryptBackupBlob(plaintext, testBackupPassphrase)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	_, err = decryptBackupBlob(blob, "wrong-passphrase")
	if !errors.Is(err, errBackupDecryptOpaque) {
		t.Fatalf("expected errBackupDecryptOpaque, got: %v", err)
	}
}

func TestDecryptBackupBlob_HeaderItersBelowFloor(t *testing.T) {
	plaintext := []byte("payload")
	blob, err := encryptBackupBlob(plaintext, testBackupPassphrase)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// Drop iters to 1 (below floor). Direct-write into the header.
	// offsets 10..13 are iters BE.
	blob[10] = 0
	blob[11] = 0
	blob[12] = 0
	blob[13] = 1
	_, err = decryptBackupBlob(blob, testBackupPassphrase)
	if err == nil {
		t.Fatal("expected iter-floor rejection")
	}
	if !strings.Contains(err.Error(), "below minimum") {
		t.Fatalf("expected 'below minimum' rejection, got: %v", err)
	}
}

// TestBackupEncrypt_NoFixedTmpFile verifies the encrypted writer no
// longer reintroduces the fixed-suffix temp-file pattern. After a
// successful encrypted backup, no "<out>.tmp" file is left in the
// destination directory, and only the published outPath plus
// pre-existing entries appear in the dir.
func TestBackupEncrypt_NoFixedTmpFile(t *testing.T) {
	dataDir := t.TempDir()
	seedFile(t, dataDir, "ui_users.json",
		[]byte(`{"users":[{"username":"admin","role":"admin","pass_hash":"deadbeef"}]}`), 0o600)
	seedFile(t, dataDir, "cluster.json", []byte(`{"nodes":{}}`), 0o600)
	seedFile(t, dataDir, "config_versions/v1.json", []byte(`{"meta":{"version":1}}`), 0o600)

	outDir := t.TempDir()
	out := filepath.Join(outDir, "backup.tar.gz.enc")

	if err := runBackupEncrypted(out, dataDir, testBackupPassphrase); err != nil {
		t.Fatalf("runBackupEncrypted: %v", err)
	}

	// The fixed-suffix path must NOT exist.
	if _, err := os.Lstat(out + ".tmp"); err == nil {
		t.Errorf("fixed temp file %q must not exist after successful encrypt", out+".tmp")
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("unexpected stat err on fixed temp file: %v", err)
	}

	// The output dir should contain only the published file.
	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(out) {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("expected only %q in outDir, got %v", filepath.Base(out), names)
	}
}

// TestBackupEncrypt_StaleTmpDoesNotAffect verifies a leftover
// "<out>.tmp" file from a prior aborted run does not interfere with a
// new encrypted backup. atomicWriteFile uses os.CreateTemp with a
// random suffix, so it cannot collide with the legacy fixed name —
// the stale file must remain untouched (not the destination of a
// rename) and the new backup must publish at outPath as usual.
func TestBackupEncrypt_StaleTmpDoesNotAffect(t *testing.T) {
	dataDir := t.TempDir()
	seedFile(t, dataDir, "ui_users.json",
		[]byte(`{"users":[{"username":"admin","role":"admin","pass_hash":"deadbeef"}]}`), 0o600)
	seedFile(t, dataDir, "cluster.json", []byte(`{"nodes":{}}`), 0o600)
	seedFile(t, dataDir, "config_versions/v1.json", []byte(`{"meta":{"version":1}}`), 0o600)

	outDir := t.TempDir()
	out := filepath.Join(outDir, "backup.tar.gz.enc")
	staleTmp := out + ".tmp"
	staleBody := []byte("STALE — must not be touched by the encrypted writer")
	if err := os.WriteFile(staleTmp, staleBody, 0o600); err != nil { // #nosec G304 G703 -- test temp path under t.TempDir()
		t.Fatalf("seed stale tmp: %v", err)
	}

	if err := runBackupEncrypted(out, dataDir, testBackupPassphrase); err != nil {
		t.Fatalf("runBackupEncrypted: %v", err)
	}

	// Encrypted output landed at the canonical path.
	body, err := os.ReadFile(out) // #nosec G304 G703 -- test temp path under t.TempDir()
	if err != nil {
		t.Fatalf("read out: %v", err)
	}
	if !isEncryptedBackupBlob(body) {
		t.Fatal("output does not carry the encrypted magic")
	}

	// Stale fixed-suffix tmp file must still exist with its original
	// body (atomicWriteFile generated a unique tmp name; the legacy
	// stale file was never touched).
	got, err := os.ReadFile(staleTmp) // #nosec G304 G703 -- test temp path under t.TempDir()
	if err != nil {
		t.Fatalf("stale tmp must still exist: %v", err)
	}
	if !bytes.Equal(got, staleBody) {
		t.Fatalf("stale tmp body was modified; got %q want %q", got, staleBody)
	}
}
