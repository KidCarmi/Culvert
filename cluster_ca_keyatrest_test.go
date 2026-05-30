package main

// CA-3 PR2 — tests for cluster CA private key encryption at rest.
//
// Globals touched (globalClusterCA / globalClusterStore / globalConfigStore)
// are snapshot+restored; env activation uses t.Setenv (auto-restored). No
// sleeps, no retries. Each case uses t.TempDir.

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// withClusterCAGlobals snapshots and restores the cluster-CA-related globals so
// ImportCA (which touches globalClusterStore/globalConfigStore) is safe to call.
func withClusterCAGlobals(t *testing.T) {
	t.Helper()
	origCA := globalClusterCA
	origStore := globalClusterStore
	origConfig := globalConfigStore
	t.Cleanup(func() {
		globalClusterCA = origCA
		globalClusterStore = origStore
		globalConfigStore = origConfig
	})
	globalClusterStore = newTestClusterStore(t)
	globalConfigStore = newTestConfigStore(t)
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

// TestClusterCAKey_PlaintextLoadsWhenDisabled: with encryption off, an existing
// plaintext key loads and stays plaintext (unchanged behavior).
func TestClusterCAKey_PlaintextLoadsWhenDisabled(t *testing.T) {
	t.Setenv(clusterCAEncryptEnvVar, "")
	dir := t.TempDir()
	if err := (&clusterCA{}).InitOrLoad(dir); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	keyPath := filepath.Join(dir, "cluster-ca.key")
	if isEncryptedKeyFile(readFile(t, keyPath)) {
		t.Fatal("key should be plaintext when encryption disabled")
	}
	// Load again into a fresh CA — must succeed and remain plaintext.
	ca := &clusterCA{}
	if err := ca.InitOrLoad(dir); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !ca.Ready() {
		t.Fatal("CA not ready after reload")
	}
	if isEncryptedKeyFile(readFile(t, keyPath)) {
		t.Fatal("key unexpectedly encrypted while disabled")
	}
}

// TestClusterCAKey_GeneratesEncryptedWhenEnabled: a fresh bootstrap with
// encryption enabled writes an encrypted key (and reloads from it).
func TestClusterCAKey_GeneratesEncryptedWhenEnabled(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(clusterCAEncryptEnvVar, "true")
	t.Setenv(envKEKName, "") // force model-B file KEK in dir

	if err := (&clusterCA{}).InitOrLoad(dir); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	keyPath := filepath.Join(dir, "cluster-ca.key")
	raw := readFile(t, keyPath)
	if !isEncryptedKeyFile(raw) {
		t.Fatal("expected encrypted key file when enabled")
	}
	if bytes.Contains(raw, []byte("EC PRIVATE KEY")) {
		t.Fatal("plaintext PEM header found in encrypted key file")
	}
	// KEK file must exist alongside.
	if _, err := os.Stat(filepath.Join(dir, clusterCAKEKFileName)); err != nil {
		t.Fatalf("expected KEK file: %v", err)
	}
	// Reload from the encrypted key.
	ca := &clusterCA{}
	if err := ca.InitOrLoad(dir); err != nil {
		t.Fatalf("reload encrypted: %v", err)
	}
	if !ca.Ready() {
		t.Fatal("CA not ready after encrypted reload")
	}
}

// TestClusterCAKey_MigratesPlaintextToEncrypted: a plaintext key created while
// disabled is migrated to encrypted on the next load with encryption enabled,
// leaving a readable .bak.
func TestClusterCAKey_MigratesPlaintextToEncrypted(t *testing.T) {
	dir := t.TempDir()
	// Phase 1: bootstrap plaintext (disabled).
	t.Setenv(clusterCAEncryptEnvVar, "")
	if err := (&clusterCA{}).InitOrLoad(dir); err != nil {
		t.Fatalf("bootstrap plaintext: %v", err)
	}
	keyPath := filepath.Join(dir, "cluster-ca.key")
	origPlain := readFile(t, keyPath)
	if isEncryptedKeyFile(origPlain) {
		t.Fatal("precondition: key should be plaintext")
	}

	// Phase 2: enable encryption, reload → migration.
	t.Setenv(clusterCAEncryptEnvVar, "1")
	t.Setenv(envKEKName, "")
	ca := &clusterCA{}
	if err := ca.InitOrLoad(dir); err != nil {
		t.Fatalf("migrate load: %v", err)
	}
	if !ca.Ready() {
		t.Fatal("CA not ready after migration")
	}
	// Active key now encrypted.
	if !isEncryptedKeyFile(readFile(t, keyPath)) {
		t.Fatal("active key not encrypted after migration")
	}
	// Plaintext .bak preserved and readable, equal to original.
	bak := readFile(t, keyPath+".plaintext.bak")
	if !bytes.Equal(bak, origPlain) {
		t.Fatal(".bak does not match original plaintext")
	}
	if isEncryptedKeyFile(bak) {
		t.Fatal(".bak should be plaintext")
	}

	// Idempotent: re-load again does not change the encrypted active key.
	encBefore := readFile(t, keyPath)
	ca2 := &clusterCA{}
	if err := ca2.InitOrLoad(dir); err != nil {
		t.Fatalf("idempotent reload: %v", err)
	}
	if !bytes.Equal(encBefore, readFile(t, keyPath)) {
		t.Fatal("encrypted key changed on idempotent reload")
	}
}

// TestClusterCAKey_MissingKEKFailsClosed: an encrypted key with no available
// KEK fails closed and does NOT regenerate the CA.
func TestClusterCAKey_MissingKEKFailsClosed(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(clusterCAEncryptEnvVar, "true")
	t.Setenv(envKEKName, "")
	if err := (&clusterCA{}).InitOrLoad(dir); err != nil {
		t.Fatalf("bootstrap encrypted: %v", err)
	}
	keyPath := filepath.Join(dir, "cluster-ca.key")
	encBefore := readFile(t, keyPath)

	// Remove the model-B KEK file → KEK now unavailable.
	if err := os.Remove(filepath.Join(dir, clusterCAKEKFileName)); err != nil {
		t.Fatalf("remove kek: %v", err)
	}

	ca := &clusterCA{}
	err := ca.InitOrLoad(dir)
	if err == nil {
		t.Fatal("expected fail-closed when KEK missing")
	}
	if ca.Ready() {
		t.Fatal("CA must not be initialized when decryption fails")
	}
	// The on-disk key must be untouched (no regeneration).
	if !bytes.Equal(encBefore, readFile(t, keyPath)) {
		t.Fatal("encrypted key file was modified on failed load (regeneration?)")
	}
}

// TestClusterCAKey_WrongKEKFailsClosed: a different KEK cannot decrypt and must
// not regenerate.
func TestClusterCAKey_WrongKEKFailsClosed(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(clusterCAEncryptEnvVar, "true")
	// Use an env KEK so we can swap it to a wrong value on reload.
	goodHex := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	t.Setenv(envKEKName, goodHex)
	if err := (&clusterCA{}).InitOrLoad(dir); err != nil {
		t.Fatalf("bootstrap encrypted: %v", err)
	}
	keyPath := filepath.Join(dir, "cluster-ca.key")
	encBefore := readFile(t, keyPath)

	// Swap to a different KEK.
	t.Setenv(envKEKName, "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100")
	ca := &clusterCA{}
	if err := ca.InitOrLoad(dir); err == nil {
		t.Fatal("expected fail-closed with wrong KEK")
	}
	if ca.Ready() {
		t.Fatal("CA must not be initialized with wrong KEK")
	}
	if !bytes.Equal(encBefore, readFile(t, keyPath)) {
		t.Fatal("encrypted key modified on wrong-KEK load")
	}
}

// TestClusterCAKey_CorruptedCiphertextFailsClosed.
func TestClusterCAKey_CorruptedCiphertextFailsClosed(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(clusterCAEncryptEnvVar, "true")
	t.Setenv(envKEKName, "")
	if err := (&clusterCA{}).InitOrLoad(dir); err != nil {
		t.Fatalf("bootstrap encrypted: %v", err)
	}
	keyPath := filepath.Join(dir, "cluster-ca.key")
	enc := readFile(t, keyPath)
	// Flip a byte in the tag/ciphertext region.
	enc[len(enc)-1] ^= 0xFF
	if err := os.WriteFile(keyPath, enc, 0o600); err != nil {
		t.Fatalf("write corrupt: %v", err)
	}
	ca := &clusterCA{}
	if err := ca.InitOrLoad(dir); err == nil {
		t.Fatal("expected fail-closed on corrupted ciphertext")
	}
	if ca.Ready() {
		t.Fatal("CA must not initialize on corrupted ciphertext")
	}
}

// TestClusterCAKey_ImportCAWritesEncrypted: ImportCA persists an encrypted key
// when encryption is enabled.
func TestClusterCAKey_ImportCAWritesEncrypted(t *testing.T) {
	withClusterCAGlobals(t)
	dir := t.TempDir()
	t.Setenv(clusterCAEncryptEnvVar, "true")
	t.Setenv(envKEKName, "")

	ca := &clusterCA{}
	if err := ca.InitOrLoad(dir); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	globalClusterCA = ca

	// A fresh CA pair to import.
	newCert, newKey := seedClusterCAFiles(t)
	if err := ca.ImportCA(newCert, newKey); err != nil {
		t.Fatalf("ImportCA: %v", err)
	}
	keyPath := filepath.Join(dir, "cluster-ca.key")
	raw := readFile(t, keyPath)
	if !isEncryptedKeyFile(raw) {
		t.Fatal("ImportCA did not write encrypted key when enabled")
	}
	if bytes.Contains(raw, []byte("EC PRIVATE KEY")) {
		t.Fatal("plaintext PEM header in ImportCA-written key")
	}
	// The key .bak from the old CA must also not be plaintext.
	if bak, err := os.ReadFile(keyPath + ".bak"); err == nil {
		if isEncryptedKeyFile(bak) {
			// good — encrypted
		} else if bytes.Contains(bak, []byte("EC PRIVATE KEY")) {
			t.Fatal("ImportCA left plaintext key .bak while encryption enabled")
		}
	}
}

// TestClusterCAKey_ImportCAPlaintextWhenDisabled: ImportCA stays plaintext when
// encryption is disabled (unchanged behavior).
func TestClusterCAKey_ImportCAPlaintextWhenDisabled(t *testing.T) {
	withClusterCAGlobals(t)
	dir := t.TempDir()
	t.Setenv(clusterCAEncryptEnvVar, "")

	ca := &clusterCA{}
	if err := ca.InitOrLoad(dir); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	globalClusterCA = ca
	newCert, newKey := seedClusterCAFiles(t)
	if err := ca.ImportCA(newCert, newKey); err != nil {
		t.Fatalf("ImportCA: %v", err)
	}
	raw := readFile(t, filepath.Join(dir, "cluster-ca.key"))
	if isEncryptedKeyFile(raw) {
		t.Fatal("ImportCA encrypted key while disabled")
	}
}

// TestClusterCAKey_FailedMigrationPreservesReadableBak: if the encrypt step
// fails after the .bak is written, the active key is restored from the .bak so
// a readable key remains.
func TestClusterCAKey_FailedMigrationPreservesReadableBak(t *testing.T) {
	dir := t.TempDir()
	if err := (&clusterCA{}).InitOrLoad(dir); err != nil {
		t.Fatalf("bootstrap plaintext: %v", err)
	}
	keyPath := filepath.Join(dir, "cluster-ca.key")
	plain := readFile(t, keyPath)

	// Force migration failure: point the model-B KEK at an unwritable location
	// by making the KEK path a directory (CreateTemp in it is fine, but we make
	// the *key dir's* kek path a directory so KEK generation fails). Simpler:
	// use an env KEK that is malformed so encryptWithKEK fails.
	t.Setenv(clusterCAEncryptEnvVar, "1")
	t.Setenv(envKEKName, "not-valid-hex-kek")

	err := migrateClusterCAKeyToEncrypted(dir, keyPath, plain)
	if err == nil {
		t.Fatal("expected migration to fail with malformed KEK")
	}
	// A readable plaintext key must remain at keyPath or the .bak.
	active, aerr := os.ReadFile(keyPath)
	bak, berr := os.ReadFile(keyPath + ".plaintext.bak")
	readable := (aerr == nil && !isEncryptedKeyFile(active)) ||
		(berr == nil && !isEncryptedKeyFile(bak))
	if !readable {
		t.Fatal("no readable plaintext key remains after failed migration")
	}
	// And whichever is readable must equal the original.
	if aerr == nil && !isEncryptedKeyFile(active) && !bytes.Equal(active, plain) {
		t.Fatal("active key diverged from original after failed migration")
	}
}

// TestClusterCAKey_EnabledLoadsExistingEncryptedNoBak: loading an
// already-encrypted key with encryption enabled does not produce a .bak (no
// migration needed).
func TestClusterCAKey_EnabledLoadsExistingEncryptedNoBak(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(clusterCAEncryptEnvVar, "true")
	t.Setenv(envKEKName, "")
	if err := (&clusterCA{}).InitOrLoad(dir); err != nil {
		t.Fatalf("bootstrap encrypted: %v", err)
	}
	ca := &clusterCA{}
	if err := ca.InitOrLoad(dir); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "cluster-ca.key.plaintext.bak")); err == nil {
		t.Fatal("unexpected migration .bak when key already encrypted")
	}
}
