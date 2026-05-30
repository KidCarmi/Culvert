package main

// CA-3 PR3 — tests for DP node private key encryption at rest.
//
// Most cases drive the helpers directly with explicit t.TempDir paths (no CWD
// dependence, race-safe). One integration case exercises persistEnrollCerts via
// os.Chdir (mirrors enroll_util_test.go) to prove the enrollment write path
// encrypts. Env via t.Setenv; no sleeps/retries.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// dpTestKeyPEM returns a fresh ECDSA P-256 private key as plaintext EC PEM.
func dpTestKeyPEM(t *testing.T) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// dpReadFile is a small fatal-on-error read helper.
func dpReadFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

// TestDPNodeKey_PlaintextWriteWhenDisabled: writeDPNodeKey stays plaintext when
// encryption is disabled (unchanged behavior).
func TestDPNodeKey_PlaintextWriteWhenDisabled(t *testing.T) {
	t.Setenv(dpNodeKeyEncryptEnvVar, "")
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "dp-node.key")
	plain := dpTestKeyPEM(t)
	if err := writeDPNodeKey(keyPath, plain); err != nil {
		t.Fatalf("writeDPNodeKey: %v", err)
	}
	raw := dpReadFile(t, keyPath)
	if isEncryptedKeyFile(raw) {
		t.Fatal("key encrypted while disabled")
	}
	if !bytes.Equal(raw, plain) {
		t.Fatal("plaintext key bytes changed on write")
	}
}

// TestDPNodeKey_EncryptedWriteWhenEnabled: writeDPNodeKey produces a PSCA
// envelope (no plaintext key bytes) when enabled, and loadDPNodeKeyPair-style
// decrypt round-trips.
func TestDPNodeKey_EncryptedWriteWhenEnabled(t *testing.T) {
	t.Setenv(dpNodeKeyEncryptEnvVar, "true")
	t.Setenv(envKEKName, "")
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "dp-node.key")
	plain := dpTestKeyPEM(t)

	if err := writeDPNodeKey(keyPath, plain); err != nil {
		t.Fatalf("writeDPNodeKey: %v", err)
	}
	raw := dpReadFile(t, keyPath)
	if !isEncryptedKeyFile(raw) {
		t.Fatal("expected encrypted key when enabled")
	}
	if bytes.Contains(raw, []byte("EC PRIVATE KEY")) {
		t.Fatal("plaintext PEM header in encrypted key file")
	}
	if bytes.Contains(raw, plain) {
		t.Fatal("plaintext key bytes present in encrypted key file")
	}
	// KEK file generated alongside.
	if _, err := os.Stat(filepath.Join(dir, dpNodeKEKFileName)); err != nil {
		t.Fatalf("expected KEK file: %v", err)
	}
	// Decrypt round-trip.
	got, wasEnc, err := decryptDPNodeKey(keyPath, raw)
	if err != nil || !wasEnc {
		t.Fatalf("decrypt: err=%v wasEnc=%v", err, wasEnc)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("decrypted key does not match original")
	}
}

// TestDPNodeKey_PlaintextLoadsWhenDisabled: a plaintext key decrypts (passes
// through) without a KEK, regardless of flag.
func TestDPNodeKey_PlaintextLoadsWhenDisabled(t *testing.T) {
	t.Setenv(dpNodeKeyEncryptEnvVar, "")
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "dp-node.key")
	plain := dpTestKeyPEM(t)
	if err := os.WriteFile(keyPath, plain, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	got, wasEnc, err := decryptDPNodeKey(keyPath, dpReadFile(t, keyPath))
	if err != nil {
		t.Fatalf("decryptDPNodeKey(plaintext): %v", err)
	}
	if wasEnc {
		t.Fatal("plaintext key reported as encrypted")
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("plaintext passthrough mismatch")
	}
}

// TestDPNodeKey_LoadKeyPair_EncryptedAndPlaintext: loadDPNodeKeyPair assembles a
// usable tls.Certificate from a real cert + (encrypted or plaintext) key.
func TestDPNodeKey_LoadKeyPair_EncryptedAndPlaintext(t *testing.T) {
	t.Setenv(dpNodeKeyEncryptEnvVar, "true")
	t.Setenv(envKEKName, "")
	dir := t.TempDir()
	certPath := filepath.Join(dir, "dp-node.crt")
	keyPath := filepath.Join(dir, "dp-node.key")

	// Generate a self-signed cert + key pair via the cluster CA bootstrap path
	// (gives a matching cert/key), then split into files.
	certPEM, keyPEM := genPlaintextClusterCAPair(t) // matching ECDSA cert+key
	// genPlaintextClusterCAPair resets the encrypt env to ""; restore it.
	t.Setenv(dpNodeKeyEncryptEnvVar, "true")
	t.Setenv(envKEKName, "")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := writeDPNodeKey(keyPath, keyPEM); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if !isEncryptedKeyFile(dpReadFile(t, keyPath)) {
		t.Fatal("precondition: key should be encrypted")
	}

	cert, err := loadDPNodeKeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("loadDPNodeKeyPair (encrypted): %v", err)
	}
	if cert.PrivateKey == nil || len(cert.Certificate) == 0 {
		t.Fatal("assembled tls.Certificate is incomplete")
	}

	// Plaintext key path also works.
	t.Setenv(dpNodeKeyEncryptEnvVar, "")
	keyPath2 := filepath.Join(dir, "dp-node-plain.key")
	if err := os.WriteFile(keyPath2, keyPEM, 0o600); err != nil {
		t.Fatalf("write plain key: %v", err)
	}
	if _, err := loadDPNodeKeyPair(certPath, keyPath2); err != nil {
		t.Fatalf("loadDPNodeKeyPair (plaintext): %v", err)
	}
}

// TestDPNodeKey_MissingKEKFailsClosed: an encrypted key with no available KEK
// fails closed; the on-disk file is untouched (no regeneration).
func TestDPNodeKey_MissingKEKFailsClosed(t *testing.T) {
	t.Setenv(dpNodeKeyEncryptEnvVar, "true")
	t.Setenv(envKEKName, "")
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "dp-node.key")
	if err := writeDPNodeKey(keyPath, dpTestKeyPEM(t)); err != nil {
		t.Fatalf("write: %v", err)
	}
	encBefore := dpReadFile(t, keyPath)
	if err := os.Remove(filepath.Join(dir, dpNodeKEKFileName)); err != nil {
		t.Fatalf("remove kek: %v", err)
	}
	_, _, err := decryptDPNodeKey(keyPath, dpReadFile(t, keyPath))
	if err == nil {
		t.Fatal("expected fail-closed with missing KEK")
	}
	if !bytes.Equal(encBefore, dpReadFile(t, keyPath)) {
		t.Fatal("encrypted key modified on failed decrypt")
	}
}

// TestDPNodeKey_WrongKEKFailsClosed: a different KEK cannot decrypt the
// envelope and must fail closed.
func TestDPNodeKey_WrongKEKFailsClosed(t *testing.T) {
	t.Setenv(dpNodeKeyEncryptEnvVar, "true")
	t.Setenv(envKEKName, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "dp-node.key")
	if err := writeDPNodeKey(keyPath, dpTestKeyPEM(t)); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Setenv(envKEKName, "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100")
	if _, _, err := decryptDPNodeKey(keyPath, dpReadFile(t, keyPath)); err == nil {
		t.Fatal("expected fail-closed with wrong KEK")
	}
}

// TestDPNodeKey_CorruptedCiphertextFailsClosed: a flipped tag byte fails closed.
func TestDPNodeKey_CorruptedCiphertextFailsClosed(t *testing.T) {
	t.Setenv(dpNodeKeyEncryptEnvVar, "true")
	t.Setenv(envKEKName, "")
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "dp-node.key")
	if err := writeDPNodeKey(keyPath, dpTestKeyPEM(t)); err != nil {
		t.Fatalf("write: %v", err)
	}
	enc := dpReadFile(t, keyPath)
	enc[len(enc)-1] ^= 0xFF
	if _, _, err := decryptDPNodeKey(keyPath, enc); err == nil {
		t.Fatal("expected fail-closed on corrupted ciphertext")
	}
}

// TestDPNodeKey_MigrationCreatesReadableBakAndIsIdempotent: opt-in migration
// encrypts the active key, leaves a readable plaintext .bak, and is a no-op on
// re-run.
func TestDPNodeKey_MigrationCreatesReadableBakAndIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "dp-node.key")
	plain := dpTestKeyPEM(t)
	// Seed plaintext (as a disabled install would have).
	if err := os.WriteFile(keyPath, plain, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	t.Setenv(dpNodeKeyEncryptEnvVar, "1")
	t.Setenv(envKEKName, "")
	if err := maybeMigrateDPNodeKey(keyPath); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if !isEncryptedKeyFile(dpReadFile(t, keyPath)) {
		t.Fatal("active key not encrypted after migration")
	}
	bak := dpReadFile(t, keyPath+".plaintext.bak")
	if !bytes.Equal(bak, plain) || isEncryptedKeyFile(bak) {
		t.Fatal(".bak is not the original readable plaintext")
	}
	// Idempotent: re-run leaves the encrypted active key unchanged.
	encBefore := dpReadFile(t, keyPath)
	if err := maybeMigrateDPNodeKey(keyPath); err != nil {
		t.Fatalf("idempotent migrate: %v", err)
	}
	if !bytes.Equal(encBefore, dpReadFile(t, keyPath)) {
		t.Fatal("encrypted key changed on idempotent re-run")
	}
}

// TestDPNodeKey_MigrationAcceptsNonECKey: a manually-provisioned DP node may
// carry an RSA/PKCS#8 key (loadable by tls.LoadX509KeyPair). Migration must
// accept and encrypt it, not abort on an EC-only parse check.
func TestDPNodeKey_MigrationAcceptsNonECKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "dp-node.key")

	// PKCS#8-wrapped RSA key (covers both the PKCS#8 and RSA acceptance paths).
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa gen: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("pkcs8 marshal: %v", err)
	}
	plain := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(keyPath, plain, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	t.Setenv(dpNodeKeyEncryptEnvVar, "1")
	t.Setenv(envKEKName, "")
	if err := maybeMigrateDPNodeKey(keyPath); err != nil {
		t.Fatalf("migrate non-EC key: %v", err)
	}
	if !isEncryptedKeyFile(dpReadFile(t, keyPath)) {
		t.Fatal("non-EC key not encrypted after migration")
	}
	// Decrypt round-trips back to the original PKCS#8 PEM.
	got, _, err := decryptDPNodeKey(keyPath, dpReadFile(t, keyPath))
	if err != nil {
		t.Fatalf("decrypt migrated non-EC key: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("decrypted non-EC key does not match original")
	}
}

// TestDPNodeKey_MigrationDisabledIsNoop: with encryption off, migration leaves
// the plaintext key as-is and creates no .bak.
func TestDPNodeKey_MigrationDisabledIsNoop(t *testing.T) {
	t.Setenv(dpNodeKeyEncryptEnvVar, "")
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "dp-node.key")
	plain := dpTestKeyPEM(t)
	if err := os.WriteFile(keyPath, plain, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := maybeMigrateDPNodeKey(keyPath); err != nil {
		t.Fatalf("migrate noop: %v", err)
	}
	if !bytes.Equal(dpReadFile(t, keyPath), plain) {
		t.Fatal("plaintext key changed while disabled")
	}
	if _, err := os.Stat(keyPath + ".plaintext.bak"); err == nil {
		t.Fatal("unexpected .bak while disabled")
	}
}

// TestDPNodeKey_MigrationMissingFileIsNoop: no enrolled key yet → no error.
func TestDPNodeKey_MigrationMissingFileIsNoop(t *testing.T) {
	t.Setenv(dpNodeKeyEncryptEnvVar, "true")
	t.Setenv(envKEKName, "")
	dir := t.TempDir()
	if err := maybeMigrateDPNodeKey(filepath.Join(dir, "dp-node.key")); err != nil {
		t.Fatalf("expected no-op for missing key, got %v", err)
	}
}

// TestDPNodeKey_MigrationEncryptedPresentMissingKEKFailsClosed: maybeMigrate must
// surface a decrypt failure (envelope present, KEK gone) rather than silently
// re-migrating or regenerating.
func TestDPNodeKey_FailedMigrationPreservesReadableBak(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "dp-node.key")
	plain := dpTestKeyPEM(t)
	if err := os.WriteFile(keyPath, plain, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Force encrypt failure with a malformed env KEK.
	t.Setenv(dpNodeKeyEncryptEnvVar, "1")
	t.Setenv(envKEKName, "not-valid-hex")
	if err := maybeMigrateDPNodeKey(keyPath); err == nil {
		t.Fatal("expected migration failure with malformed KEK")
	}
	// A readable plaintext key remains at active path or .bak.
	active, aerr := os.ReadFile(keyPath)
	bak, berr := os.ReadFile(keyPath + ".plaintext.bak")
	readable := (aerr == nil && !isEncryptedKeyFile(active) && bytes.Equal(active, plain)) ||
		(berr == nil && !isEncryptedKeyFile(bak) && bytes.Equal(bak, plain))
	if !readable {
		t.Fatal("no readable original plaintext key remains after failed migration")
	}
}

// TestDPNodeKey_PersistEnrollCertsEncryptsKey: the enrollment write path
// encrypts the key (and only the key) when enabled. Uses os.Chdir like
// enroll_util_test.go because persistEnrollCerts writes CWD-relative paths.
func TestDPNodeKey_PersistEnrollCertsEncryptsKey(t *testing.T) {
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(origDir) })

	t.Setenv(dpNodeKeyEncryptEnvVar, "true")
	t.Setenv(envKEKName, "")

	// A real signed cert+key would require a CA; persistEnrollCerts only needs
	// a parseable private key for the key file and writes resp.CertPEM verbatim.
	certPEM, keyPEM := genPlaintextClusterCAPair(t)
	t.Setenv(dpNodeKeyEncryptEnvVar, "true") // helper reset it
	t.Setenv(envKEKName, "")
	key, _ := x509.ParseECPrivateKey(mustPEMBlock(t, keyPEM))
	resp := &EnrollResponse{CertPEM: string(certPEM), CAPEM: string(certPEM), NodeID: "dp-test"}

	if _, err := persistEnrollCerts(key, resp, "cp:9000", "dp-test"); err != nil {
		t.Fatalf("persistEnrollCerts: %v", err)
	}
	// Key encrypted; cert + cluster-ca.crt remain plaintext certs.
	if !isEncryptedKeyFile(dpReadFile(t, "./dp-node.key")) {
		t.Fatal("dp-node.key not encrypted by enrollment write")
	}
	if isEncryptedKeyFile(dpReadFile(t, "./dp-node.crt")) {
		t.Fatal("dp-node.crt must remain a plaintext cert")
	}
	if isEncryptedKeyFile(dpReadFile(t, "./cluster-ca.crt")) {
		t.Fatal("cluster-ca.crt must remain a plaintext cert")
	}
}

// mustPEMBlock decodes the first PEM block's DER bytes or fails.
func mustPEMBlock(t *testing.T, pemBytes []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("no PEM block")
	}
	return block.Bytes
}
