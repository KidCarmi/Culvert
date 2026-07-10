package main

// CA-3 PR3b — tests for CDR/Sluice client private key encryption at rest.
//
// Helpers are driven directly with explicit t.TempDir paths (instance-local,
// race-safe). Env via t.Setenv; no sleeps/retries.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// cdrTestKeyPEM returns a fresh ECDSA P-256 private key as plaintext EC PEM.
func cdrTestKeyPEM(t *testing.T) []byte {
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

func cdrReadFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

// cdrOpenPlain decrypts raw via openCDRClientKey and returns a COPY of the
// plaintext (for assertion) plus wasEncrypted. Fails the test on decrypt error.
func cdrOpenPlain(t *testing.T, keyPath string, raw []byte) (plain []byte, wasEnc bool) {
	t.Helper()
	sealed, wasEnc, err := openCDRClientKey(keyPath, raw)
	if err != nil {
		t.Fatalf("openCDRClientKey: %v", err)
	}
	if werr := sealed.WithPlaintext(func(b []byte) error {
		plain = append(plain, b...)
		return nil
	}); werr != nil {
		t.Fatalf("WithPlaintext: %v", werr)
	}
	return plain, wasEnc
}

// TestCDRClientKey_PlaintextWriteWhenDisabled: encode is a passthrough when
// disabled (existing plaintext behavior).
func TestCDRClientKey_PlaintextWriteWhenDisabled(t *testing.T) {
	t.Setenv(cdrClientKeyEncryptEnvVar, "")
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "client.key")
	plain := cdrTestKeyPEM(t)
	out, err := encodeCDRClientKeyForWrite(keyPath, plain)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if isEncryptedKeyFile(out) {
		t.Fatal("encoded encrypted while disabled")
	}
	if !bytes.Equal(out, plain) {
		t.Fatal("plaintext changed while disabled")
	}
}

// TestCDRClientKey_EncryptedWriteWhenEnabled: encode produces a PSCA envelope
// (no plaintext bytes) when enabled and round-trips.
func TestCDRClientKey_EncryptedWriteWhenEnabled(t *testing.T) {
	t.Setenv(cdrClientKeyEncryptEnvVar, "true")
	t.Setenv(envKEKName, "")
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "client.key")
	plain := cdrTestKeyPEM(t)

	out, err := encodeCDRClientKeyForWrite(keyPath, plain)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !isEncryptedKeyFile(out) {
		t.Fatal("expected encrypted output when enabled")
	}
	if bytes.Contains(out, []byte("EC PRIVATE KEY")) || bytes.Contains(out, plain) {
		t.Fatal("plaintext key bytes present in encrypted output")
	}
	// Persist and decrypt via the load helper.
	if err := os.WriteFile(keyPath, out, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// KEK file is anchored to the key file.
	if _, err := os.Stat(keyPath + cdrClientKEKSuffix); err != nil {
		t.Fatalf("expected per-key KEK file: %v", err)
	}
	got, wasEnc := cdrOpenPlain(t, keyPath, cdrReadFile(t, keyPath))
	if !wasEnc {
		t.Fatal("expected wasEncrypted for envelope")
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("decrypted key mismatch")
	}
}

// TestCDRClientKey_PlaintextLoadsWhenDisabled: a plaintext key passes through
// decrypt without a KEK.
func TestCDRClientKey_PlaintextLoadsWhenDisabled(t *testing.T) {
	t.Setenv(cdrClientKeyEncryptEnvVar, "")
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "client.key")
	plain := cdrTestKeyPEM(t)
	if err := os.WriteFile(keyPath, plain, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	got, wasEnc := cdrOpenPlain(t, keyPath, cdrReadFile(t, keyPath))
	if wasEnc {
		t.Fatal("plaintext reported as encrypted")
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("plaintext passthrough mismatch")
	}
}

// TestCDRClientKey_LoadBundleDecryptsKey: loadCDRCertBundle returns plaintext
// key bytes for an encrypted key while leaving cert + CA as-is.
func TestCDRClientKey_LoadBundleDecryptsKey(t *testing.T) {
	t.Setenv(cdrClientKeyEncryptEnvVar, "true")
	t.Setenv(envKEKName, "")
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	certPath := filepath.Join(dir, "client.pem")
	keyPath := filepath.Join(dir, "client.key")

	caPEM := []byte("-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n")
	certPEM := []byte("-----BEGIN CERTIFICATE-----\nCLIENT\n-----END CERTIFICATE-----\n")
	plainKey := cdrTestKeyPEM(t)
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatalf("ca: %v", err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("cert: %v", err)
	}
	enc, err := encodeCDRClientKeyForWrite(keyPath, plainKey)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := os.WriteFile(keyPath, enc, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	ca, cert, keySealed, err := loadCDRCertBundle(caPath, certPath, keyPath)
	if err != nil {
		t.Fatalf("loadCDRCertBundle: %v", err)
	}
	if !bytes.Equal(ca, caPEM) || !bytes.Equal(cert, certPEM) {
		t.Fatal("cert/CA must be returned unchanged (plaintext)")
	}
	if werr := keySealed.WithPlaintext(func(key []byte) error {
		if !bytes.Equal(key, plainKey) {
			t.Fatal("returned key is not the decrypted plaintext")
		}
		return nil
	}); werr != nil {
		t.Fatalf("WithPlaintext: %v", werr)
	}
}

// TestCDRClientKey_MissingKEKFailsClosed: an encrypted key with no available
// KEK fails closed and leaves the on-disk file untouched.
func TestCDRClientKey_MissingKEKFailsClosed(t *testing.T) {
	t.Setenv(cdrClientKeyEncryptEnvVar, "true")
	t.Setenv(envKEKName, "")
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "client.key")
	enc, err := encodeCDRClientKeyForWrite(keyPath, cdrTestKeyPEM(t))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := os.WriteFile(keyPath, enc, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	encBefore := cdrReadFile(t, keyPath)
	if err := os.Remove(keyPath + cdrClientKEKSuffix); err != nil {
		t.Fatalf("remove kek: %v", err)
	}
	if _, _, derr := openCDRClientKey(keyPath, cdrReadFile(t, keyPath)); derr == nil {
		t.Fatal("expected fail-closed with missing KEK")
	}
	if !bytes.Equal(encBefore, cdrReadFile(t, keyPath)) {
		t.Fatal("encrypted key modified on failed decrypt")
	}
}

// TestCDRClientKey_WrongKEKFailsClosed: a different KEK cannot decrypt.
func TestCDRClientKey_WrongKEKFailsClosed(t *testing.T) {
	t.Setenv(cdrClientKeyEncryptEnvVar, "true")
	t.Setenv(envKEKName, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "client.key")
	enc, err := encodeCDRClientKeyForWrite(keyPath, cdrTestKeyPEM(t))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := os.WriteFile(keyPath, enc, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Setenv(envKEKName, "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100")
	if _, _, derr := openCDRClientKey(keyPath, cdrReadFile(t, keyPath)); derr == nil {
		t.Fatal("expected fail-closed with wrong KEK")
	}
}

// TestCDRClientKey_CorruptedCiphertextFailsClosed: a flipped tag byte fails.
func TestCDRClientKey_CorruptedCiphertextFailsClosed(t *testing.T) {
	t.Setenv(cdrClientKeyEncryptEnvVar, "true")
	t.Setenv(envKEKName, "")
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "client.key")
	enc, err := encodeCDRClientKeyForWrite(keyPath, cdrTestKeyPEM(t))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	enc[len(enc)-1] ^= 0xFF
	if _, _, derr := openCDRClientKey(keyPath, enc); derr == nil {
		t.Fatal("expected fail-closed on corrupted ciphertext")
	}
}

// TestCDRClientKey_MigrationCreatesReadableBakAndIsIdempotent: opt-in migration
// encrypts the active key, leaves a readable plaintext .bak, and is a no-op on
// re-run. Structural symmetry with the DP node key migration test is intentional.
//
//nolint:dupl // intentional parallel shape across key types, not accidental copy
func TestCDRClientKey_MigrationCreatesReadableBakAndIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "client.key")
	plain := cdrTestKeyPEM(t)
	if err := os.WriteFile(keyPath, plain, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	t.Setenv(cdrClientKeyEncryptEnvVar, "1")
	t.Setenv(envKEKName, "")
	if err := maybeMigrateCDRClientKey(keyPath); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if !isEncryptedKeyFile(cdrReadFile(t, keyPath)) {
		t.Fatal("active key not encrypted after migration")
	}
	bak := cdrReadFile(t, keyPath+".plaintext.bak")
	if !bytes.Equal(bak, plain) || isEncryptedKeyFile(bak) {
		t.Fatal(".bak is not readable original plaintext")
	}
	// Idempotent.
	encBefore := cdrReadFile(t, keyPath)
	if err := maybeMigrateCDRClientKey(keyPath); err != nil {
		t.Fatalf("idempotent migrate: %v", err)
	}
	if !bytes.Equal(encBefore, cdrReadFile(t, keyPath)) {
		t.Fatal("encrypted key changed on idempotent re-run")
	}
}

// TestCDRClientKey_MigrationDisabledIsNoop: with encryption off, migration
// leaves the plaintext key as-is and creates no .bak.
func TestCDRClientKey_MigrationDisabledIsNoop(t *testing.T) {
	t.Setenv(cdrClientKeyEncryptEnvVar, "")
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "client.key")
	plain := cdrTestKeyPEM(t)
	if err := os.WriteFile(keyPath, plain, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := maybeMigrateCDRClientKey(keyPath); err != nil {
		t.Fatalf("migrate noop: %v", err)
	}
	if !bytes.Equal(cdrReadFile(t, keyPath), plain) {
		t.Fatal("plaintext changed while disabled")
	}
	if _, err := os.Stat(keyPath + ".plaintext.bak"); err == nil {
		t.Fatal("unexpected .bak while disabled")
	}
}

// TestCDRClientKey_FailedMigrationPreservesReadableBak: a malformed KEK aborts
// the encrypt step; a readable plaintext key must remain.
func TestCDRClientKey_FailedMigrationPreservesReadableBak(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "client.key")
	plain := cdrTestKeyPEM(t)
	if err := os.WriteFile(keyPath, plain, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	t.Setenv(cdrClientKeyEncryptEnvVar, "1")
	t.Setenv(envKEKName, "not-valid-hex")
	if err := maybeMigrateCDRClientKey(keyPath); err == nil {
		t.Fatal("expected migration failure with malformed KEK")
	}
	active, aerr := os.ReadFile(keyPath)
	bak, berr := os.ReadFile(keyPath + ".plaintext.bak")
	readable := (aerr == nil && !isEncryptedKeyFile(active) && bytes.Equal(active, plain)) ||
		(berr == nil && !isEncryptedKeyFile(bak) && bytes.Equal(bak, plain))
	if !readable {
		t.Fatal("no readable original plaintext key remains after failed migration")
	}
}

// TestCDRClientKey_ShredRemovesSidecars: revoking/removing a migrated instance
// must purge the at-rest sidecars (the plaintext-migration backup and the
// model-B KEK) alongside the primary key/cert/CA, leaving no raw key material.
// Writes under cdrCertsRoot, skipping gracefully if the env can't create it
// (mirrors TestPersistCDREnrollment_WritesBundleAndRegisters).
func TestCDRClientKey_ShredRemovesSidecars(t *testing.T) {
	dir, err := cdrInstanceCertsDir("keyatrest-shred-test")
	if err != nil || os.MkdirAll(dir, 0o700) != nil {
		t.Skipf("cannot create dir under cdrCertsRoot in this env: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	caPath := filepath.Join(dir, "ca.pem")
	certPath := filepath.Join(dir, "client.pem")
	keyPath := filepath.Join(dir, "client.key")
	bakPath := keyPath + ".plaintext.bak"
	kekPath := keyPath + cdrClientKEKSuffix

	for _, p := range []string{caPath, certPath, keyPath, bakPath, kekPath} {
		if werr := os.WriteFile(p, []byte("x"), 0o600); werr != nil {
			t.Fatalf("seed %s: %v", p, werr)
		}
	}

	shredCDRCerts(&CDREnrolledInstance{
		CACertPath:     caPath,
		ClientCertPath: certPath,
		ClientKeyPath:  keyPath,
	})

	for _, p := range []string{caPath, certPath, keyPath, bakPath, kekPath} {
		if _, statErr := os.Stat(p); statErr == nil {
			t.Fatalf("shred left %s behind", filepath.Base(p))
		}
	}
}

// TestCDRClientKey_InstanceIsolation: two instances with distinct key files use
// independent KEKs; one's KEK cannot decrypt the other's key.
func TestCDRClientKey_InstanceIsolation(t *testing.T) {
	t.Setenv(cdrClientKeyEncryptEnvVar, "true")
	t.Setenv(envKEKName, "") // force per-file model-B KEKs
	dir := t.TempDir()
	keyA := filepath.Join(dir, "a", "client.key")
	keyB := filepath.Join(dir, "b", "client.key")
	if err := os.MkdirAll(filepath.Dir(keyA), 0o700); err != nil {
		t.Fatalf("mkdir a: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyB), 0o700); err != nil {
		t.Fatalf("mkdir b: %v", err)
	}
	plainA := cdrTestKeyPEM(t)
	plainB := cdrTestKeyPEM(t)
	encA, err := encodeCDRClientKeyForWrite(keyA, plainA)
	if err != nil {
		t.Fatalf("encode a: %v", err)
	}
	encB, err := encodeCDRClientKeyForWrite(keyB, plainB)
	if err != nil {
		t.Fatalf("encode b: %v", err)
	}
	// Distinct KEK files exist per key.
	if _, err := os.Stat(keyA + cdrClientKEKSuffix); err != nil {
		t.Fatalf("kek a: %v", err)
	}
	if _, err := os.Stat(keyB + cdrClientKEKSuffix); err != nil {
		t.Fatalf("kek b: %v", err)
	}
	// Each decrypts with its own KEK.
	if got, _ := cdrOpenPlain(t, keyA, encA); !bytes.Equal(got, plainA) {
		t.Fatal("decrypt a: plaintext mismatch")
	}
	if got, _ := cdrOpenPlain(t, keyB, encB); !bytes.Equal(got, plainB) {
		t.Fatal("decrypt b: plaintext mismatch")
	}
	// Cross-decrypt must fail: A's envelope under B's KEK path.
	if err := os.WriteFile(keyB, encA, 0o600); err != nil {
		t.Fatalf("overwrite b with a's envelope: %v", err)
	}
	if _, _, err := openCDRClientKey(keyB, encA); err == nil {
		t.Fatal("expected cross-instance decrypt to fail (independent KEKs)")
	}
}
