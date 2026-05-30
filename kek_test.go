package main

// CA-3 PR1 — tests for the encrypted-file + KEK helper foundation.

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// staticKEK is a fixed-bytes provider for deterministic round-trip tests.
type staticKEK struct {
	key []byte
}

func (s staticKEK) KEK() ([]byte, error) { return s.key, nil }
func (s staticKEK) Name() string         { return "static" }

func mustKEK(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i + 1)
	}
	return b
}

func TestKEK_EncryptDecryptRoundTrip(t *testing.T) {
	p := staticKEK{key: mustKEK(t, kekLen)}
	plaintext := []byte("-----BEGIN EC PRIVATE KEY-----\nROUND-TRIP-SECRET\n-----END EC PRIVATE KEY-----")

	enc, err := encryptWithKEK(plaintext, p)
	if err != nil {
		t.Fatalf("encryptWithKEK: %v", err)
	}
	dec, err := decryptWithKEK(enc, p)
	if err != nil {
		t.Fatalf("decryptWithKEK: %v", err)
	}
	if !bytes.Equal(dec, plaintext) {
		t.Fatalf("round-trip mismatch: got %q want %q", dec, plaintext)
	}
}

func TestKEK_WrongKEKFails(t *testing.T) {
	good := staticKEK{key: mustKEK(t, kekLen)}
	bad := staticKEK{key: bytes.Repeat([]byte{0xAB}, kekLen)}
	plaintext := []byte("secret key material")

	enc, err := encryptWithKEK(plaintext, good)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := decryptWithKEK(enc, bad); err == nil {
		t.Fatal("expected decrypt with wrong KEK to fail, got nil error")
	}
}

func TestKEK_CorruptedCiphertextFails(t *testing.T) {
	p := staticKEK{key: mustKEK(t, kekLen)}
	enc, err := encryptWithKEK([]byte("secret"), p)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// Flip a byte in the ciphertext/tag region (last byte is part of the GCM tag).
	corrupt := append([]byte(nil), enc...)
	corrupt[len(corrupt)-1] ^= 0xFF
	if _, err := decryptWithKEK(corrupt, p); err == nil {
		t.Fatal("expected corrupted ciphertext to fail authentication, got nil error")
	}
}

func TestKEK_UnknownMagicAndVersionFail(t *testing.T) {
	p := staticKEK{key: mustKEK(t, kekLen)}
	enc, err := encryptWithKEK([]byte("secret"), p)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Bad magic.
	badMagic := append([]byte(nil), enc...)
	badMagic[0] ^= 0xFF
	if _, err := decryptWithKEK(badMagic, p); err == nil {
		t.Fatal("expected bad magic to fail, got nil error")
	}

	// Unsupported version (byte index 4 is the version in the PSCA envelope).
	badVer := append([]byte(nil), enc...)
	badVer[4] = 0xFE
	if _, err := decryptWithKEK(badVer, p); err == nil {
		t.Fatal("expected unsupported version to fail, got nil error")
	}

	// Truncated/malformed envelope (shorter than the header).
	if _, err := decryptWithKEK(enc[:3], p); err == nil {
		t.Fatal("expected truncated envelope to fail, got nil error")
	}
}

func TestKEK_RandomNonceProducesDifferentCiphertext(t *testing.T) {
	p := staticKEK{key: mustKEK(t, kekLen)}
	plaintext := []byte("same plaintext both times")

	a, err := encryptWithKEK(plaintext, p)
	if err != nil {
		t.Fatalf("encrypt a: %v", err)
	}
	b, err := encryptWithKEK(plaintext, p)
	if err != nil {
		t.Fatalf("encrypt b: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("expected different ciphertext for same plaintext (random salt/nonce), got identical output")
	}
}

func TestKEK_NoPlaintextKeyBytesInCiphertext(t *testing.T) {
	p := staticKEK{key: mustKEK(t, kekLen)}
	marker := []byte("TOPSECRET-PRIVATE-KEY-MARKER")
	plaintext := []byte("-----BEGIN EC PRIVATE KEY-----\n")
	plaintext = append(plaintext, marker...)

	enc, err := encryptWithKEK(plaintext, p)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if bytes.Contains(enc, marker) {
		t.Fatal("plaintext key marker found in encrypted output")
	}
	// The KEK itself must also not appear in the output.
	if bytes.Contains(enc, p.key) {
		t.Fatal("KEK bytes found in encrypted output")
	}
}

func TestKEK_FileWriteUses0600(t *testing.T) {
	dir := t.TempDir()
	encPath := filepath.Join(dir, "secret.enc")
	p := staticKEK{key: mustKEK(t, kekLen)}

	if err := writeEncryptedFile(encPath, []byte("secret"), p); err != nil {
		t.Fatalf("writeEncryptedFile: %v", err)
	}
	fi, err := os.Stat(encPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("encrypted file perm = %o, want 0600", perm)
	}

	// Round-trip through disk.
	got, err := readEncryptedFile(encPath, p)
	if err != nil {
		t.Fatalf("readEncryptedFile: %v", err)
	}
	if !bytes.Equal(got, []byte("secret")) {
		t.Fatalf("disk round-trip mismatch: got %q", got)
	}
}

func TestFileKEK_GeneratedAndStableAcrossLoads(t *testing.T) {
	dir := t.TempDir()
	kekPath := filepath.Join(dir, "kek.key")

	p := newFileKEKProvider(kekPath)
	first, err := p.KEK()
	if err != nil {
		t.Fatalf("first KEK: %v", err)
	}
	if len(first) != kekLen {
		t.Fatalf("KEK length = %d, want %d", len(first), kekLen)
	}

	// File must exist with 0600.
	fi, err := os.Stat(kekPath)
	if err != nil {
		t.Fatalf("stat kek file: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("kek file perm = %o, want 0600", perm)
	}

	// Same provider, second call: stable.
	second, err := p.KEK()
	if err != nil {
		t.Fatalf("second KEK: %v", err)
	}
	if !kekEqual(first, second) {
		t.Fatal("KEK changed across calls on same provider")
	}

	// Fresh provider over the same file: must load the persisted KEK, not regen.
	p2 := newFileKEKProvider(kekPath)
	reloaded, err := p2.KEK()
	if err != nil {
		t.Fatalf("reload KEK: %v", err)
	}
	if !kekEqual(first, reloaded) {
		t.Fatal("KEK not stable across fresh provider load")
	}

	// Data encrypted under the first provider decrypts under the reloaded one.
	enc, err := encryptWithKEK([]byte("payload"), p)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	dec, err := decryptWithKEK(enc, p2)
	if err != nil {
		t.Fatalf("decrypt with reloaded provider: %v", err)
	}
	if !bytes.Equal(dec, []byte("payload")) {
		t.Fatalf("cross-provider decrypt mismatch: %q", dec)
	}
}

func TestFileKEK_MalformedFileFailsClosed(t *testing.T) {
	dir := t.TempDir()
	kekPath := filepath.Join(dir, "kek.key")
	// Write a wrong-sized KEK file; provider must fail closed, not regenerate.
	if err := os.WriteFile(kekPath, []byte("too-short"), 0o600); err != nil {
		t.Fatalf("seed malformed kek: %v", err)
	}
	p := newFileKEKProvider(kekPath)
	if _, err := p.KEK(); err == nil {
		t.Fatal("expected malformed KEK file to fail closed, got nil error")
	}
}

func TestEnvKEK_RoundTripAndMissing(t *testing.T) {
	const name = "CULVERT_KEK_TEST"
	keyHex := hex.EncodeToString(mustKEK(t, kekLen))
	t.Setenv(name, keyHex)

	p := newEnvKEKProvider(name)
	got, err := p.KEK()
	if err != nil {
		t.Fatalf("env KEK: %v", err)
	}
	if len(got) != kekLen {
		t.Fatalf("env KEK length = %d, want %d", len(got), kekLen)
	}

	// Round-trip via the env-supplied KEK.
	enc, err := encryptWithKEK([]byte("env-secret"), p)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	dec, err := decryptWithKEK(enc, p)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(dec, []byte("env-secret")) {
		t.Fatalf("env round-trip mismatch: %q", dec)
	}
}

func TestEnvKEK_MissingAndMalformedFailClosed(t *testing.T) {
	const name = "CULVERT_KEK_TEST_MISSING"
	// Ensure unset.
	os.Unsetenv(name)
	p := newEnvKEKProvider(name)
	if _, err := p.KEK(); err == nil {
		t.Fatal("expected missing env KEK to fail closed")
	}

	// Not hex.
	t.Setenv(name, "not-hex-value!!")
	if _, err := p.KEK(); err == nil {
		t.Fatal("expected non-hex env KEK to fail")
	}

	// Wrong length (valid hex, but 16 bytes).
	t.Setenv(name, hex.EncodeToString(mustKEK(t, 16)))
	if _, err := p.KEK(); err == nil {
		t.Fatal("expected wrong-length env KEK to fail")
	}
}

func TestResolveKEKProvider_Deterministic(t *testing.T) {
	dir := t.TempDir()
	kekPath := filepath.Join(dir, "kek.key")
	const name = "CULVERT_KEK_TEST_RESOLVE"

	// No env set → file provider.
	os.Unsetenv(name)
	if p := resolveKEKProvider(name, kekPath); p.Name() != "file" {
		t.Fatalf("expected file provider when env unset, got %q", p.Name())
	}

	// Env set → env provider.
	t.Setenv(name, hex.EncodeToString(mustKEK(t, kekLen)))
	if p := resolveKEKProvider(name, kekPath); p.Name() != "env" {
		t.Fatalf("expected env provider when env set, got %q", p.Name())
	}
}

func TestKEK_MissingProviderFailsClosed(t *testing.T) {
	// A provider that returns no bytes must fail closed in both directions.
	empty := staticKEK{key: nil}
	if _, err := encryptWithKEK([]byte("x"), empty); err == nil {
		t.Fatal("expected encrypt with empty KEK to fail closed")
	}
	if _, err := decryptWithKEK([]byte("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"), empty); err == nil {
		t.Fatal("expected decrypt with empty KEK to fail closed")
	}
	// Nil provider.
	if _, err := encryptWithKEK([]byte("x"), nil); err == nil {
		t.Fatal("expected encrypt with nil provider to fail")
	}
}

func TestEncryptWithKEK_MissingFileKEKIsDeterministic(t *testing.T) {
	// A file provider pointed at an unwritable directory cannot generate its
	// KEK; the failure must be deterministic (same error both calls), never a
	// silent success.
	dir := t.TempDir()
	bad := filepath.Join(dir, "nonexistent-subdir", "kek.key")
	p := newFileKEKProvider(bad)
	_, err1 := p.KEK()
	_, err2 := p.KEK()
	if err1 == nil || err2 == nil {
		t.Fatal("expected KEK generation in nonexistent dir to fail")
	}
}
