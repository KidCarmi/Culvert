package main

// D1.2a cold-start tests for the encrypted root CA bundle (ca.bundle).
//
// Existing ca_test.go covers happy paths (encrypted round-trip, plain-PEM
// round-trip, wrong-passphrase rejection). This file pins the bad-state
// behaviors that are not currently asserted:
//
//   - missing file
//   - empty file
//   - garbage bytes (no PEM, no magic header)
//   - encrypted bundle truncated below the magic header
//
// One D1.2-flag finding is documented inline:
// LoadCA's plain-PEM detection is permissive — if the on-disk bytes do
// not start with caMagic, the bundle is treated as plain PEM regardless
// of whether a passphrase is set. That means a plain-PEM bundle written
// by an earlier instance loads cleanly even after operators add a
// passphrase. This is intentional flexibility (per ca.go:189), but it
// also means "passphrase set + corrupted file without magic" produces a
// PEM-decode error rather than a decrypt error — surprising-but-safe.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/ca"
)

func makeInitedCertManager(t *testing.T) *CertManager {
	t.Helper()
	cm := ca.New()
	if err := cm.InitCA(); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	return cm
}

func TestColdStart_CABundle_MissingFile(t *testing.T) {
	cases := []struct {
		name       string
		passphrase string
	}{
		{"no_passphrase", ""},
		{"with_passphrase", "test-passphrase"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "ca.bundle") // does not exist
			cm := ca.New()
			err := cm.LoadCA(path, c.passphrase)
			if err == nil {
				t.Fatal("expected error on missing file")
			}
			if !strings.Contains(err.Error(), "CA read") {
				t.Errorf("error should mention CA read, got: %v", err)
			}
		})
	}
}

func TestColdStart_CABundle_EmptyFile(t *testing.T) {
	// Empty file (0 bytes). Both code paths route through importBundle
	// (no magic, len < 5), which then fails to find any PEM block.
	cases := []struct {
		name       string
		passphrase string
	}{
		{"no_passphrase", ""},
		{"with_passphrase", "test-passphrase"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "ca.bundle")
			if err := os.WriteFile(path, []byte{}, 0o600); err != nil {
				t.Fatalf("write empty: %v", err)
			}
			cm := ca.New()
			err := cm.LoadCA(path, c.passphrase)
			if err == nil {
				t.Fatal("expected error on empty file")
			}
			if !strings.Contains(err.Error(), "CA bundle") {
				t.Errorf("error should mention CA bundle, got: %v", err)
			}
		})
	}
}

func TestColdStart_CABundle_GarbageBytes(t *testing.T) {
	// Random non-PEM bytes that also do not start with caMagic. Goes to
	// plain-PEM path → importBundle finds no CERTIFICATE/EC PRIVATE KEY
	// blocks → returns "missing CERTIFICATE or EC PRIVATE KEY block".
	dir := t.TempDir()
	path := filepath.Join(dir, "ca.bundle")
	if err := os.WriteFile(path, []byte("totally not a CA bundle, just text"), 0o600); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	cm := ca.New()
	err := cm.LoadCA(path, "test-passphrase")
	if err == nil {
		t.Fatal("expected error on garbage bytes")
	}
	if !strings.Contains(err.Error(), "missing CERTIFICATE") {
		t.Errorf("error should mention missing CERTIFICATE block, got: %v", err)
	}
}

func TestColdStart_CABundle_PlainPEMLoadsEvenWithPassphraseSet(t *testing.T) {
	// D1.2-flag (informational): plain PEM written by an earlier instance
	// without a passphrase loads cleanly even after the operator adds a
	// passphrase, because LoadCA detects "no magic header" → plain-PEM
	// path. This is intentional flexibility documented at ca.go:189; the
	// test pins the behavior so any future change is intentional.
	dir := t.TempDir()
	path := filepath.Join(dir, "ca.bundle")

	cm := makeInitedCertManager(t)
	if err := cm.SaveCA(path, ""); err != nil {
		t.Fatalf("SaveCA plain: %v", err)
	}
	origPEM := cm.CACertPEM()

	// Now try to load with a passphrase set — should still succeed.
	cm2 := ca.New()
	if err := cm2.LoadCA(path, "operator-set-this-later"); err != nil {
		t.Fatalf("LoadCA with passphrase on plain-PEM file: %v", err)
	}
	if string(cm2.CACertPEM()) != string(origPEM) {
		t.Error("cert PEM mismatch on plain-PEM-with-passphrase load")
	}
}

func TestColdStart_CABundle_EncryptedTruncated(t *testing.T) {
	// Encrypted bundle truncated mid-body. Magic header still present
	// (file > 5 bytes and starts with caMagic), so decryptBundle is
	// invoked and fails with a wrapped "CA decrypt" error.
	dir := t.TempDir()
	path := filepath.Join(dir, "ca.bundle")

	cm := makeInitedCertManager(t)
	if err := cm.SaveCA(path, "real-passphrase"); err != nil {
		t.Fatalf("SaveCA encrypted: %v", err)
	}

	// Read the encrypted bundle, truncate to keep magic + a few bytes.
	full, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read encrypted: %v", err)
	}
	if len(full) < 32 {
		t.Fatalf("encrypted bundle unexpectedly short: %d bytes", len(full))
	}
	truncated := full[:16]                                       // keeps magic header + a sliver
	if err := os.WriteFile(path, truncated, 0o600); err != nil { // #nosec G703 -- test fixture path from t.TempDir()
		t.Fatalf("write truncated: %v", err)
	}

	cm2 := ca.New()
	err = cm2.LoadCA(path, "real-passphrase")
	if err == nil {
		t.Fatal("expected error on truncated encrypted bundle")
	}
	if !strings.Contains(err.Error(), "CA decrypt") {
		t.Errorf("error should mention CA decrypt, got: %v", err)
	}
}
