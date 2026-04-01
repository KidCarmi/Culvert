package main

import (
	"os"
	"path/filepath"
	"testing"
)

// ── InitCA ────────────────────────────────────────────────────────────────────

func TestInitCA_Ready(t *testing.T) {
	cm := &CertManager{cache: map[string]*certCacheEntry{}}
	if err := cm.InitCA(); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	if !cm.Ready() {
		t.Error("Ready() should return true after InitCA")
	}
	if pem := cm.CACertPEM(); len(pem) == 0 {
		t.Error("CACertPEM() should return non-empty PEM after InitCA")
	}
}

// ── SaveCA / LoadCA round-trip ────────────────────────────────────────────────

func TestSaveLoadCA_WithPassphrase(t *testing.T) {
	cm := &CertManager{cache: map[string]*certCacheEntry{}}
	if err := cm.InitCA(); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	origPEM := cm.CACertPEM()

	path := filepath.Join(t.TempDir(), "ca.bundle")
	if err := cm.SaveCA(path, "s3cr3t-pa55phrase"); err != nil {
		t.Fatalf("SaveCA: %v", err)
	}

	// File must exist and be non-empty.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("bundle file missing: %v", err)
	}
	if fi.Size() == 0 {
		t.Fatal("bundle file is empty")
	}
	// File permissions must be 0600 (owner read/write only).
	if fi.Mode().Perm() != 0600 {
		t.Errorf("bundle perms = %o, want 0600", fi.Mode().Perm())
	}

	// Load into a fresh manager.
	cm2 := &CertManager{cache: map[string]*certCacheEntry{}}
	if err := cm2.LoadCA(path, "s3cr3t-pa55phrase"); err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	if !cm2.Ready() {
		t.Error("Ready() should be true after LoadCA")
	}
	if string(cm2.CACertPEM()) != string(origPEM) {
		t.Error("cert PEM mismatch after save/load round-trip")
	}
}

func TestLoadCA_WrongPassphrase(t *testing.T) {
	cm := &CertManager{cache: map[string]*certCacheEntry{}}
	if err := cm.InitCA(); err != nil {
		t.Fatalf("InitCA: %v", err)
	}

	path := filepath.Join(t.TempDir(), "ca.bundle")
	if err := cm.SaveCA(path, "correct-passphrase"); err != nil {
		t.Fatalf("SaveCA: %v", err)
	}

	cm2 := &CertManager{cache: map[string]*certCacheEntry{}}
	err := cm2.LoadCA(path, "wrong-passphrase")
	if err == nil {
		t.Error("LoadCA with wrong passphrase should return an error")
	}
}

func TestSaveLoadCA_NoPassphrase(t *testing.T) {
	cm := &CertManager{cache: map[string]*certCacheEntry{}}
	if err := cm.InitCA(); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	origPEM := cm.CACertPEM()

	path := filepath.Join(t.TempDir(), "ca-plain.pem")
	if err := cm.SaveCA(path, ""); err != nil {
		t.Fatalf("SaveCA (no passphrase): %v", err)
	}

	cm2 := &CertManager{cache: map[string]*certCacheEntry{}}
	if err := cm2.LoadCA(path, ""); err != nil {
		t.Fatalf("LoadCA (no passphrase): %v", err)
	}
	if string(cm2.CACertPEM()) != string(origPEM) {
		t.Error("cert PEM mismatch on plain round-trip")
	}
}

// ── LoadOrInitCA ──────────────────────────────────────────────────────────────

func TestLoadOrInitCA_CreatesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.bundle")
	cm := &CertManager{cache: map[string]*certCacheEntry{}}

	// File does not exist → should generate + save.
	if err := cm.LoadOrInitCA(path, "mypassphrase"); err != nil {
		t.Fatalf("LoadOrInitCA (create): %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("bundle file not created: %v", err)
	}

	// Load it again → same cert.
	origPEM := cm.CACertPEM()
	cm2 := &CertManager{cache: map[string]*certCacheEntry{}}
	if err := cm2.LoadOrInitCA(path, "mypassphrase"); err != nil {
		t.Fatalf("LoadOrInitCA (load): %v", err)
	}
	if string(cm2.CACertPEM()) != string(origPEM) {
		t.Error("cert mismatch between create and subsequent load")
	}
}

// ── signLeaf ──────────────────────────────────────────────────────────────────

func TestSignLeaf_ValidCert(t *testing.T) {
	cm := &CertManager{cache: map[string]*certCacheEntry{}}
	if err := cm.InitCA(); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	cert, err := cm.signLeaf("example.com")
	if err != nil {
		t.Fatalf("signLeaf: %v", err)
	}
	if cert == nil {
		t.Fatal("signLeaf returned nil cert")
	}
}
