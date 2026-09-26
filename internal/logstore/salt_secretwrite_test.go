package logstore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// SEC-SECRETWRITE-1 — EncKey mints the PBKDF2 salt sidecar only when there is
// no store it could strand. That mint is reached when the sidecar could not be
// read, which a DANGLING SYMLINK at "<dir>.salt" also produces, so the writer
// must not follow it: a salt written outside the store's directory can be
// deleted or replaced by whoever chose the target, after which no boot can
// re-derive the key and the encrypted history is unreadable for good.
// Verified failing against the pre-fix os.WriteFile shape.
func TestEncKey_SaltMintDoesNotFollowAPlantedSymlink(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "history") // never created: an empty store
	saltPath := dir + ".salt"
	outside := filepath.Join(t.TempDir(), "attacker-chosen")
	if err := os.Symlink(outside, saltPath); err != nil {
		t.Fatalf("plant symlink: %v", err)
	}
	if _, err := os.ReadFile(saltPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dangling symlink should read as ErrNotExist, got %v", err)
	}

	key, err := EncKey(dir, "correct horse battery staple")
	if err != nil {
		t.Fatalf("EncKey: %v", err)
	}
	if len(key) != encKeyLen {
		t.Fatalf("key length = %d, want %d", len(key), encKeyLen)
	}
	if _, err := os.Lstat(outside); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the salt escaped to the symlink target %s", outside)
	}
	fi, err := os.Lstat(saltPath)
	if err != nil {
		t.Fatalf("lstat salt: %v", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("salt path is still a symlink — the mint wrote through it")
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("salt mode = %v, want 0600", perm)
	}

	// The salt must be re-readable, or the whole point of persisting it is lost.
	again, err := EncKey(dir, "correct horse battery staple")
	if err != nil {
		t.Fatalf("EncKey second call: %v", err)
	}
	if !bytes.Equal(key, again) {
		t.Fatal("a second derivation produced a different key — the salt did not survive")
	}
}

// CONTROL: an empty passphrase still derives no key, and a store that HAS
// content still refuses to mint over its sidecar (the ErrSaltUnusable
// contract must not be weakened by this change).
func TestEncKey_ContractsUnchanged(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "history")
	if k, err := EncKey(dir, ""); err != nil || k != nil {
		t.Fatalf("empty passphrase: key=%v err=%v, want nil/nil", k, err)
	}

	// A store with content and an unusable sidecar must refuse, never mint.
	full := filepath.Join(t.TempDir(), "history")
	if err := os.MkdirAll(full, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(full, "MANIFEST"), []byte("x"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := os.WriteFile(full+".salt", []byte("short"), 0o600); err != nil {
		t.Fatalf("seed salt: %v", err)
	}
	if _, err := EncKey(full, "pass"); !errors.Is(err, ErrSaltUnusable) {
		t.Fatalf("EncKey on a populated store with a bad salt = %v, want ErrSaltUnusable", err)
	}
	// And the operator's recovery material is untouched.
	if b, _ := os.ReadFile(full + ".salt"); string(b) != "short" {
		t.Fatalf("the refused mint rewrote the sidecar: %q", b)
	}
}

// No temp artifact may survive beside the store.
func TestEncKey_SaltMintLeavesNoTempArtifact(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "history")
	if _, err := EncKey(dir, "pass"); err != nil {
		t.Fatalf("EncKey: %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "history.salt" {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("expected only history.salt, got %v", names)
	}
}
