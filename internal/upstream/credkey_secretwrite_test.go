package upstream

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// SEC-SECRETWRITE-1 — the node-local credential KEK unwraps every sealed
// parent-proxy password on this appliance. OpenKey's mint branch is reached
// whenever the read answered fs.ErrNotExist, and a DANGLING SYMLINK planted at
// the key path produces exactly that answer, so the writer must never follow
// it. Verified failing against the pre-fix os.WriteFile shape.
func TestOpenKey_MintDoesNotFollowAPlantedSymlink(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "attacker-chosen")
	path := filepath.Join(dir, KeyFileName)
	if err := os.Symlink(outside, path); err != nil {
		t.Fatalf("plant symlink: %v", err)
	}

	// The precondition the attack relies on: a dangling link reads as absent,
	// so OpenKey takes the mint branch rather than the load branch.
	if _, err := os.ReadFile(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dangling symlink should read as ErrNotExist, got %v", err)
	}

	kr, err := OpenKey(dir, true)
	if err != nil {
		t.Fatalf("OpenKey mint: %v", err)
	}
	if kr == nil || kr.KeyID() == "" {
		t.Fatal("mint returned no keyring")
	}
	if _, err := os.Lstat(outside); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the credential KEK escaped the data directory to %s", outside)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat key path: %v", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("key path is still a symlink — the KEK was written through it")
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("KEK mode = %v, want 0600", perm)
	}
}

// The mint must also survive a wide-mode file planted at the path: os.WriteFile
// would keep that mode and publish the KEK.
func TestOpenKey_MintDoesNotInheritAPlantedMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, KeyFileName)
	// A 31-byte file is not a usable key, so OpenKey refuses it rather than
	// minting — that refusal is itself the fail-closed contract.
	// Seed at 0600 (gosec G306), then widen explicitly: WriteFile's mode is
	// umask-filtered anyway, so the Chmod is what actually plants 0666.
	if err := os.WriteFile(path, make([]byte, 31), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, err := OpenKey(dir, true); err == nil {
		t.Fatal("expected OpenKey to refuse a wrong-length key file rather than overwrite it")
	}
}

// CONTROL: the ordinary path is unchanged — a fresh directory mints once, the
// key round-trips, and a second OpenKey loads the SAME key rather than minting
// a second generation (which would strand every credential sealed under the
// first).
func TestOpenKey_MintThenLoadIsStable(t *testing.T) {
	dir := t.TempDir()
	first, err := OpenKey(dir, true)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	second, err := OpenKey(dir, false)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if first.KeyID() != second.KeyID() {
		t.Fatalf("key id changed across load: %s != %s", first.KeyID(), second.KeyID())
	}
	raw, err := os.ReadFile(filepath.Join(dir, KeyFileName))
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if len(raw) != 32 {
		t.Fatalf("key length = %d, want 32", len(raw))
	}
	// A read against an empty directory must still be ErrKeyMissing, never a
	// silent mint.
	if _, err := OpenKey(t.TempDir(), false); !errors.Is(err, ErrKeyMissing) {
		t.Fatalf("read path on an empty dir = %v, want ErrKeyMissing", err)
	}
}

// No temp file may survive the mint: a leftover would itself be a predictable
// path holding key material.
func TestOpenKey_MintLeavesNoTempArtifact(t *testing.T) {
	dir := t.TempDir()
	if _, err := OpenKey(dir, true); err != nil {
		t.Fatalf("mint: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != KeyFileName {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("expected only %s in the data dir, got %v", KeyFileName, names)
	}
}
