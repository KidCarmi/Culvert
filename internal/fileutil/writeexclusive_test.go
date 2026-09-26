package fileutil

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// legacyWriteFile is the VERBATIM pre-fix shape every secret writer used
// before SEC-SECRETWRITE-1 (os.WriteFile with a 0600 perm argument). It is
// kept here as the differential ORACLE so each defect gate below can be shown
// to fail against the code it replaces rather than merely passing against the
// code it protects.
func legacyWriteFile(path string, data []byte, perm os.FileMode) error {
	return os.WriteFile(path, data, perm)
}

const secret = "0123456789abcdef0123456789abcdef"

// ── DEFECT GATE 1: a planted symlink must not redirect the write ────────────
//
// The dangling case is the dangerous one for a KEY file, because the read that
// precedes every mint (os.ReadFile) reports fs.ErrNotExist for a dangling
// link — which is exactly the condition a mint treats as "no key yet".
func TestWriteFileExclusive_DanglingSymlinkDoesNotRedirectTheWrite(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "attacker-chosen")
	path := filepath.Join(dir, ".secret_key")
	if err := os.Symlink(outside, path); err != nil {
		t.Fatalf("plant symlink: %v", err)
	}

	// Precondition the mint path depends on: the read looks like "absent".
	if _, err := os.ReadFile(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dangling symlink should read as ErrNotExist, got %v", err)
	}

	if err := WriteFileExclusive(path, []byte(secret), 0o600); err != nil {
		t.Fatalf("WriteFileExclusive: %v", err)
	}
	if _, err := os.Lstat(outside); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("secret escaped to the symlink target %s", outside)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != secret {
		t.Fatalf("secret did not land at the intended path: %q err=%v", got, err)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("path is still a symlink after the write")
	}
}

func TestWriteFileExclusive_ExistingTargetSymlinkDoesNotRedirectTheWrite(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "attacker-owned")
	if err := os.WriteFile(outside, []byte("placeholder"), 0o666); err != nil { //nolint:gosec // G306: deliberately world-readable — the planted file this test defends against
		t.Fatalf("seed: %v", err)
	}
	path := filepath.Join(dir, ".secret_key")
	if err := os.Symlink(outside, path); err != nil {
		t.Fatalf("plant symlink: %v", err)
	}
	if err := WriteFileExclusive(path, []byte(secret), 0o600); err != nil {
		t.Fatalf("WriteFileExclusive: %v", err)
	}
	if b, _ := os.ReadFile(outside); string(b) != "placeholder" {
		t.Fatalf("secret was written through the symlink: %q", b)
	}
}

// LEGACY CONTROL: the same two shapes against the pre-fix writer. This is what
// makes the two gates above defect gates rather than assertions about nothing.
func TestWriteFileExclusive_LegacyWriterFollowsSymlinks(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "attacker-chosen")
	path := filepath.Join(dir, ".secret_key")
	if err := os.Symlink(outside, path); err != nil {
		t.Fatalf("plant symlink: %v", err)
	}
	if err := legacyWriteFile(path, []byte(secret), 0o600); err != nil {
		t.Fatalf("legacy write: %v", err)
	}
	b, err := os.ReadFile(outside)
	if err != nil || string(b) != secret {
		t.Fatalf("expected the legacy writer to follow the link and leak; got %q err=%v", b, err)
	}
}

// ── DEFECT GATE 2: a pre-existing file's mode must not be inherited ──────────
//
// os.WriteFile's perm argument applies only on CREATION, so a wide-mode file
// planted at a predictable path receives the secret and stays readable.
func TestWriteFileExclusive_DoesNotInheritAPreExistingMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.key.tmp")
	if err := os.WriteFile(path, []byte("planted"), 0o666); err != nil { //nolint:gosec // G306: deliberately world-readable — the planted file this test defends against
		t.Fatalf("seed: %v", err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if err := WriteFileExclusive(path, []byte(secret), 0o600); err != nil {
		t.Fatalf("WriteFileExclusive: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode inherited from the planted file: got %v want 0600", perm)
	}
}

func TestWriteFileExclusive_LegacyWriterInheritsAPreExistingMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.key.tmp")
	if err := os.WriteFile(path, []byte("planted"), 0o666); err != nil { //nolint:gosec // G306: deliberately world-readable — the planted file this test defends against
		t.Fatalf("seed: %v", err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if err := legacyWriteFile(path, []byte(secret), 0o600); err != nil {
		t.Fatalf("legacy write: %v", err)
	}
	fi, _ := os.Stat(path)
	if perm := fi.Mode().Perm(); perm != 0o666 {
		t.Fatalf("expected the legacy writer to keep 0666; got %v", perm)
	}
}

// ── CONTROL: the rendezvous semantics callers depend on are preserved ────────
//
// The cheapest way to pass every gate above is to refuse whenever anything is
// already at the path — which would wedge the CDR renewal permanently the
// first time a crash left a stale "<bundle>.tmp" behind. A stale REGULAR file
// must still be superseded, exactly as a truncating write superseded it.
func TestWriteFileExclusive_SupersedesAStaleRendezvousFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.key.tmp")
	if err := os.WriteFile(path, []byte("stale-from-an-interrupted-renewal"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := WriteFileExclusive(path, []byte(secret), 0o600); err != nil {
		t.Fatalf("WriteFileExclusive over a stale file: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != secret {
		t.Fatalf("stale content survived: %q", got)
	}
}

func TestWriteFileExclusive_CreatesAtTheRequestedModeAndContent(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name string
		data []byte
		perm os.FileMode
	}{
		{"empty", nil, 0o600},
		{"secret", []byte(secret), 0o600},
		{"nul-and-newline", []byte("a\x00b\nc"), 0o600},
		{"tighter", []byte("x"), 0o400},
		{"large", []byte(strings.Repeat("k", 1<<16)), 0o600},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name)
			if err := WriteFileExclusive(path, tc.data, tc.perm); err != nil {
				t.Fatalf("write: %v", err)
			}
			fi, err := os.Stat(path)
			if err != nil {
				t.Fatalf("stat: %v", err)
			}
			if fi.Mode().Perm() != tc.perm {
				t.Fatalf("perm = %v want %v", fi.Mode().Perm(), tc.perm)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if !bytes.Equal(got, tc.data) {
				t.Fatalf("content mismatch (%d vs %d bytes)", len(got), len(tc.data))
			}
		})
	}
}

// ── BOUNDARY: a path that cannot be created fails closed, leaving nothing ────
func TestWriteFileExclusive_FailsClosedOnAnUncreatablePath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "missing-parent", "key")
	err := WriteFileExclusive(path, []byte(secret), 0o600)
	if err == nil {
		t.Fatal("expected an error for a missing parent directory")
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("error should name the path: %v", err)
	}
	if _, serr := os.Stat(path); !errors.Is(serr, os.ErrNotExist) {
		t.Fatalf("a failed write must leave nothing behind: %v", serr)
	}
}

// A NON-EMPTY directory at the path cannot be cleared, so the write fails
// closed rather than landing somewhere else. (An EMPTY directory is a stale
// artifact and is superseded like a stale file — os.Remove takes it. That is a
// deliberate widening over os.WriteFile, which answered EISDIR; nothing
// security-relevant distinguishes an empty directory at a key path from no
// entry at all, and self-healing is the better default for a rendezvous.)
func TestWriteFileExclusive_FailsClosedOnANonEmptyDirectoryAtThePath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	if err := os.MkdirAll(filepath.Join(path, "child"), 0o700); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := WriteFileExclusive(path, []byte(secret), 0o600); err == nil {
		t.Fatal("expected a refusal when a non-empty directory occupies the path")
	}
	if fi, serr := os.Stat(path); serr != nil || !fi.IsDir() {
		t.Fatalf("the failed write disturbed the directory: %v", serr)
	}

	empty := filepath.Join(dir, "empty-key")
	if err := os.Mkdir(empty, 0o700); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := WriteFileExclusive(empty, []byte(secret), 0o600); err != nil {
		t.Fatalf("an empty directory should be superseded: %v", err)
	}
	if got, _ := os.ReadFile(empty); string(got) != secret {
		t.Fatalf("content = %q", got)
	}
}

// ── CONCURRENCY: exactly one writer wins; no torn or mixed content ───────────
func TestWriteFileExclusive_ConcurrentWritersNeverProduceTornContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	payloads := []string{strings.Repeat("A", 4096), strings.Repeat("B", 4096), strings.Repeat("C", 4096)}

	var wg sync.WaitGroup
	for round := 0; round < 40; round++ {
		for _, p := range payloads {
			wg.Add(1)
			go func(p string) {
				defer wg.Done()
				_ = WriteFileExclusive(path, []byte(p), 0o600) // a loser may legitimately fail
			}(p)
		}
	}
	wg.Wait()

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	for _, p := range payloads {
		if string(got) == p {
			return
		}
	}
	t.Fatalf("file holds neither payload intact — torn write of %d bytes", len(got))
}

// Codex review (PR #1467): the file's fsync does not make its directory entry
// durable, so the rendezvous name could vanish after a power loss. The write
// must sync the PARENT directory before reporting success, and a failure of
// that sync must fail the write closed with nothing left at the path.
func TestWriteFileExclusive_SyncsTheParentDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.key.tmp")
	orig := exclusiveSyncDir
	t.Cleanup(func() { exclusiveSyncDir = orig })

	var synced []string
	exclusiveSyncDir = func(d string) error { synced = append(synced, d); return orig(d) }
	if err := WriteFileExclusive(path, []byte("k"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if len(synced) != 1 || synced[0] != dir {
		t.Fatalf("parent dir fsync calls = %v, want exactly [%s]", synced, dir)
	}

	boom := errors.New("dir fsync failed")
	exclusiveSyncDir = func(string) error { return boom }
	if err := WriteFileExclusive(path, []byte("k2"), 0o600); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped dir-fsync failure", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("a write whose directory entry is not durable must leave nothing at the path (lstat err=%v)", err)
	}
}

// A failed write must leave the path empty DURABLY: after removing the file
// the parent directory is synced again, and a cleanup that cannot be made
// durable is reported rather than hidden behind the original error.
func TestWriteFileExclusive_FailedWriteCleanupIsDurable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.key.tmp")
	orig := exclusiveSyncDir
	t.Cleanup(func() { exclusiveSyncDir = orig })

	boom := errors.New("dir fsync failed")
	calls := 0
	exclusiveSyncDir = func(string) error {
		calls++
		if calls == 1 {
			return boom
		}
		return nil
	}
	err := WriteFileExclusive(path, []byte("k"), 0o600)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the dir-fsync failure", err)
	}
	if calls != 2 {
		t.Fatalf("parent dir fsync calls = %d, want 2 (the write, then the cleanup's unlink)", calls)
	}
	if _, lerr := os.Lstat(path); !os.IsNotExist(lerr) {
		t.Fatalf("cleanup left an entry at the path (lstat err=%v)", lerr)
	}

	cleanupBoom := errors.New("cleanup fsync failed")
	exclusiveSyncDir = func(string) error { return cleanupBoom }
	err = WriteFileExclusive(path, []byte("k"), 0o600)
	if !errors.Is(err, cleanupBoom) || !strings.Contains(err.Error(), "cleanup") {
		t.Fatalf("err = %v, want the non-durable cleanup reported", err)
	}
}
