package fileutil

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicWrite_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.json")
	want := []byte(`{"k":"v"}`)
	if err := AtomicWrite(path, want, 0o600); err != nil {
		t.Fatalf("AtomicWrite: %v", err)
	}
	got, err := os.ReadFile(path) // #nosec G304 -- test-controlled temp path
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("content = %q, want %q", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("perm = %o, want 600", perm)
	}
}

func TestAtomicWrite_Overwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := AtomicWrite(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWrite(path, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path) // #nosec G304 -- test-controlled temp path
	if string(got) != "second" {
		t.Fatalf("after overwrite = %q, want %q", got, "second")
	}
}

func TestAtomicWrite_BadDirErrors(t *testing.T) {
	// A non-existent parent directory must surface an error (no temp file can be
	// created), never silently succeed.
	if err := AtomicWrite("/nonexistent-dir-xyz/f", []byte("x"), 0o600); err == nil {
		t.Fatal("AtomicWrite into a missing directory must return an error")
	}
}

// TestProbeAtomicWrite_LeavesTargetAndDirectoryUntouched pins that the probe
// has no effect on the live file: content, mode and mtime are unchanged, an
// absent target is not created, and no scratch file is left behind.
func TestProbeAtomicWrite_LeavesTargetAndDirectoryUntouched(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ui_users.json")
	if err := ProbeAtomicWrite(path); err != nil {
		t.Fatalf("probe of a writable dir: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("probe created the target (stat err %v)", err)
	}

	want := []byte(`{"users":[]}`)
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ProbeAtomicWrite(path); err != nil {
		t.Fatalf("probe beside an existing target: %v", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path) // #nosec G304 -- test-controlled temp path
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) || after.Mode() != before.Mode() || !after.ModTime().Equal(before.ModTime()) ||
		!os.SameFile(before, after) {
		t.Fatalf("probe altered the target: content %q mode %v→%v mtime %v→%v", got, before.Mode(), after.Mode(),
			before.ModTime(), after.ModTime())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "ui_users.json" {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("probe left scratch files: %q", names)
	}
}

// TestProbeAtomicWrite_RefusedDirectory: a missing directory always fails; a
// mode-0555 directory fails unless the runner bypasses mode bits (root or
// CAP_DAC_OVERRIDE), in which case that half is skipped — and when it does
// fail, AtomicWrite fails there too, so the probe agrees with the real write.
func TestProbeAtomicWrite_RefusedDirectory(t *testing.T) {
	if err := ProbeAtomicWrite(filepath.Join(t.TempDir(), "missing", "f.json")); err == nil {
		t.Error("probe in a missing directory succeeded")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "f.json")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o555); err != nil { // #nosec G302 -- deliberately read-only fixture dir
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) // #nosec G302 -- restore so TempDir cleanup can remove it
	probeErr := ProbeAtomicWrite(path)
	writeErr := AtomicWrite(path, []byte("y"), 0o600)
	if (probeErr == nil) != (writeErr == nil) {
		t.Fatalf("probe and AtomicWrite disagree: probe %v, write %v", probeErr, writeErr)
	}
	if probeErr == nil {
		t.Skip("runner bypasses directory mode bits (root or CAP_DAC_OVERRIDE); read-only half not reproducible")
	}
}
