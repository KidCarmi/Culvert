package fileutil

// Rotating-writer tests, moved in-package from package main's
// logger_ca_clam_test.go with the RotatingFile move (ADR-0002, store.go
// decomposition Phase B).

import (
	"os"
	"testing"
)

func TestNewRotatingFile_CreatesFile(t *testing.T) {
	f, err := os.CreateTemp("", "rottest*.log")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	defer os.Remove(f.Name())        //nolint:errcheck // test cleanup
	defer os.Remove(f.Name() + ".1") //nolint:errcheck // test cleanup

	rf, err := NewRotatingFile(f.Name(), 1)
	if err != nil {
		t.Fatalf("NewRotatingFile: %v", err)
	}
	defer rf.Close() //nolint:errcheck // test cleanup

	n, err := rf.Write([]byte("hello\n"))
	if err != nil {
		t.Errorf("Write error: %v", err)
	}
	if n != 6 {
		t.Errorf("Write returned %d, want 6", n)
	}
}

func TestRotatingFile_Rotate(t *testing.T) {
	f, err := os.CreateTemp("", "rottest*.log")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	path := f.Name()
	defer os.Remove(path)        //nolint:errcheck // test cleanup
	defer os.Remove(path + ".1") //nolint:errcheck // test cleanup

	// maxMB=0 defaults to 50MB, set maxBytes tiny by creating with a raw struct
	rf := &RotatingFile{
		path:     path,
		maxBytes: 10, // force rotation after 10 bytes
		size:     0,
	}
	rf.file, err = os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer rf.Close() //nolint:errcheck // test cleanup

	// Write more than 10 bytes to trigger rotation
	_, err = rf.Write([]byte("this is more than 10 bytes of data"))
	if err != nil {
		t.Errorf("Write after rotation error: %v", err)
	}
}

func TestRotatingFile_DefaultMaxMB(t *testing.T) {
	f, err := os.CreateTemp("", "rottest_default*.log")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	defer os.Remove(f.Name()) //nolint:errcheck // test cleanup

	// 0 and negative both fall back to the 50 MB default. A negative maxMB
	// (e.g. a stray -log-max-mb -1) used to yield a negative maxBytes, making
	// the Write-time rotation check always fire and rotate on every write.
	for _, maxMB := range []int{0, -1, -50} {
		rf, err := NewRotatingFile(f.Name(), maxMB)
		if err != nil {
			t.Fatalf("NewRotatingFile with maxMB=%d: %v", maxMB, err)
		}
		if rf.maxBytes != 50*1024*1024 {
			t.Errorf("maxMB=%d: maxBytes = %d, want %d (default)", maxMB, rf.maxBytes, 50*1024*1024)
		}
		rf.Close() //nolint:errcheck // test cleanup
	}
}

func TestRotatingFile_RotationArchivesCurrentContent(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/app.log"

	rf, err := NewRotatingFile(path, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer rf.Close() //nolint:errcheck // test cleanup
	rf.maxBytes = 10

	if _, err := rf.Write([]byte("0123456789")); err != nil { // exactly at cap, no rotation
		t.Fatal(err)
	}
	if _, err := rf.Write([]byte("X")); err != nil { // pushes over cap → rotates first
		t.Fatal(err)
	}

	archived, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatalf("read archive: %v", err)
	}
	if string(archived) != "0123456789" {
		t.Errorf("archive = %q, want %q", archived, "0123456789")
	}
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read current: %v", err)
	}
	if string(current) != "X" {
		t.Errorf("current = %q, want %q", current, "X")
	}
}

// TestRotatingFile_ReopenFailureDoesNotDestroyArchive pins the disk-full
// recovery contract: when rotation renames the log to .1 but the reopen of a
// fresh current file fails (e.g. ENOSPC), subsequent writes must RETRY THE
// REOPEN ONLY — re-entering the rotation branch would os.Remove the
// just-rotated .1 archive, destroying the only surviving copy of the data
// (the pre-fix behavior: audit/request logs lost on a transient disk-full).
func TestRotatingFile_ReopenFailureDoesNotDestroyArchive(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/app.log"

	rf, err := NewRotatingFile(path, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer rf.Close() //nolint:errcheck // test cleanup

	if _, err := rf.Write([]byte("precious-archive-data")); err != nil {
		t.Fatal(err)
	}

	// Reproduce the exact state Write leaves behind when the post-rotation
	// reopen fails: current renamed to .1, no open handle. Then make the
	// reopen ITSELF fail deterministically by occupying the log path with a
	// directory (EISDIR — works regardless of euid, unlike permission traps).
	rf.mu.Lock()
	rf.file.Close() //nolint:errcheck // test setup
	rf.file = nil
	rf.size = 0
	if err := os.Rename(path, path+".1"); err != nil {
		rf.mu.Unlock()
		t.Fatal(err)
	}
	rf.mu.Unlock()
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}

	// Two failed writes: the second one is the pre-fix kill shot (it used to
	// re-rotate and delete the .1 archive).
	for i := 0; i < 2; i++ {
		if _, err := rf.Write([]byte("more")); err == nil {
			t.Fatalf("write %d: expected reopen error while path is a directory", i)
		}
		archived, err := os.ReadFile(path + ".1")
		if err != nil {
			t.Fatalf("write %d destroyed the archive: %v", i, err)
		}
		if string(archived) != "precious-archive-data" {
			t.Fatalf("write %d corrupted the archive: %q", i, archived)
		}
	}

	// Disk "recovers": the path frees up, the next write reopens and succeeds,
	// and the archive is still intact.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := rf.Write([]byte("recovered")); err != nil {
		t.Fatalf("write after recovery: %v", err)
	}
	archived, err := os.ReadFile(path + ".1")
	if err != nil || string(archived) != "precious-archive-data" {
		t.Fatalf("archive after recovery = %q, %v; want intact", archived, err)
	}
	current, err := os.ReadFile(path)
	if err != nil || string(current) != "recovered" {
		t.Fatalf("current after recovery = %q, %v; want %q", current, err, "recovered")
	}
}
