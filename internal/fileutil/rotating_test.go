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
