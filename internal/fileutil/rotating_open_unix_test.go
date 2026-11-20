//go:build unix

package fileutil

// Hardened-open tests for RotatingFile (CWE-59/CWE-61): the audit and request
// logs must not follow a symlink planted at the log path, and must not block
// on a FIFO planted there.

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// openTimeout bounds how long a guarded open may take on a FIFO before the
// test declares it hung; the fixed open returns immediately.
const openTimeout = 5 * time.Second

// assertNoTarget fails if target exists: the open must not have created the
// file a symlink points at.
func assertNoTarget(t *testing.T, target string) {
	t.Helper()
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("symlink target %s exists after a refused open (Lstat err %v): the link was followed", target, err)
	}
}

func TestNewRotatingFile_RefusesSymlinkToMissingTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "elsewhere.log")
	path := filepath.Join(dir, "audit.log")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}

	rf, err := NewRotatingFile(path, 1)
	if err == nil {
		_, _ = rf.Write([]byte("redirected\n"))
		_ = rf.Close()
		t.Fatal("NewRotatingFile followed a symlink at the log path; want an error")
	}
	assertNoTarget(t, target)
}

func TestNewRotatingFile_RefusesSymlinkToExistingFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "victim")
	const original = "do-not-touch\n"
	if err := os.WriteFile(target, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "request.log")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}

	rf, err := NewRotatingFile(path, 1)
	if err == nil {
		_, _ = rf.Write([]byte("appended-through-link\n"))
		_ = rf.Close()
		t.Error("NewRotatingFile followed a symlink at the log path; want an error")
	}
	got, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != original {
		t.Fatalf("symlink target was written: %q, want %q", got, original)
	}
}

// TestRotatingFile_ReopenRefusesSymlinkPlantedAfterRotation covers the second
// open site: after a rotation renames the log away, a symlink swapped in at
// the path must be refused by the reopen in Write, and the archive kept.
func TestRotatingFile_ReopenRefusesSymlinkPlantedAfterRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	target := filepath.Join(t.TempDir(), "elsewhere.log")

	rf, err := NewRotatingFile(path, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer rf.Close() //nolint:errcheck // test cleanup
	if _, err := rf.Write([]byte("archived")); err != nil {
		t.Fatal(err)
	}

	// The state a rotation leaves behind (current renamed to .1, no handle),
	// then the attacker's link at the freed path.
	rf.mu.Lock()
	_ = rf.file.Close()
	rf.file = nil
	rf.size = 0
	if err := os.Rename(path, path+".1"); err != nil {
		rf.mu.Unlock()
		t.Fatal(err)
	}
	rf.mu.Unlock()
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}

	if _, err := rf.Write([]byte("redirected")); err == nil {
		t.Error("reopen after rotation followed a symlink at the log path; want an error")
	}
	assertNoTarget(t, target)
	if got, err := os.ReadFile(path + ".1"); err != nil || string(got) != "archived" {
		t.Fatalf("archive = %q, %v; want %q intact", got, err, "archived")
	}
}

type openResult struct {
	rf  *RotatingFile
	err error
}

// openWithTimeout runs NewRotatingFile(path) and reports whether it returned
// within openTimeout. On a hang it opens the FIFO for reading to release the
// blocked writer-side open, so the goroutine does not outlive the test.
func openWithTimeout(t *testing.T, path string) (openResult, bool) {
	t.Helper()
	done := make(chan openResult, 1)
	go func() {
		rf, err := NewRotatingFile(path, 1)
		done <- openResult{rf, err}
	}()
	select {
	case res := <-done:
		return res, true
	case <-time.After(openTimeout):
		r, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
		if err == nil {
			defer r.Close() //nolint:errcheck // test cleanup
		}
		res := <-done
		if res.rf != nil {
			_ = res.rf.Close()
		}
		return res, false
	}
}

func TestNewRotatingFile_FIFOWithoutReaderReturnsPromptly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}

	res, returned := openWithTimeout(t, path)
	if !returned {
		t.Fatalf("NewRotatingFile blocked for over %s on a FIFO at the log path", openTimeout)
	}
	if res.err == nil {
		_ = res.rf.Close()
		t.Fatal("NewRotatingFile accepted a FIFO at the log path; want an error")
	}
}

// TestNewRotatingFile_FIFOWithReaderRefused covers the FIFO an attacker holds
// open for reading: the non-blocking open then succeeds, so the fstat
// regular-file check is what must refuse it.
func TestNewRotatingFile_FIFOWithReaderRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "request.log")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	reader, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close() //nolint:errcheck // test cleanup

	res, returned := openWithTimeout(t, path)
	if !returned {
		t.Fatalf("NewRotatingFile blocked for over %s on a FIFO at the log path", openTimeout)
	}
	if res.err == nil {
		_ = res.rf.Close()
		t.Fatal("NewRotatingFile accepted a FIFO at the log path; want an error")
	}
	if !errors.Is(res.err, errNotRegular) {
		t.Fatalf("NewRotatingFile error = %v; want errNotRegular", res.err)
	}
}

// assertBlocking fails if f's descriptor still has O_NONBLOCK set.
func assertBlocking(t *testing.T, f *os.File) {
	t.Helper()
	rc, err := f.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var flags int
	var flagErr error
	if err := rc.Control(func(fd uintptr) { flags, flagErr = unix.FcntlInt(fd, unix.F_GETFL, 0) }); err != nil {
		t.Fatal(err)
	}
	if flagErr != nil {
		t.Fatal(flagErr)
	}
	if flags&unix.O_NONBLOCK != 0 {
		t.Fatal("log descriptor still has O_NONBLOCK set after the regular-file check")
	}
}

// TestRotatingFile_RegularFileOpenAndRotationStillWork pins that the guarded
// open leaves an ordinary path fully working: appends to an existing file,
// reports its size, rotates, and every descriptor (startup and reopen) is in
// blocking mode once verified.
func TestRotatingFile_RegularFileOpenAndRotationStillWork(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, []byte("prior\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	rf, err := NewRotatingFile(path, 1)
	if err != nil {
		t.Fatalf("NewRotatingFile on a regular file: %v", err)
	}
	defer rf.Close() //nolint:errcheck // test cleanup
	if rf.size != int64(len("prior\n")) {
		t.Fatalf("size = %d, want %d", rf.size, len("prior\n"))
	}
	assertBlocking(t, rf.file)

	if _, err := rf.Write([]byte("first\n")); err != nil {
		t.Fatal(err)
	}
	rf.mu.Lock()
	rf.maxBytes = int64(len("prior\nfirst\n")) // the next write rotates
	rf.mu.Unlock()
	if _, err := rf.Write([]byte("second\n")); err != nil {
		t.Fatalf("write across rotation: %v", err)
	}
	assertBlocking(t, rf.file)

	if got, err := os.ReadFile(path + ".1"); err != nil || string(got) != "prior\nfirst\n" {
		t.Fatalf("archive = %q, %v; want %q", got, err, "prior\nfirst\n")
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "second\n" {
		t.Fatalf("current = %q, %v; want %q", got, err, "second\n")
	}
	if fi, err := os.Lstat(path); err != nil || fi.Mode().Perm() != 0o600 || !fi.Mode().IsRegular() {
		t.Fatalf("reopened log = %v, %v; want a regular 0600 file", fi, err)
	}
}
