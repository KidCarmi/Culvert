package fileutil

// writefail_test.go — CHAOS-45 durable-write failure observer.
//
// The observer exists because a dozen AtomicWrite call sites discard the
// returned error, so a data directory that goes read-only or full after boot
// loses persisted state in silence. These tests pin the properties package
// main's observer relies on: it fires on every failure branch, it never fires
// on success, it carries the target path (not the temp name), and it never
// changes what AtomicWrite returns.

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// withObserver installs fn for the duration of the test and clears it after,
// so an observer can never leak into a sibling test.
func withObserver(t *testing.T, fn func(path string, err error)) {
	t.Helper()
	SetWriteFailureObserver(fn)
	t.Cleanup(func() { SetWriteFailureObserver(nil) })
}

func TestWriteFailureObserver_FiresOnFailureWithTargetPath(t *testing.T) {
	var (
		mu     sync.Mutex
		paths  []string
		errStr []string
	)
	withObserver(t, func(path string, err error) {
		mu.Lock()
		defer mu.Unlock()
		paths = append(paths, path)
		errStr = append(errStr, err.Error())
	})

	// A target inside a directory that does not exist: CreateTemp fails with
	// ENOENT. Chosen over a chmod-0500 directory because root bypasses mode
	// bits, and CI containers run as root — this failure is deterministic for
	// every uid.
	target := filepath.Join(t.TempDir(), "missing-subdir", "state.json")
	err := AtomicWrite(target, []byte("{}"), 0o600)
	if err == nil {
		t.Fatal("AtomicWrite succeeded into a missing directory; wanted a failure to observe")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(paths) != 1 {
		t.Fatalf("observer fired %d times, want exactly 1", len(paths))
	}
	if paths[0] != target {
		t.Errorf("observed path = %q, want the TARGET path %q (not the temp file)", paths[0], target)
	}
	if errStr[0] != err.Error() {
		t.Errorf("observed error = %q, want the same error AtomicWrite returned (%q)", errStr[0], err.Error())
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("returned error lost its cause: %v", err)
	}
}

func TestWriteFailureObserver_SilentOnSuccess(t *testing.T) {
	fired := false
	withObserver(t, func(string, error) { fired = true })

	target := filepath.Join(t.TempDir(), "state.json")
	if err := AtomicWrite(target, []byte("{}"), 0o600); err != nil {
		t.Fatalf("AtomicWrite: %v", err)
	}
	if fired {
		t.Error("observer fired on a SUCCESSFUL write — every durable write would look like a failure")
	}
	// The write must still have landed: the observer seam must not alter behaviour.
	if b, err := os.ReadFile(target); err != nil || string(b) != "{}" {
		t.Errorf("content = %q, err = %v; want {} written", string(b), err)
	}
}

func TestWriteFailureObserver_NilIsSafe(t *testing.T) {
	// No observer installed (the production default until main's init runs,
	// and the state every other package sees).
	SetWriteFailureObserver(nil)
	target := filepath.Join(t.TempDir(), "missing-subdir", "state.json")
	if err := AtomicWrite(target, []byte("{}"), 0o600); err == nil {
		t.Fatal("want an error writing into a missing directory")
	}
	// Reaching here without panicking is the assertion.

	// A replaced observer takes over; the previous one must not also fire.
	var first, second int
	SetWriteFailureObserver(func(string, error) { first++ })
	withObserver(t, func(string, error) { second++ })
	_ = AtomicWrite(target, []byte("{}"), 0o600)
	if first != 0 {
		t.Errorf("replaced observer fired %d times, want 0", first)
	}
	if second != 1 {
		t.Errorf("current observer fired %d times, want 1", second)
	}
}
