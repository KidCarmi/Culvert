//go:build unix

package storeguard

import (
	"errors"
	"os"
	"path/filepath"
	"runtime/debug"
	"syscall"
	"testing"
)

// mapTruncatedFile returns a mapping whose backing file has been truncated to
// zero, so touching it raises SIGBUS. This is the kernel behavior that makes a
// badger `.sst` on a failing volume able to kill the process: the mapping stays
// valid, the pages behind it stop existing.
func mapTruncatedFile(t *testing.T) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mapped")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer func() { _ = f.Close() }()
	page := os.Getpagesize()
	if err := f.Truncate(int64(page)); err != nil {
		t.Fatalf("grow: %v", err)
	}
	m, err := syscall.Mmap(int(f.Fd()), 0, page, syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		t.Fatalf("mmap: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Munmap(m) })
	// The backing store goes away underneath the live mapping.
	if err := f.Truncate(0); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return m
}

// TestContainFault_MemoryFaultBecomesError is the core CHAOS-74 gate. Without
// ContainFault this read is `fatal error: fault` and the test binary dies, so
// this test passing at all is the containment working.
func TestContainFault_MemoryFaultBecomesError(t *testing.T) {
	m := mapTruncatedFile(t)
	var sink byte
	err := ContainFault(func() error {
		sink = m[0]
		return nil
	})
	_ = sink
	if err == nil {
		t.Fatal("reading a truncated mapping returned no error; the fault was not contained or not raised")
	}
	if !IsStoreFault(err) {
		t.Fatalf("fault was not classified as a store fault: %v", err)
	}
	if !errors.Is(err, ErrStoreFault) {
		t.Fatalf("errors.Is(err, ErrStoreFault) is false: %v", err)
	}
	// The whole point: the process is still here.
	t.Logf("contained: %v", err)
}

// TestContainFault_NilDerefIsNotAStoreFault is the negative control that keeps
// the fix from reclassifying bugs as disk damage. A nil dereference carries the
// SAME message text as a contained mapping fault, so only the Addr() method
// tells them apart; if that discrimination ever breaks, this test fails rather
// than a real panic being silently reported as a failing volume.
func TestContainFault_NilDerefIsNotAStoreFault(t *testing.T) {
	var got any
	func() {
		defer func() { got = recover() }()
		_ = ContainFault(func() error {
			var p *int
			_ = *p
			return nil
		})
	}()
	if got == nil {
		t.Fatal("a nil dereference inside op was swallowed; it must keep propagating to crashguard")
	}
	if _, isAddr := got.(interface{ Addr() uintptr }); isAddr {
		t.Fatalf("a nil dereference reported a fault address, so the discriminator is unsound: %v", got)
	}
	t.Logf("re-panicked as expected: %v", got)
}

func TestContainFault_PassesErrorsAndSuccessThrough(t *testing.T) {
	sentinel := errors.New("badger said no")
	if err := ContainFault(func() error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("op error not returned verbatim: %v", err)
	}
	if IsStoreFault(sentinel) {
		t.Fatal("an ordinary error must not classify as a store fault")
	}
	if err := ContainFault(func() error { return nil }); err != nil {
		t.Fatalf("clean op returned %v", err)
	}
}

// TestContainFault_RestoresPanicOnFault keeps the helper from leaking
// per-goroutine state into a caller that has its own setting.
func TestContainFault_RestoresPanicOnFault(t *testing.T) {
	for _, want := range []bool{false, true} {
		prev := debug.SetPanicOnFault(want)
		_ = ContainFault(func() error { return nil })
		got := debug.SetPanicOnFault(prev)
		if got != want {
			t.Fatalf("SetPanicOnFault(%v) not restored: got %v", want, got)
		}
	}
}
