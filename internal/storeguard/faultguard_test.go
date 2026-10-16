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

// ── fault marker: the contained fault survives the restart ───────────────────

// A recorded fault quarantines the store BEFORE the opener runs, and the marker
// is consumed so the following start is a plain open.
func TestOpen_RecordedFaultQuarantinesBeforeOpening(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	seedDir(t, dir)
	if err := RecordFault(dir, "test fault"); err != nil {
		t.Fatalf("RecordFault: %v", err)
	}
	if !faultRecorded(dir) {
		t.Fatal("marker not visible after RecordFault")
	}
	if tmps := siblings(dir, FaultMarkerTempSuffix); len(tmps) != 0 {
		t.Fatalf("atomic write left temp files: %v", tmps)
	}

	o := &opener{}
	st, rec, err := Open(dir, Policy{}, o.open)
	if err != nil || st == nil {
		t.Fatalf("Open = (%v, %v)", st, err)
	}
	if rec.Trigger != TriggerRuntimeFault || !rec.Quarantined || rec.QuarantinePath == "" {
		t.Fatalf("recovery = %+v, want a runtime-fault quarantine", rec)
	}
	if o.calls != 1 {
		t.Errorf("open calls = %d, want 1", o.calls)
	}
	if faultRecorded(dir) {
		t.Error("the acted-on fault marker was not cleared; every start would quarantine again")
	}

	_, rec, err = Open(dir, Policy{}, o.open)
	if err != nil || rec.Trigger != TriggerNone || rec.Quarantined {
		t.Fatalf("second Open = (%+v, %v), want a plain open", rec, err)
	}
}

// Negative control: a LIVE holder of the store lock vetoes the quarantine, and
// the marker must survive so the next start can still act on it.
func TestOpen_RecordedFaultRespectsALiveLockHolder(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	seedDir(t, dir)
	if err := RecordFault(dir, "test fault"); err != nil {
		t.Fatalf("RecordFault: %v", err)
	}
	held, err := LockStore(dir)
	if err != nil || held == nil {
		t.Fatalf("LockStore = (%v, %v)", held, err)
	}
	defer held.Release()

	_, rec, _ := Open(dir, Policy{}, (&opener{}).open)
	if rec.Quarantined {
		t.Fatalf("quarantined a store another process holds: %+v", rec)
	}
	if rec.Trigger != TriggerRuntimeFault || rec.Skipped == "" {
		t.Fatalf("recovery = %+v, want a triggered-but-skipped runtime fault", rec)
	}
	if _, serr := os.Stat(dir); serr != nil {
		t.Fatalf("store moved despite the live lock: %v", serr)
	}
	if !faultRecorded(dir) {
		t.Error("an unresolved fault marker was cleared")
	}
}

// A store an operator already removed has nothing to quarantine: the marker is
// resolved and cleared rather than reported as a phantom recovery forever.
func TestOpen_RecordedFaultForAMissingStoreIsCleared(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	if err := RecordFault(dir, "test fault"); err != nil {
		t.Fatalf("RecordFault: %v", err)
	}
	_, rec, err := Open(dir, Policy{}, (&opener{}).open)
	if err != nil || rec.Trigger != TriggerNone || rec.Quarantined {
		t.Fatalf("Open = (%+v, %v), want a plain open", rec, err)
	}
	if faultRecorded(dir) {
		t.Error("marker for an absent store was not cleared")
	}
}

// Only a regular file is a signal. A directory at the marker path could never
// be cleared, so honouring it would quarantine a healthy store on every start.
func TestOpen_DirectoryAtFaultMarkerPathIsIgnored(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	seedDir(t, dir)
	if err := os.MkdirAll(dir+FaultMarkerSuffix, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	_, rec, err := Open(dir, Policy{}, (&opener{}).open)
	if err != nil || rec.Trigger != TriggerNone || rec.Quarantined {
		t.Fatalf("Open = (%+v, %v), want a plain open", rec, err)
	}
}
