//go:build linux

package storeguard

import (
	"errors"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"testing"
)

// mapTruncatedFile returns a mapping whose backing file has been truncated to
// zero, so touching it raises SIGBUS. This is the kernel behavior that makes a
// badger `.sst` on a failing volume able to kill the process: the mapping stays
// valid, the pages behind it stop existing.
func mapTruncatedFile(t *testing.T) (mapping []byte, storeDir string) {
	t.Helper()
	storeDir = t.TempDir()
	path := filepath.Join(storeDir, "mapped")
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
	return m, storeDir
}

// TestContainFault_MemoryFaultBecomesError is the core CHAOS-74 gate. Without
// ContainFault this read is `fatal error: fault` and the test binary dies, so
// this test passing at all is the containment working.
func TestContainFault_MemoryFaultBecomesError(t *testing.T) {
	m, dir := mapTruncatedFile(t)
	var sink byte
	err := ContainFault(dir, func() error {
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
		_ = ContainFault(t.TempDir(), func() error {
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
	if err := ContainFault(t.TempDir(), func() error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("op error not returned verbatim: %v", err)
	}
	if IsStoreFault(sentinel) {
		t.Fatal("an ordinary error must not classify as a store fault")
	}
	if err := ContainFault(t.TempDir(), func() error { return nil }); err != nil {
		t.Fatalf("clean op returned %v", err)
	}
}

// TestContainFault_RestoresPanicOnFault keeps the helper from leaking
// per-goroutine state into a caller that has its own setting.
func TestContainFault_RestoresPanicOnFault(t *testing.T) {
	for _, want := range []bool{false, true} {
		prev := debug.SetPanicOnFault(want)
		_ = ContainFault(t.TempDir(), func() error { return nil })
		got := debug.SetPanicOnFault(prev)
		if got != want {
			t.Fatalf("SetPanicOnFault(%v) not restored: got %v", want, got)
		}
	}
}

// rePanicValue runs fn and returns what it panicked with (nil if it returned).
func rePanicValue(fn func()) (got any) {
	defer func() { got = recover() }()
	fn()
	return nil
}

// A real mapping fault whose address is NOT inside a mapping under the given
// store directory must propagate. This is the stand-in for a wild non-nil
// pointer dereference: it carries Addr() exactly like a store fault, and only
// the address-to-mapping check tells them apart.
func TestContainFault_FaultOutsideTheStoreIsRePanicked(t *testing.T) {
	m, _ := mapTruncatedFile(t)
	otherStore := t.TempDir()
	var sink byte
	got := rePanicValue(func() {
		_ = ContainFault(otherStore, func() error {
			sink = m[0]
			return nil
		})
	})
	_ = sink
	if got == nil {
		t.Fatal("a fault outside the store's mappings was swallowed; it must keep propagating")
	}
	if _, isAddr := got.(interface{ Addr() uintptr }); !isAddr {
		t.Fatalf("re-panicked value lost its fault address: %v", got)
	}
}

// Fail closed: when the memory map cannot be read, the fault's origin cannot be
// established, so even a genuine in-store fault re-panics.
func TestContainFault_UnreadableMapsRePanics(t *testing.T) {
	m, dir := mapTruncatedFile(t)
	unreadable := func() ([]byte, error) { return nil, errors.New("maps unavailable") }
	var sink byte
	got := rePanicValue(func() {
		_ = containFault(dir, unreadable, func() error {
			sink = m[0]
			return nil
		})
	})
	_ = sink
	if got == nil {
		t.Fatal("a fault was contained without evidence it came from the store")
	}
}

// The kernel reports resolved paths, so a store opened through a symlink must
// still match its own mapping.
func TestContainFault_StoreReachedThroughASymlinkIsContained(t *testing.T) {
	m, dir := mapTruncatedFile(t)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	var sink byte
	err := ContainFault(link, func() error {
		sink = m[0]
		return nil
	})
	_ = sink
	if !IsStoreFault(err) {
		t.Fatalf("fault on a symlinked store was not contained: %v", err)
	}
}

func TestParseMapsLine(t *testing.T) {
	cases := []struct {
		line   string
		ok     bool
		lo, hi uint64
		path   string
	}{
		{"7f00a000-7f00b000 r--s 00000000 08:01 1234    /data/cat feed/000001.sst", true, 0x7f00a000, 0x7f00b000, "/data/cat feed/000001.sst"},
		{"7f00a000-7f00b000 r--s 00000000 08:01 1234 /data/cat/000001.sst (deleted)", true, 0x7f00a000, 0x7f00b000, "/data/cat/000001.sst"},
		{"7f00a000-7f00b000 rw-p 00000000 00:00 0 ", false, 0, 0, ""},
		{"7ffd0000-7ffd1000 rw-p 00000000 00:00 0                          [stack]", false, 0, 0, ""},
		{"garbage", false, 0, 0, ""},
		{"zz-7f00b000 r--s 00000000 08:01 1234 /x", false, 0, 0, ""},
		{"7f00b000-7f00a000 r--s 00000000 08:01 1234 /x", false, 0, 0, ""},
	}
	for _, c := range cases {
		lo, hi, path, ok := parseMapsLine(c.line)
		if ok != c.ok || lo != c.lo || hi != c.hi || path != c.path {
			t.Errorf("parseMapsLine(%q) = (%x, %x, %q, %v), want (%x, %x, %q, %v)", c.line, lo, hi, path, ok, c.lo, c.hi, c.path, c.ok)
		}
	}
}

// faultAt carries Addr() like the runtime's converted-fault error, so the
// address-to-mapping decision can be driven with an injected memory map.
type faultAt uintptr

func (f faultAt) Error() string { return "synthetic fault" }
func (f faultAt) Addr() uintptr { return uintptr(f) }

// The positive case through the seam: an address inside an injected mapping of
// a file under the store directory is contained.
func TestContainFault_InStoreAddressFromInjectedMapsIsContained(t *testing.T) {
	if !FaultContainmentSupported {
		t.Fatal("FaultContainmentSupported must be true on Linux")
	}
	dir := t.TempDir()
	maps := func() ([]byte, error) {
		return []byte("1000-2000 r--s 00000000 08:01 1 " + filepath.Join(dir, "000001.sst") + "\n"), nil
	}
	err := containFault(dir, maps, func() error { panic(faultAt(0x1800)) })
	if !IsStoreFault(err) {
		t.Fatalf("in-store fault not contained: %v", err)
	}
	got := rePanicValue(func() {
		_ = containFault(dir, maps, func() error { panic(faultAt(0x3000)) })
	})
	if _, ok := got.(faultAt); !ok {
		t.Fatalf("out-of-range fault: re-panicked with %T (%v), want the original value", got, got)
	}
}

// A sibling store whose name extends this one's must not count as "under" it.
func TestAddrInStoreMapping_RequiresAPathBoundary(t *testing.T) {
	maps := func() ([]byte, error) {
		return []byte("1000-2000 r--s 00000000 08:01 1 /data/catfeeddb-old/000001.sst\n"), nil
	}
	if addrInStoreMapping(0x1800, "/data/catfeeddb", maps) {
		t.Fatal("matched a neighbouring directory that merely shares a prefix")
	}
	if !addrInStoreMapping(0x1800, "/data/catfeeddb-old", maps) {
		t.Fatal("did not match the store's own mapping")
	}
	if addrInStoreMapping(0x2000, "/data/catfeeddb-old", maps) {
		t.Fatal("end of range is exclusive")
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

// failMarkerRemoval is a remover that refuses to unlink the fault marker and
// behaves like os.Remove for everything else.
func failMarkerRemoval(path string) error {
	if strings.HasSuffix(path, FaultMarkerSuffix) {
		return &os.PathError{Op: "remove", Path: path, Err: syscall.EACCES}
	}
	return os.Remove(path)
}

// If the marker cannot be cleared after a successful quarantine, recovery is
// NOT complete: opening a replacement would leave a marker that quarantines the
// healthy replacement on the next start, and the one-copy prune would then
// delete the original evidence. The store must stay unopened and the error must
// reach the caller.
func TestOpen_FaultMarkerThatCannotBeClearedStopsRecovery(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	seedDir(t, dir)
	if err := RecordFault(dir, "test fault"); err != nil {
		t.Fatalf("RecordFault: %v", err)
	}
	o := &opener{}
	st, rec, err := openWith(dir, Policy{}, o.open, failMarkerRemoval)
	if err == nil || st != nil {
		t.Fatalf("openWith = (%v, %+v, %v), want an error and no store", st, rec, err)
	}
	if !errors.Is(err, syscall.EACCES) {
		t.Errorf("removal cause not wrapped: %v", err)
	}
	if o.calls != 0 {
		t.Errorf("opener ran %d time(s); no replacement may be created while the marker remains", o.calls)
	}
	if !rec.Quarantined || rec.Trigger != TriggerRuntimeFault {
		t.Errorf("recovery = %+v, want the quarantine reported", rec)
	}
	if !faultRecorded(dir) {
		t.Fatal("test precondition: marker should still be present")
	}
	evidence := rec.QuarantinePath

	// Next start, the remover works again: the store is already gone, so the
	// marker is cleared, a fresh store opens, and the evidence is untouched.
	o2 := &opener{}
	st, rec, err = Open(dir, Policy{}, o2.open)
	if err != nil || st == nil || rec.Quarantined {
		t.Fatalf("follow-up Open = (%v, %+v, %v), want a plain open", st, rec, err)
	}
	if faultRecorded(dir) {
		t.Error("marker survived a working remover")
	}
	if _, serr := os.Stat(evidence); serr != nil {
		t.Errorf("original evidence lost: %v", serr)
	}
}

// Same rule when the store is already gone: a marker that cannot be cleared
// must not be followed by creating a replacement.
func TestOpen_FaultMarkerForAMissingStoreThatCannotBeClearedStopsRecovery(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	if err := RecordFault(dir, "test fault"); err != nil {
		t.Fatalf("RecordFault: %v", err)
	}
	o := &opener{}
	st, _, err := openWith(dir, Policy{}, o.open, failMarkerRemoval)
	if err == nil || st != nil || o.calls != 0 {
		t.Fatalf("openWith = (%v, %v) after %d open(s), want an error and no open", st, err, o.calls)
	}
}
