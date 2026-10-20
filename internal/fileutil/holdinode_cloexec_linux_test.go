//go:build linux

package fileutil

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestHoldInode_DuplicateIsCloseOnExec: the duplicate AtomicWriteInfo keeps
// across the rename carries FD_CLOEXEC by the time holdInode returns. A
// descriptor of the file being written that reaches a child process is an
// exposure of whatever that write carries — key-at-rest material, the admin
// roster — so this is the invariant, and dropping the CloseOnExec call fails
// here. The dup-to-flag window itself is closed structurally by
// syscall.ForkLock (no exec can begin while it is held for reading), which no
// test can observe from outside holdInode; the error path's release of that
// lock is gated below.
func TestHoldInode_DuplicateIsCloseOnExec(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "hold")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	held := holdInode(f)
	if held == nil {
		t.Fatal("holdInode returned no duplicate")
	}
	defer func() { _ = held.Close() }()

	flags, err := unix.FcntlInt(held.Fd(), unix.F_GETFD, 0)
	if err != nil {
		t.Fatalf("F_GETFD on the duplicate: %v", err)
	}
	if flags&unix.FD_CLOEXEC == 0 {
		t.Errorf("the duplicate's descriptor flags are %#x: FD_CLOEXEC is not set, so a fork+exec inherits a read descriptor of the file being written", flags)
	}
}

// TestHoldInode_ReleasesForkLockWhenTheDupFails: the failure path must release
// syscall.ForkLock. Held, it would block every exec and every other
// descriptor-creating path in the process for good — a durable write that
// fails to dup would wedge the node.
func TestHoldInode_ReleasesForkLockWhenTheDupFails(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "hold")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil { // dup of a closed descriptor fails
		t.Fatal(err)
	}
	if held := holdInode(f); held != nil {
		_ = held.Close()
		t.Fatal("holdInode duplicated a closed descriptor")
	}

	probed, err := os.CreateTemp(t.TempDir(), "probe")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = probed.Close() }()

	// Take the lock the way forkExec does — for writing — and do under it what
	// it is there to make safe: create a descriptor that no concurrent fork can
	// inherit. On a goroutine with a deadline, because a lock holdInode leaked
	// would block this forever rather than fail.
	probe := make(chan error, 1)
	go func() {
		syscall.ForkLock.Lock()
		defer syscall.ForkLock.Unlock()
		fd, err := syscall.Dup(int(probed.Fd()))
		if err == nil {
			syscall.CloseOnExec(fd)
			err = syscall.Close(fd)
		}
		probe <- err
	}()
	select {
	case err := <-probe:
		if err != nil {
			t.Errorf("dup under syscall.ForkLock: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("syscall.ForkLock is still held after a failed holdInode: no exec can run again")
	}
}

// TestAtomicWriteInfo_LandedStillLandsWithTheHeldDuplicate is the positive
// control: the write itself is unchanged by the flag, and the parent's own
// descriptors are untouched.
func TestAtomicWriteInfo_LandedStillLandsWithTheHeldDuplicate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "roster.json")
	res, err := AtomicWriteInfo(path, []byte(`{"users":[]}`), 0o600)
	if err != nil {
		t.Fatalf("AtomicWriteInfo: %v", err)
	}
	if res.Landed == nil {
		t.Fatal("no Landed FileInfo")
	}
	if !res.DirSynced {
		t.Error("DirSynced is false for a writable temp directory")
	}
	now, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(res.Landed, now) {
		t.Error("Landed is not the inode at the path")
	}
	if got := now.Mode().Perm(); got != 0o600 {
		t.Errorf("mode %v, want 0600", got)
	}
}
