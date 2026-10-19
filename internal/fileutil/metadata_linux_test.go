//go:build linux

package fileutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// Gates for RewriteInPlace's single metadata step (Codex P2s 4316645541 and
// 4316645546 on PR #1601, the third round of metadata findings): the full
// 12-bit mode, the fsync after the last metadata change, and inode flags.

const fsNodumpFL = 0x00000040

func rawMode(t *testing.T, path string) uint32 {
	t.Helper()
	st, ok := statT(t, path).Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("no Stat_t")
	}
	return st.Mode & 0o7777
}

// modeFixture is rewriteFixture at the raw mode (special bits included).
func modeFixture(t *testing.T, loaded []byte, mode uint32) (path string, fi os.FileInfo) {
	t.Helper()
	path, _ = rewriteFixture(t, loaded)
	if err := unix.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	if got := rawMode(t, path); got != mode {
		t.Skipf("the test filesystem or privileges keep mode %04o as %04o", mode, got)
	}
	return path, statT(t, path)
}

// TestRewriteInPlace_PreservesSpecialModeBits: setgid, sticky and setuid
// survive (4316645541). Chmodding with only the permission bits, or before
// the chown (which clears setuid and setgid), fails this test.
func TestRewriteInPlace_PreservesSpecialModeBits(t *testing.T) {
	for _, mode := range []uint32{0o2750, 0o1640, 0o4750, 0o6750} {
		t.Run(fmt.Sprintf("%04o", mode), func(t *testing.T) {
			loaded := []byte(`{"users":[]}`)
			path, before := modeFixture(t, loaded, mode)
			if err := RewriteInPlace(path, loaded, before); err != nil {
				t.Fatalf("RewriteInPlace: %v", err)
			}
			if os.SameFile(before, statT(t, path)) {
				t.Fatal("same inode: the exchange did not happen")
			}
			if got := rawMode(t, path); got != mode {
				t.Errorf("mode %04o after the rewrite, want %04o", got, mode)
			}
			assertOnlyTarget(t, path)
		})
	}
}

// TestRewriteInPlace_DroppedSpecialBitIsRefused: the kernel silently drops
// setgid when an unprivileged process chmods a file whose group it is not in;
// that is injected here (the tests run as root). The read-back catches it and
// nothing is exchanged. Dropping the mode from the read-back fails this test.
func TestRewriteInPlace_DroppedSpecialBitIsRefused(t *testing.T) {
	loaded := []byte(`{"users":[]}`)
	path, fi := modeFixture(t, loaded, 0o2750)
	prev := fchmod
	fchmod = func(fd int, mode uint32) error { return prev(fd, mode&^unix.S_ISGID) }
	t.Cleanup(func() { fchmod = prev })
	exchanges := countExchanges(t)

	err := RewriteInPlace(path, loaded, fi)
	if !errors.Is(err, ErrMetadataNotPreservable) || errors.Is(err, ErrConcurrentChange) {
		t.Fatalf("err = %v, want ErrMetadataNotPreservable", err)
	}
	if n := exchanges.Load(); n != 0 {
		t.Errorf("%d exchange(s) ran although setgid was lost", n)
	}
	assertUntouched(t, path, fi, loaded)
	if got := rawMode(t, path); got != 0o2750 {
		t.Errorf("target mode %04o, want 02750", got)
	}
}

// TestRewriteInPlace_ConcurrentSpecialBitChangeIsSwappedBack: a chmod g+s on
// the target just before the exchange is a concurrent change: the displaced
// file is compared on all 12 mode bits.
func TestRewriteInPlace_ConcurrentSpecialBitChangeIsSwappedBack(t *testing.T) {
	loaded := []byte(`{"users":[]}`)
	path, fi := rewriteFixture(t, loaded)
	setRewriteHooks(t, func(string) {
		if err := unix.Chmod(path, 0o2640); err != nil {
			t.Error(err)
		}
	}, nil)
	if err := RewriteInPlace(path, loaded, fi); !errors.Is(err, ErrConcurrentChange) {
		t.Fatalf("err = %v, want ErrConcurrentChange", err)
	}
	if !os.SameFile(fi, statT(t, path)) || rawMode(t, path) != 0o2640 {
		t.Errorf("the chmodded original was not swapped back (mode %04o)", rawMode(t, path))
	}
	assertOnlyTarget(t, path)
}

// TestRewriteInPlace_FsyncsMetadataBeforeExchange (4316645546): with no
// extended attributes, the chown and chmod are still fsynced, after the last
// metadata step and before the exchange. Restoring the "only if an attribute
// changed" shortcut, or reordering chown and chmod, fails this test.
func TestRewriteInPlace_FsyncsMetadataBeforeExchange(t *testing.T) {
	loaded := []byte(`{"users":[]}`)
	path, fi := rewriteFixture(t, loaded)
	if len(lxattrsT(t, path)) != 0 {
		t.Fatalf("precondition: the fixture has extended attributes %q", lxattrsT(t, path))
	}
	var mu sync.Mutex
	var events []string
	record := func(e string) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	}
	prevChown, prevChmod, prevSet, prevSync := fchown, fchmod, fsetxattr, fsyncFile
	fchown = func(f *os.File, uid, gid int) error { record("chown"); return prevChown(f, uid, gid) }
	fchmod = func(fd int, mode uint32) error { record("chmod"); return prevChmod(fd, mode) }
	fsetxattr = func(fd int, n string, v []byte) error { record("setxattr"); return prevSet(fd, n, v) }
	fsyncFile = func(f *os.File) error { record("fsync"); return prevSync(f) }
	t.Cleanup(func() { fchown, fchmod, fsetxattr, fsyncFile = prevChown, prevChmod, prevSet, prevSync })
	kernelExchange := renameExchange
	setRenameExchange(t, func(a, b string) error { record("exchange"); return kernelExchange(a, b) })

	if err := RewriteInPlace(path, loaded, fi); err != nil {
		t.Fatalf("RewriteInPlace: %v", err)
	}
	if want := []string{"chown", "chmod", "fsync", "exchange"}; !reflect.DeepEqual(events, want) {
		t.Errorf("metadata steps = %q, want %q", events, want)
	}
}

// setInodeFlagsOrSkip ORs flags into path's inode flags with the real ioctl,
// skipping where the filesystem or privileges do not allow it, and clears
// them again on cleanup (an immutable file cannot be removed).
func setInodeFlagsOrSkip(t *testing.T, path string, flags uint32) {
	t.Helper()
	f, err := os.Open(path) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	cur, err := unix.IoctlGetUint32(int(f.Fd()), unix.FS_IOC_GETFLAGS)
	if err == nil {
		err = unix.IoctlSetPointerInt(int(f.Fd()), unix.FS_IOC_SETFLAGS, int(cur|flags))
	}
	if err != nil {
		t.Skipf("cannot set inode flags %#x on the test filesystem (%v); the injected-flag cases cover the logic", flags, err)
	}
	t.Cleanup(func() {
		g, err := os.Open(path) // #nosec G304 -- test temp path
		if err != nil {
			return
		}
		defer func() { _ = g.Close() }()
		_ = unix.IoctlSetPointerInt(int(g.Fd()), unix.FS_IOC_SETFLAGS, int(cur))
	})
}

// injectInodeFlags makes the flags ioctl report flags (and err) for the
// inode of fi only, and the real flags for every other file.
func injectInodeFlags(t *testing.T, fi os.FileInfo, flags uint32, err error) {
	t.Helper()
	prev := inodeFlags
	inodeFlags = func(fd int) (uint32, error) {
		var st unix.Stat_t
		if unix.Fstat(fd, &st) == nil {
			if want, ok := fi.Sys().(*syscall.Stat_t); ok && st.Ino == want.Ino && st.Dev == want.Dev {
				return flags, err
			}
		}
		return prev(fd)
	}
	t.Cleanup(func() { inodeFlags = prev })
}

// TestRewriteInPlace_InodeFlagsAreNeverChanged: RewriteInPlace does not set
// inode flags, so a roster carrying one a fresh file lacks (nodump, which
// backup tools honour), a temp that inherits one from its directory, or a
// flags ioctl that fails, means nothing is exchanged. Dropping the flags from
// the read-back fails this test.
func TestRewriteInPlace_InodeFlagsAreNeverChanged(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, path string, fi os.FileInfo)
	}{
		{"nodump on the roster", func(t *testing.T, path string, _ os.FileInfo) {
			setInodeFlagsOrSkip(t, path, fsNodumpFL)
		}},
		{"nodump inherited by the temp from the directory", func(t *testing.T, path string, _ os.FileInfo) {
			setInodeFlagsOrSkip(t, filepath.Dir(path), fsNodumpFL)
		}},
		{"injected nodump on the roster", func(t *testing.T, _ string, fi os.FileInfo) {
			injectInodeFlags(t, fi, fsNodumpFL, nil)
		}},
		{"injected flags ioctl failure", func(t *testing.T, _ string, fi os.FileInfo) {
			injectInodeFlags(t, fi, 0, syscall.EIO)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			loaded := []byte(`{"users":[]}`)
			path, fi := rewriteFixture(t, loaded)
			tc.setup(t, path, fi)
			fi = statT(t, path)
			exchanges := countExchanges(t)

			err := RewriteInPlace(path, loaded, fi)
			if !errors.Is(err, ErrMetadataNotPreservable) || errors.Is(err, ErrConcurrentChange) {
				t.Fatalf("err = %v, want ErrMetadataNotPreservable", err)
			}
			if n := exchanges.Load(); n != 0 {
				t.Errorf("%d exchange(s) ran although the inode flags would change", n)
			}
			assertUntouched(t, path, fi, loaded)
		})
	}
}

// TestRewriteInPlace_ImmutableTargetIsAWriteRefusal: an immutable or
// append-only roster (chattr +i/+a) is never exchanged. rename(2) would
// refuse a save over it with EPERM, so this is reported as a plain EPERM
// write refusal, not as unpreservable metadata. Dropping the precheck fails
// this test (the read-back would then report unpreservable flags instead).
func TestRewriteInPlace_ImmutableTargetIsAWriteRefusal(t *testing.T) {
	cases := []struct {
		name   string
		flags  uint32
		inject bool
	}{
		{"immutable", fsImmutableFL, false},
		{"append-only", fsAppendFL, false},
		{"injected immutable", fsImmutableFL, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			loaded := []byte(`{"users":[]}`)
			path, fi := rewriteFixture(t, loaded)
			if tc.inject {
				injectInodeFlags(t, fi, tc.flags, nil)
			} else {
				setInodeFlagsOrSkip(t, path, tc.flags)
			}
			fi = statT(t, path)
			exchanges := countExchanges(t)

			err := RewriteInPlace(path, loaded, fi)
			if !errors.Is(err, ErrReplacementBlocked) || !errors.Is(err, syscall.EPERM) ||
				errors.Is(err, ErrMetadataNotPreservable) || errors.Is(err, ErrConcurrentChange) {
				t.Fatalf("err = %v, want a plain EPERM write refusal", err)
			}
			if n := exchanges.Load(); n != 0 {
				t.Errorf("%d exchange(s) ran on an immutable or append-only roster", n)
			}
			assertUntouched(t, path, fi, loaded)
		})
	}
}

// TestRewriteInPlace_NoInodeFlagSupportIsNoFlags: where the flags ioctl is
// unsupported (ENOTTY, ENOTSUP), the file has no flags to lose and the
// rewrite lands.
func TestRewriteInPlace_NoInodeFlagSupportIsNoFlags(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.ENOTTY, syscall.ENOTSUP} {
		t.Run(errno.Error(), func(t *testing.T) {
			prev := inodeFlags
			inodeFlags = func(int) (uint32, error) { return 0, errno }
			t.Cleanup(func() { inodeFlags = prev })
			loaded := []byte(`{"users":[]}`)
			path, fi := rewriteFixture(t, loaded)
			if err := RewriteInPlace(path, loaded, fi); err != nil {
				t.Fatalf("RewriteInPlace: %v", err)
			}
			if os.SameFile(fi, statT(t, path)) {
				t.Error("same inode: the exchange did not happen")
			}
			assertOnlyTarget(t, path)
		})
	}
}

// TestRewriteInPlace_ConcurrentInodeFlagChangeIsSwappedBack: a chattr +d on
// the target just before the exchange makes the displaced file differ.
func TestRewriteInPlace_ConcurrentInodeFlagChangeIsSwappedBack(t *testing.T) {
	loaded := []byte(`{"users":[]}`)
	path, fi := rewriteFixture(t, loaded)
	var flagged bool
	prev := inodeFlags
	inodeFlags = func(fd int) (uint32, error) {
		fl, err := prev(fd)
		var st unix.Stat_t
		if want, ok := fi.Sys().(*syscall.Stat_t); flagged && ok && unix.Fstat(fd, &st) == nil && st.Ino == want.Ino {
			fl |= fsNodumpFL
		}
		return fl, err
	}
	t.Cleanup(func() { inodeFlags = prev })
	setRewriteHooks(t, func(string) { flagged = true }, nil)

	if err := RewriteInPlace(path, loaded, fi); !errors.Is(err, ErrConcurrentChange) {
		t.Fatalf("err = %v, want ErrConcurrentChange", err)
	}
	if !os.SameFile(fi, statT(t, path)) {
		t.Error("the flagged original was not swapped back")
	}
	assertOnlyTarget(t, path)
}
