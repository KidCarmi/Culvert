//go:build linux

package fileutil

import (
	"errors"
	"os"
	"runtime"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Gates for Codex P2 4317024211 on PR #1601: struct fsxattr (project ID,
// extent-size hints, xflags) and statx attributes are part of the compared
// metadata, so the "one more inode attribute" class is closed.

// isInode reports whether fd is the inode fi describes.
func isInode(fd int, fi os.FileInfo) bool {
	var st unix.Stat_t
	want, ok := fi.Sys().(*syscall.Stat_t)
	return ok && unix.Fstat(fd, &st) == nil && st.Ino == want.Ino && st.Dev == want.Dev
}

// injectFsxattr makes FS_IOC_FSGETXATTR report x (and err) for fi's inode
// while on() is true, and the real result otherwise.
func injectFsxattr(t *testing.T, fi os.FileInfo, on func() bool, x fsxattr, err error) {
	t.Helper()
	prev := fsGetxattr
	fsGetxattr = func(fd int) (fsxattr, error) {
		if on() && isInode(fd, fi) {
			return x, err
		}
		return prev(fd)
	}
	t.Cleanup(func() { fsGetxattr = prev })
}

// injectStatx makes statx report attrs (and err) for fi's inode while on()
// is true.
func injectStatx(t *testing.T, fi os.FileInfo, on func() bool, attrs uint64, err error) {
	t.Helper()
	prev := statxAttributes
	statxAttributes = func(fd int) (uint64, error) {
		if on() && isInode(fd, fi) {
			return attrs, err
		}
		return prev(fd)
	}
	t.Cleanup(func() { statxAttributes = prev })
}

func always() bool { return true }

// realFsxattr is the fixture's real struct fsxattr, or a zero one where the
// filesystem does not support the ioctl.
func realFsxattr(t *testing.T, path string) fsxattr {
	t.Helper()
	f, err := os.Open(path) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	x, err := fsGetxattr(int(f.Fd()))
	if err != nil && !errors.Is(err, unix.ENOTTY) && !errors.Is(err, unix.ENOTSUP) {
		t.Fatalf("FS_IOC_FSGETXATTR: %v", err)
	}
	return x
}

// TestFsIocFsgetxattr_Number pins the derived ioctl number against the
// kernel's _IOR('X', 31, struct fsxattr) on the common architectures.
func TestFsIocFsgetxattr_Number(t *testing.T) {
	want := map[string]uint{"amd64": 0x801c581f, "arm64": 0x801c581f, "386": 0x801c581f, "arm": 0x801c581f,
		"riscv64": 0x801c581f, "loong64": 0x801c581f, "s390x": 0x801c581f, "ppc64le": 0x401c581f, "mips64le": 0x401c581f}
	if unsafe.Sizeof(fsxattr{}) != 28 {
		t.Fatalf("struct fsxattr is %d bytes, want 28", unsafe.Sizeof(fsxattr{}))
	}
	if w, ok := want[runtime.GOARCH]; ok && fsIocFsgetxattr != w {
		t.Errorf("FS_IOC_FSGETXATTR = %#x on %s, want %#x", fsIocFsgetxattr, runtime.GOARCH, w)
	}
}

// TestRewriteInPlace_InodeAttributeDifferencesAreRefused: a project quota ID,
// an extent-size hint or a compared xflag the replacement would not carry,
// or a statx attribute it would not have, means nothing is exchanged.
// Dropping the fsxattr or the statx comparison fails this test.
func TestRewriteInPlace_InodeAttributeDifferencesAreRefused(t *testing.T) {
	const fsXflagNodefrag = 0x00002000
	cases := []struct {
		name   string
		inject func(t *testing.T, path string, fi os.FileInfo)
	}{
		{"project ID", func(t *testing.T, path string, fi os.FileInfo) {
			x := realFsxattr(t, path)
			x.Projid = 4242
			injectFsxattr(t, fi, always, x, nil)
		}},
		{"extent-size hint", func(t *testing.T, path string, fi os.FileInfo) {
			x := realFsxattr(t, path)
			x.Extsize = 1 << 20
			injectFsxattr(t, fi, always, x, nil)
		}},
		{"nodefrag xflag", func(t *testing.T, path string, fi os.FileInfo) {
			x := realFsxattr(t, path)
			x.Xflags |= fsXflagNodefrag
			injectFsxattr(t, fi, always, x, nil)
		}},
		{"fsxattr ioctl failure", func(t *testing.T, _ string, fi os.FileInfo) {
			injectFsxattr(t, fi, always, fsxattr{}, syscall.EIO)
		}},
		{"statx compressed", func(t *testing.T, _ string, fi os.FileInfo) {
			injectStatx(t, fi, always, unix.STATX_ATTR_COMPRESSED, nil)
		}},
		{"statx verity", func(t *testing.T, _ string, fi os.FileInfo) {
			injectStatx(t, fi, always, unix.STATX_ATTR_VERITY, nil)
		}},
		{"statx dax", func(t *testing.T, _ string, fi os.FileInfo) {
			injectStatx(t, fi, always, unix.STATX_ATTR_DAX, nil)
		}},
		{"statx failure", func(t *testing.T, _ string, fi os.FileInfo) {
			injectStatx(t, fi, always, 0, syscall.EIO)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			loaded := []byte(`{"users":[]}`)
			path, fi := rewriteFixture(t, loaded)
			tc.inject(t, path, fi)
			exchanges := countExchanges(t)

			err := RewriteInPlace(path, loaded, fi)
			if !errors.Is(err, ErrMetadataNotPreservable) || errors.Is(err, ErrConcurrentChange) {
				t.Fatalf("err = %v, want ErrMetadataNotPreservable", err)
			}
			if n := exchanges.Load(); n != 0 {
				t.Errorf("%d exchange(s) ran although the inode attributes would change", n)
			}
			assertUntouched(t, path, fi, loaded)
		})
	}
}

// TestRewriteInPlace_RealProjectIDIsRefused sets a real project ID with
// FS_IOC_FSSETXATTR where the filesystem supports project quotas (XFS, or
// ext4 with the project feature); elsewhere it skips, and the injected
// "project ID" case above covers the logic.
func TestRewriteInPlace_RealProjectIDIsRefused(t *testing.T) {
	loaded := []byte(`{"users":[]}`)
	path, _ := rewriteFixture(t, loaded)
	f, err := os.Open(path) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	x, err := fsGetxattr(int(f.Fd()))
	if err == nil {
		x.Projid = 4242
		setReq := uint(unix.FS_IOC_SETFLAGS)&0xE0000000 | uint(unsafe.Sizeof(fsxattr{}))<<16 | 'X'<<8 | 32
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), uintptr(setReq), uintptr(unsafe.Pointer(&x))) // #nosec G103 -- FS_IOC_FSSETXATTR argument, as the kernel ABI requires
		if errno != 0 {
			err = errno
		}
	}
	_ = f.Close()
	if err != nil {
		t.Skipf("the test filesystem cannot hold a project ID (%v)", err)
	}
	fi := statT(t, path)
	exchanges := countExchanges(t)
	if err := RewriteInPlace(path, loaded, fi); !errors.Is(err, ErrMetadataNotPreservable) {
		t.Fatalf("err = %v, want ErrMetadataNotPreservable", err)
	}
	if n := exchanges.Load(); n != 0 {
		t.Errorf("%d exchange(s) ran on a roster with a project ID", n)
	}
	assertUntouched(t, path, fi, loaded)
}

// TestRewriteInPlace_StatxImmutableIsAWriteRefusal: an immutable roster that
// only statx reports as such (inode flags unsupported) is the same plain
// EPERM write refusal as chattr +i.
func TestRewriteInPlace_StatxImmutableIsAWriteRefusal(t *testing.T) {
	loaded := []byte(`{"users":[]}`)
	path, fi := rewriteFixture(t, loaded)
	injectInodeFlags(t, fi, 0, syscall.ENOTTY)
	injectStatx(t, fi, always, unix.STATX_ATTR_IMMUTABLE, nil)
	exchanges := countExchanges(t)

	err := RewriteInPlace(path, loaded, fi)
	if !errors.Is(err, ErrReplacementBlocked) || !errors.Is(err, syscall.EPERM) || errors.Is(err, ErrMetadataNotPreservable) {
		t.Fatalf("err = %v, want a plain EPERM write refusal", err)
	}
	if n := exchanges.Load(); n != 0 {
		t.Errorf("%d exchange(s) ran on an immutable roster", n)
	}
	assertUntouched(t, path, fi, loaded)
}

// TestRewriteInPlace_UnsupportedInodeAttributesAreNone: FS_IOC_FSGETXATTR
// unsupported (ENOTTY, ENOTSUP) and a kernel without statx (ENOSYS) mean the
// filesystem keeps no such metadata, so the rewrite lands. Treating them as
// errors fails this test.
func TestRewriteInPlace_UnsupportedInodeAttributesAreNone(t *testing.T) {
	cases := []struct {
		name string
		set  func()
	}{
		{"fsxattr ENOTTY", func() { fsGetxattr = func(int) (fsxattr, error) { return fsxattr{}, syscall.ENOTTY } }},
		{"fsxattr ENOTSUP", func() { fsGetxattr = func(int) (fsxattr, error) { return fsxattr{}, syscall.ENOTSUP } }},
		{"statx ENOSYS", func() { statxAttributes = func(int) (uint64, error) { return 0, syscall.ENOSYS } }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prevFsx, prevStatx := fsGetxattr, statxAttributes
			t.Cleanup(func() { fsGetxattr, statxAttributes = prevFsx, prevStatx })
			tc.set()
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

// TestRewriteInPlace_ConcurrentInodeAttributeChangeIsSwappedBack: a project
// ID or statx attribute that changes on the target just before the exchange
// makes the displaced file differ, so the exchange is undone.
func TestRewriteInPlace_ConcurrentInodeAttributeChangeIsSwappedBack(t *testing.T) {
	for _, name := range []string{"project ID", "statx nodump"} {
		t.Run(name, func(t *testing.T) {
			loaded := []byte(`{"users":[]}`)
			path, fi := rewriteFixture(t, loaded)
			var changed bool
			on := func() bool { return changed }
			if name == "project ID" {
				x := realFsxattr(t, path)
				x.Projid = 4242
				injectFsxattr(t, fi, on, x, nil)
			} else {
				injectStatx(t, fi, on, unix.STATX_ATTR_NODUMP, nil)
			}
			setRewriteHooks(t, func(string) { changed = true }, nil)

			if err := RewriteInPlace(path, loaded, fi); !errors.Is(err, ErrConcurrentChange) {
				t.Fatalf("err = %v, want ErrConcurrentChange", err)
			}
			if !os.SameFile(fi, statT(t, path)) {
				t.Error("the changed original was not swapped back")
			}
			assertOnlyTarget(t, path)
		})
	}
}

// TestRewriteInPlace_VerityOrDAXRosterIsRefused: an fs-verity or DAX roster
// is refused outright, even where a fresh temp file would report the same
// attribute (DAX inherited from the directory), so the read-back alone would
// pass. Dropping the precheck fails this test.
func TestRewriteInPlace_VerityOrDAXRosterIsRefused(t *testing.T) {
	for name, attr := range map[string]uint64{"verity": unix.STATX_ATTR_VERITY, "dax": unix.STATX_ATTR_DAX} {
		t.Run(name, func(t *testing.T) {
			prev := statxAttributes
			statxAttributes = func(int) (uint64, error) { return attr, nil } // every file, the temp included
			t.Cleanup(func() { statxAttributes = prev })
			loaded := []byte(`{"users":[]}`)
			path, fi := rewriteFixture(t, loaded)
			exchanges := countExchanges(t)

			if err := RewriteInPlace(path, loaded, fi); !errors.Is(err, ErrMetadataNotPreservable) {
				t.Fatalf("err = %v, want ErrMetadataNotPreservable", err)
			}
			if n := exchanges.Load(); n != 0 {
				t.Errorf("%d exchange(s) ran on a verity or DAX roster", n)
			}
			assertUntouched(t, path, fi, loaded)
		})
	}
}
