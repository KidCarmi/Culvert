//go:build linux

package fileutil

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// Gates for ReplacementBlocked, the read-only "can any save replace this
// file" check the admin_roster_durability probe uses (Codex P2 4319694761 on
// PR #1601).

func replacementFixture(t *testing.T) (path string, fi os.FileInfo) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "ui_users.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, fi
}

func sameInode(fd int, fi os.FileInfo) bool {
	var st unix.Stat_t
	want, ok := fi.Sys().(*syscall.Stat_t)
	return ok && unix.Fstat(fd, &st) == nil && st.Ino == want.Ino && st.Dev == want.Dev
}

func injectFlags(t *testing.T, fi os.FileInfo, flags uint32, err error) {
	t.Helper()
	prev := inodeFlags
	inodeFlags = func(fd int) (uint32, error) {
		if sameInode(fd, fi) {
			return flags, err
		}
		return prev(fd)
	}
	t.Cleanup(func() { inodeFlags = prev })
}

func injectAttrs(t *testing.T, fi os.FileInfo, attrs uint64, err error) {
	t.Helper()
	prev := statxAttributes
	statxAttributes = func(fd int) (uint64, error) {
		if sameInode(fd, fi) {
			return attrs, err
		}
		return prev(fd)
	}
	t.Cleanup(func() { statxAttributes = prev })
}

func injectDirAttrs(t *testing.T, attrs uint64) {
	t.Helper()
	prev := dirStatxAttributes
	dirStatxAttributes = func(string) (uint64, error) { return attrs, nil }
	t.Cleanup(func() { dirStatxAttributes = prev })
}

// TestReplacementBlocked_Cases: every input the predicate decides on, and
// the ones it must not. Dropping any of the three checks fails a case.
func TestReplacementBlocked_Cases(t *testing.T) {
	cases := []struct {
		name    string
		inject  func(t *testing.T, fi os.FileInfo)
		blocked bool
		errno   syscall.Errno
	}{
		{"nothing", func(*testing.T, os.FileInfo) {}, false, 0},
		{"nodump only", func(t *testing.T, fi os.FileInfo) { injectFlags(t, fi, 0x40, nil) }, false, 0},
		{"immutable flag", func(t *testing.T, fi os.FileInfo) { injectFlags(t, fi, fsImmutableFL, nil) }, true, syscall.EPERM},
		{"append-only flag", func(t *testing.T, fi os.FileInfo) { injectFlags(t, fi, fsAppendFL, nil) }, true, syscall.EPERM},
		{"statx immutable", func(t *testing.T, fi os.FileInfo) { injectAttrs(t, fi, unix.STATX_ATTR_IMMUTABLE, nil) }, true, syscall.EPERM},
		{"statx append-only", func(t *testing.T, fi os.FileInfo) { injectAttrs(t, fi, unix.STATX_ATTR_APPEND, nil) }, true, syscall.EPERM},
		{"mount point", func(t *testing.T, fi os.FileInfo) { injectAttrs(t, fi, unix.STATX_ATTR_MOUNT_ROOT, nil) }, true, syscall.EBUSY},
		{"append-only directory", func(t *testing.T, _ os.FileInfo) { injectDirAttrs(t, unix.STATX_ATTR_APPEND) }, true, syscall.EPERM},
		{"immutable directory", func(t *testing.T, _ os.FileInfo) { injectDirAttrs(t, unix.STATX_ATTR_IMMUTABLE) }, true, syscall.EPERM},
		{"no inode flags (ENOTTY)", func(t *testing.T, fi os.FileInfo) { injectFlags(t, fi, 0, syscall.ENOTTY) }, false, 0},
		{"no statx (ENOSYS)", func(t *testing.T, fi os.FileInfo) { injectAttrs(t, fi, 0, syscall.ENOSYS) }, false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path, fi := replacementFixture(t)
			tc.inject(t, fi)
			err := ReplacementBlocked(path)
			if !tc.blocked {
				if err != nil {
					t.Fatalf("ReplacementBlocked = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, ErrReplacementBlocked) || !errors.Is(err, tc.errno) {
				t.Fatalf("ReplacementBlocked = %v, want ErrReplacementBlocked wrapping %v", err, tc.errno)
			}
		})
	}
}

// TestReplacementBlocked_ReadErrorIsNotBlocked: a failure to read the
// attributes is reported as an error, not as blocked and not as fine.
func TestReplacementBlocked_ReadErrorIsNotBlocked(t *testing.T) {
	path, fi := replacementFixture(t)
	injectFlags(t, fi, 0, syscall.EIO)
	if err := ReplacementBlocked(path); err == nil || errors.Is(err, ErrReplacementBlocked) || !errors.Is(err, syscall.EIO) {
		t.Fatalf("ReplacementBlocked = %v, want a plain EIO", err)
	}
}

// TestReplacementBlocked_RealChattr: a real chattr +i or +a (root here) is
// reported. Skips where the filesystem or privileges do not allow the flag;
// the injected cases above cover the logic.
func TestReplacementBlocked_RealChattr(t *testing.T) {
	for name, flag := range map[string]uint32{"+i": fsImmutableFL, "+a": fsAppendFL} {
		t.Run(name, func(t *testing.T) {
			path, _ := replacementFixture(t)
			f, err := os.Open(path) // #nosec G304 -- test temp path
			if err != nil {
				t.Fatal(err)
			}
			cur, err := unix.IoctlGetUint32(int(f.Fd()), unix.FS_IOC_GETFLAGS)
			if err == nil {
				err = unix.IoctlSetPointerInt(int(f.Fd()), unix.FS_IOC_SETFLAGS, int(cur|flag))
			}
			_ = f.Close()
			if err != nil {
				t.Skipf("cannot chattr %s on the test filesystem (%v)", name, err)
			}
			t.Cleanup(func() {
				if g, err := os.Open(path); err == nil { // #nosec G304 -- test temp path
					_ = unix.IoctlSetPointerInt(int(g.Fd()), unix.FS_IOC_SETFLAGS, int(cur))
					_ = g.Close()
				}
			})
			if err := ReplacementBlocked(path); !errors.Is(err, ErrReplacementBlocked) || !errors.Is(err, syscall.EPERM) {
				t.Errorf("ReplacementBlocked = %v after chattr %s, want ErrReplacementBlocked wrapping EPERM", err, name)
			}
		})
	}
}
