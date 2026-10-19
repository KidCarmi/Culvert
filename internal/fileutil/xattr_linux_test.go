//go:build linux

package fileutil

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// Gates for Codex P2 4316064806 on PR #1601: the boot rewrite must never
// change the file's security metadata. The oracle below reads attributes by
// path with the l*xattr calls, independently of the descriptor-based code
// under test.

// lxattrsT returns path's extended attributes (no symlink follow).
func lxattrsT(t *testing.T, path string) map[string][]byte {
	t.Helper()
	list := make([]byte, xattrMaxSize)
	n, err := unix.Llistxattr(path, list)
	if errors.Is(err, unix.ENOTSUP) {
		return map[string][]byte{}
	}
	if err != nil {
		t.Fatalf("llistxattr %s: %v", path, err)
	}
	out := map[string][]byte{}
	for _, raw := range bytes.Split(list[:n], []byte{0}) {
		if len(raw) == 0 {
			continue
		}
		v := make([]byte, xattrMaxSize)
		m, err := unix.Lgetxattr(path, string(raw), v)
		if err != nil {
			t.Fatalf("lgetxattr %s %s: %v", path, raw, err)
		}
		out[string(raw)] = v[:m]
	}
	return out
}

// setXattrOrSkip sets name on path, skipping the test only when the test
// filesystem itself cannot hold that attribute.
func setXattrOrSkip(t *testing.T, path, name string, value []byte) {
	t.Helper()
	if err := unix.Lsetxattr(path, name, value, 0); err != nil {
		if errors.Is(err, unix.ENOTSUP) {
			t.Skipf("the test filesystem under %s does not support %s (%v)", filepath.Dir(path), name, err)
		}
		t.Fatalf("lsetxattr %s %s: %v", path, name, err)
	}
}

func statT(t *testing.T, path string) os.FileInfo {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi
}

func assertXattrs(t *testing.T, path string, want map[string][]byte) {
	t.Helper()
	if got := lxattrsT(t, path); !xattrSet(got).equal(want) {
		t.Errorf("extended attributes of %s = %q, want %q", path, got, want)
	}
}

// posixACL encodes a system.posix_acl_* value (POSIX_ACL_XATTR_VERSION 2:
// a little-endian u32 version, then {u16 tag, u16 perm, u32 id} entries).
func posixACL(entries ...[3]uint32) []byte {
	const version, undefinedID = 2, 0xFFFFFFFF
	b := binary.LittleEndian.AppendUint32(nil, version)
	for _, e := range entries {
		id := e[2]
		if e[0] != 0x02 && e[0] != 0x08 { // only ACL_USER and ACL_GROUP carry an id
			id = undefinedID
		}
		b = binary.LittleEndian.AppendUint16(b, uint16(e[0])) // #nosec G115 -- tag constants below
		b = binary.LittleEndian.AppendUint16(b, uint16(e[1])) // #nosec G115 -- rwx bits
		b = binary.LittleEndian.AppendUint32(b, id)
	}
	return b
}

// ACL tags (linux/posix_acl.h).
const (
	aclUserObj, aclUser, aclGroupObj, aclMask, aclOther = 0x01, 0x02, 0x04, 0x10, 0x20
)

// TestRewriteInPlace_PreservesUserXattrs: a backup or configuration agent's
// user.* attributes (one with an empty value) survive a successful rewrite,
// on the new inode. Removing the copy fails this test.
func TestRewriteInPlace_PreservesUserXattrs(t *testing.T) {
	loaded := []byte(`{"users":[]}`)
	path, _ := rewriteFixture(t, loaded)
	want := map[string][]byte{"user.backup.policy": []byte("include"), "user.empty": {}}
	for name, v := range want {
		setXattrOrSkip(t, path, name, v)
	}
	before := statT(t, path)

	if err := RewriteInPlace(path, loaded, before); err != nil {
		t.Fatalf("RewriteInPlace: %v", err)
	}
	after := statT(t, path)
	if os.SameFile(before, after) {
		t.Fatal("same inode: the exchange did not happen, so nothing was proven")
	}
	assertXattrs(t, path, want)
	if !bytes.Equal(readFileT(t, path), loaded) || after.Mode() != before.Mode() {
		t.Errorf("content or mode changed (mode %v -> %v)", before.Mode(), after.Mode())
	}
	assertOnlyTarget(t, path)
}

// TestRewriteInPlace_PreservesPOSIXAccessACL: a named-user ACL entry (the
// grant that lets a backup agent read the roster) survives, with the mode it
// implies. Set through system.posix_acl_access directly, so no setfacl is
// needed; skipped only where the filesystem rejects ACLs, in which case
// TestRewriteInPlace_UncopyableXattrIsNotExchanged still pins (through the
// fsetxattr seam) that an attribute that cannot be copied is never lost.
func TestRewriteInPlace_PreservesPOSIXAccessACL(t *testing.T) {
	loaded := []byte(`{"users":[]}`)
	path, _ := rewriteFixture(t, loaded)
	acl := posixACL(
		[3]uint32{aclUserObj, 6, 0},
		[3]uint32{aclUser, 4, 65534},
		[3]uint32{aclGroupObj, 4, 0},
		[3]uint32{aclMask, 4, 0},
		[3]uint32{aclOther, 0, 0},
	)
	setXattrOrSkip(t, path, aclAccessXattr, acl)
	want := lxattrsT(t, path)
	if _, ok := want[aclAccessXattr]; !ok {
		t.Fatalf("precondition: the fixture carries no access ACL: %q", want)
	}
	before := statT(t, path)

	if err := RewriteInPlace(path, loaded, before); err != nil {
		t.Fatalf("RewriteInPlace: %v", err)
	}
	after := statT(t, path)
	if os.SameFile(before, after) {
		t.Fatal("same inode: the exchange did not happen")
	}
	assertXattrs(t, path, want)
	if after.Mode() != before.Mode() {
		t.Errorf("mode changed: %v -> %v", before.Mode(), after.Mode())
	}
	assertOnlyTarget(t, path)
}

// TestRewriteInPlace_DoesNotAddAnInheritedACL: the temp file inherits the
// directory's default ACL as its access ACL; the roster has none, so the
// replacement must not gain one.
func TestRewriteInPlace_DoesNotAddAnInheritedACL(t *testing.T) {
	loaded := []byte(`{"users":[]}`)
	path, _ := rewriteFixture(t, loaded)
	setXattrOrSkip(t, filepath.Dir(path), "system.posix_acl_default", posixACL(
		[3]uint32{aclUserObj, 7, 0},
		[3]uint32{aclUser, 7, 65534},
		[3]uint32{aclGroupObj, 5, 0},
		[3]uint32{aclMask, 7, 0},
		[3]uint32{aclOther, 0, 0},
	))
	want := lxattrsT(t, path)
	before := statT(t, path)

	if err := RewriteInPlace(path, loaded, before); err != nil {
		t.Fatalf("RewriteInPlace: %v", err)
	}
	if os.SameFile(before, statT(t, path)) {
		t.Fatal("same inode: the exchange did not happen")
	}
	assertXattrs(t, path, want)
	if after := statT(t, path); after.Mode() != before.Mode() {
		t.Errorf("mode changed: %v -> %v", before.Mode(), after.Mode())
	}
	assertOnlyTarget(t, path)
}

// labelFixture gives path a security label where the process may set one
// (security.selinux, as root), otherwise a user.* stand-in, and returns its
// name. The seam below refuses whichever it is.
func labelFixture(t *testing.T, path string) string {
	t.Helper()
	const selinux = "security.selinux"
	if err := unix.Lsetxattr(path, selinux, []byte("system_u:object_r:etc_t:s0\x00"), 0); err == nil {
		return selinux
	}
	setXattrOrSkip(t, path, "user.label", []byte("etc_t"))
	return "user.label"
}

// TestRewriteInPlace_UncopyableXattrIsNotExchanged: when an attribute cannot
// be set on the replacement (EPERM for a label this process may not assign,
// ENOTSUP, EACCES), nothing is exchanged: the target keeps its inode, bytes
// and attributes, the temp is removed, and ErrMetadataNotPreservable is
// returned. Exchanging despite the copy failure fails this test.
func TestRewriteInPlace_UncopyableXattrIsNotExchanged(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.EPERM, syscall.ENOTSUP, syscall.EACCES} {
		t.Run(errno.Error(), func(t *testing.T) {
			loaded := []byte(`{"users":[]}`)
			path, _ := rewriteFixture(t, loaded)
			label := labelFixture(t, path)
			want := lxattrsT(t, path)
			before := statT(t, path)

			prev := fsetxattr
			fsetxattr = func(fd int, name string, value []byte) error {
				if name == label {
					return errno
				}
				return prev(fd, name, value)
			}
			t.Cleanup(func() { fsetxattr = prev })
			kernelExchange := renameExchange
			var exchanges atomic.Int32
			setRenameExchange(t, func(a, b string) error {
				exchanges.Add(1)
				return kernelExchange(a, b)
			})

			err := RewriteInPlace(path, loaded, before)
			if !errors.Is(err, ErrMetadataNotPreservable) || !errors.Is(err, errno) || errors.Is(err, ErrConcurrentChange) {
				t.Fatalf("err = %v, want ErrMetadataNotPreservable wrapping %v", err, errno)
			}
			if n := exchanges.Load(); n != 0 {
				t.Errorf("%d exchange(s) ran although the label could not be copied", n)
			}
			if !os.SameFile(before, statT(t, path)) {
				t.Error("the target was replaced although its attributes could not be preserved")
			}
			if !bytes.Equal(readFileT(t, path), loaded) {
				t.Error("content changed")
			}
			assertXattrs(t, path, want)
			assertOnlyTarget(t, path)
		})
	}
}

// TestRewriteInPlace_ConcurrentXattrChangeIsSwappedBack: an attribute added,
// changed or removed on the target just before the exchange, or set on the
// displaced file (by a descriptor holder) just after it, makes the displaced
// file differ from what was loaded, so the exchange is undone: the original
// inode, carrying the change, is back at the target. Dropping the attribute
// comparison fails this test.
func TestRewriteInPlace_ConcurrentXattrChangeIsSwappedBack(t *testing.T) {
	set := func(name, v string) func(t *testing.T, p string) {
		return func(t *testing.T, p string) {
			if err := unix.Lsetxattr(p, name, []byte(v), 0); err != nil {
				t.Error(err)
			}
		}
	}
	remove := func(t *testing.T, p string) {
		if err := unix.Lremovexattr(p, "user.keep"); err != nil {
			t.Error(err)
		}
	}
	cases := []struct {
		name          string
		before, after func(t *testing.T, p string) // before acts on the target, after on the displaced file
		want          map[string][]byte
	}{
		{"added before the exchange", set("user.new", "1"), nil,
			map[string][]byte{"user.keep": []byte("v1"), "user.new": []byte("1")}},
		{"changed before the exchange", set("user.keep", "v2"), nil,
			map[string][]byte{"user.keep": []byte("v2")}},
		{"removed before the exchange", remove, nil, map[string][]byte{}},
		{"added to the displaced file after the exchange", nil, set("user.new", "1"),
			map[string][]byte{"user.keep": []byte("v1"), "user.new": []byte("1")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			loaded := []byte(`{"users":[]}`)
			path, _ := rewriteFixture(t, loaded)
			setXattrOrSkip(t, path, "user.keep", []byte("v1"))
			fi := statT(t, path)
			var before, after func(string)
			if tc.before != nil {
				before = func(string) { tc.before(t, path) }
			}
			if tc.after != nil {
				after = func(tmp string) { tc.after(t, tmp) }
			}
			setRewriteHooks(t, before, after)

			if err := RewriteInPlace(path, loaded, fi); !errors.Is(err, ErrConcurrentChange) {
				t.Fatalf("err = %v, want ErrConcurrentChange", err)
			}
			if !os.SameFile(fi, statT(t, path)) {
				t.Error("the original inode was not swapped back to the target")
			}
			assertXattrs(t, path, tc.want)
			assertOnlyTarget(t, path)
		})
	}
}
