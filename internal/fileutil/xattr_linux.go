//go:build linux

package fileutil

import (
	"bytes"
	"errors"
	"fmt"
	"sort"

	"golang.org/x/sys/unix"
)

// Extended attributes for RewriteInPlace's metadata preservation (Codex P2
// 4316064806 on PR #1601; the whole ordered step is in metadata_linux.go and
// the contract in rewrite.go).

// xattrSet is a file's extended attributes, name to value.
type xattrSet map[string][]byte

// aclAccessXattr encodes a file's POSIX access ACL.
const aclAccessXattr = "system.posix_acl_access"

// xattrMaxSize is the kernel's XATTR_LIST_MAX and XATTR_SIZE_MAX (64 KiB):
// nothing larger can be listed or read, so a larger probe is an error.
const xattrMaxSize = 1 << 16

// xattrReadAttempts bounds the size-probe loop when a list or value grows
// between the probe and the read (ERANGE).
const xattrReadAttempts = 4

// fsetxattr sets one attribute on fd. A seam only for this package's
// white-box tests, which inject the EPERM or ENOTSUP a label or ACL the
// process may not set produces.
var fsetxattr = func(fd int, name string, value []byte) error {
	return unix.Fsetxattr(fd, name, value, 0)
}

// equal reports whether s and o hold the same names with the same values.
func (s xattrSet) equal(o xattrSet) bool {
	if len(s) != len(o) {
		return false
	}
	for name, v := range s {
		w, ok := o[name]
		if !ok || !bytes.Equal(v, w) {
			return false
		}
	}
	return true
}

// readXattrs returns every extended attribute of fd that this process can
// list. A filesystem without extended attributes (ENOTSUP, which on Linux is
// also EOPNOTSUPP) holds none, so that is an empty set, not an error. Any
// other failure is returned: an attribute that cannot be read cannot be
// preserved or compared.
func readXattrs(fd int) (xattrSet, error) {
	list, err := readSized(func(buf []byte) (int, error) { return unix.Flistxattr(fd, buf) })
	if errors.Is(err, unix.ENOTSUP) {
		return xattrSet{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("listxattr: %w", err)
	}
	set := xattrSet{}
	for _, raw := range bytes.Split(list, []byte{0}) {
		if len(raw) == 0 {
			continue
		}
		name := string(raw)
		v, err := readSized(func(buf []byte) (int, error) { return unix.Fgetxattr(fd, name, buf) })
		if err != nil {
			return nil, fmt.Errorf("getxattr %q: %w", name, err)
		}
		set[name] = v
	}
	return set, nil
}

// readSized runs a listxattr/getxattr-style call: probe the size with an
// empty buffer, then read into one of that size, retrying if it grew.
func readSized(call func(buf []byte) (int, error)) ([]byte, error) {
	for range xattrReadAttempts {
		n, err := call(nil)
		switch {
		case err != nil:
			return nil, err
		case n == 0:
			return []byte{}, nil
		case n > xattrMaxSize:
			return nil, fmt.Errorf("%d bytes: %w", n, unix.E2BIG)
		}
		buf := make([]byte, n)
		n, err = call(buf)
		if errors.Is(err, unix.ERANGE) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return buf[:n], nil
	}
	return nil, fmt.Errorf("its size kept changing while it was read: %w", unix.ERANGE)
}

// copyXattrs makes fd's extended attributes want: it sets every attribute
// of want (the access ACL last, after the chmod, because setting it rewrites
// the group permission bits from the ACL mask) and removes any fd inherited
// that want lacks (a directory's default ACL becomes a new file's access
// ACL). preserveMetadata verifies the result.
func copyXattrs(fd int, want xattrSet) error {
	for _, name := range xattrSetOrder(want) {
		if err := fsetxattr(fd, name, want[name]); err != nil {
			return fmt.Errorf("set %q on the replacement: %w", name, err)
		}
	}
	got, err := readXattrs(fd)
	if err != nil {
		return fmt.Errorf("read back the replacement's attributes: %w", err)
	}
	for name := range got {
		if _, ok := want[name]; ok {
			continue
		}
		if err := unix.Fremovexattr(fd, name); err != nil {
			return fmt.Errorf("remove %q the replacement inherited: %w", name, err)
		}
	}
	return nil
}

// xattrSetOrder is src's names sorted, with the access ACL last.
func xattrSetOrder(src xattrSet) []string {
	names := make([]string, 0, len(src))
	for name := range src {
		if name != aclAccessXattr {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	if _, ok := src[aclAccessXattr]; ok {
		names = append(names, aclAccessXattr)
	}
	return names
}
