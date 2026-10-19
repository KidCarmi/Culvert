//go:build linux

package fileutil

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"sort"
	"syscall"

	"golang.org/x/sys/unix"
)

// Extended-attribute preservation for RewriteInPlace (Codex P2 4316064806 on
// PR #1601): the exchanged-in inode must carry exactly the target's extended
// attributes, POSIX ACL and security label included. The contract is in
// rewrite.go.

// xattrSet is a file's extended attributes, name to value.
type xattrSet map[string][]byte

// aclAccessXattr encodes a file's POSIX access ACL. It is set last, after the
// chmod and the other attributes, because setting it rewrites the group
// permission bits from the ACL mask.
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

// targetXattrs reads the extended attributes of the file at path through an
// O_NOFOLLOW descriptor, after confirming that descriptor is still orig. A
// target that vanished, became a symlink or is another file is a concurrent
// change; any other failure means its metadata cannot be preserved.
func targetXattrs(op, path string, orig os.FileInfo) (xattrSet, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) // #nosec G304 -- the caller's own path
	if err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ELOOP) {
			return nil, fmt.Errorf("%s %s: open to read its attributes: %w: %w", op, path, err, ErrConcurrentChange)
		}
		return nil, fmt.Errorf("%s %s: open to read its attributes: %w: %w", op, path, err, ErrMetadataNotPreservable)
	}
	defer func() { _ = f.Close() }() // #nosec G104 -- read-only handle
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("%s %s: stat to read its attributes: %w: %w", op, path, err, ErrMetadataNotPreservable)
	}
	if !os.SameFile(fi, orig) {
		return nil, fmt.Errorf("%s %s: the target is no longer the loaded file: %w", op, path, ErrConcurrentChange)
	}
	set, err := readXattrs(int(f.Fd()))
	if err != nil {
		return nil, fmt.Errorf("%s %s: read extended attributes: %w: %w", op, path, err, ErrMetadataNotPreservable)
	}
	return set, nil
}

// copyXattrs makes the attributes of f — the temp file, already chmodded and
// chowned to match orig — exactly src: it sets every attribute of src (the
// access ACL last), removes any f inherited that src lacks (a directory's
// default ACL), and then reads f back, requiring the same attribute set,
// permission bits, owner and group as orig. It reports whether it changed
// any attribute on f.
func copyXattrs(f *os.File, src xattrSet, orig os.FileInfo) (bool, error) {
	fd := int(f.Fd())
	for _, name := range xattrSetOrder(src) {
		if err := fsetxattr(fd, name, src[name]); err != nil {
			return false, fmt.Errorf("set %q on the replacement: %w", name, err)
		}
	}
	changed := len(src) > 0
	got, err := readXattrs(fd)
	if err != nil {
		return changed, fmt.Errorf("read back the replacement's attributes: %w", err)
	}
	for name := range got {
		if _, ok := src[name]; ok {
			continue
		}
		if err := unix.Fremovexattr(fd, name); err != nil {
			return changed, fmt.Errorf("remove %q the replacement inherited: %w", name, err)
		}
		changed = true
	}
	if got, err = readXattrs(fd); err != nil {
		return changed, fmt.Errorf("read back the replacement's attributes: %w", err)
	}
	if !got.equal(src) {
		return changed, errors.New("the replacement's extended attributes differ from the target's after copying")
	}
	fi, err := f.Stat()
	if err != nil {
		return changed, fmt.Errorf("stat the replacement: %w", err)
	}
	if fi.Mode().Perm() != orig.Mode().Perm() {
		return changed, fmt.Errorf("the replacement's permission bits are %v after copying, want %v",
			fi.Mode().Perm(), orig.Mode().Perm())
	}
	if !sameOwner(fi, orig) {
		return changed, errors.New("the replacement's owner or group differs from the target's")
	}
	return changed, nil
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

// preserveMetadata is RewriteInPlace's metadata step on the open temp file,
// after its chmod: it gives f orig's owner and group (first, because a chown
// clears security.capability), copies src onto it, verifies the result
// exactly, and, if an attribute changed, fsyncs f again so the metadata is as
// durable as the bytes. A failure to preserve ownership or attributes wraps
// ErrMetadataNotPreservable.
func preserveMetadata(f *os.File, orig os.FileInfo, src xattrSet) error {
	if err := preserveOwner(f, orig); err != nil {
		return fmt.Errorf("preserve owner and group: %w: %w", err, ErrMetadataNotPreservable)
	}
	changed, err := copyXattrs(f, src, orig)
	if err != nil {
		return fmt.Errorf("preserve extended attributes: %w: %w", err, ErrMetadataNotPreservable)
	}
	if changed {
		if err := f.Sync(); err != nil {
			return fmt.Errorf("fsync after copying extended attributes: %w", err)
		}
	}
	return nil
}
