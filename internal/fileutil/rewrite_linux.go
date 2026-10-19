//go:build linux

package fileutil

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// renameExchange atomically swaps the directory entries a and b
// (renameat2 RENAME_EXCHANGE). Permission checks are rename(2)'s for BOTH
// entries: the kernel applies the delete check (write+search on the
// directory, and the sticky-bit owner rule) to each side, so a non-owner of
// the target in a sticky directory is refused with EPERM exactly as a rename
// over it is. A seam only for this package's white-box tests.
var renameExchange = func(a, b string) error {
	if err := unix.Renameat2(unix.AT_FDCWD, a, unix.AT_FDCWD, b, unix.RENAME_EXCHANGE); err != nil {
		return &os.LinkError{Op: "renameat2 exchange", Old: a, New: b, Err: err}
	}
	return nil
}

// rewriteHooks are white-box test seams that let a test land an external
// write just before and just after the exchange. Nil in production.
var rewriteHooks struct {
	beforeExchange func(tmp string)
	afterExchange  func(tmp string)
}

// RewriteInPlace writes the loaded data back onto path by exchange, never
// over a concurrent change; the full contract is in rewrite.go.
func RewriteInPlace(path string, data []byte, orig os.FileInfo) error {
	const op = "rewrite in place"
	want, err := targetMeta(op, path, orig)
	if err != nil {
		return err // nothing written
	}
	var metaErr error
	tmp, err := writeTempBeside(op, path, data, orig.Mode().Perm(), func(f *os.File) {
		metaErr = preserveMetadata(f, want)
	})
	if err != nil {
		return err
	}
	if metaErr != nil {
		// The replacement would not carry the target's metadata exactly (or
		// is not durable), so it is never exchanged in: the target is
		// untouched.
		removeTemp(tmp)
		return fmt.Errorf("%s %s: %w", op, path, metaErr)
	}
	mine, err := os.Lstat(tmp)
	if err != nil {
		removeTemp(tmp)
		return fmt.Errorf("%s %s: stat temp: %w", op, path, err)
	}
	if h := rewriteHooks.beforeExchange; h != nil {
		h(tmp)
	}
	if err := renameExchange(tmp, path); err != nil {
		removeTemp(tmp) // the exchange did not happen: still only our bytes
		return exchangeError(op, path, err)
	}
	if h := rewriteHooks.afterExchange; h != nil {
		h(tmp)
	}
	if why := displacedDiffers(tmp, data, want); why != "" {
		return undoExchange(op, path, tmp, mine, why)
	}
	// What was live just before the swap is exactly what the caller loaded,
	// so removing it destroys nothing. Best effort: a leftover is a duplicate.
	removeTemp(tmp)
	return syncParentDir(op, path)
}

func removeTemp(tmp string) { _ = os.Remove(tmp) } // #nosec G104 -- best-effort cleanup

// exchangeError classifies a failed first exchange. Nothing was swapped.
func exchangeError(op, path string, err error) error {
	switch {
	case errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EINVAL), errors.Is(err, unix.EOPNOTSUPP):
		// An old kernel, or a filesystem without RENAME_EXCHANGE support.
		return fmt.Errorf("%s %s: exchange: %w: %w", op, path, err, ErrRewriteUnsupported)
	case errors.Is(err, unix.ENOENT):
		// The target was removed or renamed away after the caller loaded it.
		return fmt.Errorf("%s %s: exchange: %w: %w", op, path, err, ErrConcurrentChange)
	}
	return fmt.Errorf("%s %s: exchange: %w", op, path, err)
}

// undoExchange swaps the newer file back onto path after a mismatch. The temp
// path is deleted only if it then holds our own temp file again; otherwise it
// holds someone's content and is left where it is.
func undoExchange(op, path, tmp string, mine os.FileInfo, why string) error {
	if err := renameExchange(tmp, path); err != nil {
		return fmt.Errorf("%s %s: %s, and the exchange back failed (%w); the newer content is preserved at %s: %w",
			op, path, why, err, tmp, ErrExchangeBackFailed)
	}
	back, err := os.Lstat(tmp)
	if err != nil || !os.SameFile(back, mine) {
		return fmt.Errorf("%s %s: %s, and the target changed again while it was being restored; the file the "+
			"restore displaced is preserved at %s: %w", op, path, why, tmp, ErrExchangeBackFailed)
	}
	removeTemp(tmp)
	_ = syncParentDir(op, path) // #nosec G104 -- best effort: path holds the external writer's file again
	return fmt.Errorf("%s %s: %s: %w", op, path, why, ErrConcurrentChange)
}

// displacedDiffers compares the file the exchange displaced (now at tmp) with
// what the caller loaded: content, and the full fileMeta read from the target
// before the exchange (want) — owner, group, all 12 mode bits, inode flags
// and extended attributes. "" means identical; any doubt is a difference.
func displacedDiffers(tmp string, data []byte, want fileMeta) string {
	// O_NOFOLLOW|O_NONBLOCK: the displaced entry is whatever was at the
	// target, so it is not trusted to be a regular file.
	f, err := os.OpenFile(tmp, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) // #nosec G304 -- our own temp name beside the caller's path
	if err != nil {
		return "the file displaced from the target could not be opened for comparison"
	}
	defer func() { _ = f.Close() }() // #nosec G104 -- read-only handle
	fi, err := f.Stat()
	switch {
	case err != nil:
		return "the file displaced from the target could not be inspected"
	case !fi.Mode().IsRegular():
		return "the entry displaced from the target is not a regular file"
	case fi.Size() != int64(len(data)):
		return "the file displaced from the target differs in size from the loaded content"
	}
	got, err := readMeta(f)
	if err != nil {
		return "the metadata of the file displaced from the target could not be read for comparison"
	}
	if what := want.differs(got); what != "" {
		return "the file displaced from the target has a different " + what + " than the loaded one"
	}
	content, err := io.ReadAll(io.LimitReader(f, int64(len(data))+1))
	if err != nil {
		return "the file displaced from the target could not be read for comparison"
	}
	if !bytes.Equal(content, data) {
		return "the file displaced from the target differs from the loaded content"
	}
	return ""
}

// sameOwner reports whether a and b have the same owner and group.
func sameOwner(a, b os.FileInfo) bool {
	sa, okA := a.Sys().(*syscall.Stat_t)
	sb, okB := b.Sys().(*syscall.Stat_t)
	return okA && okB && sa.Uid == sb.Uid && sa.Gid == sb.Gid
}
