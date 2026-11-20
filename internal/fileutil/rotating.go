package fileutil

import (
	"errors"
	"fmt"
	"os"
	"sync"
)

// errNotRegular reports that the log path names something other than a
// regular file (a FIFO, a device node, a socket), which openLogAppend refuses.
var errNotRegular = errors.New("not a regular file")

// openLogAppend opens path for appending, creating it 0600 when absent, and
// returns the descriptor and its current size. It is the one open both
// NewRotatingFile and the post-rotation reopen in Write use, so the startup
// open, the deferred re-attempts (audit and request log) and every rotation
// get the same guarantees (CWE-59/CWE-61):
//
//   - oNoFollow refuses a symlink at the FINAL path component, so a link
//     planted at the log path (or swapped in after a rotation) cannot redirect
//     the audit/request log into, or create, a file elsewhere. Directory
//     components are still resolved normally; only the leaf is guarded.
//   - oNonBlock makes the open return at once on a FIFO planted at the path
//     (ENXIO with no reader) instead of blocking the caller — the startup path
//     or a request-path Write holding the writer's mutex — until a reader
//     appears.
//   - The descriptor is fstat'ed and anything but a regular file is refused,
//     which catches the FIFO that does have a reader, and device nodes.
//   - O_NONBLOCK is then cleared, so writes to the verified regular file have
//     ordinary blocking semantics on every platform.
//
// Where the platform has no O_NOFOLLOW/O_NONBLOCK (rotating_open_other.go),
// both flags are 0: the open follows a symlink and may block on a FIFO as it
// did before, and only the regular-file check still applies.
func openLogAppend(path string) (*os.File, int64, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND|oNoFollow|oNonBlock, 0o600)
	if err != nil {
		return nil, 0, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, fmt.Errorf("stat log file: %w", err)
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, 0, fmt.Errorf("open log file %q: %w (mode %s)", path, errNotRegular, info.Mode().Type())
	}
	if err := clearNonBlock(f); err != nil {
		_ = f.Close()
		return nil, 0, fmt.Errorf("clear O_NONBLOCK on log file: %w", err)
	}
	return f, info.Size(), nil
}

// RotatingFile wraps a log file and rotates it when it exceeds maxBytes.
type RotatingFile struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	file     *os.File
	size     int64
}

// NewRotatingFile opens path for append and returns a writer that rotates
// the file to path+".1" when it exceeds maxMB (<=0 falls back to 50 MB).
// It refuses a symlink at path and anything that is not a regular file, and
// does not block on a FIFO there (see openLogAppend).
func NewRotatingFile(path string, maxMB int) (*RotatingFile, error) {
	f, sz, err := openLogAppend(path)
	if err != nil {
		return nil, err
	}
	maxBytes := int64(maxMB) * 1024 * 1024
	if maxBytes <= 0 {
		// Zero or negative (e.g. a stray -log-max-mb -1) would make the
		// Write-time rotation check size+len > maxBytes always true, rotating
		// on every write and thrashing the disk. Fall back to the default.
		maxBytes = 50 * 1024 * 1024 // 50 MB default
	}
	return &RotatingFile{path: path, maxBytes: maxBytes, file: f, size: sz}, nil
}

// Write appends p, rotating first when the size cap would be exceeded.
func (r *RotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.file != nil && r.size+int64(len(p)) > r.maxBytes {
		r.file.Close()
		r.file = nil
		r.size = 0
		// Remove any previous rotated file before renaming the current one.
		// This prevents unbounded growth from accumulating stale .1 files.
		_ = os.Remove(r.path + ".1")
		_ = os.Rename(r.path, r.path+".1")
	}
	if r.file == nil {
		// Fresh open after rotation — or a reopen retry after a rotation
		// whose reopen failed (e.g. disk full). Retrying here, OUTSIDE the
		// rotation branch, is load-bearing: re-entering rotation on the next
		// write would os.Remove the just-rotated .1 archive, destroying the
		// only surviving copy of the log data. The same guarded open as
		// NewRotatingFile: a symlink or FIFO planted at the path after a
		// rotation is refused here too.
		f, sz, err := openLogAppend(r.path)
		if err != nil {
			return 0, err
		}
		r.file = f
		r.size = sz
	}

	n, err := r.file.Write(p)
	r.size += int64(n)
	return n, err
}

// Close closes the underlying file.
func (r *RotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file == nil {
		return nil
	}
	err := r.file.Close()
	r.file = nil
	return err
}
