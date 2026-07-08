package fileutil

import (
	"os"
	"sync"
)

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
func NewRotatingFile(path string, maxMB int) (*RotatingFile, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	info, _ := f.Stat()
	var sz int64
	if info != nil {
		sz = info.Size()
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
		// only surviving copy of the log data.
		f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return 0, err
		}
		r.file = f
		r.size = 0
		if info, statErr := f.Stat(); statErr == nil {
			r.size = info.Size()
		}
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
