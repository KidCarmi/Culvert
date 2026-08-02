package spool

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// fsBackend is the injected filesystem seam the spool commits through. The real
// implementation (osBackend) calls the OS directly; tests substitute a failing
// backend to exercise every commit-failure branch (short write, append error,
// ENOSPC, fsync error, directory-sync error, rename failure) DETERMINISTICALLY,
// without depending on filling the test host's disk. Every method a durable
// commit relies on is a seam here so a fault can be injected at exactly one step
// and the fail-closed posture proven for that step alone.
//
// Durability contract: AppendSync appends a complete frame and fsyncs the file in
// one call — a returned nil means the bytes are on stable storage for that file.
// AtomicReplace writes a whole metadata file via a temp+rename+dir-sync sequence
// (the checkpoint / state / sealed-DEK writer). A non-nil error from either is a
// commit FAILURE: the caller must treat the write as not durable and fail closed.
type fsBackend interface {
	// MkdirAll creates dir (and parents) with perm.
	MkdirAll(dir string, perm os.FileMode) error
	// AppendSync opens path (creating with perm), appends frame at the end, and
	// fsyncs the file. It returns the total number of frame bytes durably written
	// and an error. A short write (n < len(frame)) is reported as an error so the
	// caller never advances the committed position past unwritten bytes.
	AppendSync(path string, frame []byte, perm os.FileMode) error
	// AtomicReplace writes data to path via temp+fsync+rename+dir-sync (whole-file
	// durable replacement) with perm.
	AtomicReplace(path string, data []byte, perm os.FileMode) error
	// ReadFile reads a whole file.
	ReadFile(path string) ([]byte, error)
	// ReadAt reads up to len(buf) bytes at off from path.
	ReadAt(path string, off int64, buf []byte) (int, error)
	// Truncate truncates path to size (drops an uncommitted tail).
	Truncate(path string, size int64) error
	// Remove removes a file (segment reclamation).
	Remove(path string) error
	// Size returns the byte size of path.
	Size(path string) (int64, error)
	// List returns the base names of entries in dir (non-recursive); an absent
	// dir returns an empty list, not an error.
	List(dir string) ([]string, error)
}

// errShortWrite is returned when an append could not place the whole frame.
var errShortWrite = errors.New("spool: short write")

// osBackend is the production fsBackend. It uses O_APPEND + explicit fsync for
// records and fileutil-style temp+rename+dir-sync for metadata. Only READ and
// APPEND are used for segment data; whole-file replacement is reserved for
// bounded metadata (checkpoints, state, sealed DEK).
type osBackend struct{}

func (osBackend) MkdirAll(dir string, perm os.FileMode) error { return os.MkdirAll(dir, perm) }

func (osBackend) AppendSync(path string, frame []byte, perm os.FileMode) error {
	f, err := os.OpenFile(filepath.Clean(path), os.O_CREATE|os.O_WRONLY|os.O_APPEND, perm)
	if err != nil {
		return err
	}
	n, werr := f.Write(frame)
	if werr == nil && n != len(frame) {
		werr = errShortWrite
	}
	if werr != nil {
		_ = f.Close()
		return werr
	}
	if serr := f.Sync(); serr != nil {
		_ = f.Close()
		return serr
	}
	return f.Close()
}

func (osBackend) AtomicReplace(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = tmp.Close(); _ = os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return syncDir(dir)
}

// syncDir fsyncs a directory so a rename/create is itself durable. A filesystem
// that does not support directory fsync (EINVAL/ENOTSUP/EOPNOTSUPP) is tolerated,
// matching fileutil.AtomicWrite's precedent.
func syncDir(dir string) error {
	d, err := os.Open(filepath.Clean(dir))
	if err != nil {
		return err
	}
	serr := d.Sync()
	cerr := d.Close()
	// Tolerate filesystems without directory-fsync support, matching
	// fileutil.AtomicWrite's precedent.
	if serr != nil &&
		!errors.Is(serr, syscall.EINVAL) &&
		!errors.Is(serr, syscall.ENOTSUP) &&
		!errors.Is(serr, syscall.EOPNOTSUPP) {
		return serr
	}
	return cerr
}

func (osBackend) ReadFile(path string) ([]byte, error) { return os.ReadFile(filepath.Clean(path)) }

func (osBackend) ReadAt(path string, off int64, buf []byte) (int, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return 0, err
	}
	defer f.Close() //nolint:errcheck // read-only handle
	return f.ReadAt(buf, off)
}

func (osBackend) Truncate(path string, size int64) error {
	return os.Truncate(filepath.Clean(path), size)
}

func (osBackend) Remove(path string) error { return os.Remove(filepath.Clean(path)) }

func (osBackend) Size(path string) (int64, error) {
	fi, err := os.Stat(filepath.Clean(path))
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}

func (osBackend) List(dir string) ([]string, error) {
	ents, err := os.ReadDir(filepath.Clean(dir))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	return names, nil
}
