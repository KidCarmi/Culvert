package spool

import (
	"os"
	"syscall"
)

// hookBackend wraps a real Backend and lets a test inject a deterministic
// failure at exactly one filesystem step, without depending on filling the host
// disk. A hook returning a non-nil error fails that operation instead of
// delegating; a nil hook delegates. This is how the post-admission commit-failure
// cases (append error, fsync/ENOSPC, checkpoint rename failure) are proven to fail
// closed at each individual step.
type hookBackend struct {
	inner     Backend
	onAppend  func(path string) error
	onReplace func(path string) error
	onReadAt  func(path string) error
}

func newHookBackend() *hookBackend { return &hookBackend{inner: osBackend{}} }

func (h *hookBackend) MkdirAll(dir string, perm os.FileMode) error {
	return h.inner.MkdirAll(dir, perm)
}

func (h *hookBackend) AppendSync(path string, frame []byte, perm os.FileMode) error {
	if h.onAppend != nil {
		if err := h.onAppend(path); err != nil {
			return err
		}
	}
	return h.inner.AppendSync(path, frame, perm)
}

func (h *hookBackend) AtomicReplace(path string, data []byte, perm os.FileMode) error {
	if h.onReplace != nil {
		if err := h.onReplace(path); err != nil {
			return err
		}
	}
	return h.inner.AtomicReplace(path, data, perm)
}

func (h *hookBackend) ReadFile(path string) ([]byte, error) { return h.inner.ReadFile(path) }

func (h *hookBackend) ReadAt(path string, off int64, buf []byte) (int, error) {
	if h.onReadAt != nil {
		if err := h.onReadAt(path); err != nil {
			return 0, err
		}
	}
	return h.inner.ReadAt(path, off, buf)
}

func (h *hookBackend) Truncate(path string, size int64) error { return h.inner.Truncate(path, size) }
func (h *hookBackend) Remove(path string) error               { return h.inner.Remove(path) }
func (h *hookBackend) Size(path string) (int64, error)        { return h.inner.Size(path) }
func (h *hookBackend) List(dir string) ([]string, error)      { return h.inner.List(dir) }

// enospc is a wrapped no-space error for the ENOSPC injection case.
var enospc = &os.PathError{Op: "write", Path: "spool", Err: syscall.ENOSPC}
