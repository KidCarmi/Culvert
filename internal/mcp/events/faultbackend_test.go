package events

import (
	"errors"
	"os"
	"strings"
	"sync"
	"syscall"

	"github.com/KidCarmi/Culvert/internal/mcp/events/spool"
)

// faultBackend wraps the real OS backend and injects a deterministic append or
// replace failure whose target path matches a substring, optionally only after
// the segment header is written. It lets the manager containment tests drive a
// specific capability's P-CRIT commit to fail (post-admission) without touching
// the host disk or the other capability's domain.
type faultBackend struct {
	inner spool.Backend
	mu    sync.Mutex

	appendFailSub  string // fail record appends whose path contains this (after header)
	appendENOSPC   bool   // use ENOSPC instead of a generic error
	replaceFailSub string
	seenHeader     map[string]bool
}

func newFaultBackend() *faultBackend {
	return &faultBackend{inner: spool.NewOSBackend(), seenHeader: map[string]bool{}}
}

func (f *faultBackend) failAppendFor(sub string, enospc bool) {
	f.mu.Lock()
	f.appendFailSub = sub
	f.appendENOSPC = enospc
	f.mu.Unlock()
}

func (f *faultBackend) MkdirAll(dir string, perm os.FileMode) error {
	return f.inner.MkdirAll(dir, perm)
}

func (f *faultBackend) AppendSync(path string, frame []byte, perm os.FileMode) error {
	f.mu.Lock()
	sub, enospc := f.appendFailSub, f.appendENOSPC
	f.mu.Unlock()
	if sub != "" && strings.Contains(path, sub) && strings.Contains(path, "seg-") {
		// Let the segment header through, fail the first record append.
		f.mu.Lock()
		seen := f.seenHeader[path]
		f.seenHeader[path] = true
		f.mu.Unlock()
		if seen {
			if enospc {
				return &os.PathError{Op: "write", Path: path, Err: syscall.ENOSPC}
			}
			return errors.New("injected append fault")
		}
	}
	return f.inner.AppendSync(path, frame, perm)
}

func (f *faultBackend) AtomicReplace(path string, data []byte, perm os.FileMode) error {
	f.mu.Lock()
	sub := f.replaceFailSub
	f.mu.Unlock()
	if sub != "" && strings.Contains(path, sub) {
		return errors.New("injected replace fault")
	}
	return f.inner.AtomicReplace(path, data, perm)
}

func (f *faultBackend) ReadFile(path string) ([]byte, error) { return f.inner.ReadFile(path) }
func (f *faultBackend) ReadAt(path string, off int64, buf []byte) (int, error) {
	return f.inner.ReadAt(path, off, buf)
}
func (f *faultBackend) Truncate(path string, size int64) error { return f.inner.Truncate(path, size) }
func (f *faultBackend) Remove(path string) error               { return f.inner.Remove(path) }
func (f *faultBackend) Size(path string) (int64, error)        { return f.inner.Size(path) }
func (f *faultBackend) List(dir string) ([]string, error)      { return f.inner.List(dir) }
