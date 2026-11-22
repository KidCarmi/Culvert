package writerlock

import (
	"errors"
	"os"
	"path/filepath"
)

// FileName is the lock file's name inside the directory. It lives in the
// directory, not beside it, so it travels with a bind mount, a docker volume
// and an NFS export: the three ways two processes end up sharing one data
// root. The file is zero bytes and means nothing on its own; the flock is the
// state.
const FileName = ".culvert-writer.lock"

// Verdict is the outcome of one acquisition attempt.
type Verdict int

const (
	// Acquired means this caller is the single writer for as long as the Lock in
	// the Attempt stays open.
	Acquired Verdict = iota
	// Held means a live process holds the lock.
	Held
	// Undetermined means the lock state could not be established. Cause in the
	// Attempt says why.
	Undetermined
)

// Lock is a held single-writer lock. The flock is tied to the open file
// description, so the Lock must stay reachable for as long as the caller means
// to hold it: dropping it would let the descriptor be finalized and the lock
// released.
type Lock struct {
	f *os.File
}

// Close releases the lock. The kernel also releases it when the process
// exits, which is how a process-lifetime holder gives it up.
func (l *Lock) Close() error { return l.f.Close() }

// Attempt is what Take found.
type Attempt struct {
	// Verdict is the outcome.
	Verdict Verdict
	// Path is the lock file path that was used. Empty only when no directory
	// was named.
	Path string
	// Cause is the underlying error for an Undetermined verdict, and nil
	// otherwise.
	Cause error
	// Lock is the held lock. Non-nil exactly when Verdict is Acquired.
	Lock *Lock
}

// Take takes the single-writer lock on dir.
//
// It writes nothing but the directory itself, when absent, and the zero-byte
// lock file, and it never blocks: a live holder is reported immediately,
// because waiting would turn a misconfiguration into a hang.
func Take(dir string) Attempt {
	if dir == "" {
		return Attempt{Verdict: Undetermined, Cause: errors.New("no persisted-state root configured")}
	}
	path := filepath.Join(dir, FileName)
	// The directory may not exist yet on a fresh install, and the caller runs
	// this before anything else would create it. Opening the lock file first
	// would return ENOENT and leave the process holding nothing for its whole
	// life, while startup then created the directory and a second process
	// could take the lock beside it. Creating the directory here is what makes
	// the lock real on a first boot. A creation that fails (read-only volume,
	// no permission, a root that is a file) is Undetermined.
	//
	// 0o700 matches loadPAC in package main, the statement that otherwise
	// creates this directory. MkdirAll is a no-op on an existing directory and
	// never changes its mode, so an operator's 0o750 volume is left as it is.
	if err := os.MkdirAll(dir, 0o700); err != nil { // #nosec G304 G703 -- the operator-configured persisted-state root itself; no request input reaches it
		return Attempt{Verdict: Undetermined, Path: path, Cause: err}
	}
	// O_CREATE without O_EXCL by design: the lock file is expected to survive
	// across boots. Mode 0600 matches every other file the application creates
	// in the directory.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 G703 -- operator-configured persisted-state root joined with a compile-time basename; no request input reaches this path
	if err != nil {
		// A read-only or permission-denied volume is a documented degraded
		// mode (CHAOS-05/07), so it is Undetermined and never Held.
		return Attempt{Verdict: Undetermined, Path: path, Cause: err}
	}
	held, lockErr := flockExclusiveNonBlocking(f)
	if lockErr != nil {
		_ = f.Close()
		return Attempt{Verdict: Undetermined, Path: path, Cause: lockErr}
	}
	if !held {
		_ = f.Close()
		return Attempt{Verdict: Held, Path: path}
	}
	return Attempt{Verdict: Acquired, Path: path, Lock: &Lock{f: f}}
}
