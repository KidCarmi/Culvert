//go:build linux

package server

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// hostMaintenanceLockName is the file the agent and `culvert-os-update`
// both flock: the agent for every state-changing operation, the OS tool for
// its whole run. Either side that finds it held refuses, so an OS/engine
// update or reboot can never start under an agent operation, and an agent
// operation can never be admitted while one runs (Codex P1, PR #1528 — a
// one-time journal snapshot could not see an op admitted a second later).
// A read-only descriptor is enough for flock, so a file root created first
// (0644) is still lockable by the agent.
const hostMaintenanceLockName = "host-maintenance.lock"

// acquireHostMaintenanceLock takes the lock without blocking. busy reports
// that another process holds it. Any other failure returns err and no
// release; the caller decides whether that is fatal.
func acquireHostMaintenanceLock(stateDir string) (release func(), busy bool, err error) {
	f, err := os.OpenFile(filepath.Join(stateDir, hostMaintenanceLockName), os.O_RDONLY|os.O_CREATE, 0o640) //nolint:gosec // fixed name under the agent's own state dir
	if err != nil {
		return nil, false, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil { //nolint:gosec // fd fits in int
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, true, nil
		}
		return nil, false, err
	}
	return func() { _ = f.Close() }, false, nil // closing the descriptor drops the flock
}
