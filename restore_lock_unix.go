//go:build unix

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// errDataDirLocked is returned when another process holds the data-directory
// lock — in practice the running proxy, which must be stopped before a
// restore commit or an interrupted-restore recovery mutates /data.
var errDataDirLocked = errors.New("data directory is locked by another Culvert process (is the proxy still running? stop the stack first)")

// acquireDataDirLock takes a non-blocking exclusive advisory flock on
// <dataDir>/.culvert.lock. The returned release func unlocks and closes.
//
// Semantics the callers rely on:
//   - Held by the PROXY for its whole lifetime (main.go, after the
//     interrupted-restore guard). flock is inode-based, so a cli container
//     sharing the same volume on the same host sees the lock.
//   - The restore COMMIT and RECOVERY refuse (errDataDirLocked) when it is
//     held: quiescing is enforced, not merely documented.
//   - A lock file that cannot be created (read-only fs, missing dir) is NOT
//     an error for the proxy — it logs and runs unlocked (the lock is a
//     safety net, never a reason to refuse to serve) — but IS an error for
//     the restore side only when the lock is positively held.
func acquireDataDirLock(dataDir string) (release func(), err error) {
	path := filepath.Join(dataDir, dataDirLockName)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- operator-controlled data dir
	if err != nil {
		return nil, fmt.Errorf("open data-dir lock %s: %w", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, errDataDirLocked
		}
		return nil, fmt.Errorf("flock %s: %w", path, err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
