//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"culvert-maint/internal/server"
)

// acquireRecoveryHostLock takes the shared host maintenance flock. Recovery
// runs as root, so when the lock file does not exist yet it is created here
// with the state directory's ownership — a root-owned 0640 file would be
// unopenable by the (non-root) agent afterwards.
func acquireRecoveryHostLock(stateDir string) (release func(), busy bool, err error) {
	p := filepath.Join(stateDir, server.HostMaintenanceLockName)
	if _, err := os.Lstat(p); errors.Is(err, os.ErrNotExist) {
		fi, err := os.Lstat(stateDir)
		if err != nil {
			return nil, false, err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || !fi.IsDir() {
			return nil, false, errors.New("state_dir is not a directory")
		}
		f, err := os.OpenFile(p, os.O_RDONLY|os.O_CREATE|os.O_EXCL, 0o640) //nolint:gosec // fixed name under the agent state dir
		if err != nil {
			return nil, false, err
		}
		cerr := f.Chown(int(st.Uid), int(st.Gid))
		_ = f.Close()
		if cerr != nil {
			return nil, false, cerr
		}
	}
	return server.AcquireHostMaintenanceLock(stateDir)
}
