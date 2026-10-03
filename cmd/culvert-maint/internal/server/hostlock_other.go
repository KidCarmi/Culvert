//go:build !linux

package server

const hostMaintenanceLockName = "host-maintenance.lock"

func acquireHostMaintenanceLock(string) (release func(), busy bool, err error) {
	return func() {}, false, nil
}
