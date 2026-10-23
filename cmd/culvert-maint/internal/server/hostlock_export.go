package server

// AcquireHostMaintenanceLock exposes the host maintenance flock to offline
// tooling in this binary (release-trust recovery), so an offline repair can
// never run concurrently with an agent operation or `culvert-os-update`.
// Semantics are exactly acquireHostMaintenanceLock's.
func AcquireHostMaintenanceLock(stateDir string) (release func(), busy bool, err error) {
	return acquireHostMaintenanceLock(stateDir)
}

// HostMaintenanceLockName is the lock file's name under the state dir.
const HostMaintenanceLockName = hostMaintenanceLockName
