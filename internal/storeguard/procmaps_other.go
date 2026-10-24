//go:build !linux

package storeguard

import "errors"

// FaultContainmentSupported is false off Linux: runtime fault containment is
// deliberately Linux-only. Off Linux, ContainFault cannot establish that a
// fault came from the store's mappings, so it re-panics every fault (fail
// closed), which is the same behaviour as before containment existed. A
// per-platform mapping verifier (mach vm_region, VirtualQuery) would be
// platform code CI cannot exercise, for platforms production does not deploy
// on. Callers surface this constant so an operator on such a build is not told
// a containment exists that does not.
const FaultContainmentSupported = false

// readProcMaps has no source of truth off Linux, so a fault's origin cannot be
// established and ContainFault re-panics (fail closed).
func readProcMaps() ([]byte, error) {
	return nil, errors.New("process memory map is not observable on this platform")
}
