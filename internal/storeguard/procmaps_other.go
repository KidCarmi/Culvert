//go:build !linux

package storeguard

import "errors"

// readProcMaps has no source of truth off Linux, so a fault's origin cannot be
// established and ContainFault re-panics (fail closed). Culvert ships on Linux
// only; this keeps the package building on other platforms.
func readProcMaps() ([]byte, error) {
	return nil, errors.New("process memory map is not observable on this platform")
}
