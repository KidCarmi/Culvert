//go:build linux

package storeguard

import "os"

// FaultContainmentSupported reports whether ContainFault can establish that a
// fault came from the store's mappings on this platform, and so whether it ever
// contains one. It is true on Linux, the production deployment target
// (Docker/OVA), where /proc/self/maps is the source of truth.
const FaultContainmentSupported = true

// readProcMaps returns this process's memory map, which ContainFault uses to
// confirm a faulting address belongs to the store's mapped files.
func readProcMaps() ([]byte, error) {
	return os.ReadFile("/proc/self/maps")
}
