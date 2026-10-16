//go:build linux

package storeguard

import "os"

// readProcMaps returns this process's memory map, which ContainFault uses to
// confirm a faulting address belongs to the store's mapped files.
func readProcMaps() ([]byte, error) {
	return os.ReadFile("/proc/self/maps")
}
