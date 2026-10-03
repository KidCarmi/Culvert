//go:build linux

package server

import "syscall"

// statfsFreeBytes returns the bytes available to unprivileged writers on
// the filesystem holding path (Bavail — what a non-root pull would see is
// irrelevant here, but Bavail is also what df reports as "Avail").
func statfsFreeBytes(path string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return st.Bavail * uint64(st.Bsize), nil //nolint:gosec // Bsize is positive
}
