//go:build !windows

package main

import "syscall"

// diskUsage returns used %, free bytes, and total bytes for the filesystem
// holding path (Unix implementation via statfs(2)). It drives disk protection
// in logguard.go for the whole volume, not just the logs.
//
// The disk-protection orchestrator (logguard.go) is cross-platform, so the
// Windows build needs its own diskUsage (diskusage_windows.go, via
// GetDiskFreeSpaceEx) — statfs is undefined on Windows.
func diskUsage(path string) (usedPct float64, free, total uint64, err error) {
	var st syscall.Statfs_t
	if e := syscall.Statfs(path, &st); e != nil {
		return 0, 0, 0, e
	}
	bs := uint64(st.Bsize) // #nosec G115 -- block size is positive
	total = st.Blocks * bs
	free = st.Bavail * bs
	if total == 0 {
		return 0, free, total, nil
	}
	usedPct = float64(total-free) / float64(total) * 100
	return usedPct, free, total, nil
}
