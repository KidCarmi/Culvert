//go:build windows

package main

import "golang.org/x/sys/windows"

// diskUsage returns used %, free bytes, and total bytes for the volume holding
// path (Windows implementation via GetDiskFreeSpaceEx). The Windows build is a
// compile/CLI convenience target only — Culvert ships as a Linux Docker
// appliance — but the disk-protection orchestrator (logguard.go) is
// cross-platform, so it needs a working diskUsage on every target.
//
// GetDiskFreeSpaceEx accepts any path on the volume (a directory, which is what
// the disk-guard passes); it reports the caller-available free bytes and the
// volume total, matching the statfs semantics used by the Unix build.
func diskUsage(path string) (usedPct float64, free, total uint64, err error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, 0, 0, err
	}
	var freeToCaller, totalBytes, totalFree uint64
	if e := windows.GetDiskFreeSpaceEx(p, &freeToCaller, &totalBytes, &totalFree); e != nil {
		return 0, 0, 0, e
	}
	total = totalBytes
	free = freeToCaller
	if total == 0 {
		return 0, free, total, nil
	}
	usedPct = float64(total-free) / float64(total) * 100
	return usedPct, free, total, nil
}
