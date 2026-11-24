//go:build linux

package main

// restore_layout_linux.go — what the restore commit needs to know about the
// filesystem before it picks a swap. See restore_inplace.go.

import (
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// restoreMountinfoPath is where the mount table is read from. Variable so a
// test can supply one.
var restoreMountinfoPath = "/proc/self/mountinfo"

// restoreDirIsMountPoint reports whether abs is a mount point. A bind mount of
// a directory on the same filesystem keeps the device number, so the mount
// table is the authority and the device comparison only the fallback.
func restoreDirIsMountPoint(abs string) bool {
	if body, err := os.ReadFile(restoreMountinfoPath); err == nil { // #nosec G304 -- a fixed procfs path
		for _, line := range strings.Split(string(body), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 4 && unescapeMountinfo(fields[4]) == abs {
				return true
			}
		}
		return false
	}
	var self, parent unix.Stat_t
	if unix.Lstat(abs, &self) != nil || unix.Lstat(abs+"/..", &parent) != nil {
		return false
	}
	return self.Dev != parent.Dev
}

// unescapeMountinfo undoes the octal escapes the kernel applies to a mount
// point (space, tab, newline, backslash).
func unescapeMountinfo(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(s)
}

// restoreDirWritable reports whether this process may create entries in dir.
func restoreDirWritable(dir string) bool {
	return unix.Access(dir, unix.W_OK|unix.X_OK) == nil
}

// restoreFreeBytes returns the space an unprivileged process may still use on
// dir's filesystem.
func restoreFreeBytes(dir string) (uint64, bool) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil || st.Bsize <= 0 {
		return 0, false
	}
	return st.Bavail * uint64(st.Bsize), true // #nosec G115 -- Bsize checked positive above
}
