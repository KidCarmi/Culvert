package ops

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SweepOpLogs deletes per-operation transcript files under
// <stateDir>/operations/ whose mtime is older than maxAge, returning the count
// removed. This enforces LogRetentionDays: without it every async op leaves an
// <op_id>.log forever and the state dir fills over the agent's lifetime (which
// in turn arms the disk-full failures on the audit/journal write paths).
//
// Best-effort and non-fatal: a stat/remove error on one file is skipped, never
// returned, so a single unreadable entry can't block the sweep. A currently-
// running op's log has a fresh mtime and is far younger than any sane retention,
// so it is never swept. now is injected for tests.
func SweepOpLogs(stateDir string, maxAge time.Duration, now time.Time) int {
	if maxAge <= 0 {
		return 0
	}
	dir := filepath.Join(stateDir, "operations")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0 // no operations dir yet, or unreadable — nothing to sweep
	}
	cutoff := now.Add(-maxAge)
	removed := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".log") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			if err := os.Remove(filepath.Join(dir, e.Name())); err == nil {
				removed++
			}
		}
	}
	return removed
}
