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
// isRunning guards against reaping an IN-FLIGHT op's log: an op still running is
// skipped regardless of mtime, because a long-silent stage (or a retention
// shorter than operation_timeout) could otherwise age its log past the cutoff,
// and /v1/operations/{id}/logs reopens by path — deleting it would lose the
// transcript for exactly the op an operator is inspecting. May be nil (skip the
// guard) for callers with no live-op view, e.g. a pure startup sweep before any
// op could be admitted.
//
// Best-effort and non-fatal: a stat/remove error on one file is skipped, never
// returned, so a single unreadable entry can't block the sweep. now is injected
// for tests.
func SweepOpLogs(stateDir string, maxAge time.Duration, now time.Time, isRunning func(opID string) bool) int {
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
		// Never sweep the log of a still-running op (path-reopened by the logs
		// endpoint). The filename is "<op_id>.log".
		if isRunning != nil && isRunning(strings.TrimSuffix(e.Name(), ".log")) {
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
