package main

// logguard.go — production-grade log retention & disk-protection ORCHESTRATOR.
// The priority-aware deletion passes (CleanupBytes/deletePass) moved into
// internal/logstore with the engine (ADR-0002); this file keeps the policy:
// disk-usage checks, the critical-threshold override, emergency minimal mode
// (whose state the engine reads through the injected hook), audit recording,
// and the GUI status.
//
// Priority order (highest first):
//   1. Keep the proxy operational — all cleanup is bounded and never blocks the
//      request path (writes are async; cleanup runs on the janitor goroutine).
//   2. Prevent the disk reaching 100% — when overall disk usage crosses the
//      critical threshold, cleanup runs IMMEDIATELY and OVERRIDES the retention
//      period (delete logs even if younger than the configured age).
//   3. Enforce the max log-storage size — size-cap cleanup.
//   4. Respect the retention period — native per-key TTL (best effort).
//
// Cleanup removes LOW-priority entries (access/traffic, Level INFO/DEBUG) before
// HIGH-priority security entries (Level WARN/ERROR: threats, malware, auth
// failures, policy violations) whenever possible.
//
// Emergency mode: if cleanup cannot bring disk usage below the threshold (the
// disk is full from non-log data), the store switches to MINIMAL logging —
// access/traffic entries are no longer persisted, only security/system events —
// the app log level is raised, and a critical alert is emitted.

import (
	"fmt"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	defaultCriticalDiskPct = 95
	// diskRecoverMargin: after a critical cleanup, aim to get this many points
	// below the threshold (hysteresis) so we don't thrash at the boundary.
	diskRecoverMargin = 3
)

// criticalDiskPct is the admin-configurable critical disk-usage threshold (%).
var criticalDiskPct int64 = defaultCriticalDiskPct

func setCriticalDiskPct(p int) {
	switch {
	case p < 50:
		p = 50 // a very low threshold would thrash; floor it
	case p > 99:
		p = 99 // 100 would never trigger before the disk is actually full
	}
	atomic.StoreInt64(&criticalDiskPct, int64(p))
}

func getCriticalDiskPct() int { return int(atomic.LoadInt64(&criticalDiskPct)) }

// logGuard holds disk-protection runtime state for the GUI and audit trail.
var logGuard struct {
	mu            sync.Mutex
	lastCleanupMs int64
	lastReason    string
	pressureBytes int64 // cumulative bytes deleted due to disk/size pressure
	pressureCount int64 // cumulative entries deleted due to pressure
	warning       string
	priorLogLevel LogLevel
	minimal       atomic.Bool
}

// diskUsage returns used %, free bytes, and total bytes for the filesystem
// holding path. Used to drive disk protection (the whole volume, not just logs).
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

// fmtBytes renders a byte count for audit/log detail (server-side counterpart
// to the UI's humanBytes).
func fmtBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit && exp < 3; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGT"[exp])
}

// auditSystem records an automatic (non-user) action in the audit trail.
func auditSystem(action, object, detail string) {
	now := time.Now()
	auditAdd(AuditEntry{
		TS:     now.UnixMilli(),
		Time:   now.Format("2006-01-02 15:04:05"),
		Actor:  "system",
		Action: action,
		Object: object,
		Detail: detail,
	})
}

// recordPressureCleanup updates the guard counters, the last-cleanup marker, and
// emits the required audit event (timestamp, reason, disk usage, amount removed,
// categories affected). No-op when nothing was deleted.
func recordPressureCleanup(reason string, freed, count int64, levels map[string]int64) {
	if count == 0 {
		return
	}
	usedPct, _, _, _ := diskUsage(logStoreDir)
	logGuard.mu.Lock()
	logGuard.lastCleanupMs = time.Now().UnixMilli()
	logGuard.lastReason = reason
	logGuard.pressureBytes += freed
	logGuard.pressureCount += count
	logGuard.mu.Unlock()

	detail := fmt.Sprintf("reason=%q diskUsage=%.1f%% removed=%s entries=%d categories=%s",
		reason, usedPct, fmtBytes(freed), count, formatLevelBreakdown(levels))
	auditSystem("logstore.cleanup", "history", detail)
	logger.Printf("WARN LogGuard: cleanup (%s) removed %d entries (%s); disk %.1f%%",
		reason, count, fmtBytes(freed), usedPct)
}

func formatLevelBreakdown(levels map[string]int64) string {
	if len(levels) == 0 {
		return "none"
	}
	out := ""
	for _, lvl := range []string{"INFO", "DEBUG", "WARN", "ERROR"} {
		if n := levels[lvl]; n > 0 {
			if out != "" {
				out += ","
			}
			out += fmt.Sprintf("%s=%d", lvl, n)
		}
	}
	if out == "" {
		out = "other"
	}
	return out
}

// enterMinimalMode engages emergency minimal logging: stop persisting low-
// priority entries, raise the app log level, alert, and audit. Idempotent.
func enterMinimalMode(diskPct float64) {
	if logGuard.minimal.Swap(true) {
		return // already minimal
	}
	logGuard.mu.Lock()
	logGuard.priorLogLevel = GetLogLevel()
	logGuard.warning = fmt.Sprintf("Disk usage %.0f%% — EMERGENCY minimal logging: access/traffic logs are no longer being recorded (security events still are). Free disk space or reduce retention.", diskPct)
	logGuard.mu.Unlock()

	SetLogLevel(ParseLogLevel("warn")) // suppress debug/info app logs
	auditSystem("logstore.minimal_mode", "logging",
		fmt.Sprintf("ENABLED at diskUsage=%.1f%% — recording security/system events only", diskPct))
	go fireAlert("disk_critical", AlertPayload{
		Detail: fmt.Sprintf("disk usage %.0f%% — minimal logging engaged after cleanup could not free enough space", diskPct),
		Source: "logguard",
	})
	logger.Printf("ERROR LogGuard: EMERGENCY minimal logging mode engaged (disk %.0f%%)", diskPct)
}

// exitMinimalMode restores normal logging once the disk recovers. Idempotent.
func exitMinimalMode() {
	if !logGuard.minimal.Swap(false) {
		return // wasn't minimal
	}
	logGuard.mu.Lock()
	prior := logGuard.priorLogLevel
	logGuard.warning = ""
	logGuard.mu.Unlock()

	// Only restore the pre-minimal level if nothing changed it meanwhile. If an
	// admin set the log level during minimal mode, GetLogLevel() != the WARN we
	// forced on entry — honor the admin's choice instead of clobbering it.
	if GetLogLevel() == LevelWarn {
		SetLogLevel(prior)
	}
	auditSystem("logstore.minimal_mode", "logging", "DISABLED — disk recovered, normal logging resumed")
	logger.Printf("LogGuard: minimal logging mode cleared — normal logging resumed")
}

// minimalMode reports whether emergency minimal logging is active.
func minimalMode() bool { return logGuard.minimal.Load() }

// effectiveAdminLogLevel returns the log level that reflects the ADMIN's intent,
// for persistence in admin_settings.json. During emergency minimal mode the live
// level is forced to WARN; persisting that would clobber the admin's real
// preference on restart. So while minimal mode is active and the live level is
// still the forced WARN (the admin hasn't overridden it), we report the
// pre-minimal level instead. If the admin did change the level during minimal
// mode (live != WARN), that is their intent and we report it as-is — kept
// consistent with exitMinimalMode's restore heuristic.
func effectiveAdminLogLevel() LogLevel {
	if !logGuard.minimal.Load() {
		return GetLogLevel()
	}
	if live := GetLogLevel(); live != LevelWarn {
		return live // admin overrode the forced level during minimal mode
	}
	logGuard.mu.Lock()
	prior := logGuard.priorLogLevel
	logGuard.mu.Unlock()
	return prior
}

// runDiskGuard is one pass of the disk-protection janitor (priority order 2→3):
// disk-critical cleanup that overrides retention, then the size cap. Age TTL is
// enforced natively by Badger.
func runDiskGuard(s *logStore) {
	if s == nil {
		return
	}
	usedPct, _, total, err := diskUsage(logStoreDir)
	crit := float64(getCriticalDiskPct())

	switch {
	case err == nil && usedPct >= crit:
		handleDiskCritical(s, usedPct, float64(total), crit)
	case err == nil:
		exitMinimalMode() // disk healthy
	}

	// (3) Enforce the max log-storage size (priority-aware). The engine
	// returns what it cleaned; recording the audit/pressure event is main's
	// job (the engine owns deletion, main owns observability state).
	if freed, count, levels := s.RunRetention(); count > 0 {
		recordPressureCleanup("max log storage exceeded", freed, count, levels)
	}

	// Clear a stale warning once the disk is healthy and not in minimal mode.
	logGuard.mu.Lock()
	if usedPct < crit-diskRecoverMargin && !logGuard.minimal.Load() {
		logGuard.warning = ""
	}
	logGuard.mu.Unlock()
}

// handleDiskCritical runs the disk-critical cleanup (priority 2): it overrides
// retention to free space, then re-checks — if logs can't bring the disk back
// under the threshold it engages emergency minimal mode, otherwise it posts the
// operator warning. Caller has confirmed usedPct >= crit.
func handleDiskCritical(s *logStore, usedPct, total, crit float64) {
	// Free enough to drop the whole volume to (crit - margin). Cap the target at
	// the logstore's own size — we can only ever delete our own logs, so when the
	// disk is full from non-log data this avoids an unreachable target (and
	// wasteful empty scans once our logs are gone; the re-check then trips
	// minimal mode).
	targetUsed := (crit - diskRecoverMargin) / 100 * total
	need := int64(usedPct/100*total - targetUsed)
	if own := s.BytesUsed(); need > own {
		need = own
	}
	if need > 0 {
		freed, count, levels := s.CleanupBytes(need)
		recordPressureCleanup("critical disk usage (overrides retention)", freed, count, levels)
	}
	// Re-check: if still critical, deleting logs can't fix it (disk full from
	// non-log data) → emergency minimal mode. Otherwise post a warning.
	if again, _, _, e2 := diskUsage(logStoreDir); e2 == nil && again >= crit {
		enterMinimalMode(again)
		return
	}
	exitMinimalMode()
	logGuard.mu.Lock()
	logGuard.warning = fmt.Sprintf("Disk usage reached %.0f%%. Old logs were deleted before the configured retention period expired. Consider expanding disk capacity or reducing retention settings.", usedPct)
	logGuard.mu.Unlock()
}

// diskGuardStatus is the GUI/status snapshot of disk protection.
func diskGuardStatus() map[string]any {
	usedPct, free, total, err := diskUsage(logStoreDir)
	logGuard.mu.Lock()
	st := map[string]any{
		"criticalDiskPct":   getCriticalDiskPct(),
		"minimalMode":       logGuard.minimal.Load(),
		"loggingMode":       map[bool]string{true: "Minimal", false: "Normal"}[logGuard.minimal.Load()],
		"lastCleanupMs":     logGuard.lastCleanupMs,
		"lastCleanupReason": logGuard.lastReason,
		"pressureBytes":     logGuard.pressureBytes,
		"pressureCount":     logGuard.pressureCount,
		"warning":           logGuard.warning,
	}
	logGuard.mu.Unlock()
	if err == nil {
		st["diskUsedPct"] = usedPct
		st["diskFreeBytes"] = free
		st["diskTotalBytes"] = total
	}
	return st
}
