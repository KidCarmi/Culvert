package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/logstore"
)

// TestSetCriticalDiskPct_Clamps verifies the threshold is floored at 50 and
// capped at 99 so the guard never thrashes (too low) or never fires (100).
func TestSetCriticalDiskPct_Clamps(t *testing.T) {
	orig := getCriticalDiskPct()
	t.Cleanup(func() { setCriticalDiskPct(orig) })

	cases := []struct{ in, want int }{
		{10, 50}, {49, 50}, {50, 50}, {75, 75}, {99, 99}, {100, 99}, {1000, 99},
	}
	for _, c := range cases {
		setCriticalDiskPct(c.in)
		if got := getCriticalDiskPct(); got != c.want {
			t.Errorf("setCriticalDiskPct(%d) → %d, want %d", c.in, got, c.want)
		}
	}
}

// TestLogEntryLowPriority pins the security-vs-traffic classification that drives
// priority-aware cleanup: WARN/ERROR are HIGH priority (kept), everything else
// is LOW priority (deleted first).
func TestFmtBytes(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{0, "0 B"}, {512, "512 B"}, {1024, "1.0 KB"},
		{1536, "1.5 KB"}, {1 << 20, "1.0 MB"}, {1 << 30, "1.0 GB"},
	}
	for _, c := range cases {
		if got := fmtBytes(c.in); got != c.want {
			t.Errorf("fmtBytes(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestDiskUsage sanity-checks the Statfs wrapper against a real directory.
func TestDiskUsage(t *testing.T) {
	dir := t.TempDir()
	usedPct, free, total, err := diskUsage(dir)
	if err != nil {
		t.Fatalf("diskUsage: %v", err)
	}
	if total == 0 {
		t.Fatal("total bytes = 0")
	}
	if free > total {
		t.Fatalf("free %d > total %d", free, total)
	}
	if usedPct < 0 || usedPct > 100 {
		t.Fatalf("usedPct %.2f out of range", usedPct)
	}
}

// newTestLogStore opens an unencrypted store directly (no janitor goroutine),
// wired to the real minimal-mode state like production's openLogStore, so the
// minimal-mode test drives the logguard state through Add.
func newTestLogStore(t *testing.T) *logStore {
	t.Helper()
	s, err := logstore.OpenTTL(t.TempDir(), 0, 0, nil, minimalMode)
	if err != nil {
		t.Fatalf("logstore.OpenTTL: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestMinimalMode_DropsLowPriority verifies emergency minimal mode stops
// persisting access/traffic logs while still recording security events.
func TestMinimalMode_DropsLowPriority(t *testing.T) {
	isolateLogRing(t)
	s := newTestLogStore(t)

	enterMinimalMode(99)
	t.Cleanup(exitMinimalMode)
	if !minimalMode() {
		t.Fatal("expected minimal mode active")
	}

	base := time.Now().UnixMilli()
	s.Add(LogEntry{TS: base, Level: "INFO", Host: "traffic.com"})   // should drop
	s.Add(LogEntry{TS: base + 1, Level: "WARN", Host: "block.com"}) // should persist
	s.Add(LogEntry{TS: base + 2, Level: "ERROR", Host: "auth.com"}) // should persist

	got := drainLogStore(t, s, 2)
	for i := range got {
		if logEntryLowPriority(got[i].Level) {
			t.Errorf("low-priority entry persisted in minimal mode: %+v", got[i])
		}
	}

	exitMinimalMode()
	if minimalMode() {
		t.Fatal("expected minimal mode cleared")
	}
}

// TestEnterExitMinimalMode_RestoresLogLevel ensures the app log level is raised
// to warn on entry and restored on exit.
func TestEnterExitMinimalMode_RestoresLogLevel(t *testing.T) {
	orig := GetLogLevel()
	t.Cleanup(func() { SetLogLevel(orig); exitMinimalMode() })

	SetLogLevel(ParseLogLevel("debug"))
	enterMinimalMode(99)
	if GetLogLevel() != ParseLogLevel("warn") {
		t.Errorf("expected log level warn in minimal mode, got %v", GetLogLevel())
	}
	exitMinimalMode()
	if GetLogLevel() != ParseLogLevel("debug") {
		t.Errorf("expected log level restored to debug, got %v", GetLogLevel())
	}
}

// TestExitMinimalMode_PreservesAdminLogLevelChange proves that if an admin sets
// the log level WHILE minimal mode is active, exiting minimal mode does not
// clobber the admin's choice (it only restores the pre-minimal level when the
// level is still the WARN that entry forced).
func TestExitMinimalMode_PreservesAdminLogLevelChange(t *testing.T) {
	orig := GetLogLevel()
	t.Cleanup(func() { SetLogLevel(orig); exitMinimalMode() })

	SetLogLevel(ParseLogLevel("debug")) // pre-minimal level
	enterMinimalMode(99)
	if GetLogLevel() != LevelWarn {
		t.Fatalf("entry should force warn, got %v", GetLogLevel())
	}
	// Admin changes the level during minimal mode.
	SetLogLevel(ParseLogLevel("error"))
	exitMinimalMode()
	if GetLogLevel() != ParseLogLevel("error") {
		t.Errorf("admin's error level was clobbered on exit, got %v", GetLogLevel())
	}
}

// TestEffectiveAdminLogLevel_NotForcedWarn proves the level persisted to
// admin_settings.json reflects the admin's real preference, not the WARN that
// minimal mode forces — so a restart during disk pressure doesn't lose it.
func TestEffectiveAdminLogLevel_NotForcedWarn(t *testing.T) {
	orig := GetLogLevel()
	t.Cleanup(func() { SetLogLevel(orig); exitMinimalMode() })

	// Admin prefers DEBUG; disk goes critical and minimal mode forces WARN.
	SetLogLevel(ParseLogLevel("debug"))
	enterMinimalMode(99)
	if GetLogLevel() != LevelWarn {
		t.Fatalf("entry should force warn live, got %v", GetLogLevel())
	}
	// Persistence must capture the admin's DEBUG, not the forced WARN.
	if got := effectiveAdminLogLevel(); got != ParseLogLevel("debug") {
		t.Errorf("effectiveAdminLogLevel = %v during minimal mode, want debug (admin's pref)", got)
	}
	// If the admin overrides to ERROR during minimal mode, that is their intent.
	SetLogLevel(ParseLogLevel("error"))
	if got := effectiveAdminLogLevel(); got != ParseLogLevel("error") {
		t.Errorf("effectiveAdminLogLevel = %v after admin override, want error", got)
	}
	exitMinimalMode()
	// Outside minimal mode it just mirrors the live level.
	if got := effectiveAdminLogLevel(); got != ParseLogLevel("error") {
		t.Errorf("effectiveAdminLogLevel = %v outside minimal mode, want error", got)
	}
}

// TestApiLogsRetention_EmptyBodyAudits proves an all-nil PUT does NOT take the
// settings-only no-audit early return: with the store off it returns 409 (not a
// silent 2xx), so AuditExpected stays honest.
func TestApiLogsRetention_EmptyBodyAudits(t *testing.T) {
	oldStore := globalLogStore.Swap(nil)
	t.Cleanup(func() { globalLogStore.Store(oldStore) })

	rec := httptest.NewRecorder()
	apiLogsRetention(rec, adminReq(http.MethodPut, "/api/logs/retention", `{}`))
	if rec.Code != 409 {
		t.Errorf("empty PUT with store off: status %d, want 409 (must not be a silent 2xx)", rec.Code)
	}
}

// TestRecordPressureCleanup_Audits verifies an audit event is emitted with the
// required fields (reason, disk usage, removed amount, categories). Asserts on
// entry content, not ring length (audit ring saturates under -shuffle).
func TestRecordPressureCleanup_Audits(t *testing.T) {
	baseline := time.Now().UnixMilli()
	levels := map[string]int64{"INFO": 5, "WARN": 2}
	recordPressureCleanup("unit-test reason", 4096, 7, levels)

	found := false
	for _, e := range auditGet() {
		if e.TS < baseline || e.Action != "logstore.cleanup" {
			continue
		}
		if strings.Contains(e.Detail, "unit-test reason") &&
			strings.Contains(e.Detail, "removed=") &&
			strings.Contains(e.Detail, "entries=7") &&
			strings.Contains(e.Detail, "categories=") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected logstore.cleanup audit event with reason/removed/entries/categories")
	}
}

// TestRecordPressureCleanup_NoopOnZero ensures no audit/counters move when
// nothing was deleted.
func TestRecordPressureCleanup_NoopOnZero(t *testing.T) {
	before := logGuard.pressureCount
	recordPressureCleanup("nothing", 0, 0, nil)
	if logGuard.pressureCount != before {
		t.Errorf("pressureCount changed on zero-count cleanup: %d → %d", before, logGuard.pressureCount)
	}
}

func TestFormatLevelBreakdown(t *testing.T) {
	if got := formatLevelBreakdown(nil); got != "none" {
		t.Errorf("nil breakdown = %q, want none", got)
	}
	got := formatLevelBreakdown(map[string]int64{"INFO": 3, "ERROR": 1})
	if !strings.Contains(got, "INFO=3") || !strings.Contains(got, "ERROR=1") {
		t.Errorf("breakdown %q missing expected counts", got)
	}
}

// TestDiskGuardStatus_Keys verifies the GUI status snapshot exposes the keys the
// front-end renders.
func TestDiskGuardStatus_Keys(t *testing.T) {
	st := diskGuardStatus()
	for _, k := range []string{"criticalDiskPct", "minimalMode", "loggingMode", "lastCleanupMs", "lastCleanupReason", "pressureBytes", "pressureCount", "warning"} {
		if _, ok := st[k]; !ok {
			t.Errorf("diskGuardStatus missing key %q", k)
		}
	}
	if st["loggingMode"] != "Normal" && st["loggingMode"] != "Minimal" {
		t.Errorf("loggingMode = %v, want Normal/Minimal", st["loggingMode"])
	}
}

// TestRunDiskGuard_HealthyDoesNotEnterMinimal exercises the janitor pass on a
// healthy disk: it must not engage minimal mode and must still run the size cap
// without panicking. The disk measurement is injected via diskUsageFn so the
// assertion is on the guard LOGIC, not the runner's real unprivileged free space
// (statfs Bavail) — a disk-starved CI runner or sandbox can legitimately report a
// tempdir above the critical threshold, which is environmental, not a bug.
func TestRunDiskGuard_HealthyDoesNotEnterMinimal(t *testing.T) {
	isolateLogRing(t)
	s := newTestLogStore(t)
	oldDir := logStoreDir
	logStoreDir = t.TempDir()
	oldDiskUsage := diskUsageFn
	diskUsageFn = func(string) (float64, uint64, uint64, error) {
		return 10.0, 90 << 30, 100 << 30, nil // healthy: 10% used, well below 95%
	}
	t.Cleanup(func() { diskUsageFn = oldDiskUsage; logStoreDir = oldDir; exitMinimalMode() })

	runDiskGuard(s)
	if minimalMode() {
		t.Error("healthy disk should not engage minimal mode")
	}
}

// TestApiLogsRetention_ThresholdOnly verifies a settings-only PUT updates the
// critical threshold without requiring the store to be enabled, and persists it.
func TestApiLogsRetention_ThresholdOnly(t *testing.T) {
	orig := getCriticalDiskPct()
	oldStore := globalLogStore.Swap(nil)
	t.Cleanup(func() { setCriticalDiskPct(orig); globalLogStore.Store(oldStore) })

	rec := httptest.NewRecorder()
	apiLogsRetention(rec, adminReq(http.MethodPut, "/api/logs/retention", `{"criticalDiskPct":88}`))
	if rec.Code != 200 {
		t.Fatalf("PUT threshold: status %d body %s", rec.Code, rec.Body.String())
	}
	if getCriticalDiskPct() != 88 {
		t.Errorf("threshold = %d, want 88", getCriticalDiskPct())
	}
}

// TestApiLogsRetention_ThresholdRejectsOutOfRange verifies validation bounds.
func TestApiLogsRetention_ThresholdRejectsOutOfRange(t *testing.T) {
	orig := getCriticalDiskPct()
	t.Cleanup(func() { setCriticalDiskPct(orig) })
	for _, bad := range []string{`{"criticalDiskPct":49}`, `{"criticalDiskPct":100}`} {
		rec := httptest.NewRecorder()
		apiLogsRetention(rec, adminReq(http.MethodPut, "/api/logs/retention", bad))
		if rec.Code != 400 {
			t.Errorf("body %s: status %d, want 400", bad, rec.Code)
		}
	}
}

// TestAdminSettings_PersistsThreshold round-trips the threshold through the
// admin-settings save/apply path.
func TestAdminSettings_PersistsThreshold(t *testing.T) {
	orig := getCriticalDiskPct()
	t.Cleanup(func() { setCriticalDiskPct(orig) })

	setCriticalDiskPct(77)
	var s AdminSettings
	s.LogCriticalDiskPct = getCriticalDiskPct()
	if s.LogCriticalDiskPct != 77 {
		t.Fatalf("captured %d, want 77", s.LogCriticalDiskPct)
	}
	// Apply a different stored value and confirm it takes effect.
	s.LogCriticalDiskPct = 82
	applyAdminServices(&s)
	if getCriticalDiskPct() != 82 {
		t.Errorf("applyAdminServices: threshold = %d, want 82", getCriticalDiskPct())
	}
}
