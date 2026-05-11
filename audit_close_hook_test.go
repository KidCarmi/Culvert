package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestAuditLogCloseHook_RoundTrip exercises the audit-log-close hook end to
// end: write one entry with a unique discriminator, run the late shutdown
// registry, then read the file and assert the discriminator is present.
//
// Verifies P3.3 / S7: the audit-log file descriptor is released as part of
// the late shutdown phase. ARCH_DISCOVERY Risk #6.
//
// Per CLAUDE.md "Test-authoring pitfalls": asserts on entry CONTENT via a
// unique discriminator, never on len(auditGet()) deltas. The discriminator
// (Actor IP from TEST-NET-2 reserved range 198.51.100.0/24, plus a
// timestamp-suffixed Action) makes the entry uniquely identifiable across
// shuffled cumulative runs.
func TestAuditLogCloseHook_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	// Snapshot audit globals and restore on cleanup so this test is safe
	// under -shuffle=on and -count=N.
	oldFile := auditLogFile
	oldCloser := auditCloser
	oldPath := auditLogFilePath
	oldLog := auditLog
	auditLogFile = nil
	auditCloser = nil
	auditLogFilePath = ""
	auditMu.Lock()
	auditLog = nil
	auditMu.Unlock()
	t.Cleanup(func() {
		if auditCloser != nil {
			_ = auditCloser.Close()
		}
		auditLogFile = oldFile
		auditCloser = oldCloser
		auditLogFilePath = oldPath
		auditMu.Lock()
		auditLog = oldLog
		auditMu.Unlock()
	})

	if err := InitAuditLog(path); err != nil {
		t.Fatalf("InitAuditLog: %v", err)
	}
	if auditCloser == nil {
		t.Fatal("InitAuditLog did not set auditCloser")
	}

	// Unique discriminator: TEST-NET-2 reserved IP + per-run nanosecond
	// suffix. This entry will be visible both in the in-memory ring and on
	// disk; we assert on its on-disk content after the hook runs.
	discriminator := fmt.Sprintf("p3-3-audit-close.write-%d", time.Now().UnixNano())
	entry := AuditEntry{
		TS:     time.Now().UnixMilli(),
		Time:   time.Now().UTC().Format("2006-01-02 15:04:05"),
		Actor:  "198.51.100.42",
		Action: discriminator,
		Object: "p3-3-test-object",
		Detail: "audit-log-close hook round-trip",
	}
	auditAdd(entry)

	// Run the late shutdown hooks. The audit-log-close hook is in the
	// late registry between request-log-close (130) and log-closer (140).
	var late shutdownRegistry
	registerLateShutdownHooks(&late, &startupState{}, testInertHTTPServer())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := late.RunAll(ctx); err != nil {
		t.Fatalf("late.RunAll: %v", err)
	}

	// File handle should now be closed. Read the file back from disk and
	// assert our unique discriminator was persisted.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit log after shutdown: %v", err)
	}
	if !bytes.Contains(data, []byte(discriminator)) {
		t.Fatalf("audit log file did not contain discriminator %q; got %d bytes:\n%s",
			discriminator, len(data), truncForLog(data))
	}
}

// TestAuditLogCloseHook_NilCloserIsNoOp verifies the hook is safe when no
// audit log was configured at startup (path was empty). The registry must
// still run all hooks without panicking.
func TestAuditLogCloseHook_NilCloserIsNoOp(t *testing.T) {
	oldFile := auditLogFile
	oldCloser := auditCloser
	oldPath := auditLogFilePath
	auditLogFile = nil
	auditCloser = nil
	auditLogFilePath = ""
	t.Cleanup(func() {
		auditLogFile = oldFile
		auditCloser = oldCloser
		auditLogFilePath = oldPath
	})

	var late shutdownRegistry
	registerLateShutdownHooks(&late, &startupState{}, testInertHTTPServer())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := late.RunAll(ctx); err != nil {
		t.Fatalf("late.RunAll with nil auditCloser: %v", err)
	}
}

func truncForLog(b []byte) string {
	const maxLen = 256
	s := string(b)
	if len(s) > maxLen {
		return s[:maxLen] + "…"
	}
	return strings.TrimSpace(s)
}
