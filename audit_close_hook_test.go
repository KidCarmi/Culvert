package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/audit"
)

// snapshotLateShutdownGlobals saves and zeroes every package-level handle
// that registerLateShutdownHooks can touch, then restores them on
// t.Cleanup. Without this, running the late registry in a test would
// close unrelated globals (syslog connection, community DB, request log
// file, etc.) that other tests in the same binary may depend on under
// -shuffle=on or -count=N.
//
// Zeroing each pointer turns its hook into a nil-guarded no-op, leaving
// only the audit-log-close hook live for the test to exercise. Callers
// configure the audit globals themselves after this returns.
//
// The startupState passed to registerLateShutdownHooks remains a fresh
// zero value (s.scanSvc, s.adminUISrv, s.socks5Srv, s.logCloser all
// nil), so those hooks already no-op without snapshotting.
func snapshotLateShutdownGlobals(t *testing.T) {
	t.Helper()

	// Audit engine state (internal/audit).
	restoreAudit := audit.ResetForTest()

	// Request log globals (store.go).
	oldReqWriter := requestLogWriter
	oldReqCloser := requestLogCloser
	oldReqPath := requestLogFilePath

	// Syslog (syslog.go).
	oldSyslog := globalSyslog

	// Community feed DB (catdb.go).
	oldCommunityDB := communityDB

	// Tunnel-drain hook polls this atomic counter. Snapshot defensively
	// so the test's drain returns immediately (active == 0) regardless of
	// what other tests left behind.
	oldActiveConns := atomic.LoadInt64(&activeConns)

	requestLogWriter = nil
	requestLogCloser = nil
	requestLogFilePath = ""

	globalSyslog = nil
	communityDB = nil
	atomic.StoreInt64(&activeConns, 0)

	t.Cleanup(func() {
		restoreAudit()

		requestLogWriter = oldReqWriter
		requestLogCloser = oldReqCloser
		requestLogFilePath = oldReqPath

		globalSyslog = oldSyslog
		communityDB = oldCommunityDB
		atomic.StoreInt64(&activeConns, oldActiveConns)
	})
}

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
	snapshotLateShutdownGlobals(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	if err := InitAuditLog(path); err != nil {
		t.Fatalf("InitAuditLog: %v", err)
	}
	if !audit.PersistActive() {
		t.Fatal("InitAuditLog did not wire the persistent closer")
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
	// All other late hooks no-op because snapshotLateShutdownGlobals
	// zeroed the globals they would otherwise touch.
	var late shutdownRegistry
	registerLateShutdownHooks(&late, &startupState{}, testInertHTTPServer())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := late.RunAll(ctx); err != nil {
		t.Fatalf("late.RunAll: %v", err)
	}

	// The persistent handle has just been closed by the hook. Clear it so
	// the snapshot cleanup / a later Close cannot double-close the *os.File.
	audit.ClearPersistForTest()

	// Read the file back from disk and assert our unique discriminator
	// was persisted.
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
	snapshotLateShutdownGlobals(t)

	var late shutdownRegistry
	registerLateShutdownHooks(&late, &startupState{}, testInertHTTPServer())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := late.RunAll(ctx); err != nil {
		t.Fatalf("late.RunAll with no audit persistence: %v", err)
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
