package main

// session_startup_test.go — PR3 expansion Batch 2 coverage.

import (
	"log"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/session"
)

var sessionStartupLoggerMu sync.Mutex

func ensureSessionStartupTestLogger(t *testing.T) {
	t.Helper()
	sessionStartupLoggerMu.Lock()
	defer sessionStartupLoggerMu.Unlock()
	if logger == nil {
		logger = log.New(os.Stderr, "[test] ", 0)
	}
}

// resetSessionStartupGlobals snapshots/restores the revocations path and
// session TTL for isolation under -shuffle.
func resetSessionStartupGlobals(t *testing.T) {
	t.Helper()
	origPath := session.RevocationsPath()
	origTTL := session.TTL()
	t.Cleanup(func() {
		session.SetRevocationsPath(origPath)
		session.SetTTL(origTTL)
	})
}

func TestResolveSessionStartupConfig_CLIWinsOverFileConfig(t *testing.T) {
	fc := &FileConfig{SessionSecret: "cfg-secret", SessionTimeoutHours: 5}
	got := resolveSessionStartupConfig(fc, "/cli/revs.json", 12)
	if got.Secret != "cfg-secret" {
		t.Errorf("Secret: got %q", got.Secret)
	}
	if got.RevocationsFile != "/cli/revs.json" {
		t.Errorf("RevocationsFile: got %q", got.RevocationsFile)
	}
	if got.TimeoutHours != 12 {
		t.Errorf("TimeoutHours: expected 12 (CLI wins); got %d", got.TimeoutHours)
	}
}

func TestResolveSessionStartupConfig_FallbackToFileConfig(t *testing.T) {
	fc := &FileConfig{SessionTimeoutHours: 7}
	got := resolveSessionStartupConfig(fc, "", 0)
	if got.TimeoutHours != 7 {
		t.Errorf("TimeoutHours: expected fc fallback 7; got %d", got.TimeoutHours)
	}
	if got.RevocationsFile != "" {
		t.Errorf("RevocationsFile: expected empty; got %q", got.RevocationsFile)
	}
}

func TestResolveSessionStartupConfig_AllEmpty(t *testing.T) {
	got := resolveSessionStartupConfig(&FileConfig{}, "", 0)
	if got.Secret != "" || got.RevocationsFile != "" || got.TimeoutHours != 0 {
		t.Errorf("expected zero-value; got %+v", got)
	}
}

func TestLoadSession_AppliesTTL(t *testing.T) {
	resetSessionStartupGlobals(t)
	ensureSessionStartupTestLogger(t)
	if err := loadSession(sessionStartupConfig{TimeoutHours: 3}); err != nil {
		t.Fatalf("loadSession: %v", err)
	}
	if got := getSessionTTL(); got != 3*time.Hour {
		t.Errorf("TTL not applied; got %v", got)
	}
}

func TestLoadSession_SkipsRevocationsWhenFileEmpty(t *testing.T) {
	resetSessionStartupGlobals(t)
	ensureSessionStartupTestLogger(t)
	session.SetRevocationsPath("should-not-be-overwritten")
	if err := loadSession(sessionStartupConfig{}); err != nil {
		t.Fatalf("loadSession: %v", err)
	}
	if got := session.RevocationsPath(); got != "should-not-be-overwritten" {
		t.Errorf("revocations path changed unexpectedly; got %q", got)
	}
}

func TestLoadSession_LoadsRevocationsFromFile(t *testing.T) {
	resetSessionStartupGlobals(t)
	ensureSessionStartupTestLogger(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "revs.json")
	// Absent file is non-fatal for LoadRevocations (treated as first run).
	if err := loadSession(sessionStartupConfig{RevocationsFile: path}); err != nil {
		t.Fatalf("loadSession: %v", err)
	}
	if got := session.RevocationsPath(); got != path {
		t.Errorf("revocations path: got %q, want %q", got, path)
	}
}
