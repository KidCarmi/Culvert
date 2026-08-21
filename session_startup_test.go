package main

// session_startup_test.go — PR3 expansion Batch 2 coverage.

import (
	"bytes"
	"encoding/hex"
	"log"
	"os"
	"path/filepath"
	"strings"
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

// TestLoadSession_EnvSessionSecretWinsOverConfigFile guards the documented
// priority in session.go's initSessionSecret ("CULVERT_SESSION_SECRET env >
// config file > random") and in internal/session's package doc comment ("the
// startup wiring (env/config key priority — env is read in the startup shim
// per the slice convention)"). loadSession used to call
// initSessionSecretFromConfig unconditionally after initSessionSecret, so a
// non-empty config-file session_secret always won — even when
// CULVERT_SESSION_SECRET was already set — silently reversing the documented
// order. In a multi-node/HA deployment where every node sets
// CULVERT_SESSION_SECRET (CLAUDE.md "Key Environment Variables"; required on
// every node so sessions stay valid cluster-wide) but one node also carries a
// stale/mismatched session_secret in its config.yaml, that node would sign
// admin-UI cookies with a different key than its peers — with no
// operator-visible error.
func TestLoadSession_EnvSessionSecretWinsOverConfigFile(t *testing.T) {
	resetSessionStartupGlobals(t)
	ensureSessionStartupTestLogger(t)

	origKey := session.SigningKey()
	t.Cleanup(func() { session.SetSigningKey(origKey) })

	envHex := strings.Repeat("11", 32) // 32 bytes, test-only
	cfgHex := strings.Repeat("22", 32) // different 32 bytes, test-only
	t.Setenv("CULVERT_SESSION_SECRET", envHex)

	if err := loadSession(sessionStartupConfig{Secret: cfgHex}); err != nil {
		t.Fatalf("loadSession: %v", err)
	}

	want, err := hex.DecodeString(envHex)
	if err != nil {
		t.Fatalf("decode envHex: %v", err)
	}
	if got := session.SigningKey(); !bytes.Equal(got, want) {
		t.Errorf("signing key came from the config-file session_secret, not CULVERT_SESSION_SECRET env "+
			"(got %x, want %x) — violates the documented priority env > config file > random", got, want)
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
