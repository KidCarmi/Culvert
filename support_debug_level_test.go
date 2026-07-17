package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/support"
)

// TestDebugSetRequiresTTL is the mandatory-TTL security gate: an elevation can
// never be set without a positive, bounded TTL — at the engine and the API.
func TestDebugSetRequiresTTL(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })
	now := time.Unix(1_700_000_000, 0).UTC()

	// Engine: zero, negative, sub-floor, and over-cap TTLs are all refused, and
	// none of them persists an elevation.
	for _, ttl := range []time.Duration{0, -time.Minute, debugLevelMinTTL - time.Second, debugLevelMaxTTL + time.Second} {
		if _, err := setDebugLevel(support.L3, ttl, "tester", now); err == nil {
			t.Fatalf("setDebugLevel accepted out-of-bounds TTL %v", ttl)
		}
		if lvl := effectiveDebugLevel(now); lvl != debugLevelBaseline {
			t.Fatalf("refused set still elevated level to L%d", lvl)
		}
	}

	// A valid TTL is accepted and takes effect.
	if _, err := setDebugLevel(support.L3, 10*time.Minute, "tester", now); err != nil {
		t.Fatalf("valid set rejected: %v", err)
	}
	if lvl := effectiveDebugLevel(now); lvl != support.L3 {
		t.Fatalf("valid set did not elevate: L%d", lvl)
	}

	// API: POST without ttl_seconds is a 400 (mandatory TTL at the boundary).
	req := roleReq(RoleAdmin, http.MethodPost, "/api/support/debug-level", map[string]any{"level": 3})
	rec := httptest.NewRecorder()
	apiSupportDebugLevel(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST without ttl_seconds: code=%d want 400 (body=%q)", rec.Code, rec.Body.String())
	}
}

// TestDebugLevelAutoRevert proves an elevation reverts to baseline the instant the
// wall clock passes its expiry — computed on read, no timer required.
func TestDebugLevelAutoRevert(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })
	now := time.Unix(1_700_000_000, 0).UTC()

	if _, err := setDebugLevel(support.L4, 10*time.Minute, "tester", now); err != nil {
		t.Fatalf("set: %v", err)
	}
	if lvl := effectiveDebugLevel(now.Add(5 * time.Minute)); lvl != support.L4 {
		t.Fatalf("within window level=L%d want L4", lvl)
	}
	if lvl := effectiveDebugLevel(now.Add(10 * time.Minute)); lvl != debugLevelBaseline {
		t.Fatalf("at expiry level=L%d want baseline L%d", lvl, debugLevelBaseline)
	}
	if lvl := effectiveDebugLevel(now.Add(11 * time.Minute)); lvl != debugLevelBaseline {
		t.Fatalf("past expiry level=L%d want baseline", lvl)
	}
}

// TestDebugRevertsOnRestart proves the revert survives a process restart: an
// elevation persisted mid-window reads as baseline once the clock passes expiry,
// and the watchdog reclaims the stale file — all from the on-disk state alone, no
// in-memory timer carried across the "restart".
func TestDebugRevertsOnRestart(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })
	now := time.Unix(1_700_000_000, 0).UTC()

	if _, err := setDebugLevel(support.L2, 5*time.Minute, "tester", now); err != nil {
		t.Fatalf("set: %v", err)
	}
	// The state file exists on disk (would be read by a fresh process).
	if _, err := os.Stat(debugLevelStatePath()); err != nil {
		t.Fatalf("state not persisted: %v", err)
	}
	// Simulate a restart AFTER expiry: a fresh read computes baseline from the
	// persisted expiry — no elevation leaks across the restart.
	afterExpiry := now.Add(6 * time.Minute)
	if lvl := effectiveDebugLevel(afterExpiry); lvl != debugLevelBaseline {
		t.Fatalf("post-restart level=L%d want baseline", lvl)
	}
	// The watchdog tick reclaims the stale file and reports the revert once.
	expired, lvl := debugLevelWatchdogTick(afterExpiry)
	if !expired || lvl != int(support.L2) {
		t.Fatalf("watchdog tick expired=%v level=%d want true,2", expired, lvl)
	}
	if _, err := os.Stat(debugLevelStatePath()); !os.IsNotExist(err) {
		t.Fatalf("watchdog did not clear expired state (err=%v)", err)
	}
	// A second tick is a no-op (nothing to revert).
	if expired, _ := debugLevelWatchdogTick(afterExpiry); expired {
		t.Fatal("watchdog re-fired on already-cleared state")
	}
}

// TestDebugLevelClearRevertsImmediately proves DELETE/clear drops the elevation
// before its TTL.
func TestDebugLevelClearRevertsImmediately(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })
	now := time.Unix(1_700_000_000, 0).UTC()

	if _, err := setDebugLevel(support.L3, time.Hour, "tester", now); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := clearDebugLevel(); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if lvl := effectiveDebugLevel(now); lvl != debugLevelBaseline {
		t.Fatalf("after clear level=L%d want baseline", lvl)
	}
	// Clearing when nothing is set is not an error.
	if err := clearDebugLevel(); err != nil {
		t.Fatalf("idempotent clear: %v", err)
	}
}

// TestDebugLevelCorruptStateFailsClosed proves a corrupt state file yields
// baseline, never an elevated level.
func TestDebugLevelCorruptStateFailsClosed(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })
	if err := os.MkdirAll(debugLevelStatePath()[:len(debugLevelStatePath())-len("/debug_level.json")], 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(debugLevelStatePath(), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write corrupt: %v", err)
	}
	if lvl := effectiveDebugLevel(time.Unix(1_700_000_000, 0)); lvl != debugLevelBaseline {
		t.Fatalf("corrupt state level=L%d want baseline (fail-closed)", lvl)
	}
}
