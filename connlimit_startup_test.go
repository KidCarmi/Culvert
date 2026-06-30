package main

// connlimit_startup_test.go — P4.2 / S1 coverage for the extracted
// conn-limit + IP-filter + rate-limit startup slice.
//
// Resolver tests are pure (no globals touched). Loader tests
// snapshot/restore the package-level connLimiter, ipf, rl globals
// via t.Cleanup so they are safe under -shuffle=on / -count=2.
// The cleanup goroutine in the loader-with-rate-limit test is
// parented to a per-test cancellable context (never the package-
// global appLifecycleCtx).

import (
	"context"
	"log"
	"os"
	"sync"
	"testing"
	"time"
)

var connlimitStartupLoggerMu sync.Mutex

func ensureConnlimitStartupTestLogger(t *testing.T) {
	t.Helper()
	connlimitStartupLoggerMu.Lock()
	defer connlimitStartupLoggerMu.Unlock()
	if logger == nil {
		logger = log.New(os.Stderr, "[test] ", 0)
	}
}

// snapshotConnAndRateLimitGlobals saves and resets the three
// package-level limiters touched by the loader and restores them on
// t.Cleanup. Without this, loader tests would leak state into the
// rest of the suite under -shuffle=on / -count=2.
func snapshotConnAndRateLimitGlobals(t *testing.T) {
	t.Helper()
	oldConnLimiter := connLimiter
	oldIPF := ipf
	oldRL := rl

	connLimiter = newConnLimiter()
	ipf = &IPFilter{single: map[string]bool{}}
	rl = newRateLimiter()

	t.Cleanup(func() {
		connLimiter = oldConnLimiter
		ipf = oldIPF
		rl = oldRL
	})
}

// ─── Resolver ────────────────────────────────────────────────────────

func TestResolveConnAndRateLimitStartupConfig_Defaults(t *testing.T) {
	got := resolveConnAndRateLimitStartupConfig(&FileConfig{}, "", 0)
	if got.MaxConnsPerIP != 0 {
		t.Errorf("MaxConnsPerIP = %d; want 0", got.MaxConnsPerIP)
	}
	if got.IPMode != "" {
		t.Errorf("IPMode = %q; want empty", got.IPMode)
	}
	if got.IPList != nil {
		t.Errorf("IPList = %v; want nil", got.IPList)
	}
	if got.RateLimitRPM != 0 {
		t.Errorf("RateLimitRPM = %d; want 0", got.RateLimitRPM)
	}
}

func TestResolveConnAndRateLimitStartupConfig_UsesResolvedFields(t *testing.T) {
	got := resolveConnAndRateLimitStartupConfig(&FileConfig{}, "allow", 120)
	if got.IPMode != "allow" {
		t.Errorf("IPMode = %q; want %q", got.IPMode, "allow")
	}
	if got.RateLimitRPM != 120 {
		t.Errorf("RateLimitRPM = %d; want 120", got.RateLimitRPM)
	}
}

// TestResolveConnAndRateLimitStartupConfig_IgnoresFCIPFilterMode is a
// regression guard against the resolver re-reading
// fc.Security.IPFilterMode. The pre-resolved IPMode (resolvedIPMode)
// must always win — even when empty — to keep CLI / FileConfig
// precedence as a single source of truth in loadFileConfigAndFlags.
func TestResolveConnAndRateLimitStartupConfig_IgnoresFCIPFilterMode(t *testing.T) {
	fc := &FileConfig{}
	fc.Security.IPFilterMode = "should-be-ignored"
	got := resolveConnAndRateLimitStartupConfig(fc, "", 0)
	if got.IPMode != "" {
		t.Errorf("IPMode = %q; want empty (resolver must not re-read fc.Security.IPFilterMode)", got.IPMode)
	}
}

func TestResolveConnAndRateLimitStartupConfig_PropagatesIPList(t *testing.T) {
	fc := &FileConfig{}
	fc.Security.IPList = []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}
	got := resolveConnAndRateLimitStartupConfig(fc, "allow", 0)
	if len(got.IPList) != 3 {
		t.Fatalf("IPList length = %d; want 3", len(got.IPList))
	}
	for i, want := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		if got.IPList[i] != want {
			t.Errorf("IPList[%d] = %q; want %q", i, got.IPList[i], want)
		}
	}
}

func TestResolveConnAndRateLimitStartupConfig_PropagatesMaxConnsPerIP(t *testing.T) {
	fc := &FileConfig{}
	fc.Security.MaxConnsPerIP = 50
	got := resolveConnAndRateLimitStartupConfig(fc, "", 0)
	if got.MaxConnsPerIP != 50 {
		t.Errorf("MaxConnsPerIP = %d; want 50", got.MaxConnsPerIP)
	}
}

// ─── Loader ──────────────────────────────────────────────────────────

func TestLoadConnAndRateLimit_AllZeroReturnsNil(t *testing.T) {
	ensureConnlimitStartupTestLogger(t)
	snapshotConnAndRateLimitGlobals(t)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	got := loadConnAndRateLimit(connAndRateLimitStartupConfig{}, ctx)
	if got != nil {
		t.Errorf("loadConnAndRateLimit(all-zero) returned non-nil cancel; want nil")
	}
	if connLimiter.Enabled() {
		t.Errorf("connLimiter.enabled = true after all-zero cfg; want false")
	}
}

func TestLoadConnAndRateLimit_ConnLimiterEnabled(t *testing.T) {
	ensureConnlimitStartupTestLogger(t)
	snapshotConnAndRateLimitGlobals(t)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	loadConnAndRateLimit(connAndRateLimitStartupConfig{MaxConnsPerIP: 50}, ctx)

	if !connLimiter.Enabled() {
		t.Error("connLimiter.enabled = false; want true after MaxConnsPerIP=50")
	}
	if got := connLimiter.MaxPerIP(); got != 50 {
		t.Errorf("connLimiter.MaxPerIP() = %d; want 50", got)
	}
}

func TestLoadConnAndRateLimit_IPFilterPopulatedAndInvalidSkipped(t *testing.T) {
	ensureConnlimitStartupTestLogger(t)
	snapshotConnAndRateLimitGlobals(t)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	cfg := connAndRateLimitStartupConfig{
		IPMode: "allow",
		IPList: []string{"1.1.1.1", "definitely-not-an-ip", "2.2.2.2"},
	}
	loadConnAndRateLimit(cfg, ctx)

	if ipf.Mode() != "allow" {
		t.Errorf("ipf.Mode() = %q; want %q", ipf.Mode(), "allow")
	}
	list := ipf.List()
	hasIP := func(want string) bool {
		for _, e := range list {
			if e == want {
				return true
			}
		}
		return false
	}
	if !hasIP("1.1.1.1") {
		t.Errorf("ipf.List() missing 1.1.1.1; got %v", list)
	}
	if !hasIP("2.2.2.2") {
		t.Errorf("ipf.List() missing 2.2.2.2; got %v", list)
	}
	if hasIP("definitely-not-an-ip") {
		t.Errorf("ipf.List() contains invalid entry; got %v", list)
	}
}

func TestLoadConnAndRateLimit_RateLimitEnabledReturnsCancel(t *testing.T) {
	ensureConnlimitStartupTestLogger(t)
	snapshotConnAndRateLimitGlobals(t)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	got := loadConnAndRateLimit(connAndRateLimitStartupConfig{RateLimitRPM: 60}, ctx)
	if got == nil {
		t.Fatal("loadConnAndRateLimit(RateLimitRPM=60) returned nil cancel; want non-nil")
	}
	t.Cleanup(got) // stop the spawned cleanup goroutine

	if limit := rl.Limit(); limit != 60 {
		t.Errorf("rl.Limit() = %d; want 60", limit)
	}
}

func TestLoadConnAndRateLimit_RateLimitDisabledReturnsNil(t *testing.T) {
	ensureConnlimitStartupTestLogger(t)
	snapshotConnAndRateLimitGlobals(t)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Other fields set, but RateLimitRPM == 0 — must still return nil.
	cfg := connAndRateLimitStartupConfig{
		MaxConnsPerIP: 50,
		IPMode:        "allow",
		IPList:        []string{"1.1.1.1"},
		RateLimitRPM:  0,
	}
	got := loadConnAndRateLimit(cfg, ctx)
	if got != nil {
		t.Errorf("loadConnAndRateLimit with RateLimitRPM=0 returned non-nil cancel; want nil")
	}
}

// ─── Cleanup loop cancellation ──────────────────────────────────────

// TestRateLimitCleanupLoop_ExitsOnContextDone pins the invariant that
// the cleanup loop returns within a bounded time after ctx is
// cancelled. The 5-minute ticker never fires during this test
// (cancellation fires first), so rl.Cleanup() / ssrfDNSCache.Cleanup()
// are not invoked — we are testing the select arm, not the cleanup
// work itself.
func TestRateLimitCleanupLoop_ExitsOnContextDone(t *testing.T) {
	ensureConnlimitStartupTestLogger(t)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		rateLimitCleanupLoop(ctx)
		close(done)
	}()

	// Cancel immediately — the goroutine's select arm will pick up
	// ctx.Done() whether it's already in the select or scheduled
	// shortly after. No sleep needed.
	cancel()

	select {
	case <-done:
		// goroutine exited cleanly
	case <-time.After(2 * time.Second):
		t.Fatal("rateLimitCleanupLoop did not return within 2s after ctx cancel")
	}
}
