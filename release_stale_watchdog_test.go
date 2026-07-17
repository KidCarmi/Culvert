package main

import (
	"context"
	"crypto/ed25519"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// CHAOS-23 (2026-07-10 review): the M1-3 freshness watchdog normally rides the
// periodic refresh loop, which only starts with a catalog origin in enforce
// mode. These tests enforce that deployments WITHOUT that loop — outbound
// fetch disabled (catalog_url_source=disabled) or break-glass verify modes —
// still get a runtime driver for release_catalog_stale, instead of evaluating
// staleness only at boot and on manual refresh.

// syncAlertRecorder swaps the releaseAlertFire seam for a mutex-guarded
// capture. The watchdog fires from its own goroutine, so the unsynchronized
// alertRecorder (release_alerts_test.go) would race under -race here.
func syncAlertRecorder(t *testing.T) func() []AlertPayload {
	t.Helper()
	var mu sync.Mutex
	var got []AlertPayload
	orig := releaseAlertFire
	releaseAlertFire = func(event string, p AlertPayload) {
		p.Event = event
		mu.Lock()
		got = append(got, p)
		mu.Unlock()
	}
	t.Cleanup(func() { releaseAlertFire = orig })
	return func() []AlertPayload {
		mu.Lock()
		defer mu.Unlock()
		return append([]AlertPayload(nil), got...)
	}
}

// waitForStaleCount polls until exactly n release_catalog_stale events have
// been captured (and fails fast if the count overshoots — the RT-H2 latch
// must keep repeat ticks silent).
func waitForStaleCount(t *testing.T, events func() []AlertPayload, n int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		stale := 0
		for _, p := range events() {
			if p.Event == "release_catalog_stale" {
				stale++
			}
		}
		if stale == n {
			return
		}
		if stale > n {
			t.Fatalf("stale alert overshot the latch: got %d, want %d", stale, n)
		}
		if time.Now().After(deadline) {
			t.Fatalf("stale alert count stuck at %d, want %d", stale, n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The loop drives evaluateCatalogFreshness per tick, the RT-H2 latch keeps a
// continuously-stale catalog to exactly ONE alert across ticks, and the loop
// stops promptly on context cancellation.
func TestStaleWatchdogLoop_TicksLatchesAndStops(t *testing.T) {
	events := syncAlertRecorder(t)
	var ticks atomic.Int32
	staleCat := &Catalog{expiresAt: time.Now().Add(5 * 24 * time.Hour)}
	rm := &releaseManager{observeCatalog: func() *Catalog {
		ticks.Add(1)
		return staleCat
	}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runCatalogStaleWatchdogLoop(ctx, 20*time.Millisecond, func() *releaseManager { return rm })
	}()

	deadline := time.Now().Add(3 * time.Second)
	for ticks.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if ticks.Load() < 3 {
		t.Fatal("watchdog did not tick at least three times within the deadline")
	}
	// RT-H2 through the real path: many ticks inside the window ⇒ ONE alert.
	waitForStaleCount(t, events, 1)

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog loop did not stop on context cancellation")
	}
}

// CHAOS-R1 contract carried over: in the deployments this loop serves it is
// the SOLE runtime stale driver, so a panicking tick must cost one tick — the
// loop keeps ticking and a later tick still fires the alert.
func TestStaleWatchdogLoop_SurvivesTickPanic(t *testing.T) {
	events := syncAlertRecorder(t)
	var ticks atomic.Int32
	staleCat := &Catalog{expiresAt: time.Now().Add(5 * 24 * time.Hour)}
	rm := &releaseManager{observeCatalog: func() *Catalog {
		if ticks.Add(1) == 1 {
			panic("injected observe panic")
		}
		return staleCat
	}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runCatalogStaleWatchdogLoop(ctx, 20*time.Millisecond, func() *releaseManager { return rm })
	}()

	// Tick 1 panics; a later tick must still evaluate and fire exactly once
	// (a stuck statusMu after the recovered panic would deadlock it instead).
	waitForStaleCount(t, events, 1)

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog loop did not stop after a recovered panic")
	}
}

// A non-positive interval starts nothing (bare test-constructed startup
// configs), and a nil manager per tick is tolerated (release management
// disabled after wiring — mirrors the refresh loop's contract).
func TestStaleWatchdogLoop_ZeroIntervalAndNilManager(t *testing.T) {
	done0 := make(chan struct{})
	go func() {
		defer close(done0)
		runCatalogStaleWatchdogLoop(context.Background(), 0, func() *releaseManager { return nil })
	}()
	select {
	case <-done0:
	case <-time.After(2 * time.Second):
		t.Fatal("zero-interval watchdog must return immediately")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runCatalogStaleWatchdogLoop(ctx, 10*time.Millisecond, func() *releaseManager { return nil })
	}()
	time.Sleep(40 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("nil-manager watchdog loop did not stop")
	}
}

// The CHAOS-23 regression pin, through the REAL wiring: a disabled-fetch
// enforce deployment (no refresh loop) must still re-fire the stale alert at
// runtime. Deleting the standalone-watchdog branch in startReleaseDetectionLoop
// fails this test — the boot evaluation fires once, and nothing ever fires
// again until a restart or manual refresh.
func TestStaleWatchdog_WiringRunsWithoutRefreshLoop(t *testing.T) {
	t.Cleanup(func() { setReleaseManager(nil) })
	events := syncAlertRecorder(t)
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	// Valid (loads through the enforce freshness gate) but inside the stale
	// window: expires 10 days from now.
	exp := time.Now().Add(10 * 24 * time.Hour).UTC().Format(time.RFC3339)
	writeSignedCatalogDir(t, dir, priv, freshValidSource(exp, 3))

	// Bound the wiring-started goroutine to this test: the watchdog parents on
	// resolveLifecycleCtx (same pattern as saas_feed_lifecycle_test.go).
	origCtx := appLifecycleCtx
	ctx, cancel := context.WithCancel(context.Background())
	appLifecycleCtx = ctx
	t.Cleanup(func() {
		cancel()
		appLifecycleCtx = origCtx
	})

	setReleaseManager(nil)
	loadReleaseManagement(releaseStartupConfig{
		proxyRepo:        defaultReleaseProxyRepo,
		catalogDir:       dir,
		statePath:        dir + "/state.json",
		verifyMode:       VerifyEnforce,
		trustKeys:        []TrustKey{{KeyID: holderTestKeyID, Alg: catalogSigAlg, PublicKey: pub}},
		catalogURLSource: catalogURLSourceDisabled, // fetch off ⇒ no refresh loop
		refreshInterval:  20 * time.Millisecond,    // resolved cadence (test-fast)
	})
	rm := currentReleaseManager()
	if rm == nil {
		t.Fatal("manager not published")
	}
	if rm.refreshInterval != 0 {
		t.Fatalf("no refresh loop ⇒ /api/releases must not advertise a fetch cadence; got %v", rm.refreshInterval)
	}

	// Boot evaluation fired once and latched (the pre-fix behavior ends here).
	waitForStaleCount(t, events, 1)

	// Re-arm the latch: only a RUNTIME driver can cross it again. Before the
	// CHAOS-23 fix nothing did in this deployment shape.
	rm.statusMu.Lock()
	rm.staleLatched = false
	rm.statusMu.Unlock()
	waitForStaleCount(t, events, 2)
}
