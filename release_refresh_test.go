package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// M1-2: production HTTP catalog refresh. These tests enforce the §10 map rows:
// RT-H1 (shared status between the loop and the manual endpoint — both callers go
// through runRefresh) plus the resolver/jitter/loop mechanics.

func TestResolveRefreshInterval(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"", defaultRefreshInterval},        // unset ⇒ default
		{"6h", 6 * time.Hour},               //
		{" 90m ", 90 * time.Minute},         // trimmed
		{"1h30m", 90 * time.Minute},         //
		{"garbage", defaultRefreshInterval}, // invalid ⇒ default (fail-safe: typo must not disable the loop)
		{"-1h", defaultRefreshInterval},     // non-positive ⇒ default
		{"0", defaultRefreshInterval},       //
		{"5s", time.Minute},                 // clamped: never hammer the origin
	}
	for _, c := range cases {
		if got := resolveRefreshInterval(c.in); got != c.want {
			t.Errorf("resolveRefreshInterval(%q) = %v; want %v", c.in, got, c.want)
		}
	}
}

func TestJitteredInterval_Bounds(t *testing.T) {
	base := time.Hour
	lo := time.Duration(float64(base) * (1 - refreshJitterFrac))
	hi := time.Duration(float64(base) * (1 + refreshJitterFrac))
	for i := 0; i < 200; i++ {
		if d := jitteredInterval(base); d < lo || d > hi {
			t.Fatalf("jitteredInterval(%v) = %v out of [%v, %v]", base, d, lo, hi)
		}
	}
}

// RT-H1 enforcement: the loop and the manual endpoint MUST share one status
// record — a manual failure advances the same consecutive-failure counter the
// loop reads, and a loop success resets what a manual failure set. Both callers
// go through runRefresh, so this exercises exactly that contract.
func TestRunRefresh_SharedStatusAcrossCallers(t *testing.T) {
	fail := errors.New("origin broken")
	var mode atomic.Bool // false ⇒ fail, true ⇒ succeed
	rm := &releaseManager{refresh: func(context.Context) error {
		if mode.Load() {
			return nil
		}
		return fail
	}}

	// Two failures — one "manual", one "loop" — accumulate in ONE counter.
	if err := rm.runRefresh(context.Background(), "manual"); err == nil {
		t.Fatal("expected failure")
	}
	if err := rm.runRefresh(context.Background(), "loop"); err == nil {
		t.Fatal("expected failure")
	}
	st := rm.refreshStatusSnapshot()
	if st.ConsecutiveFailures != 2 || st.LastOK || st.LastErr != "origin broken" || st.LastTrigger != "loop" {
		t.Fatalf("shared failure state wrong: %+v", st)
	}

	// A success from EITHER caller resets the shared counter.
	mode.Store(true)
	if err := rm.runRefresh(context.Background(), "manual"); err != nil {
		t.Fatalf("expected success: %v", err)
	}
	st = rm.refreshStatusSnapshot()
	if st.ConsecutiveFailures != 0 || !st.LastOK || st.LastErr != "" || st.LastTrigger != "manual" {
		t.Fatalf("shared success state wrong: %+v", st)
	}
	if st.LastAt.IsZero() {
		t.Fatal("LastAt must be set")
	}
}

// The loop invokes the SHARED wrapper per tick, tolerates a nil manager, and
// stops promptly on context cancellation.
func TestRunCatalogRefreshLoop_TicksAndStops(t *testing.T) {
	var calls atomic.Int32
	rm := &releaseManager{refresh: func(context.Context) error {
		calls.Add(1)
		return nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runCatalogRefreshLoop(ctx, 20*time.Millisecond, func() *releaseManager { return rm })
	}()

	deadline := time.Now().Add(3 * time.Second)
	for calls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if calls.Load() < 2 {
		t.Fatal("loop did not tick at least twice within the deadline")
	}
	// Loop outcomes land in the SHARED status (trigger tagged "loop").
	if st := rm.refreshStatusSnapshot(); st.LastTrigger != "loop" || !st.LastOK {
		t.Fatalf("loop tick did not record shared status: %+v", st)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("loop did not stop on context cancellation")
	}

	// A nil manager per tick must not panic (release management disabled).
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan struct{})
	go func() {
		defer close(done2)
		runCatalogRefreshLoop(ctx2, 10*time.Millisecond, func() *releaseManager { return nil })
	}()
	time.Sleep(40 * time.Millisecond)
	cancel2()
	select {
	case <-done2:
	case <-time.After(2 * time.Second):
		t.Fatal("nil-manager loop did not stop")
	}
}

// HIGH-fix enforcement (M1-2 impl review): a REJECTED catalog's ETag must never
// arm a 304 — validators are pending-only until an explicit CommitValidators
// after a fully successful seed, and InvalidateValidators forces a re-download.
// Without the fix, tick 2 here would 304 into a FALSE SUCCESS (nil), resetting
// failure counters and hiding the bad origin from M1-3's alerting.
func TestRefresh_RejectedCatalogETagNotCommitted(t *testing.T) {
	priv, trust, base := seedFixture(t)
	cfg, _ := autoSeedCfg(t, base, trust)
	if err := (freshnessPolicy{enabled: true, statePath: cfg.statePath}).writeVersionFloor(5); err != nil {
		t.Fatal(err)
	}
	// Rollback-refused catalog (version 4 < floor 5) served WITH an ETag.
	files := signedCatalogFiles(t, priv, freshValidSource("2099-01-01T00:00:00Z", 4))
	f := &fakeCatalogServer{files: files, etag: `"v4"`}
	p, _ := newHTTPProvider(t, f, trust)
	p.stageBase = base

	// Tick 1: full fetch, seed REJECTED (rollback). The closure invalidates on
	// failure — mirror that here.
	if err := autoSeedCatalog(context.Background(), p, cfg); !errors.Is(err, errCatalogRollback) {
		t.Fatalf("tick 1: want errCatalogRollback, got %v", err)
	}
	p.InvalidateValidators()

	// Tick 2 must RE-DOWNLOAD and re-reject — NOT 304 into a nil false success.
	if err := autoSeedCatalog(context.Background(), p, cfg); !errors.Is(err, errCatalogRollback) {
		t.Fatalf("tick 2: want errCatalogRollback again (re-download + re-reject), got %v", err)
	}
}

// Validators must be pending-only: a successful Stage with NO explicit commit
// leaves the next fetch unconditional (no If-None-Match ⇒ no 304).
func TestRefresh_ValidatorsPendingUntilCommit(t *testing.T) {
	priv, trust, base := seedFixture(t)
	files := signedCatalogFiles(t, priv, freshValidSource("2099-01-01T00:00:00Z", 3))
	f := &fakeCatalogServer{files: files, etag: `"v3"`}
	p, _ := newHTTPProvider(t, f, trust)
	p.stageBase = base

	if _, err := p.Stage(context.Background()); err != nil {
		t.Fatalf("stage 1: %v", err)
	}
	// NO CommitValidators: the second Stage must be a full fetch, not a 304.
	if _, err := p.Stage(context.Background()); errors.Is(err, errCatalogUnchanged) {
		t.Fatal("second Stage returned 304/unchanged although validators were never committed")
	}
	// After an explicit commit, the conditional request works as before.
	p.CommitValidators()
	if _, err := p.Stage(context.Background()); !errors.Is(err, errCatalogUnchanged) {
		t.Fatalf("post-commit Stage: want errCatalogUnchanged, got %v", err)
	}
}

// CHAOS-R1 (2026-07-10 review): the refresh loop is the sole runtime driver of
// both catalog refresh and the freshness watchdog, so a panic anywhere in the
// refresh path must cost exactly one tick — the loop keeps ticking and later
// ticks still run and record outcomes.
func TestRunCatalogRefreshLoop_SurvivesTickPanic(t *testing.T) {
	var calls atomic.Int32
	rm := &releaseManager{refresh: func(context.Context) error {
		if calls.Add(1) == 1 {
			panic("injected refresh panic")
		}
		return nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		runCatalogRefreshLoop(ctx, 20*time.Millisecond, func() *releaseManager { return rm })
	}()

	// Tick 1 panics; the loop must survive it and keep ticking.
	deadline := time.Now().Add(3 * time.Second)
	for calls.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := calls.Load(); got < 3 {
		t.Fatalf("loop died after the panicking tick (calls = %d, want >= 3)", got)
	}
	// The post-panic tick still folds into the shared status, and the panic
	// did not strand refreshRunMu/statusMu (deferred unlocks release during
	// unwinding — a stuck lock would deadlock the later ticks above).
	if st := rm.refreshStatusSnapshot(); st.LastTrigger != "loop" || !st.LastOK {
		t.Fatalf("post-panic tick did not record shared status: %+v", st)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("loop did not stop on context cancellation after a recovered panic")
	}
}
