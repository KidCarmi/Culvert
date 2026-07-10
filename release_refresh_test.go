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
