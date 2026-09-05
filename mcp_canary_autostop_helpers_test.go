package main

import (
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/execution"
)

// swapCanaryClock pins the Canary auto-stop clock (and disarms the real timer) for one test, so a
// 15-minute window can be proven in microseconds with no sleep and no wall-clock dependency.
//
// It exists because the window deadline is ABSOLUTE: restore re-derives it from the persisted
// activation instant, so a test that activates at a fixed historical instant and then restarts is —
// correctly — a restart long after expiry. Pinning the clock is how such a test says "the restart
// happened at this instant", which is the only thing that makes the assertion meaningful.
func swapCanaryClock(t *testing.T, at func() time.Time) {
	t.Helper()
	prevNow, prevAfter := canaryNow, canaryAfterFunc
	canaryNow = at
	// The watchdog is disarmed under a pinned clock: a test that wants expiry drives it by moving
	// the pinned clock and calling the reconcile/observe path, never by waiting for a real timer.
	canaryAfterFunc = func(time.Duration, func()) func() { return func() {} }
	t.Cleanup(func() { canaryNow, canaryAfterFunc = prevNow, prevAfter })
}

// swapCanaryTimer pins only the TIMER seam, leaving the clock alone, and hands the test
// deterministic control over the armed callbacks.
//
// Every arm is retained, including ones that were later stopped, because a real time.Timer can fire
// concurrently with its own Stop — so "fire a callback whose activation has been superseded" is a
// case the guards must survive, not an impossible one.
func swapCanaryTimer(t *testing.T) (fireIndex func(int), armedFor func() time.Duration) {
	t.Helper()
	prev := canaryAfterFunc
	type armed struct {
		cb func()
		d  time.Duration
	}
	var mu sync.Mutex
	var all []armed
	canaryAfterFunc = func(d time.Duration, f func()) func() {
		mu.Lock()
		all = append(all, armed{cb: f, d: d})
		mu.Unlock()
		return func() {}
	}
	t.Cleanup(func() { canaryAfterFunc = prev })
	return func(i int) {
			mu.Lock()
			var f func()
			if i >= 0 && i < len(all) {
				f = all[i].cb
			}
			mu.Unlock()
			if f != nil {
				f()
			}
		}, func() time.Duration {
			mu.Lock()
			defer mu.Unlock()
			if len(all) == 0 {
				return 0
			}
			return all[len(all)-1].d
		}
}

// swapCanaryClockVar pins the clock to a variable the test can move, so "time passes" is an
// assignment rather than a sleep.
func swapCanaryClockVar(t *testing.T, at *time.Time) {
	t.Helper()
	prev := canaryNow
	canaryNow = func() time.Time { return *at }
	t.Cleanup(func() { canaryNow = prev })
}

// newReconcileTestExecutor builds a minimal real Executor carrying the given safety funnel, so the
// reconciliation gates exercise the real ReconcileAndReport path rather than a stub.
func newReconcileTestExecutor(t *testing.T, safety execution.CanarySafety) *execution.Executor {
	t.Helper()
	ex, err := execution.New(execution.Config{
		State:    getMCPRollout().gateway,
		Events:   liveTestEvents(t),
		Upstream: &recordingUpstream{},
		Safety:   safety,
		Clock:    func() time.Time { return canaryRuntimeTestNow },
	})
	if err != nil {
		t.Fatalf("execution.New: %v", err)
	}
	return ex
}
