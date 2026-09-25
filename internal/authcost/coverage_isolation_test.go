package authcost

// Isolated deterministic fixtures for paths whose coverage previously depended
// on timing; see roadmap/CI-REDESIGN.md stage 5B.
//
// Each test below pins ONE coverage block that the existing suite reached only
// when goroutines happened to overlap (TestClientAtItsCapWaitsRatherThanBeingRefused
// fires six concurrent Admits for one client and asserts only that all six are
// eventually admitted — whether any of them ever PARKS on its own budget, and
// therefore whether the per-client wakeup and the real-timer path run at all,
// depends on how the scheduler interleaves them). The fixtures here construct
// the parked state on purpose and assert its outcome.

import (
	"runtime"
	"testing"
	"time"
)

// waitQueuedNoSleep blocks until exactly n callers are parked in the gate's
// queue, yielding the processor between polls instead of sleeping.
func waitQueuedNoSleep(t *testing.T, g *Gate, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		g.mu.Lock()
		q := g.queued
		g.mu.Unlock()
		if q == n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d queued callers (have %d)", n, q)
		}
		runtime.Gosched()
	}
}

// Pins authcost.go reserveClient `case <-changed: g.leaveQueue()` — a caller
// parked on its OWN per-client budget is woken by a Release, not by its
// deadline. Previously reached only when two same-client Admits happened to
// overlap in TestClientAtItsCapWaitsRatherThanBeingRefused.
//
// Determinism: the injected timer returns a NIL channel, so the deadline arm
// of the select can never fire; the only way out of the park is the released
// signal. The waiter is observed parked (queued == 1, which reserveClient sets
// under the same lock it reads the released channel under) before Release, so
// the wakeup cannot be lost or pre-empted.
func TestIsolation_PerClientWaiterWokenByRelease(t *testing.T) {
	g := New(2, 1, time.Hour)
	g.newTimer = func(time.Duration) (<-chan time.Time, func() bool) {
		return nil, func() bool { return true } // a deadline that never fires
	}

	mustAdmit(t, g, "c") // holds the client's whole budget (cap 1)

	type outcome struct {
		r      Refusal
		queued bool
	}
	got := make(chan outcome, 1)
	go func() {
		r, q := g.Admit("c")
		got <- outcome{r, q}
	}()
	waitQueuedNoSleep(t, g, 1)
	if s := g.Stats(); s.InFlight != 1 {
		t.Fatalf("InFlight = %d while the second request is parked on its client cap, want 1", s.InFlight)
	}

	g.Release("c") // returns the reservation → closes the released channel

	o := <-got
	if o.r != Admitted {
		t.Fatalf("parked same-client request = %v, want Admitted after the release", o.r)
	}
	if !o.queued {
		t.Fatal("queued = false, want true — the admission waited on the per-client budget")
	}
	s := g.Stats()
	if s.Waited != 1 {
		t.Fatalf("Waited = %d, want 1", s.Waited)
	}
	if s.Refusals() != 0 {
		t.Fatalf("Refusals() = %d, want 0 — the waiter must be woken by the release, not refused", s.Refusals())
	}
	if s.InFlight != 1 {
		t.Fatalf("InFlight = %d after the hand-over, want 1", s.InFlight)
	}
	g.mu.Lock()
	q := g.queued
	g.mu.Unlock()
	if q != 0 {
		t.Fatalf("queued = %d after the waiter left, want 0", q)
	}
	g.Release("c")
	if got := g.Stats().InFlight; got != 0 {
		t.Fatalf("InFlight = %d after the final release, want 0", got)
	}
}

// Pins authcost.go (*Gate).timer's production branch
// `t := time.NewTimer(d); return t.C, t.Stop` (newTimer == nil). The existing
// deterministic tests always inject newTimer; the only suite test running with
// the real timer (TestClientAtItsCapWaitsRatherThanBeingRefused) arms it only
// if one of its goroutines happens to park.
//
// Determinism: everything runs on the test goroutine and nothing ever
// releases, so the parked Admit has exactly one possible exit — the REAL
// timer firing. The outcome (RefusedPerClient) therefore does not depend on
// scheduling; only how long the wait takes does, and that is bounded by the
// 1 ms maxWait.
func TestIsolation_RealTimerDeadlineRefusesParkedClient(t *testing.T) {
	g := New(2, 1, time.Millisecond)
	if g.newTimer != nil {
		t.Fatal("New installed a timer seam; the production timer path is not under test")
	}
	mustAdmit(t, g, "c")

	r, queued := g.Admit("c") // same client, at its cap: parks on the real timer
	if r != RefusedPerClient {
		t.Fatalf("Admit at the client cap with no release = %v, want RefusedPerClient", r)
	}
	if !queued {
		// reserveClient reports that it parked; a false here would mean the
		// client was refused on the spot and the timer was never armed.
		t.Fatal("waited = false, want true — the request must park on the timer before being refused")
	}
	s := g.Stats()
	if s.RefusedPerClient != 1 {
		t.Fatalf("RefusedPerClient = %d, want 1", s.RefusedPerClient)
	}
	if s.InFlight != 1 {
		t.Fatalf("InFlight = %d, want 1 — a refused caller must hold nothing", s.InFlight)
	}
	g.mu.Lock()
	q, held := g.queued, g.perClient["c"]
	g.mu.Unlock()
	if q != 0 {
		t.Fatalf("queued = %d after the deadline, want 0", q)
	}
	if held != 1 {
		t.Fatalf("perClient[c] = %d after the refusal, want 1 (only the original admission)", held)
	}
	g.Release("c")
}
