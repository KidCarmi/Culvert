package runtime

// chaos_sweep_panic_test.go — CHAOS-25: session-sweeper panic containment.
//
// sweepLoop is a long-lived goroutine, so an unrecovered fault in a sweep round
// terminates the process — taking the whole Secure Web Gateway down for a fault
// in a disabled-by-default subsystem's housekeeping tick.
//
// The guard is per ROUND, deliberately not on the goroutine. The sweeper is
// what enforces session expiry: a goroutine-level recover would let it return
// on the first fault, after which sessions outlive their TTL forever and
// bindings are never reclaimed — while the listener still reports PhaseReady.
// That trades a loud crash for a silent security regression, which is worse.

import "testing"

// newFaultingSweeper builds a listener whose sweep round faults inside the real
// call (a nil pipeline dereferences exactly where a corrupt store would).
func newFaultingSweeper() *Listener { return &Listener{ctr: &counters{}} }

func TestChaos25_SweepRoundPanic_IsContainedAndCounted(t *testing.T) {
	l := newFaultingSweeper()

	l.sweepRound() // must not propagate: an unrecovered panic here kills the gateway

	if got := l.ctr.sweepPanics.Load(); got != 1 {
		t.Fatalf("sweepPanics = %d, want 1 — a contained sweep fault must not be silent", got)
	}
}

// A deterministic fault must cost one interval per round, not the sweeper. This
// is the assertion that fails if someone moves the guard onto the goroutine.
func TestChaos25_SweeperSurvivesDeterministicRoundFault(t *testing.T) {
	l := newFaultingSweeper()

	for i := 0; i < 25; i++ {
		l.sweepRound()
	}
	if got := l.ctr.sweepPanics.Load(); got != 25 {
		t.Fatalf("sweepPanics = %d, want 25 — every round must still run", got)
	}
}

// The counter is the only signal this subtree can raise (internal/mcp imports no
// other internal/* package and does no logging by design), so it has to reach
// the typed health snapshot or containment is invisible.
func TestChaos25_SweepPanicsSurfaceOnTheHealthSnapshot(t *testing.T) {
	l := newFaultingSweeper()
	l.sweepRound()

	snap := l.ctr.snapshot("gateway", "test")
	if snap.SweepPanics != 1 {
		t.Fatalf("HealthSnapshot.SweepPanics = %d, want 1 — a listener that cannot expire sessions "+
			"must be distinguishable from a healthy one", snap.SweepPanics)
	}
}

// The healthy path must be untouched: a clean sweep counts nothing.
func TestChaos25_HealthySweepRoundCountsNothing(t *testing.T) {
	k := newESKey(t, "k1")
	l := &Listener{ctr: &counters{}, pipe: newGatewayPipeline(t, testDeps(t, k, nil))}

	l.sweepRound()

	if got := l.ctr.sweepPanics.Load(); got != 0 {
		t.Fatalf("sweepPanics = %d on a healthy sweep, want 0", got)
	}
}
