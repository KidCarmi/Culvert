package runtime

import (
	"context"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// A request past its budget must never consume a verification slot.
//
// acquireSlot selects between "a slot is free" and "the context is done". Go
// picks UNIFORMLY AT RANDOM when both cases are ready, so under saturation a slot
// freeing at the instant the budget expires took the slot roughly half the time --
// and token/DPoP verification then began on a request whose deadline had already
// passed. That defeats the deadline bound, spends a scarce security bound on work
// no one is waiting for, and returns a credential verdict where the truthful
// answer is a timeout.
//
// Driven many times deliberately: a single trial passes a broken build half the
// time. At 200 trials a regression survives with probability 2^-200.
func TestSlotDeadline_ExpiredBudgetNeverTakesAFreeSlot(t *testing.T) {
	k := newESKey(t, "k1")
	p := newGatewayPipeline(t, testDeps(t, k, NewBoundedSink(8)))

	const trials = 200
	sem := make(chan struct{}, 1) // always free: the racing case is always ready

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	for i := 0; i < trials; i++ {
		release, err := p.acquireSlot(ctx, sem)
		if err == nil {
			release()
			t.Fatalf("trial %d: acquireSlot handed out a slot for a request whose budget "+
				"had already elapsed; verification would start past the deadline", i)
		}
		if mcperr.ReasonOf(err) != mcperr.ReasonRequestDeadlineExceeded {
			t.Fatalf("trial %d: reason = %v, want %v", i, mcperr.ReasonOf(err),
				mcperr.ReasonRequestDeadlineExceeded)
		}
	}

	// Every refusal must hand the slot BACK. A refusal that keeps it converts a
	// deadline into a permanent capacity loss — strictly worse than the bug.
	select {
	case sem <- struct{}{}:
		<-sem
	default:
		t.Fatal("the semaphore is still occupied after the refusals: a slot taken on " +
			"the racing branch was not released, so every expired request permanently " +
			"consumes verification capacity")
	}

	// Counted exactly once per refusal, on the same series as every other budget
	// expiry.
	if got := p.ctr.timeouts.Load(); got != trials {
		t.Fatalf("timeouts = %d after %d refusals, want %d (exactly one per refusal)",
			got, trials, trials)
	}
}

// The control: a live budget with a free slot must still be served, or the fix
// above would be a denial of service wearing a deadline's clothes.
func TestSlotDeadline_LiveBudgetStillAcquires(t *testing.T) {
	k := newESKey(t, "k1")
	p := newGatewayPipeline(t, testDeps(t, k, NewBoundedSink(8)))

	sem := make(chan struct{}, 1)
	release, err := p.acquireSlot(context.Background(), sem)
	if err != nil {
		t.Fatalf("a request with a live budget was refused a free slot: %v", err)
	}
	release()
	if got := p.ctr.timeouts.Load(); got != 0 {
		t.Fatalf("timeouts = %d on the success path, want 0", got)
	}
}
