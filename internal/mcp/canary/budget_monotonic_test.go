package canary

// budget_monotonic_test.go — pins the First-Canary conservative-consumption rule
// (review §12): once a reservation is granted, the TOTAL execution allowance is
// spent permanently. Uncertainty and control churn must never manufacture fresh
// execution authority.
//
// This is currently true by construction — Release touches only the concurrency
// counter — but "true by construction" is exactly the kind of property that decays
// silently, so it is pinned rather than assumed.

import (
	"testing"
	"time"
)

func monotonicTestBudget() Budget {
	return Budget{
		MaxTotalExecutions:      3,
		MaxExecutionsPerMinute:  60,
		MaxConcurrentExecutions: 3,
		Window:                  time.Hour,
		MaxPrincipals:           1,
		MaxTools:                1,
		MaxServers:              1,
	}
}

func monotonicIdent() ExecutionIdentity {
	return ExecutionIdentity{Principal: "p1", Tool: "t1", Server: "s1"}
}

// TestBudget_ReleaseDoesNotRefundTotalAllowance is the core §12 gate. A released
// concurrency slot lets ANOTHER request run in parallel; it must not restore the
// experiment's execution ceiling.
func TestBudget_ReleaseDoesNotRefundTotalAllowance(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	e := NewBudgetEnforcer(monotonicTestBudget(), 1, now)

	for i := 0; i < 3; i++ {
		if got := e.Reserve(1, now, monotonicIdent()); !got.Granted() {
			t.Fatalf("reservation %d must be granted, got %v", i+1, got)
		}
		// Release every slot — simulating a boundary refusal, an ambiguous transport
		// failure, or a completed call. None of these may return allowance.
		e.Release()
	}
	if got := e.TotalReserved(); got != 3 {
		t.Fatalf("total reserved must be monotonic at 3 after three release cycles, got %d", got)
	}
	// N+1 must be impossible even though every concurrency slot was returned.
	if got := e.Reserve(1, now, monotonicIdent()); got.Granted() {
		t.Fatal("the N+1 reservation must be denied: Release is not a budget refund")
	}
}

// TestBudget_DefinitelyNotSentStillConsumesAllowance pins the specific case the
// design constraints call out: a committed send intent followed by a final
// freshness/generation/kill refusal consumes the reservation conservatively. The
// allowance is an authorization ceiling, not an accounting reimbursement system —
// reclaiming it would let control churn manufacture extra execution authority.
func TestBudget_DefinitelyNotSentStillConsumesAllowance(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	e := NewBudgetEnforcer(monotonicTestBudget(), 1, now)

	// One reservation granted, then refused at the final boundary (the executor's
	// definitely_not_sent path) and its concurrency slot released.
	if got := e.Reserve(1, now, monotonicIdent()); !got.Granted() {
		t.Fatalf("first reservation must be granted, got %v", got)
	}
	e.Release()

	if got := e.TotalReserved(); got != 1 {
		t.Fatalf("a refused-at-boundary attempt must still consume allowance, got %d", got)
	}
	// Exactly two remain of the original three — the refused one is NOT returned.
	for i := 0; i < 2; i++ {
		if got := e.Reserve(1, now, monotonicIdent()); !got.Granted() {
			t.Fatalf("remaining reservation %d must be granted, got %v", i+1, got)
		}
		e.Release()
	}
	if got := e.Reserve(1, now, monotonicIdent()); got.Granted() {
		t.Fatal("allowance must be exhausted: definitely_not_sent does not refund the ceiling")
	}
}
