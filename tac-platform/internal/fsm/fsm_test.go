package fsm

import (
	"testing"

	"github.com/kidcarmi/tac-platform/internal/domain"
)

// Regression for R9-F1: attempt EVERY (from,to) pair; only declared-legal ones pass,
// all others are rejected with CodeIllegalTransition. Terminals reject all moves.
func TestFSM_ExhaustiveLegality(t *testing.T) {
	states := AllStates()
	for _, from := range states {
		for _, to := range states {
			err := Check(from, to)
			if Legal(from, to) {
				if err != nil {
					t.Fatalf("legal %s->%s rejected: %v", from, to, err)
				}
			} else {
				if err == nil {
					t.Fatalf("illegal %s->%s ACCEPTED", from, to)
				}
				if domain.CodeOf(err) != domain.CodeIllegalTransition {
					t.Fatalf("wrong code for %s->%s: %v", from, to, domain.CodeOf(err))
				}
			}
		}
	}
}

func TestFSM_TerminalsHaveNoExit(t *testing.T) {
	for _, s := range []domain.State{domain.StateSucceeded, domain.StateRolledBack, domain.StateCancelled,
		domain.StateExpired, domain.StatePolicyRejected, domain.StateManualRequired} {
		if !Terminal(s) {
			t.Fatalf("%s should be terminal", s)
		}
		for _, to := range AllStates() {
			if Legal(s, to) {
				t.Fatalf("terminal %s must not allow ->%s", s, to)
			}
		}
	}
}

// The specific bug the qualification found: SUCCEEDED -> PLANNING must be rejected.
func TestFSM_SucceededToPlanningRejected(t *testing.T) {
	if err := Check(domain.StateSucceeded, domain.StatePlanning); err == nil {
		t.Fatal("SUCCEEDED->PLANNING must be rejected")
	}
}
