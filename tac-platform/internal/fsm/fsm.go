// Package fsm is the legal-transition authority for operations. It is the ONLY
// place that decides whether a (from -> to) move is permitted. Callers never pass
// an arbitrary target state directly to the store; they invoke named domain
// operations (opsvc) which each declare a single from->to and are validated here.
package fsm

import "github.com/kidcarmi/tac-platform/internal/domain"

type S = domain.State

// legal maps each state to the set of states it may transition to.
var legal = map[S]map[S]bool{
	domain.StateCreated:         set(domain.StateDiscovering, domain.StateCancelled, domain.StateExpired),
	domain.StateDiscovering:     set(domain.StatePlanning, domain.StateCancelled, domain.StateExpired),
	domain.StatePlanning:        set(domain.StatePolicyRejected, domain.StateReviewPending, domain.StateApprovalPending, domain.StateCancelled, domain.StateExpired),
	domain.StateReviewPending:   set(domain.StateApprovalPending, domain.StateApproved, domain.StateCancelled, domain.StateExpired),
	domain.StateApprovalPending: set(domain.StateApproved, domain.StateExecutionQueued /*L2 auto*/, domain.StateCancelled, domain.StateExpired),
	domain.StateApproved:        set(domain.StateExecutionQueued, domain.StateApprovalPending /*re-approval*/, domain.StateCancelled, domain.StateExpired),
	domain.StateExecutionQueued: set(domain.StateExecuting, domain.StateCancelled, domain.StateExpired),
	domain.StateExecuting:       set(domain.StateValidating, domain.StateFailed, domain.StateCancelled),
	domain.StateValidating:      set(domain.StateSucceeded, domain.StateFailed),
	domain.StateFailed:          set(domain.StateRollbackPending, domain.StateManualRequired),
	domain.StateRollbackPending: set(domain.StateRollingBack, domain.StateManualRequired),
	domain.StateRollingBack:     set(domain.StateRolledBack, domain.StateManualRequired),
	// terminals:
	domain.StateSucceeded:      {},
	domain.StateRolledBack:     {},
	domain.StateCancelled:      {},
	domain.StateExpired:        {},
	domain.StatePolicyRejected: {},
	domain.StateManualRequired: {},
}

func set(states ...S) map[S]bool {
	m := make(map[S]bool, len(states))
	for _, s := range states {
		m[s] = true
	}
	return m
}

// Legal reports whether from -> to is a permitted transition.
func Legal(from, to S) bool {
	return legal[from][to]
}

// Check returns an illegal-transition error if from -> to is not permitted.
func Check(from, to S) error {
	if !Legal(from, to) {
		return domain.Errf(domain.CodeIllegalTransition, "%s -> %s not permitted", from, to)
	}
	return nil
}

// Terminal reports whether a state has no outgoing transitions.
func Terminal(s S) bool {
	m, ok := legal[s]
	return ok && len(m) == 0
}

// AllStates returns every known state (for exhaustive tests).
func AllStates() []S {
	out := make([]S, 0, len(legal))
	for s := range legal {
		out = append(out, s)
	}
	return out
}
