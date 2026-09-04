package model

import "testing"

// TestPhysicalSendState_ConservativePredicates pins the direction of uncertainty
// (§6/§10): only the two states that positively prove the peer did not act may
// answer false to MayHaveReachedPeer. Everything else — including the unset zero
// value — must be treated as possibly-effective.
func TestPhysicalSendState_ConservativePredicates(t *testing.T) {
	mayReach := map[PhysicalSendState]bool{
		SendStateUnset:            true, // unknown is never a non-event
		SendMayHaveBeenSent:       true,
		SendPeerResponseReceived:  true,
		SendReconciledReceived:    true,
		SendDefinitelyNotSent:     false,
		SendReconciledNotReceived: false,
	}
	for s, want := range mayReach {
		if got := s.MayHaveReachedPeer(); got != want {
			t.Errorf("%q.MayHaveReachedPeer() = %v, want %v", s, got, want)
		}
	}

	needsRecon := map[PhysicalSendState]bool{
		SendStateUnset:            true,
		SendMayHaveBeenSent:       true,
		SendPeerResponseReceived:  false,
		SendReconciledReceived:    false,
		SendReconciledNotReceived: false,
		SendDefinitelyNotSent:     false,
	}
	for s, want := range needsRecon {
		if got := s.ReconciliationRequired(); got != want {
			t.Errorf("%q.ReconciliationRequired() = %v, want %v", s, got, want)
		}
	}
}

// TestPhysicalSendState_UnsetIsInvalidOnACommittedOutcome pins that the zero value
// is not an acceptable committed state — a terminal record must say something.
func TestPhysicalSendState_UnsetIsInvalidOnACommittedOutcome(t *testing.T) {
	if SendStateUnset.Valid() {
		t.Fatal("the unset zero value must not be a valid committed send state")
	}
	for _, s := range []PhysicalSendState{
		SendDefinitelyNotSent, SendMayHaveBeenSent, SendPeerResponseReceived,
		SendReconciledReceived, SendReconciledNotReceived,
	} {
		if !s.Valid() {
			t.Errorf("%q must be a valid state", s)
		}
	}
	if PhysicalSendState("made_up").Valid() {
		t.Fatal("an unrecognized state string must not be valid")
	}
}
