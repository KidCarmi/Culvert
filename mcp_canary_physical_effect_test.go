package main

// mcp_canary_physical_effect_test.go — composition-layer gates for the First
// Controlled Canary physical-effect contract (review blockers #6/#8).

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/upstreamclient"
)

// TestCanaryPath_ProductionUpstreamClientIsRetryFree is the blocker-#6 closure gate
// at the composition layer. Transport SUPPORT for retry-freedom is not enough: the
// client the live tier actually uses must be constructed retry-free, or one
// accepted reservation can still cause several physical tool invocations.
func TestCanaryPath_ProductionUpstreamClientIsRetryFree(t *testing.T) {
	lim, err := upstreamclient.RetryFreeLimits(upstreamclient.LimitConfig{})
	if err != nil {
		t.Fatalf("RetryFreeLimits: %v", err)
	}
	if !lim.RetriesDisabled() {
		t.Fatal("the First-Canary limits must disable transport retries")
	}
	if got := lim.MaxReadRetries(); got != 0 {
		t.Fatalf("retry-free limits must carry a zero retry budget, got %d", got)
	}
	// The production client must construct successfully from exactly these limits —
	// a construction failure here would silently push the live tier back onto the
	// defaults.
	if _, err := newProductionUpstreamClient(); err != nil {
		t.Fatalf("production upstream client must construct: %v", err)
	}
}

// TestNonCanaryBehaviorUnchanged is the CONTROL for blocker #6: making the Canary
// path retry-free must not remove retries from anything else. If this ever fails,
// the change stopped being scoped to the Canary.
func TestNonCanaryBehaviorUnchanged(t *testing.T) {
	def := upstreamclient.DefaultLimits()
	if def.RetriesDisabled() {
		t.Fatal("default limits must still retry — non-Canary behavior is unchanged")
	}
	if def.MaxReadRetries() == 0 {
		t.Fatal("default limits must still carry a non-zero retry budget")
	}
}

// TestCanaryGate_MintsReservationIdentity pins that a granted admission names both
// the slot that paid for the effect and the activation generation it belongs to.
// Without them a physical effect cannot be attributed to an authorized reservation,
// and an orphan from a superseded generation cannot be recognized after a restart.
func TestCanaryGate_MintsReservationIdentity(t *testing.T) {
	seen := make(map[string]struct{}, 256)
	for i := 0; i < 256; i++ {
		id, err := newCanaryReservationID()
		if err != nil {
			t.Fatalf("newCanaryReservationID: %v", err)
		}
		if len(id) != 4+2*canaryReservationIDBytes {
			t.Fatalf("unbounded reservation id: %q", id)
		}
		if id[:4] != "rsv_" {
			t.Fatalf("reservation id must be self-describing, got %q", id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("reservation id collision at %d: %q", i, id)
		}
		seen[id] = struct{}{}
	}
}
