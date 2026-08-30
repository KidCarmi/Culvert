package canary

import (
	"sync"
	"testing"
	"time"
)

// TestAbortController_WholeCanaryCodesLatch proves every AbortCanary code latches the controller on
// a SINGLE occurrence, and that the latch is monotonic (the first code wins; later codes do not
// change it) and generation-scoped.
func TestAbortController_WholeCanaryCodesLatch(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	for _, cond := range AbortConditions() {
		if cond.Scope != AbortCanary {
			continue
		}
		c := NewAbortController(1)
		if r := c.Trip(cond.Code, 1, now); r != TripCanaryLatched {
			t.Fatalf("%s must latch the whole Canary, got %s", cond.Code, r)
		}
		if !c.Aborted(1) {
			t.Fatalf("%s must leave the controller aborted", cond.Code)
		}
		if c.ExecutionEligible(1) {
			t.Fatalf("%s: an aborted Canary must not be execution-eligible", cond.Code)
		}
		if c.AbortCode() != cond.Code {
			t.Fatalf("abort code = %q, want %q", c.AbortCode(), cond.Code)
		}
	}
}

// TestAbortController_PerRequestCodesNeverLatch is the load-bearing distinction: an AbortRequest
// code fails the request closed but must NEVER stop the whole Canary (request-fails-closed ≠
// Canary-stops). Feeding every per-request code leaves the controller un-aborted and eligible.
func TestAbortController_PerRequestCodesNeverLatch(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	c := NewAbortController(1)
	for _, cond := range AbortConditions() {
		if cond.Scope != AbortRequest {
			continue
		}
		if r := c.Trip(cond.Code, 1, now); r != TripRequestScoped {
			t.Fatalf("%s must be request-scoped (Canary continues), got %s", cond.Code, r)
		}
	}
	if c.Aborted(1) {
		t.Fatal("SECURITY: per-request fail-closed codes must NOT abort the whole Canary")
	}
	if !c.ExecutionEligible(1) {
		t.Fatal("a Canary that only saw per-request fail-closed events must remain execution-eligible")
	}
}

// TestAbortController_MonotonicFirstCodeWins proves the abort is monotonic: after a first whole-
// Canary code latches, a second different whole-Canary code keeps the ORIGINAL code and time.
func TestAbortController_MonotonicFirstCodeWins(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	c := NewAbortController(1)
	c.Trip("scope_escape", 1, now)
	first := c.Snapshot()
	c.Trip("budget_exhausted", 1, now.Add(time.Minute))
	second := c.Snapshot()
	if second.Code != "scope_escape" || second.AtUnixNano != first.AtUnixNano {
		t.Fatalf("the first whole-Canary code must win monotonically, got %+v", second)
	}
}

// TestAbortController_UnknownCodeFailsClosed proves an unrecognised code fails closed to a whole-
// Canary latch (never silently downgraded to a per-request fault).
func TestAbortController_UnknownCodeFailsClosed(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	if AbortScopeForCode("some_new_unclassified_trip") != AbortCanary {
		t.Fatal("an unknown code must fail closed to AbortCanary")
	}
	c := NewAbortController(1)
	if r := c.Trip("some_new_unclassified_trip", 1, now); r != TripCanaryLatched {
		t.Fatalf("an unknown code must latch the whole Canary, got %s", r)
	}
}

// TestAbortController_GenerationBinding proves a trip for a different generation is refused and
// changes no state, and that Aborted/ExecutionEligible answer only for the bound generation.
func TestAbortController_GenerationBinding(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	c := NewAbortController(5)
	if r := c.Trip("scope_escape", 4, now); r != TripGenerationMismatch {
		t.Fatalf("a trip for the wrong generation must be refused, got %s", r)
	}
	if c.Aborted(5) {
		t.Fatal("a refused (stale-generation) trip must not abort the controller")
	}
	// The controller answers only for its own generation.
	c.Trip("scope_escape", 5, now)
	if !c.Aborted(5) {
		t.Fatal("the bound generation must be aborted after a valid trip")
	}
	if c.Aborted(6) || c.ExecutionEligible(6) {
		t.Fatal("a different generation is neither aborted-for nor eligible on this controller")
	}
}

// TestAbortController_RestartPreservesAbort proves the abort survives a restart for the SAME
// generation, and that a stale/foreign snapshot does NOT transfer an abort into a new generation
// (nor let a new generation reuse an old one's state).
func TestAbortController_RestartPreservesAbort(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	c := NewAbortController(3)
	c.Trip("credential_safety_failure", 3, now)
	snap := c.Snapshot()
	if !snap.Aborted || snap.Generation != 3 {
		t.Fatalf("snapshot = %+v, want aborted gen 3", snap)
	}
	// Same generation: the abort MUST survive the restart.
	restored := RestoreAbortController(3, snap)
	if !restored.Aborted(3) || restored.ExecutionEligible(3) {
		t.Fatal("an abort must survive a restart for the same generation")
	}
	// A NEW generation (post-reactivation) must NOT inherit the old abort snapshot.
	fresh := RestoreAbortController(4, snap)
	if fresh.Aborted(4) {
		t.Fatal("SECURITY: a new generation must not inherit a stale generation's abort snapshot")
	}
	if !fresh.ExecutionEligible(4) {
		t.Fatal("a fresh generation controller must be execution-eligible")
	}
}

// TestAbortController_NilFailsClosed proves a nil controller never reports request-scoped/eligible.
func TestAbortController_NilFailsClosed(t *testing.T) {
	var c *AbortController
	if r := c.Trip("policy_deny", 1, time.Unix(1, 0)); r != TripCanaryLatched {
		t.Fatalf("a nil controller must fail closed to latched, got %s", r)
	}
	if c.ExecutionEligible(1) {
		t.Fatal("a nil controller must never be execution-eligible")
	}
	if NewAbortController(0) != nil {
		t.Fatal("generation 0 must not arm a controller")
	}
}

// TestAbortController_ConcurrentTripsIdempotent is the atomicity gate: many goroutines tripping at
// once leave the controller aborted with a single stable code (no torn latch, no panic).
func TestAbortController_ConcurrentTripsIdempotent(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	c := NewAbortController(1)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Trip("scope_escape", 1, now)
		}()
	}
	wg.Wait()
	if !c.Aborted(1) || c.AbortCode() != "scope_escape" {
		t.Fatalf("concurrent trips must leave a single stable abort, code=%q aborted=%v", c.AbortCode(), c.Aborted(1))
	}
}
