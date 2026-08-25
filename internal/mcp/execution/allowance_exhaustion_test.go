package execution

import (
	"strconv"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	"github.com/KidCarmi/Culvert/internal/mcp/runtime"
)

// keyedInput returns an ExecInput whose allowance key is unique in n.
func keyedInput(n int) runtime.ExecInput {
	in := execInputBare()
	in.Input.Session.Fingerprint = "sess-" + strconv.Itoa(n)
	return in
}

func execInputBare() runtime.ExecInput {
	return runtime.ExecInput{
		Input: policy.DecisionInput{
			Principal: policy.Principal{SubjectID: "p1", Tenant: "t1"},
			Tool:      &policy.Tool{Name: "read_file", ServerID: "s1", FingerprintHash: "fp1"},
			Session:   policy.Session{Fingerprint: "sess"},
		},
	}
}

// OVN-10. The allowance store is bounded at maxAllowanceEntries and refuses a NEW
// grant at capacity — correct, fail-closed. But an ALLOW_FOR_SESSION grant was
// only ever discarded when the SAME key was looked up again, so a grant whose
// session has timed out and is never revisited stayed in the table forever,
// occupying a slot it can never use. Enough of them and the store refuses every
// new allowance-gated operation with no recovery short of a process restart.
//
// Reclaiming them is provably behaviour-neutral: consume() already treats an
// expired grant as absent.
func TestAllowance_ExpiredSessionGrantsDoNotPermanentlyExhaustTheStore(t *testing.T) {
	s := newAllowanceStore()
	base := time.Unix(1_700_000_000, 0)

	// Fill the store with session grants that will all time out.
	for i := 0; i < maxAllowanceEntries; i++ {
		if !s.consume(keyedInput(i), rollout.ActionKindAllowSession, base) {
			t.Fatalf("filling: grant %d refused before capacity", i)
		}
	}

	// Long after every one of them has expired, a NEW grant must still be
	// obtainable — the dead entries must not hold the table hostage.
	later := base.Add(100 * sessionTTL)
	if !s.consume(keyedInput(maxAllowanceEntries+1), rollout.ActionKindAllowSession, later) {
		t.Fatal("a new grant was refused because the store is full of long-expired session " +
			"grants: the capacity bound has become a permanent denial of service")
	}
}

// The sweep must reclaim ONLY what consume() already ignores. A live session grant
// keeps both its remaining call budget and its expiry across a sweep — reclaiming
// one would silently hand its holder a fresh cap.
func TestAllowance_SweepPreservesLiveSessionGrants(t *testing.T) {
	s := newAllowanceStore()
	base := time.Unix(1_700_000_000, 0)
	live := keyedInput(1)

	// Spend the live grant's budget down to a single remaining call.
	for i := 0; i < sessionCallCap-1; i++ {
		if !s.consume(live, rollout.ActionKindAllowSession, base) {
			t.Fatalf("call %d within the cap was refused", i)
		}
	}

	// Drive the store to capacity so the sweep runs, using grants that are already
	// dead at the sweep instant.
	sweepAt := base.Add(sessionTTL / 2) // live is still inside its TTL here
	for i := 0; i < maxAllowanceEntries; i++ {
		s.consume(keyedInput(1000+i), rollout.ActionKindAllowSession, base.Add(-2*sessionTTL))
	}

	// One call left, then the cap must bite: the sweep must not have reset it.
	if !s.consume(live, rollout.ActionKindAllowSession, sweepAt) {
		t.Fatal("the live grant's last call was refused")
	}
	if s.consume(live, rollout.ActionKindAllowSession, sweepAt) {
		t.Fatal("a live session grant was reclaimed by the sweep: its call cap was reset")
	}
}

// ALLOW_ONCE is single-use FOR EVER, and no amount of capacity pressure or elapsed
// time may turn it back into a usable grant.
//
// This is the invariant that forbids the obvious "just give every entry a TTL"
// tidy-up. allowanceKey is built from identity.ResolvedContext.Fingerprint, which
// is a stable hash over (capability, tenant, subject, client, agent, resource,
// server, tool) and carries no time, session id or nonce — the same principal
// invoking the same tool produces the same key for the life of the deployment. So
// an expiring ALLOW_ONCE record is not garbage collection, it is a replay window.
func TestAllowance_OnceGrantsNeverBecomeReplayable(t *testing.T) {
	s := newAllowanceStore()
	base := time.Unix(1_700_000_000, 0)
	in := keyedInput(1)

	if !s.consume(in, rollout.ActionKindAllowOnce, base) {
		t.Fatal("first consumption must succeed")
	}
	if s.consume(in, rollout.ActionKindAllowOnce, base) {
		t.Fatal("ALLOW_ONCE was consumed twice")
	}
	// Elapsed time must not revive it — not one TTL, not a hundred.
	for _, d := range []time.Duration{sessionTTL / 2, sessionTTL + time.Second, 100 * sessionTTL} {
		if s.consume(in, rollout.ActionKindAllowOnce, base.Add(d)) {
			t.Fatalf("ALLOW_ONCE was replayed after %s: single use is not time-bounded", d)
		}
	}
	// Nor may capacity pressure (which runs the sweep) evict it.
	for i := 0; i < maxAllowanceEntries; i++ {
		s.consume(keyedInput(1000+i), rollout.ActionKindAllowSession, base.Add(-2*sessionTTL))
	}
	if s.consume(in, rollout.ActionKindAllowOnce, base.Add(100*sessionTTL)) {
		t.Fatal("ALLOW_ONCE was replayed after the sweep ran under capacity pressure")
	}
}

// A session grant still enforces its call cap and its TTL.
func TestAllowance_SessionGrantCapAndTTLUnchanged(t *testing.T) {
	s := newAllowanceStore()
	base := time.Unix(1_700_000_000, 0)
	in := keyedInput(7)

	for i := 0; i < sessionCallCap; i++ {
		if !s.consume(in, rollout.ActionKindAllowSession, base) {
			t.Fatalf("call %d within the cap was refused", i)
		}
	}
	if s.consume(in, rollout.ActionKindAllowSession, base) {
		t.Fatal("the session call cap was exceeded")
	}
	// After the TTL a fresh grant is issued (existing behaviour).
	if !s.consume(in, rollout.ActionKindAllowSession, base.Add(sessionTTL+time.Second)) {
		t.Fatal("a new session grant after the TTL was refused")
	}
}
