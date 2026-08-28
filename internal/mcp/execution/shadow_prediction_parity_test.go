package execution

// shadow_prediction_parity_test.go — the SR-01/SR-02 regression wall for the ONE
// invariant Shadow evidence rests on: a Shadow prediction must never be MORE PERMISSIVE
// than the enforcement it predicts.
//
// Shadow exists to produce the evidence an operator reads before promoting a scope to
// Canary. Every over-optimistic WOULD_EXECUTE is therefore a decision input that says
// "this traffic is ready to enforce" about traffic a fully-enforcing mode would refuse.
// Under-prediction (a would-block where live executes) costs an unnecessary hesitation;
// OVER-prediction costs a promotion made on false evidence, which is the direction this
// file walls off.
//
// Both findings are the same shape — a live pre-side-effect refusal the Shadow
// evaluator's decide() did not model — and both were reproduced against the pre-fix tree
// (PR #1226, commit e698a12) before either fix was written.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	"github.com/KidCarmi/Culvert/internal/mcp/runtime"
)

// ─────────────────────────── SR-01 · allowance capacity ───────────────────────────

// TestSR01_WouldSatisfyMatchesConsumeForAnExpiredSessionKeyAtCapacity is the
// differential gate for SR-01.
//
// consume() sweeps expired session grants BEFORE its capacity check, so a request whose
// own key is an expired ALLOW_FOR_SESSION slot has that slot DELETED by the sweep; if the
// store is still at capacity afterwards, the key is then absent and consume refuses (fail
// closed, ReasonAllowanceConsumed). wouldSatisfy read `sessKnown` BEFORE any sweep and
// treated the doomed slot as a reusable one, so it skipped the capacity gate entirely and
// answered "yes" — Shadow predicting WOULD_EXECUTE for a request live enforcement blocks.
//
// The pre-existing capacity tests do not reach this: TestAllowance_WouldSatisfyMirrors...
// uses a key that is ABSENT, and ...ReclaimsExpiredSessions frees a slot so the store is
// no longer at capacity. This case is the intersection — the requesting key is present
// but expired AND the store stays full — which is exactly where the two functions
// disagree.
func TestSR01_WouldSatisfyMatchesConsumeForAnExpiredSessionKeyAtCapacity(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	target := keyedInput(maxAllowanceEntries + 7)

	build := func() *allowanceStore {
		s := newAllowanceStore()
		// Fill to capacity with un-reclaimable ALLOW_ONCE records (never expired).
		for i := 0; i < maxAllowanceEntries; i++ {
			s.once[allowanceKey(keyedInput(i))] = struct{}{}
		}
		// The requesting key holds an EXPIRED session slot: present now, swept by consume.
		s.sess[allowanceKey(target)] = &sessGrant{calls: 1, expiry: now.Add(-time.Hour)}
		return s
	}

	// Control: this is what live enforcement actually does.
	if build().consume(target, rollout.ActionKindAllowSession, now) {
		t.Fatal("control: consume must refuse — its sweep deletes the expired slot and the store is still at capacity")
	}
	// The prediction must agree.
	if build().wouldSatisfy(target, rollout.ActionKindAllowSession, now) {
		t.Fatal("SR-01: wouldSatisfy predicted the allowance would be satisfied where consume refuses — " +
			"Shadow would report WOULD_EXECUTE for a request Canary/Production blocks with allowance_consumed")
	}
}

// TestSR01_WouldSatisfyStillAdmitsALiveSessionSlotAtCapacity is the negative half: the
// SR-01 fix must not over-tighten. A NON-expired session slot survives consume's sweep, so
// its owner is never refused at capacity — and wouldSatisfy must keep saying so.
func TestSR01_WouldSatisfyStillAdmitsALiveSessionSlotAtCapacity(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	target := keyedInput(maxAllowanceEntries + 9)

	build := func() *allowanceStore {
		s := newAllowanceStore()
		for i := 0; i < maxAllowanceEntries-1; i++ {
			s.once[allowanceKey(keyedInput(i))] = struct{}{}
		}
		s.sess[allowanceKey(target)] = &sessGrant{calls: 1, expiry: now.Add(time.Hour)} // live
		return s
	}
	if !build().consume(target, rollout.ActionKindAllowSession, now) {
		t.Fatal("control: consume must admit a request reusing its own LIVE session slot at capacity")
	}
	if !build().wouldSatisfy(target, rollout.ActionKindAllowSession, now) {
		t.Fatal("SR-01 over-tightened: wouldSatisfy refused a live session slot consume admits")
	}
}

// TestSR01_WouldSatisfyNeverMutatesTheStore pins the read-only contract the shared
// allowance store depends on. The Shadow evaluator embedded in a live Executor reads the
// SAME store the live path consumes from (executor.go), so any mutation here would let a
// Shadow evaluation burn a real ALLOW_ONCE grant — a Shadow request causing an
// enforcement-visible state change, which is the whole thing Layer B forbids.
func TestSR01_WouldSatisfyNeverMutatesTheStore(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s := newAllowanceStore()
	fresh := keyedInput(1)
	live := keyedInput(2)
	expired := keyedInput(3)
	s.sess[allowanceKey(live)] = &sessGrant{calls: 3, expiry: now.Add(time.Hour)}
	s.sess[allowanceKey(expired)] = &sessGrant{calls: 3, expiry: now.Add(-time.Hour)}
	s.once[allowanceKey(keyedInput(4))] = struct{}{}

	wantOnce, wantSess := len(s.once), len(s.sess)
	wantCalls := s.sess[allowanceKey(live)].calls

	for _, in := range []runtime.ExecInput{fresh, live, expired} {
		for _, a := range []rollout.ActionKind{rollout.ActionKindAllowOnce, rollout.ActionKindAllowSession, rollout.ActionKindAllow} {
			s.wouldSatisfy(in, a, now)
		}
	}
	if len(s.once) != wantOnce || len(s.sess) != wantSess {
		t.Fatalf("wouldSatisfy mutated the store: once %d→%d, sess %d→%d (it must never consume, create or sweep)",
			wantOnce, len(s.once), wantSess, len(s.sess))
	}
	if got := s.sess[allowanceKey(live)].calls; got != wantCalls {
		t.Fatalf("wouldSatisfy consumed a session call: %d→%d", wantCalls, got)
	}
}

// TestSR01_WouldSatisfyIsSafeUnderConcurrentConsume runs the prediction against the live
// consumption path on the SHARED store. Under -race this is the gate that the read-only
// predictor takes the same lock the mutator does.
func TestSR01_WouldSatisfyIsSafeUnderConcurrentConsume(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s := newAllowanceStore()
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(2)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				s.consume(keyedInput(g*1000+i), rollout.ActionKindAllowSession, now)
			}
		}(g)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				s.wouldSatisfy(keyedInput(g*1000+i), rollout.ActionKindAllowSession, now)
			}
		}(g)
	}
	wg.Wait()
}

// ─────────────────────── SR-02 · upstream-server usability ───────────────────────

// TestSR02_ShadowPredictsTheLiveUpstreamServerRefusal is the differential gate for SR-02.
//
// The live path refuses an absent or unusable upstream server record in runExecute —
// before the durable commit, before credential planning, before the call —
// with ReasonUpstreamServerUnusable, a HardServerTrust hard failure. decide() modelled
// hard controls, policy class, allowance, credential readiness and boundary drift, but not
// this gate, so Shadow answered WOULD_EXECUTE for a server live enforcement will not call.
//
// registry.ServerRecord.Usable() is `Enabled && Verification == VerifyVerified`. The
// policy engine reaches the same facts, but it reads them from the DECISION SNAPSHOT while
// the executor re-reads the LIVE registry (dispatchExecute) — which is precisely why the
// live refusal exists. So the reachable divergence is a TOCTOU window: the record was
// usable when the decision was computed (no hard override on the decision) and is
// disabled, identity-mismatched or gone by the time the executor looks. The absent-record
// case is the deregistration race — identity.Resolve admitted the id, then the registry
// lookup in dispatchExecute missed. In every one of them live refuses and Shadow, pre-fix,
// promised WOULD_EXECUTE.
func TestSR02_ShadowPredictsTheLiveUpstreamServerRefusal(t *testing.T) {
	cases := []struct {
		name string
		rec  *registry.ServerRecord
	}{
		{
			name: "absent_record",
			rec:  nil,
		},
		{
			name: "disabled_after_the_decision",
			rec: &registry.ServerRecord{
				ID: "s1", Endpoint: "https://s1.internal:443", PinnedIdentity: "pin1",
				Enabled: false, Verification: registry.VerifyVerified,
			},
		},
		{
			name: "identity_mismatched_after_the_decision",
			rec: &registry.ServerRecord{
				ID: "s1", Endpoint: "https://s1.internal:443", PinnedIdentity: "pin1",
				Enabled: true, Verification: registry.VerifyIdentityMismatch,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := execInput(policy.ActionAllow, false)
			in.Server = tc.rec

			live, up := liveCanary(t)
			shadow := shadowEval(t, nil)

			liveOut := runExec(live, context.Background(), in)
			shadowOut := runExec(shadow, context.Background(), in)

			if liveOut.Executed || up.calls != 0 {
				t.Fatalf("control: live enforcement must refuse an unusable server before the side effect (executed=%v calls=%d)",
					liveOut.Executed, up.calls)
			}
			if shadowOut.Executed {
				t.Fatal("shadow must never execute")
			}

			gotLive := liveCanon(t, in, liveOut, up.calls)
			gotShadow := shadowCanon(t, shadowOut)
			if gotLive != cFailHardControl {
				t.Fatalf("control: live verdict = %v, want fail_hard_control (upstream_server_unusable)", gotLive)
			}
			if gotShadow != gotLive {
				t.Fatalf("SR-02 DIFFERENTIAL DIVERGENCE: live=%v shadow=%v — Shadow evidence must never be more permissive than the enforcement it predicts",
					gotLive, gotShadow)
			}
		})
	}
}

// TestSR02_UsableServerStillPredictsWouldExecute is the negative half: the SR-02 gate must
// refuse ONLY what live refuses. A registered, enabled, verified server with an otherwise
// clean request still predicts WOULD_EXECUTE.
func TestSR02_UsableServerStillPredictsWouldExecute(t *testing.T) {
	in := execInput(policy.ActionAllow, false) // carries Enabled + VerifyVerified
	shadow := shadowEval(t, nil)
	out := runExec(shadow, context.Background(), in)
	if got := shadowCanon(t, out); got != cExecute {
		t.Fatalf("shadow verdict = %v, want execute — the server-usability gate must not refuse a usable server", got)
	}
}

// TestSR02_ServerUsabilityIsCheckedAfterPolicyAndAllowance pins the ORDER, not just the
// presence, of the new gate: live checks the server record inside runExecute, which is
// reached only AFTER the policy class and the allowance consumption. A request that is
// both allowance-exhausted and pointed at an unusable server must therefore report the
// ALLOWANCE verdict in both paths — putting the server gate earlier would silently
// re-order which control an operator sees fire.
func TestSR02_ServerUsabilityIsCheckedAfterPolicyAndAllowance(t *testing.T) {
	in := execInput(policy.ActionAllowOnce, false)
	in.Server = nil // also unusable

	live, up := liveCanary(t)
	shadow := shadowEval(t, nil)
	seedConsumedOnce(t, live.allowances, in)
	seedConsumedOnce(t, shadow.allowances, in)

	gotLive := liveCanon(t, in, runExec(live, context.Background(), in), up.calls)
	gotShadow := shadowCanon(t, runExec(shadow, context.Background(), in))
	if gotLive != cBlock {
		t.Fatalf("control: live verdict = %v, want block (allowance_consumed precedes the server gate)", gotLive)
	}
	if gotShadow != gotLive {
		t.Fatalf("order divergence: live=%v shadow=%v — the server-usability gate must sit where live sits it", gotLive, gotShadow)
	}
}
