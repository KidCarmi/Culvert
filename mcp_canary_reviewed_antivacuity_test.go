package main

import (
	"context"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/execution"
	"github.com/KidCarmi/Culvert/internal/mcp/inspection"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	mcpruntime "github.com/KidCarmi/Culvert/internal/mcp/runtime"
	"github.com/KidCarmi/Culvert/internal/mcp/tooltrust"
)

// mcp_canary_reviewed_antivacuity_test.go — §13 anti-vacuity for the reviewed-target gates.
//
// A negative gate is only worth its assertion if the request under test ACTUALLY HAPPENED. The
// hazard is specific and it is easy to write by accident: "the request was denied" is satisfied by
// a request denied for a reason that has nothing to do with the reviewed comparison — an unarmed
// lifecycle, a non-read-first operation, an exhausted budget, a fixture that never composed. Such
// a test passes forever while the mechanism it claims to pin is absent.
//
// The discipline applied here is the one the identity-attribution helper enforces on the proxy
// side (assertNoIdentityAttributionIn, authz_identity_ingress_test.go): before asserting that the
// forbidden thing is absent, PROVE the request produced the expected observation. Here the
// observation is the gate's own denial accounting — a bounded reason code incremented by exactly
// this request — so a denial that never reached the admission transaction cannot satisfy the gate.
//
// Every negative case below is paired with a positive control on the same fixture.

// denialObservations snapshots the process-wide live-gate denial counters.
func denialObservations() map[string]uint64 { return mcpLiveGateDenialSnapshot() }

// observedDenials reports how many denials of the given reason code were recorded since before.
//
// It stays in uint64 rather than converting: the counters are uint64, and a conversion to int is
// both a gosec G115 finding and a lie about the one case worth handling — a counter that appears to
// have gone BACKWARDS. That cannot happen through the production path (the counters are monotonic
// and this suite runs one request at a time), so it means a test reset the global between the two
// snapshots. Wrapping it into a huge positive delta would satisfy an "exactly 1" assertion at
// random; reporting 0 makes the anti-vacuity check fail, which is the safe direction for a helper
// whose entire job is refusing to accept evidence it cannot vouch for.
func observedDenials(before map[string]uint64, code string) uint64 {
	now := mcpLiveGateDenialSnapshot()[code]
	if now < before[code] {
		return 0
	}
	return now - before[code]
}

// assertDeniedWithObservation is the anti-vacuity assertion.
//
// It requires, in order: the request was refused; the refusal carries the EXPECTED bounded reason;
// and the gate recorded exactly one denial of that reason for this request. The last clause is the
// anti-vacuity half — without it, a fixture that never reached the gate at all would satisfy the
// first two by returning a zero-value decision.
func assertDeniedWithObservation(t *testing.T, before map[string]uint64, d execution.LiveGateDecision, want mcperr.Reason) {
	t.Helper()
	if d.Admit {
		t.Fatal("the request under test must be refused")
	}
	if d.Reason != want {
		t.Fatalf("denial reason = %q, want %q", d.Reason.Code(), want.Code())
	}
	if n := observedDenials(before, want.Code()); n != 1 {
		t.Fatalf("the gate recorded %d denials of %q for this request, want exactly 1: the request "+
			"under test did not produce the expected observation, so asserting on what it did NOT do "+
			"proves nothing (anti-vacuity)", n, want.Code())
	}
}

// ── the positive control ─────────────────────────────────────────────────────────────────────
// The fixture really does admit the reviewed target, and admitting records NO denial. Everything
// below is measured against this.
func TestReviewedAntiVacuity_FixtureAdmitsTheReviewedTargetAndRecordsNoDenial(t *testing.T) {
	r := newReviewedRig(t)
	before := denialObservations()
	d := r.g.AdmitSideEffect(driftGateInput(r.sid, r.tool, r.fp1, r.now))
	if d.Release != nil {
		d.Release()
	}
	if !d.Admit {
		t.Fatalf("the fixture must admit the reviewed target, reason=%s", d.Reason.Code())
	}
	after := denialObservations()
	for code, n := range after {
		if n > before[code] {
			t.Fatalf("an ADMITTED request recorded a denial of %q — the counter this file reads as "+
				"evidence would then be meaningless", code)
		}
	}
}

// ── drift, proven to have been observed ──────────────────────────────────────────────────────
func TestReviewedAntiVacuity_DriftDenialIsObservedNotAssumed(t *testing.T) {
	r := newReviewedRig(t)
	if !r.request(r.fp1, r.now) {
		t.Fatal("premise: the reviewed target must be admitted first")
	}
	fp2 := r.moveToF2(t)

	before := denialObservations()
	d := r.g.AdmitSideEffect(driftGateInput(r.sid, r.tool, fp2, r.now))
	if d.Release != nil {
		d.Release()
	}
	assertDeniedWithObservation(t, before, d, mcperr.ReasonLiveTrustRevalidationFailed)
	// Only now is the absence claim meaningful: the request reached the transaction and was
	// classified there.
	if !r.rt.abortedNow(r.capb) {
		t.Fatal("SECURITY: an observed drift denial must have latched the whole Canary")
	}
	if code := r.rt.abortCodeNow(r.capb); code != "tool_fingerprint_drift" {
		t.Fatalf("first cause = %q, want tool_fingerprint_drift", code)
	}
}

// ── an expired approval, proven to have been observed ────────────────────────────────────────
// The negative claim here is the delicate one: NOTHING latched. Without the observation proof, a
// fixture that silently stopped exercising the gate would satisfy it trivially and for ever.
func TestReviewedAntiVacuity_ExpiredApprovalDenialIsObservedAndLatchesNothing(t *testing.T) {
	r := newReviewedRig(t)
	expired := r.now.Add(48 * time.Hour)
	// The peer is re-observed AT the expired instant, so the only authority missing there is the
	// approval. Without this the observation is 48h stale too, admission refuses it first
	// (round 13 — freshness is asked before the approval, as at the boundary), and this case would
	// quietly stop proving anything about approval expiry.
	observeSeededToolTrustPeerAt(t, r.sid, expired)

	before := denialObservations()
	d := r.g.AdmitSideEffect(driftGateInput(r.sid, r.tool, r.fp1, expired))
	if d.Release != nil {
		d.Release()
	}
	assertDeniedWithObservation(t, before, d, mcperr.ReasonLiveTrustRevalidationFailed)
	if r.rt.abortedNow(r.capb) {
		t.Fatalf("SECURITY: an expired approval on an unchanged target must not stop the Canary "+
			"(abort code %q)", r.rt.abortCodeNow(r.capb))
	}
	// And the activation is still genuinely alive — the counterpart to "nothing latched". The
	// observation above was stamped at `expired`, which is in the FUTURE of r.now; re-observe at
	// r.now so this control is asked about the approval's life and nothing else.
	observeSeededToolTrustPeerAt(t, r.sid, r.now)
	if !r.request(r.fp1, r.now) {
		t.Fatal("the experiment must continue: the same request inside the approval's life is admitted")
	}
}

// ── an unreviewed target, proven to have been observed ───────────────────────────────────────
func TestReviewedAntiVacuity_OutOfScopeDenialIsObservedAndLatchesNothing(t *testing.T) {
	r := newReviewedRig(t)
	// Re-arm against a synthetic target, so the seeded one is genuinely OUTSIDE this activation's
	// review while remaining perfectly resolvable and perfectly approved.
	if err := r.rt.demoteCanary(r.capb); err != nil {
		t.Fatalf("demote: %v", err)
	}
	if _, err := r.rt.beginCanaryActivation(r.capb, canaryActivationSpec{
		Budget:          runtimeTestBudget(10),
		ReviewedTargets: []canary.ReviewedTarget{testReviewedTarget()},
		StartedAt:       canaryRuntimeTestNow,
	}); err != nil {
		t.Fatalf("re-arm: %v", err)
	}
	r.g = realAdmissionGate(t, r.capb)

	before := denialObservations()
	d := r.g.AdmitSideEffect(driftGateInput(r.sid, r.tool, r.fp1, r.now))
	if d.Release != nil {
		d.Release()
	}
	assertDeniedWithObservation(t, before, d, mcperr.ReasonLiveTrustRevalidationFailed)
	if r.rt.abortedNow(r.capb) {
		t.Fatal("SECURITY: a target outside the review is a REQUEST-scoped refusal — latching for it " +
			"would let any unrelated caller stop the experiment")
	}
}

// ── §7: upstream = 0 ─────────────────────────────────────────────────────────────────────────
// The end-to-end half. The three assertions above are about the gate's verdict; this one is about
// the physical effect, which is what the blocker is ultimately written in terms of: a drifted
// target must produce ZERO upstream calls.
//
// The control runs FIRST and on the SAME harness, so "no upstream call" can never mean "the
// harness never worked" — the exact vacuity this file exists to rule out.
func TestReviewedAntiVacuity_DriftedTargetReachesNoUpstream(t *testing.T) {
	fpReviewed := tooltrust.FingerprintDigest{0xA1}
	fpMoved := tooltrust.FingerprintDigest{0xA2}

	t.Run("control: the reviewed target crosses exactly once", func(t *testing.T) {
		up := &recordingUpstream{}
		ex := armReviewedLiveTier(t, up, fpReviewed, fpReviewed).Deps.Executor
		in := liveExecInput(policy.OpRead, "t1", "p1")
		in.ToolStillCurrent = func() bool { return true }
		out := ex.Execute(context.Background(), in, ex.Resolve(in))
		if up.callCount() != 1 {
			t.Fatalf("control: the reviewed target must cross exactly once, calls=%d", up.callCount())
		}
		if !out.Executed {
			t.Fatal("control: the reviewed target must report executed")
		}
	})

	t.Run("the drifted target reaches no upstream and stops the experiment", func(t *testing.T) {
		up := &recordingUpstream{}
		ex := armReviewedLiveTier(t, up, fpReviewed, fpMoved).Deps.Executor
		in := liveExecInput(policy.OpRead, "t1", "p1")
		in.ToolStillCurrent = func() bool { return true }
		out := ex.Execute(context.Background(), in, ex.Resolve(in))
		if up.callCount() != 0 {
			t.Fatalf("SECURITY: a target that is not the reviewed one must produce NO upstream call, "+
				"calls=%d", up.callCount())
		}
		if out.Executed {
			t.Fatal("a refused request must not report executed")
		}
		if !globalCanaryRuntime.abortedNow(rollout.CapabilityGateway) {
			t.Fatal("SECURITY: the drift must stop the whole Canary, not just this request")
		}
		if code := globalCanaryRuntime.abortCodeNow(rollout.CapabilityGateway); code != "tool_fingerprint_drift" {
			t.Fatalf("first cause = %q, want tool_fingerprint_drift", code)
		}
	})
}

// armReviewedLiveTier composes an ARMED, Canary-active live tier exactly as armCanaryLiveTier
// does, but binds two things independently: the fingerprint the activation was REVIEWED against,
// and the fingerprint the trust precheck currently OBSERVES. Holding everything else identical and
// moving only the observed one is what makes the pair above a controlled comparison rather than
// two differently-built fixtures.
//
// The approval half is stubbed to SATISFIED throughout, deliberately: it removes the one other
// thing that could have produced the denial, so a refusal in the moved case can only have come
// from the reviewed comparison.
func armReviewedLiveTier(t *testing.T, up *recordingUpstream, reviewedFP, currentFP tooltrust.FingerprintDigest) *mcpruntime.Config {
	t.Helper()
	resetLiveTierGlobals(t)
	swapCanaryClock(t, func() time.Time { return time.Unix(0, 1) })
	setDataDirForTest(t, t.TempDir())

	capb := rollout.CapabilityGateway
	gw := getMCPRollout().gateway
	prevCfg := gw.CurrentConfig()
	if err := gw.SetConfig(*gwCanaryCfg(1), "test", time.Unix(0, 1).UnixNano()); err != nil {
		t.Fatalf("SetConfig canary: %v", err)
	}
	t.Cleanup(func() { _ = gw.SetConfig(prevCfg, "test-restore", time.Unix(0, 2).UnixNano()) })

	gate := liveRealGate(capb, true)
	gate.trustPrecheck = stubTrustPrecheckAt(currentFP)
	cfg := &mcpruntime.Config{}
	if err := composeGatewayLiveTierInto(cfg, liveTierComposition{
		Upstream: up, Events: liveTestEvents(t),
		ResponseProfile: inspection.DefaultGatewayProfile(1),
		Clock:           func() time.Time { return time.Unix(0, 1) },
		LiveGate:        gate,
	}); err != nil {
		t.Fatalf("compose live tier: %v", err)
	}
	if err := mcpLiveTierFor(capb).arm(true, "armed"); err != nil {
		t.Fatalf("arm: %v", err)
	}
	reviewed := testReviewedTarget()
	reviewed.Fingerprint = reviewedFP
	if _, err := globalCanaryRuntime.beginCanaryActivation(capb, canaryActivationSpec{
		Budget:          runtimeTestBudget(5),
		ReviewedTargets: []canary.ReviewedTarget{reviewed},
		StartedAt:       time.Unix(0, 1),
	}); err != nil {
		t.Fatalf("begin activation: %v", err)
	}
	return cfg
}
