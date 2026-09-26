package main

import (
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/execution"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// mcp_canary_atomic_binding_test.go — the §8 race matrix for the ATOMIC activation-bound admission
// transaction.
//
// Every case here is BARRIER-DRIVEN: the racing goroutine is released from inside the trust probe,
// which runs while the activation lock is held, so the interleaving under test is forced rather
// than hoped for. There are no sleeps and no timing assumptions; each case is deterministic on any
// hardware, at any load, with or without -race.
//
// The property under test is the one five previous iterations failed to establish: an observation
// may latch generation G only if G was active before the observation began, stayed the same active
// activation throughout it, and the latch decision was made against G atomically.

// atomicRig is one armed capability runtime plus the knobs the matrix needs.
type atomicRig struct {
	rt   *canaryRuntime
	capb rollout.Capability
}

func newAtomicRig(t *testing.T) *atomicRig {
	t.Helper()
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	swapCanaryClock(t, func() time.Time { return canaryRuntimeTestNow })
	swapCanaryTimer(t)
	return &atomicRig{rt: rt, capb: rollout.CapabilityGateway}
}

func (r *atomicRig) arm(t *testing.T, total int) uint64 {
	t.Helper()
	return r.armFor(t, total)
}

// armFor arms an activation reviewed for EXPLICIT targets. Tests that seed a real inventory and
// then observe drift on it must use this: since round 31 the reviewed set decides whether an
// activation may be stopped at all, so an activation armed with the canonical SYNTHETIC target
// (server-a/tool-a) is correctly immune to drift on a different, real one — and a test that arms
// synthetically while observing `controlled/t` proves nothing about the latch it is named for.
func (r *atomicRig) armFor(t *testing.T, total int, targets ...canary.ReviewedTarget) uint64 {
	t.Helper()
	spec := testActivationSpec(runtimeTestBudget(total), canaryRuntimeTestNow, targets...)
	if _, err := r.rt.beginCanaryActivation(r.capb, spec); err != nil {
		t.Fatalf("begin activation: %v", err)
	}
	g := r.rt.currentGeneration(r.capb)
	if g == 0 {
		t.Fatal("premise: an armed activation must have a non-zero generation")
	}
	return g
}

// remaining reports the CURRENT activation's unspent budget. It is how the matrix proves WHICH
// enforcer a reservation actually landed on — a generation number in the result struct cannot,
// because it is captured before the work happens.
func (r *atomicRig) remaining() int {
	cr := r.rt.capRuntime(r.capb)
	cr.mu.Lock()
	defer cr.mu.Unlock()
	if cr.enforcer == nil {
		return -1
	}
	return cr.enforcer.Remaining()
}

func (r *atomicRig) admit(trust canaryTrustProbe) canaryAdmission {
	return r.admitAs(policy.OpRead, trust)
}

// admitAs drives one transaction with an explicit decided operation class. The default above is
// OpRead because that is the class this file's fixtures arm and the only one a tool call can carry
// through the First-Canary gate; a case ABOUT the class mismatch states the other one explicitly.
func (r *atomicRig) admitAs(opClass policy.OperationClass, trust canaryTrustProbe) canaryAdmission {
	return r.admitFull(opClass, testScopeHash, scopeProbe(testScopeHash), trust)
}

// admitFull drives one transaction with every boundary fact stated. Cases ABOUT the scope
// envelope use it directly; everything else takes the agreeing pair above, since a rig whose
// scope never matched would make every other assertion in this file unreachable.
func (r *atomicRig) admitFull(opClass policy.OperationClass, resolvedScope string, scopeNow canaryScopeProbe, trust canaryTrustProbe) canaryAdmission {
	return r.rt.admitLiveExecution(r.capb, canaryRuntimeTestNow, opClass, resolvedScope, scopeNow, canary.ExecutionIdentity{
		Principal: "p1", Tool: "t1", Server: "s1",
	}, trust)
}

// testScopeHash is the canonical synthetic authorization envelope: a request resolved under it and
// it is still installed. Shaped like a real scope hash (hex) so a test cannot pass on a value the
// production type would never carry.
const testScopeHash = "5c09e0f2b1d34a7e8f6c2b0a9d1e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e"

// scopeProbe returns a canaryScopeProbe reporting a fixed installed envelope.
func scopeProbe(h string) canaryScopeProbe { return func() string { return h } }

// probeDrift returns a probe reporting an authoritative drift ON A RESOLVED TARGET.
//
// The target is carried because a code without one is not a shape production can produce: every
// return in mcpLiveTrustPrecheck that sets DriftCode also sets Resolved, which
// TestReviewedBinding_C28 pins structurally. It matters because round 31 made the reviewed set
// decide WHETHER a cause may stop the activation — an observation with nothing to compare against
// latches nothing, since scope cannot be established for it. Carrying the canonical reviewed
// target keeps these cases exercising the drift path they are about rather than the
// nothing-resolved path.
func probeDrift(code string) canaryTrustProbe {
	return func() canaryTrustObservation {
		return canaryTrustObservation{DriftCode: code, Found: true, Current: testReviewedTarget()}
	}
}

// probeTrusted returns a probe reporting healthy trust.
// probeTrusted reports an authorized request whose CURRENT target is exactly the canonical
// synthetic reviewed target, so the transaction's reviewed comparison matches and the test
// exercises what it is about rather than tripping the new gate.
func probeTrusted() canaryTrustProbe {
	return func() canaryTrustObservation {
		return canaryTrustObservation{Found: true, Current: testReviewedTarget(), Trusted: true}
	}
}

// ── A. Normal drift ──────────────────────────────────────────────────────────

// TestAtomicBinding_A_DriftLatchesTheActiveGeneration is the base case: with G active, an
// authoritative drift latches G, denies the request, and authorizes no attempt.
func TestAtomicBinding_A_DriftLatchesTheActiveGeneration(t *testing.T) {
	r := newAtomicRig(t)
	g := r.arm(t, 3)

	adm := r.admit(probeDrift("tool_fingerprint_drift"))

	if adm.Denial != canaryAdmitDrift {
		t.Fatalf("want a drift denial, got %v", adm.Denial)
	}
	if adm.Generation != g {
		t.Fatalf("the drift must be charged to the active generation %d, got %d", g, adm.Generation)
	}
	if !adm.Latched || !r.rt.abortedNow(r.capb) {
		t.Fatal("SECURITY: an authoritative drift under an active activation must latch the whole Canary")
	}
	if adm.Granted() {
		t.Fatal("SECURITY: a drifted request must not be authorized")
	}
	if st := canaryAbortStatusFor(r.capb); st.FirstAbortReason != "tool_fingerprint_drift" {
		t.Fatalf("first cause should be the drift, got %q", st.FirstAbortReason)
	}
}

// ── B. Demotion racing the observation ───────────────────────────────────────

// TestAtomicBinding_B_DemotionRacingTheObservationNeverLatchesTheReplacement forces a demotion to
// race the trust evaluation by releasing it from INSIDE the probe.
//
// Because the probe runs under the activation lock, the demotion cannot interleave: it blocks until
// the transaction finishes. So exactly one of two outcomes is legal — the observation owned G and
// latched G, or it never started and saw no active G. What must never happen is a latch of anything
// other than G.
func TestAtomicBinding_B_DemotionRacingTheObservationNeverLatchesTheReplacement(t *testing.T) {
	r := newAtomicRig(t)
	g := r.arm(t, 3)

	var wg sync.WaitGroup
	released := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-released // released from inside the critical section
		_ = r.rt.demoteCanary(r.capb)
	}()

	drift := probeDrift("tool_fingerprint_drift")
	adm := r.admit(func() canaryTrustObservation {
		close(released) // the demotion is now runnable and MUST be unable to proceed
		return drift()  // production-shaped: a code always carries the target it drifted from
	})
	wg.Wait()

	if adm.Generation != g {
		t.Fatalf("SECURITY: the transaction must be bound to the generation it started under (%d), got %d", g, adm.Generation)
	}
	if adm.Denial != canaryAdmitDrift {
		t.Fatalf("want a drift denial, got %v", adm.Denial)
	}
	if adm.Granted() {
		t.Fatal("SECURITY: a drifted request must never be authorized")
	}
}

// ── C. Reactivation ──────────────────────────────────────────────────────────

// TestAtomicBinding_C_ObservationCanNeverLatchTheReplacementActivation is the round-15-to-19
// finding stated as a property: an observation that began under G can never stop G+1.
//
// The demote AND the re-activation are both released from inside the probe, so the transaction
// completes against G while a whole new activation is waiting to be created. The new activation
// must start clean.
func TestAtomicBinding_C_ObservationCanNeverLatchTheReplacementActivation(t *testing.T) {
	r := newAtomicRig(t)
	g1 := r.arm(t, 3)

	var wg sync.WaitGroup
	released := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-released
		_ = r.rt.demoteCanary(r.capb)
		_, _ = testBeginActivation(r.rt, r.capb, runtimeTestBudget(3), canaryRuntimeTestNow)
	}()

	// probeDrift, not a bare code: the replacement activation is armed with the SAME canonical
	// reviewed target, so with the generation re-verification removed this drift WOULD latch it.
	// A bare code carries no target, and since round 31 an observation with nothing to compare
	// against latches nothing at all — which made this gate pass for the wrong reason and let
	// mutation M08 survive.
	drift := probeDrift("tool_fingerprint_drift")
	adm := r.admit(func() canaryTrustObservation {
		close(released)
		return drift()
	})
	wg.Wait()

	g2 := r.rt.currentGeneration(r.capb)
	if g2 == g1 {
		t.Fatalf("premise: the racing goroutine must have created a new generation, still %d", g1)
	}
	if adm.Generation != g1 {
		t.Fatalf("SECURITY: the observation must be charged to %d, got %d", g1, adm.Generation)
	}
	if r.rt.abortedNow(r.capb) {
		t.Fatal("SECURITY: an observation that began under the previous activation stopped the one " +
			"that replaced it — the new experiment never saw this drift")
	}
	if st := canaryAbortStatusFor(r.capb); st.ExecutionAuthority != "granted" {
		t.Fatalf("the fresh activation must keep its authority, got %q", st.ExecutionAuthority)
	}
}

// ── D. The rollout publication gap ───────────────────────────────────────────

// TestAtomicBinding_D_PublicationGapDeniesAndPoisonsNothing covers §6: commitRolloutTransitionAt
// publishes the live Canary mode BEFORE beginCanaryActivation arms the runtime, so a request can
// resolve to an executing disposition while no activation exists.
//
// Admission must fail closed, and — the part that matters — a drift observed in that interval must
// not be banked against the activation that arrives next.
func TestAtomicBinding_D_PublicationGapDeniesAndPoisonsNothing(t *testing.T) {
	r := newAtomicRig(t) // deliberately NOT armed: this is the gap

	probed := false
	adm := r.admit(func() canaryTrustObservation {
		probed = true
		return probeDrift("tool_fingerprint_drift")()
	})

	if adm.Denial != canaryAdmitNoActivation {
		t.Fatalf("admission must fail closed with no activation, got %v", adm.Denial)
	}
	if adm.Generation != 0 || adm.Latched {
		t.Fatalf("nothing may be attributed or latched with no activation: gen=%d latched=%v", adm.Generation, adm.Latched)
	}
	if probed {
		t.Fatal("the trust probe must not even run without an activation to attribute it to")
	}

	// The activation now arrives. It must start clean — the gap observation cannot have poisoned it.
	g := r.arm(t, 3)
	if r.rt.abortedNow(r.capb) {
		t.Fatalf("SECURITY: a drift observed during the publication gap latched activation %d, "+
			"which did not exist when it was observed", g)
	}
	if st := canaryAbortStatusFor(r.capb); st.ExecutionAuthority != "granted" {
		t.Fatalf("the new activation must be executable, got %q", st.ExecutionAuthority)
	}
}

// ── E. Trust under G, reservation under G+1 ──────────────────────────────────

// TestAtomicBinding_E_TrustAndReservationShareOneGeneration constructs the old race deliberately:
// a demote-and-reactivate released from inside the probe, on the path that RESERVES.
//
// Under the previous design the trust verdict and the reservation were separate calls, so a request
// could be trusted under G and reserve under G+1. Here they are one transaction, so the split is
// not merely unlikely — it is unrepresentable.
func TestAtomicBinding_E_TrustAndReservationShareOneGeneration(t *testing.T) {
	r := newAtomicRig(t)
	g1 := r.arm(t, 3)

	var wg sync.WaitGroup
	released := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-released
		_ = r.rt.demoteCanary(r.capb)
		_, _ = testBeginActivation(r.rt, r.capb, runtimeTestBudget(3), canaryRuntimeTestNow)
	}()

	adm := r.admit(func() canaryTrustObservation {
		close(released) // a replacement activation is now racing the reservation below
		return canaryTrustObservation{Found: true, Current: testReviewedTarget(), Trusted: true}
	})
	wg.Wait()

	g2 := r.rt.currentGeneration(r.capb)
	if g2 == g1 {
		t.Fatalf("premise: a replacement generation must exist, still %d", g1)
	}
	if !adm.Trusted {
		t.Fatal("premise: the probe reported trust")
	}
	if adm.Generation != g1 {
		t.Fatalf("SECURITY: trust was evaluated under %d but the transaction reports %d — a request "+
			"must not inherit trust from one activation and budget authority from another", g1, adm.Generation)
	}
	// THE ACTUAL PROOF, and the reason a generation field is not enough: a result struct captured
	// before the work happened still SAYS g1 even if the spend landed on the replacement's enforcer.
	// So look at where the budget actually went. G2 was armed with a full budget and no request has
	// ever been admitted under it; if the reservation leaked across the boundary, G2 is short.
	if got, want := r.remaining(), 3; got != want {
		t.Fatalf("SECURITY: the replacement activation has %d of %d slots left — this request was "+
			"trusted under %d and spent budget under %d", got, want, g1, g2)
	}
}

// ── F. Control ───────────────────────────────────────────────────────────────

// TestAtomicBinding_F_HealthyRequestReservesUnderExactlyG is the anti-vacuity control. Without it,
// a transaction that denied everything would satisfy every case above.
func TestAtomicBinding_F_HealthyRequestReservesUnderExactlyG(t *testing.T) {
	r := newAtomicRig(t)
	g := r.arm(t, 3)

	adm := r.admit(probeTrusted())

	if !adm.Granted() {
		t.Fatalf("control: a trusted request under an armed activation with budget must be granted, got %v", adm.Denial)
	}
	if adm.Generation != g {
		t.Fatalf("control: the reservation must be made under exactly %d, got %d", g, adm.Generation)
	}
	if r.rt.abortedNow(r.capb) {
		t.Fatal("control: a healthy admission must not stop the Canary")
	}
	if adm.DriftCode != "" || adm.Latched {
		t.Fatalf("control: nothing should have latched: drift=%q latched=%v", adm.DriftCode, adm.Latched)
	}
}

// ── Structural: the lock is actually held across the observation ─────────────

// TestAtomicBinding_TrustProbeRunsUnderTheActivationLock is the structural proof the whole matrix
// rests on, and it contains NO timing assumption.
//
// The first version of this test raced a peer goroutine against the probe and checked whether the
// peer had finished yet. That was worthless: with the lock released the peer still usually had not
// been scheduled, so the test passed against the very defect it was written to catch — the same
// "checks the statement I had in mind, not the one the guarantee needs" failure this work has hit
// before. It now asks the lock directly.
//
// The peer performs ONE TryLock at a point the barrier guarantees is inside the probe, and the
// probe blocks until that attempt has been made and reported. Acquiring the activation mutex while
// the trust observation is running is only possible if the observation is not covered by it.
func TestAtomicBinding_TrustProbeRunsUnderTheActivationLock(t *testing.T) {
	r := newAtomicRig(t)
	r.arm(t, 3)
	cr := r.rt.capRuntime(r.capb)

	var wg sync.WaitGroup
	released := make(chan struct{})
	tried := make(chan struct{})
	var peerAcquired bool

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-released
		if cr.mu.TryLock() {
			peerAcquired = true
			cr.mu.Unlock()
		}
		close(tried)
	}()

	r.admit(func() canaryTrustObservation {
		close(released)
		<-tried // deterministic: the probe does not return until the peer has actually tried
		return canaryTrustObservation{Found: true, Current: testReviewedTarget(), Trusted: true}
	})
	wg.Wait()

	if peerAcquired {
		t.Fatal("SECURITY: the activation mutex was ACQUIRABLE while the trust observation was " +
			"running, so the observation is not covered by it. Nothing it reports can be attributed " +
			"to the activation it appeared to run under — which is the entire defect this closes")
	}
}

// TestAtomicBinding_TrustProbeMayNotReEnterTheRuntime pins the lock-order premise recorded in
// mcp_canary_admission.go: the probe runs with cr.mu held, so a probe that called back into the
// activation runtime would self-deadlock. Nothing in the trust path does today — this fails loudly
// if that ever changes, rather than hanging CI.
//
// IT DRIVES THE PRODUCTION PROBE, NOT A CLOSURE. An earlier version passed probeTrusted, which
// traverses nothing — so it would have kept passing if mcpLiveTrustPrecheck later grew a reverse
// edge into canaryRuntime and every production admission self-deadlocked (Codex round 21). A gate
// presented as pinning an audited lock order has to walk the audited path, so this composes real
// tool-trust state and calls the real precheck: coordinator -> inventory -> catalog -> registry.
func TestAtomicBinding_TrustProbeMayNotReEnterTheRuntime(t *testing.T) {
	resetInventory(t)
	resetExecDeps(t)
	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	_, fn := liveFakeClock()
	composeToolTrust(t, fn)
	requestAndApproveLive(t, sid, tool, fpHex, cat.Current().Revision())

	r := newAtomicRig(t)

	// The PRODUCTION probe, shaped exactly as the gate supplies it under the lock.
	realProbe := func() canaryTrustObservation {
		live := mcpLiveTrustPrecheck(ttTenant, sid, tool, fpHex)
		if !live.Eligible && live.Resolved {
			// Exactly the shape mcpLiveSideEffectGate builds: every fact carried, none
			// pre-classified, so the transaction's ordering rule decides scope and cause.
			return canaryTrustObservation{
				DriftCode: live.DriftCode, Found: true,
				Current: live.Authoritative, AnchorLost: live.AnchorLost,
			}
		}
		if !live.Eligible {
			return canaryTrustObservation{}
		}
		return canaryTrustObservation{
			Found: true,
			Current: canary.ReviewedTarget{
				Tenant: live.Target.Tenant, ServerID: live.Target.ServerID, ToolName: live.Target.ToolName,
				Fingerprint: live.Target.Fingerprint, FingerprintFormat: live.Target.FingerprintFormat,
				ServerIdentity: live.ServerIdentity,
			},
			Trusted: true,
		}
	}
	obs := realProbe()
	if !obs.Trusted || obs.DriftCode != "" {
		t.Fatalf("premise: the composed fixture must be trusted with no drift, got %+v", obs)
	}
	// Arm the activation against the SAME target the composed fixture publishes, so this test's
	// subject stays the lock order rather than a reviewed-target mismatch.
	if _, err := r.rt.beginCanaryActivation(r.capb, canaryActivationSpec{
		Budget:          runtimeTestBudget(3),
		ReviewedTargets: []canary.ReviewedTarget{reviewedAsRead(obs.Current)},
		StartedAt:       canaryRuntimeTestNow,
	}); err != nil {
		t.Fatalf("begin activation: %v", err)
	}

	done := make(chan canaryAdmission, 1)
	go func() {
		done <- r.admit(realProbe)
	}()
	select {
	case adm := <-done:
		if !adm.Granted() {
			t.Fatalf("premise: a trusted probe should be granted, got %v", adm.Denial)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the admission transaction did not complete: a re-entrant trust probe would " +
			"self-deadlock under cr.mu — audit the lock order recorded in mcp_canary_admission.go")
	}
}

// TestAtomicBinding_ActiveWithZeroGenerationIsNotAnActivation forces the one state the normal
// lifecycle cannot produce: a runtime flagged active whose generation is still zero.
//
// It exists because zero is not a null downstream — tripCanaryAbortForGeneration reads wantGen == 0
// as "whatever is current" and skips the generation check, a wildcard reserved for the unbound
// entry point. A transaction that let a zero out as an attribution would hand the abort authority a
// wildcard, so the guard is explicit and this pins it against a state no test could otherwise reach.
func TestAtomicBinding_InactiveRuntimeIsNotAnActivation(t *testing.T) {
	r := newAtomicRig(t)
	r.arm(t, 3)

	// Force the one shape the lifecycle cannot produce on its own: not active, but with the
	// enforcer and aborter still in place. demoteCanary nils both, so without this the `!cr.active`
	// clause is shadowed by the nil checks and a mutation removing it would survive unnoticed.
	cr := r.rt.capRuntime(r.capb)
	cr.mu.Lock()
	cr.active = false
	cr.mu.Unlock()

	probed := false
	adm := r.admit(func() canaryTrustObservation {
		probed = true
		return probeDrift("tool_fingerprint_drift")()
	})

	if adm.Denial != canaryAdmitNoActivation {
		t.Fatalf("SECURITY: an inactive runtime must not be treated as an activation, got %v", adm.Denial)
	}
	if adm.Latched || adm.Generation != 0 {
		t.Fatalf("nothing may be attributed or latched: gen=%d latched=%v", adm.Generation, adm.Latched)
	}
	if probed {
		t.Fatal("SECURITY: the trust probe ran against an inactive runtime")
	}
}

func TestAtomicBinding_ActiveWithZeroGenerationIsNotAnActivation(t *testing.T) {
	r := newAtomicRig(t)
	r.arm(t, 3)

	cr := r.rt.capRuntime(r.capb)
	cr.mu.Lock()
	cr.generation = 0 // corrupt: active, but naming no activation
	cr.mu.Unlock()

	probed := false
	adm := r.admit(func() canaryTrustObservation {
		probed = true
		return probeDrift("tool_fingerprint_drift")()
	})

	if adm.Denial != canaryAdmitNoActivation {
		t.Fatalf("SECURITY: a zero generation must not count as an activation, got %v", adm.Denial)
	}
	if adm.Generation != 0 || adm.Latched {
		t.Fatalf("nothing may be attributed or latched: gen=%d latched=%v", adm.Generation, adm.Latched)
	}
	if probed {
		t.Fatal("SECURITY: the trust probe ran with no generation to charge its verdict to")
	}
}

// ── Pre-admission drift evidence (§6) ────────────────────────────────────────
//
// The pre-executor refusal path binds to no activation, so it deliberately latches nothing. What
// it MUST do is leave a bounded, readable trace: a counter nothing can read is not evidence, it is
// dead state that only looks like observability. These gates pin both halves — that the write is
// bounded and capability-scoped, and that the read actually reaches the operator surface.

func resetPreAdmissionDriftForTest(t *testing.T) {
	t.Helper()
	mcpCanaryPreAdmissionDrift.mu.Lock()
	mcpCanaryPreAdmissionDrift.m = map[string]map[string]uint64{}
	mcpCanaryPreAdmissionDrift.mu.Unlock()
	t.Cleanup(func() {
		mcpCanaryPreAdmissionDrift.mu.Lock()
		mcpCanaryPreAdmissionDrift.m = map[string]map[string]uint64{}
		mcpCanaryPreAdmissionDrift.mu.Unlock()
	})
}

func TestAtomicBinding_PreAdmissionDriftEvidenceIsBoundedAndReadable(t *testing.T) {
	resetPreAdmissionDriftForTest(t)

	gw := rollout.CapabilityGateway.String()
	noteCanaryPreAdmissionDrift(gw, "tool_fingerprint_drift")
	noteCanaryPreAdmissionDrift(gw, "tool_fingerprint_drift")
	noteCanaryPreAdmissionDrift(gw, "server_identity_drift")

	// The key space is bounded: an arbitrary code can never become a new key.
	for _, junk := range []string{"", "attacker-controlled", "tool_fingerprint_drift ", "🙂"} {
		noteCanaryPreAdmissionDrift(gw, junk)
	}

	got := canaryPreAdmissionDriftCounts(gw)
	if got["tool_fingerprint_drift"] != 2 {
		t.Fatalf("tool_fingerprint_drift = %d, want 2", got["tool_fingerprint_drift"])
	}
	if got["server_identity_drift"] != 1 {
		t.Fatalf("server_identity_drift = %d, want 1", got["server_identity_drift"])
	}
	if got["other"] != 4 {
		t.Fatalf("unrecognised codes must fold into exactly one bucket: other = %d, want 4", got["other"])
	}
	if len(got) != 3 {
		t.Fatalf("SECURITY: the evidence key space is unbounded — %d keys: %v", len(got), got)
	}

	// The counter is capability-scoped: one capability's evidence never appears under another.
	if other := canaryPreAdmissionDriftCounts(rollout.CapabilityManagement.String()); len(other) != 0 {
		t.Fatalf("management must carry no gateway evidence, got %v", other)
	}

	// The mutation returns a COPY: a caller cannot reach in and rewrite the evidence.
	got["tool_fingerprint_drift"] = 999
	if again := canaryPreAdmissionDriftCounts(gw); again["tool_fingerprint_drift"] != 2 {
		t.Fatalf("the accessor leaked its backing map: %d", again["tool_fingerprint_drift"])
	}
}

func TestAtomicBinding_PreAdmissionDriftReachesTheOperatorSurface(t *testing.T) {
	resetPreAdmissionDriftForTest(t)

	noteCanaryPreAdmissionDrift(rollout.CapabilityGateway.String(), "server_identity_drift")

	st := mcpCanaryStatus()
	ar, ok := st["activation_runtime"].(map[string]any)
	if !ok {
		t.Fatal("activation_runtime missing from the Canary status surface")
	}
	counts, ok := ar["pre_admission_drift"].(map[string]uint64)
	if !ok {
		t.Fatalf("SECURITY: pre-admission drift evidence is write-only — it never reaches "+
			"GET /api/mcp/rollout. activation_runtime keys: %v", keysOf(ar))
	}
	if counts["server_identity_drift"] != 1 {
		t.Fatalf("server_identity_drift = %d on the operator surface, want 1", counts["server_identity_drift"])
	}
}

// ── G-I. The pre-executor drift latch ────────────────────────────────────────
//
// A rug-pull that lands BEFORE policy resolution never reaches the admission transaction: the
// pipeline refuses it upstream. Codex round 20 showed why "it will be caught on the next request"
// is false — after the catalog moves, later requests resolve cleanly against the NEW fingerprint
// and fail approval validation, which is request-scoped, not drift. So an authoritative
// whole-Canary breach would stop nothing at all.
//
// latchDriftUnderActivation closes that by re-deriving the drift under the activation lock. These
// cases pin the three outcomes that matter: it latches when an activation owns the observation, it
// latches NOTHING in the publication gap, and it never invents a breach.

// latchDrift drives the latch for the CURRENT activation generation — the healthy case, where the
// activation the request resolved under is still the one in force.
func (r *atomicRig) latchDrift(trust canaryTrustProbe) canaryDriftLatch {
	return r.latchDriftAs(r.rt.currentGeneration(r.capb), trust)
}

// latchDriftAs drives the latch for an EXPLICIT observed generation, so a test can present a stale
// observation from a superseded activation.
func (r *atomicRig) latchDriftAs(wantGen uint64, trust canaryTrustProbe) canaryDriftLatch {
	return r.rt.latchDriftUnderActivation(r.capb, wantGen, canaryRuntimeTestNow, trust)
}

// TestAtomicBinding_G_PreExecutorDriftLatchesTheActiveGeneration is the case Codex round 20 proved
// unreachable: the drift is seen before the executor, and it must still stop the experiment.
func TestAtomicBinding_G_PreExecutorDriftLatchesTheActiveGeneration(t *testing.T) {
	r := newAtomicRig(t)
	g := r.arm(t, 4)

	got := r.latchDrift(probeDrift("tool_fingerprint_drift"))

	if !got.Active || got.Generation != g {
		t.Fatalf("latch ran under generation %d (active=%v), want %d", got.Generation, got.Active, g)
	}
	if got.DriftCode != "tool_fingerprint_drift" {
		t.Fatalf("DriftCode = %q, want the code re-derived under the lock", got.DriftCode)
	}
	if !got.Latched {
		t.Fatal("SECURITY: an authoritative pre-executor drift did not latch the whole Canary — " +
			"the breach condition is declared but unreachable (Codex round 20)")
	}
	// The activation must now be dead: no later request may execute under it.
	if r.rt.executionEligible(r.capb, canaryRuntimeTestNow) {
		t.Fatal("SECURITY: the activation is still execution-eligible after a latched drift")
	}
	// And the latch must be the SAME authority the admission path uses, not a parallel one.
	if adm := r.admit(probeTrusted()); adm.Denial != canaryAdmitAborted {
		t.Fatalf("a request after the latch was denied %v, want canaryAdmitAborted", adm.Denial)
	}
}

// TestAtomicBinding_H_PreExecutorDriftInThePublicationGapLatchesNothing pins §6. During ModeCanary
// with no live activation there is nothing to attribute the observation to, and it must never be
// inherited by an activation created afterwards.
func TestAtomicBinding_H_PreExecutorDriftInThePublicationGapLatchesNothing(t *testing.T) {
	r := newAtomicRig(t)
	g := r.arm(t, 4)

	// The activation is demoted while the observation is in flight. This is the shape the gap
	// check uniquely guards: demote leaves the GENERATION recorded and only clears active and the
	// controllers, so the observation's generation still MATCHES — the equality check cannot
	// refuse it, and only "there is no live activation" can.
	if err := r.rt.demoteCanary(r.capb); err != nil {
		t.Fatalf("demote: %v", err)
	}

	got := r.latchDriftAs(g, probeDrift("server_identity_drift"))

	if got.Active || got.Latched {
		t.Fatalf("SECURITY: a drift observed with NO live activation reported %+v — ModeCanary "+
			"with a demoted runtime is not an activation, and nothing may be latched there", got)
	}

	// Now an activation is published. It must be born healthy: it never saw that drift.
	g2 := r.arm(t, 4)
	if !r.rt.executionEligible(r.capb, canaryRuntimeTestNow) {
		t.Fatalf("SECURITY: activation %d inherited a drift observed before it existed", g2)
	}
	if adm := r.admit(probeTrusted()); !adm.Granted() || adm.Generation != g2 {
		t.Fatalf("a healthy request under the new activation was denied: %+v", adm)
	}
}

// TestAtomicBinding_I_PreExecutorLatchNeverInventsABreach is the anti-vacuity control. The caller's
// upstream verdict is NOT the latch input — only the value re-derived under the lock is — so a
// probe that finds live state healthy must leave the experiment running. Without this, "latch
// whenever the pipeline reports drift" would pass every gate above while being able to stop a
// healthy Canary on a stale observation.
func TestAtomicBinding_I_PreExecutorLatchNeverInventsABreach(t *testing.T) {
	r := newAtomicRig(t)
	g := r.arm(t, 4)

	got := r.latchDrift(probeTrusted())

	if got.Latched || got.DriftCode != "" {
		t.Fatalf("SECURITY: the latch fired without re-deriving a drift: %+v", got)
	}
	if got.Generation != g {
		t.Fatalf("Generation = %d, want %d", got.Generation, g)
	}
	if !r.rt.executionEligible(r.capb, canaryRuntimeTestNow) {
		t.Fatal("SECURITY: a healthy Canary was stopped by an observation that did not reproduce")
	}
}

// TestAtomicBinding_PreExecutorLatchHoldsTheActivationLockAcrossItsProbe is the structural twin of
// the admission-path gate: the re-derivation is worthless if the activation can change under it.
func TestAtomicBinding_PreExecutorLatchHoldsTheActivationLockAcrossItsProbe(t *testing.T) {
	r := newAtomicRig(t)
	r.arm(t, 4)
	cr := r.rt.capRuntime(r.capb)

	var (
		wg           sync.WaitGroup
		peerAcquired bool
	)
	released := make(chan struct{})
	tried := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-released
		if cr.mu.TryLock() {
			peerAcquired = true
			cr.mu.Unlock()
		}
		close(tried)
	}()

	r.latchDrift(func() canaryTrustObservation {
		close(released)
		<-tried
		return probeDrift("tool_fingerprint_drift")()
	})
	wg.Wait()

	if peerAcquired {
		t.Fatal("SECURITY: the activation mutex was ACQUIRABLE while the pre-executor drift " +
			"re-derivation was running — the observation is not activation-bound, which is the " +
			"exact defect five review rounds were spent on")
	}
}

// ── §5 + revocation: trust is evaluated WHOLLY inside the transaction ────────

// TestAtomicBinding_ApprovalIsEvaluatedInsideTheTransaction is the round-22 regression gate.
//
// An earlier revision hoisted the approval lookup OUT of the activation lock to keep the durable
// store's mutex off the critical section. That fixed a real liveness hazard and bought a security
// one: a request that read approved=true and then waited for cr.mu could be admitted after the
// approval was REVOKED in that window. Nothing downstream catches it — the final boundary re-reads
// tool freshness, generation and kill state, not approval status — and revoking a LIVE approval
// disturbs neither the fingerprint nor eligibility, because catalog promotion derives from
// SHADOW-purpose approvals (rederiveTool). So the in-lock precheck still reports Eligible and a
// stale yes authorizes an irreversible call.
//
// The gate answers "revoked" at the moment of the lookup and requires the admission to be refused.
// Hoist the lookup back out and the cached yes wins, which fails this deterministically.
func TestAtomicBinding_ApprovalIsEvaluatedInsideTheTransaction(t *testing.T) {
	r := newAtomicRig(t)
	r.arm(t, 4)

	cr := r.rt.capRuntime(r.capb)
	askedInsideLock := false
	g := &mcpLiveSideEffectGate{
		capb:      r.capb,
		admit:     func() (func(), bool) { return func() {}, true },
		readFirst: func(policy.OperationClass) bool { return true },
		// Observed at the admission instant: admission asks peer freshness BEFORE the approval
		// (round 13), so a stale stub would refuse first and this case would never reach the
		// approval it exists to prove is read inside the lock.
		trustPrecheck: stubTrustPrecheckObservedAt(canaryRuntimeTestNow),
		approvalOK: func(canary.LiveTarget, policy.OperationClass, time.Time) (bool, string) {
			// The store answers DIFFERENTLY either side of the lock, which is the whole point:
			// a constant answer cannot tell a cached read from a live one. sync.Mutex is not
			// reentrant, so on this single-threaded path a successful TryLock means we are NOT
			// inside the transaction — i.e. this is the hoisted, pre-lock read.
			if cr.mu.TryLock() {
				cr.mu.Unlock()
				return true, "" // the stale pre-revocation answer
			}
			askedInsideLock = true
			return false, "" // the revocation the transaction must observe
		},
		admitUnderActivation: func(now time.Time, opClass policy.OperationClass, resolvedScope string, scopeNow canaryScopeProbe, ident canary.ExecutionIdentity, trust canaryTrustProbe) canaryAdmission {
			return r.rt.admitLiveExecution(r.capb, now, opClass, resolvedScope, scopeNow, ident, trust)
		},
		releaseBudget:     func(gen uint64) { r.rt.releaseCanaryExecution(r.capb, gen) },
		generationCurrent: func(gen uint64) bool { return r.rt.generationActive(r.capb, gen) },
		note:              noteMCPLiveGateDenied,
	}

	dec := g.AdmitSideEffect(execution.LiveGateInput{
		Capability: 0, Operation: policy.OpRead,
		Tenant: "t1", Principal: "p1", ServerID: "s1", ToolName: "x",
		Fingerprint: "fp", Now: canaryRuntimeTestNow,
	})
	if dec.Release != nil {
		dec.Release()
	}

	if !askedInsideLock {
		t.Fatal("SECURITY: the approval store was never consulted from INSIDE the transaction — " +
			"the verdict is being read before the activation lock and cached across it")
	}
	if dec.Admit {
		t.Fatal("SECURITY: an admission was granted against an approval the transaction itself " +
			"observed as absent — the approval verdict is cached across the activation-lock " +
			"acquisition, so a revocation in that window authorizes an irreversible call")
	}
	if got := r.remaining(); got != 4 {
		t.Fatalf("budget remaining = %d, want 4 — a trust-refused request reserved anyway", got)
	}
}

// ── The rug-pull latches inside the transaction ──────────────────────────────

// TestAtomicBinding_RugPullLatchesAtAdmission is the gate for the round-20/23 hole, now decided
// against the ACTIVATION's reviewed snapshot rather than against an approval.
//
// After a rug-pull the catalog settles at F2. Every later request is DECIDED against F2, so the
// fingerprint comparison in the precheck sees F2 == F2 and reports no drift; those requests were
// being denied merely for lacking an approval, which is indistinguishable from ordinary
// unauthorized traffic. The evidence that the reviewed tool moved is the activation's own record
// of what it was reviewed against — F1 — which the transaction compares under the lock.
//
// Note what this test does NOT do: it supplies no approval saying "F1 was reviewed". The approval
// store is empty of anything relevant (approvalOK returns unauthorized). That is the Round-24
// property — drift is detected with no surviving approval at all.
func TestAtomicBinding_RugPullLatchesAtAdmission(t *testing.T) {
	r := newAtomicRig(t)
	// Reviewed against F1.
	if _, err := r.rt.beginCanaryActivation(r.capb, testActivationSpec(runtimeTestBudget(4), canaryRuntimeTestNow, reviewedAt(fpF1))); err != nil {
		t.Fatalf("begin activation: %v", err)
	}
	g := r.rt.currentGeneration(r.capb)

	// The catalog has settled at F2 and NO approval covers the request.
	gate := &mcpLiveSideEffectGate{
		capb:          r.capb,
		admit:         func() (func(), bool) { return func() {}, true },
		readFirst:     func(policy.OperationClass) bool { return true },
		trustPrecheck: stubTrustPrecheckAt(fpF2),
		approvalOK: func(canary.LiveTarget, policy.OperationClass, time.Time) (bool, string) {
			return false, "" // unauthorized, and saying nothing about what was reviewed
		},
		admitUnderActivation: func(now time.Time, opClass policy.OperationClass, resolvedScope string, scopeNow canaryScopeProbe, ident canary.ExecutionIdentity, trust canaryTrustProbe) canaryAdmission {
			return r.rt.admitLiveExecution(r.capb, now, opClass, resolvedScope, scopeNow, ident, trust)
		},
		releaseBudget:     func(gen uint64) { r.rt.releaseCanaryExecution(r.capb, gen) },
		generationCurrent: func(gen uint64) bool { return r.rt.generationActive(r.capb, gen) },
		note:              noteMCPLiveGateDenied,
	}

	dec := gate.AdmitSideEffect(execution.LiveGateInput{
		Capability: 0, Operation: policy.OpRead,
		Tenant: "t1", Principal: "p1", ServerID: "s1", ToolName: "x",
		Fingerprint: "fp", Now: canaryRuntimeTestNow,
	})
	if dec.Release != nil {
		dec.Release()
	}
	if dec.Admit {
		t.Fatal("a rug-pulled target must not be admitted")
	}
	if r.rt.executionEligible(r.capb, canaryRuntimeTestNow) {
		t.Fatalf("SECURITY: activation %d is STILL execution-eligible after an authoritative "+
			"rug-pull reached admission. The breach is declared whole-Canary but stops nothing, "+
			"and no later request will latch it either — they all resolve against the new "+
			"fingerprint and read as ordinary unauthorized traffic (Codex rounds 20 and 23)", g)
	}
	// Latched against the activation that was live, with no budget spent.
	if adm := r.admit(probeTrusted()); adm.Denial != canaryAdmitAborted {
		t.Fatalf("a request after the latch was denied %v, want canaryAdmitAborted", adm.Denial)
	}
	if got := r.remaining(); got != 4 {
		t.Fatalf("budget remaining = %d, want 4 — a drift-refused request reserved anyway", got)
	}
}

// TestAtomicBinding_MissingApprovalIsNotDrift is the control. Without it, "latch whenever the
// approval check fails" would pass the gate above while stopping the experiment for every
// unauthorized request — a Canary correctly refusing one is a Canary working, not a breach.
func TestAtomicBinding_MissingApprovalIsNotDrift(t *testing.T) {
	r := newAtomicRig(t)
	r.arm(t, 4)

	gate := &mcpLiveSideEffectGate{
		capb:          r.capb,
		admit:         func() (func(), bool) { return func() {}, true },
		readFirst:     func(policy.OperationClass) bool { return true },
		trustPrecheck: stubTrustPrecheckObservedAt(canaryRuntimeTestNow), // fresh at admission: the refusal must be the MISSING APPROVAL, not staleness (round 13)
		approvalOK:    func(canary.LiveTarget, policy.OperationClass, time.Time) (bool, string) { return false, "" },
		admitUnderActivation: func(now time.Time, opClass policy.OperationClass, resolvedScope string, scopeNow canaryScopeProbe, ident canary.ExecutionIdentity, trust canaryTrustProbe) canaryAdmission {
			return r.rt.admitLiveExecution(r.capb, now, opClass, resolvedScope, scopeNow, ident, trust)
		},
		releaseBudget:     func(gen uint64) { r.rt.releaseCanaryExecution(r.capb, gen) },
		generationCurrent: func(gen uint64) bool { return r.rt.generationActive(r.capb, gen) },
		note:              noteMCPLiveGateDenied,
	}

	dec := gate.AdmitSideEffect(execution.LiveGateInput{
		Capability: 0, Operation: policy.OpRead,
		Tenant: "t1", Principal: "p1", ServerID: "s1", ToolName: "x",
		Fingerprint: "fp", Now: canaryRuntimeTestNow,
	})
	if dec.Release != nil {
		dec.Release()
	}
	if dec.Admit {
		t.Fatal("an unapproved request must not be admitted")
	}
	if !r.rt.executionEligible(r.capb, canaryRuntimeTestNow) {
		t.Fatal("SECURITY: an ordinary unauthorized request STOPPED the Canary — a missing " +
			"approval is request-scoped, and treating it as a breach makes every unauthorized " +
			"caller a kill switch")
	}
}

// reviewedAsRead states the reviewed operation class on an OBSERVED target, which carries none:
// mcpCurrentAuthoritativeTarget reports what is in force NOW, and a current target has no reviewed
// class — that fact lives only on the activation's record. The lock-order tests arm against
// whatever the composed fixture publishes and are indifferent to the semantics, so they take the
// one class a First-Canary request can actually carry.
func reviewedAsRead(t canary.ReviewedTarget) canary.ReviewedTarget {
	t.OperationClass = policy.OpRead
	return t
}

// TestAtomicBinding_I_ClassNotInForceIsRefused is the transaction-level half of the boundary class
// revalidation (Codex P1, PR #1370).
//
// The activation binds this target read-only. A request that arrives carrying a DIFFERENT decided
// class — the shape a stale decision from a superseded activation produces — is refused
// request-scoped: nothing latches, because the target did not move; the review of it did.
func TestAtomicBinding_I_ClassNotInForceIsRefused(t *testing.T) {
	r := newAtomicRig(t)
	g := r.arm(t, 3)

	// CONTROL first: the matching class is granted, so the refusal below cannot be a transaction
	// that denies everything.
	if adm := r.admitAs(policy.OpRead, probeTrusted()); !adm.Granted() {
		t.Fatalf("control: the class the activation binds must be granted, got %v", adm.Denial)
	}

	adm := r.admitAs(policy.OpWrite, probeTrusted())
	if adm.Granted() {
		t.Fatal("SECURITY: a request whose operation class the activation does not bind must not be admitted")
	}
	if adm.Denial != canaryAdmitClassNotInForce {
		t.Fatalf("the refusal must carry its own bounded reason, got %v", adm.Denial)
	}
	if adm.Generation != g {
		t.Fatalf("the refusal must be attributed to the activation that refused it, got %d want %d", adm.Generation, g)
	}
	if r.rt.abortedNow(r.capb) {
		t.Fatal("SECURITY: a class mismatch is request-scoped — the TARGET did not move, so nothing may latch")
	}
	if got, want := r.remaining(), 2; got != want {
		t.Fatalf("a refused request must not spend budget: %d of %d left", got, want)
	}
}
