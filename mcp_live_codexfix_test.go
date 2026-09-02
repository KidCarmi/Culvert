package main

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/inspection"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	mcpruntime "github.com/KidCarmi/Culvert/internal/mcp/runtime"
)

// Codex review fixes for PR #1290.

// P1: a transition whose durable rollout state committed but whose Canary runtime activation FAILS must
// be REJECTED and the durable state rolled back — never left as durable-live + disarmed-runtime, which
// denies every execution AND can never self-repair on replay (prevMode is now live ⇒ enteringLive=false).
func TestLiveCommit_BeginActivationFailureRejectsAndRollsBack(t *testing.T) {
	resetLiveTierGlobals(t)
	setDataDirForTest(t, t.TempDir())
	// Force the Canary runtime's durable persist to fail, so beginCanaryActivation fails AFTER the
	// rollout state has already been committed to the live mode — the exact split the fix closes.
	prevPersist := canaryRuntimePersist
	canaryRuntimePersist = func(*canaryRuntime, rollout.Capability, *canaryCapRuntime) error {
		return errors.New("synthetic canary persist failure")
	}
	t.Cleanup(func() { canaryRuntimePersist = prevPersist })

	// Use an ISOLATED rollout state (not the shared getMCPRollout singleton) so this test's config +
	// evidence + transition-history mutations cannot leak into other root-package tests under shuffle;
	// reconcileCanaryRuntimeAfterCommit reads only tgt.st and the (reset-isolated) globalCanaryRuntime,
	// never its receiver's state, so an isolated *mcpRollout drives the exact same path.
	r := newTestRollout()
	st := r.gateway
	capb := rollout.CapabilityGateway
	prevCfg := rollout.DisabledConfig(capb)
	prevMode := prevCfg.Mode
	prevEvidence := st.Evidence()
	cfg := gwCanaryCfg(1)
	// Simulate the coordinator's in-memory install of the new (live) mode that precedes reconciliation.
	if err := st.SetConfig(*cfg, "test", time.Unix(0, 1).UnixNano()); err != nil {
		t.Fatalf("install canary: %v", err)
	}
	persistCalls := 0
	persistedMode := rollout.ModeCanary
	tgt := commitTransitionTarget{
		st:               st,
		persist:          func(s *rollout.State) error { persistCalls++; persistedMode = s.CurrentMode(); return nil },
		setStatus:        func(string) {},
		countTransition:  func() {},
		reconcileRuntime: true,
	}
	err := r.reconcileCanaryRuntimeAfterCommit(tgt, cfg, prevMode, prevCfg, prevEvidence, runtimeTestBudget(10), "test", time.Unix(0, 1))
	if !errors.Is(err, errRolloutCanaryActivationFailed) {
		t.Fatalf("a failed begin must reject the transition with errRolloutCanaryActivationFailed, got %v", err)
	}
	if st.CurrentMode() != prevMode {
		t.Fatalf("durable state must roll back to the prior mode %v, got %v", prevMode, st.CurrentMode())
	}
	if persistCalls == 0 || persistedMode != prevMode {
		t.Fatalf("the rolled-back state must be durably persisted (calls=%d mode=%v)", persistCalls, persistedMode)
	}
	if globalCanaryRuntime.armed(capb) {
		t.Fatal("the runtime must stay disarmed after a failed activation")
	}

	// Replay repair: with the durable state rolled back to the prior (non-live) mode, a retry recomputes
	// enteringLive=true. Restore the persist seam and prove a clean retry arms the runtime — the property
	// the un-rolled-back state would have made permanently unreachable.
	canaryRuntimePersist = prevPersist
	if err := st.SetConfig(*cfg, "retry", time.Unix(0, 2).UnixNano()); err != nil {
		t.Fatalf("retry install: %v", err)
	}
	if err := r.reconcileCanaryRuntimeAfterCommit(tgt, cfg, prevMode, prevCfg, prevEvidence, runtimeTestBudget(10), "retry", time.Unix(0, 2)); err != nil {
		t.Fatalf("retry after rollback must succeed, got %v", err)
	}
	if !globalCanaryRuntime.armed(capb) {
		t.Fatal("a clean retry must arm the runtime (the rollback left a repairable state)")
	}
}

// P2 (round-5): the persist-status recorded on a failed activation reflects DURABILITY. A rollback that
// persists cleanly records activation_failed; a rollback whose compensating persist ALSO fails records
// write_failed — because rollbackPathReadyLocked treats only degraded/write_failed as unhealthy, and
// recording activation_failed on a real persistence failure would let the node retry activation over a
// disk that still holds the un-rolled-back live mode.
func TestLiveCommit_ActivationFailureStatusReflectsPersistOutcome(t *testing.T) {
	run := func(t *testing.T, persistErr error, wantStatus string) {
		resetLiveTierGlobals(t)
		setDataDirForTest(t, t.TempDir())
		prevPersist := canaryRuntimePersist
		canaryRuntimePersist = func(*canaryRuntime, rollout.Capability, *canaryCapRuntime) error {
			return errors.New("synthetic canary persist failure")
		}
		t.Cleanup(func() { canaryRuntimePersist = prevPersist })

		r := newTestRollout()
		st := r.gateway
		capb := rollout.CapabilityGateway
		prevCfg := rollout.DisabledConfig(capb)
		cfg := gwCanaryCfg(1)
		if err := st.SetConfig(*cfg, "test", time.Unix(0, 1).UnixNano()); err != nil {
			t.Fatalf("install canary: %v", err)
		}
		var gotStatus string
		tgt := commitTransitionTarget{
			st:               st,
			persist:          func(*rollout.State) error { return persistErr },
			setStatus:        func(s string) { gotStatus = s },
			countTransition:  func() {},
			reconcileRuntime: true,
		}
		err := r.reconcileCanaryRuntimeAfterCommit(tgt, cfg, prevCfg.Mode, prevCfg, st.Evidence(), runtimeTestBudget(10), "test", time.Unix(0, 1))
		if !errors.Is(err, errRolloutCanaryActivationFailed) {
			t.Fatalf("a failed begin must reject the transition, got %v", err)
		}
		if gotStatus != wantStatus {
			t.Fatalf("persist err=%v ⇒ status %q, want %q", persistErr, gotStatus, wantStatus)
		}
	}
	t.Run("clean rollback persist ⇒ activation_failed", func(t *testing.T) { run(t, nil, "activation_failed") })
	t.Run("failed rollback persist ⇒ write_failed", func(t *testing.T) {
		run(t, errors.New("compensating persist failed"), "write_failed")
	})
}

// P2 (round-6): a SAME-MODE live update (Canary→Canary scope revision) whose authoritative budget
// differs from the active generation's is REJECTED — the generation is not re-begun, so a tightened
// cap would go unenforced. A same-budget update proceeds.
func TestLiveCommit_SameModeLiveBudgetChangeIsRejected(t *testing.T) {
	resetLiveTierGlobals(t)
	setDataDirForTest(t, t.TempDir())
	capb := rollout.CapabilityGateway
	// Arm a canary generation with budget B1.
	if _, err := globalCanaryRuntime.beginCanaryActivation(capb, runtimeTestBudget(10), time.Unix(0, 1)); err != nil {
		t.Fatalf("begin: %v", err)
	}
	r := newTestRollout()
	st := r.gateway
	prevCfg := *gwCanaryCfg(1) // prior Canary (live)
	if err := st.SetConfig(prevCfg, "prev", time.Unix(0, 1).UnixNano()); err != nil {
		t.Fatalf("install prev canary: %v", err)
	}
	cfg := gwCanaryCfg(2) // SAME mode (Canary), new scope revision
	if err := st.SetConfig(*cfg, "new", time.Unix(0, 2).UnixNano()); err != nil {
		t.Fatalf("install new canary: %v", err)
	}
	tgt := commitTransitionTarget{
		st:               st,
		persist:          func(*rollout.State) error { return nil },
		setStatus:        func(string) {},
		countTransition:  func() {},
		reconcileRuntime: true,
	}
	// A DIFFERENT budget (B2) than the active generation's B1 ⇒ reject + roll back.
	err := r.reconcileCanaryRuntimeAfterCommit(tgt, cfg, prevCfg.Mode, prevCfg, st.Evidence(), runtimeTestBudget(20), "new", time.Unix(0, 2))
	if !errors.Is(err, errRolloutCanaryActivationFailed) || !errors.Is(err, errRolloutCanaryBudgetChanged) {
		t.Fatalf("a same-mode live update with a changed budget must be rejected, got %v", err)
	}
	if st.CurrentMode() != prevCfg.Mode {
		t.Fatalf("state must roll back to the prior live mode, got %v", st.CurrentMode())
	}

	// The SAME budget (B1) ⇒ no reject; the scope update proceeds.
	if err := r.reconcileCanaryRuntimeAfterCommit(tgt, cfg, prevCfg.Mode, prevCfg, st.Evidence(), runtimeTestBudget(10), "same", time.Unix(0, 3)); err != nil {
		t.Fatalf("a same-mode live update with the SAME budget must proceed, got %v", err)
	}
}

// P2: resetLiveTierGlobals must clear the process-global live-gate denial counters, so a prior shuffled
// test's denials cannot leak into a later test's telemetry assertions.
func TestLiveGate_DenialCountersResetByHelper(t *testing.T) {
	// Save/restore the whole global so this test's simulated leak never escapes to another test (this
	// outer cleanup is registered FIRST, so it runs LAST — after resetLiveTierGlobals's own restore).
	mcpLiveGateDenials.mu.Lock()
	orig := mcpLiveGateDenials.m
	mcpLiveGateDenials.m = map[string]uint64{}
	mcpLiveGateDenials.mu.Unlock()
	t.Cleanup(func() {
		mcpLiveGateDenials.mu.Lock()
		mcpLiveGateDenials.m = orig
		mcpLiveGateDenials.mu.Unlock()
	})

	// Simulate a prior test leaking a denial, then a reset.
	noteMCPLiveGateDenied(mcperr.ReasonRolloutBudgetExhausted)
	resetLiveTierGlobals(t)
	if n := len(mcpLiveGateDenialSnapshot()); n != 0 {
		t.Fatalf("resetLiveTierGlobals must clear leaked denial counters, got %d entries", n)
	}
	// And a post-reset denial counts from zero, not from the leaked baseline.
	noteMCPLiveGateDenied(mcperr.ReasonLiveTrustRevalidationFailed)
	if got := mcpLiveGateDenialSnapshot()[mcperr.ReasonLiveTrustRevalidationFailed.Code()]; got != 1 {
		t.Fatalf("post-reset denial must count from zero, got %d", got)
	}
}

// P2 (composition): a missing/zero response inspection profile carries zero limits (MaxOutputBytes==0),
// which would let the upstream side effect occur and then block the response on egress. Composition must
// reject it fail-closed, exactly like a missing upstream or events manager.
func TestLiveCompose_RejectsMissingResponseProfile(t *testing.T) {
	resetLiveTierGlobals(t)
	cfg := &mcpruntime.Config{}
	err := composeGatewayLiveTierInto(cfg, liveTierComposition{
		Upstream: &recordingUpstream{},
		Events:   liveTestEvents(t),
		// ResponseProfile deliberately omitted (zero value) — must fail closed.
		Clock: func() time.Time { return time.Unix(0, 1) },
	})
	if !errors.Is(err, errLiveComposeResponseProfileAbsent) {
		t.Fatalf("composition must reject a missing response profile, got %v", err)
	}
	if cfg.Deps.Executor != nil {
		t.Fatal("a rejected composition must not install an executor")
	}
	if mcpLiveTierFor(rollout.CapabilityGateway).composed() {
		t.Fatal("a rejected composition must not mark the tier composed")
	}
}

// P2 (composition, round-4): a profile with a real Capability but ZERO inspection limits
// (MaxOutputBytes()==0) must also be rejected — a capability-only check would let it through, and then
// every non-empty response would be reported oversized AFTER the irreversible upstream call.
func TestLiveCompose_RejectsZeroLimitProfile(t *testing.T) {
	resetLiveTierGlobals(t)
	// A named-but-limitless profile: Capability()=="gateway" (non-empty) yet MaxOutputBytes()==0.
	prof, err := inspection.NewProfile(inspection.ProfileConfig{Capability: "gateway", Revision: 1})
	if err != nil {
		t.Fatalf("NewProfile: %v", err)
	}
	if prof.Capability() == "" || prof.MaxOutputBytes() > 0 {
		t.Skipf("test premise invalid: capability=%q maxOut=%d", prof.Capability(), prof.MaxOutputBytes())
	}
	cfg := &mcpruntime.Config{}
	err = composeGatewayLiveTierInto(cfg, liveTierComposition{
		Upstream:        &recordingUpstream{},
		Events:          liveTestEvents(t),
		ResponseProfile: prof, // non-empty capability, zero limits — must still fail closed
		Clock:           func() time.Time { return time.Unix(0, 1) },
	})
	if !errors.Is(err, errLiveComposeResponseProfileAbsent) {
		t.Fatalf("composition must reject a zero-limits profile, got %v", err)
	}
	if cfg.Deps.Executor != nil {
		t.Fatal("a rejected composition must not install an executor")
	}
}

// P2 (round-5): a valid NON-Gateway profile (Management) has a non-empty capability AND positive
// limits, but the Gateway executor must use a GATEWAY profile — a Management profile's independent
// limits would block a response the Gateway bound admits, only AFTER the irreversible call.
func TestLiveCompose_RejectsNonGatewayProfile(t *testing.T) {
	resetLiveTierGlobals(t)
	mgmt := inspection.DefaultManagementProfile(1)
	if mgmt.Capability() == "gateway" || mgmt.MaxOutputBytes() <= 0 {
		t.Skipf("test premise invalid: capability=%q maxOut=%d", mgmt.Capability(), mgmt.MaxOutputBytes())
	}
	cfg := &mcpruntime.Config{}
	err := composeGatewayLiveTierInto(cfg, liveTierComposition{
		Upstream:        &recordingUpstream{},
		Events:          liveTestEvents(t),
		ResponseProfile: mgmt, // valid, but Management — must be rejected for the Gateway tier
		Clock:           func() time.Time { return time.Unix(0, 1) },
	})
	if !errors.Is(err, errLiveComposeResponseProfileAbsent) {
		t.Fatalf("composition must reject a non-Gateway profile, got %v", err)
	}
	if cfg.Deps.Executor != nil {
		t.Fatal("a rejected composition must not install an executor")
	}
}

// P2 (round-4): the Canary runtime activation failure carries a bounded, alertable mcperr.Reason (not a
// plain sentinel that would derive ReasonNone through AbortApplied's mcperr.ReasonOf), and it survives
// the %w wrap the reconcile helper applies.
func TestRolloutCanaryActivationFailed_IsClassified(t *testing.T) {
	direct := mcperr.ReasonOf(errRolloutCanaryActivationFailed)
	if direct == mcperr.ReasonNone {
		t.Fatal("errRolloutCanaryActivationFailed must carry a bounded reason, not ReasonNone")
	}
	wrapped := fmt.Errorf("%w: %v", errRolloutCanaryActivationFailed, errors.New("persist failed"))
	if got := mcperr.ReasonOf(wrapped); got != direct {
		t.Fatalf("a wrapped activation failure must keep its bounded reason %s, got %s", direct.Code(), got.Code())
	}
}

// P1 (round-8): a leaving-live rollout commit (Canary→Observe) UN-ARMS the live tier (closes admission)
// and invalidates the Canary generation — both fast, no drain. New work is refused at the gate; already
// admitted in-flight work is invalidated at the executor's final boundary (see the boundary test below).
func TestLiveCommit_LeavingLiveUnarmsAndDemotes(t *testing.T) {
	up := &recordingUpstream{}
	armCanaryLiveTier(t, up, true, 10) // composed + armed + Canary generation active
	capb := rollout.CapabilityGateway
	lt := mcpLiveTierFor(capb)
	if !lt.armed() || !globalCanaryRuntime.armed(capb) {
		t.Fatal("precondition: the live tier must be armed with an active Canary generation")
	}
	r := getMCPRollout()
	prevCfg := *gwCanaryCfg(1)
	tgt := commitTransitionTarget{
		st:               r.gateway,
		persist:          func(*rollout.State) error { return nil },
		setStatus:        func(string) {},
		countTransition:  func() {},
		reconcileRuntime: true,
	}
	if err := r.reconcileCanaryRuntimeAfterCommit(tgt, gwObserveCfg(), prevCfg.Mode, prevCfg, r.gateway.Evidence(), canary.Budget{}, "test", time.Unix(0, 2)); err != nil {
		t.Fatalf("leaving-live reconcile must succeed, got %v", err)
	}
	if lt.armed() {
		t.Fatal("a leaving-live demotion must un-arm the live tier")
	}
	if release, ok := lt.admitExecution(); ok {
		release()
		t.Fatal("an un-armed tier must reject new execution admission after a leaving-live demotion")
	}
	if globalCanaryRuntime.armed(capb) {
		t.Fatal("a leaving-live demotion must invalidate the Canary generation (demoteCanary)")
	}
}

// P1 (round-8): the leaving-live demotion must NOT block on in-flight work — a bounded drain that timed
// out could leak, and holding durableMu across a drain would block the emergency kill from engaging.
// The demote returns promptly even with an execution in flight; the in-flight work (already past the
// boundary) completes on its own.
func TestLiveCommit_LeavingLiveDemoteDoesNotBlockOnInflight(t *testing.T) {
	up := &recordingUpstream{block: make(chan struct{}, 1)}
	cfg := armCanaryLiveTier(t, up, true, 10)
	ex := cfg.Deps.Executor
	capb := rollout.CapabilityGateway
	lt := mcpLiveTierFor(capb)
	in := liveExecInput(policy.OpRead, "t1", "p1")

	done := make(chan struct{})
	go func() { ex.Execute(context.Background(), in, ex.Resolve(in)); close(done) }()
	for i := 0; i < 5_000_000 && lt.inFlightCount() == 0; i++ {
	}
	if lt.inFlightCount() != 1 {
		t.Fatalf("one execution must be in flight before the demotion, got %d", lt.inFlightCount())
	}

	r := getMCPRollout()
	prevCfg := *gwCanaryCfg(1)
	tgt := commitTransitionTarget{
		st:               r.gateway,
		persist:          func(*rollout.State) error { return nil },
		setStatus:        func(string) {},
		countTransition:  func() {},
		reconcileRuntime: true,
	}
	reconcileDone := make(chan error, 1)
	go func() {
		reconcileDone <- r.reconcileCanaryRuntimeAfterCommit(tgt, gwObserveCfg(), prevCfg.Mode, prevCfg, r.gateway.Evidence(), canary.Budget{}, "test", time.Unix(0, 2))
	}()
	select {
	case err := <-reconcileDone:
		if err != nil {
			t.Fatalf("leaving-live reconcile: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the leaving-live demote must NOT block on in-flight work (fast; the boundary invalidates residual, not a drain)")
	}
	if lt.armed() || globalCanaryRuntime.armed(capb) {
		t.Fatal("the demote must un-arm the tier and invalidate the generation")
	}
	// The in-flight execution was already past the boundary before the demote — it completes legitimately.
	up.block <- struct{}{}
	<-done
}

// P1 (round-8): the FINAL BOUNDARY invalidates an already-admitted request whose reserved Canary
// generation was demoted after admission. A gate that ADMITS (reserve granted) but whose final-boundary
// generation revalidation reports the reserved generation is no longer current must make Upstream.Call==0
// with a bounded rollout reason — this is what makes the drain-free demotion safe.
func TestLiveCommit_DemotedGenerationRefusedAtFinalBoundary(t *testing.T) {
	resetLiveTierGlobals(t)
	setDataDirForTest(t, t.TempDir())
	capb := rollout.CapabilityGateway
	gw := getMCPRollout().gateway
	prevCfg := gw.CurrentConfig()
	if err := gw.SetConfig(*gwCanaryCfg(1), "test", time.Unix(0, 1).UnixNano()); err != nil {
		t.Fatalf("SetConfig canary: %v", err)
	}
	t.Cleanup(func() { _ = gw.SetConfig(prevCfg, "restore", time.Unix(0, 2).UnixNano()) })

	up := &recordingUpstream{}
	// A gate that ADMITS (reserve granted) but whose final-boundary generationCurrent reports the
	// reserved generation is no longer current — the exact demote-after-reserve TOCTOU the boundary closes.
	gate := &mcpLiveSideEffectGate{
		capb:      capb,
		admit:     mcpLiveTierFor(capb).admitExecution,
		readFirst: canary.IsReadFirstOperation,
		trustOK:   func(string, string, string, string, time.Time) bool { return true },
		reserve: func(time.Time, canary.ExecutionIdentity) (canary.BudgetOutcome, uint64) {
			return canary.BudgetGranted, 7
		},
		releaseBudget:     func(uint64) {},
		generationCurrent: func(uint64) bool { return false }, // demoted after reserve
		note:              noteMCPLiveGateDenied,
	}
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
	ex := cfg.Deps.Executor
	in := liveExecInput(policy.OpRead, "t1", "p1")
	out := ex.Execute(context.Background(), in, ex.Resolve(in))
	if up.callCount() != 0 {
		t.Fatalf("a request whose reserved generation was demoted must be refused at the boundary (Upstream.Call==0), calls=%d", up.callCount())
	}
	if out.Executed {
		t.Fatalf("the demoted-at-boundary request must not be reported executed, out=%+v", out)
	}
	if out.Reason != mcperr.ReasonRolloutModeInvalid {
		t.Fatalf("demoted-at-boundary reason=%s want rollout_mode_invalid", out.Reason.Code())
	}
}

// P2 (round-7): a repeated quiesce preserves the residual in-flight count. A first bounded quiesce that
// times out leaves the tier composed/unarmed with nonzero inFlight; a retry must NOT take a not-armed
// early return and falsely report a clean drain (0) while the upstream request is still running.
func TestQuiesce_RepeatedAttemptPreservesResidualCount(t *testing.T) {
	up := &recordingUpstream{block: make(chan struct{}, 1)}
	cfg := armCanaryLiveTier(t, up, true, 10)
	ex := cfg.Deps.Executor
	capb := rollout.CapabilityGateway
	lt := mcpLiveTierFor(capb)
	in := liveExecInput(policy.OpRead, "t1", "p1")

	done := make(chan struct{})
	go func() { ex.Execute(context.Background(), in, ex.Resolve(in)); close(done) }()
	for i := 0; i < 5_000_000 && lt.inFlightCount() == 0; i++ {
	}
	if lt.inFlightCount() != 1 {
		t.Fatalf("one execution must be in flight, got %d", lt.inFlightCount())
	}

	// First quiesce with a zero drain budget ⇒ times out with residual 1; tier left composed/unarmed.
	if rem := quiesceLiveTier(capb, 0); rem != 1 {
		t.Fatalf("a zero-budget quiesce with one in flight must report residual 1, got %d", rem)
	}
	if lt.armed() {
		t.Fatal("the tier must be un-armed after the first quiesce")
	}
	// A RETRY (tier not armed, residual still in flight) must still report the residual, never a false 0.
	if rem := quiesceLiveTier(capb, 0); rem != 1 {
		t.Fatalf("a retry with residual in flight must still report 1, not a false clean drain, got %d", rem)
	}
	// Release the in-flight execution; a final quiesce now drains cleanly to 0.
	up.block <- struct{}{}
	<-done
	if rem := quiesceLiveTier(capb, time.Second); rem != 0 {
		t.Fatalf("after the in-flight releases, quiesce must report a clean drain 0, got %d", rem)
	}
}

// P2 (round-8): a residual-retry quiesce re-enters the QUIESCING state, so a concurrent authoritative
// re-arm stays REFUSED while the retry drains — it cannot reopen admission and leave the lifecycle state
// and the armed exec-deps bit inconsistent when the retry lands back at composed.
func TestQuiesce_ResidualRetryRefusesConcurrentRearm(t *testing.T) {
	up := &recordingUpstream{block: make(chan struct{}, 1)}
	cfg := armCanaryLiveTier(t, up, true, 10)
	ex := cfg.Deps.Executor
	capb := rollout.CapabilityGateway
	lt := mcpLiveTierFor(capb)
	in := liveExecInput(policy.OpRead, "t1", "p1")

	done := make(chan struct{})
	go func() { ex.Execute(context.Background(), in, ex.Resolve(in)); close(done) }()
	for i := 0; i < 5_000_000 && lt.inFlightCount() == 0; i++ {
	}
	if lt.inFlightCount() != 1 {
		t.Fatalf("one execution must be in flight, got %d", lt.inFlightCount())
	}

	// First quiesce times out (residual 1); tier composed/unarmed with the in-flight still held.
	if rem := quiesceLiveTier(capb, 0); rem != 1 {
		t.Fatalf("a zero-budget quiesce with one in flight must report residual 1, got %d", rem)
	}

	// A retry quiesce with a generous budget re-enters quiescing and blocks on the in-flight.
	retryDone := make(chan int, 1)
	go func() { retryDone <- quiesceLiveTier(capb, 5*time.Second) }()
	for i := 0; i < 5_000_000 && lt.State() != liveTierQuiescing; i++ {
	}
	if lt.State() != liveTierQuiescing {
		t.Fatal("a residual-retry quiesce must re-enter the quiescing state so re-arm stays refused")
	}

	// A concurrent re-arm during the retry drain must be REFUSED and must not set the exec-deps bit.
	if err := lt.arm(true, "rearm"); err == nil {
		t.Fatal("a re-arm during a residual-retry drain must be refused (the tier is quiescing)")
	}
	if liveExecDepsConfigured(false) {
		t.Fatal("the refused re-arm must not have set the armed exec-deps bit")
	}

	// Release the in-flight → retry completes → tier lands composed/unarmed and consistent.
	up.block <- struct{}{}
	<-done
	<-retryDone
	if lt.State() != liveTierComposed || lt.armed() || liveExecDepsConfigured(false) {
		t.Fatalf("after the retry drains the tier must be composed/unarmed and the exec-deps bit clear, state=%s", lt.State())
	}
}
