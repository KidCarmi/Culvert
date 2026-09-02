package main

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/inspection"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
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
