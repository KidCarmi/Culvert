package main

import (
	"errors"
	"testing"
	"time"

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

	r := getMCPRollout()
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
