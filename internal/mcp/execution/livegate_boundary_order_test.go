package execution

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/inspection"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// SIDE-EFFECT BOUNDARY ORDERING with the composition-layer LiveGate wired.
//
// Inserting the gate into callUpstream moved code in front of the one place PREREQ-MCP-KILL-1
// depends on: the emergency-kill re-read must remain the LAST authoritative state read before
// Upstream.Call, and no refusal may leak the lifecycle in-flight count or the Canary budget
// concurrency slot the gate reserved. Both properties are structural — they live in the ORDER of
// four statements in run.go and in a single `defer release()` — so a refactor that (a) moved the
// gate after preCallGuard, (b) returned on a boundary abort before the deferred release was
// armed, or (c) let the gate's reason outrank an engaged kill would compile, would keep every
// existing execution-package test green, and would each be a real safety regression:
//
//	(a) the kill re-read would no longer be last (the gate can block on a durable budget persist);
//	(b) a killed or drifted request would permanently consume a budget slot, so repeated
//	    kill-aborts would exhaust the Canary blast-radius budget and wedge the tier;
//	(c) an operator hitting emergency stop would read "budget exhausted" instead of
//	    "rollout_emergency_active" in the block evidence for the request they stopped.
//
// These gates pin all three on the REAL boundary (the gate is consulted, the ToolStillCurrent
// hook fires, Upstream.Call is counted), not on a stand-in.

// orderingGate is a deterministic LiveExecutionGate that counts its consultations and its
// Release invocations, and drives Revalidate from an injected predicate.
type orderingGate struct {
	admit      bool
	reason     mcperr.Reason
	revalidate func() bool

	mu       sync.Mutex
	calls    int
	releases int
}

func (g *orderingGate) AdmitSideEffect(LiveGateInput) LiveGateDecision {
	g.mu.Lock()
	g.calls++
	g.mu.Unlock()
	if !g.admit {
		return LiveGateDecision{Admit: false, Reason: g.reason}
	}
	return LiveGateDecision{
		Admit:      true,
		Revalidate: g.revalidate,
		Release: func() {
			g.mu.Lock()
			g.releases++
			g.mu.Unlock()
		},
	}
}

func (g *orderingGate) counts() (calls, releases int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.calls, g.releases
}

// newGatedExec builds a Canary-mode live executor with the ordering gate wired, on the
// no-credential path (execInput carries no CredentialProfile obligation, so callUpstream is
// reached through CommitThenAct rather than the broker).
func newGatedExec(t *testing.T, st *rollout.State, up UpstreamCaller, g LiveExecutionGate) *Executor {
	t.Helper()
	e, err := New(Config{
		State: st, Upstream: up, Events: realEvents(t, nil),
		ResponseProfile: inspection.DefaultGatewayProfile(1),
		Clock:           func() time.Time { return time.Unix(0, 1) },
		LiveGate:        g,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

// The emergency kill outranks an ALREADY-ADMITTED gate decision. The gate admits (so a budget
// slot and an in-flight count are held), then the kill is engaged from inside the boundary hook
// — the same window TestCanaryPrerequisite_KillStateRevalidatedAtSideEffectBoundary drives,
// now with the gate in front of it. The call must be aborted, the reason must be the kill's,
// and the gate's Release must have run exactly once so nothing is leaked.
func TestLiveGate_EmergencyKillOutranksAdmittedGateAtBoundary(t *testing.T) {
	st := stateForMode(t, rollout.ModeCanary)
	up := &fakeUpstream{}
	gate := &orderingGate{admit: true}
	e := newGatedExec(t, st, up, gate)

	in := execInput(policy.ActionAllow, false)
	killed := false
	in.ToolStillCurrent = func() bool {
		if !killed {
			st.EngageKillSwitch("oncall", 2)
			killed = true
		}
		return true // not drifted: only the boundary kill re-read can stop this call
	}

	out := runExec(e, context.Background(), in)

	if !killed {
		t.Fatal("the boundary hook never ran — the test did not reach the side-effect boundary, so it proves nothing")
	}
	calls, releases := gate.counts()
	if calls != 1 {
		t.Fatalf("the live gate must be consulted exactly once at the boundary, got %d", calls)
	}
	req0Upstream(t, up)
	if out.Reason != mcperr.ReasonRolloutEmergencyActive {
		t.Fatalf("SECURITY: an emergency kill engaged after gate admission must surface %s, got %s — the kill re-read must stay the LAST authoritative check before Upstream.Call",
			mcperr.ReasonRolloutEmergencyActive.Code(), out.Reason.Code())
	}
	if out.Executed {
		t.Fatalf("a boundary kill refusal must not report Executed=true, state=%q", out.ExecutionState)
	}
	if releases != 1 {
		t.Fatalf("SECURITY: the gate's Release must run exactly once even when the boundary aborts AFTER admission, got %d — a leaked slot permanently consumes Canary budget", releases)
	}
}

// Tool drift at the boundary likewise outranks an admitted gate, and still releases. The gate
// being consulted (calls == 1) on a request the drift check aborts is the structural proof that
// the gate runs BEFORE preCallGuard: were the order reversed, the drift would abort first and
// the gate would never be asked.
func TestLiveGate_ToolDriftOutranksAdmittedGateAndReleasesOnce(t *testing.T) {
	st := stateForMode(t, rollout.ModeCanary)
	up := &fakeUpstream{}
	gate := &orderingGate{admit: true}
	e := newGatedExec(t, st, up, gate)

	in := execInput(policy.ActionAllow, false)
	in.ToolStillCurrent = func() bool { return false } // drifted at the boundary

	out := runExec(e, context.Background(), in)

	calls, releases := gate.counts()
	if calls != 1 {
		t.Fatalf("the live gate must be consulted BEFORE the boundary freshness check (got %d consultations); the gate ordering is a PREREQ-MCP-KILL-1 invariant", calls)
	}
	req0Upstream(t, up)
	if out.Reason != mcperr.ReasonDecisionSnapshotStale {
		t.Fatalf("a boundary drift refusal must surface %s, got %s", mcperr.ReasonDecisionSnapshotStale.Code(), out.Reason.Code())
	}
	if releases != 1 {
		t.Fatalf("SECURITY: a drift abort after gate admission must still release the reserved slot exactly once, got %d", releases)
	}
}

// A gate DENIAL never reaches the upstream, surfaces the gate's own bounded reason (never a
// transport/durability fault or ReasonNone), and acquires nothing to release. This is the
// no-credential sibling of TestLiveGate_CredentialGateRefusalMetersOnce.
func TestLiveGate_DenialReachesNoUpstreamAndReleasesNothing(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reason mcperr.Reason
	}{
		{"live_trust_withdrawn", mcperr.ReasonLiveTrustRevalidationFailed},
		{"budget_exhausted", mcperr.ReasonRolloutBudgetExhausted},
		{"not_read_first", mcperr.ReasonRolloutOutOfScope},
		{"quiescing", mcperr.ReasonRolloutModeInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up := &fakeUpstream{}
			gate := &orderingGate{admit: false, reason: tc.reason}
			e := newGatedExec(t, stateForMode(t, rollout.ModeCanary), up, gate)

			out := runExec(e, context.Background(), execInput(policy.ActionAllow, false))

			calls, releases := gate.counts()
			if calls != 1 {
				t.Fatalf("the gate must be consulted exactly once, got %d", calls)
			}
			req0Upstream(t, up)
			if out.Reason != tc.reason {
				t.Fatalf("SECURITY: a gate denial must surface its own bounded reason %s, got %s", tc.reason.Code(), out.Reason.Code())
			}
			if out.Executed {
				t.Fatalf("a gate denial must not report Executed=true, state=%q", out.ExecutionState)
			}
			if releases != 0 {
				t.Fatalf("a denied gate acquires nothing, so Release must never run, got %d", releases)
			}
		})
	}
}

// The final-boundary Revalidate (a concurrent Canary demotion invalidating the generation the
// reservation was made under) refuses BEFORE Upstream.Call, reads as a bounded rollout reason
// rather than ReasonNone, and still releases exactly once.
func TestLiveGate_RevalidateFalseRefusesBeforeUpstreamAndReleasesOnce(t *testing.T) {
	up := &fakeUpstream{}
	gate := &orderingGate{admit: true, revalidate: func() bool { return false }}
	e := newGatedExec(t, stateForMode(t, rollout.ModeCanary), up, gate)

	in := execInput(policy.ActionAllow, false)
	in.ToolStillCurrent = func() bool { return true } // not drifted; only the demotion can refuse

	out := runExec(e, context.Background(), in)

	_, releases := gate.counts()
	req0Upstream(t, up)
	if out.Reason != mcperr.ReasonRolloutModeInvalid {
		t.Fatalf("SECURITY: a demoted activation generation must refuse at the final boundary with %s, got %s (never ReasonNone or a transport fault)",
			mcperr.ReasonRolloutModeInvalid.Code(), out.Reason.Code())
	}
	if out.Executed {
		t.Fatalf("a demoted-generation refusal must not report Executed=true, state=%q", out.ExecutionState)
	}
	if releases != 1 {
		t.Fatalf("SECURITY: a final-boundary demotion refusal must release the reserved slot exactly once, got %d", releases)
	}
}

// A Revalidate that reports the generation is still current does NOT interfere: the request
// proceeds to the upstream exactly once. This is the control for the three refusal gates above —
// without it, a Revalidate wired to always refuse would pass every one of them while breaking
// live execution entirely.
func TestLiveGate_RevalidateTrueStillExecutes(t *testing.T) {
	up := &fakeUpstream{}
	gate := &orderingGate{admit: true, revalidate: func() bool { return true }}
	e := newGatedExec(t, stateForMode(t, rollout.ModeCanary), up, gate)

	in := execInput(policy.ActionAllow, false)
	in.ToolStillCurrent = func() bool { return true }

	out := runExec(e, context.Background(), in)

	_, releases := gate.counts()
	if up.calls != 1 {
		t.Fatalf("an admitted, revalidated, undrifted, unkilled request must reach the upstream exactly once, got %d (out=%+v)", up.calls, out)
	}
	if releases != 1 {
		t.Fatalf("the gate's Release must run exactly once after the upstream leg, got %d", releases)
	}
}

// A nil LiveGate leaves the boundary byte-identical to the pre-gate path: the disabled-by-default
// build composes no live gate, and every non-live composition (Shadow, Observe) must be unaffected.
func TestLiveGate_NilGateLeavesBoundaryUnchanged(t *testing.T) {
	up := &fakeUpstream{}
	e := newExec(t, stateForMode(t, rollout.ModeCanary), up, realEvents(t, nil))

	in := execInput(policy.ActionAllow, false)
	in.ToolStillCurrent = func() bool { return true }

	if out := runExec(e, context.Background(), in); up.calls != 1 {
		t.Fatalf("with no LiveGate composed the boundary must be unchanged: want 1 upstream call, got %d (out=%+v)", up.calls, out)
	}
}
