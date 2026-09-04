package execution

// physical_effect_test.go — executor gates for physical-effect accounting
// (review blockers #6/#8).

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// identityGate admits with caller-chosen reservation identity so a test can drive
// both the metered and the unattributable shapes.
type identityGate struct {
	reservationID string
	generation    uint64
}

func (g identityGate) AdmitSideEffect(LiveGateInput) LiveGateDecision {
	return LiveGateDecision{
		Admit: true, Release: func() {},
		ReservationID: g.reservationID, ActivationGeneration: g.generation,
	}
}

// TestMeteredExecution_FailsClosedWithoutReservationIdentity is the structural gate
// demanded by the physical-effect contract: a metered Canary execution MUST carry a
// reservation identity and an activation generation. Either omission would make the
// resulting effect unattributable — impossible to tie to the slot that paid for it,
// and impossible to recognize as an orphan of a superseded generation after a
// restart — so the executor refuses BEFORE any upstream call.
func TestMeteredExecution_FailsClosedWithoutReservationIdentity(t *testing.T) {
	for _, tc := range []struct {
		name string
		gate identityGate
	}{
		{"no reservation id", identityGate{reservationID: "", generation: 7}},
		{"no activation generation", identityGate{reservationID: "rsv_x", generation: 0}},
		{"neither", identityGate{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up := &fakeUpstream{}
			e := newExec(t, stateForMode(t, rollout.ModeCanary), up, realEvents(t, nil))
			e.cfg.LiveGate = tc.gate

			out := e.Execute(t.Context(), execInput(policy.ActionAllow, false), rollout.Resolution{Disposition: rollout.EffectExecute})

			if out.Executed {
				t.Fatal("an unattributable metered execution must not report Executed")
			}
			if up.calls != 0 {
				t.Fatalf("no upstream call may occur without reservation identity, got %d", up.calls)
			}
			if out.Reason == mcperr.ReasonNone {
				t.Fatal("the refusal must name a bounded reason")
			}
		})
	}
}

// TestMeteredExecution_AdmitsWithFullIdentity is the CONTROL: the identical path
// with both identities present must reach the upstream. Without it the gate above
// could pass simply because execution was broken for every input.
func TestMeteredExecution_AdmitsWithFullIdentity(t *testing.T) {
	up := &fakeUpstream{}
	e := newExec(t, stateForMode(t, rollout.ModeCanary), up, realEvents(t, nil))
	e.cfg.LiveGate = identityGate{reservationID: "rsv_deadbeef", generation: 9}

	out := e.Execute(t.Context(), execInput(policy.ActionAllow, false), rollout.Resolution{Disposition: rollout.EffectExecute})

	if up.calls != 1 {
		t.Fatalf("control: a fully-identified metered execution must reach the upstream exactly once, got %d", up.calls)
	}
	if !out.Executed {
		t.Fatalf("control: expected Executed, got reason %v", out.Reason)
	}
}

// TestAuxiliaryTraffic_ConsumesNoAttempt pins §4 at the executor: lifecycle and
// discovery methods invoke no tool, so they must not mint an attempt identity or
// require reservation identity — otherwise a future MCP lifecycle implementation
// would both inflate the physical-effect count and be refused by the metered gate.
func TestAuxiliaryTraffic_ConsumesNoAttempt(t *testing.T) {
	for _, method := range []string{"initialize", "notifications/initialized", "tools/list"} {
		t.Run(method, func(t *testing.T) {
			up := &fakeUpstream{}
			e := newExec(t, stateForMode(t, rollout.ModeCanary), up, realEvents(t, nil))
			// Deliberately UNATTRIBUTABLE: auxiliary traffic must not be subject to the
			// metered-identity gate, because it consumes no reservation.
			e.cfg.LiveGate = identityGate{}

			in := execInput(policy.ActionAllow, false)
			in.Method = method
			out := e.Execute(t.Context(), in, rollout.Resolution{Disposition: rollout.EffectExecute})

			if up.calls != 1 {
				t.Fatalf("%s must reach the upstream (it consumes no reservation), got %d calls; reason %v",
					method, up.calls, out.Reason)
			}
		})
	}
}

// TestPhysicalSendState_DlpBlockStillRecordsPeerReceipt pins the distinction that
// was previously unrepresentable: a response blocked by inspection means the peer
// DID receive and act on the invocation. Recording it as "not executed" would
// under-count real side effects.
func TestPhysicalSendState_DlpBlockStillRecordsPeerReceipt(t *testing.T) {
	if !model.SendPeerResponseReceived.MayHaveReachedPeer() {
		t.Fatal("a received peer response must count as having reached the peer")
	}
	if model.SendPeerResponseReceived.ReconciliationRequired() {
		t.Fatal("a received peer response needs no reconciliation")
	}
	// The conservative direction: an interrupted attempt is never 'not sent'.
	if !model.SendMayHaveBeenSent.MayHaveReachedPeer() {
		t.Fatal("an ambiguous attempt must be treated as possibly effective")
	}
}
