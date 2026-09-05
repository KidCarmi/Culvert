package execution

// physical_effect_test.go — executor gates for physical-effect accounting
// (review blockers #6/#8).

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	"github.com/KidCarmi/Culvert/internal/mcp/upstreamclient"
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

// AdmitAuxiliary admits the lifecycle-only path. It deliberately returns NO reservation
// identity: auxiliary traffic has no attempt, so there is no slot to name.
func (g identityGate) AdmitAuxiliary(LiveGateInput) LiveGateDecision {
	return LiveGateDecision{Admit: true, Release: func() {}}
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

// neverStartedUpstream fails the way the production client fails when a call is
// refused before any leg begins, carrying the never-started fact on the error.
type neverStartedUpstream struct{ calls int }

func (u *neverStartedUpstream) Call(context.Context, upstreamclient.Target, string, json.RawMessage, upstreamclient.CallOptions) (*upstreamclient.Response, error) {
	u.calls++
	return nil, upstreamclient.MarkNeverSentForTest(
		mcperr.New(mcperr.ReasonUpstreamTransportRejected, "test", "refused before any leg began"))
}

// TestPhysicalSendState_ALocalRefusalIsNotAnAmbiguousSend pins round 14's P2.
//
// A call refused before any request bytes exist — method not admitted, invalid
// target, pool admission refused, an endpoint that will not canonicalize, a resolve
// failure, a request that will not build — is not ambiguous. Recording
// may_have_been_sent there was conservative but FALSE, and it cost twice: the outcome
// claimed Executed for an invocation that never happened, and the attempt was sent to
// witness reconciliation with nothing to establish.
func TestPhysicalSendState_ALocalRefusalIsNotAnAmbiguousSend(t *testing.T) {
	up := &neverStartedUpstream{}
	e := newExec(t, stateForMode(t, rollout.ModeCanary), up, realEvents(t, nil))
	e.cfg.LiveGate = identityGate{reservationID: "rsv_local", generation: 3}

	e.Execute(t.Context(), execInput(policy.ActionAllow, false), rollout.Resolution{Disposition: rollout.EffectExecute})

	if up.calls != 1 {
		t.Fatalf("the call must be attempted exactly once, got %d", up.calls)
	}
	// The DURABLE record is the claim under test, not the ExecOutput. ExecOutput.Executed
	// is Culvert's disposition (what the client got); Outcome.PhysicalSendState and
	// Outcome.Executed are the peer's reality, and they are what recovery and any witness
	// reconciliation read.
	st, executed := durableSendState(t, e)
	if st != model.SendDefinitelyNotSent {
		t.Fatalf("a call refused before any leg began must record definitely_not_sent, got %q", st)
	}
	if executed {
		t.Fatal("a provably never-sent attempt must not record executed")
	}
}

// durableSendState reads the terminal outcome this executor committed and returns the
// physical send state and the executed flag it durably recorded.
func durableSendState(t *testing.T, e *Executor) (model.PhysicalSendState, bool) {
	t.Helper()
	sp := e.cfg.Events.Spool(model.CapGateway)
	if sp == nil {
		t.Fatal("no gateway spool")
	}
	for _, part := range []model.Partition{model.PartCrit, model.PartOrd} {
		evs, _, _, err := sp.CommittedForExport(part, 0, 256)
		if err != nil {
			t.Fatalf("CommittedForExport(%v): %v", part, err)
		}
		for i := range evs {
			if evs[i].Phase == model.PhaseOutcome && evs[i].Outcome != nil && evs[i].Outcome.AttemptID != "" {
				return evs[i].Outcome.PhysicalSendState, evs[i].Outcome.Executed
			}
		}
	}
	t.Fatal("no terminal attempt outcome was committed")
	return "", false
}

// TestPhysicalSendState_AnUnmarkedFailureStaysAmbiguous is the CONTROL, and it is the
// one that matters: the never-started fact is ABSENT BY DEFAULT. A failure from a path
// nobody classified — or from a test double that returns a bare error — must keep the
// conservative may_have_been_sent, never be downgraded by omission.
func TestPhysicalSendState_AnUnmarkedFailureStaysAmbiguous(t *testing.T) {
	up := &fakeUpstream{err: mcperr.New(mcperr.ReasonUpstreamCallFailed, "test", "connection reset mid-flight")}
	e := newExec(t, stateForMode(t, rollout.ModeCanary), up, realEvents(t, nil))
	e.cfg.LiveGate = identityGate{reservationID: "rsv_amb", generation: 3}

	e.Execute(t.Context(), execInput(policy.ActionAllow, false), rollout.Resolution{Disposition: rollout.EffectExecute})

	// An ambiguous transport failure keeps may_have_been_sent, and therefore executed:
	// the peer may have acted, and this PR's central rule is that uncertainty is never
	// converted into "not executed".
	st, executed := durableSendState(t, e)
	if st != model.SendMayHaveBeenSent {
		t.Fatalf("an unmarked transport failure must stay ambiguous, got %q", st)
	}
	if !executed {
		t.Fatal("an ambiguous send must not be downgraded to not-executed by omission")
	}
}
