package execution

// auxiliary_admission_test.go — §4 at the ADMISSION boundary (Codex round 6, P1).
//
// openAttempt has always refused to mint an attempt identity for lifecycle and
// discovery traffic, and its comment states the contract: such traffic "must never
// consume an execution reservation or inflate the physical-effect count". The
// composition-layer gate ran ABOVE that check, unconditionally, so the contract held
// for the durable intent and not for the reservation it is supposed to name.
//
// These gates pin the admission side of the same sentence, in both directions, with
// tools/call controls on every fixture so a passing gate can never mean the gate
// simply stopped being consulted.

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// countingGate records every admission it is asked for and answers as configured.
// The COUNT is the point: a gate that admits is indistinguishable from one that was
// never consulted if you only look at the outcome, and "was never consulted" is
// exactly the property under test.
type countingGate struct {
	calls  int
	admit  bool
	reason mcperr.Reason
}

func (g *countingGate) AdmitSideEffect(LiveGateInput) LiveGateDecision {
	g.calls++
	if !g.admit {
		return LiveGateDecision{Admit: false, Reason: g.reason}
	}
	return LiveGateDecision{
		Admit: true, Release: func() {},
		ReservationID: "rsv_counted", ActivationGeneration: 4,
	}
}

// TestAuxiliaryTraffic_NeverReachesTheSideEffectGate is the accounting half. A
// reservation is the unit MaxTotalExecutions counts, so spending one on a call that
// can cause no side effect makes the budget stop measuring physical invocations —
// the exact property blocker #6 exists to establish.
func TestAuxiliaryTraffic_NeverReachesTheSideEffectGate(t *testing.T) {
	for _, method := range []string{"initialize", "notifications/initialized", "notifications/cancelled", "ping", "tools/list"} {
		t.Run(method, func(t *testing.T) {
			up := &fakeUpstream{}
			gate := &countingGate{admit: true}
			e := newExec(t, stateForMode(t, rollout.ModeCanary), up, realEvents(t, nil))
			e.cfg.LiveGate = gate

			in := execInput(policy.ActionAllow, false)
			in.Method = method
			out := e.Execute(t.Context(), in, rollout.Resolution{Disposition: rollout.EffectExecute})

			if gate.calls != 0 {
				t.Fatalf("%s consumed %d admission(s); auxiliary traffic must reserve nothing", method, gate.calls)
			}
			if up.calls != 1 {
				t.Fatalf("%s must still reach the upstream, got %d calls; reason %v", method, up.calls, out.Reason)
			}
		})
	}
}

// TestAuxiliaryTraffic_SurvivesARefusingGate is the availability half, and it is the
// shape that actually bites in production: the real gate validates tool trust against
// the invocation's tool binding, which auxiliary traffic does not have, so it
// REFUSES. An armed Canary node could therefore not complete a session handshake or
// list tools — the gate answering "no" to a question it should never have been asked.
func TestAuxiliaryTraffic_SurvivesARefusingGate(t *testing.T) {
	for _, method := range []string{"initialize", "ping", "tools/list"} {
		t.Run(method, func(t *testing.T) {
			up := &fakeUpstream{}
			gate := &countingGate{admit: false, reason: mcperr.ReasonRolloutBudgetExhausted}
			e := newExec(t, stateForMode(t, rollout.ModeCanary), up, realEvents(t, nil))
			e.cfg.LiveGate = gate

			in := execInput(policy.ActionAllow, false)
			in.Method = method
			out := e.Execute(t.Context(), in, rollout.Resolution{Disposition: rollout.EffectExecute})

			if up.calls != 1 {
				t.Fatalf("%s must not be refused by a gate it never needed, got %d calls; reason %v",
					method, up.calls, out.Reason)
			}
		})
	}
}

// TestToolCallStillReachesTheSideEffectGate is the CONTROL for both gates above, on
// the same fixtures. Without it they would pass on an executor that had stopped
// consulting the gate at all — which is the failure this PR must never introduce.
func TestToolCallStillReachesTheSideEffectGate(t *testing.T) {
	t.Run("admitting gate is consulted exactly once", func(t *testing.T) {
		up := &fakeUpstream{}
		gate := &countingGate{admit: true}
		e := newExec(t, stateForMode(t, rollout.ModeCanary), up, realEvents(t, nil))
		e.cfg.LiveGate = gate

		out := e.Execute(t.Context(), execInput(policy.ActionAllow, false), rollout.Resolution{Disposition: rollout.EffectExecute})

		if gate.calls != 1 {
			t.Fatalf("tools/call must consume exactly one admission, got %d", gate.calls)
		}
		if up.calls != 1 || !out.Executed {
			t.Fatalf("control: expected one executed upstream call, got calls=%d executed=%v reason=%v",
				up.calls, out.Executed, out.Reason)
		}
	})
	t.Run("refusing gate still blocks the side effect", func(t *testing.T) {
		up := &fakeUpstream{}
		gate := &countingGate{admit: false, reason: mcperr.ReasonRolloutBudgetExhausted}
		e := newExec(t, stateForMode(t, rollout.ModeCanary), up, realEvents(t, nil))
		e.cfg.LiveGate = gate

		out := e.Execute(t.Context(), execInput(policy.ActionAllow, false), rollout.Resolution{Disposition: rollout.EffectExecute})

		if up.calls != 0 {
			t.Fatalf("control: a refused tools/call must never reach the upstream, got %d", up.calls)
		}
		if out.Executed {
			t.Fatal("control: a refused tools/call must not report Executed")
		}
	})
}

// TestUnclassifiedMethodIsStillMetered pins the fail-closed direction of the
// exemption. The classifier's default is side-effect-bearing, so a method nobody
// classified is metered like a tool call rather than being cheaper than one — an
// exemption keyed on a denylist would be a way to spend no budget by inventing a
// method name.
func TestUnclassifiedMethodIsStillMetered(t *testing.T) {
	up := &fakeUpstream{}
	gate := &countingGate{admit: false, reason: mcperr.ReasonRolloutBudgetExhausted}
	e := newExec(t, stateForMode(t, rollout.ModeCanary), up, realEvents(t, nil))
	e.cfg.LiveGate = gate

	in := execInput(policy.ActionAllow, false)
	in.Method = "resources/write"
	out := e.Execute(t.Context(), in, rollout.Resolution{Disposition: rollout.EffectExecute})

	if gate.calls != 1 {
		t.Fatalf("an unclassified method must be admitted like a tool call, got %d admissions", gate.calls)
	}
	if up.calls != 0 {
		t.Fatalf("an unclassified method refused by the gate must not reach the upstream, got %d", up.calls)
	}
	if out.Executed {
		t.Fatal("an unclassified method refused by the gate must not report Executed")
	}
}
