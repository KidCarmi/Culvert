package main

// mcp_live_gate_auxiliary_test.go — SEC-MCP-AUX-1.
//
// The composition-layer gate answers TWO different questions, and this file pins the
// second one at the production implementation.
//
// AdmitSideEffect asks four: is the tier admitting, is this read-first, does a live
// approval still bind this exact tool, and is there a budget slot. Auxiliary traffic —
// MCP lifecycle and discovery, which invoke no tool — has a real answer to only the
// first. Routing it through all four both REFUSED it (tool trust cannot bind a tool
// that does not exist) and, had it admitted, would have spent a Canary execution
// reservation on a call that can cause no side effect.
//
// The first fix for that skipped the gate entirely, which threw away the question that
// DOES apply: a tier the operator has disarmed, or has begun quiescing, must not open a
// session to a third-party upstream or read its catalog. These gates pin AdmitAuxiliary
// running exactly the lifecycle half — no more, and no less.

import (
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/execution"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// auxSeams drives the production gate's seams for the auxiliary admission. Every seam
// that AdmitAuxiliary must NOT consult is wired to a counter, so "did not consult" is
// proven rather than assumed — a gate that quietly started reserving budget for
// discovery traffic would otherwise pass every behavioural assertion here.
type auxSeams struct {
	admitOK    bool
	admitOpen  bool
	admitRel   int
	readCalls  int
	trustCalls int
	resCalls   int
	relBudget  int
}

func newAuxGate(s *auxSeams) *mcpLiveSideEffectGate {
	return &mcpLiveSideEffectGate{
		capb: rollout.CapabilityGateway,
		admit: func() (func(), bool) {
			if !s.admitOK {
				return nil, false
			}
			return func() { s.admitRel++ }, true
		},
		admitOpen: func() bool { return s.admitOpen },
		readFirst: func(policy.OperationClass) bool { s.readCalls++; return true },
		trustOK: func(string, string, string, string, time.Time) bool {
			s.trustCalls++
			return true
		},
		reserve: func(time.Time, canary.ExecutionIdentity) (canary.BudgetOutcome, uint64) {
			s.resCalls++
			return canary.BudgetGranted, 7
		},
		releaseBudget: func(uint64) { s.relBudget++ },
	}
}

// TestAdmitAuxiliary_RefusesADisarmedOrQuiescingTier is the regression wall. Arming is
// the operator's authorization for this node to talk to a live upstream at all, and a
// restart deliberately leaves the tier composed-but-unarmed while the persisted rollout
// mode may still resolve EffectExecute. If the lifecycle answer does not reach
// auxiliary traffic, that fail-closed restart posture holds for tools/call and for
// nothing else.
func TestAdmitAuxiliary_RefusesADisarmedOrQuiescingTier(t *testing.T) {
	s := &auxSeams{admitOK: false}
	d := newAuxGate(s).AdmitAuxiliary(execution.LiveGateInput{})

	if d.Admit {
		t.Fatal("auxiliary traffic was admitted on a disarmed/quiescing tier")
	}
	if d.Reason != mcperr.ReasonRolloutModeInvalid {
		t.Fatalf("refusal reason = %v, want %v", d.Reason, mcperr.ReasonRolloutModeInvalid)
	}
	// A refusal must leak nothing: the lifecycle slot was never taken, so there is
	// nothing to release, and no budget was touched.
	if s.admitRel != 0 || s.relBudget != 0 {
		t.Fatalf("a refused admission released slots it never took: admitRel=%d relBudget=%d", s.admitRel, s.relBudget)
	}
}

// TestAdmitAuxiliary_AdmitsAnArmedTierWithoutSpendingABudgetSlot is the accounting
// half, and the reason the auxiliary admission is a separate method rather than a
// relaxed side-effect admission. The Canary budget counts AUTHORIZED TOOL EXECUTIONS;
// spending a slot on a call that can cause no side effect makes MaxTotalExecutions stop
// measuring physical invocations.
func TestAdmitAuxiliary_AdmitsAnArmedTierWithoutSpendingABudgetSlot(t *testing.T) {
	s := &auxSeams{admitOK: true, admitOpen: true}
	d := newAuxGate(s).AdmitAuxiliary(execution.LiveGateInput{})

	if !d.Admit {
		t.Fatalf("armed tier refused auxiliary traffic: %v", d.Reason)
	}
	if s.resCalls != 0 {
		t.Fatalf("auxiliary admission reserved %d budget slot(s); it must reserve none", s.resCalls)
	}
	// The two seams that ask about a TOOL must not be consulted at all — that is the
	// over-blocking bug this admission exists to avoid, and asserting on the outcome
	// alone would not catch a gate that consulted them and happened to be told yes.
	if s.trustCalls != 0 {
		t.Fatalf("auxiliary admission ran tool-trust revalidation %d time(s); it has no tool to bind", s.trustCalls)
	}
	if s.readCalls != 0 {
		t.Fatalf("auxiliary admission ran the read-first rule %d time(s)", s.readCalls)
	}
	// No slot was reserved, so no slot may be named. A reservation identity here could
	// only ever attribute a physical effect to a grant that authorized none.
	if d.ReservationID != "" || d.ActivationGeneration != 0 {
		t.Fatalf("auxiliary admission named a reservation it never took: id=%q gen=%d",
			d.ReservationID, d.ActivationGeneration)
	}
	if d.Release == nil {
		t.Fatal("an admitted auxiliary call must return a Release, or a quiesce drain never completes")
	}
	d.Release()
	if s.admitRel != 1 {
		t.Fatalf("lifecycle in-flight releases = %d, want exactly 1", s.admitRel)
	}
}

// TestAdmitAuxiliary_RevalidatesTheLifecycleAtTheBoundary pins the final-boundary
// re-check. Admission alone is a check-then-act: a disarm or quiesce landing between the
// admission and the irreversible call would otherwise still reach the upstream.
func TestAdmitAuxiliary_RevalidatesTheLifecycleAtTheBoundary(t *testing.T) {
	s := &auxSeams{admitOK: true, admitOpen: true}
	d := newAuxGate(s).AdmitAuxiliary(execution.LiveGateInput{})
	if !d.Admit || d.Revalidate == nil {
		t.Fatalf("expected an admitted decision carrying a Revalidate; admit=%v", d.Admit)
	}
	if !d.Revalidate() {
		t.Fatal("revalidation refused while admission was still open")
	}
	// The tier closes admission after the grant.
	s.admitOpen = false
	if d.Revalidate() {
		t.Fatal("revalidation admitted after the tier closed admission mid-flight")
	}
}

// TestAdmitAuxiliary_RevalidationIsReadOnly is the control for the test above. The
// revalidation must NOT re-run admitExecution: that would take a second lifecycle
// in-flight slot which nothing releases, and a quiesce drain waits on that count
// forever — turning a wind-down into a hang.
func TestAdmitAuxiliary_RevalidationIsReadOnly(t *testing.T) {
	s := &auxSeams{admitOK: true, admitOpen: true}
	d := newAuxGate(s).AdmitAuxiliary(execution.LiveGateInput{})
	admitsBefore := s.admitRel

	for i := 0; i < 3; i++ {
		d.Revalidate()
	}
	d.Release()

	if got := s.admitRel - admitsBefore; got != 1 {
		t.Fatalf("lifecycle releases after 3 revalidations + 1 release = %d, want 1 "+
			"(revalidation must take no in-flight slot)", got)
	}
}

// TestAdmissionOpen_MatchesAdmitExecution pins the tier predicate the revalidation reads
// against the admission it mirrors. They must agree on every state, or the boundary
// re-check would answer a different question from the admission — in particular
// admitClosed, which is the bit quiesce and demote actually set.
func TestAdmissionOpen_MatchesAdmitExecution(t *testing.T) {
	for _, tc := range []struct {
		name        string
		state       liveTierState
		admitClosed bool
		want        bool
	}{
		{"absent", liveTierAbsent, false, false},
		{"composed but unarmed", liveTierComposed, false, false},
		{"armed", liveTierArmed, false, true},
		{"armed with admission closed (demoted)", liveTierArmed, true, false},
		{"quiescing", liveTierQuiescing, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lt := newMCPLiveTier(rollout.CapabilityGateway)
			lt.state, lt.admitClosed = tc.state, tc.admitClosed
			if got := lt.admissionOpen(); got != tc.want {
				t.Fatalf("admissionOpen() = %v, want %v", got, tc.want)
			}
			// The predicate is the read-only form of admitExecution, so the two must
			// never disagree — that equivalence is the whole reason it is safe to use
			// one as the other's boundary re-check.
			rel, ok := lt.admitExecution()
			if ok != tc.want {
				t.Fatalf("admitExecution ok = %v but admissionOpen = %v; the two must agree", ok, tc.want)
			}
			if ok {
				rel()
			}
		})
	}
}
