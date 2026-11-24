//go:build lifecycle_conformance

package lifecyclemodel

import (
	"testing"
)

// convergeMutant is the model with one converge behaviour changed: a negative control for
// the R properties. events/step/observe return ok=false to fall back to the real model.
type convergeMutant struct {
	Model
	events  func(s State) ([]string, bool)
	step    func(s State, e string) (State, bool)
	observe func(s State, o map[string]any)
}

func (c convergeMutant) Events(s State) []string {
	if c.events != nil {
		if ev, ok := c.events(s); ok {
			return ev
		}
	}
	return c.Model.Events(s)
}

func (c convergeMutant) Step(s State, e string) State {
	if c.step != nil {
		if t, ok := c.step(s, e); ok {
			return t
		}
	}
	return c.Model.Step(s, e)
}

func (c convergeMutant) Observe(s State) map[string]any {
	o := c.Model.Observe(s)
	if c.observe != nil {
		c.observe(s, o)
	}
	return o
}

// after runs the real step and lets mod change the result, at states where match holds.
func after(match func(s State, e string) bool, mod func(s, t *State)) func(State, string) (State, bool) {
	return func(s State, e string) (State, bool) {
		if !match(s, e) {
			return State{}, false
		}
		t := Model{}.Step(s, e)
		mod(&s, &t)
		return t, true
	}
}

// at matches the step of event e at stage pc.
func at(pc, e string) func(State, string) bool {
	return func(s State, ev string) bool { return s.PC == pc && ev == e }
}

func property(t *testing.T, id string) []Property {
	t.Helper()
	props, _, err := EmbeddedProperties()
	if err != nil {
		t.Fatal(err)
	}
	for i := range props {
		if props[i].ID == id {
			return props[i : i+1]
		}
	}
	t.Fatalf("no property %s", id)
	return nil
}

// convergeMutants: each reintroduces one behaviour owner decision 1 forbids for the
// converge reconcile, and names the property that must catch it.
func convergeMutants() []struct {
	name, kills string
	m           convergeMutant
} {
	upEvents := []string{evRcUpOK, evRcUpStale, evRcUpFail, evRcUpFailRecreated, evRcCrash}
	return []struct {
		name, kills string
		m           convergeMutant
	}{
		{"finish a rollback the journal does not prove armed", "R7", convergeMutant{step: after(at(pcRcDecide, evRcDecide),
			func(s, t *State) {
				a := *s
				a.Armed = true
				*t = Model{}.Step(a, evRcDecide)
				t.Armed = s.Armed
			})}},
		{"T/T finish: `up` before the retag, without the pre-up recheck", "R1", convergeMutant{
			step: after(at(pcRcDecide, evRcDecide), func(_, t *State) {
				if actionOf(t.RcAct) == v2FinishRetag {
					t.PC = pcRcUp
				}
			}),
			events: func(s State) ([]string, bool) { return upEvents, s.PC == pcRcUp }}},
		// The probe at retirement (R15) would also stop an unhealthy prior after the
		// `up`, so the mutant removes both the gate and that probe: verify, then audit.
		{"no fresh gate after the converge `up`", "R6", convergeMutant{step: func(s State, e string) (State, bool) {
			switch {
			case s.PC == pcRcUp && e == evRcUpOK:
				t := Model{}.Step(s, e)
				if t.PC == pcRcGate {
					t.PC = pcRcVerify
				}
				return t, true
			case s.PC == pcRcServe && e == evRcServe && (actionOf(s.RcAct) == v2Finish || actionOf(s.RcAct) == v2FinishRetag):
				t := Model{}.Step(s, e)
				if t.PC == pcReconciled && t.RcOut == rcRR {
					t.PC, t.RcOut = pcRcAudit, ""
				}
				return t, true
			}
			return State{}, false
		}}},
		{"retire an armed rollback found on the prior without a ready probe", "R6", convergeMutant{step: after(at(pcRcDecide, evRcDecide),
			func(_, t *State) {
				if t.RcAct == verdictOf(v2RR, "armed_rollback_prior_not_ready") {
					t.PC, t.RcOut, t.RcAct = pcRcAudit, "", verdictOf(v2Noop, "armed_rollback_prior_ready")
				}
			})}},
		{"a second `up` after the gate failed", "R12", convergeMutant{step: after(at(pcRcGate, evRcGate), func(_, t *State) {
			if t.PC == pcReconciled && t.RcOut == rcRR {
				t.PC, t.RcOut = pcRcUp, ""
			}
		})}},
		{"act without the durable write-ahead attempt", "R8", convergeMutant{step: after(at(pcRcDecide, evRcDecide), func(s, t *State) {
			t.Attempts = s.Attempts
		})}},
		{"audit the retirement again after a crash", "R9", convergeMutant{step: after(at(pcRcAudit, evRcAudit), func(s, t *State) {
			t.Audits = min(s.Audits+1, 2)
		})}},
		{"retire without the audit entry", "R10", convergeMutant{step: after(at(pcRcAudit, evRcAudit), func(s, t *State) {
			t.Audits = s.Audits
		})}},
		{"T/P finish retags the target before its `up`", "R2", convergeMutant{step: after(at(pcRcUp, evRcUpOK), func(s, t *State) {
			if t.PC == pcRcGate {
				t.Tag, t.Running = imgT, imgT
			}
		})}},
		{"the verify brings the target back up", "R3", convergeMutant{step: after(at(pcRcVerify, evRcVerify), func(_, t *State) {
			t.Running = imgT
		})}},
		{"the verify restarts the container", "R4", convergeMutant{step: after(at(pcRcVerify, evRcVerify), func(_, t *State) {
			t.Running = t.Tag
		})}},
		{"retire after a failed verify", "R5", convergeMutant{step: after(at(pcRcVerify, evRcVerify), func(s, t *State) {
			if t.PC == pcReconciled {
				t.PC, t.RcOut = pcRcAudit, ""
			}
		})}},
		{"report the interrupted operation succeeded", "R11", convergeMutant{step: after(at(pcRcRemove, evRcRemove), func(_, t *State) {
			t.Op = "succeeded"
		})}},
		// Since retireIfServing (R15) every retirement is probed again, which also
		// stops an unready prior here; the mutant therefore removes both checks (the
		// armed probe and the one at retirement) and goes straight to the audit. The
		// verify it also skips cannot fail on this path: after the retag, container
		// and tag are both on the prior.
		{"retire an armed realign without the fresh probe", "O4", convergeMutant{step: after(at(pcRcTag, evRcTagOK), func(_, t *State) {
			if t.PC == pcRcProbe {
				t.PC = pcRcAudit
			}
		})}},
		{"retire without the readiness probe at retirement (pre-#2062)", "R15", convergeMutant{step: after(at(pcRcServe, evRcServe), func(_, t *State) {
			if t.PC == pcReconciled && t.RcOut == rcRR {
				t.PC, t.RcOut = pcRcAudit, ""
			}
		})}},
		{"before decision 1: report T/T armed instead of finishing it", "R13", convergeMutant{step: after(at(pcRcDecide, evRcDecide),
			func(s, t *State) {
				if actionOf(t.RcAct) == v2FinishRetag {
					*t = rcEnd(*s, rcRR)
				}
			})}},
		{"adopt a target that never passed the gate", "R14", convergeMutant{observe: func(s State, o map[string]any) {
			if s.PC == pcCrashed && s.Running == imgT && s.Tag == imgT && s.JR == "restarted" {
				o["reconcile_v2"] = v2Adopt
			}
		}}},
	}
}

// TestConvergeProperties_NegativeControls: every converge mutant makes its property FAIL
// (and the property PASSes on the real model), so the properties are able to see the
// behaviour they exist to forbid.
func TestConvergeProperties_NegativeControls(t *testing.T) {
	passed := map[string]bool{}
	for _, mc := range convergeMutants() {
		props := property(t, mc.kills)
		if !passed[mc.kills] {
			res, _, err := Check[State](Model{}, props, budgetStates, budgetTime)
			if err != nil || res[0].Verdict != VerdictPass {
				t.Fatalf("%s on the real model: %+v err=%v", mc.kills, res, err)
			}
			passed[mc.kills] = true
		}
		res, _, err := Check[State](mc.m, props, budgetStates, budgetTime)
		if err != nil {
			t.Errorf("mutant %q: %v", mc.name, err)
			continue
		}
		if res[0].Verdict != VerdictFail {
			t.Errorf("mutant %q survived %s (%s)", mc.name, mc.kills, res[0].Verdict)
			continue
		}
		t.Logf("mutant %q killed by %s: %v", mc.name, mc.kills, res[0].Trace)
	}
}

// TestConvergeRecheck_IsWhatProtectsTheUp: a plan that runs the T/T finish's `up` before
// its retag, but keeps the recheck, never restarts on the target tag: the recheck refuses
// (positive control for the mutant above that also drops the recheck).
func TestConvergeRecheck_IsWhatProtectsTheUp(t *testing.T) {
	m := convergeMutant{step: after(at(pcRcDecide, evRcDecide), func(_, t *State) {
		if actionOf(t.RcAct) == v2FinishRetag {
			t.PC = pcRcUp
		}
	})}
	res, _, err := Check[State](m, property(t, "R1"), budgetStates, budgetTime)
	if err != nil || res[0].Verdict != VerdictPass {
		t.Fatalf("R1 with the up-first plan but the recheck kept: %+v err=%v", res, err)
	}
}
