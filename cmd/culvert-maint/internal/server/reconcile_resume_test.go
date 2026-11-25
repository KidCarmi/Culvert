package server

import (
	"sync"
	"testing"
	"time"

	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
)

// Forward resumption (ADR-0062 slice 7) as exhaustive properties.
//
// resumeGateV2 is consulted in exactly one place, the branch that otherwise
// says target_live_ungated, and that reason is produced nowhere else. So the
// real decision equals decideWithResume(resumeGateV2): the decision with the
// switch off, unless that is target_live_ungated and the resume function says
// yes. The test checks that equality on every input, which is what lets the
// negative controls swap in a mutated resume function.

func decideWithResume(resume func(*reconcileInputsV2, v2ids) (reconcileVerdictV2, bool)) func(reconcileInputsV2) reconcileVerdictV2 {
	return func(in reconcileInputsV2) reconcileVerdictV2 {
		off := in
		off.ResumeEnabled = false
		base := reconcileDecisionV2(off)
		if !in.ResumeEnabled || base != rr("target_live_ungated") {
			return base
		}
		if v, ok := resume(&in, idsOf(&in)); ok {
			return v
		}
		return base
	}
}

// resumeRegion: the only inputs where resume can apply: an upgrade at
// restarted or restarting with container, tag and the target's local id all
// the same image (whatever the recorded id and the digests say: those are
// what RV19 checks). Every other input is still checked, with the switch on
// and off, by the plain equality and RV19's "the switch changes nothing
// else"; only the resume dimensions are not varied there, as they cannot
// matter.
func resumeRegion(in *reconcileInputsV2) bool {
	run := normID(in.RunningImageID)
	return in.Kind == ops.KindUpgradeApply && in.Mode == "" &&
		(in.Phase == journal.PhaseRestarted || in.Phase == journal.PhaseRestarting) &&
		in.DockerReadable && in.ContainerRunning && run != "" &&
		run == normID(in.TagImageID) && run == normID(in.TargetLocalID)
}

// resumeRegionBases: every generated input in resumeRegion, collected once.
// Walking the full space costs most of a run; the negative controls only need
// this region.
var resumeRegionBases = sync.OnceValue(func() []reconcileInputsV2 {
	var out []reconcileInputsV2
	forEachV2Input(func(in *reconcileInputsV2) bool {
		if resumeRegion(in) {
			cp := *in
			cp.RunningDigests = append([]string(nil), in.RunningDigests...)
			out = append(out, cp)
		}
		return true
	})
	return out
})

// forEachResumeVariant runs fn over the resume dimensions of base, and over a
// death inside the operation's `compose up` found by this start: the generator
// varies that only where no container runs (where it decided anything before
// resume existed), but a container the cut `up` had already started runs.
func forEachResumeVariant(base reconcileInputsV2, fn func(*reconcileInputsV2) bool) bool {
	if !forEachResumeDims(base, fn) {
		return false
	}
	if base.UpInterrupted {
		return true
	}
	cut := base
	cut.UpInterrupted, cut.UpEvidence = true, upEvidencePresent
	return forEachResumeDims(cut, fn)
}

func forEachResumeDims(base reconcileInputsV2, fn func(*reconcileInputsV2) bool) bool {
	tid := base.TargetLocalID // the image resumeIdentity would name
	cks := []ckFacts{
		{},
		{Present: true, Step: journal.StepGateTarget, Attempts: 1, Epoch: 0, ImageID: tid},
		{Present: true, Step: journal.StepGateTarget, Attempts: 1, Epoch: 1, ImageID: tid},
		{Present: true, Step: journal.StepGateTarget, Attempts: 1, Epoch: 2, ImageID: tid},
		{Present: true, Step: journal.StepGateTarget, Attempts: 2, Epoch: 1, ImageID: tid},
		{Present: true, Step: journal.StepGateTarget, Attempts: 0, Epoch: 1, ImageID: tid},
		{Present: true, Step: journal.StepGateTarget, Attempts: 1, Epoch: 1, ImageID: "sha256:" + imgOther},
		{Present: true, Step: journal.StepGateTarget, Attempts: 1, Epoch: 1, ImageID: ""},
		{Present: true, Step: journal.StepGateTarget, Result: journal.CheckpointPassed, Attempts: 1, Epoch: 1, ImageID: tid},
		{Present: true, Step: journal.StepGateTarget, Result: "failed:unhealthy", Attempts: 1, Epoch: 1, ImageID: tid},
		{Present: true, Step: journal.StepGatePrior, Attempts: 1, Epoch: 1, ImageID: tid},
	}
	for _, on := range []bool{false, true} {
		for _, seen := range []int{0, 1, 2, 3} {
			for _, ck := range cks {
				for _, audited := range []bool{false, true} {
					in := base
					in.ResumeEnabled, in.Seen, in.Ck, in.ResumeAudited = on, seen, ck, audited
					if !fn(&in) {
						return false
					}
				}
			}
		}
	}
	return true
}

// resumeViolation: RV19, the conditions under which the agent may vouch for an
// image it has not gated, checked on any decide function.
//
//nolint:cyclop // one flat list of independent properties reads best
func resumeViolation(in *reconcileInputsV2, decide func(reconcileInputsV2) reconcileVerdictV2) string {
	v := decide(*in)
	off := *in
	off.ResumeEnabled = false
	vOff := decide(off)
	if v.Action != actV2ResumeGate {
		if v != vOff {
			return "RV19 the switch changes a verdict other than into resume_gate"
		}
		return ""
	}
	ids := idsOf(in)
	switch {
	case !in.ResumeEnabled:
		return "RV19 resume_gate with resume_interrupted_gate off"
	case vOff != rr("target_live_ungated"):
		return "RV19 resume_gate where the switch-off decision is not target_live_ungated"
	case in.Kind != ops.KindUpgradeApply || in.Mode != "" ||
		(in.Phase != journal.PhaseRestarted && in.Phase != journal.PhaseRestarting):
		return "RV19 resume_gate only for an upgrade at restarted or restarting"
	case in.UpInterrupted:
		return "RV19 never resume after a death inside the op's compose up"
	case in.RollbackArmed:
		return "RV19 never resume an armed record"
	case !in.DockerReadable || !in.ContainerRunning || ids.target == "" ||
		ids.run != ids.target || ids.tag != ids.target || ids.target == ids.prior:
		return "RV19 resume only with container, tag and the validated target reference on one id, not the prior"
	case !digestListed(in.RunningDigests, in.TargetDigest):
		return "RV19 resume only for an image that carries the pinned digest"
	case in.Phase == journal.PhaseRestarted && ids.tid != ids.target:
		return "RV19 at restarted the recorded id must be that id"
	case in.Phase == journal.PhaseRestarting && ids.tid != "":
		return "RV19 at restarting no id may be recorded yet"
	case v.Action.mutatesDocker():
		return "RV19 resume_gate changes Docker by itself"
	}
	ck := in.Ck
	switch v {
	case verdictResumeRetire:
		if !in.ResumeAudited {
			return "RV19 resumed_not_retired without the :resumed entry"
		}
	case verdictResumeNotBegun:
		if ck.Present || in.Seen != 1 {
			return "RV19 a gate that never began resumes only at interrupted_seen 1, with no checkpoint"
		}
	case verdictResumeInterrupted:
		switch {
		case !ck.Present || ck.Step != journal.StepGateTarget || ck.Result != "":
			return "RV19 target_gate_interrupted only from an open gate:target checkpoint"
		case normID(ck.ImageID) != ids.target:
			return "RV19 the checkpoint must name the target id"
		case ck.Epoch != in.Seen-1:
			return "RV19 resume only when no start but this one saw the record since the gate began"
		case ck.Attempts < 1 || ck.Attempts >= resumeMaxGateRuns:
			return "RV19 resume only below the gate-run cap"
		}
	default:
		return "RV19 resume_gate with an unknown reason"
	}
	if !in.ResumeAudited && v == verdictResumeRetire {
		return "RV19 resumed_not_retired without the :resumed entry"
	}
	return ""
}

func TestReconcileResume_ExhaustiveProperties(t *testing.T) {
	composed := decideWithResume(resumeGateV2)
	seen := map[string]int{}
	fails, region := 0, 0
	forEachV2Input(func(base *reconcileInputsV2) bool {
		check := func(in *reconcileInputsV2) bool {
			got := reconcileDecisionV2(*in)
			if want := composed(*in); got != want {
				t.Fatalf("decideWithResume is not the real decision: %+v real=%v composed=%v", *in, got, want)
			}
			seen[got.Action.String()+"/"+got.Reason]++
			if got.Action == actV2ResumeGate {
				seen["resume at "+string(in.Phase)]++
			}
			if viol := resumeViolation(in, reconcileDecisionV2); viol != "" {
				if fails < 10 {
					t.Errorf("PROPERTY %s\n input=%+v verdict=%v", viol, *in, got)
				}
				fails++
			}
			return true
		}
		if !resumeRegion(base) {
			on := *base
			on.ResumeEnabled = true
			return check(base) && check(&on)
		}
		region++
		return forEachResumeVariant(*base, check)
	})
	if region == 0 {
		t.Fatal("the resume region is empty: the generator never reaches an upgrade at restarted with container and tag agreeing")
	}
	for _, w := range []string{"resume_gate/target_gate_interrupted", "resume_gate/target_gate_not_begun",
		"resume_gate/resumed_not_retired", "recovery_required/target_live_ungated",
		"resume at " + string(journal.PhaseRestarted), "resume at " + string(journal.PhaseRestarting)} {
		if seen[w] == 0 {
			t.Errorf("VACUOUS: verdict %q never produced", w)
		}
	}
	t.Logf("resume region: %d base inputs; resume verdicts %d/%d/%d", region,
		seen["resume_gate/target_gate_interrupted"], seen["resume_gate/target_gate_not_begun"], seen["resume_gate/resumed_not_retired"])
}

// resumeMutant is resumeGateV2 with one RV19 condition dropped.
type resumeMutant struct {
	name string
	fn   func(*reconcileInputsV2, v2ids) (reconcileVerdictV2, bool)
}

//nolint:funlen,gocognit // one flat table of mutants, each a few lines
func resumeMutants() []resumeMutant {
	open := func(in *reconcileInputsV2, ids v2ids) bool {
		_, ok := resumeIdentity(in, ids)
		return in.ResumeEnabled && in.Kind == ops.KindUpgradeApply && in.Mode == "" && ok
	}
	// loose: resumeGateV2 with id in place of resumeIdentity.
	loose := func(id func(*reconcileInputsV2, v2ids) (string, bool)) func(*reconcileInputsV2, v2ids) (reconcileVerdictV2, bool) {
		return func(in *reconcileInputsV2, ids v2ids) (reconcileVerdictV2, bool) {
			if !in.ResumeEnabled || in.Kind != ops.KindUpgradeApply || in.Mode != "" || in.UpInterrupted || in.RollbackArmed {
				return reconcileVerdictV2{}, false
			}
			t, ok := id(in, ids)
			if !ok {
				return reconcileVerdictV2{}, false
			}
			if in.ResumeAudited {
				return verdictResumeRetire, true
			}
			c := in.Ck
			if !c.Present {
				if in.Seen != 1 {
					return reconcileVerdictV2{}, false
				}
				return verdictResumeNotBegun, true
			}
			if c.Step != journal.StepGateTarget || c.Result != "" || normID(c.ImageID) != t || c.Epoch != in.Seen-1 ||
				c.Attempts < 1 || c.Attempts >= resumeMaxGateRuns {
				return reconcileVerdictV2{}, false
			}
			return verdictResumeInterrupted, true
		}
	}
	sameImage := func(in *reconcileInputsV2, ids v2ids) bool {
		t := ids.target
		return t != "" && ids.run == t && ids.tag == t && t != ids.prior && in.ContainerRunning
	}
	return []resumeMutant{
		{"ignores the epoch", func(in *reconcileInputsV2, ids v2ids) (reconcileVerdictV2, bool) {
			c := in.Ck
			if open(in, ids) && !in.UpInterrupted && c.Present && c.Step == journal.StepGateTarget && c.Result == "" &&
				normID(c.ImageID) == ids.target && c.Attempts >= 1 && c.Attempts < resumeMaxGateRuns {
				return verdictResumeInterrupted, true
			}
			return resumeGateV2(in, ids)
		}},
		{"no checkpoint at any interrupted_seen", func(in *reconcileInputsV2, ids v2ids) (reconcileVerdictV2, bool) {
			if open(in, ids) && !in.UpInterrupted && !in.Ck.Present {
				return verdictResumeNotBegun, true
			}
			return resumeGateV2(in, ids)
		}},
		{"ignores a death inside compose up", func(in *reconcileInputsV2, ids v2ids) (reconcileVerdictV2, bool) {
			x := *in
			x.UpInterrupted = false
			return resumeGateV2(&x, ids)
		}},
		{"ignores the cap", func(in *reconcileInputsV2, ids v2ids) (reconcileVerdictV2, bool) {
			c := in.Ck
			if open(in, ids) && !in.UpInterrupted && c.Present && c.Step == journal.StepGateTarget && c.Result == "" &&
				normID(c.ImageID) == ids.target && c.Epoch == in.Seen-1 && c.Attempts >= 1 {
				return verdictResumeInterrupted, true
			}
			return resumeGateV2(in, ids)
		}},
		{"ignores the checkpoint's image", func(in *reconcileInputsV2, ids v2ids) (reconcileVerdictV2, bool) {
			x := *in
			if x.Ck.Present {
				x.Ck.ImageID = "sha256:" + ids.tid
			}
			return resumeGateV2(&x, ids)
		}},
		{"resumes a closed checkpoint", func(in *reconcileInputsV2, ids v2ids) (reconcileVerdictV2, bool) {
			x := *in
			x.Ck.Result = ""
			return resumeGateV2(&x, ids)
		}},
		{"ignores the pinned digest", loose(func(in *reconcileInputsV2, ids v2ids) (string, bool) {
			ok := sameImage(in, ids) && ((in.Phase == journal.PhaseRestarted && ids.tid == ids.target) ||
				(in.Phase == journal.PhaseRestarting && ids.tid == ""))
			return ids.target, ok
		})},
		{"accepts a recorded id at restarting", loose(func(in *reconcileInputsV2, ids v2ids) (string, bool) {
			ok := sameImage(in, ids) && digestListed(in.RunningDigests, in.TargetDigest) &&
				((in.Phase == journal.PhaseRestarted && ids.tid == ids.target) || in.Phase == journal.PhaseRestarting)
			return ids.target, ok
		})},
		{"ignores the recorded id at restarted", loose(func(in *reconcileInputsV2, ids v2ids) (string, bool) {
			ok := sameImage(in, ids) && digestListed(in.RunningDigests, in.TargetDigest) &&
				(in.Phase == journal.PhaseRestarted || (in.Phase == journal.PhaseRestarting && ids.tid == ""))
			return ids.target, ok
		})},
		{"retires without the :resumed entry", func(in *reconcileInputsV2, ids v2ids) (reconcileVerdictV2, bool) {
			if open(in, ids) && !in.UpInterrupted && in.Ck.Present && in.Ck.Result == journal.CheckpointPassed {
				return verdictResumeRetire, true
			}
			return resumeGateV2(in, ids)
		}},
	}
}

// TestReconcileResume_NegativeControls: each mutant drops one RV19 condition
// from resumeGateV2 and must be caught somewhere in the space.
func TestReconcileResume_NegativeControls(t *testing.T) {
	mutants := resumeMutants()
	for _, m := range mutants {
		start := time.Now()
		decide := decideWithResume(m.fn)
		caught := false
		for _, base := range resumeRegionBases() {
			if !forEachResumeVariant(base, func(in *reconcileInputsV2) bool {
				caught = resumeViolation(in, decide) != ""
				return !caught
			}) {
				break
			}
		}
		if !caught {
			t.Errorf("mutant %q survived the RV19 properties", m.name)
		}
		t.Logf("mutant %q caught=%v in %s", m.name, caught, time.Since(start).Round(time.Millisecond))
	}
}
