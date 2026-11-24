//go:build lifecycle_conformance

package lifecyclemodel

// The opt-in startup reconcile, reconcile_on_startup = "converge" (contract AGT-900,
// owner decision 1), as a further step after a crash: `restart_converge` starts an agent
// that reconciles the journal record, next to the default `restart_agent` ("off", which
// only reports). Source of truth: cmd/culvert-maint/internal/server/startup_reconcile.go
// (execution) and reconcile_decision_v2.go (decision and step plan).
//
// Per start: decide (ReconcileV2Spec); for a verdict that changes Docker, count the
// attempt durably first (write-ahead); then the plan's steps, each Docker change preceded
// by a recheck that must still decide the step's expected verdict on the current Docker
// facts; the gate after `up`; the verify by id; the audit (written only if none exists:
// exactly once across crashes); the retirement. Any step can be killed (`rc_crash`): the
// next start decides again from the durable journal and Docker. Docker changes only
// through this agent's own steps here; an operator changing Docker between the reads is
// covered by the Go tests, not by this model.
//
// Abstraction: P and T only. The record's prior reference resolves locally to the prior
// image iff the record names one (prior = valid); the target reference to the target iff
// the record names one. The health gate and the readiness probe answer as the model's
// TH/PH say for the running image.

import "strings"

// Converge stages (State.PC), in execution order, and the end of a converge start.
const (
	pcRcDecide   = "rc_decide"
	pcRcTag      = "rc_tag"
	pcRcUp       = "rc_up"
	pcRcGate     = "rc_gate"
	pcRcProbe    = "rc_probe" // after an armed realign: a fresh read and probe, changes nothing
	pcRcVerify   = "rc_verify"
	pcRcServe    = "rc_serve" // retireIfServing: a fresh readiness probe before EVERY retirement
	pcRcAudit    = "rc_audit"
	pcRcRemove   = "rc_remove"
	pcReconciled = "reconciled"
)

// Converge events.
const (
	evRestartConverge   = "restart_converge"
	evRcDecide          = "rc_decide"
	evRcTagOK           = "rc_tag_ok"
	evRcTagFail         = "rc_tag_fail"
	evRcRecheckFail     = "rc_recheck_fail"
	evRcUpOK            = "rc_up_ok"
	evRcUpStale         = "rc_up_stale" // exit 0 without recreating the proxy
	evRcUpFail          = "rc_up_fail"  // exit != 0, proxy untouched
	evRcUpFailRecreated = "rc_up_fail_recreated"
	evRcGate            = "rc_gate"
	evRcProbe           = "rc_probe"
	evRcVerify          = "rc_verify"
	evRcServe           = "rc_serve"
	evRcAudit           = "rc_audit"
	evRcRemove          = "rc_remove"
	evRcCrash           = "rc_crash"
)

// Converge outcomes (State.RcOut) and the persisted attempt cap.
const (
	rcConverged = "converged"
	rcRR        = "recovery_required"
	rcMaxTries  = 2 // startup_reconcile.go maxReconcileAttempts
)

// V2 actions, as reconcileActionV2.String() names them.
const (
	v2Noop         = "noop"
	v2Realign      = "realign"
	v2Finish       = "finish_rollback"
	v2FinishRetag  = "finish_rollback_retag"
	v2Adopt        = "adopt"
	v2RR           = "recovery_required"
	v2FinishVerdct = v2Finish + "/rollback_interrupted"     // the recheck in front of every `up`
	v2ArmedReady   = v2Noop + "/armed_rollback_prior_ready" // what the probe after an armed realign must decide
)

func isConvergePC(pc string) bool {
	switch pc {
	case pcRcDecide, pcRcTag, pcRcUp, pcRcGate, pcRcProbe, pcRcVerify, pcRcServe, pcRcAudit, pcRcRemove:
		return true
	}
	return false
}

// Probe values of ReconcileV2Inputs.Probe.
const (
	probeNotRun   = ""
	probeReady    = "ready"
	probeNotReady = "not_ready"
)

// ReconcileV2Inputs is the V2 decision's input in model symbols ("P", "T", "X", ""). Kind
// is always an upgrade (the model has no standalone or data rollback) and Docker is always
// readable (the model has no daemon outage).
type ReconcileV2Inputs struct {
	Phase            string
	Attempts         int
	RefValid         bool
	TargetRefPresent bool
	PriorRefPresent  bool
	TargetID         string // record TargetImageID
	PriorID          string // record PriorImageID
	Armed            bool
	RunningID        string // "" = no proxy container
	TagID            string
	TargetLocal      string // what the record's TargetRef resolves to locally
	PriorLocal       string // what the record's PriorRef resolves to locally
	Probe            string
}

// ReconcileV2InputsForState is what the real startup reconcile reads for s: the record the
// model expects at s, plus Docker truth. The probe is not run (the caller decides).
func ReconcileV2InputsForState(s State, attempts int) ReconcileV2Inputs {
	r := RecordForState(s)
	in := ReconcileV2Inputs{Phase: s.JR, Attempts: attempts, RefValid: r.PriorRef || r.TargetRef,
		TargetRefPresent: r.TargetRef, PriorRefPresent: r.PriorRef, TargetID: r.TargetID, PriorID: r.PriorID,
		Armed: r.Armed, TagID: s.Tag}
	if s.Running != imgNone {
		in.RunningID = s.Running
	}
	if r.TargetRef {
		in.TargetLocal = imgT
	}
	if r.PriorRef {
		in.PriorLocal = imgP
	}
	return in
}

// ReconcileV2Spec is the model's statement of the V2 decision (reconcileDecisionV2)
// for an upgrade record with Docker readable. It returns (action, reason).
func ReconcileV2Spec(i ReconcileV2Inputs) (action, reason string) {
	if i.Attempts >= rcMaxTries {
		return v2RR, "reconcile_exhausted"
	}
	if isSafePhase(i.Phase) {
		return v2SafePhase(i)
	}
	if !i.RefValid {
		return v2RR, "invalid_record_ref"
	}
	if i.RunningID == "" {
		return v2RR, "stack_down"
	}
	p, t := i.PriorID, ""
	if i.TargetRefPresent {
		t = i.TargetLocal
	}
	if p != "" && i.RunningID == p && i.TagID == p {
		if i.Armed {
			return v2ArmedOnPrior(i.Probe)
		}
		return v2Noop, "already_on_prior"
	}
	switch t {
	case "":
		return v2RR, "target_not_identifiable"
	case p:
		return v2RR, "target_equals_prior_ambiguous"
	}
	return v2ByIdentity(i, p, t)
}

func v2SafePhase(i ReconcileV2Inputs) (action, reason string) {
	t := ""
	if i.RefValid && i.TargetRefPresent {
		t = i.TargetLocal
	}
	switch {
	case t != "" && t != i.PriorID && (i.TagID == t || i.RunningID == t):
		return v2RR, "journal_contradicts_docker"
	case i.RunningID == "":
		return v2RR, "stack_down_unverifiable"
	case i.TagID != i.RunningID:
		return v2RR, "tag_differs_from_running"
	case i.PriorID != "" && i.RunningID != i.PriorID:
		return v2RR, "running_not_prior"
	}
	return v2Noop, "safe_boundary_unchanged"
}

func v2ArmedOnPrior(probe string) (action, reason string) {
	switch probe {
	case probeReady:
		return v2Noop, "armed_rollback_prior_ready"
	case probeNotReady:
		return v2RR, "armed_rollback_prior_not_ready"
	}
	return v2RR, "readiness_not_probed"
}

func v2PriorRestorable(i ReconcileV2Inputs, p string) bool {
	return i.PriorRefPresent && p != "" && i.PriorLocal == p
}

// v2FinishArmed: an armed rollback (the caller checked the marker) is finished only
// before phase verified and with the prior image restorable.
func v2FinishArmed(i ReconcileV2Inputs, p, act, why string) (action, reason string) {
	switch {
	case i.Phase == "verified":
		return v2RR, "rollback_armed_at_verified"
	case !v2PriorRestorable(i, p):
		return v2RR, "prior_not_restorable"
	}
	return act, why
}

// v2RealignTag: retag only. An armed record's realign is retired only after a fresh
// probe (rc_probe), so it is a verdict of its own.
func v2RealignTag(i ReconcileV2Inputs, p string) (action, reason string) {
	switch {
	case !v2PriorRestorable(i, p):
		return v2RR, "prior_not_restorable"
	case i.Armed:
		return v2Realign, "armed_tag_ahead_container_on_prior"
	}
	return v2Realign, "tag_ahead_container_on_prior"
}

func v2ByIdentity(i ReconcileV2Inputs, p, t string) (action, reason string) {
	run, tag := i.RunningID, i.TagID
	switch {
	case p != "" && run == p && tag == t: // tag ahead, container on the prior
		return v2RealignTag(i, p)
	case run == t && tag == t: // T/T
		if i.Armed {
			return v2FinishArmed(i, p, v2FinishRetag, "rollback_armed_tag_not_moved")
		}
		return v2Adoption(i, t)
	case p != "" && run == t && tag == p: // T/P
		if !i.Armed {
			return v2RR, "tag_on_prior_rollback_unproven"
		}
		return v2FinishArmed(i, p, v2Finish, "rollback_interrupted")
	}
	return v2RR, "docker_state_unrecognised"
}

// v2Adoption: the running image's digests carry the target digest iff it runs T.
func v2Adoption(i ReconcileV2Inputs, t string) (action, reason string) {
	switch {
	case i.Phase != "verified":
		return v2RR, "target_live_ungated"
	case i.TargetID != t:
		return v2RR, "verified_target_id_mismatch"
	case i.Probe == probeReady:
		return v2Adopt, "verified_target_live"
	case i.Probe == probeNotReady:
		return v2RR, "verified_target_not_ready"
	}
	return v2RR, "readiness_not_probed"
}

// reconcileV2ForState decides for s as the real reconcile does: the probe is run only
// when it can change the verdict, and then answers as the running image's health says.
func reconcileV2ForState(s State, attempts int) (action, reason string) {
	in := ReconcileV2InputsForState(s, attempts)
	a0, r0 := ReconcileV2Spec(in)
	in.Probe = probeReady
	if a1, r1 := ReconcileV2Spec(in); a1 == a0 && r1 == r0 {
		return a0, r0
	}
	in.Probe = probeNotReady
	if healthy(s, s.Running) {
		in.Probe = probeReady
	}
	return ReconcileV2Spec(in)
}

func verdictOf(action, reason string) string { return action + "/" + reason }

func actionOf(verdict string) string {
	a, _, _ := strings.Cut(verdict, "/")
	return a
}

// rcRecheckOK is the fresh read before a Docker change: the decision on the current facts,
// with the attempt count the start decided on (the write-ahead already counted this one),
// must be exactly the step's expected verdict.
func rcRecheckOK(s State, expect string) bool {
	return verdictOf(reconcileV2ForState(s, s.Attempts-1)) == expect
}

// rcExpect is the verdict the recheck in front of the step at s must still decide
// (reconcilePlan): the executed verdict, except that the `up` of a T/T finish is guarded
// by the T/P finish its own retag leads to.
func rcExpect(s State) string {
	if s.PC == pcRcUp && actionOf(s.RcAct) == v2FinishRetag {
		return v2FinishVerdct
	}
	return s.RcAct
}

func convergeEvents(s State) []string {
	switch s.PC {
	case pcReconciled:
		if s.JR == "removed" {
			return nil
		}
		return []string{evRestartConverge}
	case pcRcDecide:
		return []string{evRcDecide, evRcCrash}
	case pcRcTag:
		if !rcRecheckOK(s, rcExpect(s)) {
			return []string{evRcRecheckFail, evRcCrash}
		}
		return []string{evRcTagOK, evRcTagFail, evRcCrash}
	case pcRcUp:
		if !rcRecheckOK(s, rcExpect(s)) {
			return []string{evRcRecheckFail, evRcCrash}
		}
		return []string{evRcUpOK, evRcUpStale, evRcUpFail, evRcUpFailRecreated, evRcCrash}
	case pcRcGate:
		return []string{evRcGate, evRcCrash}
	case pcRcProbe:
		return []string{evRcProbe, evRcCrash}
	case pcRcVerify:
		return []string{evRcVerify, evRcCrash}
	case pcRcServe:
		return []string{evRcServe, evRcCrash}
	case pcRcAudit:
		return []string{evRcAudit, evRcCrash}
	}
	return []string{evRcRemove, evRcCrash} // pcRcRemove
}

// rcEnd ends this start's reconcile with outcome out. A kept record stays as it is.
func rcEnd(s State, out string) State {
	s.PC, s.RcOut = pcReconciled, out
	return s
}

func stepConverge(s State, e string) State {
	switch e {
	case evRestartConverge: // main.go initJournal marks the op interrupted; then the reconcile
		s.PC, s.Op, s.RcAct, s.RcOut = pcRcDecide, "interrupted", "", ""
		return s
	case evRcCrash: // the agent dies: only the journal, the audit log and Docker survive
		s.PC, s.RcAct, s.RcOut = pcCrashed, "", ""
		return s
	case evRcRecheckFail, evRcTagFail, evRcUpFail:
		return rcEnd(s, rcRR)
	}
	switch s.PC {
	case pcRcDecide:
		return rcDecide(s)
	case pcRcTag:
		return rcTag(s)
	case pcRcUp:
		return rcUp(s, e)
	}
	return rcCheckAndRetire(s)
}

// rcTag is `docker tag <the record's PriorRef> culvert/proxy:pinned`, the only tag step.
func rcTag(s State) State {
	s.Tag = imgP
	switch {
	case actionOf(s.RcAct) == v2FinishRetag:
		s.PC = pcRcUp
	case s.RcAct == verdictOf(v2Realign, "armed_tag_ahead_container_on_prior"):
		s.PC = pcRcProbe
	default:
		s.PC = pcRcVerify
	}
	return s
}

// rcUp is `compose up -d`: the container runs what the tag names, unless `up` did not
// recreate it (stale) or failed before it (fail, handled by the caller).
func rcUp(s State, e string) State {
	if e == evRcUpOK || e == evRcUpFailRecreated {
		s.Running = s.Tag
	}
	if e == evRcUpFailRecreated {
		return rcEnd(s, rcRR)
	}
	s.PC = pcRcGate
	return s
}

// rcCheckAndRetire: the gate, the verify, the audit and the retirement.
func rcCheckAndRetire(s State) State {
	switch s.PC {
	case pcRcGate:
		if !healthy(s, s.Running) {
			return rcEnd(s, rcRR) // no second `up`
		}
		s.PC = pcRcVerify
		return s
	case pcRcProbe: // the decision on fresh facts and a fresh probe: the armed-on-prior retirement
		if verdictOf(reconcileV2ForState(s, s.Attempts-1)) != v2ArmedReady {
			return rcEnd(s, rcRR) // armed_rollback_prior_not_ready; nothing more changes
		}
		s.PC = pcRcVerify
		return s
	case pcRcVerify: // container, tag and the PriorRef all on the recorded prior image
		if s.Running != imgP || s.Tag != imgP || !RecordForState(s).PriorRef {
			return rcEnd(s, rcRR)
		}
		s.PC = pcRcServe
		return s
	case pcRcServe: // retireIfServing (#2062): a probe taken now must answer ready, on every path
		if !healthy(s, s.Running) {
			return rcEnd(s, rcRR) // not_ready_at_retirement; the record is kept
		}
		s.PC = pcRcAudit
		return s
	case pcRcAudit: // written only if this record has no succeeded entry yet
		if s.Audits == 0 {
			s.Audits = 1
		}
		s.PC = pcRcRemove
		return s
	}
	// pcRcRemove: the record is retired. Armed is kept as the retired record's last
	// content, so a property can ask what kind of record a retirement ended.
	s.JR = "removed"
	return rcEnd(s, rcConverged)
}

// rcDecide decides, and for a verdict that changes Docker counts the attempt durably
// first (write-ahead) and enters the plan's first step.
func rcDecide(s State) State {
	if s.JR == "removed" {
		return rcEnd(s, "")
	}
	act, why := reconcileV2ForState(s, s.Attempts)
	s.RcAct = verdictOf(act, why)
	switch act {
	case v2Noop, v2Adopt:
		s.PC = pcRcServe
	case v2Realign, v2FinishRetag:
		s.Attempts, s.Acts, s.PC = s.Attempts+1, min(s.Acts+1, rcMaxTries+1), pcRcTag
	case v2Finish:
		s.Attempts, s.Acts, s.PC = s.Attempts+1, min(s.Acts+1, rcMaxTries+1), pcRcUp
	default:
		return rcEnd(s, rcRR)
	}
	return s
}
