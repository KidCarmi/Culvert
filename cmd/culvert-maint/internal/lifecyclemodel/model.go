//go:build lifecycle_conformance

// Package lifecyclemodel is an explicit-state model of the maintenance agent's
// `upgrades.apply` flow, its crash journal, the PR-E reference reconcile table (V1, never
// wired) and the opt-in converge reconcile that IS wired (V2 decision and its execution
// steps across agent kills, converge.go), together with a small model checker and the conformance vectors derived
// from the model. Source of truth for the modelled behaviour:
// cmd/culvert-maint/internal/{server,journal,ops}.
//
// SHADOW / NON-BLOCKING. Every file of this package carries the build tag
// `lifecycle_conformance`, so a plain `go build ./...`, `go vet ./...` or
// `go test ./...` neither compiles nor runs any of it.
//
// Fault outcomes are what the FAKE exec layer can be told to do. `ok_stale` (`compose up`
// exits 0 without recreating the container although the tag moved to a different image)
// was NOT observed on real Docker 29.10 / Compose v5.7.1; it is kept as a robustness
// input, not as a claim about Docker.
//
// Culvert has no boot slots: an upgrade pulls an image, moves one fixed tag
// (culvert/proxy:pinned) and recreates the container.
//
// Abstraction: two images, P (prior) and T (target). Docker world = (running, tag).
// `compose up` makes the container run whatever the tag points at. Each event is the
// outcome of the stage about to run; "crash" kills the agent process.
package lifecyclemodel

import "strings"

// State is one model state. It is comparable, so it can key a map.
//
//	Prior  : valid | nodigest (running image has no registry digest) | down (no container)
//	Same   : target already running        Backup/RB: request flags     TH/PH: is T / P healthy
//	JR     : last durable journal phase, or "removed"      TID: image id stored as TargetImageID
type State struct {
	Prior       string
	Same        bool
	Backup      bool
	RB          bool
	TH          bool
	PH          bool
	PC          string
	Running     string
	Tag         string
	JR          string
	FailStage   string
	Reason      string
	PostFail    bool
	RbAtt       bool
	RbFailed    bool
	RbRestarted bool
	RbOK        bool
	Op          string
	TID         string
	// Ev is the evidence the agent holds about the running image (running_evidence.go):
	// "" nothing captured yet, "fresh" a capture after the last `compose up`, "stale" an `up`
	// ran after the last capture. A capture succeeds iff a container runs.
	Ev string

	// Armed is the journal record's durable rollback_armed marker: written by the inline
	// rollback right before its rollback_restart moves the tag (armRollbackInJournal),
	// dropped with the record. (rollbackArmed(s) is whether a rollback WILL run.)
	Armed bool
	// Converge bookkeeping (converge.go). Attempts and Audits are durable (the journal's
	// reconcile_attempts; succeeded `:reconciled` audit entries for the record); RcAct (the
	// verdict being executed, "action/reason") and RcOut (the start's outcome) live in the
	// agent process. Acts is a ghost counter of the converge starts that acted, saturated
	// at the cap + 1: it equals Attempts unless an attempt is not counted durably.
	Attempts int
	Acts     int
	Audits   int
	RcAct    string
	RcOut    string
}

const (
	evFresh = "fresh"
	evStale = "stale"
)

// captureEv is the evidence after a capture attempt: it succeeds iff a container runs.
func captureEv(s State) string {
	if s.Running != imgNone {
		return evFresh
	}
	return s.Ev
}

// upThenCaptureEv is the evidence after a `compose up` followed by a capture attempt (the
// apply restart stage always re-captures after `up`: the target id on success, the AGT-002
// re-read on failure).
func upThenCaptureEv(s State) string {
	s.Ev = evStale
	return captureEv(s)
}

// Stage names, in execution order.
const (
	pcCapture   = "capture_before"
	pcResolve   = "resolve_target"
	pcBackup    = "pre_backup"
	pcPull      = "pull"
	pcRestart   = "restart"
	pcHealth    = "health_gate"
	pcVerify    = "verify"
	pcRbPull    = "rb_pull"
	pcRbRestart = "rb_restart"
	pcRbHealth  = "rb_health"
	pcRbVerify  = "rb_verify"
	pcReport    = "report"
	pcDone      = "done"
	pcCrashed   = "crashed"
	pcRecovered = "recovered"
)

// Event labels.
const (
	evOK              = "ok"
	evFail            = "fail"
	evSkip            = "skip"
	evOKStale         = "ok_stale"
	evBarrierFail     = "barrier_fail"
	evTagFail         = "tag_fail"
	evUpFailStale     = "up_fail_stale"
	evUpFailRecreated = "up_fail_recreated"
	evCaptureFail     = "capture_fail"
	evMismatch        = "mismatch"
	evCrash           = "crash"
	evCrashAfterBar   = "crash_after_barrier"
	evCrashBeforeTag  = "crash_before_tag"
	evCrashAfterTag   = "crash_after_tag"
	evCrashAfterUp    = "crash_after_up"
	evRestartAgent    = "restart_agent"
)

const (
	imgT    = "T"
	imgP    = "P"
	imgNone = "none"

	priorValid    = "valid"
	priorNoDigest = "nodigest"
	priorDown     = "down"

	jrRestarting = "restarting"
)

var stages = []string{pcCapture, pcResolve, pcBackup, pcPull, pcRestart, pcHealth, pcVerify,
	pcRbPull, pcRbRestart, pcRbHealth, pcRbVerify, pcReport}

var failReason = map[string]string{pcResolve: "command_error", pcBackup: "cli_error", pcPull: "command_error",
	pcRestart: "command_error", pcHealth: "health_failed", pcVerify: "health_failed"}

// stagesSeen ranks a journal phase by how many identifier-bearing stages it implies.
var stagesSeen = map[string]int{"admitted": 0, "captured": 1, "resolved": 2, "pulled": 3, jrRestarting: 3,
	"restarted": 4, "verified": 5, "removed": 9}

func stageIndex(pc string) int {
	for i, s := range stages {
		if s == pc {
			return i
		}
	}
	return -1
}

func healthy(s State, img string) bool {
	switch img {
	case imgT:
		return s.TH
	case imgP:
		return s.PH
	}
	return false
}

func rollbackArmed(s State) bool {
	return s.PostFail && s.RB && s.Prior == priorValid
}

// Model is the apply-flow model. The zero value is ready to use.
type Model struct{}

// Inits returns every initial state, in a fixed order.
func (Model) Inits() []State {
	type ps struct {
		prior string
		same  bool
	}
	var out []State
	for _, p := range []ps{{priorValid, false}, {priorValid, true}, {priorNoDigest, false}, {priorDown, false}} {
		running := imgP
		if p.prior == priorDown {
			running = imgNone
		}
		for _, backup := range []bool{false, true} {
			for _, rb := range []bool{true, false} {
				for _, th := range []bool{true, false} {
					for _, ph := range []bool{true, false} {
						out = append(out, State{Prior: p.prior, Same: p.same, Backup: backup, RB: rb, TH: th, PH: ph,
							PC: pcCapture, Running: running, Tag: imgP, JR: "admitted", Op: "running"})
					}
				}
			}
		}
	}
	return out
}

// Events lists the outcomes the next stage can have, in a fixed order (the order
// decides breadth-first tie-breaking and therefore which shortest trace is reported).
func (m Model) Events(s State) []string {
	switch s.PC {
	case pcCrashed:
		return []string{evRestartAgent, evRestartConverge}
	case pcReconciled:
		return convergeEvents(s)
	case pcDone, pcRecovered:
		return nil
	}
	if isConvergePC(s.PC) {
		return convergeEvents(s)
	}
	ev := m.Outcomes(s)
	if (s.PC == pcRestart || s.PC == pcRbRestart) && !contains(ev, evSkip) {
		first := evCrashBeforeTag
		if s.PC == pcRestart {
			first = evCrashAfterBar
		}
		ev = append(ev, first, evCrashAfterTag, evCrashAfterUp)
	}
	return append(ev, evCrash)
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// Outcomes lists the non-crash outcomes of the stage about to run.
func (Model) Outcomes(s State) []string {
	pc := s.PC
	if pc == pcCapture || pc == pcReport {
		return []string{evOK}
	}
	if i := stageIndex(pc); i >= 1 && i < 7 {
		return forwardOutcomes(s)
	}
	if !rollbackArmed(s) || s.RbFailed {
		return []string{evSkip}
	}
	switch pc {
	case pcRbPull:
		return []string{evOK, evFail}
	case pcRbRestart:
		return []string{evOK, evOKStale, evTagFail, evUpFailStale, evUpFailRecreated}
	case pcRbHealth:
		return healthOutcomes(s)
	}
	return verifyOutcomes(s, imgP)
}

func forwardOutcomes(s State) []string {
	pc := s.PC
	if s.Same && (pc == pcPull || pc == pcRestart || pc == pcHealth || pc == pcVerify) {
		return []string{evSkip}
	}
	switch pc {
	case pcResolve, pcPull:
		return []string{evOK, evFail}
	case pcBackup:
		if s.Backup && !s.Same {
			return []string{evOK, evFail}
		}
		return []string{evSkip}
	case pcRestart:
		return []string{evOK, evOKStale, evBarrierFail, evTagFail, evUpFailStale, evUpFailRecreated}
	case pcHealth:
		return healthOutcomes(s)
	}
	return verifyOutcomes(s, imgT)
}

func healthOutcomes(s State) []string {
	if healthy(s, s.Running) {
		return []string{evOK}
	}
	return []string{evFail}
}

func verifyOutcomes(s State, want string) []string {
	if s.Running == want {
		return []string{evOK, evCaptureFail}
	}
	return []string{evMismatch}
}

// Step applies event e to state s.
func (Model) Step(s State, e string) State {
	pc := s.PC
	if e == evRestartAgent { // main.go initJournal: mark interrupted, nothing else
		s.PC, s.Op = pcRecovered, "interrupted"
		return s
	}
	if e == evRestartConverge || isConvergePC(pc) {
		return stepConverge(s, e)
	}
	if strings.HasPrefix(e, evCrash) {
		return stepCrash(s, e)
	}
	if pc == pcReport {
		return stepReport(s)
	}
	nxt := stages[stageIndex(pc)+1]
	if pc == pcCapture {
		s.PC, s.JR = nxt, "captured"
		s.Ev = captureEv(s)
		return s
	}
	if stageIndex(pc) < 7 {
		return stepForward(s, e, nxt)
	}
	return stepRollback(s, e, nxt)
}

func stepCrash(s State, e string) State {
	forward := s.PC == pcRestart
	img := imgP
	if forward {
		img = imgT
	}
	if s.PC == pcRbRestart && e != evCrash {
		// Killed inside rollback_restart: the armed marker is written before its tag move.
		s.Armed = true
	}
	switch e {
	case evCrashAfterBar:
		s.JR = jrRestarting
	case evCrashAfterTag:
		s.Tag = img
		if forward {
			s.JR = jrRestarting
		}
	case evCrashAfterUp:
		s.Tag, s.Running = img, img
		if forward {
			s.JR = jrRestarting
		}
	}
	s.PC = pcCrashed
	return s
}

func stepReport(s State) State {
	failed := s.FailStage != ""
	s.PC = pcDone
	// ADR-0062 slice 1 (server/terminal_record.go): the record is removed at
	// terminal when the op succeeded, failed before the write-ahead barrier, or
	// its inline rollback passed its gate and verify. Otherwise it is KEPT at
	// the phase the op last wrote, rollback_armed included (stampTerminal
	// changes only the terminal fields), for an operator, a later success or
	// the converge reconcile's armed finish.
	if !failed || s.RbOK || !dangerJR(s.JR) {
		s.JR, s.Armed = "removed", false
	}
	if s.Ev != evFresh { // option C: one read-only final capture when evidence is stale or missing
		s.Ev = captureEv(s)
	}
	switch {
	case !failed:
		s.Op, s.Reason = "succeeded", ""
	case s.RbFailed:
		s.Op, s.Reason = "failed", "rollback_failed"
	default:
		s.Op = "failed"
	}
	return s
}

// bad is the forward-stage failure transition: jump to the inline rollback.
func bad(s State) State {
	s.FailStage, s.Reason = s.PC, failReason[s.PC]
	s.PC = pcRbPull
	return s
}

func stepForward(s State, e, nxt string) State {
	if e == evSkip {
		s.PC = nxt
		return s
	}
	switch s.PC {
	case pcResolve:
		return okOrBad(s, e, nxt, "resolved")
	case pcBackup:
		return okOrBad(s, e, nxt, "")
	case pcPull:
		return okOrBad(s, e, nxt, "pulled")
	case pcRestart:
		return stepRestart(s, e, nxt)
	case pcHealth:
		if e == evOK {
			s.PC = nxt
			return s
		}
		s = bad(s)
		s.PostFail = true
		return s
	}
	// verify
	if e != evCaptureFail {
		s.Ev = captureEv(s)
	}
	if e == evOK {
		s.PC, s.JR, s.TID = pcRbPull, "verified", imgT
		return s
	}
	s = bad(s)
	s.PostFail = true
	return s
}

func okOrBad(s State, e, nxt, jr string) State {
	if e != evOK {
		return bad(s)
	}
	s.PC = nxt
	if jr != "" {
		s.JR = jr
	}
	return s
}

func stepRestart(s State, e, nxt string) State {
	switch e {
	case evBarrierFail:
		return bad(s)
	case evTagFail:
		s = bad(s)
		s.JR = jrRestarting
		return s
	case evUpFailStale:
		// AGT-002 (realignPinnedTagAfterFailedUp): the container provably still runs the
		// prior image, so the tag is moved back -- but only when the prior image has an
		// allow-listed registry ref to name it by. Stack down or no such ref: tag stays.
		tag := imgT
		if s.Prior == priorValid {
			tag = imgP
		}
		s = bad(s)
		s.JR, s.Tag, s.PostFail = jrRestarting, tag, true
		s.Ev = upThenCaptureEv(s)
		return s
	case evUpFailRecreated:
		s = bad(s)
		s.JR, s.Tag, s.Running, s.PostFail = jrRestarting, imgT, imgT, true
		s.Ev = upThenCaptureEv(s)
		return s
	}
	run := s.Running
	if e == evOK {
		run = imgT
	}
	// F1 (journal_phases.go restartWithBarrier): the post-`up` capture is recorded as
	// the target's id only when its RepoDigests carry the pinned digest, i.e. only when
	// the container really runs T. `ok_stale` (still P) and a down stack record nothing.
	tid := ""
	if run == imgT {
		tid = imgT
	}
	s.PC, s.Tag, s.Running, s.JR, s.TID = nxt, imgT, run, "restarted", tid
	s.Ev = upThenCaptureEv(s)
	return s
}

// stepRollback handles the inline rollback stages (ContinueOnError).
func stepRollback(s State, e, nxt string) State {
	pc := s.PC
	s.PC = nxt
	if e == evSkip {
		return s
	}
	s.RbAtt = true
	if pc == pcRbRestart {
		return stepRbRestart(s, e)
	}
	if pc == pcRbVerify && e != evCaptureFail { // rollback_verify captured (ok or mismatch)
		s.Ev = captureEv(s)
	}
	if e != evOK {
		s.RbFailed = true
		return s
	}
	if pc == pcRbVerify {
		s.RbOK = true
	}
	return s
}

func stepRbRestart(s State, e string) State {
	s.Armed = true      // armRollbackInJournal, before the tag move, whatever the stage's outcome
	if e != evTagFail { // the rollback's `up` ran: earlier evidence is stale (no capture follows)
		s.Ev = evStale
	}
	switch e {
	case evTagFail:
		s.RbFailed = true
	case evUpFailStale:
		s.RbFailed, s.Tag = true, imgP
	case evUpFailRecreated:
		s.RbFailed, s.Tag, s.Running = true, imgP, imgP
	default:
		s.Tag, s.RbRestarted = imgP, true
		if e == evOK {
			s.Running = imgP
		}
	}
	return s
}

// dangerJR reports whether a journal phase is at or past the write-ahead barrier.
func dangerJR(jr string) bool {
	return jr == jrRestarting || jr == "restarted" || jr == "verified"
}

// ObservedFields lists every field Observe produces. Properties may reference only these.
var ObservedFields = []string{"prior", "same", "backup", "rb", "th", "ph", "pc", "running", "tag", "jr",
	"fail_stage", "reason", "post_fail", "rb_att", "rb_failed", "rb_restarted", "rb_ok", "op", "tid",
	"terminal", "danger_phase", "rollback_armed", "tag_ahead", "serving_healthy", "jr_rank", "rb_resolved",
	"stopped", "reconcile",
	"journal_armed", "converge", "attempts", "acts", "audits", "rc_action", "rc_out", "reconcile_v2"}

// Observe projects a state onto the named fields the properties are written against.
// Values are string, bool or float64.
func (Model) Observe(s State) map[string]any {
	rank := float64(stagesSeen[s.JR])
	if s.JR == jrRestarting {
		rank += 0.5
	}
	rec, rec2 := "n/a", "n/a"
	if s.PC == pcCrashed || s.PC == pcRecovered {
		rec, _ = ReconcileSpec(ReconcileInputsForState(s))
	}
	if s.PC == pcCrashed {
		rec2, _ = reconcileV2ForState(s, s.Attempts)
	}
	return map[string]any{
		"journal_armed": s.Armed, "converge": isConvergePC(s.PC), "attempts": float64(s.Attempts),
		"acts": float64(s.Acts), "audits": float64(s.Audits), "rc_action": actionOf(s.RcAct), "rc_out": s.RcOut,
		"reconcile_v2": rec2,
		"prior":        s.Prior, "same": s.Same, "backup": s.Backup, "rb": s.RB, "th": s.TH, "ph": s.PH,
		"pc": s.PC, "running": s.Running, "tag": s.Tag, "jr": s.JR, "fail_stage": s.FailStage,
		"reason": s.Reason, "post_fail": s.PostFail, "rb_att": s.RbAtt, "rb_failed": s.RbFailed,
		"rb_restarted": s.RbRestarted, "rb_ok": s.RbOK, "op": s.Op, "tid": s.TID,
		"terminal":        s.PC == pcDone,
		"danger_phase":    dangerJR(s.JR),
		"rollback_armed":  rollbackArmed(s),
		"tag_ahead":       tagAhead(s),
		"serving_healthy": healthy(s, s.Running),
		"jr_rank":         rank,
		"rb_resolved":     s.RbOK || s.RbFailed || s.PC == pcCrashed,
		"stopped":         s.PC == pcDone || s.PC == pcCrashed || s.PC == pcRecovered || s.PC == pcReconciled,
		"reconcile":       rec,
	}
}

func tagAhead(s State) bool {
	return s.Tag == imgT && s.Running != imgT && !s.Same
}
