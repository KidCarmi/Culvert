//go:build lifecycle_conformance

package lifecyclemodel

import (
	"encoding/json"
	"strings"
)

// Conformance vectors are derived deterministically from the model (no randomness):
//
//	ApplyVectors      every fault path of the apply flow to a terminal state, with the expected outcome
//	CrashVectors      every executable crash point, with the expected journal record and reconcile verdict
//	ReconcileVectors  the full bounded input space of the reconcile decision, with the expected verdict

// Params are the request and world parameters of one run.
type Params struct {
	Prior  string `json:"prior"`
	Same   bool   `json:"same"`
	Backup bool   `json:"backup"`
	RB     bool   `json:"rb"`
	TH     bool   `json:"th"`
	PH     bool   `json:"ph"`
}

// ScriptStep is one [stage, outcome] pair.
type ScriptStep [2]string

// PlanEntry tells the fake exec layer to inject Mode into the N-th occurrence of Cmd.
type PlanEntry struct {
	Cmd  string `json:"cmd"`
	N    int    `json:"n"`
	Mode string `json:"mode"`
}

// BlockPoint is where a real run can be frozen to emulate a crash.
type BlockPoint struct {
	Cmd      string `json:"cmd"`
	N        int    `json:"n"`
	AfterTag bool   `json:"after_tag,omitempty"`
	AfterUp  bool   `json:"after_up,omitempty"`
}

// ApplyExpectation is the model's outcome of a run to a terminal state.
type ApplyExpectation struct {
	Op                    string   `json:"op"`
	Reason                string   `json:"reason"`
	Running               string   `json:"running"`
	Tag                   string   `json:"tag"`
	JournalEmpty          bool     `json:"journal_empty"`
	Cmds                  []string `json:"cmds"`
	UpgradeSucceeded      bool     `json:"upgrade_succeeded"`
	RollbackAttempted     bool     `json:"rollback_attempted"`
	RollbackSucceeded     bool     `json:"rollback_succeeded"`
	RollbackSkippedReason string   `json:"rollback_skipped_reason"`
	TagAhead              bool     `json:"tag_ahead"`
	// The reported final running image (owner decision 2): verified only by a capture after
	// the last `compose up`. FinalDigest is the registry digest ("none" when the image has no
	// allow-listed registry reference or the state is unverified); FinalImage the image id.
	FinalState  string `json:"final_state"`
	FinalDigest string `json:"final_digest"`
	FinalImage  string `json:"final_image"`
}

// finalRunningExpect is the model's prediction of the result's final running image.
func finalRunningExpect(t State) (state, digest, image string) {
	if t.Ev != evFresh {
		return "unverified", imgNone, imgNone
	}
	digest = t.Running
	if t.Running == imgP && t.Prior == priorNoDigest { // only a local reference: no registry digest
		digest = imgNone
	}
	return "verified", digest, t.Running
}

// ApplyVector is one fault path of the apply flow.
type ApplyVector struct {
	Params Params           `json:"params"`
	Script []ScriptStep     `json:"script"`
	Plan   []PlanEntry      `json:"plan"`
	Expect ApplyExpectation `json:"expect"`
}

// CrashExpectation is the model's view of the world at a crash point.
type CrashExpectation struct {
	Phase           string   `json:"phase"`
	Tag             string   `json:"tag"`
	Running         string   `json:"running"`
	Record          Record   `json:"record"`
	ReconcileAction string   `json:"reconcile_action"`
	ReconcileReason string   `json:"reconcile_reason"`
	CmdsBeforeBlock []string `json:"cmds_before_block"`
}

// CrashVector is one executable crash point.
type CrashVector struct {
	Params Params           `json:"params"`
	Script []ScriptStep     `json:"script"`
	Plan   []PlanEntry      `json:"plan"`
	Block  BlockPoint       `json:"block"`
	Expect CrashExpectation `json:"expect"`
}

// counts is the number of times each fake-exec command key has been issued so far.
type counts map[string]int

func (n counts) clone() counts {
	c := make(counts, len(n))
	for k, v := range n {
		c[k] = v
	}
	return c
}

// issued accumulates the Docker commands a stage issues plus fault-plan entries.
type issued struct {
	n    counts
	cmds []string
	plan []PlanEntry
}

func (is *issued) do(tok, mode string) {
	key, _, _ := strings.Cut(tok, ":")
	if key == "capture" {
		key = "ps"
	}
	is.n[key]++
	is.cmds = append(is.cmds, tok)
	if mode != "" {
		is.plan = append(is.plan, PlanEntry{Cmd: key, N: is.n[key], Mode: mode})
	}
}

// failIf is the fault mode of a command that either works or fails.
func failIf(cond bool) string {
	if cond {
		return "fail"
	}
	return ""
}

// commands returns the Docker commands the stage at s issues for outcome e, plus
// fault-plan entries. n counts occurrences and is updated in place.
func commands(s State, e string, n counts) (cmds []string, plan []PlanEntry) {
	is := &issued{n: n}
	if e == evSkip {
		return nil, nil
	}
	switch s.PC {
	case pcCapture:
		is.do("capture", "")
	case pcResolve:
		is.do("manifest", failIf(e == evFail))
	case pcBackup:
		is.do("backup", failIf(e == evFail))
	case pcPull:
		is.do("pull:T", failIf(e == evFail))
	case pcRbPull:
		is.do("pull:P", failIf(e == evFail))
	case pcRestart, pcRbRestart:
		is.restart(s, e)
	case pcVerify, pcRbVerify:
		is.do("capture", failIf(e == evCaptureFail))
	case pcReport:
		if s.Ev != evFresh { // option C: the bounded read-only final capture
			is.do("capture", "")
		}
	}
	return is.cmds, is.plan
}

var upModes = map[string]string{evUpFailStale: "fail_stale", evUpFailRecreated: "fail_recreated", evOKStale: "ok_stale"}

func (is *issued) restart(s State, e string) {
	img := imgP
	if s.PC == pcRestart {
		img = imgT
	}
	switch e {
	case evBarrierFail:
		is.plan = append(is.plan, PlanEntry{Cmd: "pull", N: is.n["pull"], Mode: "corrupt_journal"})
		return
	case evTagFail:
		is.do("tag:"+img, "fail")
		return
	}
	is.do("tag:"+img, "")
	is.do("up", upModes[e])
	if s.PC == pcRestart {
		is.do("capture", "") // success: journal the target id; failure: AGT-002 re-read
		if e == evUpFailStale && s.Prior == priorValid {
			is.do("tag:P", "") // AGT-002: container never moved, tag goes back
		}
	}
}

// collapse merges consecutive captures and always returns a non-nil slice.
func collapse(cmds []string) []string {
	out := make([]string, 0, len(cmds))
	for _, c := range cmds {
		if c == "capture" && len(out) > 0 && out[len(out)-1] == "capture" {
			continue
		}
		out = append(out, c)
	}
	return out
}

func skippedReason(s State) string {
	switch {
	case s.RbAtt || s.Op == "succeeded":
		return ""
	case s.PostFail && !s.RB:
		return "disabled"
	case s.PostFail:
		return "no_prior_digest"
	}
	return "pre_restart_failure"
}

var blockCmd = map[string]string{pcCapture: "ps", pcResolve: "manifest", pcBackup: "backup", pcPull: "pull",
	pcVerify: "ps", pcRbPull: "pull", pcRbVerify: "ps"}

// blockPoint says where a real run can be frozen to emulate crash e at s; ok is false
// when the crash is not executable.
func blockPoint(s State, e string, n counts) (bp BlockPoint, ok bool) {
	switch e {
	case evCrashAfterBar, evCrashBeforeTag:
		return BlockPoint{Cmd: "tag", N: n["tag"] + 1}, true
	case evCrashAfterTag:
		return BlockPoint{Cmd: "up", N: n["up"] + 1, AfterTag: true}, true
	case evCrashAfterUp:
		if s.PC == pcRestart {
			return BlockPoint{Cmd: "ps", N: n["ps"] + 1, AfterUp: true}, true
		}
		return BlockPoint{Cmd: "health", N: n["up"] + 1, AfterUp: true}, true
	}
	switch s.PC {
	case pcRestart, pcRbRestart, pcReport:
		return BlockPoint{}, false
	}
	if (Model{}).Outcomes(s)[0] == evSkip {
		return BlockPoint{}, false
	}
	if s.PC == pcHealth || s.PC == pcRbHealth {
		return BlockPoint{Cmd: "health", N: n["up"]}, true
	}
	cmd := blockCmd[s.PC]
	return BlockPoint{Cmd: cmd, N: n[cmd] + 1}, true
}

func paramsOf(s State) Params {
	return Params{Prior: s.Prior, Same: s.Same, Backup: s.Backup, RB: s.RB, TH: s.TH, PH: s.PH}
}

// extend returns a fresh slice (never aliasing a), non-nil even when empty.
func extend[T any](a []T, more ...T) []T {
	out := make([]T, 0, len(a)+len(more))
	return append(append(out, a...), more...)
}

// walker enumerates every path of the model depth-first, in event order, and keeps the
// first vector seen for each distinct observable behaviour.
type walker struct {
	apply     []ApplyVector
	crash     []CrashVector
	seenApply map[string]bool
	seenCrash map[string]bool
	// inputs records every distinct concrete apply input (parameters + fault plan) the walk
	// reached, so a test can prove deduplication dropped only exact duplicates.
	inputs map[string]bool
}

func dedupKey(parts ...any) string {
	b, err := json.Marshal(parts)
	if err != nil {
		panic(err) // plain data: cannot fail
	}
	return string(b)
}

func (w *walker) rec(s State, script []ScriptStep, cmds []string, plan []PlanEntry, n counts) {
	m := Model{}
	for _, e := range m.Events(s) {
		step := extend(script, ScriptStep{s.PC, e})
		if strings.HasPrefix(e, evCrash) {
			w.crashPoint(s, e, step, cmds, plan, n)
			continue
		}
		n2 := n.clone()
		c, p := commands(s, e, n2)
		t := m.Step(s, e)
		if t.PC != pcDone {
			w.rec(t, step, extend(cmds, c...), extend(plan, p...), n2)
			continue
		}
		fState, fDigest, fImage := finalRunningExpect(t)
		v := ApplyVector{Params: paramsOf(s), Script: step, Plan: extend(plan, p...),
			Expect: ApplyExpectation{FinalState: fState, FinalDigest: fDigest, FinalImage: fImage,
				Op: t.Op, Reason: t.Reason, Running: t.Running, Tag: t.Tag, JournalEmpty: true,
				Cmds: collapse(extend(cmds, c...)), UpgradeSucceeded: t.Op == "succeeded", RollbackAttempted: t.RbAtt,
				RollbackSucceeded: t.RbOK, RollbackSkippedReason: skippedReason(t), TagAhead: tagAhead(t)}}
		// Deduplicate only IDENTICAL concrete inputs (every parameter + the fault plan). Keying on
		// prior/same alone merged runs whose other parameters (th/ph/backup/rb) drive different
		// code paths in the agent -- e.g. "health gate fails, rollback verify capture fails" with
		// "verify capture fails, rollback health fails" -- whenever plan and expectation matched,
		// silently dropping a distinct real-code path from conformance.
		w.inputs[dedupKey(v.Params, v.Plan)] = true
		if key := dedupKey(v.Params, v.Plan, v.Expect); !w.seenApply[key] {
			w.seenApply[key] = true
			w.apply = append(w.apply, v)
		}
	}
}

func (w *walker) crashPoint(s State, e string, script []ScriptStep, cmds []string, plan []PlanEntry, n counts) {
	bp, ok := blockPoint(s, e, n)
	if !ok {
		return
	}
	var extra []string
	if e == evCrashAfterTag || e == evCrashAfterUp { // the stage got as far as tag / up
		img := imgP
		if s.PC == pcRestart {
			img = imgT
		}
		extra = append(extra, "tag:"+img)
		if e == evCrashAfterUp {
			extra = append(extra, "up")
		}
	}
	t := (Model{}).Step(s, e)
	act, why := ReconcileSpec(ReconcileInputsForState(t))
	v := CrashVector{Params: paramsOf(s), Script: script, Plan: extend(plan), Block: bp,
		Expect: CrashExpectation{Phase: t.JR, Tag: t.Tag, Running: t.Running, Record: RecordForState(t),
			ReconcileAction: act, ReconcileReason: why, CmdsBeforeBlock: collapse(extend(cmds, extra...))}}
	if key := dedupKey(v.Params, v.Script, v.Plan, v.Block, v.Expect); !w.seenCrash[key] {
		w.seenCrash[key] = true
		w.crash = append(w.crash, v)
	}
}

// distinctApplyInputs is the number of distinct concrete apply inputs the walk reaches.
func distinctApplyInputs() int {
	w := &walker{seenApply: map[string]bool{}, seenCrash: map[string]bool{}, inputs: map[string]bool{}}
	inits := (Model{}).Inits()
	for i := range inits {
		w.rec(inits[i], nil, nil, nil, counts{})
	}
	return len(w.inputs)
}

// Vectors walks the model and returns the apply-flow and crash-point vectors.
func Vectors() ([]ApplyVector, []CrashVector) {
	w := &walker{seenApply: map[string]bool{}, seenCrash: map[string]bool{}, inputs: map[string]bool{}}
	inits := (Model{}).Inits()
	for i := range inits {
		w.rec(inits[i], nil, nil, nil, counts{})
	}
	return w.apply, w.crash
}

// ───────────────────────── reconcile decision: full bounded input space

// ReconcileReasons indexes the single-digit codes of ReconcileVectors.Expected.
var ReconcileReasons = []string{"data_window_manual", "invalid_record_ref", "reconcile_exhausted",
	"live_target_prior_equals_target", "live_target", "tag_advanced_container_stale", "already_on_prior",
	"safe_boundary_confirmed", "indeterminate_restore_prior", "no_recovery_target"}

// The bounded domains, in odometer order (the last one varies fastest).
var (
	domKindMode       = [][2]string{{"upgrades.apply", ""}, {"rollbacks.create", "image"}, {"rollbacks.create", "data"}, {"upgrades.apply", "data"}}
	domPhase          = []string{"admitted", "captured", "resolved", "pulled", "restarting", "restarted", "verified"}
	domAttempts       = [][2]int{{0, 0}, {0, 3}, {3, 3}}
	domRefValid       = []bool{true, false}
	domRunningID      = []string{"", "P", "T", "X"}
	domTargetID       = []string{"", "T", "P"}
	domPriorID        = []string{"", "P", "T"}
	domRunningDigests = [][]string{{}, {"P"}, {"T"}, {"X"}}
	domTargetDigests  = [][]string{{}, {"T"}}
	domPriorDigests   = [][]string{{}, {"P"}, {"T"}}
	domTagDigests     = [][]string{{}, {"P"}, {"T"}}
)

// ReconcileDomain names one input dimension and its values.
type ReconcileDomain struct {
	Name   string `json:"name"`
	Values []any  `json:"values"`
}

// ReconcileVectors is the reconcile decision table over the whole bounded input space.
// Expected holds one verdict code per input (a digit indexing Reasons and Actions), in
// odometer order over Domains, so 435,456 inputs cost 435,456 bytes. A verdict is the
// PAIR (action, reason): Actions[c] is the action the model returns together with
// Reasons[c], and Verdict gives both for an input.
type ReconcileVectors struct {
	Order    string            `json:"order"`
	Reasons  []string          `json:"reasons"`
	Actions  []string          `json:"actions"`
	Domains  []ReconcileDomain `json:"domains"`
	Expected string            `json:"expected"`
}

func anySlice[T any](xs []T) []any {
	out := make([]any, len(xs))
	for i, x := range xs {
		out[i] = x
	}
	return out
}

func reconcileDomains() []ReconcileDomain {
	return []ReconcileDomain{
		{"kind_mode", anySlice(domKindMode)}, {"phase", anySlice(domPhase)}, {"attempts", anySlice(domAttempts)},
		{"ref_valid", anySlice(domRefValid)}, {"running_id", anySlice(domRunningID)},
		{"target_id", anySlice(domTargetID)}, {"prior_id", anySlice(domPriorID)},
		{"running_digests", anySlice(domRunningDigests)}, {"target_digests", anySlice(domTargetDigests)},
		{"prior_digests", anySlice(domPriorDigests)}, {"tag_digests", anySlice(domTagDigests)},
	}
}

// ReconcileInputAt returns the input at the given per-domain indices (len 11, in
// domain order).
func ReconcileInputAt(idx []int) ReconcileInputs {
	km, at := domKindMode[idx[0]], domAttempts[idx[2]]
	return ReconcileInputs{Kind: km[0], Mode: km[1], Phase: domPhase[idx[1]], Attempts: at[0], MaxAttempts: at[1],
		RefValid: domRefValid[idx[3]], RunningID: domRunningID[idx[4]], TargetID: domTargetID[idx[5]],
		PriorID: domPriorID[idx[6]], RunningDigests: domRunningDigests[idx[7]], TargetDigests: domTargetDigests[idx[8]],
		PriorDigests: domPriorDigests[idx[9]], TagDigests: domTagDigests[idx[10]]}
}

// Advance moves idx to the next input in odometer order (last domain fastest) and
// reports false after the last one.
func (rv *ReconcileVectors) Advance(idx []int) bool {
	for d := len(idx) - 1; d >= 0; d-- {
		idx[d]++
		if idx[d] < len(rv.Domains[d].Values) {
			return true
		}
		idx[d] = 0
	}
	return false
}

// Verdict returns the model's (action, reason) for the n-th input in odometer order.
func (rv *ReconcileVectors) Verdict(n int) (action, reason string) {
	c := rv.Expected[n] - '0'
	return rv.Actions[c], rv.Reasons[c]
}

// GenReconcileVectors evaluates the reference decision on every input and records the
// action as well as the reason. One code per input can carry both only because the
// reference table gives every reason exactly one action; that is checked on every
// input here, not assumed.
func GenReconcileVectors() *ReconcileVectors {
	rv := &ReconcileVectors{Order: "odometer over domains, last domain varies fastest",
		Reasons: ReconcileReasons, Actions: make([]string, len(ReconcileReasons)), Domains: reconcileDomains()}
	code := map[string]byte{}
	total := 1
	for i, r := range ReconcileReasons {
		code[r] = byte('0' + i)
	}
	for _, d := range rv.Domains {
		total *= len(d.Values)
	}
	out := make([]byte, 0, total)
	idx := make([]int, len(rv.Domains))
	for more := true; more; more = rv.Advance(idx) {
		action, reason := ReconcileSpec(ReconcileInputAt(idx))
		c, known := code[reason]
		if !known {
			panic("lifecyclemodel: reconcile reason " + reason + " is missing from ReconcileReasons")
		}
		if prev := rv.Actions[c-'0']; prev != "" && prev != action {
			panic("lifecyclemodel: reconcile reason " + reason + " has two actions: " + prev + " and " + action)
		}
		rv.Actions[c-'0'] = action
		out = append(out, c)
	}
	rv.Expected = string(out)
	return rv
}
