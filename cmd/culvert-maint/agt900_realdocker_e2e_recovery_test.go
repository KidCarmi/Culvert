//go:build agt900_e2e

package main

// agt900_realdocker_e2e_recovery_test.go — the outstanding AGT-900 recovery
// cases of the real-Docker e2e (driven by test/agt900-e2e/run.sh, build tag
// agt900_e2e, like agt900_realdocker_e2e_test.go whose rig they reuse):
//
//   - standalone `rollbacks.create` image records (S1/S2/S3 of the V2 matrix)
//     and a data record (data_window_manual, Docker never read for it);
//   - the reconcile deadline: a record left `abandoned`, untouched;
//   - the verify-to-audit window, hit deterministically by fault injection
//     (strace SIGKILLs the agent at the entry of its audit write);
//   - dockerd stopped (and restarted) while the reconcile is held;
//   - a stopped proxy container (container_not_running);
//   - ok_stale: `compose up` exits 0 but the container keeps the prior image,
//     produced with the production compose_override_file pinning that image.
//
// Expectations come from the V2 decision matrix (reconcile_decision_v2.go)
// and the AGT-900 contract; contract checks FAIL, owner-strict checks GAP.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// e2eOkStaleOverride is the case-specific compose_override_file of the
// ok_stale case in root mode (sudoers mode edits the configured override).
const e2eOkStaleOverride = "docker-compose.okstale-e2e.yml"

type e2eNamedCase struct {
	name string
	run  func()
}

// standalone expectations: the stack ran `good` (an earlier upgrade) and the
// rollback was moving it TO `prior`.
func standaloneX(x e2eExpect) e2eExpect {
	x.pre, x.targets = "good", []string{"prior"}
	return x
}

func e2eRecoveryCases(t *testing.T, e *e2eEnv) []e2eNamedCase {
	tagFailed := xp("realign", "tag_failed", []string{"tag:prior"}, "good", "prior", false, "recovery_required", "recovery_required")
	verifyFailed := xp("realign", "post_verify_failed", []string{"tag:prior"}, "prior", "prior", false, "recovery_required", "recovery_required")
	// `docker compose ps --format json` (the sudoers-bound read) lists running
	// and paused containers but not exited ones, so a STOPPED proxy reads as no
	// container at all; the V2 row container_not_running is reached by a
	// container compose still lists in another state: paused. The kill is held
	// at up_before:1, so `up` is attributed, and `compose ps -a` shows an
	// exited (once started) container, not the never-started one a death
	// inside `up` leaves: B1 (#2109) refuses to restore without that evidence.
	stopped := rrKeep("stack_down_no_up_evidence", "good", "prior")
	stopped.status = "exited"
	paused := rrKeep("container_not_running", "good", "prior")
	paused.status = "paused"
	return []e2eNamedCase{
		// S1: killed before the rollback's pull: the tag never moved.
		{"standalone_rb_before_pull", func() {
			e.caseStandalone(t, "standalone_rb_before_pull", "pull_before:1",
				standaloneX(xp("noop", "rollback_never_moved_tag", []string{}, "good", "good", true, "done", "")))
		}},
		// S2: killed after the rollback's retag, before its `up`.
		{"standalone_rb_tag_moved", func() {
			e.caseStandalone(t, "standalone_rb_tag_moved", "up_before:1",
				standaloneX(rrKeep("rollback_target_partially_applied", "prior", "good")))
		}},
		// S3: killed after the rollback's `up`, before its gate.
		{"standalone_rb_up_done", func() {
			e.caseStandalone(t, "standalone_rb_up_done", "up_after:1",
				standaloneX(rrKeep("rollback_target_partially_applied", "prior", "prior")))
		}},
		{"data_rollback_record", func() { e.caseDataRecord(t, "data_rollback_record") }},
		{"reconcile_deadline_abandoned", func() { e.caseDeadline(t, "reconcile_deadline_abandoned") }},
		{"verify_to_audit_window", func() { e.caseVerifyAuditWindow(t, "verify_to_audit_window") }},
		{"dockerd_restart_before_action", func() {
			e.caseDockerdMidReconcile(t, "dockerd_restart_before_action", "tag_before:1", true, xRealign, nil)
		}},
		{"dockerd_down_at_action", func() {
			e.caseDockerdMidReconcile(t, "dockerd_down_at_action", "tag_before:1", false, tagFailed, &xRealign)
		}},
		{"dockerd_down_at_verify", func() {
			e.caseDockerdMidReconcile(t, "dockerd_down_at_verify", "ps_before:4", false, verifyFailed, &xOnPrior)
		}},
		{"container_stopped", func() { e.caseContainerNotRunning(t, "container_stopped", "stop", stopped) }},
		{"container_paused", func() { e.caseContainerNotRunning(t, "container_paused", "pause", paused) }},
		{"ok_stale_realign", func() { e.caseOkStale(t, "ok_stale_realign") }},
	}
}

// caseStandalone: a successful upgrade to good, then a standalone image
// rollback (POST /v1/rollbacks mode=image) to prior on a fresh agent process,
// SIGKILLed at point; then a converge restart.
func (e *e2eEnv) caseStandalone(t *testing.T, name, point string, x e2eExpect) {
	res := &e2eResult{name: name, expected: "standalone rollback to prior killed at " + point + "; restart: " + x.String()}
	defer e.record(t, res)
	if err := e.reset(); err != nil {
		res.err = "reset: " + err.Error()
		return
	}
	r := newE2ERig(t, e, name)
	r.res = res
	p := r.start("converge", "2m")
	up, err := r.apply(p, "good")
	if err != nil {
		res.err = err.Error()
		return
	}
	if op := p.waitOp(up, 3*time.Minute); op.State != "succeeded" {
		res.err = fmt.Sprintf("the upgrade to good did not succeed: %s(%s)", op.State, op.FailureReason)
		return
	}
	r.killProc(p)
	r.start("converge", "2m") // fresh call counters; the journal is empty
	opID, how, err := r.crashOp(func(p *agentProc) (string, error) { return r.rollback(p, "image", "prior") }, point)
	if err != nil {
		res.err = "crash: " + err.Error()
		return
	}
	res.how = "upgrade to good succeeded; rollback " + how
	rec := r.record(opID)
	res.eq("crash record", "rollbacks.create/image/admitted target=prior",
		fmt.Sprintf("%s/%s/%s target=%s", recStr(rec, "kind"), recStr(rec, "mode"), recStr(rec, "phase"), r.roleOfRef(recStr(rec, "target_ref"))))
	o := r.restartConverge(opID, "2m")
	r.assertConvergeObs(res, opID, x, &o)
	r.killProc(r.a)
}

// caseDataRecord: a data rollback (restore of a backup) SIGKILLed at its first
// Docker call after admission. Converge must report it data_window_manual and
// never read Docker for it: the only container read is the reconcile's
// wait-for-Docker, and no image reference or the fixed tag is inspected.
func (e *e2eEnv) caseDataRecord(t *testing.T, name string) {
	x := rrKeep("data_window_manual", "prior", "prior")
	res := &e2eResult{name: name, expected: "data rollback killed after admission; restart: " + x.String() + "; Docker never read for the record"}
	defer e.record(t, res)
	if err := e.reset(); err != nil {
		res.err = "reset: " + err.Error()
		return
	}
	r := newE2ERig(t, e, name)
	r.res = res
	r.start("converge", "2m")
	// any:1 is the synchronous backup-list preflight; any:2 is the first stage.
	opID, how, err := r.crashOp(func(p *agentProc) (string, error) { return r.rollback(p, "data", "") }, "any_before:2")
	if err != nil {
		res.err = "crash: " + err.Error()
		return
	}
	res.how = "data rollback " + how
	rec := r.record(opID)
	res.eq("crash record", "rollbacks.create/data/admitted", recStr(rec, "kind")+"/"+recStr(rec, "mode")+"/"+recStr(rec, "phase"))
	var o restartObs
	o.before = e.snap()
	o.recBefore = r.record(opID)
	ends0 := r.reconcileEnds()
	p := r.start("converge", "2m")
	var n int
	o.view, o.raw, n, o.err = r.waitReconcileQuiet(p, ends0, e2eReconcTO)
	r.observe(p, opID, &o)
	r.jcheck("after the restart")
	r.assertConvergeObs(res, opID, x, &o)
	inspects, refReads := 0, 0
	for _, c := range o.allCalls[:min(n, len(o.allCalls))] { // the reconcile's own calls only
		f := strings.Fields(c)
		switch {
		case f[0] == "inspect":
			inspects++
		case len(f) > 2 && f[0] == "image" && f[1] == "inspect" && (f[len(f)-1] == e2ePinned || strings.Contains(f[len(f)-1], "@sha256:")):
			refReads++
		}
	}
	res.check("Docker never read for the data record", inspects == 1 && refReads == 0,
		"1 container inspect (the wait for Docker), 0 pinned-tag / image-ref inspects",
		fmt.Sprintf("%d container inspect(s), %d pinned-tag/ref inspect(s)", inspects, refReads))
	r.killProc(r.a)
}

// crashVerified crashes an upgrade to good at the journal's `verified` (a
// polled kill, retried from scratch when it misses).
func (e *e2eEnv) crashVerified(t *testing.T, name string, res *e2eResult) (*e2eRig, string, string, error) {
	for attempt := 1; attempt <= 6; attempt++ {
		if err := e.reset(); err != nil {
			return nil, "", "", fmt.Errorf("reset: %w", err)
		}
		r := newE2ERig(t, e, name)
		r.res = res
		r.start("converge", "2m")
		opID, how, err := r.crash("good", "verified")
		if errors.Is(err, errMissedWindow) {
			continue
		}
		if attempt > 1 {
			how += fmt.Sprintf(", attempt %d", attempt)
		}
		return r, opID, how, err
	}
	return nil, "", "", errors.New("the polled kill missed its window 6 times")
}

// recordOf finds one record's reconcile result in a status view.
func recordOf(v reconcileView, opID string) string {
	if v.Reconcile == nil {
		return "<no reconcile>"
	}
	for _, rr := range v.Reconcile.Records {
		if rr.OpID == opID {
			return rr.Decision + "/" + rr.Reason + ":" + rr.Outcome
		}
	}
	return "<absent>"
}

// nonPS drops `compose ps` (GET /v1/status polls it too) from a call log.
func nonPS(calls []string) []string {
	var out []string
	for _, c := range calls {
		if composeSub(strings.Fields(c)) != "ps" {
			out = append(out, c)
		}
	}
	return out
}

// caseDeadline: two records, the reconcile deadline (2 x stage_timeout) runs
// out on the first. A = an upgrade killed at `verified`; its adopt needs a
// fresh /ready probe, which is stalled, so the probe consumes the deadline. B =
// a standalone image rollback killed before its pull (B's op id sorts after
// A's). Converge with stage_timeout 5s must finish A as recovery_required, then
// leave B `abandoned`: not read, not changed, record untouched; state
// abandoned. A later start (ready again) converges both.
func (e *e2eEnv) caseDeadline(t *testing.T, name string) {
	res := &e2eResult{name: name, expected: "stage_timeout 5s (deadline 10s), /ready stalled: A=recovery_required/verified_target_not_ready, " +
		"B=recovery_required/deadline_elapsed:abandoned untouched, state abandoned, no Docker change; then A adopt + B noop/rollback_never_moved_tag, both retired"}
	defer e.record(t, res)
	r, opA, how, err := e.crashVerified(t, name, res)
	if err != nil {
		res.err = "crash A: " + err.Error()
		return
	}
	res.how = "A: " + how
	p2 := r.start("off", "2m") // reports A, changes nothing, leaves the lock free
	if v, _, werr := p2.waitStatus(); werr != nil || v.Reconcile != nil {
		res.err = fmt.Sprintf("off-mode start: %v (reconcile %v)", werr, v.Reconcile != nil)
		return
	}
	opB, howB, err := r.crashOp(func(p *agentProc) (string, error) { return r.rollback(p, "image", "prior") }, "pull_before:1")
	if err != nil {
		res.err = "crash B: " + err.Error()
		return
	}
	res.how += "; B (standalone rollback to prior): " + howB
	if !(opB > opA) {
		res.err = fmt.Sprintf("B's op id %s does not sort after A's %s", opB, opA)
		return
	}
	recA := r.record(opA)
	res.eq("records before", "A=upgrades.apply/verified B=rollbacks.create/image/admitted",
		fmt.Sprintf("A=%s/%s B=%s", recStr(recA, "kind"), recStr(recA, "phase"), func() string {
			m := r.record(opB)
			return recStr(m, "kind") + "/" + recStr(m, "mode") + "/" + recStr(m, "phase")
		}()))
	before := e.snap()
	if err := os.WriteFile(e.ctlFile("hang_ready"), []byte("1\n"), 0o644); err != nil {
		res.err = err.Error()
		return
	}
	_ = os.Remove(e.ctlFile("ready_hit"))
	ends0 := r.reconcileEnds()
	// This case is about the reconcile DEADLINE (2 x stage_timeout = 10s) being
	// spent in A's stalled readiness probe. Since the settle window (#2062) the
	// reconcile first waits out interrupted_settle (default 75s) from agent
	// start, which alone outlasts a 10s deadline (settle_wait_cut_short, tested
	// on its own), so A would never be probed. This one start therefore runs
	// with no settle window; the expectations are unchanged.
	r.cfgExtra = "interrupted_settle = \"0s\"\n"
	p3 := r.start("converge", "5s")
	r.cfgExtra = ""
	if !waitFile(e.ctlFile("ready_hit"), time.Minute) {
		res.err = "A's readiness probe never reached /ready"
		return
	}
	atProbe := len(nonPS(p3.calls()))
	v, _, nQuiet, err := r.waitReconcileQuiet(p3, ends0, 2*time.Minute)
	_ = os.Remove(e.ctlFile("hang_ready"))
	if err != nil {
		res.err = err.Error()
		return
	}
	after := e.snap()
	state := ""
	if v.Reconcile != nil {
		state = v.Reconcile.State
	}
	res.observed = fmt.Sprintf("state=%s A=%s B=%s actions=[%s] %s", state, recordOf(v, opA), recordOf(v, opB),
		strings.Join(r.mutating(p3), ","), e.describe(after))
	res.eq("reconcile state", "abandoned", state)
	res.eq("A", "recovery_required/verified_target_not_ready:recovery_required", recordOf(v, opA))
	res.eq("B", "recovery_required/deadline_elapsed:abandoned", recordOf(v, opB))
	var rop opView
	if v.Reconcile != nil {
		_, _ = p3.get("/v1/operations/"+v.Reconcile.OpID, &rop)
	}
	res.eq("reconcile op", "reconcile.startup:failed(recovery_required)", rop.Kind+":"+rop.State+"("+rop.FailureReason+")")
	got := "<absent>"
	if v.RecoveryRequired != nil {
		got = strconv.FormatBool(*v.RecoveryRequired)
	}
	res.eq("status.recovery_required", "true", got)
	res.eq("docker commands", "[]", "["+strings.Join(r.mutating(p3), ",")+"]")
	res.check("I3 Docker unchanged", after.ContainerID == before.ContainerID && after.Image == before.Image &&
		after.Tag == before.Tag && after.Status == before.Status, e.describe(before), e.describe(after))
	all := p3.calls()
	end := nonPS(all[:min(nQuiet, len(all))])
	res.check("no Docker call after A's probe began (B never read)", len(end) == atProbe,
		fmt.Sprintf("%d calls", atProbe), fmt.Sprintf("%d calls: %s", len(end), strings.Join(end[min(atProbe, len(end)):], " | ")))
	// The startup's interruption bookkeeping (interrupted_seen,
	// interrupt_audited) runs before the reconcile; the reconcile itself must
	// not have written B.
	mB := r.record(opB)
	var wrote []string
	for _, k := range []string{"reconcile_attempts", "reconcile_outcome", "reconcile_decision", "last_reconcile_at"} {
		if _, ok := mB[k]; ok {
			wrote = append(wrote, k)
		}
	}
	res.check("B carries no reconcile write", mB != nil && len(wrote) == 0, "kept, no reconcile_* field",
		fmt.Sprintf("kept=%v fields=%v", mB != nil, wrote))
	res.eq("A's kept record outcome", "recovery_required", recStr(r.record(opA), "reconcile_outcome"))
	for _, id := range []string{opA, opB} {
		var op opView
		_, _ = p3.get("/v1/operations/"+id, &op)
		res.eq("I6 interrupted op "+short(id), "failed(agent_restart_interrupted)", op.State+"("+op.FailureReason+")")
	}
	r.privCheck(res, p3, "deadline restart")
	r.jcheck("after the deadline")
	r.killProc(p3)

	res.prefix = "r2 "
	p4 := r.start("converge", "2m")
	v2, _, err := p4.waitReconcile(e2eReconcTO)
	if err != nil {
		res.err = err.Error()
		return
	}
	final := e.snap()
	st2 := ""
	if v2.Reconcile != nil {
		st2 = v2.Reconcile.State
	}
	res.observed += fmt.Sprintf("; then state=%s A=%s B=%s %s", st2, recordOf(v2, opA), recordOf(v2, opB), e.describe(final))
	res.eq("reconcile state", "done", st2)
	res.eq("A", "adopt/verified_target_live:converged", recordOf(v2, opA))
	res.eq("B", "noop/rollback_never_moved_tag:converged", recordOf(v2, opB))
	res.eq("docker commands", "[]", "["+strings.Join(r.mutating(p4), ",")+"]")
	res.eq("Docker", "tag=good run=good(running,ready)", e.describe(final))
	for _, id := range []string{opA, opB} {
		n := p4.reconciledAudits(id)["succeeded"]
		res.check("I7 "+short(id)+" retired after its audit entry", r.record(id) == nil && n >= 1, "retired, >= 1 entry",
			fmt.Sprintf("retired=%v entries=%d", r.record(id) == nil, n))
		res.gapCheck("OWNER exactly one audit entry "+short(id), n == 1, "1", strconv.Itoa(n))
	}
	r.privCheck(res, p4, "final restart")
	r.jcheck("after the final restart")
	res.prefix = ""
	r.killProc(p4)
}

// reconcileEnds counts the terminal audit entries of reconcile.startup ops.
func (r *e2eRig) reconcileEnds() int {
	n := 0
	for _, l := range strings.Split(readFile(filepath.Join(r.state, "audit.jsonl")), "\n") {
		if strings.Contains(l, `"kind":"reconcile.startup"`) &&
			(strings.Contains(l, `"outcome":"succeeded"`) || strings.Contains(l, `"outcome":"failed"`)) {
			n++
		}
	}
	return n
}

// waitReconcileQuiet waits for p's reconcile to finish WITHOUT polling GET
// /v1/status, which itself reads Docker (the running image and the fixed tag)
// while interrupted operations exist: it watches audit.jsonl for the
// reconcile op's terminal entry (ends0 = reconcileEnds() before p started).
// It returns how many Docker calls p had made by then: all of them the
// reconcile's own. Only then is the status read for the result.
func (r *e2eRig) waitReconcileQuiet(p *agentProc, ends0 int, d time.Duration) (reconcileView, map[string]json.RawMessage, int, error) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) && r.reconcileEnds() <= ends0 {
		time.Sleep(100 * time.Millisecond)
	}
	if r.reconcileEnds() <= ends0 {
		return reconcileView{}, nil, 0, errors.New("the reconcile wrote no terminal audit entry")
	}
	n := len(p.calls())
	v, raw, err := p.waitReconcile(time.Minute)
	return v, raw, n, err
}

// waitStatus waits for GET /v1/status to answer.
func (p *agentProc) waitStatus() (reconcileView, map[string]interface{}, error) {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		var v reconcileView
		if code, _ := p.get("/v1/status", &v); code == 200 {
			return v, nil, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return reconcileView{}, nil, errors.New("status did not answer")
}

// caseVerifyAuditWindow: the window between the reconcile's verify returning
// and its `:reconciled` audit write has no Docker call and no file write to
// hold on to, so it is hit by fault injection instead. The reconcile is held
// right after the verify's last Docker read (image_after:13); strace attaches
// to the agent with a SIGKILL injected at the entry of the first write(2) to
// audit.jsonl; the hold is released. The agent therefore dies after the verify
// returned and before one byte of the audit entry is written.
func (e *e2eEnv) caseVerifyAuditWindow(t *testing.T, name string) {
	res := &e2eResult{name: name, expected: "realign killed at its audit write (after the verify): no `:reconciled` entry, record kept (attempts 1), " +
		"tag=prior run=prior; next start: " + xOnPrior.String() + " with exactly 1 entry"}
	defer e.record(t, res)
	if _, err := exec.LookPath("strace"); err != nil {
		res.err = "strace is required for this case"
		return
	}
	if err := e.reset(); err != nil {
		res.err = "reset: " + err.Error()
		return
	}
	r := newE2ERig(t, e, name)
	r.res = res
	r.start("converge", "2m")
	opID, how, err := r.crash("good", "up_before:1")
	if err != nil {
		res.err = "crash: " + err.Error()
		return
	}
	res.how = how
	p := r.newProc("h1", "converge", "2m")
	if err := os.WriteFile(filepath.Join(p.ctl, "block_on"), []byte("image_after:13\n"), 0o600); err != nil {
		res.err = err.Error()
		return
	}
	r.startProc(p)
	r.a = p
	if !waitFile(filepath.Join(p.ctl, "blocked"), 2*time.Minute) {
		res.err = "the reconcile never reached the verify's last read"
		return
	}
	auditPath := filepath.Join(r.state, "audit.jsonl")
	pid := p.cmd.Process.Pid
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	slog := filepath.Join(r.dir, "strace.log")
	st := exec.CommandContext(ctx, "strace", "-f", "-p", strconv.Itoa(pid), "-P", auditPath, "-e", "trace=write", // #nosec G204 -- harness-controlled
		"-e", "inject=write:error=EIO:signal=SIGKILL:when=1", "-o", slog)
	var serr lockedBuffer
	st.Stderr = &serr
	if err := st.Start(); err != nil {
		res.err = "strace: " + err.Error()
		return
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(serr.String(), "attached") {
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.Contains(serr.String(), "attached") {
		res.err = "strace did not attach: " + serr.String()
		return
	}
	time.Sleep(300 * time.Millisecond)
	if err := os.WriteFile(filepath.Join(p.ctl, "release"), []byte("1\n"), 0o600); err != nil {
		res.err = err.Error()
		return
	}
	_ = st.Wait() // strace exits when its tracee dies
	ps, _ := p.cmd.Process.Wait()
	killed := false
	if ps != nil {
		if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() && ws.Signal() == syscall.SIGKILL {
			killed = true
		}
	}
	trace := readFile(slog)
	res.check("killed at the audit write", killed && strings.Contains(trace, "write(") && strings.Contains(trace, "killed by SIGKILL"),
		"SIGKILL at the entry of write(audit.jsonl)", fmt.Sprintf("killed=%v trace=%q", killed, strings.Join(strings.Fields(trace), " ")))
	r.killProc(p)
	res.how += "; reconcile SIGKILLed by strace at its first write(2) to audit.jsonl, after the verify returned (image_after:13 released)"
	r.jcheck("after the kill at the audit write")
	held := e.snap()
	res.eq("Docker after the kill", "tag=prior run=prior", fmt.Sprintf("tag=%s run=%s", e.class(held.Tag), e.class(held.Image)))
	rec := r.record(opID)
	res.check("record kept", rec != nil, "kept", strconv.FormatBool(rec != nil))
	res.eq("attempts after the kill", "1", strconv.Itoa(recInt(rec, "reconcile_attempts")))
	n := 0
	for _, l := range bytes.Split([]byte(readFile(auditPath)), []byte("\n")) {
		if bytes.Contains(l, []byte(`"op_id":"`+opID+`"`)) && bytes.Contains(l, []byte(`:reconciled"`)) {
			n++
		}
	}
	res.eq("`:reconciled` entries after the kill", "0", strconv.Itoa(n))
	res.prefix = "r1 "
	o := r.restartConverge(opID, "2m")
	r.assertConvergeObs(res, opID, xOnPrior, &o)
	res.prefix = ""
	r.killProc(r.a)
}

// caseDockerdMidReconcile: the reconcile of a tag-ahead record is held at
// hold; the private dockerd is stopped (restart=true: and started again, the
// proxy back by its restart policy) before the hold is released. first is
// the expectation for that restart; final, if set, for the next start (with
// dockerd running).
func (e *e2eEnv) caseDockerdMidReconcile(t *testing.T, name, hold string, restart bool, first e2eExpect, final *e2eExpect) {
	what := "stopped"
	if restart {
		what = "stopped and started again"
	}
	exp := fmt.Sprintf("reconcile held at %s, dockerd %s, released: %s", hold, what, first)
	if final != nil {
		exp += "; dockerd back, next start: " + final.String()
	}
	res := &e2eResult{name: name, expected: exp}
	defer e.record(t, res)
	daemonDown := false
	defer func() {
		if daemonDown {
			_ = e.daemon(e.dockerdStart)
		}
	}()
	if err := e.reset(); err != nil {
		res.err = "reset: " + err.Error()
		return
	}
	r := newE2ERig(t, e, name)
	r.res = res
	r.start("converge", "2m")
	opID, how, err := r.crash("good", "up_before:1")
	if err != nil {
		res.err = "crash: " + err.Error()
		return
	}
	res.how = how
	var o restartObs
	o.before = e.snap()
	o.recBefore = r.record(opID)
	p := r.newProc("h1", "converge", "2m")
	if err := os.WriteFile(filepath.Join(p.ctl, "block_on"), []byte(hold+"\n"), 0o600); err != nil {
		res.err = err.Error()
		return
	}
	r.startProc(p)
	r.a = p
	if !waitFile(filepath.Join(p.ctl, "blocked"), 2*time.Minute) {
		res.err = "the reconcile never reached " + hold
		return
	}
	if err := e.daemon(e.dockerdStop); err != nil {
		res.err = err.Error()
		return
	}
	daemonDown = true
	res.how += "; reconcile held at " + hold + ", dockerd " + what
	startDaemon := func() bool {
		if err := e.daemon(e.dockerdStart); err != nil {
			res.err = err.Error()
			return false
		}
		daemonDown = false
		if err := e.waitReady(90 * time.Second); err != nil {
			res.err = "after dockerd start: " + err.Error()
			return false
		}
		return true
	}
	if restart && !startDaemon() {
		return
	}
	if err := os.WriteFile(filepath.Join(p.ctl, "release"), []byte("1\n"), 0o600); err != nil {
		res.err = err.Error()
		return
	}
	o.view, o.raw, o.err = p.waitReconcile(e2eReconcTO)
	if !restart && !startDaemon() {
		return
	}
	res.prefix = "r1 "
	r.observe(p, opID, &o)
	r.jcheck("after the reconcile (dockerd running again)")
	r.assertConvergeObs(res, opID, first, &o)
	if !first.retired {
		res.eq("attempts after the restart", "1", strconv.Itoa(recInt(r.record(opID), "reconcile_attempts")))
	}
	r.killProc(p)
	if final != nil {
		res.prefix = "r2 "
		o2 := r.restartConverge(opID, "2m")
		r.assertConvergeObs(res, opID, *final, &o2)
		r.killProc(r.a)
	}
	res.prefix = ""
}

// caseContainerNotRunning: the upgrade was killed with the tag ahead (the
// realign case), then the proxy container was stopped (`docker stop`; it
// stays exited: restart: unless-stopped) or paused (`docker pause`). Converge
// must not act on a container that is not running: recovery_required, Docker
// unchanged.
func (e *e2eEnv) caseContainerNotRunning(t *testing.T, name, how0 string, x e2eExpect) {
	res := &e2eResult{name: name, expected: "tag ahead, proxy container `docker " + how0 + "`: " + x.String()}
	defer e.record(t, res)
	if err := e.reset(); err != nil {
		res.err = "reset: " + err.Error()
		return
	}
	r := newE2ERig(t, e, name)
	r.res = res
	r.start("converge", "2m")
	opID, how, err := r.crash("good", "up_before:1")
	if err != nil {
		res.err = "crash: " + err.Error()
		return
	}
	s := e.snap()
	if _, err := e.docker(how0, s.ContainerID); err != nil {
		res.err = err.Error()
		return
	}
	if how0 == "pause" {
		defer func() { _, _ = e.docker("unpause", s.ContainerID) }()
	}
	res.how = how + "; then `docker " + how0 + "` of the proxy container"
	o := r.restartConverge(opID, "2m")
	r.assertConvergeObs(res, opID, x, &o)
	r.killProc(r.a)
}

// caseOkStale: `compose up` exits 0 but the container keeps running the prior
// image although the tag moved to the target, produced the way the agent
// documents it can happen: the compose_override_file (merged onto the agent's
// recreate) pins the proxy image to the prior digest. The upgrade is killed at
// its verify (phase restarted; the F1 fix records no target image id). V2 row
// A8: realign, retired.
func (e *e2eEnv) caseOkStale(t *testing.T, name string) {
	res := &e2eResult{name: name, expected: "override pins prior, upgrade killed at its verify (tag=good run=prior, phase restarted, no target id): " + xRealign.String()}
	defer e.record(t, res)
	if err := e.reset(); err != nil {
		res.err = "reset: " + err.Error()
		return
	}
	r := newE2ERig(t, e, name)
	r.res = res
	pin := "    image: " + e.ref("prior") + "   # AGT-900 e2e ok_stale: pins the prior image\n"
	if e.override == "" {
		body := "services:\n  proxy:\n" + pin
		if err := os.WriteFile(filepath.Join(e.proj, e2eOkStaleOverride), []byte(body), 0o644); err != nil {
			res.err = err.Error()
			return
		}
		r.cfgExtra = fmt.Sprintf("compose_override_file = %q\n", e2eOkStaleOverride)
		res.how = "compose_override_file " + e2eOkStaleOverride + " pins the prior digest"
	} else {
		body := strings.Replace(e.overrideOrig, "  proxy:\n", "  proxy:\n"+pin, 1)
		if body == e.overrideOrig {
			res.err = "the configured override has no proxy service to pin"
			return
		}
		if err := os.WriteFile(filepath.Join(e.proj, e.override), []byte(body), 0o644); err != nil {
			res.err = err.Error()
			return
		}
		res.how = "the configured " + e.override + " also pins the prior digest"
	}
	r.start("converge", "2m")
	crashed := r.a
	opID, how, err := r.crash("good", "ps_before:3")
	if err != nil {
		res.err = "crash: " + err.Error()
		return
	}
	res.how += "; upgrade " + how
	s := e.snap()
	rec := r.record(opID)
	upRan := false
	for _, m := range r.mutating(crashed) {
		if m == "up" {
			upRan = true
		}
	}
	res.check("ok_stale produced", upRan && e.class(s.Tag) == "good" && e.class(s.Image) == "prior" && s.Status == "running" &&
		recStr(rec, "phase") == "restarted" && recStr(rec, "target_image_id") == "",
		"`up` exited 0, tag=good, container still prior and running, phase restarted, no target_image_id",
		fmt.Sprintf("up=%v %s phase=%s target_image_id=%q", upRan, e.describe(s), recStr(rec, "phase"), recStr(rec, "target_image_id")))
	o := r.restartConverge(opID, "2m")
	r.assertConvergeObs(res, opID, xRealign, &o)
	r.killProc(r.a)
}
