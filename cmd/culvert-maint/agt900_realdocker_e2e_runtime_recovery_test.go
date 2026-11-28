//go:build agt900_e2e

// Real-Docker rows for the runtime recovery (ADR-0062 slice 6, PR 4;
// contracts AGT-010 and AGT-900). The agent runs with the observer at its
// smallest interval (1m) and runtime_recovery = "restore_last_gated". Every
// row starts from an install of the agent's own: the observer gates the
// prior image, the agent upgrades to good (installed.json: good replaced
// prior), then a /ctl switch makes an image fail /ready.
//
// Besides Docker's state, every row checks what the agent itself ran through
// its shim: the exact mutating commands, and that every `compose run` it
// issued was the read-only `cli --print-data-epoch`.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The trigger is 3 consecutive not_ready samples one interval apart, plus the
// recovery itself; a crash restart adds the settle window.
const (
	e2eRecoveryWait = 7 * time.Minute
	e2eRecoverySet  = `runtime_health_interval = "1m"` + "\n" + `runtime_recovery = "restore_last_gated"` + "\n"
)

// e2eRecoveryView is the runtime_recovery part of GET /v1/status.
type e2eRecoveryView struct {
	RuntimeRecovery *struct {
		Policy         string `json:"policy"`
		Threshold      int    `json:"threshold"`
		NotReadyStreak int    `json:"not_ready_streak"`
		Running        bool   `json:"running"`
		Last           *struct {
			OpID           string `json:"op_id"`
			Outcome        string `json:"outcome"`
			Reason         string `json:"reason"`
			ImageID        string `json:"image_id"`
			RestoreImageID string `json:"restore_image_id"`
		} `json:"last"`
	} `json:"runtime_recovery"`
}

func (v e2eRecoveryView) last() string {
	if v.RuntimeRecovery == nil {
		return "absent"
	}
	if v.RuntimeRecovery.Last == nil || v.RuntimeRecovery.Running {
		return "none"
	}
	return v.RuntimeRecovery.Last.Outcome + "/" + v.RuntimeRecovery.Last.Reason
}

// waitRecovery polls runtime_recovery until an attempt has finished.
func (p *agentProc) waitRecovery(d time.Duration) e2eRecoveryView {
	deadline := time.Now().Add(d)
	for {
		var v e2eRecoveryView
		_, _ = p.get("/v1/status", &v)
		if v.last() != "none" || time.Now().After(deadline) {
			return v
		}
		time.Sleep(2 * time.Second)
	}
}

// e2eAuditEv is one audit entry, in log order.
type e2eAuditEv struct {
	OpID          string `json:"op_id"`
	Kind          string `json:"kind"`
	Actor         string `json:"actor"`
	Outcome       string `json:"outcome"`
	FailureReason string `json:"failure_reason"`
}

// recoveryAudit renders opID's runtime.recover entries as kind/outcome@actor.
func (p *agentProc) recoveryAudit(opID string) string {
	var av struct {
		Events []e2eAuditEv `json:"events"`
	}
	_, _ = p.get("/v1/audit?limit=1000", &av)
	var out []string
	for _, ev := range av.Events {
		if strings.HasPrefix(ev.Kind, "runtime.recover") && (opID == "" || ev.OpID == opID) {
			s := ev.Kind + "/" + ev.Outcome + "@" + strings.TrimPrefix(ev.Actor, "agent:")
			if ev.FailureReason != "" {
				s += "(" + ev.FailureReason + ")"
			}
			out = append(out, s)
		}
	}
	return strings.Join(out, " ")
}

// recoveryRecords lists the runtime.recover journal records as
// op_id:terminal_outcome:armed.
func (r *e2eRig) recoveryRecords() string {
	ents, _ := os.ReadDir(filepath.Join(r.state, "reconcile"))
	var out []string
	for _, en := range ents {
		n := en.Name()
		if !strings.HasSuffix(n, ".json") || strings.HasPrefix(n, ".") {
			continue
		}
		m := r.record(strings.TrimSuffix(n, ".json"))
		if recStr(m, "kind") != "runtime.recover" {
			continue
		}
		armed, _ := m["rollback_armed"].(bool) //nolint:errcheck // absent → false
		out = append(out, fmt.Sprintf("%s:%s:armed=%v", recStr(m, "op_id"), recStr(m, "terminal_outcome"), armed))
	}
	return strings.Join(out, " ")
}

// attempts is recover_attempts.json's entries as "<n>" per entry, "" when absent.
func (r *e2eRig) attempts() string {
	var a struct {
		Entries []struct {
			Begun int `json:"begun"`
		} `json:"entries"`
	}
	raw := readFile(filepath.Join(r.state, "health", "recover_attempts.json"))
	if raw == "" || json.Unmarshal([]byte(raw), &a) != nil {
		return raw
	}
	var out []string
	for _, e := range a.Entries {
		out = append(out, fmt.Sprint(e.Begun))
	}
	return strings.Join(out, ",")
}

// changesSince renders p's mutating commands after the first n, without the
// data-epoch reads (`compose run`), which runOnlyReadsEpoch checks.
func (r *e2eRig) changesSince(p *agentProc, n int) string {
	all := r.mutating(p)
	var out []string
	for _, m := range all[min(n, len(all)):] {
		if m != "run" {
			out = append(out, m)
		}
	}
	return "[" + strings.Join(out, ",") + "]"
}

// runOnlyReadsEpoch: every `compose run` p issued was `cli --print-data-epoch`.
func runOnlyReadsEpoch(p *agentProc) (ok bool, got string) {
	reads := 0
	for _, l := range p.calls() {
		f := strings.Fields(l)
		if composeSub(f) != "run" {
			continue
		}
		if !strings.HasSuffix(l, " cli --print-data-epoch") {
			return false, l
		}
		reads++
	}
	return true, fmt.Sprintf("%d data-epoch read(s), nothing else", reads)
}

// setDataEpoch writes the data-epoch marker in the proxy's /data ("" removes
// it), through the fake proxy binary in the running container.
func (e *e2eEnv) setDataEpoch(content string) error {
	s := e.snap()
	if s.ContainerID == "" {
		return fmt.Errorf("no proxy container to write the data epoch in")
	}
	_, err := e.docker("exec", s.ContainerID, "/app", "-set-data-epoch", content)
	return err
}

// recoveryStart is what recoveryInstall leaves: the rig, its agent, the prior
// and good image ids, and the agent's mutating-command count after the install.
type recoveryStart struct {
	r           *e2eRig
	p           *agentProc
	prior, good string
	n           int
}

// recoveryInstall is the start every row shares: reset, an agent with the
// observer (and, when on, the recovery), the prior gated, then an upgrade to
// good that succeeds. ok is false when it could not get there (res.err says
// why); st.r is set once a rig exists, so the caller can clean it up.
func (e *e2eEnv) recoveryInstall(t *testing.T, name string, res *e2eResult, policy, gateGood bool) (st recoveryStart, ok bool) {
	if err := e.reset(); err != nil {
		res.err = "reset: " + err.Error()
		return st, false
	}
	if err := e.setDataEpoch(""); err != nil {
		res.err = "clear data epoch: " + err.Error()
		return st, false
	}
	r := newE2ERig(t, e, name)
	st.r = r
	r.res = res
	r.cfgExtra = `runtime_health_interval = "1m"` + "\n"
	if policy {
		r.cfgExtra = e2eRecoverySet
	}
	p := r.start("converge", "2m")
	st.p = p
	prior := e.snap().Image
	st.prior = prior
	if v, _ := p.waitHealth(e2eFirstSample, healthIs("gated", "gate_passed", prior)); stateOf(v) != "gated/gate_passed" {
		res.err = "the prior was never gated: " + stateOf(v)
		return st, false
	}
	opID, err := r.apply(p, "good")
	if err != nil {
		res.err = err.Error()
		return st, false
	}
	if op := p.waitOp(opID, 10*time.Minute); op.State != "succeeded" {
		res.err = "the install did not succeed: " + op.State
		return st, false
	}
	good := e.snap().Image
	st.good = good
	if gateGood {
		if v, _ := p.waitHealth(e2eNextSample+30*time.Second, healthIs("gated", "gate_passed", good)); stateOf(v) != "gated/gate_passed" {
			res.err = "the installed image was never gated: " + stateOf(v)
			return st, false
		}
	}
	st.n = len(st.r.mutating(st.p))
	return st, true
}

func failReady(e *e2eEnv, roles ...string) error {
	for _, role := range roles {
		if err := os.WriteFile(e.ctlFile("fail_ready_"+role), []byte("1\n"), 0o644); err != nil { // #nosec G306 -- read by the fake proxy as another uid
			return err
		}
	}
	return nil
}

// rr_restore: an upgrade this agent installed passed, was gated, and later
// fails /ready. The agent puts the prior back with the armed-rollback plan:
// exactly one retag to the prior and one `up`, the record retired, the
// terminal entry written, the attempt counted.
func (e *e2eEnv) caseRecoveryRestore(t *testing.T, name string) {
	res := &e2eResult{name: name, expected: "recovered/rollback_armed_tag_not_moved: tag:prior,up; prior running under the tag and ready; no record; started -> :reconciled -> succeeded; attempts 1"}
	defer e.record(t, res)
	st, ok := e.recoveryInstall(t, name, res, true, true)
	if st.r != nil {
		defer st.r.killProc(st.p)
	}
	if !ok {
		return
	}
	r, p, prior, good, n := st.r, st.p, st.prior, st.good, st.n
	if err := failReady(e, "good"); err != nil {
		res.err = err.Error()
		return
	}
	v := p.waitRecovery(e2eRecoveryWait)
	res.eq("recovery", "recovered/rollback_armed_tag_not_moved", v.last())
	if l := v.RuntimeRecovery; l != nil && l.Last != nil {
		res.eq("unhealthy image", shortID(good), shortID(l.Last.ImageID))
		res.eq("restore image", shortID(prior), shortID(l.Last.RestoreImageID))
		res.eq("recovery audit", "runtime.recover/started@runtime-recovery runtime.recover:reconciled/succeeded@runtime-recovery runtime.recover/succeeded@runtime-recovery",
			p.recoveryAudit(l.Last.OpID))
	}
	s := e.snap()
	res.eq("docker after", "run="+shortID(prior)+" tag="+shortID(prior)+" ready=true", fmt.Sprintf("run=%s tag=%s ready=%v", shortID(s.Image), shortID(s.Tag), s.Ready))
	res.eq("agent changes", "[tag:prior,up]", r.changesSince(p, n))
	runOK, runGot := runOnlyReadsEpoch(p)
	res.check("compose run only reads the data epoch", runOK, "cli --print-data-epoch only", runGot)
	res.eq("runtime.recover records", "", r.recoveryRecords())
	res.eq("attempts", "1", r.attempts())
	res.observed = fmt.Sprintf("%s; %s", v.last(), e.describe(s))
}

// rr_incompatible: the data epoch moved past what the prior reads (the marker
// a migrating image leaves). The recovery is refused before any operation:
// nothing changes, nothing is written.
func (e *e2eEnv) caseRecoveryIncompatible(t *testing.T, name string) {
	res := &e2eResult{name: name, expected: "refused/restore_incompatible: no op, no record, no audit entry, no attempt; good still running under the tag"}
	defer e.record(t, res)
	st, ok := e.recoveryInstall(t, name, res, true, false)
	if st.r != nil {
		defer st.r.killProc(st.p)
		defer func() { _ = e.setDataEpoch("") }()
	}
	if !ok {
		return
	}
	r, p, good, n := st.r, st.p, st.good, st.n
	if err := e.setDataEpoch(`{"schema":1,"epoch":2}`); err != nil {
		res.err = err.Error()
		return
	}
	if err := failReady(e, "good"); err != nil {
		res.err = err.Error()
		return
	}
	v := p.waitRecovery(e2eRecoveryWait)
	r.assertRefused(res, p, v, "refused/restore_incompatible", good, n)
}

// rr_hand_change: the agent installed good; an operator then moves the tag to
// bad by hand and recreates. bad fails /ready, but the agent did not install
// it: the recovery is refused (a manual change is evidence, not
// authorization) and the agent changes nothing.
func (e *e2eEnv) caseRecoveryHandChange(t *testing.T, name string) {
	res := &e2eResult{name: name, expected: "refused/no_provenance: the agent ran no tag or up after the hand change; bad still running"}
	defer e.record(t, res)
	st, ok := e.recoveryInstall(t, name, res, true, false)
	if st.r != nil {
		defer st.r.killProc(st.p)
	}
	if !ok {
		return
	}
	r, p, n := st.r, st.p, st.n
	for _, args := range [][]string{{"pull", "-q", e.ref("bad")}, {"tag", e.ref("bad"), e2ePinned}, e.composeArgs("up", "-d")} {
		if _, err := e.docker(args...); err != nil {
			res.err = fmt.Sprintf("hand change %v: %v", args, err)
			return
		}
	}
	bad := e.snap().Image
	v := p.waitRecovery(e2eRecoveryWait)
	r.assertRefused(res, p, v, "refused/no_provenance", bad, n)
}

// assertRefused: a refusal begins no operation, writes nothing and changes
// nothing; running is still on the image it was.
func (r *e2eRig) assertRefused(res *e2eResult, p *agentProc, v e2eRecoveryView, want, running string, n int) {
	res.eq("recovery", want, v.last())
	if l := v.RuntimeRecovery; l != nil && l.Last != nil {
		res.eq("no operation begun", "", l.Last.OpID)
	}
	s := r.e.snap()
	res.eq("docker unchanged", "run="+shortID(running)+" tag="+shortID(running), fmt.Sprintf("run=%s tag=%s", shortID(s.Image), shortID(s.Tag)))
	res.eq("agent changes", "[]", r.changesSince(p, n))
	runOK, runGot := runOnlyReadsEpoch(p)
	res.check("compose run only reads the data epoch", runOK, "cli --print-data-epoch only", runGot)
	res.eq("runtime.recover audit entries", "", p.recoveryAudit(""))
	res.eq("runtime.recover records", "", r.recoveryRecords())
	res.eq("attempts", "", r.attempts())
	res.observed = fmt.Sprintf("%s; %s", v.last(), r.e.describe(s))
}

// rr_restore_fails: the prior fails /ready too. The plan restores it once and
// its gate fails: no second up, the record kept and stamped failed, the
// failure audited, the attempt counted.
func (e *e2eEnv) caseRecoveryRestoreFails(t *testing.T, name string) {
	res := &e2eResult{name: name, expected: "failed/prior_not_ready: tag:prior,up (one up); prior under the tag; record kept failed:recovery_required armed; started -> :reconciled failed -> failed; attempts 1"}
	defer e.record(t, res)
	st, ok := e.recoveryInstall(t, name, res, true, false)
	if st.r != nil {
		defer st.r.killProc(st.p)
	}
	if !ok {
		return
	}
	r, p, prior, n := st.r, st.p, st.prior, st.n
	if err := failReady(e, "good", "prior"); err != nil {
		res.err = err.Error()
		return
	}
	v := p.waitRecovery(e2eRecoveryWait)
	res.eq("recovery", "failed/prior_not_ready", v.last())
	opID := ""
	if l := v.RuntimeRecovery; l != nil && l.Last != nil {
		opID = l.Last.OpID
		res.eq("recovery audit", "runtime.recover/started@runtime-recovery runtime.recover:reconciled/failed@runtime-recovery(recovery_required) runtime.recover/failed@runtime-recovery(recovery_required)",
			p.recoveryAudit(opID))
	}
	s := e.snap()
	res.eq("docker after", "run="+shortID(prior)+" tag="+shortID(prior), fmt.Sprintf("run=%s tag=%s", shortID(s.Image), shortID(s.Tag)))
	res.eq("agent changes", "[tag:prior,up]", r.changesSince(p, n))
	res.eq("runtime.recover records", opID+":failed:recovery_required:armed=true", r.recoveryRecords())
	res.eq("attempts", "1", r.attempts())
	res.observed = fmt.Sprintf("%s; %s", v.last(), e.describe(s))
}

// rr_crash_after_tag: the agent is killed inside the recovery, between its
// retag and its `up` (the tag on the prior, the unhealthy image still
// running). The next start (converge) decides the armed record with the same
// branch, finish_rollback, reads compatibility again and runs the one `up`
// left: the prior runs, the record is retired.
func (e *e2eEnv) caseRecoveryCrashAfterTag(t *testing.T, name string) {
	res := &e2eResult{name: name, expected: "killed at up_before:2 with tag=prior run=good; restart: finish_rollback/rollback_interrupted converged, up only; prior running and ready; record retired"}
	defer e.record(t, res)
	st, ok := e.recoveryInstall(t, name, res, true, false)
	if st.r != nil {
		defer func() { st.r.killProc(st.r.a) }()
	}
	if !ok {
		return
	}
	r, p, prior, good := st.r, st.p, st.prior, st.good
	if err := os.WriteFile(filepath.Join(p.ctl, "block_on"), []byte("up_before:2\n"), 0o600); err != nil {
		res.err = err.Error()
		return
	}
	if err := failReady(e, "good"); err != nil {
		res.err = err.Error()
		return
	}
	if !waitFile(filepath.Join(p.ctl, "blocked"), e2eRecoveryWait) {
		res.err = "the recovery never reached its up: " + p.waitRecovery(time.Second).last()
		return
	}
	held := e.snap()
	res.eq("at the kill", "tag="+shortID(prior)+" run="+shortID(good), fmt.Sprintf("tag=%s run=%s", shortID(held.Tag), shortID(held.Image)))
	recs := r.recoveryRecords()
	res.check("armed record written before the retag", strings.HasSuffix(recs, "::armed=true"), "<op>::armed=true", recs)
	opID := strings.SplitN(recs, ":", 2)[0]
	r.killProc(p)

	p2 := r.start("converge", "2m")
	view, _, err := p2.waitReconcile(e2eReconcTO + time.Minute)
	if err != nil {
		res.err = err.Error()
		return
	}
	res.eq("startup decision", "finish_rollback/rollback_interrupted:converged", recordOf(view, opID))
	s := e.snap()
	res.eq("docker after", "run="+shortID(prior)+" tag="+shortID(prior)+" ready=true", fmt.Sprintf("run=%s tag=%s ready=%v", shortID(s.Image), shortID(s.Tag), s.Ready))
	res.eq("restart's changes", "[up]", r.changesSince(p2, 0))
	runOK, runGot := runOnlyReadsEpoch(p2)
	res.check("the restart read the data epoch", runOK && !strings.HasPrefix(runGot, "0 "), "at least one cli --print-data-epoch, nothing else", runGot)
	res.eq("runtime.recover records", "", r.recoveryRecords())
	res.eq("recovery audit", "runtime.recover/started@runtime-recovery runtime.recover/failed@startup(agent_restart_interrupted) runtime.recover:reconciled/succeeded@reconcile",
		p2.recoveryAudit(opID))
	res.how = "held at up_before:2, SIGKILL"
	res.observed = fmt.Sprintf("%s; %s", recordOf(view, opID), e.describe(s))
}

// rr_off: the same install and the same failing image without the policy:
// the observer reports it unhealthy, and nothing is ever attempted.
func (e *e2eEnv) caseRecoveryOff(t *testing.T, name string) {
	res := &e2eResult{name: name, expected: "runtime_recovery absent from status; >=3 not_ready samples kept; the agent changed nothing; no runtime.recover entry, record or attempt"}
	defer e.record(t, res)
	st, ok := e.recoveryInstall(t, name, res, false, false)
	if st.r != nil {
		defer st.r.killProc(st.p)
	}
	if !ok {
		return
	}
	r, p, good, n := st.r, st.p, st.good, st.n
	if err := failReady(e, "good"); err != nil {
		res.err = err.Error()
		return
	}
	var bad []time.Time
	p.waitHealth(e2eRecoveryWait-2*time.Minute, func(v e2eHealthView) bool {
		if h := v.RuntimeHealth; h != nil && h.ObservedAt != nil && stateOf(v) == "unhealthy/not_ready" &&
			(len(bad) == 0 || !bad[len(bad)-1].Equal(*h.ObservedAt)) {
			bad = append(bad, *h.ObservedAt)
		}
		return len(bad) > 3
	})
	res.check("not_ready samples kept", len(bad) > 3, "> 3 (past the trigger threshold)", fmt.Sprint(len(bad)))
	raw := map[string]json.RawMessage{}
	_, _ = p.get("/v1/status", &raw)
	_, has := raw["runtime_recovery"]
	res.check("no runtime_recovery in status", !has, "absent", fmt.Sprint(has))
	s := e.snap()
	res.eq("docker unchanged", "run="+shortID(good)+" tag="+shortID(good), fmt.Sprintf("run=%s tag=%s", shortID(s.Image), shortID(s.Tag)))
	res.eq("agent changes", "[]", r.changesSince(p, n))
	res.eq("runtime.recover audit entries", "", p.recoveryAudit(""))
	res.eq("runtime.recover records", "", r.recoveryRecords())
	res.eq("attempts", "", r.attempts())
	res.observed = fmt.Sprintf("%d not_ready samples; %s", len(bad), e.describe(s))
}

// e2eRuntimeRecoveryCases are the slice 6 rows, registered after the
// observer rows.
func e2eRuntimeRecoveryCases(t *testing.T, e *e2eEnv) []e2eNamedCase {
	return []e2eNamedCase{
		{"rr_restore", func() { e.caseRecoveryRestore(t, "rr_restore") }},
		{"rr_incompatible", func() { e.caseRecoveryIncompatible(t, "rr_incompatible") }},
		{"rr_hand_change", func() { e.caseRecoveryHandChange(t, "rr_hand_change") }},
		{"rr_restore_fails", func() { e.caseRecoveryRestoreFails(t, "rr_restore_fails") }},
		{"rr_crash_after_tag", func() { e.caseRecoveryCrashAfterTag(t, "rr_crash_after_tag") }},
		{"rr_off", func() { e.caseRecoveryOff(t, "rr_off") }},
	}
}
