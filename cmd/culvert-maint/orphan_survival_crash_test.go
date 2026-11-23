//go:build lifecycle_conformance

package main

// orphan_survival_crash_test.go — orphan-survival crash vectors (SHADOW).
//
// The crash rig in startup_crash_recovery_test.go kills the agent AND the
// model command the agent was blocked in (crashRig.kill). So every existing
// crash vector runs in the world where the in-flight `docker` dies with the
// agent. The kernel does not do that: a SIGKILLed parent's child is
// re-parented and keeps running, and the runner puts every child in its own
// process group (runner/procgroup_linux.go), so nothing aimed at the agent's
// group reaches it either.
//
// These vectors kill ONLY the agent, prove from /proc that the model command
// is alive and re-parented, restart the agent and record what it reports,
// then release the orphan, record the model's Docker truth, and read the
// reports again (and after one more restart). Per kill point they classify:
//
//	Q1 durable report vs live view: whether a durable statement (operation
//	   result, audit entry) is contradicted by the orphan's late effect
//	   ("durable_stale"), else whether the live /v1/status view read after the
//	   restart changed once the orphan finished ("live_changed") or not
//	   ("live_stable"). On this model "durable_stale" cannot occur: the
//	   durable docker_state is "unchanged" only at the three pre-barrier points,
//	   whose in-flight commands change neither tag nor container, and it is
//	   already "indeterminate" wherever the orphan can act. So Q1 establishes
//	   that the durable report is conservative, and whether a conclusive-looking
//	   live read changes afterwards. It does not test staleness of a durable
//	   report that could have been wrong.
//	Q2 tag residue after the fact: the fixed tag moves after startup reported
//	   it, and whether /v1/status still says so;
//	Q3 false success: an operation admitted while the orphan is alive reports
//	   success, then the orphan changes what that operation left behind.
//	Q4 (draft #2039, startup convergence) is not measurable on main, which
//	   has no convergence mode.
//
// Findings are pinned in orphanExpectations, every entry "open": the test
// fails when reality stops matching the table in either direction, never
// because a finding exists. It runs only under the lifecycle_conformance
// build tag, from test/lifecycle-conformance/run.sh.
//
// Model limits (properties of the model, not findings):
//   - the model's `compose up` reads the fixed tag when it is RELEASED; a real
//     in-flight `compose up` has already resolved its image;
//   - the model's mutating commands write nothing to stdout/stderr after the
//     hold. The runner captures a child's output through pipes, so once the
//     agent is dead a real orphan gets SIGPIPE/EPIPE on its next write (real
//     `docker compose up` writes progress);
//   - an orphaned `pull` changes the local image store, which the model's
//     truth (tag, container) does not represent.
// Nothing here says how real Docker, systemd (KillMode) or sudo behave.
//
// Negative controls that live in the code (the rest are run by hand and
// recorded in the pull request). Any of them failing is INVALID, which
// run.sh reports as incomplete (exit 2), never as a finding:
//   - A1/A2: a vector whose in-flight command mutates must show the model
//     change after release, one that only reads must not;
//   - completion: a mutating orphan must write the variant script's
//     completion marker after release, in both flows;
//   - A3: TestOrphanSurvival_ReapedControl runs the same vectors with the
//     orphan reaped (today's kill()) and requires no divergence at all;
//   - A5: liveness comes from /proc (state, ppid, cmdline), never from the
//     agent or the model's own files;
//   - the report reads must answer 200, and at R1 /v1/status must list
//     exactly the interrupted op, so its later absence is evidence.

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// orphanRelease is what a held model command does once released: leave blk()
// and finish the command it was in.
const orphanRelease = "return 0"

// orphanHoldSeconds bounds the hold: if no release comes (a run killed before
// its cleanups), the held command gives up on its own, like the shared
// script's `exec sleep 300`, exits 70 and mutates nothing.
const orphanHoldSeconds = 300

// orphanModelScript is fakeDockerScript with two changes: a blocked command
// waits (bounded) for the orphan_release file and then carries on, instead of
// `exec sleep 300`; and a command that was held writes orphan_done.<blk> when
// it reaches the script's final `exit 0`, i.e. after its effect. The shared
// script and every existing test are untouched; only the tests in this file
// install this variant.
func orphanModelScript(t *testing.T, model string) string {
	t.Helper()
	const held = "    exec sleep 300\n"
	const tail = "\nexit 0\n"
	if strings.Count(fakeDockerScript, held) != 1 || strings.Count(fakeDockerScript, tail) != 1 || !strings.HasSuffix(fakeDockerScript, tail) {
		t.Fatalf("INVALID: fakeDockerScript changed shape (want one %q and a final %q) — update the orphan variant", held, tail)
	}
	// `sleep 0.05` where fractional sleep works, else `sleep 1`: slower, never
	// a busy loop. The expiry path exits non-zero, writes orphan_expired and
	// never orphan_done, so it cannot pass for a release.
	hold := fmt.Sprintf(`    HELD=$1; _end=$(( $(date +%%s) + %d ))
    while [ ! -f "$S/orphan_release" ]; do
      if [ "$(date +%%s)" -ge "$_end" ]; then echo "$1" >> "$S/orphan_expired"; exit 70; fi
      sleep 0.05 2>/dev/null || sleep 1
    done
    `, orphanHoldSeconds) + orphanRelease + "\n"
	script := strings.Replace(fakeDockerScript, held, hold, 1)
	script = strings.TrimSuffix(script, tail) + "\n" + `if [ -n "$HELD" ]; then echo $$ > "$S/orphan_done.$HELD"; fi` + tail
	return strings.NewReplacer("__STATE__", model, "__REPO__", crashRepo).Replace(script)
}

// orphanExpect is one kill point's pinned outcome. status is always "open":
// each entry records an observation for the owner, not a verdict.
type orphanExpect struct {
	mutates  bool   // the in-flight command changes the model once released (A1/A2)
	q1, q2   string // report flow
	q3       string // later-operation flow
	status   string
	observed string
}

// orphanExpectations pins what the vectors measured. A change in either
// direction (a finding disappears, or a new one appears) fails the test so it
// is updated deliberately.
var orphanExpectations = map[string]orphanExpect{
	"admitted_at_capture": {false, "live_stable", "none", "none", "open",
		"in-flight `compose ps` is read-only in the model; no divergence"},
	"captured_at_resolve": {false, "live_stable", "none", "none", "open",
		"in-flight `manifest inspect` is read-only; no divergence"},
	"resolved_at_pull": {false, "live_stable", "none", "none", "open",
		"in-flight `pull` changes no tag or container in the model (its effect on the image store is not modelled); no divergence"},
	"barrier_before_tag": {true, "live_changed", "residue_reported", "false_success_unreported", "open",
		"durable report already says indeterminate; orphan `docker tag` moves the tag after restart and /v1/status shows it while the record exists, " +
			"but a rollback admitted meanwhile succeeds, retires the record, and the tag then moves with nothing reporting it"},
	"tag_moved_before_up": {true, "live_changed", "none", "none", "open",
		"durable report already says indeterminate; orphan `compose up` recreates the container on the target after restart (running_image prior -> target). " +
			"Q3 none is a MODEL property: the model's up reads the tag at release, after the rollback re-pinned it; a real in-flight up has already resolved its image"},
	"up_done_unrecorded": {false, "live_stable", "none", "none", "open",
		"the up had already landed before the kill; the orphan has nothing left to change"},
	"restarted_at_verify": {false, "live_stable", "none", "none", "open",
		"in-flight `compose ps` is read-only; no divergence"},
}

// orphanKillPoints is every existing kill point at which a docker command is
// in flight: all of killPoints() except the health gate.
func orphanKillPoints() []killPoint {
	var out []killPoint
	for _, kp := range killPoints() {
		if kp.point != "health" {
			out = append(out, kp)
		}
	}
	return out
}

// heldCommand is the blk() name of the command a kill point holds.
func heldCommand(kp *killPoint) string {
	return strings.SplitN(kp.point, ":", 2)[0]
}

type dockerTruth struct{ Pinned, Running string }

func (d dockerTruth) String() string {
	return "tag=" + imgName(d.Pinned) + " ctr=" + imgName(d.Running)
}

func imgName(id string) string {
	switch id {
	case imgA:
		return "A"
	case imgB:
		return "B"
	case "":
		return "-"
	}
	return "?"
}

func (r *crashRig) truth() dockerTruth {
	return dockerTruth{Pinned: r.read("pinned"), Running: r.read("running")}
}

// reportSnap is what the agent says at one moment. The op and audit fields are
// durable (written once at startup); the status fields are read live.
type reportSnap struct {
	OpCode            int
	OpState           string
	OpDockerState     string
	AuditEntries      int
	AuditDockerState  string
	Entries           int
	OwnEntry          bool
	StatusDockerState string
	RunningImage      string
	PinnedMatch       string
}

func (s reportSnap) String() string {
	return fmt.Sprintf("op=%d/%s durable.docker_state=%s audit=%d/%s status.entries=%d status.docker_state=%s running_image=%s pinned.matches_running=%s",
		s.OpCode, s.OpState, s.OpDockerState, s.AuditEntries, s.AuditDockerState, s.Entries, s.StatusDockerState, s.RunningImage, s.PinnedMatch)
}

// snapshot reads the reports. Any answer other than 200 (404 for an op that a
// later success retired) is INVALID: an error must never read as "nothing
// reported".
func (r *crashRig) snapshot(opID string) reportSnap {
	r.t.Helper()
	var s reportSnap
	var op opView
	s.OpCode = r.get("/v1/operations/"+opID, &op)
	if s.OpCode != http.StatusOK && s.OpCode != http.StatusNotFound {
		r.t.Fatalf("INVALID: GET /v1/operations/%s answered HTTP %d", opID, s.OpCode)
	}
	s.OpState = op.State
	if intr, ok := op.Result["interrupted"].(map[string]interface{}); ok {
		s.OpDockerState, _ = intr["docker_state"].(string) //nolint:errcheck // absent → ""
	}
	var av auditView
	if code := r.get("/v1/audit?limit=1000", &av); code != http.StatusOK {
		r.t.Fatalf("INVALID: GET /v1/audit answered HTTP %d", code)
	}
	for _, e := range av.Events {
		if e.OpID == opID && e.FailureReason == "agent_restart_interrupted" {
			s.AuditEntries++
			s.AuditDockerState, _ = e.Params["docker_state"].(string) //nolint:errcheck // absent → ""
		}
	}
	var st statusView
	if code := r.get("/v1/status", &st); code != http.StatusOK {
		r.t.Fatalf("INVALID: GET /v1/status answered HTTP %d", code)
	}
	s.Entries = len(st.Interrupted)
	for i := range st.Interrupted {
		if st.Interrupted[i].OpID == opID {
			s.OwnEntry = true
			s.StatusDockerState = st.Interrupted[i].DockerState
			s.RunningImage = st.Interrupted[i].RunningImage
		}
	}
	s.PinnedMatch = "absent"
	if st.PinnedTag != nil && st.PinnedTag.MatchesRunning != nil {
		s.PinnedMatch = strconv.FormatBool(*st.PinnedTag.MatchesRunning)
	}
	return s
}

// procStat reads a process's state and parent from /proc/<pid>/stat.
func procStat(pid int) (state byte, ppid int, ok bool) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, 0, false
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')') // comm may contain spaces and parens
	if i < 0 || i+2 >= len(s) {
		return 0, 0, false
	}
	f := strings.Fields(s[i+2:])
	if len(f) < 2 || f[0] == "" {
		return 0, 0, false
	}
	ppid, err = strconv.Atoi(f[1])
	return f[0][0], ppid, err == nil
}

func procAlive(pid int) bool {
	st, _, ok := procStat(pid)
	return ok && st != 'Z' && st != 'X'
}

// runsShim reports whether pid's command line still names the shim, so a
// reused PID is never mistaken for (or killed as) the orphan.
func runsShim(pid int, shim string) bool {
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	return err == nil && strings.Contains(string(cmdline), shim)
}

// modelChildOf finds, from /proc alone, the model command the agent is
// running: a direct child of agentPid whose command line runs the shim.
func modelChildOf(agentPid int, shim string) (int, error) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}
	var found []int
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if _, ppid, ok := procStat(pid); !ok || ppid != agentPid {
			continue
		}
		if runsShim(pid, shim) {
			found = append(found, pid)
		}
	}
	if len(found) != 1 {
		return 0, fmt.Errorf("want exactly one model child of agent %d, found %v", agentPid, found)
	}
	return found[0], nil
}

func waitProc(pid int, alive bool, budget time.Duration) bool {
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if procAlive(pid) == alive {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return procAlive(pid) == alive
}

// vectorObs is everything one run of a vector observed.
type vectorObs struct {
	orphanPID, orphanPPID, agentPID int
	atKill, atRestart, afterOp      dockerTruth
	afterRelease                    dockerTruth
	r1, r2, r3                      reportSnap
	laterKind, laterState           string
	completed                       bool // the held command wrote orphan_done after release
}

// orphanRun drives one vector. reaped selects today's kill() (control);
// laterOp admits and completes the operator's next operation while the
// orphan is alive, before releasing it.
type orphanRun struct {
	t       *testing.T
	r       *crashRig
	kp      *killPoint
	shim    string
	reaped  bool
	laterOp bool
	pid     int // the live orphan; zeroed once it is known to have exited
	obs     vectorObs
}

func newOrphanRun(t *testing.T, kp *killPoint, reaped, laterOp bool) *orphanRun {
	t.Helper()
	r := newCrashRig(t)
	shim := filepath.Join(r.shimDir, "docker")
	if err := os.WriteFile(shim, []byte(orphanModelScript(t, r.model)), 0o700); err != nil { // #nosec G306 -- must be executable
		t.Fatal(err)
	}
	o := &orphanRun{t: t, r: r, kp: kp, shim: shim, reaped: reaped, laterOp: laterOp}
	// Registered after newCrashRig's, so it runs first: never leave a held
	// model command behind a failed run, and never signal a reused PID.
	t.Cleanup(func() {
		_ = os.WriteFile(filepath.Join(r.model, "orphan_release"), []byte("1\n"), 0o600)
		if o.pid > 1 && procAlive(o.pid) && runsShim(o.pid, o.shim) {
			_ = syscall.Kill(o.pid, syscall.SIGKILL)
		}
		_ = os.Remove(filepath.Join(r.model, "blocked"))
	})
	return o
}

// crash blocks the upgrade at the kill point and kills the agent: only the
// agent (orphan world) or, for the control, the agent and the model command.
func (o *orphanRun) crash() string {
	t, r := o.t, o.r
	t.Helper()
	r.put("block_on", o.kp.point)
	opID := r.applyUpgrade()
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(r.model, "blocked")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("INVALID: the apply flow never reached %q; agent output:\n%s", o.kp.point, r.logs.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	o.obs.agentPID = r.cmd.Process.Pid
	pid, err := modelChildOf(o.obs.agentPID, o.shim)
	if err != nil {
		t.Fatalf("INVALID: the kill did not land in a docker command: %v", err)
	}
	o.pid, o.obs.orphanPID = pid, pid
	if o.reaped {
		r.kill() // today's crash: also reaps the model command
		if !waitProc(pid, false, 5*time.Second) {
			t.Fatalf("INVALID control: model command %d survived the reaping kill()", pid)
		}
		o.pid = 0
	} else {
		_ = r.cmd.Process.Signal(syscall.SIGKILL)
		_ = r.cmd.Wait()
		r.cmd = nil
		_ = os.Remove(filepath.Join(r.model, "block_on"))
		_ = os.Remove(filepath.Join(r.model, "blocked"))
		o.requireOrphan("after the agent was killed")
		_, o.obs.orphanPPID, _ = procStat(pid)
	}
	o.obs.atKill = r.truth()
	return opID
}

// requireOrphan is A5: the model command is alive, still the shim, and no
// longer the dead agent's child, by /proc alone.
func (o *orphanRun) requireOrphan(when string) {
	o.t.Helper()
	st, ppid, ok := procStat(o.pid)
	if !ok || st == 'Z' || st == 'X' {
		o.t.Fatalf("INVALID: model command %d not alive %s (state %q)", o.pid, when, st)
	}
	if !runsShim(o.pid, o.shim) {
		o.t.Fatalf("INVALID: PID %d no longer runs the model shim %s", o.pid, when)
	}
	if ppid == o.obs.agentPID {
		o.t.Fatalf("INVALID: model command %d still parented by the dead agent %d %s", o.pid, o.obs.agentPID, when)
	}
}

// later admits the operator's next operation, as /v1/status advises it, and
// runs it to completion while the orphan is still alive.
func (o *orphanRun) later() {
	t, r := o.t, o.r
	t.Helper()
	path, body := "/v1/upgrades/apply", map[string]interface{}{"image_ref": refB}
	o.obs.laterKind = "upgrade->B"
	if o.obs.r1.StatusDockerState != "unchanged" {
		path, body = "/v1/rollbacks", map[string]interface{}{"mode": "image", "image_ref": refA}
		o.obs.laterKind = "rollback->A"
	}
	var op opView
	if code := r.post(path, body, &op); code != http.StatusAccepted {
		o.obs.laterState = "rejected:" + strconv.Itoa(code)
		return
	}
	done := r.waitOp(op.OpID)
	o.obs.laterState = done.State
	if !o.reaped {
		o.requireOrphan("when the later operation finished")
	}
}

// release lets the orphan finish and waits for it, then records whether the
// held command reached its completion marker.
func (o *orphanRun) release() {
	t, r := o.t, o.r
	t.Helper()
	r.put("orphan_release", "1")
	if o.pid != 0 {
		if !waitProc(o.pid, false, 10*time.Second) {
			t.Fatalf("INVALID: released model command %d did not exit", o.pid)
		}
		o.pid = 0
	}
	_, err := os.Stat(filepath.Join(r.model, "orphan_done."+heldCommand(o.kp)))
	o.obs.completed = err == nil
	if exp := r.read("orphan_expired"); exp != "" {
		t.Fatalf("INVALID: a held model command hit its hold limit instead of being released: %s", exp)
	}
}

func (o *orphanRun) run() vectorObs {
	t, r := o.t, o.r
	t.Helper()
	r.start()
	opID := o.crash()

	r.clearCalls()
	r.start()
	o.obs.r1 = r.snapshot(opID)
	// The "entries" signal must be live before its absence is used as evidence.
	if o.obs.r1.Entries != 1 || !o.obs.r1.OwnEntry {
		t.Fatalf("INVALID: at restart /v1/status lists %d interrupted op(s) (own=%v), want exactly the crashed op", o.obs.r1.Entries, o.obs.r1.OwnEntry)
	}
	o.obs.atRestart = r.truth()
	if m := r.mutatingCalls(); len(m) != 0 {
		t.Errorf("restart issued state-changing docker commands: %v", m)
	}
	if !o.reaped {
		o.requireOrphan("while the restarted agent reported")
	}
	o.obs.afterOp = o.obs.atRestart
	if o.laterOp {
		o.later()
		o.obs.afterOp = r.truth()
	}

	o.release()
	o.obs.afterRelease = r.truth()
	o.obs.r2 = r.snapshot(opID)
	r.kill()
	r.start()
	o.obs.r3 = r.snapshot(opID)
	return o.obs
}

// classifyReport answers Q1 and Q2 for a report-flow run.
func classifyReport(o *vectorObs) (q1, q2 string) {
	initial := dockerTruth{Pinned: imgA, Running: imgA}
	switch {
	case o.r2.OpDockerState == "unchanged" && o.afterRelease != initial,
		o.r2.AuditDockerState == "unchanged" && o.afterRelease != initial:
		q1 = "durable_stale" // unreachable on this model; see the file comment
	case o.r1.RunningImage != o.r2.RunningImage || o.r1.PinnedMatch != o.r2.PinnedMatch:
		q1 = "live_changed"
	default:
		q1 = "live_stable"
	}
	q2 = tagResidue(o, o.atRestart)
	return q1, q2
}

func tagResidue(o *vectorObs, base dockerTruth) string {
	if o.afterRelease.Pinned == base.Pinned {
		return "none"
	}
	if o.r2.Entries > 0 && o.r2.PinnedMatch == "false" && o.r3.Entries > 0 && o.r3.PinnedMatch == "false" {
		return "residue_reported"
	}
	return "residue_unreported"
}

// classifyLater answers Q3 for a later-operation run.
func classifyLater(o *vectorObs) string {
	if o.laterState != "succeeded" {
		return "later_op_" + o.laterState
	}
	if o.afterRelease == o.afterOp {
		return "none"
	}
	if o.r2.Entries == 0 && o.r3.Entries == 0 {
		return "false_success_unreported"
	}
	return "false_success_reported"
}

// checkSensitivity is A1/A2 (report flow) and the completion check (both
// flows): the vector must exercise exactly the hazard it claims to, or the
// run is invalid.
func checkSensitivity(t *testing.T, kp *killPoint, exp *orphanExpect, o *vectorObs, reportFlow bool) {
	t.Helper()
	if exp.mutates && !o.completed {
		t.Fatalf("INVALID: %s's mutating in-flight command did not reach its completion marker after release (later-op flow=%v)", kp.name, !reportFlow)
	}
	if !reportFlow {
		return
	}
	moved := o.afterRelease != o.atRestart
	if exp.mutates && !moved {
		t.Fatalf("INVALID (A1): %s's in-flight command mutates, but the model did not change after the orphan exited (%s at restart, %s after) — the rig is not exercising orphan survival",
			kp.name, o.atRestart, o.afterRelease)
	}
	if !exp.mutates && moved {
		t.Fatalf("INVALID (A2): %s's in-flight command only reads, but the model changed after the orphan exited (%s -> %s)", kp.name, o.atRestart, o.afterRelease)
	}
}

func checkTableCoversKillPoints(t *testing.T) {
	t.Helper()
	kps := orphanKillPoints()
	seen := map[string]bool{}
	for i := range kps {
		if _, ok := orphanExpectations[kps[i].name]; !ok {
			t.Errorf("INVALID: kill point %s has no orphanExpectations entry", kps[i].name)
		}
		seen[kps[i].name] = true
	}
	for name, e := range orphanExpectations {
		if !seen[name] {
			t.Errorf("INVALID: orphanExpectations has %s, which is not a docker-in-flight kill point", name)
		}
		if e.status != "open" {
			t.Errorf("INVALID: %s: status %q; only the owner closes a finding, in the change that fixes it", name, e.status)
		}
	}
	if t.Failed() {
		t.FailNow()
	}
	t.Logf("orphan-survival vectors: %d kill points with a docker command in flight (crashRig.kill reaps that command in every existing crash test)", len(kps))
}

// TestOrphanSurvival_CrashVectors runs, per kill point with a docker command in
// flight, the report flow (Q1, Q2, A1/A2) and the later-operation flow (Q3),
// and compares the classification with orphanExpectations.
func TestOrphanSurvival_CrashVectors(t *testing.T) {
	checkTableCoversKillPoints(t)
	for _, kp := range orphanKillPoints() {
		t.Run(kp.name, func(t *testing.T) {
			exp := orphanExpectations[kp.name]
			rep := newOrphanRun(t, &kp, false, false).run()
			checkSensitivity(t, &kp, &exp, &rep, true)
			q1, q2 := classifyReport(&rep)
			t.Logf("VECTOR %s report: orphan pid=%d ppid=%d (agent %d) completed=%v | kill %s | restart %s | released %s\n  R1 %s\n  R2 %s\n  R3 %s",
				kp.name, rep.orphanPID, rep.orphanPPID, rep.agentPID, rep.completed, rep.atKill, rep.atRestart, rep.afterRelease, rep.r1, rep.r2, rep.r3)

			lat := newOrphanRun(t, &kp, false, true).run()
			checkSensitivity(t, &kp, &exp, &lat, false)
			q3 := classifyLater(&lat)
			t.Logf("VECTOR %s later: %s=%s while orphan %d alive, completed=%v | restart %s | after op %s | released %s\n  R2 %s\n  R3 %s",
				kp.name, lat.laterKind, lat.laterState, lat.orphanPID, lat.completed, lat.atRestart, lat.afterOp, lat.afterRelease, lat.r2, lat.r3)

			t.Logf("CLASSIFY %s: mutates=%v Q1=%s Q2=%s Q3=%s (expected %s/%s/%s, %s)", kp.name, exp.mutates, q1, q2, q3, exp.q1, exp.q2, exp.q3, exp.status)
			if q1 != exp.q1 || q2 != exp.q2 || q3 != exp.q3 {
				t.Errorf("EXPECTATION MISMATCH %s: measured Q1=%s Q2=%s Q3=%s, pinned Q1=%s Q2=%s Q3=%s — update orphanExpectations deliberately (pinned: %s)",
					kp.name, q1, q2, q3, exp.q1, exp.q2, exp.q3, exp.observed)
			}
		})
	}
}

// TestOrphanSurvival_ReapedControl is A3: the same vectors with the model
// command reaped at the crash, as every existing crash test does. Nothing may
// diverge, so whatever the orphan vectors find comes from survival alone.
func TestOrphanSurvival_ReapedControl(t *testing.T) {
	for _, kp := range orphanKillPoints() {
		t.Run(kp.name, func(t *testing.T) {
			for _, laterOp := range []bool{false, true} {
				o := newOrphanRun(t, &kp, true, laterOp).run()
				var got []string
				if laterOp {
					got = append(got, classifyLater(&o))
				} else {
					q1, q2 := classifyReport(&o)
					got = append(got, q1, q2)
				}
				t.Logf("CONTROL %s later=%v: restart %s after-op %s released %s completed=%v → %v", kp.name, laterOp, o.atRestart, o.afterOp, o.afterRelease, o.completed, got)
				if o.afterRelease != o.afterOp || o.completed {
					t.Errorf("A3: with the model command reaped, Docker still changed or the held command completed after release (%s -> %s, completed=%v)", o.afterOp, o.afterRelease, o.completed)
				}
				for _, g := range got {
					if g != "none" && g != "live_stable" {
						t.Errorf("A3: control classified %q, want none/live_stable", g)
					}
				}
			}
		})
	}
}
