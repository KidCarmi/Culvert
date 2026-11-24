package main

// startup_restore_crash_test.go — an agent killed in the middle of a restore.
//
// Same rig as startup_crash_recovery_test.go: the real agent binary, the real
// socket, SIGKILL, a restart against the same state_dir, and the Docker model
// as the only substitute. The model's `compose down` stops the proxy, its
// restore commit replaces a content marker, and both can be made to block so
// the kill lands at a known boundary.
//
// Before restore.commit was journaled, every one of these kills left: the
// operation answering 404, nothing under interrupted_operations, an audit log
// ending at `started`, and the proxy down. TestRestoreCrash_NegativeControl
// reproduces that state and shows the assertions here detect it.
//
// Contract pinned here (docs/adr/0061, addendum of 2026-11-24):
//   - an interrupted restore is reported, durably, with the stage it reached
//     and what that stage establishes about the stack and the data;
//   - the restarted agent runs no docker command on account of the record;
//   - the report survives further restarts and is audited exactly once;
//   - a later restore that commits and passes its health check retires it, and
//     never retires an interrupted upgrade.

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// restoreView is the restore-class part of an interrupted-operation entry.
type restoreView struct {
	OpID           string `json:"op_id"`
	Kind           string `json:"kind"`
	Mode           string `json:"mode"`
	JournalPhase   string `json:"journal_phase"`
	DockerState    string `json:"docker_state"`
	RestoreStage   string `json:"restore_stage"`
	StackTouched   *bool  `json:"stack_touched"`
	DataChanged    string `json:"data_changed"`
	PreviousState  string `json:"previous_state"`
	RestartSafe    string `json:"restart_safe"`
	OperatorAction string `json:"operator_action"`
	DockerActed    *bool  `json:"docker_reconciled"`
	StartsSeen     int    `json:"agent_starts_seen"`
}

type restoreStatusView struct {
	StackUp     bool          `json:"compose_stack_up"`
	Interrupted []restoreView `json:"interrupted_operations"`
}

// restoreKill is one boundary of the restore flow, and what must be reported
// after a kill there.
type restoreKill struct {
	name  string
	point string // "<model command>:<nth>", or "health"
	stage string
	// What the report must say.
	stackTouched bool
	dataChanged  string
	previous     string
	// What the model must show after the kill: is the proxy still running, and
	// did the commit replace the data.
	modelRunning  bool
	modelRestored bool
}

func restoreKills() []restoreKill {
	return []restoreKill{
		// Before the stop: the read-only preflight is running, the proxy serves.
		{"before_stop_in_preflight", "dryrun:1", "preflight", false, "no", "in_place", true, false},
		// The stop was recorded and the docker command started, but it has not
		// stopped anything yet. The report says what the operation set out to do.
		{"stop_requested", "down_before:1", "stopping", true, "no", "in_place", true, false},
		// After the stop, before the commit.
		{"after_stop_before_commit", "down_after:1", "stopping", true, "no", "in_place", false, false},
		// During the commit, before it changed anything...
		{"during_commit_before_swap", "commit_before:1", "committing", true, "unknown", "recoverable_at_next_proxy_start_or_manual", false, false},
		// ...and after it changed the data but before the agent learned the
		// result. The journal cannot tell these two apart, and says so.
		{"during_commit_after_swap", "commit_after:1", "committing", true, "unknown", "recoverable_at_next_proxy_start_or_manual", false, true},
		// After the commit returned, before the stack is started.
		{"after_commit_before_start", "up_before:1", "starting", true, "yes", "kept_in_backup_dir", false, true},
		// `compose up` has started the proxy and has not returned.
		{"during_start", "up_after:1", "starting", true, "yes", "kept_in_backup_dir", true, true},
		// After the start, before the health check passed.
		{"after_start_before_health", "health", "started", true, "yes", "kept_in_backup_dir", true, true},
	}
}

// submitRestore posts a restore.commit (or, with dataRollback, a rollbacks
// mode=data) and returns its op id.
func (r *crashRig) submitRestore(dataRollback bool) string {
	r.t.Helper()
	path, body := "/v1/restores/commit", map[string]interface{}{"path": "/backup/b.tar.gz", "mode": "full"}
	if dataRollback {
		path, body = "/v1/rollbacks", map[string]interface{}{"mode": "data", "filename": "b.tar.gz"}
	}
	var op opView
	if code := r.post(path, body, &op); code != http.StatusAccepted {
		r.t.Fatalf("%s: HTTP %d; agent output:\n%s", path, code, r.logs.String())
	}
	return op.OpID
}

// crashRestoreAt drives a real restore until point and SIGKILLs the agent there.
func (r *crashRig) crashRestoreAt(point string, dataRollback bool) string {
	r.t.Helper()
	if point == "health" {
		r.healthMu.Lock()
		r.healthHang = true
		r.healthMu.Unlock()
	} else {
		r.put("block_on", point)
	}
	opID := r.submitRestore(dataRollback)
	deadline := time.Now().Add(30 * time.Second)
	reached := false
	for !reached && time.Now().Before(deadline) {
		if point == "health" {
			select {
			case <-r.healthHit:
				reached = true
			case <-time.After(50 * time.Millisecond):
			}
			continue
		}
		if _, err := os.Stat(filepath.Join(r.model, "blocked")); err == nil {
			reached = true
			continue
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !reached {
		r.t.Fatalf("the restore flow never reached %q; agent output:\n%s\ncalls:\n%s", point, r.logs.String(), r.read("calls.log"))
	}
	r.kill()
	r.healthMu.Lock()
	r.healthHang = false
	r.healthMu.Unlock()
	return opID
}

// allCalls returns every docker command the model saw since the last clear.
func (r *crashRig) allCalls() []string {
	var out []string
	for _, line := range strings.Split(r.read("calls.log"), "\n") {
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}

// restoreMutatingCalls is mutatingCalls plus the restore commit itself.
func (r *crashRig) restoreMutatingCalls() []string {
	out := r.mutatingCalls()
	for _, line := range r.allCalls() {
		if strings.Contains(" "+line+" ", " --confirm ") {
			out = append(out, line)
		}
	}
	return out
}

// interruptedRestoreProblems checks everything an operator must be able to see
// about the interrupted restore opID after a restart, and returns what is
// wrong. It is a function returning findings, not a set of t.Error calls, so
// that the negative control can run it against the un-journaled state and
// require it to object.
func interruptedRestoreProblems(r *crashRig, opID, kind string, tc *restoreKill, wantStarts int) []string {
	bad := restoreOpProblems(r, opID, kind, tc)

	var st restoreStatusView
	if code := r.get("/v1/status", &st); code != http.StatusOK {
		return append(bad, sprintf("GET /v1/status: HTTP %d", code))
	}
	if len(st.Interrupted) != 1 {
		bad = append(bad, sprintf("status.interrupted_operations has %d entries, want 1", len(st.Interrupted)))
	} else {
		bad = append(bad, restoreEntryProblems(&st.Interrupted[0], opID, kind, tc, wantStarts)...)
	}
	// The one signal that existed before, and still must be true.
	if st.StackUp != tc.modelRunning {
		bad = append(bad, sprintf("compose_stack_up = %v, want %v", st.StackUp, tc.modelRunning))
	}
	if n := r.interruptedAudits(opID); n != 1 {
		bad = append(bad, sprintf("audit has %d failed(agent_restart_interrupted) entries for the op, want 1", n))
	}
	return bad
}

// restoreOpProblems: GET /v1/operations/{id} for the interrupted restore.
func restoreOpProblems(r *crashRig, opID, kind string, tc *restoreKill) []string {
	var op opView
	if code := r.get("/v1/operations/"+opID, &op); code != http.StatusOK {
		return []string{sprintf("GET /v1/operations/%s: HTTP %d, want 200", opID, code)}
	}
	var bad []string
	if op.State != "failed" || op.FailureReason != "agent_restart_interrupted" {
		bad = append(bad, sprintf("op = %s(%s), want failed(agent_restart_interrupted)", op.State, op.FailureReason))
	}
	if op.Kind != kind {
		bad = append(bad, sprintf("op.kind = %q, want %q", op.Kind, kind))
	}
	intr, _ := op.Result["interrupted"].(map[string]interface{}) //nolint:errcheck // absent → nil map, reported below
	if intr["restore_stage"] != tc.stage || intr["data_changed"] != tc.dataChanged || intr["stack_touched"] != tc.stackTouched {
		bad = append(bad, sprintf("op.result.interrupted = stage %v data_changed %v stack_touched %v, want %s/%s/%v",
			intr["restore_stage"], intr["data_changed"], intr["stack_touched"], tc.stage, tc.dataChanged, tc.stackTouched))
	}
	return bad
}

// restoreEntryProblems: one interrupted_operations entry of GET /v1/status.
func restoreEntryProblems(got *restoreView, opID, kind string, tc *restoreKill, wantStarts int) []string {
	var bad []string
	add := func(ok bool, format string, args ...interface{}) {
		if !ok {
			bad = append(bad, sprintf(format, args...))
		}
	}
	add(got.OpID == opID && got.Kind == kind, "status entry is %s %s, want %s %s", got.Kind, got.OpID, kind, opID)
	add(got.RestoreStage == tc.stage, "restore_stage = %q, want %q", got.RestoreStage, tc.stage)
	add(got.StackTouched != nil && *got.StackTouched == tc.stackTouched, "stack_touched = %v, want %v", got.StackTouched, tc.stackTouched)
	add(got.DataChanged == tc.dataChanged && got.PreviousState == tc.previous,
		"data_changed/previous_state = %q/%q, want %q/%q", got.DataChanged, got.PreviousState, tc.dataChanged, tc.previous)
	add(got.DockerState == "data_indeterminate" && got.JournalPhase == "admitted",
		"docker_state/journal_phase = %q/%q, want data_indeterminate/admitted", got.DockerState, got.JournalPhase)
	add(got.DockerActed != nil && !*got.DockerActed, "docker_reconciled must be stated false, got %v", got.DockerActed)
	add(got.RestartSafe != "" && got.OperatorAction != "", "restart_safe or operator_action is empty")
	add(got.StartsSeen == wantStarts, "agent_starts_seen = %d, want %d", got.StartsSeen, wantStarts)
	return bad
}

func sprintf(format string, args ...interface{}) string {
	return strings.ReplaceAll(fmt.Sprintf(format, args...), "\n", " ")
}

// TestRestoreCrash_EveryKillPoint SIGKILLs a real restore.commit at each
// boundary of its flow and restarts the agent twice.
func TestRestoreCrash_EveryKillPoint(t *testing.T) {
	kills := restoreKills()
	for i := range kills {
		tc := &kills[i]
		t.Run(tc.name, func(t *testing.T) { runRestoreKill(t, tc) })
	}
}

// modelProblems compares the Docker model with what the kill point must leave.
func modelProblems(r *crashRig, tc *restoreKill) []string {
	var bad []string
	if got := r.read("running") != ""; got != tc.modelRunning {
		bad = append(bad, sprintf("model: proxy running = %v, want %v", got, tc.modelRunning))
	}
	if got := r.read("data") == "restored"; got != tc.modelRestored {
		bad = append(bad, sprintf("model: data replaced = %v, want %v", got, tc.modelRestored))
	}
	return bad
}

func runRestoreKill(t *testing.T, tc *restoreKill) {
	t.Helper()
	r := newCrashRig(t)
	r.start()
	opID := r.crashRestoreAt(tc.point, false)

	if bad := modelProblems(r, tc); len(bad) != 0 {
		t.Fatalf("after the kill: %v", bad)
	}
	if files := r.journalFiles(); len(files) != 1 || files[0] != opID {
		t.Fatalf("journal after the crash = %v, want exactly [%s]", files, opID)
	}

	// First restart. Until something asks for the status, the agent must not
	// have run ANY docker command: startup reports from the journal alone.
	r.clearCalls()
	r.start()
	if code := r.get("/v1/operations/"+opID, nil); code != http.StatusOK {
		t.Fatalf("GET op after restart: HTTP %d, want 200", code)
	}
	if c := r.allCalls(); len(c) != 0 {
		t.Errorf("the restarted agent ran docker commands on its own: %v", c)
	}
	for _, p := range interruptedRestoreProblems(r, opID, "restore.commit", tc, 1) {
		t.Errorf("first restart: %s", p)
	}

	// Second restart: reported again, counted, not audited again.
	r.kill()
	r.start()
	for _, p := range interruptedRestoreProblems(r, opID, "restore.commit", tc, 2) {
		t.Errorf("second restart: %s", p)
	}

	// Neither restart, nor the status reads, changed Docker or the data.
	if m := r.restoreMutatingCalls(); len(m) != 0 {
		t.Errorf("restarts issued state-changing docker commands: %v", m)
	}
	for _, p := range modelProblems(r, tc) {
		t.Errorf("changed across the restarts: %s", p)
	}
	if files := r.journalFiles(); len(files) != 1 || files[0] != opID {
		t.Errorf("journal after two restarts = %v, want the record kept", files)
	}
}

// TestRestoreCrash_LaterRestoreRetiresTheRecord: the operator submits the
// restore again. It commits, starts the stack, passes the health check, and
// its success retires the interrupted record: status lists nothing, the old
// operation is not re-reported by a later start, and its audit entry stays one.
func TestRestoreCrash_LaterRestoreRetiresTheRecord(t *testing.T) {
	for _, point := range []string{"down_after:1", "commit_before:1", "up_before:1"} {
		t.Run(point, func(t *testing.T) { runLaterRestoreRetires(t, point) })
	}
}

func runLaterRestoreRetires(t *testing.T, point string) {
	t.Helper()
	r := newCrashRig(t)
	r.start()
	oldOp := r.crashRestoreAt(point, false)
	r.start()

	newOp := r.submitRestore(false)
	if newOp == oldOp {
		t.Fatal("the re-submitted restore reused the interrupted op id")
	}
	done := r.waitOp(newOp)
	if done.State != "succeeded" {
		t.Fatalf("re-submitted restore = %s(%s); agent output:\n%s", done.State, done.FailureReason, r.logs.String())
	}
	if r.read("running") == "" || r.read("data") != "restored" {
		t.Fatalf("after the re-submitted restore: running=%q data=%q", r.read("running"), r.read("data"))
	}
	if files := r.waitJournal(); len(files) != 0 {
		t.Errorf("journal still holds %v after a later restore succeeded", files)
	}
	ids, _ := done.Result["superseded_interrupted_ops"].([]interface{}) //nolint:errcheck // absent → nil, asserted below
	if len(ids) != 1 || ids[0] != oldOp {
		t.Errorf("result.superseded_interrupted_ops = %v, want [%s]", ids, oldOp)
	}
	var st restoreStatusView
	r.get("/v1/status", &st)
	if len(st.Interrupted) != 0 || !st.StackUp {
		t.Errorf("status after a later restore succeeded: interrupted=%+v stack_up=%v", st.Interrupted, st.StackUp)
	}

	// A later restart must not resurrect the old op as a fresh failure.
	r.kill()
	r.start()
	if code := r.get("/v1/operations/"+oldOp, nil); code != http.StatusNotFound {
		t.Errorf("superseded op after a later restart: HTTP %d, want 404 (not re-reported)", code)
	}
	if n := r.interruptedAudits(oldOp); n != 1 {
		t.Errorf("superseded op has %d interruption audit entries, want the original 1", n)
	}
	st = restoreStatusView{}
	r.get("/v1/status", &st)
	if len(st.Interrupted) != 0 {
		t.Errorf("status after the restart lists %+v", st.Interrupted)
	}
}

// TestRestoreCrash_FailedLaterRestoreKeepsTheRecord: a re-submitted restore
// that fails retires nothing. Here Docker stops answering, so the new restore
// fails at its preflight; every other failing stage is covered in process by
// TestRetireRestore_NotWhenTheRestoreDidNotEstablishItsState.
func TestRestoreCrash_FailedLaterRestoreKeepsTheRecord(t *testing.T) {
	r := newCrashRig(t)
	r.start()
	oldOp := r.crashRestoreAt("down_after:1", false)
	r.start()
	r.put("docker_down", "1")

	done := r.waitOp(r.submitRestore(false))
	if done.State != "failed" {
		t.Fatalf("restore with Docker down = %s, want failed", done.State)
	}
	if files := r.waitJournal(oldOp); len(files) != 1 || files[0] != oldOp {
		t.Errorf("journal = %v, want the interrupted record kept after a failed restore", files)
	}
	_ = os.Remove(filepath.Join(r.model, "docker_down"))
	var st restoreStatusView
	r.get("/v1/status", &st)
	if len(st.Interrupted) != 1 || st.Interrupted[0].OpID != oldOp || st.Interrupted[0].RestoreStage != "stopping" {
		t.Errorf("status must keep listing the interrupted restore: %+v", st.Interrupted)
	}
}

// TestRestoreCrash_DataRollbackReportsTheSameStages: rollbacks mode=data runs
// the same stages and gets the same report, under its own kind.
func TestRestoreCrash_DataRollbackReportsTheSameStages(t *testing.T) {
	kills := restoreKills()
	for i := range kills {
		tc := &kills[i]
		if tc.point != "down_after:1" && tc.point != "commit_before:1" && tc.point != "up_before:1" {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			r := newCrashRig(t)
			r.start()
			opID := r.crashRestoreAt(tc.point, true)
			r.clearCalls()
			r.start()
			for _, p := range interruptedRestoreProblems(r, opID, "rollbacks.create", tc, 1) {
				t.Errorf("%s", p)
			}
			var st restoreStatusView
			r.get("/v1/status", &st)
			if len(st.Interrupted) == 1 && st.Interrupted[0].Mode != "data" {
				t.Errorf("mode = %q, want data", st.Interrupted[0].Mode)
			}
			if m := r.restoreMutatingCalls(); len(m) != 0 {
				t.Errorf("restart issued state-changing docker commands: %v", m)
			}
			// A later restore.commit retires a data rollback's record too.
			if done := r.waitOp(r.submitRestore(false)); done.State != "succeeded" {
				t.Fatalf("restore = %s(%s)", done.State, done.FailureReason)
			}
			if files := r.waitJournal(); len(files) != 0 {
				t.Errorf("journal still holds %v", files)
			}
		})
	}
}

// TestRestoreCrash_RestoreDoesNotRetireAnInterruptedUpgrade: with an upgrade
// killed between `docker tag` and `compose up` outstanding, a restore succeeds
// — and its own `compose up` is what starts the image the fixed tag was left
// on. The upgrade's record must stay: nothing health-gated that image as an
// upgrade, and the restore re-pinned nothing.
func TestRestoreCrash_RestoreDoesNotRetireAnInterruptedUpgrade(t *testing.T) {
	r := newCrashRig(t)
	r.start()
	upgradeOp := r.crashAt("up_before:1")
	r.start()

	done := r.waitOp(r.submitRestore(false))
	if done.State != "succeeded" {
		t.Fatalf("restore = %s(%s); agent output:\n%s", done.State, done.FailureReason, r.logs.String())
	}
	if files := r.waitJournal(upgradeOp); len(files) != 1 || files[0] != upgradeOp {
		t.Errorf("journal = %v, want the interrupted upgrade's record kept", files)
	}
	if _, ok := done.Result["superseded_interrupted_ops"]; ok {
		t.Errorf("the restore claims it retired something: %+v", done.Result)
	}
	var st statusView
	r.get("/v1/status", &st)
	if len(st.Interrupted) != 1 || st.Interrupted[0].OpID != upgradeOp || st.Interrupted[0].Kind != "upgrades.apply" {
		t.Errorf("status must keep listing the interrupted upgrade: %+v", st.Interrupted)
	}
}

// TestRestoreCrash_NegativeControl: what the agent left before restore.commit
// was journaled is exactly "no record". Removing the record after the kill
// reproduces that state with the same binary, and the assertions used above
// must then object to each of the symptoms that were measured on real Docker:
// the operation is unknown (404), status lists nothing, no audit entry.
//
// The other half was measured by mutation, not left to argument: with
// restore.commit deleted from ops.journaledKinds, TestRestoreCrash_EveryKillPoint
// fails at every kill point: the operation comes back as kind "unknown" with
// none of the restore fields. (A record still exists in that mutant, because
// the stages re-create a missing record before they advance it; what the
// mutant loses is the fail-closed admission write and the kind's report.)
func TestRestoreCrash_NegativeControl(t *testing.T) {
	tc := &restoreKills()[2] // after the stop, before the commit: the proxy is down
	r := newCrashRig(t)
	r.start()
	opID := r.crashRestoreAt(tc.point, false)
	if err := os.Remove(filepath.Join(r.state, "reconcile", opID+".json")); err != nil {
		t.Fatalf("the kill left no journal record to remove (%v): journaling of restore.commit is not in effect", err)
	}
	r.start()

	problems := strings.Join(interruptedRestoreProblems(r, opID, "restore.commit", tc, 1), "\n")
	for _, want := range []string{
		"HTTP 404, want 200",
		"status.interrupted_operations has 0 entries, want 1",
		"audit has 0 failed(agent_restart_interrupted) entries",
	} {
		if !strings.Contains(problems, want) {
			t.Errorf("the checks did not object with %q to an un-journaled interrupted restore; they said:\n%s", want, problems)
		}
	}
	// The only true signal in that state, then and now.
	var st restoreStatusView
	r.get("/v1/status", &st)
	if st.StackUp {
		t.Error("compose_stack_up is true although the restore stopped the stack")
	}
}
