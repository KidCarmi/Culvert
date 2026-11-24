package server

// restore_journal_test.go — the restore flow's journal record: written ahead of
// each step, fail-closed before the two destructive ones, and honest about a
// commit it could not record. Both restore-class kinds run every case: they
// share the stages, so they must share the record.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"culvert-maint/internal/auth"
	"culvert-maint/internal/health"
	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
	"culvert-maint/internal/runner"
)

// restoreRig is a journaled server whose docker is a recorder. Each command is
// classified (restoreCmd*) and handed to onExec BEFORE it "runs", which is
// where a test reads the journal as a crash at that instant would leave it.
type restoreRig struct {
	srv *Server
	jnl *journal.Journal

	mu     sync.Mutex
	ran    []string
	onExec func(cmd string)
	fail   map[string]bool

	healthFail atomic.Bool
	onHealth   func()
}

const (
	restoreCmdList   = "list"
	restoreCmdDryRun = "dryrun"
	restoreCmdDown   = "down"
	restoreCmdCommit = "commit"
	restoreCmdUp     = "up"
)

func classifyRestoreCmd(argv []string) string {
	switch {
	case argvHas(argv, "--list-backups"):
		return restoreCmdList
	case argvHas(argv, "--restore") && argvHas(argv, "--confirm"):
		return restoreCmdCommit
	case argvHas(argv, "--restore"):
		return restoreCmdDryRun
	case argvHas(argv, "down"):
		return restoreCmdDown
	case argvHas(argv, "up"):
		return restoreCmdUp
	}
	return "other"
}

func newRestoreRig(t *testing.T) *restoreRig {
	t.Helper()
	srv, jnl := newJournalTestServer(t)
	rig := &restoreRig{srv: srv, jnl: jnl, fail: map[string]bool{}}
	rn, err := runner.New(runner.Options{
		ComposeProjectDir: srv.opts.Cfg.ComposeProjectDir, ComposeFile: "docker-compose.yml",
		StageTimeout: 5 * time.Second, EnvAllow: []string{runner.EnvCulvertBackupPassphrase}, DockerBinary: "/usr/bin/docker",
	})
	if err != nil {
		t.Fatal(err)
	}
	rn.SetExecHooksForTest(
		func(cmd *exec.Cmd) error {
			c := classifyRestoreCmd(cmd.Args)
			rig.mu.Lock()
			rig.ran = append(rig.ran, c)
			hook := rig.onExec
			rig.mu.Unlock()
			if hook != nil {
				hook(c)
			}
			return nil
		},
		func(cmd *exec.Cmd) error {
			rig.mu.Lock()
			defer rig.mu.Unlock()
			if rig.fail[classifyRestoreCmd(cmd.Args)] {
				return fmt.Errorf("simulated failure")
			}
			return nil
		},
	)
	srv.opts.Runner = rn
	srv.opts.Cfg.AllowedBackupDir = "/backup"
	srv.opts.Cfg.StageTimeout = 5 * time.Second
	srv.opts.Cfg.ProxyRepo = repo
	base, _ := url.Parse("http://127.0.0.1:8080")
	srv.opts.HealthProbeFactory = func() health.Probe {
		return health.Probe{
			BaseURL: base, HealthPath: "/health", ReadyPath: "/ready",
			Budget: 200 * time.Millisecond, PollInterval: 50 * time.Millisecond, RequestTimeout: 100 * time.Millisecond,
			Client: &http.Client{Timeout: time.Second, Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if rig.onHealth != nil {
					rig.onHealth()
				}
				code := http.StatusOK
				if rig.healthFail.Load() {
					code = http.StatusServiceUnavailable
				}
				return &http.Response{StatusCode: code, Status: fmt.Sprintf("%d test", code), Body: io.NopCloser(strings.NewReader("ok")), Request: req}, nil
			})},
		}
	}
	return rig
}

// commands returns the classified docker commands in the order they ran,
// without the data rollback's pre-admission backup listing.
func (r *restoreRig) commands() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, c := range r.ran {
		if c != restoreCmdList {
			out = append(out, c)
		}
	}
	return out
}

// restoreKinds are the two operations that run the restore stages.
var restoreKinds = []struct {
	name, kind, mode string
}{
	{"restore.commit", ops.KindRestoreCommit, ""},
	{"rollbacks.create mode=data", ops.KindRollbackCreate, "data"},
}

// run submits a restore of the given kind through its real handler and waits
// for it to finish.
func (r *restoreRig) run(t *testing.T, kind string) *ops.Op {
	t.Helper()
	path, body := "/v1/restores/commit", map[string]interface{}{"path": "/backup/x.enc", "mode": "full"}
	if kind == ops.KindRollbackCreate {
		path, body = "/v1/rollbacks", map[string]interface{}{"mode": "data", "filename": "x.enc"}
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, bytes.NewReader(raw))
	w := httptest.NewRecorder()
	peer := auth.PeerInfo{UID: 1000, Username: "cp"}
	if kind == ops.KindRollbackCreate {
		r.srv.handleRollback(w, req, peer)
	} else {
		r.srv.handleRestoreCommit(w, req, peer)
	}
	if w.Code != http.StatusAccepted {
		t.Fatalf("%s: HTTP %d %s", kind, w.Code, w.Body.String())
	}
	var ack struct {
		OpID string `json:"op_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &ack); err != nil || ack.OpID == "" {
		t.Fatalf("ack: %v %s", err, w.Body.String())
	}
	r.srv.opWG.Wait()
	op := r.srv.opts.Ops.Get(ack.OpID)
	if op == nil {
		t.Fatal("op vanished")
	}
	return op
}

// onlyRecord returns the single journal record, or nil.
func (r *restoreRig) onlyRecord() *journal.Record {
	recs, err := r.jnl.List()
	if err != nil || len(recs) != 1 {
		return nil
	}
	return &recs[0]
}

// breakJournal makes every later journal read and write fail, the way a state
// directory that went away (or filled up) does.
func (r *restoreRig) breakJournal(t *testing.T) {
	t.Helper()
	if err := os.Rename(r.jnl.Dir(), r.jnl.Dir()+".gone"); err != nil {
		t.Errorf("rename: %v", err)
	}
}

func stageOutput(op *ops.Op, stage string) (string, ops.State) {
	for _, st := range op.Progress {
		if st.Name == stage {
			return st.Output, st.State
		}
	}
	return "", ""
}

// TestAdmissionJournalRecord_RestoreKinds: both restore-class kinds are admitted
// with the `admitted` stage; restore.commit does not persist its RESTORE mode
// in the journal's rollback-mode field; other kinds carry no stage.
func TestAdmissionJournalRecord_RestoreKinds(t *testing.T) {
	rc := admissionJournalRecord(testOpULID, ops.KindRestoreCommit, "cp", map[string]interface{}{"mode": "trust-root-only"})
	if rc.Kind != ops.KindRestoreCommit || rc.Mode != "" || rc.RestoreStage != journal.RestoreStageAdmitted || rc.Phase != journal.PhaseAdmitted {
		t.Errorf("restore.commit admission record: %+v", rc)
	}
	dr := admissionJournalRecord(testOpULID, ops.KindRollbackCreate, "cp", map[string]interface{}{"mode": "data"})
	if dr.Mode != "data" || dr.RestoreStage != journal.RestoreStageAdmitted {
		t.Errorf("data rollback admission record: %+v", dr)
	}
	for _, rec := range []journal.Record{
		admissionJournalRecord(testOpULID, ops.KindUpgradeApply, "cp", nil),
		admissionJournalRecord(testOpULID, ops.KindRollbackCreate, "cp", map[string]interface{}{"mode": "image"}),
	} {
		if rec.RestoreStage != "" {
			t.Errorf("%s/%s carries a restore stage %q", rec.Kind, rec.Mode, rec.RestoreStage)
		}
	}
}

// assertStageAt checks the record captured when `at` started.
func assertStageAt(t *testing.T, seen map[string]journal.Record, at string, want journal.RestoreStage, kind, mode string) {
	t.Helper()
	rec, ok := seen[at]
	if !ok {
		t.Errorf("no journal record when %q started", at)
		return
	}
	if rec.RestoreStage != want {
		t.Errorf("record when %q started: restore_stage = %q, want %q", at, rec.RestoreStage, want)
	}
	if rec.Kind != kind || rec.Mode != mode || rec.Phase != journal.PhaseAdmitted || rec.Actor == "" || rec.StartedAt.IsZero() {
		t.Errorf("record when %q started lost its admission fields: %+v", at, rec)
	}
}

// TestRestore_StageIsWrittenAheadOfEveryCommand reads the record at the moment
// each docker command starts — what a kill at that instant would leave — and
// at the health probe. The record is gone once the operation is terminal.
func TestRestore_StageIsWrittenAheadOfEveryCommand(t *testing.T) {
	for _, k := range restoreKinds {
		t.Run(k.name, func(t *testing.T) {
			rig := newRestoreRig(t)
			seen := map[string]journal.Record{}
			note := func(at string) {
				if rec := rig.onlyRecord(); rec != nil {
					seen[at] = *rec
				}
			}
			rig.onExec = note
			rig.onHealth = func() { note("health") }

			op := rig.run(t, k.kind)
			if op.State != ops.StateSucceeded {
				t.Fatalf("op = %s(%s) %+v", op.State, op.FailureReason, op.Progress)
			}
			for at, want := range map[string]journal.RestoreStage{
				restoreCmdDryRun: journal.RestoreStagePreflight,
				restoreCmdDown:   journal.RestoreStageStopping,
				restoreCmdCommit: journal.RestoreStageCommitting,
				restoreCmdUp:     journal.RestoreStageStarting,
				"health":         journal.RestoreStageStarted,
			} {
				assertStageAt(t, seen, at, want, k.kind, k.mode)
			}
			if recs, err := rig.jnl.List(); err != nil || len(recs) != 0 {
				t.Errorf("record not retired at terminal: %d left, err=%v", len(recs), err)
			}
			if op.Result["restore_committed"] != true {
				t.Errorf("result.restore_committed = %v, want true", op.Result["restore_committed"])
			}
		})
	}
}

// TestRestore_FailedCommitKeepsItsStageThroughTheRecoveryStart: after a commit
// that returned an error the stage says so, and the best-effort `compose up`
// that follows does not overwrite it — it is the only durable statement about
// the data.
func TestRestore_FailedCommitKeepsItsStageThroughTheRecoveryStart(t *testing.T) {
	for _, k := range restoreKinds {
		t.Run(k.name, func(t *testing.T) {
			rig := newRestoreRig(t)
			rig.fail[restoreCmdCommit] = true
			var atUp, atHealth journal.RestoreStage
			rig.onExec = func(c string) {
				if rec := rig.onlyRecord(); c == restoreCmdUp && rec != nil {
					atUp = rec.RestoreStage
				}
			}
			rig.onHealth = func() {
				if rec := rig.onlyRecord(); rec != nil {
					atHealth = rec.RestoreStage
				}
			}
			op := rig.run(t, k.kind)
			if op.State != ops.StateFailed || op.FailureReason != string(ops.ReasonCLIError) {
				t.Fatalf("op = %s(%s), want failed(cli_error)", op.State, op.FailureReason)
			}
			if atUp != journal.RestoreStageCommitFailed || atHealth != journal.RestoreStageCommitFailed {
				t.Errorf("stage at up = %q, at health = %q; want commit_failed at both", atUp, atHealth)
			}
			if op.Result["restore_committed"] != false {
				t.Errorf("result.restore_committed = %v, want false", op.Result["restore_committed"])
			}
		})
	}
}

// TestRestore_FailedStopKeepsStopping: `compose down` failed; the commit is
// skipped and the recovery start runs with the stage still at `stopping`.
func TestRestore_FailedStopKeepsStopping(t *testing.T) {
	rig := newRestoreRig(t)
	rig.fail[restoreCmdDown] = true
	var atUp journal.RestoreStage
	rig.onExec = func(c string) {
		if rec := rig.onlyRecord(); c == restoreCmdUp && rec != nil {
			atUp = rec.RestoreStage
		}
	}
	op := rig.run(t, ops.KindRestoreCommit)
	if op.State != ops.StateFailed || op.FailureReason != string(ops.ReasonCommandError) {
		t.Fatalf("op = %s(%s)", op.State, op.FailureReason)
	}
	if got := strings.Join(rig.commands(), ","); got != "dryrun,down,up" {
		t.Errorf("commands = %s, want dryrun,down,up", got)
	}
	if atUp != journal.RestoreStageStopping {
		t.Errorf("stage at the recovery up = %q, want stopping", atUp)
	}
}

// TestRestore_JournalFailureBeforeStopMeansNoStop: the journal breaks during
// the preflight. `stopping` cannot be recorded, so `compose down` is not run,
// and neither is anything after it: the proxy keeps serving.
func TestRestore_JournalFailureBeforeStopMeansNoStop(t *testing.T) {
	for _, k := range restoreKinds {
		t.Run(k.name, func(t *testing.T) {
			rig := newRestoreRig(t)
			rig.onExec = func(c string) {
				if c == restoreCmdDryRun {
					rig.breakJournal(t)
				}
			}
			healthProbed := false
			rig.onHealth = func() { healthProbed = true }
			op := rig.run(t, k.kind)
			if op.State != ops.StateFailed || op.FailureReason != string(ops.ReasonCommandError) {
				t.Fatalf("op = %s(%s), want failed(command_error)", op.State, op.FailureReason)
			}
			if got := strings.Join(rig.commands(), ","); got != "dryrun" {
				t.Errorf("commands = %s; nothing may run after the preflight when the journal cannot be written", got)
			}
			out, state := stageOutput(op, "stop_stack")
			if state != ops.StateFailed || !strings.Contains(out, "refusing to stop the stack") {
				t.Errorf("stop_stack = %s %q", state, out)
			}
			if healthProbed {
				t.Error("the health check probed a stack this operation never stopped")
			}
			if op.Result["restore_committed"] != false {
				t.Errorf("result.restore_committed = %v, want false", op.Result["restore_committed"])
			}
		})
	}
}

// TestRestore_JournalFailureBeforeCommitMeansNoCommit: the journal breaks while
// the stack is being stopped. `committing` cannot be recorded, so the commit
// command is not run; the stack, which IS down, is started again.
func TestRestore_JournalFailureBeforeCommitMeansNoCommit(t *testing.T) {
	for _, k := range restoreKinds {
		t.Run(k.name, func(t *testing.T) {
			rig := newRestoreRig(t)
			rig.onExec = func(c string) {
				if c == restoreCmdDown {
					rig.breakJournal(t)
				}
			}
			op := rig.run(t, k.kind)
			if op.State != ops.StateFailed {
				t.Fatalf("op = %s, want failed", op.State)
			}
			if got := strings.Join(rig.commands(), ","); got != "dryrun,down,up" {
				t.Errorf("commands = %s, want dryrun,down,up (no commit; the stack is brought back)", got)
			}
			out, state := stageOutput(op, "run_cli_restore_commit")
			if state != ops.StateFailed || !strings.Contains(out, "refusing to run the commit") || !strings.Contains(out, "was not changed") {
				t.Errorf("run_cli_restore_commit = %s %q", state, out)
			}
			if op.Result["restore_committed"] != false {
				t.Errorf("result.restore_committed = %v, want false", op.Result["restore_committed"])
			}
		})
	}
}

// TestRestore_CommitThatCannotBeRecordedFailsSayingTheDataChanged: the commit
// command succeeds and `committed` cannot be written. The operation must not
// report plain success, must not look like a restore that failed and changed
// nothing, and must still start and health-check the stack.
func TestRestore_CommitThatCannotBeRecordedFailsSayingTheDataChanged(t *testing.T) {
	for _, k := range restoreKinds {
		t.Run(k.name, func(t *testing.T) {
			rig := newRestoreRig(t)
			rig.onExec = func(c string) {
				if c == restoreCmdCommit {
					rig.breakJournal(t)
				}
			}
			healthProbed := false
			rig.onHealth = func() { healthProbed = true }

			op := rig.run(t, k.kind)
			if op.State != ops.StateFailed {
				t.Fatalf("op = %s; a commit that could not be recorded must not be a plain success", op.State)
			}
			if op.FailureReason != string(ops.ReasonCommandError) {
				t.Errorf("failure_reason = %q, want command_error (cli_error would read as \"the restore failed\")", op.FailureReason)
			}
			out, state := stageOutput(op, "run_cli_restore_commit")
			if state != ops.StateFailed || !strings.Contains(out, "COMMITTED") || !strings.Contains(out, "WAS replaced") {
				t.Errorf("the failed stage does not say the data changed: %s %q", state, out)
			}
			if op.Result["restore_committed"] != true {
				t.Errorf("result.restore_committed = %v, want true: the data directory was replaced", op.Result["restore_committed"])
			}
			if got := strings.Join(rig.commands(), ","); got != "dryrun,down,commit,up" {
				t.Errorf("commands = %s, want the stack started after the commit", got)
			}
			if !healthProbed {
				t.Error("the health check did not run")
			}
		})
	}
}

// TestRestore_NilFlowRunsTheStagesUnjournaled: the stages work without a flow
// (and without a journal), as every pre-existing caller builds them.
func TestRestore_NilFlowRunsTheStagesUnjournaled(t *testing.T) {
	rig := newRestoreRig(t)
	var f *restoreFlow
	if f.established() {
		t.Error("a nil flow established something")
	}
	if err := rig.srv.advanceRestoreStage(nil, journal.RestoreStageStopping); err != nil {
		t.Errorf("nil flow: %v", err)
	}
	if err := rig.srv.advanceRestoreStage(&restoreFlow{}, journal.RestoreStageStopping); err != nil {
		t.Errorf("flow without an op id: %v", err)
	}
	if recs, _ := rig.jnl.List(); len(recs) != 0 {
		t.Errorf("a no-op advance wrote %d record(s)", len(recs))
	}
}

// TestAdvanceRestoreStage_RecreatesAMissingRecord: like the upgrade's barrier,
// a record that vanished is re-established rather than letting a destructive
// step run unrecorded.
func TestAdvanceRestoreStage_RecreatesAMissingRecord(t *testing.T) {
	rig := newRestoreRig(t)
	f := newRestoreFlow(ops.KindRollbackCreate, "data", "cp")
	f.opID = testOpULID
	if err := rig.srv.advanceRestoreStage(f, journal.RestoreStageStopping); err != nil {
		t.Fatal(err)
	}
	rec, found, err := rig.jnl.Read(testOpULID)
	if err != nil || !found {
		t.Fatalf("found=%v err=%v", found, err)
	}
	if rec.Kind != ops.KindRollbackCreate || rec.Mode != "data" || rec.RestoreStage != journal.RestoreStageStopping || rec.Actor != "cp" {
		t.Errorf("re-created record: %+v", rec)
	}
}

// TestRestore_AdmissionFailsClosedWhenTheJournalCannotBeWritten: like an
// upgrade, a restore that cannot be journaled is not run at all. The request
// is refused with the op id, the op is failed, and no docker command of the
// flow starts.
func TestRestore_AdmissionFailsClosedWhenTheJournalCannotBeWritten(t *testing.T) {
	rig := newRestoreRig(t)
	rig.breakJournal(t)
	raw, err := json.Marshal(map[string]interface{}{"path": "/backup/x.enc", "mode": "full"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/restores/commit", bytes.NewReader(raw))
	w := httptest.NewRecorder()
	rig.srv.handleRestoreCommit(w, req, auth.PeerInfo{UID: 1000, Username: "cp"})
	rig.srv.opWG.Wait()

	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusInternalServerError || body["error"] != "journal_write_failed" || body["state"] != "failed" {
		t.Fatalf("HTTP %d %v, want 500 journal_write_failed", w.Code, body)
	}
	opID, _ := body["op_id"].(string) //nolint:errcheck // absent → "", Get then returns nil
	if op := rig.srv.opts.Ops.Get(opID); op == nil || op.State != ops.StateFailed {
		t.Errorf("op = %+v, want failed", op)
	}
	if c := rig.commands(); len(c) != 0 {
		t.Errorf("docker commands ran for a restore that could not be journaled: %v", c)
	}
}
