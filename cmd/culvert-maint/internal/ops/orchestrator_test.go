package ops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"culvert-maint/internal/audit"
)

// orchTestRig is the standard wiring for orchestrator tests: a
// Manager, audit logger, and OpLog rooted in a t.TempDir(). Returns
// the deps along with paths so tests can inspect the audit jsonl /
// op-log content directly.
type orchTestRig struct {
	mgr       *Manager
	deps      OrchestratorDeps
	auditPath string
	opLogPath string
	opID      string
}

func newOrchTestRig(t *testing.T) *orchTestRig {
	t.Helper()
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	logger, err := audit.New(auditPath)
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	mgr := NewManager(nil)
	op, _, err := mgr.BeginIdempotent(KindBackupCreate, "uid=1,user=test", "", map[string]interface{}{"k": "v"})
	if err != nil {
		t.Fatalf("BeginIdempotent: %v", err)
	}
	oplog, err := OpenOpLog(dir, op.ID)
	if err != nil {
		t.Fatalf("OpenOpLog: %v", err)
	}
	return &orchTestRig{
		mgr:       mgr,
		opID:      op.ID,
		auditPath: auditPath,
		opLogPath: oplog.Path(),
		deps: OrchestratorDeps{
			Manager: mgr,
			Audit:   logger,
			OpLog:   oplog,
		},
	}
}

func (r *orchTestRig) opLogContent(t *testing.T) string {
	t.Helper()
	body, err := os.ReadFile(r.opLogPath) //nolint:gosec // test path
	if err != nil {
		t.Fatalf("read op log: %v", err)
	}
	return string(body)
}

func (r *orchTestRig) auditContent(t *testing.T) string {
	t.Helper()
	body, err := os.ReadFile(r.auditPath) //nolint:gosec // test path
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	return string(body)
}

// stage helper.
func okStage(name string, stdout string) FlowStage {
	return FlowStage{
		Name: name,
		Run: func(_ context.Context) ([]byte, []byte, error) {
			return []byte(stdout), nil, nil
		},
	}
}

// failStage builds an aborting failed stage. ContinueOnError-true
// failures are constructed inline by tests that need them, since
// they're rare.
func failStage(name, errMsg string, reason FailureReason) FlowStage {
	return FlowStage{
		Name:          name,
		Run:           func(_ context.Context) ([]byte, []byte, error) { return nil, nil, errors.New(errMsg) },
		FailureReason: reason,
	}
}

func TestRun_AllStagesSucceed(t *testing.T) {
	rig := newOrchTestRig(t)
	Run(context.Background(), rig.deps, rig.opID, KindBackupCreate, "uid=1,user=test", map[string]interface{}{"k": "v"}, "",
		[]FlowStage{
			okStage("preflight", "validated"),
			okStage("run", "wrote /backup/x.tar.gz"),
			okStage("verify", "size=1234"),
		},
	)

	op := rig.mgr.Get(rig.opID)
	if op.State != StateSucceeded {
		t.Errorf("state: got %s want succeeded", op.State)
	}
	if op.FailureReason != "" {
		t.Errorf("failure_reason should be empty: %q", op.FailureReason)
	}
	if len(op.Progress) != 3 {
		t.Errorf("progress: got %d stages, want 3", len(op.Progress))
	}
	for _, st := range op.Progress {
		if st.State != StateSucceeded {
			t.Errorf("stage %q state: got %s want succeeded", st.Name, st.State)
		}
	}

	body := rig.opLogContent(t)
	for _, want := range []string{"preflight\tSTART", "run\tSTART", "run\tout\twrote /backup/x.tar.gz", "verify\tEND succeeded", "op finished succeeded"} {
		if !strings.Contains(body, want) {
			t.Errorf("op-log missing %q\nlog:\n%s", want, body)
		}
	}

	auditBody := rig.auditContent(t)
	if !strings.Contains(auditBody, `"outcome":"started"`) {
		t.Error("audit missing started event")
	}
	if !strings.Contains(auditBody, `"outcome":"succeeded"`) {
		t.Error("audit missing succeeded event")
	}
	if strings.Contains(auditBody, `"outcome":"failed"`) {
		t.Error("audit must not contain failed event on success")
	}
}

func TestRun_FailingStageAbortsRest(t *testing.T) {
	rig := newOrchTestRig(t)
	Run(context.Background(), rig.deps, rig.opID, KindBackupCreate, "uid=1", nil, "",
		[]FlowStage{
			okStage("a", "ok"),
			failStage("b", "boom", ReasonCLIError),
			okStage("c", "should-be-skipped"),
		},
	)

	op := rig.mgr.Get(rig.opID)
	if op.State != StateFailed {
		t.Errorf("state: got %s want failed", op.State)
	}
	if op.FailureReason != string(ReasonCLIError) {
		t.Errorf("failure_reason: got %q want %q", op.FailureReason, ReasonCLIError)
	}

	body := rig.opLogContent(t)
	if !strings.Contains(body, "b\tEND failed\tboom") {
		t.Errorf("op-log missing failed marker for b\n%s", body)
	}
	if !strings.Contains(body, "c\tNOTE\tskipped (earlier failure)") {
		t.Errorf("op-log must mark c as skipped\n%s", body)
	}
	if strings.Contains(body, "should-be-skipped") {
		t.Errorf("c must NOT have run; output leaked into log\n%s", body)
	}
}

// Best-effort recovery: a failing stage is followed by a
// ContinueOnError stage that DOES run. The op is still marked failed
// (first failure wins for the audit reason), but the recovery output
// is captured.
func TestRun_ContinueOnErrorRunsAfterFailure(t *testing.T) {
	rig := newOrchTestRig(t)
	Run(context.Background(), rig.deps, rig.opID, KindRestoreCommit, "uid=1", nil, "",
		[]FlowStage{
			okStage("stop_stack", "stack down"),
			failStage("run_cli_restore", "cli barfed", ReasonCLIError),
			{
				Name:            "best_effort_up",
				ContinueOnError: true,
				Run: func(_ context.Context) ([]byte, []byte, error) {
					return []byte("recovery: stack back up"), nil, nil
				},
			},
		},
	)

	op := rig.mgr.Get(rig.opID)
	if op.State != StateFailed {
		t.Errorf("op must be failed (first failure wins); got %s", op.State)
	}
	if op.FailureReason != string(ReasonCLIError) {
		t.Errorf("failure_reason should be from FIRST failure: got %q", op.FailureReason)
	}
	body := rig.opLogContent(t)
	if !strings.Contains(body, "best_effort_up\tSTART") {
		t.Errorf("best-effort stage must have run\n%s", body)
	}
	if !strings.Contains(body, "recovery: stack back up") {
		t.Errorf("best-effort stdout missing\n%s", body)
	}
}

// FailureReason on the FlowStage propagates to the op record, NOT
// the default ReasonCLIError.
func TestRun_PropagatesStageFailureReason(t *testing.T) {
	rig := newOrchTestRig(t)
	Run(context.Background(), rig.deps, rig.opID, KindRestoreCommit, "uid=1", nil, "",
		[]FlowStage{
			okStage("ok", "ok"),
			failStage("health", "ready timed out", ReasonHealthFailed),
		},
	)
	op := rig.mgr.Get(rig.opID)
	if op.FailureReason != string(ReasonHealthFailed) {
		t.Errorf("failure_reason: want %q, got %q", ReasonHealthFailed, op.FailureReason)
	}
	body := rig.auditContent(t)
	if !strings.Contains(body, `"failure_reason":"health_failed"`) {
		t.Errorf("audit missing health_failed reason: %s", body)
	}
}

// Lock release: state-changing op holding the lock must release it
// after Finish, regardless of success/failure.
func TestRun_ReleasesLockOnTerminal(t *testing.T) {
	rig := newOrchTestRig(t)
	if rig.mgr.Holder() == nil {
		t.Fatal("setup: state-changing op should be holding the lock")
	}
	Run(context.Background(), rig.deps, rig.opID, KindBackupCreate, "uid=1", nil, "",
		[]FlowStage{failStage("x", "boom", ReasonCLIError)},
	)
	if rig.mgr.Holder() != nil {
		t.Errorf("lock must be released on terminal state; holder=%+v", rig.mgr.Holder())
	}
}

// Idempotency_key in the started audit event flows through.
func TestRun_PropagatesIdempotencyKeyToAudit(t *testing.T) {
	rig := newOrchTestRig(t)
	Run(context.Background(), rig.deps, rig.opID, KindBackupCreate, "uid=1", nil, "key-XYZ",
		[]FlowStage{okStage("a", "")},
	)
	body := rig.auditContent(t)
	if !strings.Contains(body, `"idempotency_key":"key-XYZ"`) {
		t.Errorf("audit missing idempotency_key=key-XYZ:\n%s", body)
	}
}

func TestRun_ConfigErrorMarksOpFailed(t *testing.T) {
	mgr := NewManager(nil)
	op, _, err := mgr.BeginIdempotent(KindBackupCreate, "uid=1", "", nil)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	deps := OrchestratorDeps{Manager: mgr} // missing Audit + OpLog
	Run(context.Background(), deps, op.ID, KindBackupCreate, "uid=1", nil, "", nil)
	got := mgr.Get(op.ID)
	if got.State != StateFailed {
		t.Errorf("misconfig must mark op failed; got %s", got.State)
	}
	if got.FailureReason != string(ReasonValidation) {
		t.Errorf("misconfig reason should be validation; got %q", got.FailureReason)
	}
}
