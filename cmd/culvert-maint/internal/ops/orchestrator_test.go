package ops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
		nil,
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
		nil,
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
		nil,
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
		nil,
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
		nil,
	)
	if rig.mgr.Holder() != nil {
		t.Errorf("lock must be released on terminal state; holder=%+v", rig.mgr.Holder())
	}
}

// panicStage builds a stage whose Run panics — the "never crash" case.
func panicStage(name, msg string) FlowStage {
	return FlowStage{
		Name: name,
		Run: func(_ context.Context) ([]byte, []byte, error) {
			panic(msg)
		},
	}
}

// TestRun_PanicInStageIsContained is the core never-crash guarantee: a stage
// panic must NOT propagate out of ops.Run (which would kill the whole agent
// process, since Run executes on a bare goroutine). Instead the op is marked
// failed(agent_panic) and the maintenance lock is released.
func TestRun_PanicInStageIsContained(t *testing.T) {
	rig := newOrchTestRig(t)
	if rig.mgr.Holder() == nil {
		t.Fatal("setup: state-changing op should be holding the lock")
	}
	// If the panic barrier is missing, this call re-panics and crashes the test
	// binary — which IS the failure mode we are guarding against. A recover here
	// would mask a regression, so we deliberately do NOT wrap the call: a green
	// test proves ops.Run swallowed the panic itself.
	Run(context.Background(), rig.deps, rig.opID, KindBackupCreate, "uid=1", nil, "",
		[]FlowStage{okStage("first", "ok"), panicStage("boom", "kaboom"), okStage("never", "")},
		nil,
	)

	op := rig.mgr.Get(rig.opID)
	if op == nil {
		t.Fatal("op missing after panic")
	}
	if op.State != StateFailed {
		t.Errorf("panicking op state = %q, want failed", op.State)
	}
	if op.FailureReason != string(ReasonAgentPanic) {
		t.Errorf("panicking op reason = %q, want %q", op.FailureReason, ReasonAgentPanic)
	}
	if rig.mgr.Holder() != nil {
		t.Errorf("maintenance lock must be released after a panic; holder=%+v", rig.mgr.Holder())
	}
	// The op-log records the panic + the culprit stage for forensics.
	body := rig.opLogContent(t)
	if !strings.Contains(body, "PANIC recovered") || !strings.Contains(body, "boom") {
		t.Errorf("op-log missing panic forensics:\n%s", body)
	}
	// A terminal failed audit event was still emitted.
	if a := rig.auditContent(t); !strings.Contains(a, `"failure_reason":"agent_panic"`) {
		t.Errorf("audit missing terminal agent_panic event:\n%s", a)
	}
}

// TestRun_PanicInResultFnIsContained proves the barrier also covers the
// resultFn (which runs after the stage loop, still inside Run's goroutine).
func TestRun_PanicInResultFnIsContained(t *testing.T) {
	rig := newOrchTestRig(t)
	Run(context.Background(), rig.deps, rig.opID, KindBackupCreate, "uid=1", nil, "",
		[]FlowStage{okStage("a", "ok")},
		func(_ State, _ FailureReason) map[string]interface{} { panic("resultFn boom") },
	)
	op := rig.mgr.Get(rig.opID)
	if op == nil || op.State != StateFailed || op.FailureReason != string(ReasonAgentPanic) {
		t.Errorf("resultFn panic not contained: %+v", op)
	}
	if rig.mgr.Holder() != nil {
		t.Error("lock must be released after a resultFn panic")
	}
}

// Idempotency_key in the started audit event flows through.
func TestRun_PropagatesIdempotencyKeyToAudit(t *testing.T) {
	rig := newOrchTestRig(t)
	Run(context.Background(), rig.deps, rig.opID, KindBackupCreate, "uid=1", nil, "key-XYZ",
		[]FlowStage{okStage("a", "")},
		nil,
	)
	body := rig.auditContent(t)
	if !strings.Contains(body, `"idempotency_key":"key-XYZ"`) {
		t.Errorf("audit missing idempotency_key=key-XYZ:\n%s", body)
	}
}

// When a ContinueOnError stage runs only because an earlier stage
// failed, the orchestrator must mark its op-log entry with a
// "recovery:" note so the operator can immediately distinguish a
// happy-path execution from a diagnostic / recovery one.
func TestRun_RecoveryNoteOnContinueOnErrorAfterFailure(t *testing.T) {
	rig := newOrchTestRig(t)
	Run(context.Background(), rig.deps, rig.opID, KindRestoreCommit, "uid=1", nil, "",
		[]FlowStage{
			failStage("first", "boom", ReasonCLIError),
			{
				Name:            "best_effort",
				ContinueOnError: true,
				Run: func(_ context.Context) ([]byte, []byte, error) {
					return []byte("ran for recovery"), nil, nil
				},
			},
		},
		nil,
	)
	body := rig.opLogContent(t)
	if !strings.Contains(body, "best_effort\tNOTE\trecovery: running after earlier failure at stage=first") {
		t.Errorf("op-log must mark best-effort recovery note:\n%s", body)
	}
	// Sanity: the recovery note does NOT fire when there is no
	// earlier failure.
	rig2 := newOrchTestRig(t)
	Run(context.Background(), rig2.deps, rig2.opID, KindBackupCreate, "uid=1", nil, "",
		[]FlowStage{
			{
				Name:            "best_effort",
				ContinueOnError: true,
				Run:             func(_ context.Context) ([]byte, []byte, error) { return nil, nil, nil },
			},
		},
		nil,
	)
	body2 := rig2.opLogContent(t)
	if strings.Contains(body2, "recovery: running after earlier failure") {
		t.Errorf("recovery note must NOT fire on a clean ContinueOnError stage:\n%s", body2)
	}
}

// Item #7 follow-on: timeout produces a result map with timed_out=true
// AND the original failure reason is preserved in the result for
// diagnostics (even though the audit failure_reason is promoted to
// "timeout").
func TestRun_TimeoutSurfaceInOpResult(t *testing.T) {
	rig := newOrchTestRig(t)
	blockingStage := FlowStage{
		Name:          "block",
		FailureReason: ReasonCLIError,
		Run: func(ctx context.Context) ([]byte, []byte, error) {
			<-ctx.Done()
			return nil, nil, ctx.Err()
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	Run(ctx, rig.deps, rig.opID, KindBackupCreate, "uid=1", nil, "",
		[]FlowStage{blockingStage}, nil,
	)
	op := rig.mgr.Get(rig.opID)
	if op.State != StateFailed {
		t.Fatalf("state: got %s want failed", op.State)
	}
	if op.FailureReason != string(ReasonTimeout) {
		t.Errorf("failure_reason: got %q want timeout", op.FailureReason)
	}
	if op.Result == nil {
		t.Fatalf("op.Result must be populated on timeout; got nil")
	}
	if v, _ := op.Result["timed_out"].(bool); !v {
		t.Errorf("op.Result[timed_out] must be true; got %v", op.Result)
	}
	if v, _ := op.Result["original_failure_reason"].(string); v != string(ReasonCLIError) {
		t.Errorf("op.Result[original_failure_reason]: got %q want %q", v, ReasonCLIError)
	}
	if v, _ := op.Result["timed_out_at_stage"].(string); v != "block" {
		t.Errorf("op.Result[timed_out_at_stage]: got %q want %q", v, "block")
	}
}

// Operation-level timeout: a long-running stage that respects its
// context should be cancelled when ctx hits its deadline; the op's
// final reason must be ReasonTimeout (overriding any stage reason).
func TestRun_OperationTimeoutMarksReasonTimeout(t *testing.T) {
	rig := newOrchTestRig(t)

	// Stage that blocks until ctx is cancelled — simulates a real
	// CLI command that respects timeouts.
	blockingStage := FlowStage{
		Name: "block",
		// FailureReason intentionally NOT ReasonTimeout — we want
		// to prove the orchestrator promotes the reason regardless
		// of what the stage declared.
		FailureReason: ReasonCLIError,
		Run: func(ctx context.Context) ([]byte, []byte, error) {
			<-ctx.Done()
			return nil, nil, ctx.Err()
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	Run(ctx, rig.deps, rig.opID, KindBackupCreate, "uid=1", nil, "",
		[]FlowStage{blockingStage}, nil,
	)

	op := rig.mgr.Get(rig.opID)
	if op.State != StateFailed {
		t.Errorf("state: got %s want failed", op.State)
	}
	if op.FailureReason != string(ReasonTimeout) {
		t.Errorf("failure_reason: got %q want %q (timeout must override stage reason)",
			op.FailureReason, ReasonTimeout)
	}
	body := rig.auditContent(t)
	if !strings.Contains(body, `"failure_reason":"timeout"`) {
		t.Errorf("audit must record timeout reason: %s", body)
	}
	logBody := rig.opLogContent(t)
	if !strings.Contains(logBody, "operation_timeout reached") {
		t.Errorf("op-log must note the timeout promotion:\n%s", logBody)
	}
}

func TestRun_ConfigErrorMarksOpFailed(t *testing.T) {
	mgr := NewManager(nil)
	op, _, err := mgr.BeginIdempotent(KindBackupCreate, "uid=1", "", nil)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	deps := OrchestratorDeps{Manager: mgr} // missing Audit + OpLog
	Run(context.Background(), deps, op.ID, KindBackupCreate, "uid=1", nil, "", nil, nil)
	got := mgr.Get(op.ID)
	if got.State != StateFailed {
		t.Errorf("misconfig must mark op failed; got %s", got.State)
	}
	if got.FailureReason != string(ReasonValidation) {
		t.Errorf("misconfig reason should be validation; got %q", got.FailureReason)
	}
}
