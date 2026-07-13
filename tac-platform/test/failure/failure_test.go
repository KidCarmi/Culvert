package failure

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/kidcarmi/tac-platform/internal/domain"
	"github.com/kidcarmi/tac-platform/internal/provider"
	"github.com/kidcarmi/tac-platform/test/harness"
)

var crashBin string

func TestMain(m *testing.M) {
	wd, _ := os.Getwd()
	root := filepath.Join(wd, "..", "..")
	crashBin = filepath.Join(os.TempDir(), "tac-crash-executor")
	cmd := exec.Command("go", "build", "-o", crashBin, "./cmd/crash-executor")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		os.Stderr.Write(out)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func crashEnv(op, approval, at string) []string {
	return append(os.Environ(),
		"TAC_DSN="+harness.DSN(), "TAC_TENANT="+harness.TenantA, "TAC_ENV="+harness.Env0,
		"TAC_REGION="+harness.Region0, "TAC_OP="+op, "TAC_APPROVAL="+approval, "TAC_CRASH_AT="+at)
}

// REAL crash semantics: a separate process is terminated (os.Exit, no defers) at each
// of the four named points. The op is left with the lease HELD; only the reconciler
// (after lease expiry, from provider truth) resolves it. No blind retry.
func TestRealCrashSemantics(t *testing.T) {
	cases := []struct {
		at    string
		final domain.State
	}{
		{"before_mutation", domain.StateRolledBack}, // no mutation -> FAILED -> auto reverse-deploy -> ROLLED_BACK
		{"after_mutation", domain.StateSucceeded},   // mutation applied (=after success, before receipt) -> resume -> SUCCEEDED
		{"after_receipt", domain.StateSucceeded},    // receipt persisted, before validation -> re-validate -> SUCCEEDED
	}
	for _, c := range cases {
		t.Run(c.at, func(t *testing.T) {
			k := harness.Env(t)
			ctx := context.Background()
			opID, _, approvalID := k.DeployApproved(t, harness.DigNew)

			cmd := exec.Command(crashBin)
			cmd.Env = crashEnv(opID, approvalID, c.at)
			err := cmd.Run()
			if ec := exitCode(err); ec != 137 {
				t.Fatalf("crash-executor should exit 137, got %d (%v)", ec, err)
			}
			// the op is orphaned mid-flight with the lease still held
			held, holder := k.Store.LeaseHeld(ctx, k.Scope, harness.Worker0)
			if !held || holder != opID {
				t.Fatalf("after crash the lease must still be held by %s (held=%v holder=%s)", opID, held, holder)
			}
			v, _ := k.Svc.Get(ctx, k.Scope, opID)
			if v.Operation.State != domain.StateExecuting && v.Operation.State != domain.StateValidating {
				t.Fatalf("after crash state=%s, want EXECUTING/VALIDATING (stuck)", v.Operation.State)
			}
			// reconciler resolves from provider truth after lease expiry
			if err := k.Store.ForceExpireLease(ctx, k.Scope, harness.Worker0); err != nil {
				t.Fatal(err)
			}
			if _, err := k.Svc.Reconcile(ctx); err != nil {
				t.Fatal(err)
			}
			got, _ := k.Svc.Get(ctx, k.Scope, opID)
			if got.Operation.State != c.final {
				t.Fatalf("%s: reconciled state=%s, want %s", c.at, got.Operation.State, c.final)
			}
			if ok, _ := k.Store.VerifyAuditChain(ctx, k.Scope, opID); !ok {
				t.Fatal("audit chain must verify after crash+reconcile")
			}
		})
	}
}

// Unknown/in-doubt provider outcome: op stays EXECUTING; NO blind retry; the
// reconciler resolves from truth, and the mutation is applied exactly once.
func TestUnknownOutcome_NoBlindRetry(t *testing.T) {
	k := harness.Env(t, provider.FaultUnknown)
	ctx := context.Background()
	opID, _, approvalID := k.DeployApproved(t, harness.DigNew)
	st, err := k.Svc.Execute(ctx, k.Scope, opID, approvalID, nil)
	if st != domain.StateExecuting || domain.CodeOf(err) != domain.CodeUnknownOutcome {
		t.Fatalf("unknown outcome: state=%s err=%v (want EXECUTING + unknown_outcome)", st, err)
	}
	genBefore, _ := k.Mock.Inspect(ctx, k.Scope, harness.Worker0)
	k.Mock.SetFaults() // provider now answers cleanly for the reconciler's Inspect
	_ = k.Store.ForceExpireLease(ctx, k.Scope, harness.Worker0)
	if _, err := k.Svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	got, _ := k.Svc.Get(ctx, k.Scope, opID)
	if got.Operation.State != domain.StateSucceeded {
		t.Fatalf("state=%s want SUCCEEDED after reconcile", got.Operation.State)
	}
	genAfter, _ := k.Mock.Inspect(ctx, k.Scope, harness.Worker0)
	if genAfter.Generation != genBefore.Generation {
		t.Fatalf("mutation must NOT be re-applied: generation %d -> %d", genBefore.Generation, genAfter.Generation)
	}
}

// The remaining failure-matrix scenarios (mirrors the Python reference oracle).
func TestFailureMatrix(t *testing.T) {
	ctx := context.Background()

	t.Run("1_disconnect_during_planning", func(t *testing.T) {
		k := harness.Env(t)
		op, _, _ := k.Svc.CreateDeployPlan(ctx, k.Scope, harness.Worker0, harness.DigNew, "d", "i1", "human:alice", nil)
		v, _ := k.Svc.Get(ctx, k.Scope, op.ID)
		if v.Operation.State != domain.StateReviewPending {
			t.Fatalf("state=%s want REVIEW_PENDING (plan intact)", v.Operation.State)
		}
	})
	t.Run("2_disconnect_during_execution", func(t *testing.T) {
		k := harness.Env(t)
		opID, _, approvalID := k.DeployApproved(t, harness.DigNew)
		st, _ := k.Svc.Execute(ctx, k.Scope, opID, approvalID, nil)
		if st != domain.StateValidating {
			t.Fatalf("op continues in executor -> VALIDATING, got %s", st)
		}
	})
	t.Run("3_duplicate_request", func(t *testing.T) {
		k := harness.Env(t)
		a, _ := k.Svc.RestartWorker(ctx, k.Scope, harness.Worker0, "x", "dup3", "h", nil)
		b, _ := k.Svc.RestartWorker(ctx, k.Scope, harness.Worker0, "x", "dup3", "h", nil)
		if a.ID != b.ID {
			t.Fatal("duplicate must return the same op")
		}
	})
	t.Run("4_stale_approval", func(t *testing.T) {
		k := harness.Env(t)
		opID, planID, approvalID := k.DeployApproved(t, harness.DigNew)
		_, _ = planID, approvalID
		_, _ = k.Store.Pool.Exec(ctx, `UPDATE approvals SET expires_at = now() - interval '1 minute' WHERE op_id=$1`, opID)
		st, err := k.Svc.Execute(ctx, k.Scope, opID, approvalID, nil)
		if domain.CodeOf(err) != domain.CodeApprovalInvalid {
			t.Fatalf("stale approval must be rejected, got %v (state %s)", err, st)
		}
	})
	t.Run("5_plan_changed_after_approval", func(t *testing.T) {
		k := harness.Env(t)
		opID, planID, approvalID := k.DeployApproved(t, harness.DigNew)
		// the plan bytes change after approval (commit/digest changed) -> signature differs
		_, _ = k.Store.Pool.Exec(ctx, `UPDATE plans SET signature='CHANGED-AFTER-APPROVAL' WHERE plan_id=$1`, planID)
		_, err := k.Svc.Execute(ctx, k.Scope, opID, approvalID, nil)
		if domain.CodeOf(err) != domain.CodeApprovalInvalid {
			t.Fatalf("changed plan must invalidate approval, got %v", err)
		}
	})
	t.Run("6_policy_rejection", func(t *testing.T) {
		k := harness.Env(t)
		op, _, err := k.Svc.CreateDeployPlan(ctx, k.Scope, harness.Worker0, harness.DigUnapproved, "d", "i6", "human:alice", nil)
		if domain.CodeOf(err) != domain.CodePolicyRejected || op.State != domain.StatePolicyRejected {
			t.Fatalf("unapproved digest must be POLICY_REJECTED, got state=%s err=%v", op.State, err)
		}
	})
	t.Run("10_validation_failure_rolls_back", func(t *testing.T) {
		k := harness.Env(t, provider.FaultValidationFail)
		opID, _, approvalID := k.DeployApproved(t, harness.DigNew)
		_, _ = k.Svc.Execute(ctx, k.Scope, opID, approvalID, nil)
		ok, _, _ := k.Svc.Validate(ctx, k.Scope, opID)
		if ok {
			t.Fatal("bad digest must fail validation")
		}
		k.Mock.SetFaults()
		st, _ := k.Svc.Rollback(ctx, k.Scope, opID)
		if st != domain.StateRolledBack {
			t.Fatalf("want ROLLED_BACK, got %s", st)
		}
	})
	t.Run("11_rollback_failure_manual", func(t *testing.T) {
		k := harness.Env(t, provider.FaultValidationFail)
		opID, _, approvalID := k.DeployApproved(t, harness.DigNew)
		_, _ = k.Svc.Execute(ctx, k.Scope, opID, approvalID, nil)
		_, _, _ = k.Svc.Validate(ctx, k.Scope, opID)
		k.Mock.SetFaults(provider.FaultRollbackFail) // reverse-deploy also unhealthy
		st, _ := k.Svc.Rollback(ctx, k.Scope, opID)
		if st != domain.StateManualRequired {
			t.Fatalf("rollback failure must reach MANUAL_INTERVENTION_REQUIRED, got %s", st)
		}
	})
	t.Run("12_concurrent_op_same_worker", func(t *testing.T) {
		k := harness.Env(t)
		opID, _, approvalID := k.DeployApproved(t, harness.DigNew)
		_, _ = k.Svc.Execute(ctx, k.Scope, opID, approvalID, nil) // holds lease (VALIDATING)
		b, _ := k.Svc.RestartWorker(ctx, k.Scope, harness.Worker0, "x", "conc12", "h", nil)
		// b should be blocked at execute time by the worker lease
		v, _ := k.Svc.Get(ctx, k.Scope, b.ID)
		if v.Operation.State == domain.StateSucceeded {
			t.Fatal("second op must not run while the worker lease is held")
		}
	})
	t.Run("14_expired_credentials_clean_fail", func(t *testing.T) {
		k := harness.Env(t, provider.FaultUnavailable)
		opID, _, approvalID := k.DeployApproved(t, harness.DigNew)
		st, err := k.Svc.Execute(ctx, k.Scope, opID, approvalID, nil)
		if st != domain.StateFailed || domain.CodeOf(err) != domain.CodeProviderError {
			t.Fatalf("clean provider failure -> FAILED, got state=%s err=%v", st, err)
		}
	})
	t.Run("15_provider_unavailable", func(t *testing.T) {
		k := harness.Env(t, provider.FaultUnavailable)
		opID, _, approvalID := k.DeployApproved(t, harness.DigNew)
		st, _ := k.Svc.Execute(ctx, k.Scope, opID, approvalID, nil)
		if st != domain.StateFailed {
			t.Fatalf("provider unavailable -> FAILED, got %s", st)
		}
	})
	t.Run("16_ai_unavailable_tacctl_path", func(t *testing.T) {
		k := harness.Env(t)
		op, _ := k.Svc.RestartWorker(ctx, k.Scope, harness.Worker0, "x", "noai16", "human:cli", nil)
		if op.State != domain.StateSucceeded {
			t.Fatalf("full flow with no AI must succeed, got %s", op.State)
		}
	})
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	return -1
}
