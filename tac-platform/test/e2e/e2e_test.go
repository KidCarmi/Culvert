package e2e

import (
	"context"
	"testing"

	"github.com/kidcarmi/tac-platform/internal/audit"
	"github.com/kidcarmi/tac-platform/internal/domain"
	"github.com/kidcarmi/tac-platform/internal/store"
	"github.com/kidcarmi/tac-platform/test/harness"
)

// L2 restart, fully autonomous, same executor spine -> SUCCEEDED + audit intact.
func TestRestartHappy_L2(t *testing.T) {
	k := harness.Env(t)
	op, err := k.Svc.RestartWorker(context.Background(), k.Scope, harness.Worker0, "stuck", "idem-r1", "human:cli", nil)
	if err != nil {
		t.Fatal(err)
	}
	if op.State != domain.StateSucceeded {
		t.Fatalf("restart state = %s, want SUCCEEDED", op.State)
	}
	ok, _ := k.Store.VerifyAuditChain(context.Background(), k.Scope, op.ID)
	if !ok {
		t.Fatal("audit chain must verify")
	}
}

// L3 deploy through the SAME executor spine: plan -> approve -> execute -> validate.
func TestDeployHappy_L3(t *testing.T) {
	k := harness.Env(t)
	ctx := context.Background()
	opID, _, approvalID := k.DeployApproved(t, harness.DigNew)
	st, err := k.Svc.Execute(ctx, k.Scope, opID, approvalID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if st != domain.StateValidating {
		t.Fatalf("execute -> %s, want VALIDATING", st)
	}
	ok, _, err := k.Svc.Validate(ctx, k.Scope, opID)
	if err != nil || !ok {
		t.Fatalf("validate ok=%v err=%v", ok, err)
	}
	v, _ := k.Svc.Get(ctx, k.Scope, opID)
	if v.Operation.State != domain.StateSucceeded {
		t.Fatalf("state=%s want SUCCEEDED", v.Operation.State)
	}
	tr, _ := k.Mock.Inspect(ctx, k.Scope, harness.Worker0)
	if tr.Digest != harness.DigNew {
		t.Fatalf("provider truth digest=%s want new", tr.Digest)
	}
}

// Failed validation -> explicit reverse-deploy rollback to known-good.
func TestDeployFail_Rollback(t *testing.T) {
	k := harness.Env(t, "validation_fail")
	ctx := context.Background()
	opID, _, approvalID := k.DeployApproved(t, harness.DigNew)
	_, _ = k.Svc.Execute(ctx, k.Scope, opID, approvalID, nil)
	ok, _, _ := k.Svc.Validate(ctx, k.Scope, opID)
	if ok {
		t.Fatal("validation should FAIL on a bad digest")
	}
	k.Mock.SetFaults() // the previous known-good image is healthy
	st, err := k.Svc.Rollback(ctx, k.Scope, opID)
	if err != nil {
		t.Fatal(err)
	}
	if st != domain.StateRolledBack {
		t.Fatalf("rollback state=%s want ROLLED_BACK", st)
	}
	tr, _ := k.Mock.Inspect(ctx, k.Scope, harness.Worker0)
	if tr.Digest != harness.DigGood {
		t.Fatalf("after rollback digest=%s want good", tr.Digest)
	}
}

// The operation record is fully reconstructable after the process ends: a brand-new
// store connection re-reads the op + verifies the signed hash chain.
func TestAuditReconstruct_AfterProcessEnd(t *testing.T) {
	k := harness.Env(t)
	ctx := context.Background()
	op, err := k.Svc.RestartWorker(ctx, k.Scope, harness.Worker0, "x", "idem-audit", "human:cli", nil)
	if err != nil {
		t.Fatal(err)
	}
	// "process end": a fresh Store/pool with no in-memory state.
	fresh, err := store.Connect(ctx, harness.DSN(), audit.DefaultTestSigner())
	if err != nil {
		t.Fatal(err)
	}
	ok, err := fresh.VerifyAuditChain(ctx, k.Scope, op.ID)
	if err != nil || !ok {
		t.Fatalf("audit must verify from a fresh process: ok=%v err=%v", ok, err)
	}
	evs, _ := fresh.ReadEvents(ctx, k.Scope, op.ID)
	if len(evs) < 6 {
		t.Fatalf("expected the full event chain, got %d", len(evs))
	}
}

// Idempotency through the service interface: a completed op is not re-executed.
func TestIdempotency_ThroughService(t *testing.T) {
	k := harness.Env(t)
	ctx := context.Background()
	op1, _ := k.Svc.RestartWorker(ctx, k.Scope, harness.Worker0, "x", "idem-dup", "human:cli", nil)
	evs1, _ := k.Store.ReadEvents(ctx, k.Scope, op1.ID)
	op2, _ := k.Svc.RestartWorker(ctx, k.Scope, harness.Worker0, "x", "idem-dup", "human:cli", nil)
	evs2, _ := k.Store.ReadEvents(ctx, k.Scope, op2.ID)
	if op1.ID != op2.ID {
		t.Fatalf("duplicate produced a new op: %s vs %s", op1.ID, op2.ID)
	}
	if len(evs1) != len(evs2) {
		t.Fatalf("duplicate re-executed: events %d -> %d", len(evs1), len(evs2))
	}
}
