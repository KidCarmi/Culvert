package opsvc

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/kidcarmi/tac-platform/internal/approval"
	"github.com/kidcarmi/tac-platform/internal/domain"
	"github.com/kidcarmi/tac-platform/internal/validator"
)

// Execute is the single mutation spine (L2 restart and L3 deploy). tx1 atomically:
// verifies the plan-bound approval (L3), acquires the per-worker lease, consumes the
// approval, and moves the op to EXECUTING. Then the provider is mutated OUTSIDE any
// DB tx (the crash window). hook(point) lets the crash-executor die at a named point.
func (s *Service) Execute(ctx context.Context, sc domain.Scope, opID, approvalID string, hook Hook) (domain.State, error) {
	tx, err := s.St.Begin(ctx)
	if err != nil {
		return "", err
	}
	op, err := s.St.LockOperation(ctx, tx, sc, opID)
	if err != nil {
		tx.Rollback(ctx)
		return "", err
	}
	p, err := s.St.GetPlan(ctx, sc, op.CurrentPlanID)
	if err != nil {
		tx.Rollback(ctx)
		return op.State, err
	}
	if op.Level == domain.L3 {
		appr, aerr := s.St.GetApproval(ctx, sc, approvalID)
		if aerr != nil {
			tx.Rollback(ctx)
			return op.State, aerr
		}
		if verr := approval.Verify(op, p, appr, s.Sg, s.Now()); verr != nil {
			_ = s.St.Transition(ctx, tx, &op, domain.StateApprovalPending, "executor:"+s.ExecName, domain.ActorService, "execution.rejected",
				map[string]any{"reason": verr.Error()})
			_ = tx.Commit(ctx)
			return op.State, verr
		}
	}
	if err := s.St.AcquireLease(ctx, tx, sc, op.WorkerID, op.ID, s.ExecName, leaseTTL); err != nil {
		tx.Rollback(ctx)
		return op.State, err
	}
	if op.Level == domain.L3 {
		if err := s.St.ConsumeApproval(ctx, tx, sc, approvalID); err != nil {
			tx.Rollback(ctx)
			return op.State, err
		}
	}
	if err := s.St.Transition(ctx, tx, &op, domain.StateExecutionQueued, "operation-svc", domain.ActorService, "queued", nil); err != nil {
		tx.Rollback(ctx)
		return op.State, err
	}
	if err := s.St.Transition(ctx, tx, &op, domain.StateExecuting, "executor:"+s.ExecName, domain.ActorService, "execution.started",
		map[string]any{"plan_id": p.PlanID, "minted_cred": "scoped ttl=15m (no value logged)"}); err != nil {
		tx.Rollback(ctx)
		return op.State, err
	}
	if err := tx.Commit(ctx); err != nil {
		return op.State, err
	}

	// ── crash window A: before provider mutation ──
	if hook != nil {
		hook("before_mutation")
	}
	receipt, mErr := s.Ex.Mutate(ctx, op, p) // provider side effect (the only mutation)
	// ── crash window B: after provider mutation, before receipt persistence ──
	if hook != nil {
		hook("after_mutation")
	}
	if mErr != nil {
		if domain.CodeOf(mErr) == domain.CodeUnknownOutcome {
			return domain.StateExecuting, mErr // in-doubt: no retry, no transition; reconciler resolves
		}
		s.mustTx(ctx, sc, opID, func(o *domain.Operation, tx pgx.Tx) error {
			_ = s.St.ReleaseLease(ctx, tx, sc, o.WorkerID, o.ID)
			return s.St.Transition(ctx, tx, o, domain.StateFailed, "executor:"+s.ExecName, domain.ActorService, "execution.failed",
				map[string]any{"error_code": string(domain.CodeOf(mErr))})
		})
		return domain.StateFailed, mErr
	}
	s.mustTx(ctx, sc, opID, func(o *domain.Operation, tx pgx.Tx) error {
		_ = s.St.SaveExecResult(ctx, tx, sc, o.ID, string(o.Kind), receipt.CorrelationID, receipt, receipt.Applied, orOK(receipt.Outcome))
		return s.St.Transition(ctx, tx, o, domain.StateValidating, "executor:"+s.ExecName, domain.ActorService, "execution.applied",
			map[string]any{"provider_correlation_id": receipt.CorrelationID, "outcome": orOK(receipt.Outcome)})
	})
	// ── crash window C: after receipt persistence, before validation ──
	if hook != nil {
		hook("after_receipt")
	}
	return domain.StateValidating, nil
}

func orOK(s string) string {
	if s == "" {
		return "ok"
	}
	return s
}

// Validate gates SUCCEEDED. Provider-200 is not success; validator reads truth.
func (s *Service) Validate(ctx context.Context, sc domain.Scope, opID string) (bool, validator.Result, error) {
	op, err := s.St.GetOperation(ctx, sc, opID)
	if err != nil {
		return false, validator.Result{}, err
	}
	p, err := s.St.GetPlan(ctx, sc, op.CurrentPlanID)
	if err != nil {
		return false, validator.Result{}, err
	}
	outcome, _ := s.St.LatestOutcome(ctx, sc, opID)
	res, err := validator.Run(ctx, s.Ex, op, p, outcome)
	if err != nil {
		return false, res, err
	}
	_ = s.St.SetValidation(ctx, sc, opID, string(op.Kind), res)
	s.mustTx(ctx, sc, opID, func(o *domain.Operation, tx pgx.Tx) error {
		if res.Passed {
			_ = s.St.ReleaseLease(ctx, tx, sc, o.WorkerID, o.ID)
			return s.St.Transition(ctx, tx, o, domain.StateSucceeded, "validator", domain.ActorService, "succeeded",
				map[string]any{"gates": res.Gates})
		}
		return s.St.Transition(ctx, tx, o, domain.StateFailed, "validator", domain.ActorService, "validation.failed",
			map[string]any{"gates": res.Gates})
	})
	return res.Passed, res, nil
}

// mustTx locks the op FOR UPDATE and runs fn in one tx. Panics on infra error so
// test failures are loud; domain outcomes are returned via op state.
func (s *Service) mustTx(ctx context.Context, sc domain.Scope, opID string, fn func(op *domain.Operation, tx pgx.Tx) error) {
	tx, err := s.St.Begin(ctx)
	if err != nil {
		panic(err)
	}
	defer tx.Rollback(ctx)
	op, err := s.St.LockOperation(ctx, tx, sc, opID)
	if err != nil {
		panic(err)
	}
	if err := fn(&op, tx); err != nil {
		panic(err)
	}
	if err := tx.Commit(ctx); err != nil {
		panic(err)
	}
}
