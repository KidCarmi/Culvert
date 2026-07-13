package opsvc

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/kidcarmi/tac-platform/internal/domain"
)

// Rollback performs an explicit reverse-deploy to the previous known-good digest
// (NOT a tofu-atomic rollback). Partial/validation failures land here from FAILED.
// Restart failures, missing previous image, and reverse-deploy failures reach
// MANUAL_INTERVENTION_REQUIRED.
func (s *Service) Rollback(ctx context.Context, sc domain.Scope, opID string) (domain.State, error) {
	tx, err := s.St.Begin(ctx)
	if err != nil {
		return "", err
	}
	op, err := s.St.LockOperation(ctx, tx, sc, opID)
	if err != nil {
		tx.Rollback(ctx)
		return "", err
	}
	if op.State != domain.StateFailed {
		tx.Rollback(ctx)
		return op.State, domain.Errf(domain.CodeInvalidInput, "rollback requires FAILED, got %s", op.State)
	}
	// restart has no rollback target -> a human decides.
	if op.Kind != domain.KindDeploy {
		_ = s.St.ReleaseLease(ctx, tx, sc, op.WorkerID, op.ID)
		_ = s.St.Transition(ctx, tx, &op, domain.StateManualRequired, "operation-svc", domain.ActorService, "operation.manual_required",
			map[string]any{"reason": "restart has no rollback target"})
		return op.State, tx.Commit(ctx)
	}
	rt := op.RollbackTarget
	if err := s.St.Transition(ctx, tx, &op, domain.StateRollbackPending, "operation-svc", domain.ActorService, "rollback.pending",
		map[string]any{"target": rt.ImageDigest}); err != nil {
		tx.Rollback(ctx)
		return op.State, err
	}
	// previous image must be pullable (approved) — else MANUAL.
	w, werr := s.St.GetWorker(ctx, sc, op.WorkerID)
	if werr != nil || !contains(w.ApprovedDigests, rt.ImageDigest) {
		_ = s.St.ReleaseLease(ctx, tx, sc, op.WorkerID, op.ID)
		_ = s.St.Transition(ctx, tx, &op, domain.StateManualRequired, "executor:"+s.ExecName, domain.ActorService, "operation.manual_required",
			map[string]any{"reason": "previous image unavailable"})
		return op.State, tx.Commit(ctx)
	}
	if err := s.St.Transition(ctx, tx, &op, domain.StateRollingBack, "executor:"+s.ExecName, domain.ActorService, "rollback.started",
		map[string]any{"target": rt.ImageDigest}); err != nil {
		tx.Rollback(ctx)
		return op.State, err
	}
	if err := tx.Commit(ctx); err != nil {
		return op.State, err
	}
	// reverse-deploy (executor) + validate the known-good
	receipt, rerr := s.Ex.MutateReverse(ctx, op, rt.ImageDigest)
	ok := false
	if rerr == nil {
		if truth, terr := s.Ex.Inspect(ctx, op); terr == nil {
			ok = truth.Healthy && truth.Digest == rt.ImageDigest
		}
	}
	s.mustTx(ctx, sc, opID, func(o *domain.Operation, tx pgx.Tx) error {
		_ = s.St.ReleaseLease(ctx, tx, sc, o.WorkerID, o.ID)
		if ok {
			_ = s.St.SaveExecResult(ctx, tx, sc, o.ID, "rollback", receipt.CorrelationID, receipt, receipt.Applied, "ok")
			return s.St.Transition(ctx, tx, o, domain.StateRolledBack, "validator", domain.ActorService, "operation.rolled_back",
				map[string]any{"restored_digest": rt.ImageDigest})
		}
		return s.St.Transition(ctx, tx, o, domain.StateManualRequired, "validator", domain.ActorService, "operation.manual_required",
			map[string]any{"reason": "rollback reverse-deploy failed validation"})
	})
	return s.reload(ctx, sc, opID).State, nil
}

// Reconcile resolves operations orphaned by an executor process death, using
// provider TRUTH — never a blind retry. EXECUTING with an expired lease is resolved
// to VALIDATING (mutation applied) or FAILED (no change); VALIDATING with an expired
// lease re-runs validation.
func (s *Service) Reconcile(ctx context.Context) ([]string, error) {
	var log []string
	execStuck, err := s.St.StuckOps(ctx, domain.StateExecuting)
	if err != nil {
		return nil, err
	}
	for _, op := range execStuck {
		sc := op.Scope
		p, _ := s.St.GetPlan(ctx, sc, op.CurrentPlanID)
		truth, terr := s.Ex.Inspect(ctx, op)
		applied := op.Kind == domain.KindDeploy && terr == nil && truth.Digest == p.TargetImageDigest
		s.mustTx(ctx, sc, op.ID, func(o *domain.Operation, tx pgx.Tx) error {
			if o.State != domain.StateExecuting {
				return nil
			}
			_ = s.St.ReleaseLease(ctx, tx, sc, o.WorkerID, o.ID)
			if applied {
				_ = s.St.SaveExecResult(ctx, tx, sc, o.ID, string(o.Kind), truth.Digest, map[string]any{"reconciled": true}, []map[string]any{{"outcome": "updated"}}, "ok")
				return s.St.Transition(ctx, tx, o, domain.StateValidating, "reconciler", domain.ActorService, "reconcile.applied",
					map[string]any{"provider_truth": "applied", "digest": truth.Digest})
			}
			return s.St.Transition(ctx, tx, o, domain.StateFailed, "reconciler", domain.ActorService, "reconcile.no_change",
				map[string]any{"provider_truth": "no change / in-doubt"})
		})
		if applied {
			if ok, _, verr := s.Validate(ctx, sc, op.ID); verr == nil {
				log = append(log, op.ID+": reconciled->VALIDATING->"+cond(ok, "SUCCEEDED", "FAILED"))
			}
		} else {
			// deploy no-change or restart in-doubt -> FAILED; deploy can roll back, restart -> MANUAL.
			cur := s.reload(ctx, sc, op.ID)
			if cur.State == domain.StateFailed {
				st, _ := s.Rollback(ctx, sc, op.ID)
				log = append(log, op.ID+": reconciled->FAILED->"+string(st))
			}
		}
	}
	valStuck, err := s.St.StuckOps(ctx, domain.StateValidating)
	if err != nil {
		return log, err
	}
	for _, op := range valStuck {
		if ok, _, verr := s.Validate(ctx, op.Scope, op.ID); verr == nil {
			log = append(log, op.ID+": stuck-VALIDATING re-validated->"+cond(ok, "SUCCEEDED", "FAILED"))
		}
	}
	return log, nil
}

// View is a full, chat-independent read of an operation (state + events).
type View struct {
	Operation domain.Operation
	Events    []domain.Event
	AuditOK   bool
}

func (s *Service) Get(ctx context.Context, sc domain.Scope, opID string) (View, error) {
	op, err := s.St.GetOperation(ctx, sc, opID)
	if err != nil {
		return View{}, err
	}
	evs, err := s.St.ReadEvents(ctx, sc, opID)
	if err != nil {
		return View{}, err
	}
	ok, _ := s.St.VerifyAuditChain(ctx, sc, opID)
	return View{Operation: op, Events: evs, AuditOK: ok}, nil
}

func contains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}
func cond(b bool, a, c string) string {
	if b {
		return a
	}
	return c
}
