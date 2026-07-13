// Package opsvc is the transactional operation service: the named domain operations
// that drive the FSM. Callers (tacctl, REST, future MCP) invoke these methods; none
// passes an arbitrary target state. The executor is the only infra mutator, invoked
// only from Execute / Rollback / Reconcile here.
package opsvc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/kidcarmi/tac-platform/internal/approval"
	"github.com/kidcarmi/tac-platform/internal/audit"
	"github.com/kidcarmi/tac-platform/internal/domain"
	"github.com/kidcarmi/tac-platform/internal/executor"
	"github.com/kidcarmi/tac-platform/internal/plan"
	"github.com/kidcarmi/tac-platform/internal/store"
)

const leaseTTL = 90 * time.Second

// Hook lets the crash-executor terminate the process at a named point to produce
// REAL crash semantics (not a caught exception). nil in normal operation.
type Hook func(point string)

type Service struct {
	St       *store.Store
	Ex       *executor.Executor
	Sg       *audit.Signer
	Now      func() time.Time
	ExecName string
}

func New(st *store.Store, ex *executor.Executor, sg *audit.Signer, execName string) *Service {
	return &Service{St: st, Ex: ex, Sg: sg, Now: func() time.Time { return time.Now().UTC() }, ExecName: execName}
}

func newOpID() string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return "OP-2026-" + hex.EncodeToString(b)
}

func (s *Service) buildOp(sc domain.Scope, kind domain.Kind, level domain.Level, worker, intent, idem, actor string, meta map[string]any) domain.Operation {
	if meta == nil {
		meta = map[string]any{}
	}
	return domain.Operation{ID: newOpID(), Scope: sc, Kind: kind, Level: level, WorkerID: worker,
		Intent: intent, IdempotencyKey: idem, InitiatingActor: actor, SessionMeta: meta}
}

// ── L2: restart_stateless_worker (autonomous when all preconditions pass) ───────
func (s *Service) RestartWorker(ctx context.Context, sc domain.Scope, worker, reason, idem, actor string, meta map[string]any) (domain.Operation, error) {
	op, existed, err := s.St.CreateOperation(ctx, s.buildOp(sc, domain.KindRestart, domain.L2, worker, reason, idem, actor, meta))
	if err != nil || existed {
		return op, err
	}
	if err := s.planAndPolicy(ctx, sc, &op, domain.KindRestart, "", domain.StateApprovalPending); err != nil {
		return s.reload(ctx, sc, op.ID), err
	}
	if op.State == domain.StatePolicyRejected {
		return op, nil
	}
	st, err := s.Execute(ctx, sc, op.ID, "", nil)
	if err != nil {
		return s.reload(ctx, sc, op.ID), err
	}
	if st == domain.StateValidating {
		if ok, _, verr := s.Validate(ctx, sc, op.ID); verr == nil && !ok {
			_, _ = s.Rollback(ctx, sc, op.ID) // restart -> MANUAL_INTERVENTION_REQUIRED
		}
	}
	return s.reload(ctx, sc, op.ID), nil
}

// ── L3: deploy_new_worker_version — plan (executes nothing) ─────────────────────
func (s *Service) CreateDeployPlan(ctx context.Context, sc domain.Scope, worker, targetDigest, reason, idem, actor string, meta map[string]any) (domain.Operation, domain.Plan, error) {
	op, existed, err := s.St.CreateOperation(ctx, s.buildOp(sc, domain.KindDeploy, domain.L3, worker, reason, idem, actor, meta))
	if err != nil {
		return op, domain.Plan{}, err
	}
	if existed {
		p, perr := s.St.GetPlan(ctx, sc, op.CurrentPlanID)
		return op, p, perr
	}
	if err := s.planAndPolicy(ctx, sc, &op, domain.KindDeploy, targetDigest, domain.StateReviewPending); err != nil {
		return op, domain.Plan{}, err
	}
	p, err := s.St.GetPlan(ctx, sc, op.CurrentPlanID)
	if op.State == domain.StatePolicyRejected {
		return op, p, domain.ErrD(domain.CodePolicyRejected, "plan rejected by policy", join(p.PolicyResult.FailedIDs()))
	}
	return op, p, err
}

// planAndPolicy: CREATED->DISCOVERING->PLANNING, build+persist plan, then either
// ->POLICY_REJECTED or ->passState. One transaction.
func (s *Service) planAndPolicy(ctx context.Context, sc domain.Scope, op *domain.Operation, kind domain.Kind, target string, passState domain.State) error {
	tx, err := s.St.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	locked, err := s.St.LockOperation(ctx, tx, sc, op.ID)
	if err != nil {
		return err
	}
	*op = locked
	if err := s.St.Transition(ctx, tx, op, domain.StateDiscovering, "operation-svc", domain.ActorService, "discovering", nil); err != nil {
		return err
	}
	w, err := s.St.GetWorker(ctx, sc, op.WorkerID)
	if err != nil {
		return err
	}
	if err := s.St.Transition(ctx, tx, op, domain.StatePlanning, "planner", domain.ActorService, "planning", nil); err != nil {
		return err
	}
	p := plan.Build(*op, w, kind, target, s.Sg, s.Now())
	if err := s.St.SavePlan(ctx, tx, p); err != nil {
		return err
	}
	if err := s.St.SetCurrentPlan(ctx, tx, *op, p.PlanID, p.RollbackTarget); err != nil {
		return err
	}
	op.CurrentPlanID = p.PlanID
	op.RollbackTarget = p.RollbackTarget
	if !p.PolicyResult.Passed {
		if err := s.St.Transition(ctx, tx, op, domain.StatePolicyRejected, "policy", domain.ActorService, "policy.rejected",
			map[string]any{"failed": p.PolicyResult.FailedIDs()}); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	etype := "policy.passed"
	if passState == domain.StateApprovalPending {
		etype = "approval.not_required"
	}
	if err := s.St.Transition(ctx, tx, op, passState, "policy", domain.ActorService, etype,
		map[string]any{"plan_id": p.PlanID}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ── Approve (human, plan-bound) ─────────────────────────────────────────────────
func (s *Service) Approve(ctx context.Context, sc domain.Scope, opID, planID, approver string) (domain.Approval, error) {
	op, err := s.St.GetOperation(ctx, sc, opID)
	if err != nil {
		return domain.Approval{}, err
	}
	p, err := s.St.GetPlan(ctx, sc, planID)
	if err != nil {
		return domain.Approval{}, err
	}
	appr, err := approval.Build(op, p, approver, s.Sg, s.Now())
	if err != nil {
		return domain.Approval{}, err
	}
	tx, err := s.St.Begin(ctx)
	if err != nil {
		return domain.Approval{}, err
	}
	defer tx.Rollback(ctx)
	locked, err := s.St.LockOperation(ctx, tx, sc, opID)
	if err != nil {
		return domain.Approval{}, err
	}
	if err := s.St.SaveApproval(ctx, tx, appr); err != nil {
		return domain.Approval{}, err
	}
	if err := s.St.Transition(ctx, tx, &locked, domain.StateApproved, "human:"+approver, domain.ActorHuman, "approved",
		map[string]any{"approval_id": appr.ApprovalID, "plan_id": planID}); err != nil {
		return domain.Approval{}, err
	}
	return appr, tx.Commit(ctx)
}

func (s *Service) reload(ctx context.Context, sc domain.Scope, id string) domain.Operation {
	op, _ := s.St.GetOperation(ctx, sc, id)
	return op
}

func join(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}
