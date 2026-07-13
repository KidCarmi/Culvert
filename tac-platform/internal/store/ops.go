package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/kidcarmi/tac-platform/internal/domain"
)

// CreateOperation inserts a new CREATED op. On idempotency-key reuse (per tenant)
// it returns the EXISTING op and existed=true (exactly-once create; R9-F2).
func (s *Store) CreateOperation(ctx context.Context, op domain.Operation) (domain.Operation, bool, error) {
	tx, err := s.Begin(ctx)
	if err != nil {
		return op, false, err
	}
	defer tx.Rollback(ctx)
	now := s.Now()
	_, err = tx.Exec(ctx,
		`INSERT INTO operations(id,tenant_id,kind,level,environment,region,worker_id,intent,state,idempotency_key,initiating_actor,session_meta,version,created_at,updated_at,expires_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,'CREATED',$9,$10,$11,0,$12,$12,$13)`,
		op.ID, op.Scope.TenantID, op.Kind, op.Level, op.Scope.Environment, op.Scope.Region, op.WorkerID, op.Intent,
		op.IdempotencyKey, op.InitiatingActor, jsonb(op.SessionMeta), now, now.Add(30*time.Minute))
	if err != nil {
		// The failed INSERT aborts this tx; the deferred Rollback cleans it up. Load
		// the existing op on a FRESH pool connection (not the aborted tx).
		if isUnique(err) {
			existing, lerr := s.loadOp(ctx, s.Pool, op.Scope.TenantID, "idempotency_key", op.IdempotencyKey, false)
			if lerr != nil {
				return op, false, lerr
			}
			return existing, true, nil
		}
		return op, false, err
	}
	op.State = domain.StateCreated
	if err := s.appendEvent(ctx, tx, op, "", domain.StateCreated, actorOf(op), akOf(op), "created",
		map[string]any{"intent": op.Intent, "idempotency_key": op.IdempotencyKey, "initiating_actor": op.InitiatingActor, "session_meta": op.SessionMeta}); err != nil {
		return op, false, err
	}
	return op, false, tx.Commit(ctx)
}

func actorOf(op domain.Operation) string {
	if v, ok := op.SessionMeta["via"]; ok && v == "ai" {
		return "claude:planner"
	}
	return op.InitiatingActor
}
func akOf(op domain.Operation) domain.ActorKind {
	if v, ok := op.SessionMeta["via"]; ok && v == "ai" {
		return domain.ActorModel
	}
	return domain.ActorHuman
}

// GetOperation loads an op scoped to tenant. Cross-tenant reads return not_found.
func (s *Store) GetOperation(ctx context.Context, sc domain.Scope, id string) (domain.Operation, error) {
	return s.loadOp(ctx, s.Pool, sc.TenantID, "id", id, false)
}

// LockOperation loads an op FOR UPDATE inside tx (tenant-scoped).
func (s *Store) LockOperation(ctx context.Context, tx pgx.Tx, sc domain.Scope, id string) (domain.Operation, error) {
	return s.loadOp(ctx, tx, sc.TenantID, "id", id, true)
}

type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func (s *Store) loadOp(ctx context.Context, q querier, tenant, col, val string, forUpdate bool) (domain.Operation, error) {
	sql := `SELECT id,tenant_id,kind,level,environment,region,worker_id,intent,state,current_plan_id,rollback_target,idempotency_key,initiating_actor,session_meta,version,created_at,updated_at,expires_at
			FROM operations WHERE tenant_id=$1 AND ` + col + `=$2`
	if forUpdate {
		sql += " FOR UPDATE"
	}
	var op domain.Operation
	var planID, rt, sm *string
	err := q.QueryRow(ctx, sql, tenant, val).Scan(
		&op.ID, &op.Scope.TenantID, &op.Kind, &op.Level, &op.Scope.Environment, &op.Scope.Region, &op.WorkerID, &op.Intent, &op.State,
		&planID, &rt, &op.IdempotencyKey, &op.InitiatingActor, &sm, &op.Version, &op.CreatedAt, &op.UpdatedAt, &op.ExpiresAt)
	if err == pgx.ErrNoRows {
		return op, domain.Err(domain.CodeNotFound, "operation not found in tenant scope")
	}
	if err != nil {
		return op, err
	}
	if planID != nil {
		op.CurrentPlanID = *planID
	}
	if rt != nil {
		_ = json.Unmarshal([]byte(*rt), &op.RollbackTarget)
	}
	if sm != nil {
		_ = json.Unmarshal([]byte(*sm), &op.SessionMeta)
	}
	return op, nil
}

// SetCurrentPlan records the op's current plan + rollback target (inside tx).
func (s *Store) SetCurrentPlan(ctx context.Context, tx pgx.Tx, op domain.Operation, planID string, rt domain.RollbackTarget) error {
	_, err := tx.Exec(ctx, `UPDATE operations SET current_plan_id=$1, rollback_target=$2 WHERE id=$3`,
		planID, jsonb(rt), op.ID)
	return err
}

// ── plans ───────────────────────────────────────────────────────────────────
func (s *Store) SavePlan(ctx context.Context, tx pgx.Tx, p domain.Plan) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO plans(plan_id,tenant_id,op_id,kind,commit_sha,config_digest,provider_lock_digest,target_image_digest,expected_changes,policy_result,review_results,rollback_target,cost_delta_usd,health_validation,signature,signer_key_id,created_at,expires_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'{}',$11,$12,$13,$14,$15,$16,$17) ON CONFLICT (plan_id) DO NOTHING`,
		p.PlanID, p.Scope.TenantID, p.OpID, p.Kind, p.CommitSHA, p.ConfigDigest, p.ProviderLockDigest, p.TargetImageDigest,
		jsonb(p.ExpectedChanges), jsonb(p.PolicyResult), jsonb(p.RollbackTarget), p.CostDeltaUSD, p.HealthValidation,
		p.Signature, p.SignerKeyID, p.CreatedAt, p.ExpiresAt)
	return err
}

func (s *Store) GetPlan(ctx context.Context, sc domain.Scope, planID string) (domain.Plan, error) {
	var p domain.Plan
	var ec, pr, rt string
	err := s.Pool.QueryRow(ctx,
		`SELECT plan_id,tenant_id,op_id,kind,commit_sha,config_digest,provider_lock_digest,target_image_digest,expected_changes,policy_result,rollback_target,cost_delta_usd,health_validation,signature,signer_key_id,created_at,expires_at
		 FROM plans WHERE tenant_id=$1 AND plan_id=$2`, sc.TenantID, planID).Scan(
		&p.PlanID, &p.Scope.TenantID, &p.OpID, &p.Kind, &p.CommitSHA, &p.ConfigDigest, &p.ProviderLockDigest, &p.TargetImageDigest,
		&ec, &pr, &rt, &p.CostDeltaUSD, &p.HealthValidation, &p.Signature, &p.SignerKeyID, &p.CreatedAt, &p.ExpiresAt)
	if err == pgx.ErrNoRows {
		return p, domain.Err(domain.CodeNotFound, "plan not found in tenant scope")
	}
	if err != nil {
		return p, err
	}
	_ = json.Unmarshal([]byte(ec), &p.ExpectedChanges)
	_ = json.Unmarshal([]byte(pr), &p.PolicyResult)
	_ = json.Unmarshal([]byte(rt), &p.RollbackTarget)
	p.Scope.Environment = sc.Environment
	p.Scope.Region = sc.Region
	return p, nil
}

// ── approvals ─────────────────────────────────────────────────────────────────
func (s *Store) SaveApproval(ctx context.Context, tx pgx.Tx, a domain.Approval) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO approvals(approval_id,tenant_id,op_id,plan_id,bound_plan_signature,approver,approver_is_author,approver_signature,decision,single_use_consumed,created_at,expires_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,false,$10,$11)`,
		a.ApprovalID, a.Scope.TenantID, a.OpID, a.PlanID, a.BoundPlanSignature, a.Approver, a.ApproverIsAuthor, a.ApproverSignature, a.Decision, a.CreatedAt, a.ExpiresAt)
	return err
}

func (s *Store) GetApproval(ctx context.Context, sc domain.Scope, id string) (domain.Approval, error) {
	var a domain.Approval
	err := s.Pool.QueryRow(ctx,
		`SELECT approval_id,tenant_id,op_id,plan_id,bound_plan_signature,approver,approver_is_author,approver_signature,decision,single_use_consumed,created_at,expires_at
		 FROM approvals WHERE tenant_id=$1 AND approval_id=$2`, sc.TenantID, id).Scan(
		&a.ApprovalID, &a.Scope.TenantID, &a.OpID, &a.PlanID, &a.BoundPlanSignature, &a.Approver, &a.ApproverIsAuthor, &a.ApproverSignature, &a.Decision, &a.SingleUseConsumed, &a.CreatedAt, &a.ExpiresAt)
	if err == pgx.ErrNoRows {
		return a, domain.Err(domain.CodeNotFound, "approval not found in tenant scope")
	}
	return a, err
}

// ConsumeApproval marks an approval single-use-consumed; MUST run in the same tx as
// StartExecution. Returns conflict if already consumed (idempotency at execute).
func (s *Store) ConsumeApproval(ctx context.Context, tx pgx.Tx, sc domain.Scope, id string) error {
	ct, err := tx.Exec(ctx, `UPDATE approvals SET single_use_consumed=true WHERE tenant_id=$1 AND approval_id=$2 AND single_use_consumed=false`, sc.TenantID, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return domain.Err(domain.CodeApprovalInvalid, "approval already consumed")
	}
	return nil
}

// ── leases (SELECT FOR UPDATE) ────────────────────────────────────────────────
// AcquireLease grabs the per-worker mutation lease inside tx. Uses SELECT ... FOR
// UPDATE on the lease row so concurrent executors serialize; returns lease_held if
// a live lease is owned by another op.
func (s *Store) AcquireLease(ctx context.Context, tx pgx.Tx, sc domain.Scope, worker, opID, exec string, ttl time.Duration) error {
	key := sc.LeaseKey(worker)
	var holder string
	var exp time.Time
	err := tx.QueryRow(ctx, `SELECT holder_op_id, expires_at FROM leases WHERE resource_key=$1 FOR UPDATE`, key).Scan(&holder, &exp)
	now := s.Now()
	if err == nil {
		if holder != opID && exp.After(now) {
			return domain.Errf(domain.CodeLeaseHeld, "worker lease held by %s", holder)
		}
		_, err = tx.Exec(ctx, `UPDATE leases SET holder_op_id=$2, holder_exec=$3, acquired_at=$4, heartbeat_at=$4, expires_at=$5 WHERE resource_key=$1`,
			key, opID, exec, now, now.Add(ttl))
		return err
	}
	if err == pgx.ErrNoRows {
		_, err = tx.Exec(ctx, `INSERT INTO leases(resource_key,tenant_id,holder_op_id,holder_exec,acquired_at,heartbeat_at,expires_at) VALUES($1,$2,$3,$4,$5,$5,$6)`,
			key, sc.TenantID, opID, exec, now, now.Add(ttl))
		return err
	}
	return err
}

func (s *Store) ReleaseLease(ctx context.Context, q execer, sc domain.Scope, worker, opID string) error {
	_, err := q.Exec(ctx, `DELETE FROM leases WHERE resource_key=$1 AND holder_op_id=$2`, sc.LeaseKey(worker), opID)
	return err
}

// ForceExpireLease simulates the lease TTL elapsing (used by crash tests).
func (s *Store) ForceExpireLease(ctx context.Context, sc domain.Scope, worker string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE leases SET expires_at=$2 WHERE resource_key=$1`, sc.LeaseKey(worker), s.Now().Add(-time.Second))
	return err
}

func (s *Store) LeaseHeld(ctx context.Context, sc domain.Scope, worker string) (bool, string) {
	var holder string
	var exp time.Time
	err := s.Pool.QueryRow(ctx, `SELECT holder_op_id, expires_at FROM leases WHERE resource_key=$1`, sc.LeaseKey(worker)).Scan(&holder, &exp)
	if err != nil {
		return false, ""
	}
	return exp.After(s.Now()), holder
}

type execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}
