package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kidcarmi/tac-platform/internal/audit"
	"github.com/kidcarmi/tac-platform/internal/domain"
)

// Migrate applies schema SQL (idempotent create-if-not-exists is the caller's job;
// tests drop-and-recreate). It also tolerates re-runs by ignoring "already exists".
func (s *Store) Migrate(ctx context.Context, sqlText string) error {
	_, err := s.Pool.Exec(ctx, sqlText)
	return err
}

func (s *Store) Reset(ctx context.Context) error {
	_, err := s.Pool.Exec(ctx, `DROP TABLE IF EXISTS outbox, operation_events, execution_results, approvals, plans, leases, operations, approved_digests, provider_worker_state, workers CASCADE`)
	return err
}

// SeedWorker registers an allowlisted worker + its approved digests + provider truth.
func (s *Store) SeedWorker(ctx context.Context, w domain.Worker) error {
	tx, err := s.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx,
		`INSERT INTO workers(tenant_id,worker_id,environment,region,allowlisted,approved_registry,current_image_digest,known_good_digest,config)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
		 ON CONFLICT (tenant_id,worker_id) DO UPDATE SET allowlisted=$5,current_image_digest=$7,known_good_digest=$8`,
		w.Scope.TenantID, w.WorkerID, w.Scope.Environment, w.Scope.Region, w.Allowlisted, w.ApprovedReg, w.CurrentDigest, w.KnownGoodDigest, jsonb(w.Config)); err != nil {
		return err
	}
	for _, d := range w.ApprovedDigests {
		if _, err := tx.Exec(ctx, `INSERT INTO approved_digests(tenant_id,worker_id,image_digest) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, w.Scope.TenantID, w.WorkerID, d); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO provider_worker_state(tenant_id,worker_id,current_digest,healthy,generation) VALUES($1,$2,$3,true,1)
		 ON CONFLICT (tenant_id,worker_id) DO UPDATE SET current_digest=$3, healthy=true`,
		w.Scope.TenantID, w.WorkerID, w.CurrentDigest); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) GetWorker(ctx context.Context, sc domain.Scope, workerID string) (domain.Worker, error) {
	var w domain.Worker
	var cfg string
	err := s.Pool.QueryRow(ctx,
		`SELECT tenant_id,worker_id,environment,region,allowlisted,approved_registry,current_image_digest,known_good_digest,config
		 FROM workers WHERE tenant_id=$1 AND worker_id=$2`, sc.TenantID, workerID).Scan(
		&w.Scope.TenantID, &w.WorkerID, &w.Scope.Environment, &w.Scope.Region, &w.Allowlisted, &w.ApprovedReg, &w.CurrentDigest, &w.KnownGoodDigest, &cfg)
	if err == pgx.ErrNoRows {
		return w, domain.Err(domain.CodeNotFound, "worker not found in tenant scope")
	}
	if err != nil {
		return w, err
	}
	_ = json.Unmarshal([]byte(cfg), &w.Config)
	rows, err := s.Pool.Query(ctx, `SELECT image_digest FROM approved_digests WHERE tenant_id=$1 AND worker_id=$2 ORDER BY image_digest`, sc.TenantID, workerID)
	if err != nil {
		return w, err
	}
	defer rows.Close()
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return w, err
		}
		w.ApprovedDigests = append(w.ApprovedDigests, d)
	}
	return w, rows.Err()
}

// SaveExecResult records a provider receipt / applied set (executor).
func (s *Store) SaveExecResult(ctx context.Context, q execer, sc domain.Scope, opID, phase, corr string, resp any, applied any, outcome string) error {
	_, err := q.Exec(ctx,
		`INSERT INTO execution_results(tenant_id,op_id,attempt,phase,provider_correlation_id,provider_response,applied_resources,outcome)
		 VALUES($1,$2,1,$3,$4,$5,$6,$7)
		 ON CONFLICT (op_id,attempt,phase) DO UPDATE SET provider_correlation_id=$4, provider_response=$5, applied_resources=$6, outcome=$7`,
		sc.TenantID, opID, phase, corr, jsonb(resp), jsonb(applied), outcome)
	return err
}

func (s *Store) SetValidation(ctx context.Context, sc domain.Scope, opID, phase string, vr any) error {
	_, err := s.Pool.Exec(ctx, `UPDATE execution_results SET validation_result=$3 WHERE tenant_id=$1 AND op_id=$2 AND phase=$4`,
		sc.TenantID, opID, jsonb(vr), phase)
	return err
}

func (s *Store) LatestOutcome(ctx context.Context, sc domain.Scope, opID string) (string, error) {
	var out *string
	err := s.Pool.QueryRow(ctx, `SELECT outcome FROM execution_results WHERE tenant_id=$1 AND op_id=$2 ORDER BY id DESC LIMIT 1`, sc.TenantID, opID).Scan(&out)
	if err == pgx.ErrNoRows || out == nil {
		return "", nil
	}
	return *out, err
}

// StuckOps returns ops in `state` whose lease is expired/absent — the reconciler's
// work list after an executor process death.
func (s *Store) StuckOps(ctx context.Context, state domain.State) ([]domain.Operation, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT o.id, o.tenant_id, o.environment, o.region FROM operations o
		 LEFT JOIN leases l ON l.resource_key = o.tenant_id||':'||o.environment||':'||o.region||':'||o.worker_id
		 WHERE o.state=$1 AND (l.resource_key IS NULL OR l.expires_at < now())`, string(state))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Operation
	for rows.Next() {
		var id, t, e, r string
		if err := rows.Scan(&id, &t, &e, &r); err != nil {
			return nil, err
		}
		op, err := s.GetOperation(ctx, domain.Scope{TenantID: t, Environment: e, Region: r}, id)
		if err != nil {
			return nil, err
		}
		out = append(out, op)
	}
	return out, rows.Err()
}

// ── audit reads / verification ────────────────────────────────────────────────
func (s *Store) ReadEvents(ctx context.Context, sc domain.Scope, opID string) ([]domain.Event, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT seq,tenant_id,op_id,ts,actor,actor_kind,event_type,from_state,to_state,detail,prev_hash,hash,sig_domain,signature
		 FROM operation_events WHERE tenant_id=$1 AND op_id=$2 ORDER BY seq`, sc.TenantID, opID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Event
	for rows.Next() {
		var e domain.Event
		var from, to *string
		var detail string
		if err := rows.Scan(&e.Seq, &e.TenantID, &e.OpID, &e.TS, &e.Actor, &e.ActorKind, &e.EventType, &from, &to, &detail, &e.PrevHash, &e.Hash, &e.SigDomain, &e.Signature); err != nil {
			return nil, err
		}
		if from != nil {
			e.FromState = domain.State(*from)
		}
		if to != nil {
			e.ToState = domain.State(*to)
		}
		_ = json.Unmarshal([]byte(detail), &e.Detail)
		out = append(out, e)
	}
	return out, rows.Err()
}

// VerifyAuditChain recomputes the hash chain + audit signatures for an op.
func (s *Store) VerifyAuditChain(ctx context.Context, sc domain.Scope, opID string) (bool, error) {
	evs, err := s.ReadEvents(ctx, sc, opID)
	if err != nil {
		return false, err
	}
	prev := ""
	for _, e := range evs {
		ev := map[string]any{
			"op_id": e.OpID, "seq": e.Seq, "ts": e.TS.UTC().Format(time.RFC3339Nano),
			"actor": e.Actor, "actor_kind": string(e.ActorKind), "event_type": e.EventType,
			"from_state": string(e.FromState), "to_state": string(e.ToState), "detail": e.Detail,
		}
		h := audit.Sha256Hex(audit.Canon(ev), []byte(prev))
		if h != e.Hash || !s.Signer.Verify(domain.SigAudit, []byte(h), e.Signature) {
			return false, nil
		}
		prev = e.Hash
	}
	return len(evs) > 0, nil
}

// ReadOutbox returns unpublished outbox rows in publish order (for ordering tests).
func (s *Store) ReadOutbox(ctx context.Context, tenant string) ([]string, error) {
	rows, err := s.Pool.Query(ctx, `SELECT topic FROM outbox WHERE tenant_id=$1 ORDER BY id`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
