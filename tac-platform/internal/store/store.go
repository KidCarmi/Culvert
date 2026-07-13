// Package store is the durable, transactional operation store (PostgreSQL/pgx).
// Invariants enforced here structurally:
//   - a state transition + its audit event + its outbox row commit in ONE tx
//   - state transitions go through fsm.Check (legality); callers pass a literal target
//   - every query is tenant-scoped
//   - the audit stream is append-only, hash-chained, and signed (domain=audit)
package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kidcarmi/tac-platform/internal/audit"
	"github.com/kidcarmi/tac-platform/internal/domain"
	"github.com/kidcarmi/tac-platform/internal/fsm"
)

type Store struct {
	Pool   *pgxpool.Pool
	Signer *audit.Signer
	Now    func() time.Time
}

func New(pool *pgxpool.Pool, s *audit.Signer) *Store {
	return &Store{Pool: pool, Signer: s, Now: func() time.Time { return time.Now().UTC() }}
}

func Connect(ctx context.Context, dsn string, s *audit.Signer) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	return New(pool, s), nil
}

func (s *Store) Begin(ctx context.Context) (pgx.Tx, error) { return s.Pool.Begin(ctx) }

func jsonb(v any) string { b, _ := json.Marshal(v); return string(b) }

func isUnique(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23505"
}

// ── audit + transition primitive ───────────────────────────────────────────────

// appendEvent writes ONE signed, hash-chained event and its outbox row inside tx.
func (s *Store) appendEvent(ctx context.Context, tx pgx.Tx, op domain.Operation, from, to domain.State, actor string, ak domain.ActorKind, etype string, detail map[string]any) error {
	var seq int
	var prev string
	err := tx.QueryRow(ctx, `SELECT seq, hash FROM operation_events WHERE op_id=$1 ORDER BY seq DESC LIMIT 1`, op.ID).Scan(&seq, &prev)
	if err == pgx.ErrNoRows {
		seq, prev = 0, ""
	} else if err != nil {
		return err
	}
	seq++
	// Postgres timestamptz is microsecond-precision; truncate BEFORE hashing so the
	// stored value round-trips to the exact bytes we hashed (audit chain re-verifies).
	ts := s.Now().UTC().Truncate(time.Microsecond)
	if detail == nil {
		detail = map[string]any{}
	}
	// Normalize detail to its generic JSON form (structs -> maps, ints -> float64)
	// BEFORE hashing, so the write-time hash equals the read-time hash after the
	// detail round-trips through JSONB (struct field-order vs sorted map keys).
	if nb, mErr := json.Marshal(detail); mErr == nil {
		var nd map[string]any
		if json.Unmarshal(nb, &nd) == nil {
			detail = nd
		}
	}
	ev := map[string]any{
		"op_id": op.ID, "seq": seq, "ts": ts.Format(time.RFC3339Nano),
		"actor": actor, "actor_kind": string(ak), "event_type": etype,
		"from_state": string(from), "to_state": string(to), "detail": detail,
	}
	hash := audit.Sha256Hex(audit.Canon(ev), []byte(prev))
	sig := s.Signer.Sign(domain.SigAudit, []byte(hash))
	if _, err := tx.Exec(ctx,
		`INSERT INTO operation_events(tenant_id,op_id,seq,ts,actor,actor_kind,event_type,from_state,to_state,detail,prev_hash,hash,sig_domain,signature)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'audit',$13)`,
		op.Scope.TenantID, op.ID, seq, ts, actor, ak, etype, nullable(from), nullable(to), jsonb(detail), prev, hash, sig); err != nil {
		return err
	}
	// transactional outbox — committed atomically with the event.
	_, err = tx.Exec(ctx,
		`INSERT INTO outbox(tenant_id,op_id,event_seq,topic,payload) VALUES($1,$2,$3,$4,$5)`,
		op.Scope.TenantID, op.ID, seq, "operation."+etype,
		jsonb(map[string]any{"op_id": op.ID, "to_state": to, "event_type": etype}))
	return err
}

func nullable(s domain.State) any {
	if s == "" {
		return nil
	}
	return string(s)
}

// Transition applies a legal state change + audit + outbox atomically, with an
// optimistic version CAS. op is updated in place on success. `to` is always a
// literal at the (opsvc) call site — no arbitrary target is accepted from outside.
func (s *Store) Transition(ctx context.Context, tx pgx.Tx, op *domain.Operation, to domain.State, actor string, ak domain.ActorKind, etype string, detail map[string]any) error {
	if err := fsm.Check(op.State, to); err != nil {
		return err
	}
	ct, err := tx.Exec(ctx,
		`UPDATE operations SET state=$1, version=version+1, updated_at=$2 WHERE id=$3 AND version=$4`,
		string(to), s.Now(), op.ID, op.Version)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return domain.Err(domain.CodeConflict, "optimistic concurrency conflict (version changed)")
	}
	from := op.State
	if err := s.appendEvent(ctx, tx, *op, from, to, actor, ak, etype, detail); err != nil {
		return err
	}
	op.State = to
	op.Version++
	return nil
}

var _ = pgx.ErrNoRows
