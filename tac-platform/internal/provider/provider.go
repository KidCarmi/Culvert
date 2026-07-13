// Package provider defines the infrastructure-mutation boundary and a deterministic
// mock. The mock's "provider truth" lives in the provider_worker_state table so it
// is durable and cross-process: after an executor process is killed mid-operation,
// the reconciler (a different process) can still read what actually happened.
package provider

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kidcarmi/tac-platform/internal/domain"
)

// Fault injection points (used by tests and the crash-executor helper).
const (
	FaultUnavailable    = "unavailable"
	FaultTimeout        = "timeout"
	FaultPartial        = "partial_success"
	FaultDelayed        = "delayed_success"
	FaultUnknown        = "unknown_response"    // mutation MAY have applied; result in-doubt
	FaultValidationFail = "validation_fail"     // applies but comes up unhealthy
	FaultRestartUnhealthy = "restart_unhealthy"
	FaultRollbackFail   = "rollback_fail"       // reverse-deploy comes up unhealthy
)

type Receipt struct {
	CorrelationID string           `json:"correlation_id"`
	Applied       []map[string]any `json:"applied"`
	Outcome       string           `json:"outcome"` // ok | partial
}

type Truth struct {
	Generation int
	Digest     string
	Healthy    bool
}

// Adapter is the only interface through which infrastructure is mutated.
type Adapter interface {
	Inspect(ctx context.Context, sc domain.Scope, worker string) (Truth, error)
	Restart(ctx context.Context, sc domain.Scope, worker string) (Receipt, error)
	Deploy(ctx context.Context, sc domain.Scope, worker, targetDigest string) (Receipt, error)
}

type Mock struct {
	pool   *pgxpool.Pool
	faults map[string]bool
	seq    int
}

func NewMock(pool *pgxpool.Pool, faults ...string) *Mock {
	m := &Mock{pool: pool, faults: map[string]bool{}}
	for _, f := range faults {
		m.faults[f] = true
	}
	return m
}

func (m *Mock) has(f string) bool { return m.faults[f] }

// SetFaults replaces the active fault set (tests use this to inject a fault at a
// specific stage, e.g. make the reverse-deploy fail during a rollback test).
func (m *Mock) SetFaults(faults ...string) {
	m.faults = map[string]bool{}
	for _, f := range faults {
		m.faults[f] = true
	}
}

func (m *Mock) corr() string {
	m.seq++
	return "corr-" + time.Now().UTC().Format("150405.000000") + "-" + itoa(m.seq)
}

func (m *Mock) Inspect(ctx context.Context, sc domain.Scope, worker string) (Truth, error) {
	var t Truth
	err := m.pool.QueryRow(ctx,
		`SELECT generation, current_digest, healthy FROM provider_worker_state WHERE tenant_id=$1 AND worker_id=$2`,
		sc.TenantID, worker).Scan(&t.Generation, &t.Digest, &t.Healthy)
	if err == pgx.ErrNoRows {
		return Truth{}, domain.Err(domain.CodeNotFound, "provider has no such worker")
	}
	return t, err
}

func (m *Mock) Restart(ctx context.Context, sc domain.Scope, worker string) (Receipt, error) {
	if m.has(FaultUnavailable) {
		return Receipt{}, domain.Err(domain.CodeProviderError, "provider unavailable")
	}
	if m.has(FaultTimeout) {
		return Receipt{}, domain.Err(domain.CodeUnknownOutcome, "provider timeout (result in-doubt)")
	}
	healthy := !m.has(FaultRestartUnhealthy)
	c := m.corr()
	if err := m.bump(ctx, sc, worker, "", healthy, c); err != nil {
		return Receipt{}, err
	}
	return Receipt{CorrelationID: c, Outcome: "ok",
		Applied: []map[string]any{{"address": "...machine", "action": "restart", "outcome": "restarted"}}}, nil
}

func (m *Mock) Deploy(ctx context.Context, sc domain.Scope, worker, target string) (Receipt, error) {
	if m.has(FaultUnavailable) {
		return Receipt{}, domain.Err(domain.CodeProviderError, "provider unavailable")
	}
	if m.has(FaultDelayed) {
		time.Sleep(50 * time.Millisecond)
	}
	c := m.corr()
	if m.has(FaultPartial) {
		// one replica updated, one failed: digest advances but outcome is partial.
		if err := m.bump(ctx, sc, worker, target, true, c); err != nil {
			return Receipt{}, err
		}
		return Receipt{CorrelationID: c, Outcome: "partial",
			Applied: []map[string]any{{"address": "...machine[0]", "outcome": "updated"}, {"address": "...machine[1]", "outcome": "failed"}}}, nil
	}
	if m.has(FaultUnknown) {
		// The mutation IS applied in provider truth, but the call returns in-doubt:
		// the executor must NOT blindly retry; the reconciler resolves from truth.
		if err := m.bump(ctx, sc, worker, target, true, c); err != nil {
			return Receipt{}, err
		}
		return Receipt{CorrelationID: c}, domain.Err(domain.CodeUnknownOutcome, "provider returned an unknown/in-doubt response")
	}
	healthy := !m.has(FaultValidationFail) && !m.has(FaultRollbackFail)
	if err := m.bump(ctx, sc, worker, target, healthy, c); err != nil {
		return Receipt{}, err
	}
	return Receipt{CorrelationID: c, Outcome: "ok",
		Applied: []map[string]any{{"address": "...machine", "action": "update", "outcome": "updated"}}}, nil
}

// bump updates provider truth (generation++, digest if given, health).
func (m *Mock) bump(ctx context.Context, sc domain.Scope, worker, digest string, healthy bool, corr string) error {
	if digest == "" {
		_, err := m.pool.Exec(ctx,
			`UPDATE provider_worker_state SET generation=generation+1, healthy=$3, last_correlation_id=$4
			 WHERE tenant_id=$1 AND worker_id=$2`, sc.TenantID, worker, healthy, corr)
		return err
	}
	_, err := m.pool.Exec(ctx,
		`UPDATE provider_worker_state SET generation=generation+1, current_digest=$3, healthy=$4, last_correlation_id=$5
		 WHERE tenant_id=$1 AND worker_id=$2`, sc.TenantID, worker, digest, healthy, corr)
	return err
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
