// Package harness provides a real-PostgreSQL test environment. It connects to
// $TAC_DSN (default 127.0.0.1:5433/tac), resets + migrates the schema, and seeds a
// synthetic allowlisted worker. Tests that need PG call Env(t); if PG is
// unreachable the test is skipped (never a false failure).
package harness

import (
	"context"
	"os"
	"testing"

	"github.com/kidcarmi/tac-platform/internal/audit"
	"github.com/kidcarmi/tac-platform/internal/domain"
	"github.com/kidcarmi/tac-platform/internal/executor"
	"github.com/kidcarmi/tac-platform/internal/opsvc"
	"github.com/kidcarmi/tac-platform/internal/provider"
	"github.com/kidcarmi/tac-platform/internal/store"
	"github.com/kidcarmi/tac-platform/migrations"
)

const (
	TenantA = "tenant-A"
	TenantB = "tenant-B"
	Env0    = "staging"
	Region0 = "us-local"
	Worker0 = "tac-analysis-worker-1"

	DigGood       = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	DigNew        = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	DigUnapproved = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

func DSN() string {
	if v := os.Getenv("TAC_DSN"); v != "" {
		return v
	}
	return "postgres://postgres@127.0.0.1:5433/tac?sslmode=disable"
}

func Scope(tenant string) domain.Scope {
	return domain.Scope{TenantID: tenant, Environment: Env0, Region: Region0}
}

type Kit struct {
	Svc    *opsvc.Service
	Store  *store.Store
	Scope  domain.Scope
	Mock   *provider.Mock
	Signer *audit.Signer
}

// Env resets the DB, migrates, and seeds tenant A's worker. Provider faults (if any)
// are injected into the mock used by the service's executor.
func Env(t *testing.T, faults ...string) *Kit {
	t.Helper()
	ctx := context.Background()
	sg := audit.DefaultTestSigner()
	st, err := store.Connect(ctx, DSN(), sg)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — start it and set TAC_DSN", err)
	}
	if err := st.Pool.Ping(ctx); err != nil {
		t.Skipf("postgres ping failed (%v)", err)
	}
	if err := st.Reset(ctx); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if err := st.Migrate(ctx, migrations.Schema); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	SeedWorker(t, st, TenantA)
	mock := provider.NewMock(st.Pool, faults...)
	ex := executor.New(mock, "exec-test")
	return &Kit{Svc: opsvc.New(st, ex, sg, "exec-test"), Store: st, Scope: Scope(TenantA), Mock: mock, Signer: sg}
}

func SeedWorker(t *testing.T, st *store.Store, tenant string) {
	t.Helper()
	err := st.SeedWorker(context.Background(), domain.Worker{
		Scope: Scope(tenant), WorkerID: Worker0, Allowlisted: true,
		ApprovedReg: "registry.tac.example/analysis-worker", CurrentDigest: DigGood, KnownGoodDigest: DigGood,
		Config: map[string]string{"QUEUE": "staging-analysis"}, ApprovedDigests: []string{DigGood, DigNew},
	})
	if err != nil {
		t.Fatalf("seed worker (%s): %v", tenant, err)
	}
}

// DeployApproved runs create-plan + approve, returning op id + plan id + approval id.
func (k *Kit) DeployApproved(t *testing.T, target string) (string, string, string) {
	t.Helper()
	ctx := context.Background()
	op, p, err := k.Svc.CreateDeployPlan(ctx, k.Scope, Worker0, target, "deploy", "idem-"+randID(), "human:alice", map[string]any{"via": "ai"})
	if err != nil && domain.CodeOf(err) != domain.CodePolicyRejected {
		t.Fatalf("plan: %v", err)
	}
	a, err := k.Svc.Approve(ctx, k.Scope, op.ID, p.PlanID, "human:bob")
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	return op.ID, p.PlanID, a.ApprovalID
}

var seq int

func randID() string { seq++; return itoa(seq) + "-" + itoa(os.Getpid()) }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
