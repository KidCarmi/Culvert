// tacctl is the human CLI fallback. The ENTIRE workflow (inspect/plan/approve/
// execute/validate/rollback/reconcile) runs through it with no AI in the loop —
// proving Claude is replaceable. DSN from $TAC_DSN. Dev signer (distinct keys).
package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/kidcarmi/tac-platform/internal/audit"
	"github.com/kidcarmi/tac-platform/internal/domain"
	"github.com/kidcarmi/tac-platform/internal/executor"
	"github.com/kidcarmi/tac-platform/internal/opsvc"
	"github.com/kidcarmi/tac-platform/internal/provider"
	"github.com/kidcarmi/tac-platform/internal/store"
	"github.com/kidcarmi/tac-platform/migrations"
)

const (
	Tenant  = "tenant-synthetic-1"
	Env     = "staging"
	Region  = "us-local"
	Worker  = "tac-analysis-worker-1"
	digGood = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digNew  = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func scope() domain.Scope { return domain.Scope{TenantID: Tenant, Environment: Env, Region: Region} }

func dsn() string {
	if v := os.Getenv("TAC_DSN"); v != "" {
		return v
	}
	return "postgres://postgres@127.0.0.1:5433/tac?sslmode=disable"
}

func svc(ctx context.Context) (*opsvc.Service, *store.Store) {
	sg := audit.DefaultTestSigner()
	st, err := store.Connect(ctx, dsn(), sg)
	must(err)
	ex := executor.New(provider.NewMock(st.Pool), "exec-cli")
	return opsvc.New(st, ex, sg, "exec-cli"), st
}

func main() {
	ctx := context.Background()
	args := os.Args[1:]
	if len(args) == 0 {
		usage()
		return
	}
	switch args[0] {
	case "init":
		s, st := svc(ctx)
		_ = st.Reset(ctx)
		must(st.Migrate(ctx, migrations.Schema))
		must(st.SeedWorker(ctx, domain.Worker{Scope: scope(), WorkerID: Worker, Allowlisted: true,
			ApprovedReg: "registry.tac.example/analysis-worker", CurrentDigest: digGood, KnownGoodDigest: digGood,
			Config: map[string]string{"QUEUE": "staging-analysis"}, ApprovedDigests: []string{digGood, digNew}}))
		_ = s
		fmt.Println("initialized: schema applied, worker", Worker, "seeded (allowlisted)")
	case "worker":
		_, st := svc(ctx)
		w, err := st.GetWorker(ctx, scope(), arg(args, 2, Worker))
		must(err)
		tr, _ := provider.NewMock(st.Pool).Inspect(ctx, scope(), w.WorkerID)
		fmt.Printf("worker=%s env=%s allowlisted=%v running=%s healthy=%v\n", w.WorkerID, Env, w.Allowlisted, short(tr.Digest), tr.Healthy)
	case "restart":
		s, _ := svc(ctx)
		op, err := s.RestartWorker(ctx, scope(), Worker, flag(args, "--reason", "cli restart"), flag(args, "--idem", "idem-"+randish()), flag(args, "--actor", "human:cli"), nil)
		must(err)
		fmt.Printf("restart op=%s state=%s\n", op.ID, op.State)
	case "plan":
		s, _ := svc(ctx)
		op, p, err := s.CreateDeployPlan(ctx, scope(), Worker, resolveImage(flag(args, "--image", "new")), flag(args, "--reason", "deploy"), flag(args, "--idem", "idem-"+randish()), flag(args, "--actor", "human:alice"), map[string]any{"via": "cli"})
		if err != nil && domain.CodeOf(err) != domain.CodePolicyRejected {
			must(err)
		}
		fmt.Printf("op=%s plan=%s policy_passed=%v state=%s target=%s\n", op.ID, p.PlanID, p.PolicyResult.Passed, op.State, short(p.TargetImageDigest))
	case "approve":
		s, _ := svc(ctx)
		a, err := s.Approve(ctx, scope(), args[1], args[2], flag(args, "--as-human", "bob"))
		must(err)
		fmt.Printf("approved op=%s plan=%s approval=%s\n", args[1], args[2], a.ApprovalID)
	case "execute":
		s, _ := svc(ctx)
		st, err := s.Execute(ctx, scope(), args[1], flag(args, "--approval", ""), nil)
		if err != nil {
			fmt.Printf("execute op=%s state=%s err=%s\n", args[1], st, err)
			return
		}
		fmt.Printf("execute op=%s state=%s\n", args[1], st)
	case "validate":
		s, _ := svc(ctx)
		ok, res, err := s.Validate(ctx, scope(), args[1])
		must(err)
		fmt.Printf("validate op=%s passed=%v gates=%d\n", args[1], ok, len(res.Gates))
	case "rollback":
		s, _ := svc(ctx)
		st, err := s.Rollback(ctx, scope(), args[1])
		must(err)
		fmt.Printf("rollback op=%s state=%s\n", args[1], st)
	case "reconcile":
		s, _ := svc(ctx)
		log, err := s.Reconcile(ctx)
		must(err)
		fmt.Printf("reconciled %d op(s)\n", len(log))
		for _, l := range log {
			fmt.Println("  " + l)
		}
	case "show":
		s, _ := svc(ctx)
		v, err := s.Get(ctx, scope(), args[1])
		must(err)
		fmt.Printf("OP %s kind=%s level=%s state=%s worker=%s audit_ok=%v\n", v.Operation.ID, v.Operation.Kind, v.Operation.Level, v.Operation.State, v.Operation.WorkerID, v.AuditOK)
		for _, e := range v.Events {
			fmt.Printf("  #%d %s %-16s %-22s %s->%s\n", e.Seq, e.TS.Format("15:04:05"), e.Actor, e.EventType, e.FromState, e.ToState)
		}
	default:
		usage()
	}
}

func resolveImage(alias string) string {
	if alias == "good" {
		return digGood
	}
	return digNew
}
func short(s string) string {
	if len(s) > 18 {
		return s[:18] + "…"
	}
	return s
}
func arg(a []string, i int, def string) string {
	if len(a) > i && !strings.HasPrefix(a[i], "--") {
		return a[i]
	}
	return def
}
func flag(a []string, name, def string) string {
	for i, x := range a {
		if x == name && i+1 < len(a) {
			return a[i+1]
		}
	}
	return def
}
func randish() string { b := make([]byte, 4); _, _ = os.Stdin.Read(b); return fmt.Sprintf("%d", os.Getpid()) }
func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
func usage() {
	fmt.Println(`tacctl (no-AI CLI): init | worker [id] | restart | plan [--image good|new] | approve <op> <plan> | execute <op> [--approval id] | validate <op> | rollback <op> | reconcile | show <op>`)
}
