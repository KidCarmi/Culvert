// crash-executor drives a single Execute() and terminates the PROCESS (os.Exit,
// no deferred cleanup) at a named crash point. This produces REAL crash semantics
// for the failure suite — the operation is left EXECUTING/VALIDATING with the lease
// still held, exactly as a killed executor would; the reconciler must resolve it.
//
// Env: TAC_DSN, TAC_TENANT, TAC_ENV, TAC_REGION, TAC_OP, TAC_APPROVAL, TAC_CRASH_AT,
//      TAC_FAULT (optional provider fault, e.g. validation_fail).
package main

import (
	"context"
	"os"
	"strings"

	"github.com/kidcarmi/tac-platform/internal/audit"
	"github.com/kidcarmi/tac-platform/internal/domain"
	"github.com/kidcarmi/tac-platform/internal/executor"
	"github.com/kidcarmi/tac-platform/internal/opsvc"
	"github.com/kidcarmi/tac-platform/internal/provider"
	"github.com/kidcarmi/tac-platform/internal/store"
)

func main() {
	ctx := context.Background()
	sg := audit.DefaultTestSigner()
	st, err := store.Connect(ctx, os.Getenv("TAC_DSN"), sg)
	if err != nil {
		os.Exit(2)
	}
	var faults []string
	if f := os.Getenv("TAC_FAULT"); f != "" {
		faults = strings.Split(f, ",")
	}
	ex := executor.New(provider.NewMock(st.Pool, faults...), "exec-crash")
	s := opsvc.New(st, ex, sg, "exec-crash")
	sc := domain.Scope{TenantID: os.Getenv("TAC_TENANT"), Environment: os.Getenv("TAC_ENV"), Region: os.Getenv("TAC_REGION")}
	crashAt := os.Getenv("TAC_CRASH_AT")
	hook := func(point string) {
		if point == crashAt {
			os.Exit(137) // uncatchable-style termination: no defers, no lease release
		}
	}
	_, _ = s.Execute(ctx, sc, os.Getenv("TAC_OP"), os.Getenv("TAC_APPROVAL"), hook)
	os.Exit(0)
}
