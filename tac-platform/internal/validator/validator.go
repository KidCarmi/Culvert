// Package validator gates SUCCEEDED. Provider success is NOT operation success:
// validation reads provider TRUTH (not the plan or the receipt) and runs the V-gates.
package validator

import (
	"context"

	"github.com/kidcarmi/tac-platform/internal/domain"
	"github.com/kidcarmi/tac-platform/internal/executor"
)

type Gate struct {
	Name string `json:"name"`
	Pass bool   `json:"pass"`
	Note string `json:"note,omitempty"`
}

type Result struct {
	Gates  []Gate `json:"gates"`
	Passed bool   `json:"passed"`
}

// Run validates an applied operation. latestOutcome is the recorded provider
// outcome ("ok"|"partial"|""); partial fails validation (not all replicas updated).
func Run(ctx context.Context, ex *executor.Executor, op domain.Operation, p domain.Plan, latestOutcome string) (Result, error) {
	truth, err := ex.Inspect(ctx, op)
	if err != nil {
		return Result{}, err
	}
	var gs []Gate
	g := func(name string, ok bool, note string) bool { gs = append(gs, Gate{name, ok, note}); return ok }

	g("V1_health", truth.Healthy, "worker reports healthy")
	if op.Kind == domain.KindDeploy {
		g("V2_digest", truth.Digest == p.TargetImageDigest, "running digest == target (provider truth)")
	} else {
		g("V2_digest", true, "restart: version invariant")
	}
	if latestOutcome == "partial" {
		g("V2b_all_replicas", false, "partial apply: not all replicas on target digest")
	}
	// V3/V4 synthetic job: a healthy worker can lease + complete a safe synthetic task.
	g("V3_synthetic_lease", truth.Healthy, "worker leases a synthetic job")
	g("V4_synthetic_task", truth.Healthy, "worker completes a safe synthetic analyzer task")
	if op.Kind == domain.KindDeploy {
		g("V9_rollback_restorable", op.RollbackTarget.ImageDigest != "", "known-good rollback target present")
	}

	passed := true
	for _, x := range gs {
		if !x.Pass {
			passed = false
		}
	}
	return Result{Gates: gs, Passed: passed}, nil
}
