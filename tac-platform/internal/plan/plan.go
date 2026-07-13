// Package plan builds content-addressed, signed plan artifacts. The executor may
// apply ONLY the exact approved plan; any field change yields a new plan_id and
// invalidates prior approval.
package plan

import (
	"time"

	"github.com/kidcarmi/tac-platform/internal/audit"
	"github.com/kidcarmi/tac-platform/internal/domain"
	"github.com/kidcarmi/tac-platform/internal/policy"
)

const planTTL = 15 * time.Minute

// Build assembles the plan body, runs policy, content-addresses the id, and signs
// (domain=plan). It does NOT persist. now is injected for determinism.
func Build(op domain.Operation, w domain.Worker, kind domain.Kind, targetDigest string, s *audit.Signer, now time.Time) domain.Plan {
	rt := domain.RollbackTarget{ImageDigest: w.KnownGoodDigest, CommitSHA: "prev-commit", ConfigDigest: configDigest(w)}
	var ec domain.ExpectedChanges
	commit := ""
	if kind == domain.KindDeploy {
		ec = domain.ExpectedChanges{Create: 0, Delete: 0, Update: 1, Resources: []map[string]any{{
			"address": "module.workers.tac_analysis_worker.machine", "action": "update",
			"field": "image", "from": w.CurrentDigest, "to": targetDigest}}}
		if len(targetDigest) > 15 {
			commit = "commit-" + targetDigest[7:15]
		}
	} else {
		ec = domain.ExpectedChanges{Action: "restart"}
	}
	body := domain.PlanBody{
		OpID: op.ID, TenantID: op.Scope.TenantID, Environment: op.Scope.Environment, Region: op.Scope.Region,
		WorkerID: op.WorkerID, Kind: kind, CommitSHA: commit,
		ConfigDigest: configDigest(w), ProviderLockDigest: "sha256:lock-v1",
		TargetImageDigest: targetDigest, ExpectedChanges: ec, RollbackTarget: rt,
		CostDeltaUSD: 0, HealthValidation: true,
		CreatedAt: now.UTC(), ExpiresAt: now.Add(planTTL).UTC(),
	}
	pol := policy.Evaluate(w, body)
	raw := audit.Canon(body)
	planID := "PLAN-" + audit.Sha256Hex(raw)[:12]
	sig := s.Sign(domain.SigPlan, raw)
	return domain.Plan{
		PlanID: planID, Scope: op.Scope, OpID: op.ID, Kind: kind, CommitSHA: commit,
		ConfigDigest: body.ConfigDigest, ProviderLockDigest: body.ProviderLockDigest,
		TargetImageDigest: targetDigest, ExpectedChanges: ec, PolicyResult: pol,
		RollbackTarget: rt, CostDeltaUSD: 0, HealthValidation: true,
		Signature: sig, SignerKeyID: s.KeyID(domain.SigPlan),
		CreatedAt: body.CreatedAt, ExpiresAt: body.ExpiresAt,
	}
}

func configDigest(w domain.Worker) string {
	return "sha256:cfg-" + audit.Sha256Hex(audit.Canon(w.Config))[:24]
}
