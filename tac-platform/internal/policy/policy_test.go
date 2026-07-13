package policy

import (
	"testing"
	"time"

	"github.com/kidcarmi/tac-platform/internal/domain"
)

func worker(tenant string) domain.Worker {
	return domain.Worker{Scope: domain.Scope{TenantID: tenant, Environment: "staging", Region: "us-local"},
		WorkerID: "w1", Allowlisted: true, KnownGoodDigest: "sha256:good",
		ApprovedDigests: []string{"sha256:good", "sha256:new"}}
}

func goodDeployBody(tenant string) domain.PlanBody {
	return domain.PlanBody{TenantID: tenant, Environment: "staging", Region: "us-local", WorkerID: "w1",
		Kind: domain.KindDeploy, TargetImageDigest: "sha256:new",
		ExpectedChanges: domain.ExpectedChanges{Update: 1}, RollbackTarget: domain.RollbackTarget{ImageDigest: "sha256:good"},
		CostDeltaUSD: 0, HealthValidation: true, ExpiresAt: time.Now().Add(time.Minute)}
}

func TestPolicy_HappyDeployPasses(t *testing.T) {
	if r := Evaluate(worker("t1"), goodDeployBody("t1")); !r.Passed {
		t.Fatalf("expected pass, failed: %v", r.FailedIDs())
	}
}

// Each rule has a fail case (branch coverage).
func TestPolicy_EachRuleCanFail(t *testing.T) {
	cases := map[string]func(*domain.PlanBody, *domain.Worker){
		"P0_tenant":         func(b *domain.PlanBody, w *domain.Worker) { b.TenantID = "other" },
		"P1_staging":        func(b *domain.PlanBody, w *domain.Worker) { b.Environment = "prod" },
		"P2_allowlisted":    func(b *domain.PlanBody, w *domain.Worker) { w.Allowlisted = false },
		"P4_digest":         func(b *domain.PlanBody, w *domain.Worker) { b.TargetImageDigest = "sha256:evil" },
		"P5_8_no_forbidden": func(b *domain.PlanBody, w *domain.Worker) { b.ExpectedChanges.TouchesForbidden = true },
		"P9_no_paid":        func(b *domain.PlanBody, w *domain.Worker) { b.ExpectedChanges.NewPaid = true },
		"P10_provider":      func(b *domain.PlanBody, w *domain.Worker) { b.ExpectedChanges.ProviderChanged = true },
		"P11_no_destroy":    func(b *domain.PlanBody, w *domain.Worker) { b.ExpectedChanges.Delete = 1 },
		"P12_delta":         func(b *domain.PlanBody, w *domain.Worker) { b.ExpectedChanges.Update = 2 },
		"P13_cost":          func(b *domain.PlanBody, w *domain.Worker) { b.CostDeltaUSD = 5 },
		"P14_health":        func(b *domain.PlanBody, w *domain.Worker) { b.HealthValidation = false },
		"P15_rollback":      func(b *domain.PlanBody, w *domain.Worker) { b.RollbackTarget.ImageDigest = "" },
		"P16_expiry":        func(b *domain.PlanBody, w *domain.Worker) { b.ExpiresAt = time.Time{} },
	}
	for ruleID, mutate := range cases {
		b := goodDeployBody("t1")
		w := worker("t1")
		mutate(&b, &w)
		r := Evaluate(w, b)
		if r.Passed {
			t.Fatalf("%s: mutation should have failed policy", ruleID)
		}
		found := false
		for _, id := range r.FailedIDs() {
			if id == ruleID {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s: expected that rule to fail, got %v", ruleID, r.FailedIDs())
		}
	}
}
