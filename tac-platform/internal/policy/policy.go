// Package policy is the deterministic safety boundary. It decides GO/NO-GO over a
// plan body using only structural facts; multi-agent review (elsewhere) is advisory
// and can never substitute for a policy PASS. Pure functions; no I/O.
package policy

import "github.com/kidcarmi/tac-platform/internal/domain"

func rule(rs *[]domain.PolicyRuleResult, id string, pass bool, detail string) {
	*rs = append(*rs, domain.PolicyRuleResult{ID: id, Pass: pass, Detail: detail})
}

// Evaluate runs the fixed rule set over a plan body + the target worker.
func Evaluate(w domain.Worker, b domain.PlanBody) domain.PolicyResult {
	var rs []domain.PolicyRuleResult
	approved := map[string]bool{}
	for _, d := range w.ApprovedDigests {
		approved[d] = true
	}
	ec := b.ExpectedChanges

	// P0 tenant scope: the plan's tenant must match the worker's tenant (R7-F2).
	rule(&rs, "P0_tenant", w.Scope.TenantID != "" && b.TenantID == w.Scope.TenantID, "tenant scope match")
	rule(&rs, "P1_staging", b.Environment == "staging", "staging only")
	rule(&rs, "P2_allowlisted", w.Allowlisted, "single allowlisted worker")
	if b.Kind == domain.KindDeploy {
		rule(&rs, "P4_digest", approved[b.TargetImageDigest], "image digest approved")
	} else {
		rule(&rs, "P4_digest", true, "restart: n/a")
	}
	rule(&rs, "P5_8_no_forbidden", !ec.TouchesForbidden, "no db/storage/dns/iam change")
	rule(&rs, "P9_no_paid", !ec.NewPaid, "no new paid resource")
	rule(&rs, "P10_provider", !ec.ProviderChanged, "provider lock unchanged")
	rule(&rs, "P11_no_destroy", ec.Delete == 0, "no destroy action")
	rule(&rs, "P12_delta", ec.Create == 0 && ec.Delete == 0 && ec.Update <= 1, "resource-count delta")
	rule(&rs, "P13_cost", b.CostDeltaUSD == 0, "$0 cost delta")
	rule(&rs, "P14_health", b.HealthValidation, "mandatory health validation")
	if b.Kind == domain.KindDeploy {
		rule(&rs, "P15_rollback", b.RollbackTarget.ImageDigest != "", "rollback target present")
	} else {
		rule(&rs, "P15_rollback", true, "restart: n/a")
	}
	rule(&rs, "P16_expiry", !b.ExpiresAt.IsZero(), "operation expiry set")

	passed := true
	for _, r := range rs {
		if !r.Pass {
			passed = false
		}
	}
	return domain.PolicyResult{Passed: passed, Rules: rs}
}
