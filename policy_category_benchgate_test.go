//go:build benchgate

package main

// Scaling-regression gate for destination-category resolution on the policy hot
// path.
//
//	go test -tags benchgate -run 'TestBenchGate_PolicyCategory' -v .

import "testing"

// TestBenchGate_PolicyCategoryGroupScanFlatInRuleCount locks in the ONCE-PER-SCAN
// contract for the host→category fusion during a policy scan.
//
// policyStore.Evaluate runs on every proxied request. The fusion that resolves a
// destination to its URL category depends only on the HOST, but it used to run
// once per category-group rule — and on a feed-backed deployment
// communityDB.Lookup opens a BadgerDB read transaction per domain label, so the
// per-rule multiplication was measured at 205 µs / 1.01 ms / 4.03 ms for
// 10/50/200 rules per request. hostCatScratch (policy_hostcat.go) resolves the
// fusion once per scan.
//
// GATE DESIGN. The original gate bounded the RATIO of total scan cost at 200 vs
// 10 rules. That held while one fusion cost tens of microseconds and dwarfed the
// per-rule floor — but once urlcat gained its reverse index the single fusion
// dropped to a few hundred ns, so the healthy per-rule floor (a category-group
// set probe, ~tens of ns) legitimately dominates the total and the ratio no
// longer separates healthy from regressed. The gate now measures the exact
// quantity a regression changes: the MARGINAL cost of one additional
// category-group rule, compared against the measured cost of ONE full
// single-shot fusion (lookupHostCategory) in the same run. Healthy, the
// marginal rule pays only the group probe — a small fraction of a fusion.
// Regressed (fusion back inside the rule loop), every marginal rule re-pays at
// least a whole fusion. The bound is marginal < 75% of a fusion:
// machine-independent (both sides scale together) and self-calibrating against
// future changes to the fusion's own cost.
func TestBenchGate_PolicyCategoryGroupScanFlatInRuleCount(t *testing.T) {
	const (
		smallRules  = 10
		largeRules  = 200
		maxFraction = 0.75
		measureHost = "uncategorized.example.net"
	)

	// A taxonomy with enough host patterns to make the fusion measurable, and a
	// destination in none of them — the miss case forces every tier of the
	// fusion to run to completion.
	seedCategoryTaxonomy(t, 12, 40)

	measure := func(n int) float64 {
		ps := buildCategoryGroupPolicyStore(n)
		if m := ps.Evaluate("203.0.113.7", "", "unauth", measureHost, nil); m != nil {
			t.Fatalf("rules=%d: expected no match, got %q — the gate is not measuring the full scan", n, m.Rule.Name)
		}
		res := testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = ps.Evaluate("203.0.113.7", "", "unauth", measureHost, nil)
			}
		})
		return float64(res.NsPerOp())
	}

	small := measure(smallRules)
	large := measure(largeRules)
	marginal := (large - small) / float64(largeRules-smallRules)

	fusionRes := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, _ = lookupHostCategory(measureHost)
		}
	})
	fusion := float64(fusionRes.NsPerOp())
	if fusion <= 0 {
		t.Fatalf("degenerate fusion measurement: %v ns/op", fusion)
	}

	t.Logf("Evaluate over category-group rules: %d rules = %.0f ns/op, %d rules = %.0f ns/op, "+
		"marginal %.1f ns/rule vs one fusion %.0f ns (bound %.0f%% of a fusion)",
		smallRules, small, largeRules, large, marginal, fusion, maxFraction*100)

	if marginal > maxFraction*fusion {
		t.Errorf("REGRESSION: each additional category-group rule costs %.1f ns — at least a whole "+
			"host→category fusion (%.0f ns) — so the fusion is being resolved PER RULE again instead "+
			"of once per scan. Every request would pay the taxonomy lookup — and a BadgerDB read "+
			"transaction per domain label on a feed-backed deployment — multiplied by the rule count. "+
			"See hostCatScratch in policy_hostcat.go.", marginal, fusion)
	}
}
