//go:build benchgate

package main

// Scaling-regression gate for destination-category resolution on the policy hot
// path.
//
//	go test -tags benchgate -run 'TestBenchGate_PolicyCategory' -v .

import "testing"

// TestBenchGate_PolicyCategoryGroupScanFlatInRuleCount locks in the CONSTANT-cost
// contract for the host→category fusion during a policy scan.
//
// policyStore.Evaluate runs on every proxied request. The fusion that resolves a
// destination to its URL category depends only on the HOST, but it used to run
// once per category-group rule: catStore.LookupHost walks every host pattern in
// the taxonomy on a miss (O(patterns), lowercasing and concatenating per pattern
// — 91% of the scan's profile), and on a feed-backed deployment communityDB.Lookup
// opens a BadgerDB read transaction per domain label. Multiplying that by the rule
// count made the scan grow steeply: measured 205 µs at 10 rules, 1.01 ms at 50,
// and 4.03 ms at 200 — per request, before any traffic was forwarded.
//
// The fusion is now resolved once per scan (hostCatScratch, policy_hostcat.go), so
// the cost is a small constant plus the ordinary per-rule scan: measured 21.1 µs at
// 10 rules and 26.6 µs at 200, a 1.26x spread over a 20x rule increase.
//
// The gate is therefore a RATIO, not an absolute time — it is machine-independent
// and it targets the exact failure mode. Reverting to a per-rule fusion lands the
// ratio near 20x; the bound is 4x.
func TestBenchGate_PolicyCategoryGroupScanFlatInRuleCount(t *testing.T) {
	const (
		smallRules  = 10
		largeRules  = 200
		maxRatio    = 4.0
		measureHost = "uncategorized.example.net"
	)

	// A taxonomy with enough host patterns that a per-rule LookupHost is
	// unmistakably expensive, and a destination in none of them — the case that
	// forces every tier of the fusion to run to completion.
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
	if small <= 0 {
		t.Fatalf("degenerate measurement at %d rules: %v ns/op", smallRules, small)
	}
	ratio := large / small

	t.Logf("Evaluate over category-group rules: %d rules = %.0f ns/op, %d rules = %.0f ns/op, ratio %.2fx (bound %.1fx)",
		smallRules, small, largeRules, large, ratio, maxRatio)

	if ratio > maxRatio {
		t.Errorf("REGRESSION: policy scan cost grew %.2fx when the category-group rule count grew %dx "+
			"(%.0f ns/op → %.0f ns/op), exceeding the %.1fx bound. The host→category fusion is being "+
			"resolved PER RULE again instead of once per scan, so every request pays an O(taxonomy) "+
			"pattern walk — and a BadgerDB read transaction per domain label on a feed-backed "+
			"deployment — multiplied by the rule count. See hostCatScratch in policy_hostcat.go.",
			ratio, largeRules/smallRules, small, large, maxRatio)
	}
}
