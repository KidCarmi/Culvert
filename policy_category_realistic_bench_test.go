package main

// Realistic-shape measurement for SINGLE-CATEGORY (destCategory) access rules.
//
// ── WHY THIS FILE EXISTS ────────────────────────────────────────────────────
//
// BenchmarkPolicyEvaluate_CategoryRules (policy_category_bench_test.go) is the
// existing instrument for this path, and it does not measure it. Its n rules
// name n DISTINCT categories — "Category 0" .. "Category 199" — against a
// taxonomy seeded with 12. So 188 of its 200 rules name a category that does
// not exist, miss on the category-key probe in matchesHostIn, and return
// WITHOUT ever walking the destination host against a category's host set.
// The per-rule cost it reports is therefore the cost of a lookup that fails
// immediately, not the cost of the membership probe a real rule pays.
//
// A real rulebase names categories the taxonomy DEFINES, and names far fewer
// distinct categories than it has rules: the taxonomy is bounded (the shipped
// product ships ~21 SaaS categories plus the rule-vocabulary built-ins) while a
// rulebase scoped by user group multiplies group x category into hundreds of
// rules. These benchmarks are that shape — rules cycling over categories that
// exist — measured against both destination classes:
//
//	uncategorized  no tier classifies the destination, so every rule's probe
//	               runs the full exact-then-suffix walk and misses. This is the
//	               WORST case for the path and, per
//	               categoryGroupMatchesHostScratch's own note, the COMMON case
//	               on a gateway: clean traffic to a host no tier classifies.
//	categorized    the destination is in the LAST category the rulebase names,
//	               so the scan traverses every rule before matching.
//
// Measured (go1.27.4, 4-core amd64, 12 categories / 40 hosts, benchstat over
// 10 interleaved rounds) against the existing benchmark on the same box:
//
//	rules   CategoryRules (n distinct)   realistic uncategorized
//	   10                      804 ns                     789 ns
//	   50                     2154 ns                    3766 ns
//	  200                     7386 ns                   13868 ns
//
// At 200 rules the realistic shape costs 13.9 µs of CPU per request where the
// shipped benchmark reports 7.4 µs — 107 ns per rule, paid on every proxied
// request. policy_scanindex.go declines to prefilter category rules on the
// stated grounds that they are "already amortized to O(1) per rule by their own
// per-scan scratch (hostCatScratch)"; that holds for the category-GROUP shape
// (BenchmarkPolicyEvaluate_CategoryGroupRulesSynthetic measures ~9 ns per rule)
// and does NOT hold here. These benchmarks are the instrument that shows it.
//
// NO GATE IS ATTACHED. The obvious amortization — deciding from the scan's
// memoized classification that an uncategorized destination can match no
// category — is NOT sound, and must not be adopted on the strength of these
// numbers: see TestCategoryMembership_ClassificationIsNotAMembershipOracle.

import (
	"fmt"
	"testing"
)

// buildRealisticCategoryPolicyStore returns n rules whose DestCategory cycles
// over the first cats categories of the seeded taxonomy, so every rule names a
// category that EXISTS and the rulebase has many more rules than categories.
func buildRealisticCategoryPolicyStore(n, cats int) *PolicyStore {
	ps := &PolicyStore{}
	rules := make([]PolicyRule, n)
	for i := 0; i < n; i++ {
		rules[i] = PolicyRule{
			Priority:     i + 1,
			Name:         fmt.Sprintf("real-cat-rule-%d", i),
			DestCategory: URLCategory(fmt.Sprintf("Category %d", i%cats)),
			Action:       ActionAllow,
		}
	}
	ps.ReplaceAll(rules)
	return ps
}

func BenchmarkPolicyEvaluate_CategoryRulesRealistic(b *testing.B) {
	const cats = 12
	seedCategoryTaxonomy(b, cats, 40)
	for _, n := range []int{10, 50, 200} {
		ps := buildRealisticCategoryPolicyStore(n, cats)

		// The destination no tier classifies: every rule pays a full probe.
		b.Run(fmt.Sprintf("uncategorized/rules=%d", n), func(b *testing.B) {
			if m := ps.Evaluate("203.0.113.7", "", "unauth", "uncategorized.example.net", nil); m != nil {
				b.Fatalf("expected no match, got %q — not measuring a full scan", m.Rule.Name)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = ps.Evaluate("203.0.113.7", "", "unauth", "uncategorized.example.net", nil)
			}
		})

		// A destination in the last category this rulebase actually NAMES, so
		// the scan traverses every rule before it matches. With n < cats the
		// rules only reach "Category n-1", so the index is min(n, cats)-1 —
		// picking cats-1 unconditionally would select a category no rule names
		// and silently measure a no-match scan instead (the b.Fatalf below
		// catches it).
		lastNamed := n
		if lastNamed > cats {
			lastNamed = cats
		}
		host := fmt.Sprintf("host-%d-7.example.com", lastNamed-1)
		b.Run(fmt.Sprintf("categorized/rules=%d", n), func(b *testing.B) {
			if m := ps.Evaluate("203.0.113.7", "", "unauth", host, nil); m == nil {
				b.Fatalf("expected a match on %q — not measuring the categorized shape", host)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = ps.Evaluate("203.0.113.7", "", "unauth", host, nil)
			}
		})
	}
}
