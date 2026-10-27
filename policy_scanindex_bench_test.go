package main

// Benchmarks for the packed Stage-2 destination prefilter
// (policy_scanindex.go). The point of this file is NOT to re-measure the
// favourable case — BenchmarkPolicyEvaluate_NoMatch / MatchLast and
// BenchmarkPerfQual_Evaluate already cover a rulebase whose patterns differ
// from the probe host, which is the shape the index was built for. The point is
// the ADVERSARIAL case: a rulebase the prefilter cannot reject a single rule
// from, which must not be slower than the unindexed scan, and the publication
// cost the index adds to every policy write.
//
//	go test -run '^$' -bench 'ScanIndex' -benchmem -count=10 .

import (
	"fmt"
	"testing"
	"time"
)

// buildAdversarialScanStore returns `size` rules the prefilter can prove
// nothing about: every pattern is the SAME LENGTH as the probe host and shares
// its last policyScanTailMax bytes, so every row clears both the length check
// and the tail check and every rule falls through to the full predicate. This
// is the worst case for the index and the one that decides whether it is safe
// to carry on the hot path at all.
func buildAdversarialScanStore(size int) (ps *PolicyStore, host string) {
	host = "aaaaaa0000.shared-tail.example.com"
	rules := make([]PolicyRule, size)
	for i := 0; i < size; i++ {
		// Same total length as host, same trailing bytes, differing only in the
		// leading label — so MatchFQDNNorm has to compare the bytes to refuse.
		rules[i] = PolicyRule{
			Priority: i + 1,
			Name:     fmt.Sprintf("rule-%d", i),
			DestFQDN: fmt.Sprintf("bbbbbb%04d.shared-tail.example.com", i),
			Action:   ActionAllow,
		}
	}
	ps = &PolicyStore{}
	ps.ReplaceAll(rules)
	return ps, host
}

// BenchmarkScanIndex_AdversarialNoMatch measures the scan when the prefilter
// rejects nothing. Any cost here is the row load plus two compares per rule,
// paid for no benefit; it bounds what the index can cost a rulebase it cannot
// help.
func BenchmarkScanIndex_AdversarialNoMatch(b *testing.B) {
	for _, size := range []int{100, 1000, 10000} {
		ps, host := buildAdversarialScanStore(size)
		b.Run(fmt.Sprintf("rules=%d", size), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if m := ps.Evaluate("203.0.113.7", "", "unauth", host, nil); m != nil {
					b.Fatalf("rulebase must not match")
				}
			}
		})
	}
}

// BenchmarkScanIndex_AdversarialNoIndex is the same scan with the prefilter
// forced off, so the pair is a before/after on one process and one rulebase.
// The gap between the two is the index's overhead in its worst case.
func BenchmarkScanIndex_AdversarialNoIndex(b *testing.B) {
	for _, size := range []int{100, 1000, 10000} {
		ps, host := buildAdversarialScanStore(size)
		rules := ps.evaluationSnapshot()
		in := accessEvalInput{clientIP: "203.0.113.7", authSource: "unauth", host: host, normHost: normalizeHost(host)}
		b.Run(fmt.Sprintf("rules=%d", size), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if r := evalAccessRules(rules, nil, &in, benchFixedNow, nil); r != nil {
					b.Fatalf("rulebase must not match")
				}
			}
		})
	}
}

// BenchmarkScanIndex_AdversarialWithIndex is its indexed twin, through the same
// core with the same inputs — the controlled comparison for the pair above.
func BenchmarkScanIndex_AdversarialWithIndex(b *testing.B) {
	for _, size := range []int{100, 1000, 10000} {
		ps, host := buildAdversarialScanStore(size)
		rules := ps.evaluationSnapshot()
		rows := scanIndexFor(&ps.scanIndex, rules)
		if len(rows) != len(rules) {
			b.Fatalf("no index published (%d rows for %d rules)", len(rows), len(rules))
		}
		in := accessEvalInput{clientIP: "203.0.113.7", authSource: "unauth", host: host, normHost: normalizeHost(host)}
		b.Run(fmt.Sprintf("rules=%d", size), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if r := evalAccessRules(rules, rows, &in, benchFixedNow, nil); r != nil {
					b.Fatalf("rulebase must not match")
				}
			}
		})
	}
}

// BenchmarkScanIndex_Parallel runs the indexed scan on every core. The index is
// read through one atomic pointer load and never written on the request path,
// so this must stay flat in GOMAXPROCS — a regression here would mean the
// publication had become a shared write.
func BenchmarkScanIndex_Parallel(b *testing.B) {
	ps, _ := buildMatchPositionStoreForIndexBench(1000)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = ps.Evaluate("203.0.113.7", "", "unauth", "target.example.com", nil)
		}
	})
}

// BenchmarkScanIndex_Publish measures what the index adds to a policy WRITE:
// one contiguous allocation plus one pass over the published rules, inside
// sortLocked's existing critical section. Publication holds the writer lock and
// therefore stalls evaluation, so this cost is the one to keep an eye on.
func BenchmarkScanIndex_Publish(b *testing.B) {
	for _, size := range []int{100, 1000, 10000} {
		ps, _ := buildMatchPositionStoreForIndexBench(size)
		rules := ps.evaluationSnapshot()
		b.Run(fmt.Sprintf("rules=%d", size), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				scanRowSink = buildPolicyScanRows(rules)
			}
		})
	}
}

var scanRowSink []policyScanRow

// buildMatchPositionStoreForIndexBench is a local, dependency-free rulebase
// builder: one matching rule last, the rest distinct non-matching FQDNs. It
// does not reuse the F3 qualification helper so this file stays independent of
// an untracked artifact.
func buildMatchPositionStoreForIndexBench(size int) (ps *PolicyStore, host string) {
	rules := make([]PolicyRule, size)
	for i := 0; i < size; i++ {
		rules[i] = PolicyRule{
			Priority: i + 1,
			Name:     fmt.Sprintf("rule-%d", i),
			DestFQDN: fmt.Sprintf("no-match-%d.example.invalid", i),
			Action:   ActionAllow,
		}
	}
	rules[size-1].DestFQDN = "target.example.com"
	ps = &PolicyStore{}
	ps.ReplaceAll(rules)
	return ps, "target.example.com"
}

// benchFixedNow pins the evaluation instant so the pair above differs only in
// whether the index is supplied. No rule in these stores is scheduled, so it is
// never actually called — passing a fixed clock keeps that explicit.
func benchFixedNow() time.Time { return time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC) }
