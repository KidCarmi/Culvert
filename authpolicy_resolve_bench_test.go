package main

// Stage-1 runtime auth-resolution benchmarks.
//
// resolveNoCredAuthOutcome runs on EVERY request that presents no credentials —
// all CONNECTs in an SSO deployment, and 100% of traffic in an open
// (defaultAuthOutcome=Exempt) deployment — so its scaling with rulebase size is
// a first-order latency factor, exactly like policyStore.Evaluate (see
// policy_bench_test.go). Before the snapshot resolver, this path cloned and
// re-sorted the ENTIRE rulebase per request via policyStore.List():
// ~O(rules) heap clones (~512 B/rule plus nested slices) and an RFC3339 format
// per hit rule. BenchmarkResolveAuthOutcome_PureListBaseline keeps that shape
// measurable forever (the pure resolver still serves the simulator), so the
// before/after delta is always reproducible:
//
//   go test -run '^$' -bench 'BenchmarkResolveAuthOutcome' -benchmem .
//
// The allocation contract is pinned as a hard gate in bench_regression_test.go
// (TestBenchGate_AuthResolveAllocs, -tags benchgate).

import (
	"fmt"
	"testing"
)

// benchNoCredCtx is the dominant request shape at the gate: an un-credentialed
// CONNECT that matches no auth rule (scan completes, Outcome=Default).
func benchNoCredCtx() RequestContext {
	return RequestContext{ClientIP: "203.0.113.7", Host: "target.example.com", Protocol: "connect", Method: "CONNECT"}
}

// benchAuthRules returns nAuth persistable, non-matching scoped CR rules.
func benchAuthRules(nAuth int) []PolicyRule {
	rules := make([]PolicyRule, 0, nAuth)
	for i := 0; i < nAuth; i++ {
		rules = append(rules, PolicyRule{
			Priority: i + 1,
			Name:     fmt.Sprintf("auth-%d", i),
			RuleType: ruleTypeAuth,
			SubjectMatch: &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{
				{Type: subjectPredicateCIDR, Values: []string{fmt.Sprintf("10.%d.0.0/16", i%250)}},
			}},
			DestFQDN: fmt.Sprintf("auth-no-match-%d.example.invalid", i),
			Auth:     &AuthRuleSpec{Outcome: OutcomeCredentialRequired, Owner: "bench", Reason: "bench"},
		})
	}
	return rules
}

// BenchmarkResolveAuthOutcome_AccessOnly measures the runtime snapshot resolver
// over rulebases with no auth rules — the common deployment. The scan must stay
// allocation-free at any rule count: every rule exits at the type check and the
// lazy scratch never computes.
func BenchmarkResolveAuthOutcome_AccessOnly(b *testing.B) {
	for _, n := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("rules-%d", n), func(b *testing.B) {
			ps := buildAuthResolveStore(n)
			ctx := benchNoCredCtx()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = resolveAuthOutcomeSnapshot(ps.evaluationSnapshot(), ctx)
			}
		})
	}
}

// BenchmarkResolveAuthOutcome_AuthRulesMiss adds a tranche of scoped auth rules
// that do not match — the worst case for an un-credentialed request in a
// deployment that uses Stage-1 rules (full scan, per-auth-rule subject checks,
// Outcome=Default).
func BenchmarkResolveAuthOutcome_AuthRulesMiss(b *testing.B) {
	for _, n := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("access-%d-auth-8", n), func(b *testing.B) {
			ps := buildAuthResolveStore(n, benchAuthRules(8)...)
			ctx := benchNoCredCtx()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = resolveAuthOutcomeSnapshot(ps.evaluationSnapshot(), ctx)
			}
		})
	}
}

// BenchmarkResolveAuthOutcome_AuthRuleMatch measures a request that matches the
// LAST auth rule (full auth-rule scan plus the one-time matched-rule detach
// copy).
func BenchmarkResolveAuthOutcome_AuthRuleMatch(b *testing.B) {
	match := PolicyRule{
		Priority: 99, Name: "auth-match", RuleType: ruleTypeAuth,
		SubjectMatch: &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{"203.0.113.0/24"}}}},
		DestFQDN:     "target.example.com",
		Auth:         &AuthRuleSpec{Outcome: OutcomeCredentialRequired, Owner: "bench", Reason: "bench"},
	}
	ps := buildAuthResolveStore(1000, append(benchAuthRules(8), match)...)
	ctx := benchNoCredCtx()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d := resolveAuthOutcomeSnapshot(ps.evaluationSnapshot(), ctx)
		if d.Outcome != OutcomeCredentialRequired {
			b.Fatalf("expected CR match, got %q", d.Outcome)
		}
	}
}

// BenchmarkResolveAuthOutcome_Parallel exercises the resolver concurrently —
// the snapshot read path must scale with cores (RLock + immutable published
// definitions, no per-request cloning to serialize on the allocator).
func BenchmarkResolveAuthOutcome_Parallel(b *testing.B) {
	ps := buildAuthResolveStore(1000, benchAuthRules(8)...)
	ctx := benchNoCredCtx()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = resolveAuthOutcomeSnapshot(ps.evaluationSnapshot(), ctx)
		}
	})
}

// BenchmarkResolveAuthOutcome_PureListBaseline measures the pre-optimization
// runtime shape (resolveAuthOutcomeFrom over policyStore.List()) — still the
// simulator's path, and the permanent before/after reference for the snapshot
// resolver above.
func BenchmarkResolveAuthOutcome_PureListBaseline(b *testing.B) {
	for _, n := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("rules-%d", n), func(b *testing.B) {
			ps := buildAuthResolveStore(n, benchAuthRules(8)...)
			ctx := benchNoCredCtx()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = resolveAuthOutcomeFrom(ps.List(), ctx)
			}
		})
	}
}
