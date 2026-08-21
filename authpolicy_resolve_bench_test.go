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

// ─── Stage-1 hot-path precompute benchmarks ──────────────────────────────────
//
// These pin the two per-request derivations the precompute removed. Run:
//
//   go test -run '^$' -bench 'BenchmarkResolveAuthOutcome_(Scheduled|WideCIDR)|BenchmarkAuthScheduleParseable' -benchmem .

// assertFullAuthScan fails the benchmark unless the fixture resolves to
// Default — i.e. NO rule matched, so every auth rule was actually evaluated.
//
// Every benchmark below reports a per-request cost premised on a FULL scan. A
// fixture that accidentally matches returns on the first hit, so the number
// would silently describe one rule instead of the whole tranche. That is worse
// than a failing benchmark: it reads as a real measurement. Asserting the
// premise before ResetTimer keeps the fixtures honest and, for the scheduled
// rules, keeps them independent of wall-clock time.
func assertFullAuthScan(b *testing.B, ps *PolicyStore, ctx RequestContext) {
	b.Helper()
	if d := resolveAuthOutcomeSnapshot(ps.evaluationSnapshot(), ctx); d.Outcome != OutcomeDefault {
		b.Fatalf("fixture matched a rule (outcome %q) — the benchmark would measure a partial scan, not the full rule tranche", d.Outcome)
	}
}

// benchScheduledAuthRules returns nAuth MATCHING-subject auth rules that each
// carry a timezone-scoped schedule, so every rule reaches authScheduleParseable.
// This is the shape that made an uncached time.LoadLocation catastrophic: the
// stdlib re-reads and re-parses tzdata on every call (~8.6 µs / ~8.6 KB), and
// the Stage-1 gate reaches it once per scheduled rule per request.
func benchScheduledAuthRules(nAuth int) []PolicyRule {
	rules := make([]PolicyRule, 0, nAuth)
	for i := 0; i < nAuth; i++ {
		rules = append(rules, PolicyRule{
			Priority: i + 1,
			Name:     fmt.Sprintf("auth-sched-%d", i),
			RuleType: ruleTypeAuth,
			SubjectMatch: &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{
				{Type: subjectPredicateCIDR, Values: []string{"203.0.113.0/24"}},
			}},
			// Matches the benchmark client's subject and host so the scan reaches
			// the schedule, then is rejected there — exercising the timezone path
			// on every rule of every request.
			//
			// The window must be EMPTY, not merely narrow: scheduleTimeMatch
			// evaluates start<=end as `cur >= start && cur < end`, so
			// "00:00"–"00:00" can never match at ANY instant, in any timezone. A
			// narrow-but-real window (e.g. Sun 00:00–00:01) would match inside it,
			// the first rule would return early, and the benchmark would silently
			// measure ONE rule instead of nAuth — a wall-clock-dependent result.
			DestFQDN: "target.example.com",
			Schedule: &PolicySchedule{
				Timezone:  "America/New_York",
				Days:      []string{"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"},
				TimeStart: "00:00",
				TimeEnd:   "00:00",
			},
			Auth: &AuthRuleSpec{Outcome: OutcomeCredentialRequired, Owner: "bench", Reason: "bench"},
		})
	}
	return rules
}

// BenchmarkResolveAuthOutcome_ScheduledAuthRules measures the resolver over
// timezone-scheduled auth rules — the shape dominated by timezone resolution.
// With the shared cache this stays flat; with a direct time.LoadLocation it
// costs a tzdata disk read and ~8.6 KB of garbage PER RULE PER REQUEST.
func BenchmarkResolveAuthOutcome_ScheduledAuthRules(b *testing.B) {
	for _, n := range []int{1, 8} {
		b.Run(fmt.Sprintf("sched-auth-%d", n), func(b *testing.B) {
			ps := buildAuthResolveStore(100, benchScheduledAuthRules(n)...)
			ctx := benchNoCredCtx()
			assertFullAuthScan(b, ps, ctx)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = resolveAuthOutcomeSnapshot(ps.evaluationSnapshot(), ctx)
			}
		})
	}
}

// BenchmarkAuthScheduleParseable isolates the timezone gate itself — the
// clearest before/after reference for the cache (cached ~15 ns / 0 allocs,
// uncached ~8600 ns / 13 allocs).
func BenchmarkAuthScheduleParseable(b *testing.B) {
	sched := &PolicySchedule{Timezone: "America/New_York", Days: []string{"Mon"}, TimeStart: "09:00", TimeEnd: "17:00"}
	if !authScheduleParseable(sched) { // warm the cache; measure steady state
		b.Fatal("fixture timezone did not resolve")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = authScheduleParseable(sched)
	}
}

// BenchmarkResolveAuthOutcome_WideCIDRPredicates is the stress shape for the
// subject-CIDR precompute: a realistic corporate rulebase where each auth rule
// scopes to many branch ranges. Cost per request used to be
// O(rules × values × ParseCIDR); it is now O(rules × values × Contains) with no
// allocation, so the gap widens with the number of values.
func BenchmarkResolveAuthOutcome_WideCIDRPredicates(b *testing.B) {
	for _, values := range []int{4, 32} {
		b.Run(fmt.Sprintf("values-%d", values), func(b *testing.B) {
			vals := make([]string, 0, values)
			for i := 0; i < values; i++ {
				vals = append(vals, fmt.Sprintf("10.%d.0.0/16", i%250))
			}
			auth := make([]PolicyRule, 0, 8)
			for i := 0; i < 8; i++ {
				auth = append(auth, PolicyRule{
					Priority:     i + 1,
					Name:         fmt.Sprintf("auth-wide-%d", i),
					RuleType:     ruleTypeAuth,
					SubjectMatch: &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: subjectPredicateCIDR, Values: vals}}},
					DestFQDN:     fmt.Sprintf("auth-no-match-%d.example.invalid", i),
					Auth:         &AuthRuleSpec{Outcome: OutcomeCredentialRequired, Owner: "bench", Reason: "bench"},
				})
			}
			ps := buildAuthResolveStore(100, auth...)
			ctx := benchNoCredCtx()
			assertFullAuthScan(b, ps, ctx)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = resolveAuthOutcomeSnapshot(ps.evaluationSnapshot(), ctx)
			}
		})
	}
}

// BenchmarkResolveAuthOutcome_WideCIDRParallel is the concurrency shape: the
// published nets are read-only after publication, so throughput must scale with
// cores instead of serializing on the allocator.
func BenchmarkResolveAuthOutcome_WideCIDRParallel(b *testing.B) {
	vals := make([]string, 0, 32)
	for i := 0; i < 32; i++ {
		vals = append(vals, fmt.Sprintf("10.%d.0.0/16", i%250))
	}
	auth := []PolicyRule{{
		Priority:     1,
		Name:         "auth-wide",
		RuleType:     ruleTypeAuth,
		SubjectMatch: &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: subjectPredicateCIDR, Values: vals}}},
		DestFQDN:     "auth-no-match.example.invalid",
		Auth:         &AuthRuleSpec{Outcome: OutcomeCredentialRequired, Owner: "bench", Reason: "bench"},
	}}
	ps := buildAuthResolveStore(100, auth...)
	ctx := benchNoCredCtx()
	assertFullAuthScan(b, ps, ctx)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = resolveAuthOutcomeSnapshot(ps.evaluationSnapshot(), ctx)
		}
	})
}
