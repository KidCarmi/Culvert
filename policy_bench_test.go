package main

// Policy-engine performance benchmarks (CI quality program — PR-2).
//
// These are the first benchmarks in the repository. They answer a concrete
// production question from docs/ci/proxy-quality-architecture.md: "does latency
// stay stable as the policy set grows to 1000 / 10000 rules?" The proxy hot
// path calls policyStore.Evaluate on EVERY request, so its scaling with rule
// count is a first-order latency factor.
//
// Benchmarks only run under `go test -bench`, never during the normal
// `go test ./...` that qa-gate.yml runs — so they add zero cost to the required
// gates. The nightly workflow runs them with -benchmem and emits the output as
// a benchstat-ready artifact and a baseline for the PR-3 regression gate.
//
// Run locally:
//   go test -run '^$' -bench 'BenchmarkPolicy|BenchmarkScrub' -benchmem .

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/KidCarmi/Culvert/internal/catgroup"
	"github.com/KidCarmi/Culvert/internal/urlcat"
)

// buildPolicyStore returns a store with n non-matching access rules. With a
// query host that matches none of them, Evaluate performs a full O(n) scan and
// returns nil (default deny) — the worst case, and the honest measure of how
// rule count taxes the hot path.
func buildPolicyStore(n int) *PolicyStore {
	ps := &PolicyStore{}
	rules := make([]PolicyRule, n)
	for i := 0; i < n; i++ {
		rules[i] = PolicyRule{
			Priority: i + 1,
			Name:     fmt.Sprintf("rule-%d", i),
			DestFQDN: fmt.Sprintf("no-match-%d.example.invalid", i),
			Action:   ActionAllow,
		}
	}
	// ReplaceAll sorts ONCE; an Add-per-rule loop would sort on every insert
	// (O(n^2 log n) — pathological at n=10000, multi-minute build).
	ps.ReplaceAll(rules)
	return ps
}

// BenchmarkPolicyEvaluate_NoMatch measures the full-scan / default-deny path at
// increasing rule counts. A flat ns/op-per-rule across sizes means the engine
// scales linearly with no pathological per-rule blowup.
func BenchmarkPolicyEvaluate_NoMatch(b *testing.B) {
	for _, n := range []int{10, 100, 1000, 10000} {
		ps := buildPolicyStore(n)
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if m := ps.Evaluate("203.0.113.7", "", "unauth", "target.example.com", nil); m != nil {
					b.Fatalf("expected no match (default deny), got rule %q", m.Rule.Name)
				}
			}
		})
	}
}

// BenchmarkPolicyEvaluate_MatchLast measures the cost when the matching rule is
// the lowest-priority (last-evaluated) one — i.e. the scan must traverse every
// preceding rule before the allow. This is the worst case for a request that is
// ultimately allowed, and exercises first-match-wins ordering at scale.
func BenchmarkPolicyEvaluate_MatchLast(b *testing.B) {
	for _, n := range []int{10, 100, 1000, 10000} {
		ps := buildPolicyStore(n)
		// Lowest priority number is evaluated first; give the catch-all the
		// highest number so it is evaluated last.
		ps.Add(PolicyRule{Priority: n + 1, Name: "catch-all", DestFQDN: "*", Action: ActionAllow})
		b.Run(fmt.Sprintf("rules=%d", n+1), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				m := ps.Evaluate("203.0.113.7", "", "unauth", "target.example.com", nil)
				if m == nil || m.Rule.Name != "catch-all" {
					b.Fatalf("expected catch-all match, got %v", m)
				}
			}
		})
	}
}

// buildCIDRPolicyStore returns a store with n access rules whose SourceIP is a
// CIDR the benchmark client IP (203.0.113.7) FALLS INSIDE, so every rule passes
// the source check and proceeds to the (non-matching) FQDN check. This is the
// worst case for source-scoped rulesets — every rule pays the full CIDR match —
// and mirrors how enterprise deployments scope rules by client subnet.
func buildCIDRPolicyStore(n int) *PolicyStore {
	ps := &PolicyStore{}
	rules := make([]PolicyRule, n)
	for i := 0; i < n; i++ {
		rules[i] = PolicyRule{
			Priority: i + 1,
			Name:     fmt.Sprintf("cidr-rule-%d", i),
			SourceIP: "203.0.113.0/24",
			DestFQDN: fmt.Sprintf("no-match-%d.example.invalid", i),
			Action:   ActionAllow,
		}
	}
	ps.ReplaceAll(rules)
	return ps
}

// BenchmarkPolicyEvaluate_CIDRRules measures the full scan over source-scoped
// (CIDR) rules. Before the srcIPNet precompute this re-parsed the rule's CIDR
// (net.ParseCIDR) AND the client IP (net.ParseIP) per rule per request; after,
// the scan is a Contains() on a precomputed *net.IPNet with the client IP
// parsed once per Evaluate.
func BenchmarkPolicyEvaluate_CIDRRules(b *testing.B) {
	for _, n := range []int{10, 100, 1000} {
		ps := buildCIDRPolicyStore(n)
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if m := ps.Evaluate("203.0.113.7", "", "unauth", "target.example.com", nil); m != nil {
					b.Fatalf("expected no match (default deny), got rule %q", m.Rule.Name)
				}
			}
		})
	}
}

// buildScheduledPolicyStore returns a store with n access rules carrying an
// always-active schedule pinned to a non-UTC timezone, so every rule passes the
// schedule check and proceeds to the (non-matching) FQDN check.
func buildScheduledPolicyStore(n int) *PolicyStore {
	ps := &PolicyStore{}
	rules := make([]PolicyRule, n)
	for i := 0; i < n; i++ {
		rules[i] = PolicyRule{
			Priority: i + 1,
			Name:     fmt.Sprintf("sched-rule-%d", i),
			DestFQDN: fmt.Sprintf("no-match-%d.example.invalid", i),
			Schedule: &PolicySchedule{TimeStart: "00:00", TimeEnd: "23:59", Timezone: "America/New_York"},
			Action:   ActionAllow,
		}
	}
	ps.ReplaceAll(rules)
	return ps
}

// BenchmarkPolicyEvaluate_ScheduledRules measures the full scan over rules with
// a timezone-pinned schedule. Before the shared location cache, matchSchedule
// called time.LoadLocation per rule per request — an uncached tzdata DISK READ
// on the proxy hot path.
func BenchmarkPolicyEvaluate_ScheduledRules(b *testing.B) {
	for _, n := range []int{10, 100, 1000} {
		ps := buildScheduledPolicyStore(n)
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if m := ps.Evaluate("203.0.113.7", "", "unauth", "target.example.com", nil); m != nil {
					b.Fatalf("expected no match (default deny), got rule %q", m.Rule.Name)
				}
			}
		})
	}
}

// buildCategoryGroupPolicyStore returns a store with n access rules that each
// reference a category group and constrain nothing else, so every one of them
// reaches categoryGroupMatchesHostRule during a scan. That is the shape a
// category-driven posture actually has ("Marketing → Deny", "AI → Inspect",
// …): the rules are selected by DESTINATION CATEGORY, not by FQDN, so there is
// no cheap FQDN test to short-circuit them first.
func buildCategoryGroupPolicyStore(n int) *PolicyStore {
	ps := &PolicyStore{}
	rules := make([]PolicyRule, n)
	for i := 0; i < n; i++ {
		rules[i] = PolicyRule{
			Priority:          i + 1,
			Name:              fmt.Sprintf("catgroup-rule-%d", i),
			DestCategoryGroup: fmt.Sprintf("group-%d", i),
			Action:            ActionBlockPage,
		}
	}
	ps.ReplaceAll(rules)
	return ps
}

// BenchmarkPolicyEvaluate_CategoryGroupRules is the end-to-end measure of the
// host→category resolution that category-group rules depend on.
//
// Each such rule calls categoryGroupMatchesHostRule → lookupHostCategory →
// catStore.LookupHost. That lookup used to scan every host pattern of every
// category in the taxonomy, so the per-request cost was
// (rules with a category group) x (patterns in the taxonomy) — on the SHIPPED
// default taxonomy alone (657 patterns) that measured ~24 us per rule, i.e.
// hundreds of microseconds of pure CPU inside the request goroutine for an
// ordinary posture. It is now a bounded probe per host label, independent of
// taxonomy size; see internal/urlcat.lookupIn.
//
// The query host is deliberately UNCATEGORIZED: that is both the clean-traffic
// case and the worst case, since a miss cannot short-circuit.
func BenchmarkPolicyEvaluate_CategoryGroupRules(b *testing.B) {
	origCat, origGroups := catStore, globalCategoryGroups
	b.Cleanup(func() { catStore, globalCategoryGroups = origCat, origGroups })

	// The shipped default taxonomy — what a fresh install evaluates against.
	catStore = newCategoryStore(urlcat.DefaultEntries())
	catStore.SetPathForTest(filepath.Join(b.TempDir(), "categories.json"))

	for _, n := range []int{1, 5, 20} {
		globalCategoryGroups = catgroup.New()
		groups := make([]CategoryGroup, n)
		for i := 0; i < n; i++ {
			groups[i] = CategoryGroup{
				Name:       fmt.Sprintf("group-%d", i),
				Categories: []string{"Streaming", "Gambling"},
			}
		}
		globalCategoryGroups.ReplaceAll(groups)

		ps := buildCategoryGroupPolicyStore(n)
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if m := ps.Evaluate("203.0.113.7", "", "unauth", "uncategorized.example.invalid", nil); m != nil {
					b.Fatalf("expected no match (default deny), got rule %q", m.Rule.Name)
				}
			}
		})
	}
}

// BenchmarkScrubForwardedHeaders measures the per-request header-scrub hot path
// (X-Forwarded-For / X-Real-IP private-IP stripping + X-User-Identity removal),
// run for every forwarded HTTP request.
func BenchmarkScrubForwardedHeaders(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		r, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://target.example.com/", http.NoBody)
		r.Header.Set("X-Forwarded-For", "10.0.0.1, 203.0.113.9, 192.168.1.1")
		r.Header.Set("X-Real-IP", "10.1.2.3")
		r.Header.Set("X-User-Identity", "spoofed@evil.example")
		scrubForwardedHeaders(r)
	}
}
