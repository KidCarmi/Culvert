package main

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// ─── Differential oracle ──────────────────────────────────────────────────────

// buildMatchedConditionsLegacy is a VERBATIM copy of the []string + strings.Join
// implementation that buildMatchedConditions replaced. It exists only as the
// differential oracle for TestBuildMatchedConditions_MatchesLegacy and
// FuzzBuildMatchedConditions: the optimization is a pure allocation change and
// the rendered summary must stay byte-identical, because it is persisted on the
// rule (matchedConds), emitted on every POLICY_* log line and surfaced in the
// request feed. Do not "fix" or re-order this copy — divergence from it is the
// regression the tests exist to catch.
func buildMatchedConditionsLegacy(rule *PolicyRule) string {
	var parts []string
	if rule.SourceIP != "" {
		parts = append(parts, "srcIP="+rule.SourceIP)
	}
	if rule.SourceIdentity != "" {
		parts = append(parts, "identity="+rule.SourceIdentity)
	}
	if rule.SourceGroup != "" {
		parts = append(parts, "group="+rule.SourceGroup)
	}
	if rule.AuthSource != "" {
		parts = append(parts, "authSrc="+rule.AuthSource)
	}
	if rule.DestFQDN != "" {
		parts = append(parts, "destFQDN="+rule.DestFQDN)
	}
	if rule.DestCategory != "" && rule.DestCategory != CategoryAny {
		parts = append(parts, "destCat="+string(rule.DestCategory))
	}
	if rule.DestCategoryGroup != "" {
		parts = append(parts, "destCatGroup="+rule.DestCategoryGroup)
	}
	if len(rule.DestCountry) > 0 {
		parts = append(parts, "destCountry="+strings.Join(rule.DestCountry, ","))
	}
	if rule.Schedule != nil {
		parts = append(parts, "schedule=active")
	}
	if len(parts) == 0 {
		return "any"
	}
	return strings.Join(parts, " ")
}

// ─── Rule shapes ──────────────────────────────────────────────────────────────

// matchedCondShapes are the rule shapes the benchmarks and the differential
// table share: the summary's cost is driven by how many conditions a rule
// carries, so the set spans the no-condition fast path, the one-condition shape
// the synthetic publication benchmarks install, a realistic enterprise rule and
// the saturated nine-condition worst case.
func matchedCondShapes() []struct {
	name string
	rule PolicyRule
} {
	return []struct {
		name string
		rule PolicyRule
	}{
		{"none", PolicyRule{}},
		{"fqdn-only", PolicyRule{DestFQDN: "host-4096.example.invalid"}},
		{"typical", PolicyRule{
			SourceIP:     "203.0.113.0/24",
			SourceGroup:  "engineering",
			DestCategory: "social-media",
			Schedule:     &PolicySchedule{Days: []string{"Mon"}, TimeStart: "09:00", TimeEnd: "17:00", Timezone: "UTC"},
		}},
		{"countries", PolicyRule{
			DestFQDN:    "api.example.invalid",
			DestCountry: []string{"RU", "CN", "IR", "KP", "SY", "BY"},
		}},
		{"full", PolicyRule{
			SourceIP:          "198.51.100.0/22",
			SourceIdentity:    "alice@corp.example.invalid",
			SourceGroup:       "finance-privileged",
			AuthSource:        "okta",
			DestFQDN:          "*.payments.example.invalid",
			DestCategory:      "financial-services",
			DestCategoryGroup: "restricted-finance",
			DestCountry:       []string{"US", "CA", "GB"},
			Schedule:          &PolicySchedule{Days: []string{"Mon", "Fri"}, TimeStart: "08:30", TimeEnd: "18:30", Timezone: "America/New_York"},
		}},
	}
}

// ─── Equivalence ──────────────────────────────────────────────────────────────

// TestBuildMatchedConditions_MatchesLegacy pins byte-exact equivalence with the
// pre-optimization implementation across the shared shapes plus a randomized
// sweep over every subset of the nine conditions, including the empty-string and
// empty-element edges the "any" fast path and the country join turn on.
func TestBuildMatchedConditions_MatchesLegacy(t *testing.T) {
	// Indexed, not value-ranged: PolicyRule is a large struct and copying one
	// per iteration is what the gocritic rangeValCopy check is for.
	shapes := matchedCondShapes()
	for i := range shapes {
		rule := &shapes[i].rule
		if got, want := buildMatchedConditions(rule), buildMatchedConditionsLegacy(rule); got != want {
			t.Errorf("%s: buildMatchedConditions = %q, legacy = %q", shapes[i].name, got, want)
		}
	}

	// Randomized subset sweep. Deterministic seed so a failure is reproducible.
	rng := rand.New(rand.NewSource(0x5ca1ab1e)) //nolint:gosec // G404: test input generation, not security
	vals := []string{"", "a", "x.example.invalid", "very-long-" + strings.Repeat("v", 200)}
	countrySets := [][]string{nil, {}, {"US"}, {"US", "CA"}, {""}, {"", ""}}
	for i := 0; i < 20000; i++ {
		rule := PolicyRule{
			SourceIP:          vals[rng.Intn(len(vals))],
			SourceIdentity:    vals[rng.Intn(len(vals))],
			SourceGroup:       vals[rng.Intn(len(vals))],
			AuthSource:        vals[rng.Intn(len(vals))],
			DestFQDN:          vals[rng.Intn(len(vals))],
			DestCategoryGroup: vals[rng.Intn(len(vals))],
			DestCountry:       countrySets[rng.Intn(len(countrySets))],
		}
		// DestCategory has a second wildcard spelling (CategoryAny) that must
		// be suppressed exactly as the empty value is.
		switch rng.Intn(3) {
		case 0:
			rule.DestCategory = CategoryAny
		case 1:
			rule.DestCategory = "news"
		}
		if rng.Intn(2) == 0 {
			rule.Schedule = &PolicySchedule{}
		}
		if got, want := buildMatchedConditions(&rule), buildMatchedConditionsLegacy(&rule); got != want {
			t.Fatalf("iteration %d: buildMatchedConditions = %q, legacy = %q (rule %+v)", i, got, want, rule)
		}
	}
}

// FuzzBuildMatchedConditions is the differential fuzz target: the summary is
// rendered from operator-supplied strings, so the renderer must agree with the
// oracle on inputs no table enumerates (control bytes, invalid UTF-8, embedded
// spaces and '=' that could be mistaken for a separator).
func FuzzBuildMatchedConditions(f *testing.F) {
	f.Add("203.0.113.0/24", "alice", "eng", "okta", "x.example.invalid", "news", "grp", "US,CA", true)
	f.Add("", "", "", "", "", "", "", "", false)
	f.Add(" ", "=", "a b", "\x00", "\xff\xfe", "any", "g=1", ",", true)
	f.Fuzz(func(t *testing.T, srcIP, identity, group, authSrc, fqdn, cat, catGroup, countries string, sched bool) {
		rule := PolicyRule{
			SourceIP:          srcIP,
			SourceIdentity:    identity,
			SourceGroup:       group,
			AuthSource:        authSrc,
			DestFQDN:          fqdn,
			DestCategory:      URLCategory(cat),
			DestCategoryGroup: catGroup,
		}
		if countries != "" {
			rule.DestCountry = strings.Split(countries, ",")
		}
		if sched {
			rule.Schedule = &PolicySchedule{}
		}
		if got, want := buildMatchedConditions(&rule), buildMatchedConditionsLegacy(&rule); got != want {
			t.Fatalf("buildMatchedConditions = %q, legacy = %q", got, want)
		}
	})
}

// ─── Allocation gate ──────────────────────────────────────────────────────────

// TestBuildMatchedConditions_AllocBudget is the structural regression gate. The
// point of the optimization is that the summary costs ONE allocation — the
// returned string — regardless of how many conditions a rule carries, instead of
// one per condition plus the growth of a []string plus the join. A timing
// threshold would be hardware-dependent and flaky; the allocation count is not.
//
// The no-condition shape returns a constant and must allocate nothing at all.
func TestBuildMatchedConditions_AllocBudget(t *testing.T) {
	shapes := matchedCondShapes()
	for i := range shapes {
		rule := &shapes[i].rule
		want := 1.0
		if shapes[i].name == "none" {
			want = 0.0
		}
		got := testing.AllocsPerRun(200, func() {
			sinkMatchedConds = buildMatchedConditions(rule)
		})
		if got > want {
			t.Errorf("%s: buildMatchedConditions allocated %.0f objects, budget %.0f", shapes[i].name, got, want)
		}
	}
}

// sinkMatchedConds keeps the benchmarked/measured result live so the compiler
// cannot elide the call being measured.
var sinkMatchedConds string

// ─── Benchmarks ───────────────────────────────────────────────────────────────

// BenchmarkBuildMatchedConditions times the current renderer against the legacy
// one in the SAME run and over the same shapes, so a reader comparing them is
// not comparing two machines. buildMatchedConditions runs once per rule per
// publication under ps.mu — the writer lock Evaluate's evaluationSnapshot must
// wait on — so its allocation count is a data-plane latency figure, not just a
// reload figure (see BenchmarkPolicyPublish_SortLocked).
func BenchmarkBuildMatchedConditions(b *testing.B) {
	shapes := matchedCondShapes()
	for i := range shapes {
		rule := &shapes[i].rule
		b.Run(shapes[i].name+"/current", func(b *testing.B) {
			b.ReportAllocs()
			for j := 0; j < b.N; j++ {
				sinkMatchedConds = buildMatchedConditions(rule)
			}
		})
		b.Run(shapes[i].name+"/legacy", func(b *testing.B) {
			b.ReportAllocs()
			for j := 0; j < b.N; j++ {
				sinkMatchedConds = buildMatchedConditionsLegacy(rule)
			}
		})
	}
}

// BenchmarkBuildMatchedConditionsRulebase is the in-situ arm: it renders a whole
// rulebase's worth of summaries the way sortLocked does, so the per-publication
// allocation delta is readable directly instead of being inferred from the
// per-call figure. Shapes are mixed because a real rulebase is not uniform.
func BenchmarkBuildMatchedConditionsRulebase(b *testing.B) {
	shapes := matchedCondShapes()
	for _, n := range []int{1000, 10000} {
		rules := make([]PolicyRule, n)
		for i := range rules {
			rules[i] = shapes[i%len(shapes)].rule
			rules[i].Name = fmt.Sprintf("rule-%d", i)
		}
		b.Run(fmt.Sprintf("rules=%d/current", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				for j := range rules {
					sinkMatchedConds = buildMatchedConditions(&rules[j])
				}
			}
		})
		b.Run(fmt.Sprintf("rules=%d/legacy", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				for j := range rules {
					sinkMatchedConds = buildMatchedConditionsLegacy(&rules[j])
				}
			}
		})
	}
}
