package hostutil

import (
	"strings"
	"testing"
)

// referenceMatchFQDNNorm is the VERBATIM pre-optimization body of
// MatchFQDNNorm. It is the oracle for the differential test and the fuzz
// target below, and the baseline the benchmarks measure against, so the
// before/after table in hostutil.go is reproducible from this one file
// without checking out the parent commit.
//
// Do not "tidy" it. Its value is that it is the old code, character for
// character.
func referenceMatchFQDNNorm(pattern, host string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // .example.com
		return strings.HasSuffix(host, suffix) || host == pattern[2:]
	}
	return host == pattern || strings.HasSuffix(host, "."+pattern)
}

// benchFQDNPatterns are bare-domain rule patterns at three lengths straddling
// the 32-byte stack buffer the compiler gives a non-escaping concatenation.
// The lengths are the point, not the names: below the buffer the old body
// copied, above it the old body reached the heap once per rule per request.
var benchFQDNPatterns = []struct {
	name    string
	pattern string
}{
	// 26 bytes — fits the stack buffer, so the old body never allocated here.
	// Kept because it proves the win is not merely "we stopped allocating".
	{"Short26", "no-match-42.example.invalid"},
	// 37 bytes — the ordinary shape of a bare-domain rule for a regional cloud
	// or CDN endpoint. Past the buffer: one heap allocation per evaluation.
	{"Long37", "assets.cdn.example-corporation.invalid"},
	// 54 bytes — a long internal name. Same posture, larger allocation.
	{"Long54", "eu-west-1.assets.cdn.example-corporation.invalid.example"},
}

// benchFQDNHost is the destination under evaluation. It deliberately matches
// NOTHING in benchFQDNPatterns: a hit is terminal and rare, a MISS is what
// every allowed request pays on every rule ahead of the one that matches.
const benchFQDNHost = "very-long-subdomain.assets.cdn.example-corporation.com"

var benchFQDNSink bool

// benchScanRuleCounts are the rulebase sizes the e2e proxy benchmark already
// uses (proxy_e2e_perfqual_test.go), so the two are directly comparable.
// rules=1 isolates the per-call cost; rules=100 is the per-request cost of a
// realistic policy.
var benchScanRuleCounts = []int{1, 100}

func benchScan(b *testing.B, match func(string, string) bool, pattern string, rules int) {
	b.Helper()
	pats := make([]string, rules)
	for i := range pats {
		pats[i] = pattern
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, p := range pats {
			benchFQDNSink = match(p, benchFQDNHost)
		}
	}
}

// BenchmarkMatchFQDNNorm_RuleScan measures the shipped body over a rulebase
// that misses — the policy engine's per-request destination scan.
func BenchmarkMatchFQDNNorm_RuleScan(b *testing.B) {
	for _, p := range benchFQDNPatterns {
		for _, n := range benchScanRuleCounts {
			b.Run(benchScanName(p.name, n), func(b *testing.B) {
				benchScan(b, MatchFQDNNorm, p.pattern, n)
			})
		}
	}
}

// BenchmarkMatchFQDNNorm_RuleScanBaseline measures the PRE-fix body on the
// identical inputs in the identical binary, so benchstat over this one file
// gives the honest before/after.
func BenchmarkMatchFQDNNorm_RuleScanBaseline(b *testing.B) {
	for _, p := range benchFQDNPatterns {
		for _, n := range benchScanRuleCounts {
			b.Run(benchScanName(p.name, n), func(b *testing.B) {
				benchScan(b, referenceMatchFQDNNorm, p.pattern, n)
			})
		}
	}
}

// BenchmarkMatchFQDNNorm_WildcardScan pins the "*." branch, which this change
// deliberately did not touch. It exists so a future edit that "unifies" the
// two branches has to show it did not regress this one.
func BenchmarkMatchFQDNNorm_WildcardScan(b *testing.B) {
	benchScan(b, MatchFQDNNorm, "*.assets.cdn.example-corporation.invalid", 100)
}

func benchScanName(shape string, rules int) string {
	switch rules {
	case 1:
		return shape + "/rules=1"
	case 100:
		return shape + "/rules=100"
	default:
		return shape
	}
}

// ── Correctness gates ────────────────────────────────────────────────────────

// fqdnDivergenceShapes are hand-picked pattern/host pairs chosen for the
// boundaries the index form has to get right, not for coverage of ordinary
// traffic: empty strings, a lone dot, a pattern longer than the host, equal
// lengths that are not equal values, a host that merely ENDS in the pattern
// without a label boundary ("notexample.com" vs "example.com" — the
// substring-vs-subdomain confusion this rewrite could plausibly introduce),
// and trailing dots.
var fqdnDivergenceShapes = struct {
	patterns []string
	hosts    []string
}{
	patterns: []string{
		"*", "*.", "*.example.com", "*.com", "*.a",
		"example.com", "com", "", ".", "..", "a", "a.b",
		"www.example.com", "notexample.com",
		"very-long-subdomain.assets.cdn.example-corporation.com",
	},
	hosts: []string{
		"", ".", "..", "a", "a.", "com", ".com", "example.com", ".example.com",
		"www.example.com", "x.www.example.com", "notexample.com",
		"xexample.com", "example.com.", "a.b", "sub.a.b",
		"very-long-subdomain.assets.cdn.example-corporation.com",
	},
}

// TestMatchFQDNNorm_MatchesPreOptimizationBehaviour is the correctness spine:
// the shipped body must agree with the verbatim pre-fix body on every shape.
// A behaviour change here is a POLICY change (a rule that stops matching, or
// starts matching a host it should not), which is why this is a differential
// test against the old code rather than a table of expected verdicts.
func TestMatchFQDNNorm_MatchesPreOptimizationBehaviour(t *testing.T) {
	for _, p := range fqdnDivergenceShapes.patterns {
		for _, h := range fqdnDivergenceShapes.hosts {
			want := referenceMatchFQDNNorm(p, h)
			if got := MatchFQDNNorm(p, h); got != want {
				t.Errorf("MatchFQDNNorm(%q, %q) = %v, pre-optimization body returned %v", p, h, got, want)
			}
		}
	}
}

// TestMatchFQDNNorm_SubdomainSemanticsUnchanged states the product rule the
// differential test protects, in its own words, so the intent survives even if
// the reference body is ever removed: a bare domain covers itself and its
// subdomains, and NOTHING else — in particular not a host that merely ends
// with the pattern's bytes across a label boundary.
func TestMatchFQDNNorm_SubdomainSemanticsUnchanged(t *testing.T) {
	for _, tc := range []struct {
		pattern, host string
		want          bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "www.example.com", true},
		{"example.com", "deep.sub.example.com", true},
		{"example.com", "notexample.com", false}, // no label boundary
		{"example.com", "xexample.com", false},   // no label boundary
		{"example.com", "example.com.evil.test", false},
		{"example.com", "com", false}, // pattern longer than host
		{"*.example.com", "www.example.com", true},
		{"*.example.com", "example.com", true}, // bare apex, documented
		{"*.example.com", "notexample.com", false},
		{"*", "anything.test", true},
	} {
		if got := MatchFQDNNorm(tc.pattern, tc.host); got != tc.want {
			t.Errorf("MatchFQDNNorm(%q, %q) = %v, want %v", tc.pattern, tc.host, got, tc.want)
		}
	}
}

// FuzzMatchFQDNNorm is the open-ended half of the differential: it hunts for a
// pattern/host pair on which the index form and the concatenating form
// disagree. Seeded with the label-boundary shapes a random generator is
// unlikely to reach on its own.
func FuzzMatchFQDNNorm(f *testing.F) {
	for _, p := range fqdnDivergenceShapes.patterns {
		for _, h := range fqdnDivergenceShapes.hosts {
			f.Add(p, h)
		}
	}
	f.Fuzz(func(t *testing.T, pattern, host string) {
		if got, want := MatchFQDNNorm(pattern, host), referenceMatchFQDNNorm(pattern, host); got != want {
			t.Fatalf("MatchFQDNNorm(%q, %q) = %v, pre-optimization body returned %v", pattern, host, got, want)
		}
	})
}

// ── Regression gate ──────────────────────────────────────────────────────────

// TestMatchFQDNNorm_AllocRegression is the hard, hardware-independent gate.
// ns/op varies with the runner; allocations do not. There is no pattern length
// at which a destination match should reach the heap — the whole point of the
// index form is that the answer is decided without building a key — so the
// bound is ZERO, at every shape, including the lengths at which the old body
// allocated once per rule.
//
// Reintroducing "."+pattern (or any other throwaway key) fails this
// immediately at the Long37/Long54 shapes.
func TestMatchFQDNNorm_AllocRegression(t *testing.T) {
	for _, p := range benchFQDNPatterns {
		pattern := p.pattern
		got := testing.AllocsPerRun(200, func() {
			benchFQDNSink = MatchFQDNNorm(pattern, benchFQDNHost)
		})
		if got != 0 {
			t.Errorf("MatchFQDNNorm(%s, %d-byte pattern): %.1f allocs/op, want 0", p.name, len(pattern), got)
		}
	}
	// The wildcard branch was already allocation-free; pin it so a future
	// unification of the two branches cannot regress it silently.
	got := testing.AllocsPerRun(200, func() {
		benchFQDNSink = MatchFQDNNorm("*.assets.cdn.example-corporation.invalid", benchFQDNHost)
	})
	if got != 0 {
		t.Errorf("MatchFQDNNorm(wildcard): %.1f allocs/op, want 0", got)
	}
}

// TestMatchFQDNNorm_BaselineAllocatedAtLongPatterns proves the finding this
// change closes is REAL rather than theoretical, by measuring the pre-fix body
// in this same binary: it must allocate at a pattern past the compiler's
// 32-byte stack buffer and not below it. If a toolchain change ever makes the
// old body allocation-free, this test fails and the justification above needs
// re-measuring rather than quietly becoming folklore.
func TestMatchFQDNNorm_BaselineAllocatedAtLongPatterns(t *testing.T) {
	short := testing.AllocsPerRun(200, func() {
		benchFQDNSink = referenceMatchFQDNNorm("no-match-42.example.invalid", benchFQDNHost)
	})
	if short != 0 {
		t.Logf("note: pre-fix body allocated %.1f/op even at 26 bytes on this toolchain", short)
	}
	long := testing.AllocsPerRun(200, func() {
		benchFQDNSink = referenceMatchFQDNNorm("eu-west-1.assets.cdn.example-corporation.invalid.example", benchFQDNHost)
	})
	if long == 0 {
		t.Errorf("pre-fix body allocated %.1f/op at a 54-byte pattern; the measured before/after "+
			"table in hostutil.go assumes it allocated once per evaluation — re-measure before trusting it", long)
	}
}
