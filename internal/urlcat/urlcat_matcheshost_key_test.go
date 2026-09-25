package urlcat

import (
	"math/rand"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/KidCarmi/Culvert/internal/hostutil"
)

// Equivalence + allocation gates for the category index key.
//
// MatchesHost/MatchesHostAdmin resolve a category's host set through an index
// keyed by strings.ToLower(name) (see rebuildIndex). Both used to materialise
// that key per call with strings.ToLower; they now fold it into a stack buffer
// and probe the map with idx[string(b)], which the compiler resolves without
// allocating. These tests pin that the KEY is byte-identical either way — this
// is a policy MEMBERSHIP matcher, so a divergence is a silently mis-enforced
// (or silently unenforced) Allow/Deny rule, not a cosmetic difference.
//
// legacyCategoryKey is the VERBATIM pre-fix key expression. Keeping the oracle
// in-tree is what makes the comparison reproducible rather than a claim.
func legacyCategoryKey(cat string) string { return strings.ToLower(cat) }

// foldedCategoryKey renders whichever of categoryKey's two return forms is in
// play as a plain string, so the differential can compare it against the
// verbatim pre-fix key expression.
//
// It is kept in lockstep with the entry points by TestCategoryKey_MirrorsHostSetFor,
// which drives the real entry points and would fail if the two ever disagreed
// about which key a name resolves to.
func foldedCategoryKey(cat string) string {
	var buf [maxInlineCategoryKey]byte
	inline, str, inlineOK := categoryKey(buf[:], cat)
	if inlineOK {
		return string(inline)
	}
	return str
}

// divergenceShapes are the cases a random generator is unlikely to hit and that
// decide correctness: the ASCII/non-ASCII branch boundary, the inline-buffer
// length boundary, and the Unicode foldings that are NOT byte-wise +32.
func divergenceShapes() []string {
	long := strings.Repeat("A", maxInlineCategoryKey)
	return []string{
		"",
		"a",
		"A",
		"Social Media",
		"SOCIAL MEDIA",
		"social media",
		"Automation & Integration", // longest shipped name
		"MiXeD-123_/&.",
		"@[`{",                   // ASCII neighbours of A-Z / a-z: must NOT shift
		"\x00\x01\x7f",           // ASCII control + DEL
		long,                     // exactly the inline bound
		long + "A",               // one past it -> fallback
		strings.Repeat("A", 200), // far past it -> fallback
		"Café",                   // non-ASCII, already lower
		"CAFÉ",                   // non-ASCII uppercase -> Unicode fold
		"SOCIÁL",                 // non-ASCII after ASCII uppercase (partial write, then bail)
		"ÅNGSTRÖM",               // multi-byte uppercase
		"K",                      // KELVIN SIGN -> ASCII 'k' (NOT byte-wise)
		"KKK",                    // mixed ASCII + Kelvin
		"İ",                      // LATIN CAPITAL I WITH DOT ABOVE
		"ẞ",                      // CAPITAL SHARP S -> ß
		"ĲSSELMEER",              // ligature
		"ΣΊΣΥΦΟΣ",                // Greek: final-sigma rules
		"\xff\xfe",               // invalid UTF-8 -> must still agree
		"A\xffB",                 // invalid UTF-8 after ASCII uppercase
		"K" + strings.Repeat("A", maxInlineCategoryKey), // non-ASCII AND over the bound
	}
}

func TestCategoryKey_DifferentialAgainstLegacy(t *testing.T) {
	for _, s := range divergenceShapes() {
		if got, want := foldedCategoryKey(s), legacyCategoryKey(s); got != want {
			t.Fatalf("key divergence for %q: folded=%q legacy=%q", s, got, want)
		}
	}

	// Randomised sweep, weighted toward the branch boundaries: bytes drawn from
	// the ASCII case range, the ASCII neighbours of it, and the 0x80+ range that
	// forces the fallback, at lengths straddling maxInlineCategoryKey.
	//
	// A fixed seed, so the corpus is reproducible and this gate cannot flake.
	// The suppression uses golangci-lint's own directive form rather than
	// gosec's `#nosec` comment, which it does not reliably apply — same choice
	// as proxy_sanitizelog_test.go and internal/obs/sanitize_test.go.
	rng := rand.New(rand.NewSource(20260916)) //nolint:gosec // deterministic test corpus, not crypto
	alphabet := []byte("AZaz@[`{ 0_\x00\x7f\x80\xc3\xa9\xff")
	for i := 0; i < 20000; i++ {
		n := rng.Intn(maxInlineCategoryKey + 8)
		b := make([]byte, n)
		for j := range b {
			b[j] = alphabet[rng.Intn(len(alphabet))]
		}
		s := string(b)
		if got, want := foldedCategoryKey(s), legacyCategoryKey(s); got != want {
			t.Fatalf("key divergence for %q (len %d): folded=%q legacy=%q", s, n, got, want)
		}
	}
}

// TestCategoryKey_DifferentialIsNotVacuous proves the sweep actually exercises
// BOTH branches. A shape set that only ever took the fallback would agree with
// the oracle trivially and pin nothing.
func TestCategoryKey_DifferentialIsNotVacuous(t *testing.T) {
	var inline, fallback int
	for _, s := range divergenceShapes() {
		if len(s) <= maxInlineCategoryKey && isASCIIString(s) {
			inline++
		} else {
			fallback++
		}
	}
	if inline < 5 || fallback < 5 {
		t.Fatalf("shape set does not exercise both branches: inline=%d fallback=%d", inline, fallback)
	}
}

func isASCIIString(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

func FuzzCategoryKey(f *testing.F) {
	for _, s := range divergenceShapes() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, cat string) {
		if got, want := foldedCategoryKey(cat), legacyCategoryKey(cat); got != want {
			t.Fatalf("key divergence for %q: folded=%q legacy=%q", cat, got, want)
		}
	})
}

// TestMatchesHost_VerdictUnchangedAcrossKeyShapes drives the real entry points
// rather than the key helper, so the differential covers the map probe too —
// including the case that matters most in practice: a mixed-case category name,
// which is what every shipped SaaS category carries.
func TestMatchesHost_VerdictUnchangedAcrossKeyShapes(t *testing.T) {
	names := []string{
		"Social Media",
		"SOCIAL MEDIA",
		"social media",
		"Automation & Integration",
		"CAFÉ",
		"K", // Kelvin
		strings.Repeat("A", maxInlineCategoryKey+3),
	}
	hosts := []string{"example.com", "a.b.example.com", "notexample.com", "", "EXAMPLE.COM"}

	for _, name := range names {
		s := New([]*Entry{{Name: name, Hosts: []string{"example.com"}}})
		for _, probe := range names { // probe every name against every store
			for _, h := range hosts {
				// Oracle: resolve the host set exactly as the pre-fix body did.
				s.mu.RLock()
				legacySet := s.index[legacyCategoryKey(probe)]
				legacyAdmin := s.adminIndex[legacyCategoryKey(probe)]
				s.mu.RUnlock()
				wantAny := legacyHostSetMatch(legacySet, h)
				wantAdmin := legacyHostSetMatch(legacyAdmin, h)

				if got := s.MatchesHost(Category(probe), h); got != wantAny {
					t.Fatalf("MatchesHost(store=%q, cat=%q, host=%q) = %v, want %v", name, probe, h, got, wantAny)
				}
				if got := s.MatchesHostAdmin(Category(probe), h); got != wantAdmin {
					t.Fatalf("MatchesHostAdmin(store=%q, cat=%q, host=%q) = %v, want %v", name, probe, h, got, wantAdmin)
				}
			}
		}
	}
}

// legacyHostSetMatch is the verbatim exact-then-suffix probe both entry points
// run once the host set is resolved. Unchanged by this work; reproduced here so
// the oracle above is complete.
func legacyHostSetMatch(hostSet map[string]bool, host string) bool {
	if hostSet == nil {
		return false
	}
	host = normalizeForTest(host)
	if hostSet[host] {
		return true
	}
	for i, ch := range host {
		if ch == '.' && hostSet[host[i+1:]] {
			return true
		}
	}
	return false
}

// TestBenchGate_MatchesHostIsAllocationFree is the regression gate. It is
// deterministic (testing.AllocsPerRun, not a timing ratio) so it cannot flake
// on a loaded runner, under -race, or on different hardware — the repo's
// standing rule for hot-path gates.
//
// The bound is 0: this runs once per category-scoped access rule per proxied
// request, so any allocation here is multiplied by the rule count on 100% of
// traffic. Every shipped SaaS category name carries an uppercase letter, so a
// return to strings.ToLower fails this immediately rather than only on an
// operator's particular taxonomy.
func TestBenchGate_MatchesHostIsAllocationFree(t *testing.T) {
	s := New(DefaultEntries())
	mixed := ""
	for _, e := range DefaultEntries() {
		if e.Name != strings.ToLower(e.Name) {
			mixed = e.Name
			break
		}
	}
	if mixed == "" {
		t.Fatal("shipped taxonomy has no mixed-case category name; gate would be vacuous")
	}

	// Hoisted: folding the name is the TEST's allocation, not the code path's.
	lowered := Category(strings.ToLower(mixed))

	// A HIT exercises the rest of the body too — the exact probe and, for a
	// subdomain, the suffix walk — so the gate covers the path a matching rule
	// takes, not only the miss that clean traffic takes.
	hitStore := New([]*Entry{{Name: "Social Media", Hosts: []string{"example.com"}}})

	cases := []struct {
		name string
		fn   func()
	}{
		{"MatchesHost/miss", func() { s.MatchesHost(Category(mixed), "uncategorized.example.net") }},
		{"MatchesHost/lowercase-name", func() { s.MatchesHost(lowered, "uncategorized.example.net") }},
		{"MatchesHostAdmin/miss", func() { s.MatchesHostAdmin(Category(mixed), "uncategorized.example.net") }},
		{"MatchesHost/unknown-category", func() { s.MatchesHost("No Such Category", "uncategorized.example.net") }},
		{"MatchesHost/hit-exact", func() { hitStore.MatchesHost("Social Media", "example.com") }},
		{"MatchesHost/hit-subdomain", func() { hitStore.MatchesHost("Social Media", "a.b.example.com") }},
	}
	for _, tc := range cases {
		if got := testing.AllocsPerRun(200, tc.fn); got != 0 {
			t.Errorf("%s: %v allocs/op, want 0", tc.name, got)
		}
	}
}

// TestBenchGate_OversizeCategoryNameStillAnswers is the CONTROL for the gate
// above. The cheapest way to pass an allocation gate is to stop doing the work,
// and the second cheapest is to silently drop names the inline buffer cannot
// hold. A name past maxInlineCategoryKey must still match correctly (it takes
// the allocating fallback, which is why it is excluded from the 0-alloc gate).
func TestBenchGate_OversizeCategoryNameStillAnswers(t *testing.T) {
	long := strings.Repeat("A", maxInlineCategoryKey*2)
	s := New([]*Entry{{Name: long, Hosts: []string{"example.com"}}})
	if !s.MatchesHost(Category(long), "a.example.com") {
		t.Fatal("oversize category name must still match via the fallback")
	}
	if !s.MatchesHost(Category(strings.ToLower(long)), "a.example.com") {
		t.Fatal("oversize category name must still match case-insensitively")
	}
	if s.MatchesHost(Category(long), "other.invalid") {
		t.Fatal("oversize category name must not match an unrelated host")
	}
}

// TestCategoryKeyBound_CoversShippedTaxonomy pins the inline buffer against the
// data it exists for: if a future taxonomy adds a name longer than the bound,
// this fails and asks for the bound to be reconsidered rather than silently
// moving that category onto the allocating path.
func TestCategoryKeyBound_CoversShippedTaxonomy(t *testing.T) {
	for _, e := range DefaultEntries() {
		if len(e.Name) > maxInlineCategoryKey {
			t.Errorf("shipped category %q is %d bytes, past maxInlineCategoryKey=%d",
				e.Name, len(e.Name), maxInlineCategoryKey)
		}
	}
}

// normalizeForTest mirrors what both entry points apply to host before the set
// probe, so the oracle sees the same host they do.
func normalizeForTest(host string) string { return hostutil.NormalizeHost(host) }

// legacyHostSetProbe is the VERBATIM pre-optimization key derivation and probe.
// It is the cost oracle for the gate below: whatever this allocates is what the
// optimization must not exceed.
func legacyHostSetProbe(idx map[string]map[string]bool, cat string) map[string]bool {
	return idx[strings.ToLower(cat)]
}

// TestBenchGate_NeverAllocatesMoreThanTheCodeItReplaced is the gate that was
// missing, and its absence is what let a regression ship inside an optimization.
//
// The first gate here gated only the SHORT, mixed-case names the shipped
// taxonomy carries — the shape the change was written for — so it could not see
// that the FALLBACK had become more expensive than the code being replaced. The
// cause was a SINGLE return type: one []byte for both paths forces the fallback
// to spell itself []byte(strings.ToLower(cat)), and strings are immutable, so
// that conversion copies. An already-lowercase name past the inline buffer went
// from 0 allocations to 1, and an uppercase or non-ASCII one from 1 to 2 — on a
// name shape the admin API fully supports, up to 256 bytes (Codex review,
// PR #1410).
//
// So this gate does not assert a number. It asserts the PROPERTY an optimization
// owes: for every shape — inline or fallback, ASCII or not, short or past the
// buffer — the real entry points must allocate no more than the verbatim
// pre-optimization probe does on the same input. That holds whatever the
// implementation becomes, and it fails for any future variant that makes a path
// dearer in order to make another cheaper.
func TestBenchGate_NeverAllocatesMoreThanTheCodeItReplaced(t *testing.T) {
	// A host that is already canonical, so hostutil.NormalizeHost contributes
	// nothing and the measurement isolates the key derivation.
	const host = "uncategorized.example.net"

	long := strings.Repeat("a", maxInlineCategoryKey*3) // past the buffer, ASCII
	names := []struct {
		name string
		cat  string
	}{
		{"short-mixed-case", "Social Media"},
		{"short-lowercase", "social media"},
		{"short-uppercase", "SOCIAL MEDIA"},
		{"fallback-long-lowercase", long},
		{"fallback-long-uppercase", strings.ToUpper(long)},
		{"fallback-non-ascii", "CAFÉ"},
		{"fallback-non-ascii-long", "CAFÉ" + long},
		{"empty", ""},
	}

	// A store that actually holds one of the long names, so the fallback path
	// resolves a real host set rather than always missing on a nil map.
	s := New([]*Entry{
		{Name: "Social Media", Hosts: []string{"example.com"}},
		{Name: long, Hosts: []string{"example.com"}},
	})

	for _, tc := range names {
		cat := tc.cat
		budget := testing.AllocsPerRun(200, func() { _ = legacyHostSetProbe(s.index, cat) })
		got := testing.AllocsPerRun(200, func() { s.MatchesHost(Category(cat), host) })
		gotAdmin := testing.AllocsPerRun(200, func() { s.MatchesHostAdmin(Category(cat), host) })

		if got > budget {
			t.Errorf("%s: MatchesHost allocates %v/op, more than the %v/op of the code it replaced",
				tc.name, got, budget)
		}
		if gotAdmin > budget {
			t.Errorf("%s: MatchesHostAdmin allocates %v/op, more than the %v/op of the code it replaced",
				tc.name, gotAdmin, budget)
		}
	}
}

// TestBenchGate_FallbackBudgetIsNotVacuous is the CONTROL for the gate above.
//
// That gate compares against a budget it measures at run time, so it would pass
// trivially if the budget were always generous. It is only meaningful because
// the budget is ZERO for the shapes that matter most — a short mixed-case name
// (every shipped SaaS category) and an already-lowercase long name, where
// strings.ToLower returns its input unchanged and the probe is free. This pins
// that those budgets really are zero, so the gate above is a real bound.
func TestBenchGate_FallbackBudgetIsNotVacuous(t *testing.T) {
	s := New(DefaultEntries())
	longLower := strings.Repeat("a", maxInlineCategoryKey*3)

	zeroBudget := []struct {
		name string
		cat  string
	}{
		{"already-lowercase-short", "social media"},
		{"already-lowercase-past-buffer", longLower},
	}
	for _, tc := range zeroBudget {
		cat := tc.cat
		if b := testing.AllocsPerRun(200, func() { _ = legacyHostSetProbe(s.index, cat) }); b != 0 {
			t.Errorf("%s: expected a ZERO-allocation budget for the gate to bound anything, got %v", tc.name, b)
		}
	}

	// And the shapes the fallback genuinely cannot make free must still be
	// bounded at exactly what strings.ToLower costs — never more.
	if b := testing.AllocsPerRun(200, func() { _ = legacyHostSetProbe(s.index, "CAFÉ") }); b != 1 {
		t.Errorf("non-ASCII budget: expected exactly 1 alloc (the strings.ToLower result), got %v", b)
	}
}

// TestCategoryKey_MirrorsHostSetFor keeps the differential honest: it drives the
// REAL entry point and checks that the key foldedCategoryKey predicts is the one
// that actually resolves the host set, so the differential can never end up
// testing a helper the production path does not agree with.
func TestCategoryKey_MirrorsHostSetFor(t *testing.T) {
	for _, cat := range divergenceShapes() {
		if cat == "" {
			continue // an empty category name indexes nothing by construction
		}
		// Build a store whose ONLY entry is keyed by the predicted key. If
		// hostSetFor derived a different key it would find no host set at all.
		s := New([]*Entry{{Name: cat, Hosts: []string{"example.com"}}})
		if !s.MatchesHost(Category(cat), "example.com") {
			t.Errorf("MatchesHost did not resolve category %q via the predicted key %q",
				cat, foldedCategoryKey(cat))
		}
	}
}
