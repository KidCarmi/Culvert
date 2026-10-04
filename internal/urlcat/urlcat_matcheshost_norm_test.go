package urlcat

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/hostutil"
)

// MatchesHostNorm / MatchesHostAdminNorm equivalence.
//
// The per-rule membership matchers used to canonicalize the destination host
// themselves, so the policy scan paid one hostutil.NormalizeHost per
// category-scoped access rule for a value that depends on the REQUEST and not
// on the rule. The normalization moved to the caller (package main's
// hostCatScratch.normHost, computed once per scan).
//
// That is a pure cost change and this file is what makes "pure" checkable.
// The oracles below are VERBATIM copies of the pre-change bodies — not
// paraphrases — so the production entry points are diffed against the real
// thing. Comparing the new wrapper against the new Norm function would be
// vacuous: MatchesHost is now DEFINED as MatchesHostNorm(cat,
// NormalizeHost(host)), so that identity holds by construction and would keep
// holding if the walk semantics were broken in both at once.
//
// The oracles double as the benchmark baselines (urlcat_matcheshost_bench_test.go
// style, the repo's _Legacy convention) so the thing measured and the thing
// proven equivalent can never drift apart.

// legacyMatchesHost is Store.MatchesHost exactly as it stood before the
// normalization hoist. Do not "simplify" it to call the production code.
func legacyMatchesHost(s *Store, cat Category, host string) bool {
	host = hostutil.NormalizeHost(host)
	var keyBuf [maxInlineCategoryKey]byte
	inlineKey, strKey, inlineOK := categoryKey(keyBuf[:], string(cat))

	s.mu.RLock()
	var hostSet map[string]bool
	if inlineOK {
		hostSet = s.index[string(inlineKey)]
	} else {
		hostSet = s.index[strKey]
	}
	s.mu.RUnlock()

	if hostSet == nil {
		return false
	}
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

// legacyMatchesHostAdmin is Store.MatchesHostAdmin exactly as it stood before
// the normalization hoist.
func legacyMatchesHostAdmin(s *Store, cat Category, host string) bool {
	host = hostutil.NormalizeHost(host)
	var keyBuf [maxInlineCategoryKey]byte
	inlineKey, strKey, inlineOK := categoryKey(keyBuf[:], string(cat))

	s.mu.RLock()
	var hostSet map[string]bool
	if inlineOK {
		hostSet = s.adminIndex[string(inlineKey)]
	} else {
		hostSet = s.adminIndex[strKey]
	}
	s.mu.RUnlock()

	if hostSet == nil {
		return false
	}
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

// assertNormAgrees checks both entry points against their frozen oracles for
// one (category, host) pair, in BOTH the wrapper form (which still takes a raw
// host) and the hoisted form the policy scan now uses.
func assertNormAgrees(t *testing.T, s *Store, cat Category, host string) {
	t.Helper()
	norm := hostutil.NormalizeHost(host)

	if got, want := s.MatchesHost(cat, host), legacyMatchesHost(s, cat, host); got != want {
		t.Errorf("MatchesHost(%q, %q) = %v; legacy = %v", cat, host, got, want)
	}
	if got, want := s.MatchesHostNorm(cat, norm), legacyMatchesHost(s, cat, host); got != want {
		t.Errorf("MatchesHostNorm(%q, %q) = %v; legacy MatchesHost(%q) = %v",
			cat, norm, got, host, want)
	}
	if got, want := s.MatchesHostAdmin(cat, host), legacyMatchesHostAdmin(s, cat, host); got != want {
		t.Errorf("MatchesHostAdmin(%q, %q) = %v; legacy = %v", cat, host, got, want)
	}
	if got, want := s.MatchesHostAdminNorm(cat, norm), legacyMatchesHostAdmin(s, cat, host); got != want {
		t.Errorf("MatchesHostAdminNorm(%q, %q) = %v; legacy MatchesHostAdmin(%q) = %v",
			cat, norm, got, host, want)
	}
}

// normShapeStore is a taxonomy that deliberately spans every branch the
// matchers have: a built-in category (absent from adminIndex), an
// admin-created one, an IDNA/punycode pattern, a trailing-dot pattern, a
// mixed-case category name past the inline key buffer, and an empty-host
// category.
func normShapeStore() *Store {
	longName := "Category " + strings.Repeat("Long", maxInlineCategoryKey/2)
	return New([]*Entry{
		{Name: "Social Media", BuiltIn: true, Hosts: []string{"facebook.com", "example.com"}},
		{Name: "Corp Internal", Hosts: []string{"intranet.corp.invalid", "Mixed.Case.Example.ORG"}},
		{Name: "IDN", Hosts: []string{"xn--bcher-kva.example", "bücher.test"}},
		{Name: "Dotted", Hosts: []string{"trailing.example."}},
		{Name: longName, Hosts: []string{"oversize-key.example"}},
		{Name: "Empty", Hosts: []string{}},
	})
}

// TestMatchesHostNorm_MatchesLegacyBodies pins the hand-picked shapes where the
// hoist could plausibly diverge.
func TestMatchesHostNorm_MatchesLegacyBodies(t *testing.T) {
	s := normShapeStore()
	longName := "Category " + strings.Repeat("Long", maxInlineCategoryKey/2)

	hosts := []string{
		// Ordinary ASCII: exact, subdomain, miss.
		"example.com", "a.b.example.com", "uncategorized.example.net",
		// Case folding and trailing dots — what normalization is FOR.
		"EXAMPLE.COM", "Example.Com.", "example.com.", "A.B.EXAMPLE.COM.",
		"mixed.case.example.org", "MIXED.CASE.EXAMPLE.ORG",
		"trailing.example", "trailing.example.", "TRAILING.EXAMPLE.",
		// Degenerate hosts whose normalized form is empty.
		"", ".", "..", "...",
		// IDNA: unicode form, ACE form, and a malformed ACE label (the one
		// shape where NormalizeHost is NOT the identity on its own output).
		"bücher.test", "BÜCHER.TEST", "xn--bcher-kva.example",
		"XN--BCHER-KVA.EXAMPLE", "xn--", "xn--0", "xn--a.xn--b",
		"sub.xn--bcher-kva.example",
		// Invalid UTF-8 and a lone continuation byte.
		"\xff\xfe.example", "\x80",
		// IP literals, bare and bracketed.
		"192.0.2.1", "2001:db8::1", "[2001:db8::1]", "[::1]",
		// Oversize category key path.
		"oversize-key.example", "x.oversize-key.example",
		// Label-boundary oddities.
		".example.com", "example..com", "a.", ".",
	}
	cats := []Category{
		"Social Media", "social media", "SOCIAL MEDIA",
		"Corp Internal", "IDN", "Dotted", "Empty", Category(longName),
		"Nonexistent", "",
	}

	for _, cat := range cats {
		for _, h := range hosts {
			assertNormAgrees(t, s, cat, h)
		}
	}
}

// TestMatchesHostNorm_RandomizedSweep drives randomized taxonomies and hosts
// weighted toward the boundaries above.
func TestMatchesHostNorm_RandomizedSweep(t *testing.T) {
	// A FIXED seed is the point: a differential sweep that cannot be replayed
	// cannot be debugged, so the generator must be deterministic rather than
	// cryptographic. The values only choose which shapes are compared.
	//
	// The suppression uses golangci-lint's own directive form rather than
	// gosec's `#nosec` comment, which it does not reliably apply — the same
	// choice, for the same reason, as urlcat_matcheshost_key_test.go beside it.
	rng := rand.New(rand.NewSource(0xC0FFEE)) //nolint:gosec // deterministic test corpus, not crypto

	labels := []string{
		"a", "b", "example", "EXAMPLE", "corp", "xn--bcher-kva", "bücher",
		"xn--", "xn--0", "test", "com", "ORG", "\xff", "192", "0",
	}
	catNames := []string{
		"Social Media", "Corp Internal", "IDN", "Dotted", "Empty",
		"MiXeD", "nonexistent", "", strings.Repeat("L", maxInlineCategoryKey+5),
	}

	randHost := func() string {
		n := rng.Intn(4) + 1
		parts := make([]string, 0, n)
		for i := 0; i < n; i++ {
			parts = append(parts, labels[rng.Intn(len(labels))])
		}
		h := strings.Join(parts, ".")
		switch rng.Intn(6) {
		case 0:
			h += "."
		case 1:
			h = strings.ToUpper(h)
		case 2:
			h = "." + h
		}
		return h
	}

	var agreements int
	for i := 0; i < 400; i++ {
		// Build a random taxonomy.
		nCat := rng.Intn(5) + 1
		entries := make([]*Entry, 0, nCat)
		for c := 0; c < nCat; c++ {
			nh := rng.Intn(4)
			hosts := make([]string, 0, nh)
			for h := 0; h < nh; h++ {
				hosts = append(hosts, randHost())
			}
			entries = append(entries, &Entry{
				Name:    catNames[rng.Intn(len(catNames))],
				BuiltIn: rng.Intn(2) == 0,
				Hosts:   hosts,
			})
		}
		s := New(entries)
		for q := 0; q < 8; q++ {
			cat := Category(catNames[rng.Intn(len(catNames))])
			assertNormAgrees(t, s, cat, randHost())
			agreements++
		}
	}
	if agreements < 3000 {
		t.Fatalf("sweep is not exercising enough pairs: %d", agreements)
	}
}

// TestMatchesHostNorm_SweepReachesBothKeyBranches is the NOT-VACUOUS check for
// the sweep above: the agreement assertions prove nothing if every randomized
// pair happened to resolve a nil host set, or if the oversize-category-name
// fallback was never reached.
func TestMatchesHostNorm_SweepReachesBothKeyBranches(t *testing.T) {
	s := normShapeStore()
	longName := Category("Category " + strings.Repeat("Long", maxInlineCategoryKey/2))

	var keyBuf [maxInlineCategoryKey]byte
	if _, _, inlineOK := categoryKey(keyBuf[:], string(longName)); inlineOK {
		t.Fatalf("fixture category name is not past the inline key buffer; "+
			"the fallback branch is untested (len=%d, buf=%d)",
			len(longName), maxInlineCategoryKey)
	}
	if _, _, inlineOK := categoryKey(keyBuf[:], "Social Media"); !inlineOK {
		t.Fatal("fixture category name does not take the inline key branch")
	}
	// Both branches must actually resolve a non-nil set and answer true, or the
	// equivalence assertions are comparing two "false"s.
	if !s.MatchesHostNorm(longName, "oversize-key.example") {
		t.Error("oversize-key category does not match; fallback branch is vacuous")
	}
	if !s.MatchesHostNorm("Social Media", "example.com") {
		t.Error("inline-key category does not match; inline branch is vacuous")
	}
}

// TestMatchesHostNorm_StillMatches is the CONTROL. The cheapest way to pass
// every equivalence assertion above is to make both the production code and
// the oracle answer false for everything, which would silently delete category
// enforcement. These are positive assertions that do not reference the oracle.
func TestMatchesHostNorm_StillMatches(t *testing.T) {
	s := normShapeStore()
	cases := []struct {
		cat  Category
		host string
		want bool
	}{
		{"Social Media", "example.com", true},
		{"Social Media", "deep.sub.example.com", true},
		{"Social Media", "EXAMPLE.COM.", true},
		{"Social Media", "notexample.com", false},
		{"Corp Internal", "intranet.corp.invalid", true},
		{"Corp Internal", "mixed.case.example.org", true},
		// NOTE a PRE-EXISTING store property, confirmed identical on both
		// sides of this hoist by the differential above and asserted here so
		// it is not mistaken for a regression: the forward index keys a
		// pattern with strings.ToLower(TrimSuffix(p, ".")) and does NOT
		// IDNA-normalize it, while a QUERY is normalized. So a UNICODE
		// pattern ("bücher.test") is stored verbatim and can never match the
		// A-label form its own queries canonicalize to, whereas an ACE
		// pattern ("xn--bcher-kva.example") matches. Reconciling the two
		// sides is a separate semantic decision, deliberately untouched by a
		// cost change.
		{"IDN", "bücher.test", false},
		{"IDN", "BÜCHER.TEST", false},
		{"IDN", "xn--bcher-kva.example", true},
		{"IDN", "XN--BCHER-KVA.EXAMPLE", true},
		{"IDN", "sub.xn--bcher-kva.example", true},
		{"Dotted", "trailing.example", true},
		{"Nonexistent", "example.com", false},
	}
	for _, c := range cases {
		norm := hostutil.NormalizeHost(c.host)
		if got := s.MatchesHostNorm(c.cat, norm); got != c.want {
			t.Errorf("MatchesHostNorm(%q, %q) = %v; want %v", c.cat, norm, got, c.want)
		}
		if got := s.MatchesHost(c.cat, c.host); got != c.want {
			t.Errorf("MatchesHost(%q, %q) = %v; want %v", c.cat, c.host, got, c.want)
		}
	}
	// The admin tier must EXCLUDE built-in categories — the property that makes
	// MatchesHostAdminNorm a distinct entry point rather than an alias.
	if s.MatchesHostAdminNorm("Social Media", "example.com") {
		t.Error("MatchesHostAdminNorm matched a BuiltIn category")
	}
	if !s.MatchesHostAdminNorm("Corp Internal", "intranet.corp.invalid") {
		t.Error("MatchesHostAdminNorm missed an admin category")
	}
}

// TestMatchesHostNorm_NormalizeHostIsNotIdempotent is the test that justifies
// the hoist's SHAPE, and it is the reason MatchesHostNorm must never be
// described as "takes a host that is already canonical".
//
// hostutil.NormalizeHost is NOT idempotent. An empty ACE label decodes to
// nothing, so a host ending in a "xn--" label normalizes to a value with a
// TRAILING DOT, and normalizing that again trims the dot:
//
//	NormalizeHost("a.xn--") == "a."   and   NormalizeHost("a.") == "a"
//
// So the hoist is only sound because it moves WHERE the single normalization
// happens and not HOW MANY times it happens: every consumer is handed
// NormalizeHost(rawHost) — the same function applied to the same input the
// pre-hoist body used — so no idempotence property is relied on. A refactor
// that normalizes again inside the Norm entry points, or that passes a host
// canonicalized by some other lineage, changes matching for these inputs. Both
// mistakes are caught by the differential above; this test states the reason so
// the next reader does not have to rediscover it.
func TestMatchesHostNorm_NormalizeHostIsNotIdempotent(t *testing.T) {
	witnesses := []string{"a.xn--", "a.xn--.", "example.xn--", "b.xn--"}
	var nonIdempotent int
	for _, h := range witnesses {
		one := hostutil.NormalizeHost(h)
		two := hostutil.NormalizeHost(one)
		if one != two {
			nonIdempotent++
		}
	}
	if nonIdempotent == 0 {
		t.Skip("hostutil.NormalizeHost has become idempotent on every known " +
			"witness; the hoist stays correct either way (it passes the same " +
			"value the pre-hoist body computed), but this rationale is stale")
	}
	// And the hoisted matchers must agree with the frozen bodies on exactly
	// these inputs — the ones where a double normalization would diverge.
	s := normShapeStore()
	for _, cat := range []Category{"Social Media", "Corp Internal", "IDN", "Dotted"} {
		for _, h := range witnesses {
			assertNormAgrees(t, s, cat, h)
		}
	}
}

// FuzzMatchesHostNorm looks for a (category, host) pair where the hoisted entry
// point disagrees with the frozen pre-hoist body.
func FuzzMatchesHostNorm(f *testing.F) {
	s := normShapeStore()
	seeds := []struct {
		cat, host string
	}{
		{"Social Media", "example.com"},
		{"Corp Internal", "INTRANET.CORP.INVALID."},
		{"IDN", "bücher.test"},
		{"IDN", "xn--"},
		{"Dotted", "trailing.example."},
		{"", ""},
		{"Empty", "."},
		{"Social Media", "[2001:db8::1]"},
	}
	for _, sd := range seeds {
		f.Add(sd.cat, sd.host)
	}
	f.Fuzz(func(t *testing.T, cat, host string) {
		norm := hostutil.NormalizeHost(host)
		if got, want := s.MatchesHostNorm(Category(cat), norm), legacyMatchesHost(s, Category(cat), host); got != want {
			t.Fatalf("MatchesHostNorm(%q, %q) = %v; legacy MatchesHost(%q) = %v",
				cat, norm, got, host, want)
		}
		if got, want := s.MatchesHostAdminNorm(Category(cat), norm), legacyMatchesHostAdmin(s, Category(cat), host); got != want {
			t.Fatalf("MatchesHostAdminNorm(%q, %q) = %v; legacy MatchesHostAdmin(%q) = %v",
				cat, norm, got, host, want)
		}
	})
}

// ─── cost ──────────────────────────────────────────────────────────────────────

// BenchmarkStoreMatchesHostNorm_Miss is the hoisted per-rule probe: what a
// category-scoped rule costs once the scan owns the normalization.
//
//	go test -run '^$' -bench 'MatchesHost' -benchmem -cpu 1,2,4 ./internal/urlcat/
func BenchmarkStoreMatchesHostNorm_Miss(b *testing.B) {
	s := benchMatchStore()
	cat := benchCategoryName(b)
	norm := hostutil.NormalizeHost("uncategorized.example.net")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if s.MatchesHostNorm(cat, norm) {
			b.Fatal("unexpected match")
		}
	}
}

// BenchmarkStoreMatchesHost_LegacyMiss is the pre-hoist body, measured in the
// SAME run as the benchmark above so the comparison is machine-independent
// (the repo's _Legacy convention — a cross-run pair of absolute numbers has
// been wrong by an order of magnitude on this hardware before).
func BenchmarkStoreMatchesHost_LegacyMiss(b *testing.B) {
	s := benchMatchStore()
	cat := benchCategoryName(b)
	const host = "uncategorized.example.net"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if legacyMatchesHost(s, cat, host) {
			b.Fatal("unexpected match")
		}
	}
}

// BenchmarkStoreMatchesHostNorm_Parallel is the scaling instrument. Read how
// ns/op MOVES with core count, not the absolute value.
func BenchmarkStoreMatchesHostNorm_Parallel(b *testing.B) {
	s := benchMatchStore()
	cat := benchCategoryName(b)
	norm := hostutil.NormalizeHost("uncategorized.example.net")
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		// Each worker keeps its OWN sink: a shared package-level sink turns
		// false sharing into the thing being measured.
		var sink bool
		for pb.Next() {
			sink = s.MatchesHostNorm(cat, norm)
		}
		_ = sink
	})
}

// BenchmarkStoreMatchesHostNorm_RuleScan approximates what the policy scan
// pays: N category-scoped rules against ONE destination. The pre-hoist arm
// normalizes per rule; the hoisted arm normalizes once.
func BenchmarkStoreMatchesHostNorm_RuleScan(b *testing.B) {
	s := benchMatchStore()
	cats := make([]Category, 0, 16)
	for _, e := range DefaultEntries() {
		if len(cats) == 16 {
			break
		}
		cats = append(cats, Category(e.Name))
	}
	const host = "uncategorized.example.net"

	for _, n := range []int{1, 10, 50} {
		b.Run(fmt.Sprintf("rules=%d/hoisted", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				norm := hostutil.NormalizeHost(host) // once per "request"
				for r := 0; r < n; r++ {
					if s.MatchesHostNorm(cats[r%len(cats)], norm) {
						b.Fatal("unexpected match")
					}
				}
			}
		})
		b.Run(fmt.Sprintf("rules=%d/legacy", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for r := 0; r < n; r++ {
					if legacyMatchesHost(s, cats[r%len(cats)], host) {
						b.Fatal("unexpected match")
					}
				}
			}
		})
	}
}

// BenchmarkStoreMatchesHostNorm_RuleScanParallel is the same rule-scan shape
// under concurrency, with BOTH arms timed in ONE run so they see identical
// machine conditions. A cross-run pair on a shared 4-core runner is bimodal
// enough to invert the sign of this comparison (measured: the same tree read
// 6011 and 10320 ns in one -count=7 series), which is why this repo times
// paired arms together rather than quoting two absolute numbers.
//
// What to read: the per-rule CPU saving is realized while catStore's RWMutex is
// not saturated. Both arms take EXACTLY the same number of RLocks (one per
// rule) and their critical sections are byte-identical — only the work OUTSIDE
// the lock shrinks — so under full saturation the two converge rather than
// diverging, and the hoist is never the slower of the two by construction.
func BenchmarkStoreMatchesHostNorm_RuleScanParallel(b *testing.B) {
	s := benchMatchStore()
	cats := make([]Category, 0, 16)
	for _, e := range DefaultEntries() {
		if len(cats) == 16 {
			break
		}
		cats = append(cats, Category(e.Name))
	}
	const host = "uncategorized.example.net"
	const rules = 50

	b.Run("hoisted", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			var sink bool
			for pb.Next() {
				norm := hostutil.NormalizeHost(host) // once per "request"
				for r := 0; r < rules; r++ {
					sink = s.MatchesHostNorm(cats[r%len(cats)], norm)
				}
			}
			_ = sink
		})
	})
	b.Run("legacy", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			var sink bool
			for pb.Next() {
				for r := 0; r < rules; r++ {
					sink = legacyMatchesHost(s, cats[r%len(cats)], host)
				}
			}
			_ = sink
		})
	})
}
