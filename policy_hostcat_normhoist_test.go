package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"math/rand"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/hostutil"
	"github.com/KidCarmi/Culvert/internal/urlcat"
)

// Destination-host normalization hoist — the package-main half.
//
// The per-RULE category membership matchers used to canonicalize the request
// host themselves, so a scan paid one hostutil.NormalizeHost per
// category-scoped access rule — and TWO per rule when the signed-feed
// effective view is armed, because catStore.MatchesHostAdmin and
// effectiveCategoryView.MatchesCategory each normalized independently. The
// normalization now happens once per scan, in hostCatScratch.normHost.
//
// Measured on the shipped taxonomy against a 3-label uncategorized
// destination: NormalizeHost was 45.97 ns of MatchesHost's 105.8 ns total
// (43%), and the DestCategory policy scan went 4675 ns → 2869 ns at 50 rules.
//
// Nothing about the DECISION may change, and these tests are what makes that
// checkable. The oracle below is a VERBATIM copy of the pre-hoist
// MatchesCategory body — comparing the new wrapper against the new Norm
// function would be vacuous, since the wrapper is now defined in terms of it.

// legacyViewMatchesCategory is effectiveCategoryView.MatchesCategory exactly as
// it stood before the normalization hoist. Do not "simplify" it to call the
// production code.
func legacyViewMatchesCategory(v *effectiveCategoryView, cat, host string) bool {
	if cat == "" {
		return false
	}
	h := hostutil.NormalizeHost(host)
	if h == "" {
		return false
	}
	for {
		for _, c := range v.members[h] {
			if strings.EqualFold(c, cat) {
				return true
			}
		}
		if v.sealed[h] {
			return false
		}
		i := strings.IndexByte(h, '.')
		if i < 0 {
			return false
		}
		h = h[i+1:]
	}
}

// normHoistView is a view spanning every branch MatchesCategory has: a
// many-to-many membership key, a sealed override boundary, an ACE key, and a
// deep subtree.
func normHoistView() *effectiveCategoryView {
	return &effectiveCategoryView{
		entries: map[string]string{
			"example.com":           "Social Media",
			"linkedin.com":          "Social Media",
			"sealed.example.com":    "Blocked",
			"xn--bcher-kva.example": "IDN",
		},
		members: map[string][]string{
			"example.com":           {"Social Media", "News"},
			"linkedin.com":          {"Social Media", "HR & Recruiting"},
			"sealed.example.com":    {"Blocked"},
			"xn--bcher-kva.example": {"IDN"},
		},
		sealed: map[string]bool{"sealed.example.com": true},
	}
}

// TestNormHoist_ViewMatchesCategoryNormMatchesLegacy pins the view matcher
// against its frozen pre-hoist body over the shapes where the hoist could
// plausibly diverge.
func TestNormHoist_ViewMatchesCategoryNormMatchesLegacy(t *testing.T) {
	v := normHoistView()
	hosts := []string{
		"example.com", "a.b.example.com", "EXAMPLE.COM", "example.com.",
		"linkedin.com", "LINKEDIN.COM.",
		// Sealed boundary: the walk must STOP, not climb to the ancestor.
		"sealed.example.com", "deep.sealed.example.com", "SEALED.EXAMPLE.COM.",
		// Degenerate hosts whose normalized form is empty.
		"", ".", "..",
		// IDNA, including the non-idempotent empty-ACE-label shape.
		"xn--bcher-kva.example", "bücher.example", "a.xn--", "xn--", "xn--0",
		// Invalid UTF-8, IP literals.
		"\xff\xfe.example", "192.0.2.1", "[2001:db8::1]",
		"uncategorized.example.net",
	}
	cats := []string{
		"Social Media", "social media", "News", "HR & Recruiting",
		"Blocked", "IDN", "Nonexistent", "",
	}
	for _, cat := range cats {
		for _, h := range hosts {
			norm := hostutil.NormalizeHost(h)
			want := legacyViewMatchesCategory(v, cat, h)
			if got := v.MatchesCategory(cat, h); got != want {
				t.Errorf("MatchesCategory(%q, %q) = %v; legacy = %v", cat, h, got, want)
			}
			if got := v.MatchesCategoryNorm(cat, norm); got != want {
				t.Errorf("MatchesCategoryNorm(%q, %q) = %v; legacy MatchesCategory(%q) = %v",
					cat, norm, got, h, want)
			}
		}
	}
}

// TestNormHoist_ViewRandomizedSweep drives randomized hosts weighted toward the
// boundaries above.
func TestNormHoist_ViewRandomizedSweep(t *testing.T) {
	v := normHoistView()
	rng := rand.New(rand.NewSource(0x5EED))
	labels := []string{"a", "example", "EXAMPLE", "com", "linkedin", "sealed",
		"xn--", "xn--0", "bücher", "xn--bcher-kva", "\xff", "net"}
	cats := []string{"Social Media", "News", "Blocked", "IDN", "HR & Recruiting", "", "zzz"}

	for i := 0; i < 4000; i++ {
		n := rng.Intn(4) + 1
		parts := make([]string, 0, n)
		for j := 0; j < n; j++ {
			parts = append(parts, labels[rng.Intn(len(labels))])
		}
		h := strings.Join(parts, ".")
		if rng.Intn(4) == 0 {
			h += "."
		}
		if rng.Intn(5) == 0 {
			h = strings.ToUpper(h)
		}
		cat := cats[rng.Intn(len(cats))]
		want := legacyViewMatchesCategory(v, cat, h)
		if got := v.MatchesCategoryNorm(cat, hostutil.NormalizeHost(h)); got != want {
			t.Fatalf("MatchesCategoryNorm(%q, %q) = %v; legacy = %v",
				cat, hostutil.NormalizeHost(h), got, want)
		}
	}
}

// TestNormHoist_ViewStillMatches is the CONTROL for the view matcher: the
// cheapest way to pass every equivalence assertion is for production and oracle
// to both answer false, which would delete the signed-feed membership tier.
func TestNormHoist_ViewStillMatches(t *testing.T) {
	v := normHoistView()
	cases := []struct {
		cat, host string
		want      bool
	}{
		{"Social Media", "example.com", true},
		{"Social Media", "a.b.example.com", true},
		{"News", "example.com", true},
		// Many-to-many membership: the SECOND category must still match, which
		// is the fail-open this matcher exists to prevent.
		{"HR & Recruiting", "linkedin.com", true},
		{"Social Media", "linkedin.com", true},
		// Sealed boundary must shadow the ancestor.
		{"Social Media", "sealed.example.com", false},
		{"Blocked", "sealed.example.com", true},
		{"Blocked", "deep.sealed.example.com", true},
		{"Nonexistent", "example.com", false},
	}
	for _, c := range cases {
		norm := hostutil.NormalizeHost(c.host)
		if got := v.MatchesCategoryNorm(c.cat, norm); got != c.want {
			t.Errorf("MatchesCategoryNorm(%q, %q) = %v; want %v", c.cat, norm, got, c.want)
		}
	}
}

// FuzzViewMatchesCategoryNorm looks for a (category, host) pair where the
// hoisted view matcher disagrees with the frozen pre-hoist body.
func FuzzViewMatchesCategoryNorm(f *testing.F) {
	v := normHoistView()
	for _, sd := range []struct{ cat, host string }{
		{"Social Media", "example.com"},
		{"Blocked", "deep.sealed.example.com"},
		{"IDN", "a.xn--"},
		{"", ""},
		{"News", "EXAMPLE.COM."},
	} {
		f.Add(sd.cat, sd.host)
	}
	f.Fuzz(func(t *testing.T, cat, host string) {
		want := legacyViewMatchesCategory(v, cat, host)
		got := v.MatchesCategoryNorm(cat, hostutil.NormalizeHost(host))
		if got != want {
			t.Fatalf("MatchesCategoryNorm(%q, %q) = %v; legacy MatchesCategory(%q) = %v",
				cat, hostutil.NormalizeHost(host), got, host, want)
		}
	})
}

// ─── the scratch memo ──────────────────────────────────────────────────────────

// TestNormHoist_ScratchNormalizesOnceAndLazily pins the two properties that
// make the memo a hoist rather than an extra cost: it is computed at most once
// per scan, and a scan that reaches no category-scoped rule never computes it.
func TestNormHoist_ScratchNormalizesOnceAndLazily(t *testing.T) {
	sc := newHostCatScratch("A.B.EXAMPLE.COM.")
	if sc.normHostSet {
		t.Fatal("a fresh scratch must not have normalized anything (the lazy contract)")
	}
	want := normalizeHost("A.B.EXAMPLE.COM.")
	if got := sc.normHost(); got != want {
		t.Fatalf("normHost() = %q; want %q", got, want)
	}
	if !sc.normHostSet {
		t.Fatal("normHost() did not record the memo")
	}
	// A second call must serve the memo. Poison the raw host: if the memo is
	// bypassed the value changes, which no amount of equality on the first call
	// could reveal.
	sc.host = "poisoned.example.invalid"
	if got := sc.normHost(); got != want {
		t.Fatalf("normHost() recomputed from the raw host: got %q, want memoized %q", got, want)
	}
}

// TestNormHoist_ScratchMemoizesTheEmptyNormalForm is the boundary the memo's
// own guard exists for: NormalizeHost(".") == "", and "" is a LEGITIMATE
// normalized result. A memo keyed on emptiness instead of its own bool would
// re-normalize on every rule for exactly these hosts — silently restoring the
// per-rule cost on the degenerate inputs an attacker can choose.
func TestNormHoist_ScratchMemoizesTheEmptyNormalForm(t *testing.T) {
	for _, raw := range []string{"", ".", "..", "..."} {
		sc := newHostCatScratch(raw)
		if got := sc.normHost(); got != normalizeHost(raw) {
			t.Fatalf("normHost(%q) = %q; want %q", raw, got, normalizeHost(raw))
		}
		if !sc.normHostSet {
			t.Errorf("normHost(%q) produced the empty string without recording the memo", raw)
		}
	}
}

// TestNormHoist_MatchesCategoryUnchangedWithoutView pins the end-to-end
// decision through the real scratch on the no-view branch (the common
// deployment), against the pre-hoist entry point.
func TestNormHoist_MatchesCategoryUnchangedWithoutView(t *testing.T) {
	prev := catStore
	catStore = urlcat.New([]*urlcat.Entry{
		{Name: "Social Media", Hosts: []string{"example.com"}},
		{Name: "Corp Internal", Hosts: []string{"intranet.corp.invalid"}},
	})
	t.Cleanup(func() { catStore = prev })

	for _, host := range []string{
		"example.com", "a.b.EXAMPLE.com.", "intranet.corp.invalid",
		"uncategorized.example.net", "a.xn--", ".", "",
	} {
		for _, cat := range []URLCategory{"Social Media", "Corp Internal", "Nope"} {
			sc := newHostCatScratch(host)
			got := sc.matchesCategory(cat)
			// The pre-hoist decision is MatchesHost over the RAW host.
			want := catStore.MatchesHost(urlcat.Category(cat), host)
			if got != want {
				t.Errorf("matchesCategory(%q) for host %q = %v; pre-hoist MatchesHost = %v",
					cat, host, got, want)
			}
		}
	}
}

// TestBenchGate_HoistedCategoryMatchIsAllocationFree is the allocation gate for
// the hoisted per-rule path, measured through the REAL scratch rather than the
// urlcat entry points in isolation.
//
// It is deterministic (testing.AllocsPerRun, not a timing ratio) so it cannot
// flake on a loaded runner, under -race, or on other hardware — the repo's
// standing rule for hot-path gates. The bound is 0: this runs once per
// category-scoped access rule per proxied request, so one allocation here is
// multiplied by the rule count on 100% of category-scoped traffic. The memo
// itself must not allocate either — it stores a string header, not a copy.
func TestBenchGate_HoistedCategoryMatchIsAllocationFree(t *testing.T) {
	prev := catStore
	catStore = urlcat.New([]*urlcat.Entry{
		{Name: "Social Media", Hosts: []string{"example.com"}},
		{Name: "Corp Internal", Hosts: []string{"intranet.corp.invalid"}},
	})
	t.Cleanup(func() { catStore = prev })

	// A scan reuses ONE scratch across every rule, which is the shape the memo
	// exists for: the first rule normalizes, the rest serve the memo.
	hit := newHostCatScratch("a.b.example.com")
	miss := newHostCatScratch("uncategorized.example.net")
	mixedCase := newHostCatScratch("A.B.EXAMPLE.COM.")

	cases := []struct {
		name string
		fn   func()
	}{
		{"miss", func() { miss.matchesCategory("Social Media") }},
		{"hit-subdomain", func() { hit.matchesCategory("Social Media") }},
		{"unknown-category", func() { miss.matchesCategory("No Such Category") }},
		{"mixed-case-host", func() { mixedCase.matchesCategory("Social Media") }},
		{"normHost-memo", func() { _ = miss.normHost() }},
	}
	for _, tc := range cases {
		if got := testing.AllocsPerRun(200, tc.fn); got != 0 {
			t.Errorf("%s: %v allocs/op, want 0", tc.name, got)
		}
	}

	// CONTROL: the cheapest way to pass an allocation gate is to stop doing the
	// work. These must still answer correctly after the runs above.
	if !hit.matchesCategory("Social Media") {
		t.Error("hit scratch stopped matching; the gate above is vacuous")
	}
	if miss.matchesCategory("Social Media") {
		t.Error("miss scratch started matching")
	}
}

// ─── structural wall ──────────────────────────────────────────────────────────

// TestWall_PerRuleCategoryMatchersTakeTheHoistedHost is the regression gate, and
// it is STRUCTURAL rather than timing-based on purpose: a cost ratio on this
// path needs a large taxonomy the test cannot cheaply build, and a gate that
// can flake on a loaded shared runner gets muted (the standing rule this repo
// applies to sanitizeLog, connlimit, the latency histogram and the IP filter).
//
// It walks hostCatScratch.matchesCategory and requires that every membership
// matcher it calls is a *Norm entry point handed sc.normHost(). Behavioural
// coverage cannot catch the regression this guards: re-introducing a per-rule
// NormalizeHost changes no decision at all, so every differential and control
// above keeps passing while the cost silently returns.
func TestWall_PerRuleCategoryMatchersTakeTheHoistedHost(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "policy_hostcat.go", nil, 0)
	if err != nil {
		t.Fatalf("parse policy_hostcat.go: %v", err)
	}

	// The per-rule matchers. Each must be called with sc.normHost().
	hoisted := map[string]bool{
		"MatchesHostNorm":      true,
		"MatchesHostAdminNorm": true,
		"MatchesCategoryNorm":  true,
	}
	// The normalizing wrappers. None may appear on the per-rule path.
	forbidden := map[string]bool{
		"MatchesHost":      true,
		"MatchesHostAdmin": true,
		"MatchesCategory":  true,
		"normalizeHost":    true,
		"NormalizeHost":    true,
	}

	var body *ast.FuncDecl
	for _, d := range file.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "matchesCategory" || fn.Recv == nil {
			continue
		}
		body = fn
	}
	if body == nil {
		t.Fatal("hostCatScratch.matchesCategory not found in policy_hostcat.go; " +
			"this wall no longer guards the per-rule path")
	}

	var checked int
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			// A bare identifier call, e.g. normalizeHost(...).
			if id, isID := call.Fun.(*ast.Ident); isID && forbidden[id.Name] {
				t.Errorf("matchesCategory calls %s(...) directly: the destination host "+
					"must be canonicalized ONCE per scan via sc.normHost(), not per rule",
					id.Name)
			}
			return true
		}
		name := sel.Sel.Name
		if forbidden[name] {
			t.Errorf("matchesCategory calls the normalizing entry point %s(...): "+
				"use the *Norm variant with sc.normHost() so the host is "+
				"canonicalized once per scan, not once per rule", name)
			return true
		}
		if !hoisted[name] {
			return true
		}
		checked++
		// The host argument is the LAST one for all three matchers.
		if len(call.Args) == 0 {
			t.Errorf("%s(...) called with no arguments", name)
			return true
		}
		arg := call.Args[len(call.Args)-1]
		inner, ok := arg.(*ast.CallExpr)
		if !ok {
			t.Errorf("%s(...) host argument is not sc.normHost(): %T", name, arg)
			return true
		}
		innerSel, ok := inner.Fun.(*ast.SelectorExpr)
		if !ok || innerSel.Sel.Name != "normHost" {
			t.Errorf("%s(...) host argument is not sc.normHost()", name)
		}
		return true
	})

	// NOT-VACUOUS: all three matchers must have been seen. A selector typo or a
	// refactor that moves the calls elsewhere would otherwise leave this gate
	// passing against nothing.
	if checked < 3 {
		t.Fatalf("wall matched only %d hoisted matcher calls, want >= 3 "+
			"(MatchesHostAdminNorm, MatchesCategoryNorm, MatchesHostNorm); "+
			"the selector has gone stale", checked)
	}
}
