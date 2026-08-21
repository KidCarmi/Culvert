package main

// saas_feed_view_membership_test.go — regression proofs for the F3b-4 membership
// fail-open: matchCategory answered a MEMBERSHIP question ("is host in category C?")
// from the effective view's CLASSIFICATION index ("what is host?"), which admits one
// category per host. The embedded baseline (catStore's BuiltIn taxonomy) is
// many-to-many, so every category but one was dropped — and with it any policy rule
// keyed on a losing category. The view is installed on EVERY startup
// (startSignedFeedLifecycle → recover → installEmbedded), so this was live by default
// and not gated on the signed feed being enabled.
//
// The pinning strategy is differential, not example-based: TestViewMembership_Matches
// CatStoreAcrossBuiltInTaxonomy replays the whole shipped taxonomy through both the
// pre-view matcher (catStore.MatchesHost) and the view matcher and requires zero
// divergences, so a future taxonomy edit that introduces a new multi-category host is
// covered without anyone remembering to add a case.

import (
	"strings"
	"sync"
	"testing"

	"github.com/KidCarmi/Culvert/internal/catoverride"
	"github.com/KidCarmi/Culvert/internal/urlcat"
)

// builtInMultiCategoryHosts returns the hosts in the LIVE catStore that belong to more
// than one BuiltIn category — the exact population the collapse used to silently
// truncate. Empty is a legitimate result for a taxonomy with no overlap; the tests that
// need a concrete case fall back to a synthetic store.
func builtInMultiCategoryHosts(t *testing.T) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for h, cats := range catStore.BuiltInHostMemberships() {
		if len(cats) > 1 {
			out[h] = cats
		}
	}
	return out
}

// ─── the shipped-taxonomy regression ─────────────────────────────────────────────────

// The concrete fail-open, pinned against the taxonomy as shipped: linkedin.com is listed
// under both "Social Media" (hardcoded built-ins) and "HR & Recruiting" (embedded SaaS
// taxonomy). Pre-fix, installing the effective view made a deny rule on "Social Media"
// stop blocking linkedin.com and every subdomain of it.
func TestViewMembership_ShippedMultiCategoryHostMatchesEveryCategory(t *testing.T) {
	multi := builtInMultiCategoryHosts(t)
	if len(multi) == 0 {
		t.Skip("shipped taxonomy currently has no multi-category built-in host")
	}
	swapSaaSView(t, embeddedBaselineView())

	for host, cats := range multi {
		if len(cats) < 2 {
			continue
		}
		for _, cat := range cats {
			for _, probe := range []string{host, "www." + host, "a.b." + host} {
				if !matchCategory(URLCategory(cat), probe) {
					t.Errorf("matchCategory(%q, %q) = false with the effective view installed; "+
						"the host is a member of %v and every one of them must still match", cat, probe, cats)
				}
			}
		}
	}
}

// The same population must also have matched BEFORE the view existed — this asserts the
// baseline the fix restores, so a failure here means the taxonomy (not the view) changed.
func TestViewMembership_PreViewBaselineMatchesEveryCategory(t *testing.T) {
	multi := builtInMultiCategoryHosts(t)
	if len(multi) == 0 {
		t.Skip("shipped taxonomy currently has no multi-category built-in host")
	}
	swapSaaSView(t, nil) // lifecycle unarmed: the pre-F3b-4 catStore path

	for host, cats := range multi {
		for _, cat := range cats {
			if !matchCategory(URLCategory(cat), host) {
				t.Errorf("pre-view baseline: matchCategory(%q, %q) = false, want true", cat, host)
			}
		}
	}
}

// ─── differential equivalence over the whole taxonomy ────────────────────────────────

// The view matcher must agree with catStore.MatchesHost — the function it replaced — on
// every (category, host) pair the shipped taxonomy can produce, plus subdomain and
// non-member probes. Zero divergences is the contract; this is what catches a future
// taxonomy edit that reintroduces the collapse.
func TestViewMembership_MatchesCatStoreAcrossBuiltInTaxonomy(t *testing.T) {
	view := embeddedBaselineView()

	cats := map[string]struct{}{}
	hosts := map[string]struct{}{}
	for h, cs := range catStore.BuiltInHostMemberships() {
		hosts[h] = struct{}{}
		hosts["www."+h] = struct{}{}
		hosts["deep.sub."+h] = struct{}{}
		for _, c := range cs {
			cats[c] = struct{}{}
		}
	}
	// Non-members: must be false under both.
	for _, h := range []string{"not-in-any-category.example", "example.invalid", "localhost", ""} {
		hosts[h] = struct{}{}
	}

	divergences := 0
	for cat := range cats {
		for host := range hosts {
			want := catStore.MatchesHost(urlcat.Category(cat), host)
			got := view.MatchesCategory(cat, host)
			if want != got {
				divergences++
				if divergences <= 10 {
					t.Errorf("divergence: cat=%q host=%q catStore.MatchesHost=%v view.MatchesCategory=%v",
						cat, host, want, got)
				}
			}
		}
	}
	if divergences > 0 {
		t.Errorf("%d total divergences between the view matcher and catStore.MatchesHost", divergences)
	}
}

// ─── no shadowing by a more specific key in a different category ─────────────────────

// catStore.MatchesHost checks the exact host AND every suffix, so an ancestor key in
// category A keeps matching even when a more specific descendant key sits in category B.
// The view's LookupHost stops at the most specific key, which is precisely why it cannot
// answer a membership question. MatchesCategory must not shadow.
func TestViewMembership_SpecificKeyDoesNotShadowAncestorCategory(t *testing.T) {
	view := newEffectiveViewWithMembership(
		map[string]string{"example.com": "CatA", "app.example.com": "CatB"},
		map[string][]string{"example.com": {"CatA"}, "app.example.com": {"CatB"}},
		effectiveCategoryView{Source: sourceDownloaded},
	)

	cases := []struct {
		host, cat string
		want      bool
	}{
		{"app.example.com", "CatA", true}, // ancestor key still governs — no shadowing
		{"app.example.com", "CatB", true}, // the specific key matches too
		{"x.app.example.com", "CatA", true},
		{"x.app.example.com", "CatB", true},
		{"other.example.com", "CatA", true},
		{"other.example.com", "CatB", false},
		{"example.com", "CatB", false}, // a descendant key never matches upward
		{"notexample.com", "CatA", false},
	}
	for _, c := range cases {
		if got := view.MatchesCategory(c.cat, c.host); got != c.want {
			t.Errorf("MatchesCategory(%q, %q) = %v, want %v", c.cat, c.host, got, c.want)
		}
	}
}

// TestViewMembership_OverrideSealsAncestorCategory is the regression for the
// descendant-override shadowing P1. It is the deliberate CONTRAST to
// TestViewMembership_SpecificKeyDoesNotShadowAncestorCategory: a more-specific
// key from the many-to-many BASELINE stays additive (no shadowing), but a host an
// override makes authoritative — recategorized, added, or tombstoned — SEALS its
// subtree, so an ancestor baseline category the override did not assert must not
// leak back in via the suffix walk.
func TestViewMembership_OverrideSealsAncestorCategory(t *testing.T) {
	baseEntries := map[string]string{"example.com": "Social"}
	baseMembers := map[string][]string{"example.com": {"Social"}}
	ov := catoverride.Overrides{Recategorized: map[string]string{"sub.example.com": "Business"}}

	view := newEffectiveViewWithMembership(
		catoverride.ComposeView(baseEntries, ov),
		catoverride.ComposeMembership(baseMembers, ov),
		effectiveCategoryView{Source: sourceDownloaded, sealed: catoverride.SealedKeys(ov)},
	)

	cases := []struct {
		host, cat string
		want      bool
	}{
		{"sub.example.com", "Business", true},   // the override's own category
		{"sub.example.com", "Social", false},    // ancestor SHADOWED by the recategorization
		{"x.sub.example.com", "Business", true}, // the whole subtree is governed by the override
		{"x.sub.example.com", "Social", false},  // ...and shadowed from the ancestor
		{"example.com", "Social", true},         // the ancestor itself is untouched
		{"other.example.com", "Social", true},   // a sibling NOT under the override still matches upward
	}
	for _, c := range cases {
		if got := view.MatchesCategory(c.cat, c.host); got != c.want {
			t.Errorf("MatchesCategory(%q, %q) = %v, want %v", c.cat, c.host, got, c.want)
		}
	}
}

// TestViewMembership_TombstoneSealsAncestorCategory pins the same seal for a
// tombstone: a suppressed host (and its subtree) must match NOTHING, not climb to
// an ancestor baseline category.
func TestViewMembership_TombstoneSealsAncestorCategory(t *testing.T) {
	ov := catoverride.Overrides{Tombstones: []string{"sub.example.com"}}
	view := newEffectiveViewWithMembership(
		catoverride.ComposeView(map[string]string{"example.com": "Social"}, ov),
		catoverride.ComposeMembership(map[string][]string{"example.com": {"Social"}}, ov),
		effectiveCategoryView{Source: sourceDownloaded, sealed: catoverride.SealedKeys(ov)},
	)
	if view.MatchesCategory("Social", "sub.example.com") {
		t.Error("a tombstoned host must not match the ancestor category via the suffix walk")
	}
	if view.MatchesCategory("Social", "x.sub.example.com") {
		t.Error("the tombstoned subtree must not match the ancestor category")
	}
	if !view.MatchesCategory("Social", "example.com") {
		t.Error("the ancestor itself must still match")
	}
}

// ─── malformed / boundary input ──────────────────────────────────────────────────────

func TestViewMembership_MalformedAndBoundaryInput(t *testing.T) {
	view := newEffectiveViewWithMembership(
		map[string]string{"example.com": "CatA"},
		map[string][]string{"example.com": {"CatA", "CatB"}},
		effectiveCategoryView{Source: sourceDownloaded},
	)

	cases := []struct {
		name, cat, host string
		want            bool
	}{
		{"empty category never matches", "", "example.com", false},
		{"empty host never matches", "CatA", "", false},
		{"both empty", "", "", false},
		{"whitespace host", "CatA", "   ", false},
		{"uppercase host normalizes", "CatA", "EXAMPLE.COM", true},
		{"uppercase category folds", "cata", "example.com", true},
		{"mixed-case category folds", "CaTa", "example.com", true},
		{"second membership matches", "CatB", "sub.example.com", true},
		{"unknown category", "CatZ", "example.com", false},
		{"lone dot", "CatA", ".", false},
		{"leading dot", "CatA", ".example.com", true},
		{"bare tld is not a member", "CatA", "com", false},
		{"suffix must be label-aligned", "CatA", "notexample.com", false},
		{"deep subdomain", "CatA", "a.b.c.d.e.example.com", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := view.MatchesCategory(c.cat, c.host); got != c.want {
				t.Errorf("MatchesCategory(%q, %q) = %v, want %v", c.cat, c.host, got, c.want)
			}
		})
	}
}

// A host key whose membership list is empty must be dropped, never treated as a wildcard.
func TestViewMembership_EmptyMembershipListIsNotAWildcard(t *testing.T) {
	view := newEffectiveViewWithMembership(
		map[string]string{},
		map[string][]string{"ghost.example": {}},
		effectiveCategoryView{Source: sourceDownloaded},
	)
	if view.MatchesCategory("CatA", "ghost.example") {
		t.Error("an empty membership list must not match any category")
	}
	if _, ok := view.LookupHost("ghost.example"); ok {
		t.Error("an empty membership list must not become a classification entry")
	}
}

// ─── index reconciliation ────────────────────────────────────────────────────────────

// newEffectiveView (the one-category-per-host constructor used by the signed feed and
// the override grammar) must derive a membership index that answers identically to the
// classification index — no source of drift for single-category sources.
func TestViewMembership_SingleCategoryConstructorIsConsistent(t *testing.T) {
	entries := map[string]string{"a.example": "CatA", "b.example": "CatB"}
	view := newEffectiveView(entries, effectiveCategoryView{Source: sourceDownloaded})

	for host, cat := range entries {
		if !view.MatchesCategory(cat, host) {
			t.Errorf("MatchesCategory(%q, %q) = false, want true", cat, host)
		}
		if c, ok := view.LookupHost(host); !ok || c != cat {
			t.Errorf("LookupHost(%q) = (%q,%v), want (%q,true)", host, c, ok, cat)
		}
	}
	if view.MatchesCategory("CatB", "a.example") {
		t.Error("a single-category source must not leak a second category")
	}
}

// Every key must be present in BOTH indices: a members-only key would match without ever
// classifying (invisible to the admin lookup API), an entries-only key would classify
// without ever matching (a silent fail-open).
func TestViewMembership_IndicesAreReconciled(t *testing.T) {
	view := newEffectiveViewWithMembership(
		map[string]string{"only-entries.example": "CatA"},
		map[string][]string{"only-members.example": {"CatB"}},
		effectiveCategoryView{Source: sourceEmbedded},
	)
	if !view.MatchesCategory("CatA", "only-entries.example") {
		t.Error("an entries-only key must be reconciled into the membership index")
	}
	if c, ok := view.LookupHost("only-members.example"); !ok || c != "CatB" {
		t.Errorf("a members-only key must be reconciled into the classification index; got (%q,%v)", c, ok)
	}
	if view.HostCount() != 2 {
		t.Errorf("HostCount = %d, want 2", view.HostCount())
	}
}

// The view is immutable after construction: mutating the caller's maps must not be
// observable through it.
func TestViewMembership_ConstructorDefensivelyCopies(t *testing.T) {
	entries := map[string]string{"a.example": "CatA"}
	members := map[string][]string{"a.example": {"CatA"}}
	view := newEffectiveViewWithMembership(entries, members, effectiveCategoryView{Source: sourceEmbedded})

	entries["b.example"] = "CatB"
	members["a.example"][0] = "CatZ"
	members["c.example"] = []string{"CatC"}

	if view.MatchesCategory("CatB", "b.example") || view.MatchesCategory("CatC", "c.example") {
		t.Error("post-construction map mutation must not be observable through the view")
	}
	if !view.MatchesCategory("CatA", "a.example") {
		t.Error("post-construction slice mutation must not be observable through the view")
	}
}

// ─── override interaction (a removal must stay a removal) ────────────────────────────

// A tombstone must suppress a multi-category host completely: it must not survive
// through one of its other categories. Same for the subtree the tombstone governs.
func TestViewMembership_TombstoneSuppressesEveryCategory(t *testing.T) {
	base := map[string][]string{
		"multi.example":     {"CatA", "CatB"},
		"sub.multi.example": {"CatC"},
		"keep.example":      {"CatA"},
	}
	out := catoverride.ComposeMembership(base, catoverride.Overrides{Tombstones: []string{"multi.example"}})

	if _, ok := out["multi.example"]; ok {
		t.Error("tombstoned host must be removed from the membership index")
	}
	if _, ok := out["sub.multi.example"]; ok {
		t.Error("tombstone governs its whole subtree")
	}
	if got := out["keep.example"]; len(got) != 1 || got[0] != "CatA" {
		t.Errorf("unrelated host must survive unchanged, got %v", got)
	}
}

// A recategorization replaces the WHOLE membership list for its subtree — the override
// key is the sole authority there, so an old category must not linger.
func TestViewMembership_RecategorizeReplacesWholeMembership(t *testing.T) {
	base := map[string][]string{
		"multi.example":     {"CatA", "CatB"},
		"sub.multi.example": {"CatC"},
	}
	out := catoverride.ComposeMembership(base,
		catoverride.Overrides{Recategorized: map[string]string{"multi.example": "CatNew"}})

	got := out["multi.example"]
	if len(got) != 1 || got[0] != "CatNew" {
		t.Errorf("recategorized host membership = %v, want [CatNew]", got)
	}
	if _, ok := out["sub.multi.example"]; ok {
		t.Error("recategorization governs its whole subtree")
	}
}

// ComposeMembership and ComposeView must agree on which keys survive — a key that
// survives in only one index is exactly the drift the reconciliation guards against, and
// it would mean a host matches but never classifies (or the reverse).
func TestViewMembership_ComposeMembershipAgreesWithComposeView(t *testing.T) {
	entries := embeddedBaselineEntries()
	members := embeddedBaselineMemberships()
	ov := catoverride.Overrides{
		Tombstones:    []string{"linkedin.com"},
		Recategorized: map[string]string{"facebook.com": "Blocked"},
		Added:         map[string]string{"new.example": "CatNew"},
	}
	cv := catoverride.ComposeView(entries, ov)
	cm := catoverride.ComposeMembership(members, ov)

	if len(cv) != len(cm) {
		t.Errorf("key-count divergence: ComposeView=%d ComposeMembership=%d", len(cv), len(cm))
	}
	for h, cat := range cv {
		cats, ok := cm[h]
		if !ok {
			t.Errorf("host %q survived ComposeView but not ComposeMembership", h)
			continue
		}
		if !containsFoldTest(cats, cat) {
			t.Errorf("host %q: ComposeView category %q missing from membership %v", h, cat, cats)
		}
	}
	for h := range cm {
		if _, ok := cv[h]; !ok {
			t.Errorf("host %q survived ComposeMembership but not ComposeView", h)
		}
	}
}

func containsFoldTest(cats []string, want string) bool {
	for _, c := range cats {
		if strings.EqualFold(c, want) {
			return true
		}
	}
	return false
}

// ─── classification precedence ───────────────────────────────────────────────────────

// BuiltInHostCategories collapses a multi-category host to ONE category. That collapse
// must pick the same category the pre-view classification path picked
// (catStore.LookupHost, which scans entries top-down), otherwise the category-GROUP
// enforcement path — which resolves host→category through lookupHostCategory — silently
// changes which group a host belongs to.
func TestViewMembership_ClassificationCollapseMatchesCatStoreLookup(t *testing.T) {
	collapsed := catStore.BuiltInHostCategories()
	members := catStore.BuiltInHostMemberships()

	for host, cat := range collapsed {
		if want, _, ok := catStore.LookupHost(host); ok && !strings.EqualFold(want, cat) {
			t.Errorf("collapse divergence for %q: BuiltInHostCategories=%q catStore.LookupHost=%q (members=%v)",
				host, cat, want, members[host])
		}
		if got := members[host]; len(got) == 0 || !strings.EqualFold(got[0], cat) {
			t.Errorf("collapse for %q must be members[0]: collapsed=%q members=%v", host, cat, got)
		}
	}
}

// The multi-category population must classify the same way with and without the view, so
// the category-group path does not silently change groups.
func TestViewMembership_GroupPathClassificationUnchangedByView(t *testing.T) {
	multi := builtInMultiCategoryHosts(t)
	if len(multi) == 0 {
		t.Skip("shipped taxonomy currently has no multi-category built-in host")
	}

	before := map[string]string{}
	swapSaaSView(t, nil)
	for host := range multi {
		cat, _, _ := lookupHostCategory(host)
		before[host] = cat
	}

	saasEffectiveView.Swap(embeddedBaselineView())
	for host, want := range before {
		got, _, _ := lookupHostCategory(host)
		if !strings.EqualFold(got, want) {
			t.Errorf("lookupHostCategory(%q) = %q with the view installed, want %q (pre-view) — "+
				"the category-group path would resolve a different group", host, got, want)
		}
	}
}

// ─── concurrency ─────────────────────────────────────────────────────────────────────

// The view is read lock-free from the request path while the coordinator swaps it. Under
// -race this proves the membership index is published safely and that a reader observes
// an entirely-old or entirely-new view, never a blend.
func TestViewMembership_ConcurrentReadsDuringSwap(t *testing.T) {
	swapSaaSView(t, embeddedBaselineView())

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// Any result is acceptable; the assertion is the absence of a race and
				// of a panic on a half-published index.
				_ = matchCategory("Social Media", "www.linkedin.com")
				_, _, _ = lookupHostCategory("linkedin.com")
			}
		}()
	}
	for i := 0; i < 200; i++ {
		if i%2 == 0 {
			saasEffectiveView.Swap(embeddedBaselineView())
		} else {
			saasEffectiveView.Swap(viewOf(map[string]string{"linkedin.com": "Social Media"}))
		}
	}
	close(stop)
	wg.Wait()
}
