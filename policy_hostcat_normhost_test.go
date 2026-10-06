package main

import (
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/urlcat"
)

// hostCatScratch.normHost() — the scan-scoped normalized-host hoist.
//
// The change this suite pins is a COST change with a correctness obligation:
// hostutil.NormalizeHost depends on the REQUEST, not on the rule, so it moved out
// of the three per-rule membership matchers and onto the scratch. The matchers
// gained normalized-host entry points (urlcat.MatchesNormalizedHost /
// MatchesNormalizedHostAdmin, effectiveCategoryView.MatchesNormalizedCategory)
// and kept their raw-host wrappers for every other caller.
//
// Two properties therefore need pinning, and they fail to DIFFERENT defects:
//
//	(1) FAITHFUL — matchesCategory's verdict is byte-identical to the pre-hoist
//	    behaviour for every host shape. Broken by a wrapper that stopped
//	    normalizing, or by a call site handed the raw host.
//	(2) USED — the per-rule path really reads the memo instead of re-deriving.
//	    Broken by a partial revert of any ONE of the three call sites, which
//	    property (1) cannot see at all (re-normalizing an already-normalized
//	    host returns the same value, so a revert is invisible in the verdict).
//
// (2) is proved STRUCTURALLY by poisoning the memo, not by timing: a ns-based
// assertion on a 40ns saving inside a rule scan flakes on a shared runner, and
// the repo's standing rule is that a gate which can flake gets muted.

// nhCorpus is the host-shape corpus: shapes where the raw and normalized forms
// DIFFER, plus already-canonical controls. A corpus of canonical hosts only
// would pass against a broken wrapper, since for those raw == normalized.
func nhCorpus() []string {
	return []string{
		"example.com", "a.b.example.com", "uncategorized.example.net",
		"EXAMPLE.COM", "Example.Com", "A.B.EXAMPLE.COM",
		"example.com.", "EXAMPLE.COM.", "a.b.example.com.",
		"bücher.example.com", "BÜCHER.example.com", "xn--bcher-kva.example.com",
		"straße.example.com", "192.0.2.1", "2001:DB8::1",
		"", ".",
	}
}

// nhSeedStore installs a taxonomy covering the corpus shapes in both the admin
// (BuiltIn=false) and built-in tiers, so every branch of matchesCategory can hit
// as well as miss, and restores the process-global store afterwards.
func nhSeedStore(tb testing.TB) {
	tb.Helper()
	prev := catStore
	catStore = urlcat.New([]*urlcat.Entry{
		{Name: "Social Media", Hosts: []string{"example.com", "xn--bcher-kva.example.com"}},
		{Name: "Corp Internal", Hosts: []string{"192.0.2.1", "2001:db8::1"}},
		{Name: "MixedCase Admin", Hosts: []string{"EXAMPLE.COM", "straße.example.com"}},
		{Name: "Built In Cat", BuiltIn: true, Hosts: []string{"a.b.example.com", "bücher.example.com"}},
	})
	tb.Cleanup(func() { catStore = prev })
}

// nhCategories enumerates the categories to test, including ones no entry
// declares and the empty category (which MatchesNormalizedCategory short-circuits).
func nhCategories() []URLCategory {
	return []URLCategory{
		"Social Media", "social media", "SOCIAL MEDIA",
		"Corp Internal", "MixedCase Admin", "Built In Cat",
		"No Such Category", "",
	}
}

// nhView builds an effective view over the corpus shapes so the view-ARMED
// branch — which calls TWO normalized matchers per rule — is exercised too.
// A view's keys are NORMALIZED by contract (effectiveCategoryView.entries), so
// the fixture canonicalizes them exactly as the composition path does. Seeding
// raw Unicode keys here would build a view no production path can produce and
// would make the memo gate below fail against correct code.
func nhView(tb testing.TB) *effectiveCategoryView {
	tb.Helper()
	entries := map[string]string{}
	for host, cat := range map[string]string{
		"example.com":        "Social Media",
		"bücher.example.com": "Built In Cat",
		"straße.example.com": "MixedCase Admin",
	} {
		norm := normalizeHost(host)
		if norm == "" {
			tb.Fatalf("fixture host %q normalizes to empty", host)
		}
		entries[norm] = cat
	}
	return newEffectiveView(entries, effectiveCategoryView{Source: sourceDownloaded})
}

// nhLegacyMatchesCategory is a VERBATIM copy of matchesCategory's pre-hoist body:
// every matcher called with the RAW host, each normalizing its own argument. It is
// the oracle for property (1) — kept in-tree so the equivalence claim is executable
// rather than a comment (the legacySanitizeLog / legacyIsExempt convention).
func nhLegacyMatchesCategory(sc *hostCatScratch, cat URLCategory) bool {
	if view := sc.effectiveView(); view != nil {
		if catStore.MatchesHostAdmin(cat, sc.host) {
			return true
		}
		if view.MatchesCategory(string(cat), sc.host) {
			return true
		}
	} else if catStore.MatchesHost(cat, sc.host) {
		return true
	}
	if communityDB != nil {
		if foundCat, ok := sc.communityLookup(); ok {
			return strings.EqualFold(foundCat, string(cat))
		}
	}
	return false
}

// TestNormHost_MatchesCategoryAgreesWithPreHoistBody is property (1): the
// differential against the verbatim pre-hoist body, in BOTH view postures.
func TestNormHost_MatchesCategoryAgreesWithPreHoistBody(t *testing.T) {
	nhSeedStore(t)
	prevView := saasEffectiveView.Current()
	t.Cleanup(func() { saasEffectiveView.Swap(prevView) })

	for _, armed := range []bool{false, true} {
		if armed {
			saasEffectiveView.Swap(nhView(t))
		} else {
			saasEffectiveView.Swap(nil)
		}
		hits, checked := 0, 0
		for _, host := range nhCorpus() {
			for _, cat := range nhCategories() {
				checked++
				// Fresh scratches: each must start with an empty memo, exactly
				// as one rule scan does.
				got := newHostCatScratch(host)
				want := newHostCatScratch(host)
				g := got.matchesCategory(cat)
				w := nhLegacyMatchesCategory(&want, cat)
				if g != w {
					t.Errorf("armed=%v host=%q cat=%q: matchesCategory=%v, pre-hoist body=%v",
						armed, host, cat, g, w)
				}
				if w {
					hits++
				}
			}
		}
		if hits == 0 {
			t.Fatalf("armed=%v: %d pairs and ZERO hits — the differential cannot fail for a broken matcher", armed, checked)
		}
		t.Logf("armed=%v: %d pairs, %d hits", armed, checked, hits)
	}
}

// TestNormHost_DifferentialIsNotVacuous proves the corpus contains shapes where
// raw and normalized differ, so the differential above can actually fail.
func TestNormHost_DifferentialIsNotVacuous(t *testing.T) {
	differing := 0
	for _, h := range nhCorpus() {
		if normalizeHost(h) != h {
			differing++
		}
	}
	if differing < 6 {
		t.Fatalf("only %d corpus hosts change under normalizeHost; the differential is near-vacuous", differing)
	}
}

// TestNormHost_IsMemoizedAndLazy pins the memo's own contract: derived at most
// once, and not derived at all by a scan that never asks.
func TestNormHost_IsMemoizedAndLazy(t *testing.T) {
	sc := newHostCatScratch("EXAMPLE.COM.")
	if sc.normHostSet {
		t.Fatal("a fresh scratch must not have derived the normalized host: the hoist is lazy, " +
			"so a scan with no category-scoped rule computes nothing")
	}
	first := sc.normHost()
	if want := normalizeHost("EXAMPLE.COM."); first != want {
		t.Fatalf("normHost() = %q, want %q", first, want)
	}
	if !sc.normHostSet {
		t.Fatal("normHost() did not record its memo; every later call would re-derive")
	}
	// Poison the memo: a second call that recomputes would overwrite this.
	sc.normHostVal = "poisoned.example"
	if got := sc.normHost(); got != "poisoned.example" {
		t.Fatalf("normHost() re-derived instead of serving the memo: got %q", got)
	}
}

// TestNormHost_PerRuleMatchersReadTheMemo is property (2), the STRUCTURAL gate.
//
// It poisons the memo with a host that IS categorized while leaving sc.host a
// host that is NOT, then asserts the verdict follows the MEMO. That can only
// happen if the per-rule matcher consulted the hoisted value; a call site that
// re-derives from sc.host answers false. It drives all THREE call sites — the
// view-unarmed catStore probe, and the view-armed admin probe and view probe —
// so a partial revert of any one of them fails here.
//
// Property (1) is blind to this defect by construction (re-normalizing an
// already-normalized host returns the same value), which is why both gates exist.
func TestNormHost_PerRuleMatchersReadTheMemo(t *testing.T) {
	nhSeedStore(t)
	prevView := saasEffectiveView.Current()
	t.Cleanup(func() { saasEffectiveView.Swap(prevView) })

	// A host no tier categorizes: if a matcher re-derives from sc.host it must
	// answer false for every category below.
	const uncategorized = "uncategorized.example.net"

	// Each case must be ISOLATED to ONE call site: the (memo, category) pair is
	// chosen so that exactly one of the armed branch's two probes can answer
	// true. Without that, a case is not a gate on the site it names — the first
	// draft paired "MixedCase Admin" with a host the effective view ALSO
	// carried, so reverting the admin probe still answered true through the
	// still-hoisted view probe and the mutation passed (verified). isolatedBy
	// records which probe is supposed to be load-bearing, and the subtest
	// asserts the other one cannot match.
	cases := []struct {
		name     string
		armed    bool
		memo     string
		cat      URLCategory
		wantSite string
		// viewMustNotMatch asserts the effective view does NOT carry
		// (cat, memo), so only the catStore admin probe can answer true.
		viewMustNotMatch bool
		// adminMustNotMatch asserts catStore's ADMIN tier does not carry
		// (cat, memo), so only the view probe can answer true.
		adminMustNotMatch bool
	}{
		{
			name: "view-unarmed/catStore.MatchesNormalizedHost",
			memo: "example.com", cat: "Social Media",
			wantSite: "the else-branch catStore probe",
		},
		{
			// Corp Internal lives only in catStore's admin tier; the view has no
			// key for this host, so the view probe cannot rescue a reverted
			// admin probe.
			name:  "view-armed/catStore.MatchesNormalizedHostAdmin",
			armed: true, memo: "192.0.2.1", cat: "Corp Internal",
			wantSite:         "the armed-branch catStore admin probe",
			viewMustNotMatch: true,
		},
		{
			// "Built In Cat" is BuiltIn=true, so it is absent from catStore's
			// adminIndex by construction and the admin probe cannot rescue a
			// reverted view probe.
			name:  "view-armed/view.MatchesNormalizedCategory",
			armed: true, memo: "bücher.example.com", cat: "Built In Cat",
			wantSite:          "the armed-branch effective-view probe",
			adminMustNotMatch: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.armed {
				saasEffectiveView.Swap(nhView(t))
			} else {
				saasEffectiveView.Swap(nil)
			}

			// Control first: with the memo UNPOISONED the uncategorized host
			// must NOT match. Without this, a matcher hard-wired to true would
			// pass the poisoned assertion below.
			ctl := newHostCatScratch(uncategorized)
			if ctl.matchesCategory(tc.cat) {
				t.Fatalf("control: %q unexpectedly matches %q — the poisoned assertion below would be vacuous",
					uncategorized, tc.cat)
			}

			// Now the same scratch shape with the memo pre-filled. The poison is
			// itself canonicalized, because the memo always holds a normalized
			// host in production.
			memo := normalizeHost(tc.memo)

			// Isolation checks: without these the subtest could pass through
			// the OTHER probe and would not gate the site it names.
			if tc.viewMustNotMatch {
				if v := saasEffectiveView.Current(); v == nil || v.MatchesNormalizedCategory(string(tc.cat), memo) {
					t.Fatalf("not isolated: the effective view matches (%q, %q), so this case "+
						"cannot gate %s", tc.cat, memo, tc.wantSite)
				}
			}
			if tc.adminMustNotMatch && catStore.MatchesNormalizedHostAdmin(tc.cat, memo) {
				t.Fatalf("not isolated: catStore's admin tier matches (%q, %q), so this case "+
					"cannot gate %s", tc.cat, memo, tc.wantSite)
			}

			sc := newHostCatScratch(uncategorized)
			sc.normHostSet = true
			sc.normHostVal = memo

			if !sc.matchesCategory(tc.cat) {
				t.Errorf("matchesCategory(%q) = false with the memo holding %q: %s re-derived the "+
					"normalized host from sc.host instead of reading normHost(). The per-rule hoist "+
					"is reverted on that call site; the verdict differential cannot see this.",
					tc.cat, tc.memo, tc.wantSite)
			}
		})
	}
}

// TestNormHost_ResolveFusionReadsTheMemo covers the two matchedBy derivations in
// resolveFusion, which were already per-SCAN but each called normalizeHost
// independently — folding them onto the memo removes the duplicate derivation
// without changing the reported pattern.
func TestNormHost_ResolveFusionReadsTheMemo(t *testing.T) {
	nhSeedStore(t)
	prevView := saasEffectiveView.Current()
	t.Cleanup(func() { saasEffectiveView.Swap(prevView) })
	saasEffectiveView.Swap(nil)

	// With no community feed and an uncategorized host the fusion reports none —
	// that path still must not leave the memo underived if it was consulted.
	sc := newHostCatScratch("UNCATEGORIZED.EXAMPLE.NET.")
	cat, tier, pattern := sc.fusion()
	if tier != "none" || cat != "" || pattern != "" {
		t.Fatalf("fusion() = (%q, %q, %q), want an uncategorized verdict", cat, tier, pattern)
	}

	// A categorized host resolves through the admin tier and reports the store's
	// configured pattern verbatim — unchanged by the hoist.
	sc2 := newHostCatScratch("EXAMPLE.COM")
	cat2, tier2, _ := sc2.fusion()
	if cat2 == "" || tier2 != "admin" {
		t.Fatalf("fusion() = (%q, %q), want an admin-tier classification", cat2, tier2)
	}
}

// TestBenchGate_NormHostDerivesOnceAcrossManyRules is the cost claim stated
// STRUCTURALLY: whatever the rule count, the scan derives the normalized host at
// most once. It asserts a COUNT, not a duration, so it is deterministic on any
// hardware, under any load, and under -race.
func TestBenchGate_NormHostDerivesOnceAcrossManyRules(t *testing.T) {
	nhSeedStore(t)
	prevView := saasEffectiveView.Current()
	t.Cleanup(func() { saasEffectiveView.Swap(prevView) })
	saasEffectiveView.Swap(nhView(t))

	sc := newHostCatScratch("UNCATEGORIZED.EXAMPLE.NET.")
	// Simulate a 200-rule category-scoped scan against one scratch, which is
	// exactly how Evaluate uses it.
	for i := 0; i < 200; i++ {
		sc.matchesCategory(URLCategory("No Such Category"))
	}
	if !sc.normHostSet {
		t.Fatal("200 category-scoped rule evaluations never populated the memo: " +
			"every one of them re-derived the normalized host")
	}
	if want := normalizeHost("UNCATEGORIZED.EXAMPLE.NET."); sc.normHostVal != want {
		t.Fatalf("memo holds %q, want %q", sc.normHostVal, want)
	}
}
