package main

import (
	"fmt"
	"testing"

	"github.com/KidCarmi/Culvert/internal/catgroup"
	"github.com/KidCarmi/Culvert/internal/urlcat"
)

// swapCatStore installs entries as the process-wide admin taxonomy and restores
// the previous store when the test ends.
func swapCatStore(tb testing.TB, entries []*urlcat.Entry) {
	tb.Helper()
	prev := catStore
	catStore = urlcat.New(entries)
	tb.Cleanup(func() { catStore = prev })
}

// TestHostCatScratch_ResolvesFusionOnce is the memoization proof. The scratch is
// asked for the host's category, the underlying taxonomy is then replaced, and
// the scratch is asked again: a second answer that reflects the NEW taxonomy
// would mean the fusion ran twice, which is exactly the per-rule repetition the
// scratch exists to remove.
//
// Serving the first answer for the rest of the scan is the intended contract,
// not a staleness bug — it is the same one-decision-point guarantee Evaluate
// already gives for the clock (scanNow) and the client IP.
func TestHostCatScratch_ResolvesFusionOnce(t *testing.T) {
	swapCatStore(t, []*urlcat.Entry{
		{Name: "Social Media", Hosts: []string{"example.com"}},
	})

	sc := newHostCatScratch("host.example.com")
	cat, tier, _ := sc.fusion()
	if cat != "Social Media" || tier != "admin" {
		t.Fatalf("first fusion = (%q, %q); want (\"Social Media\", \"admin\")", cat, tier)
	}

	// Replace the taxonomy underneath the scratch.
	catStore = urlcat.New([]*urlcat.Entry{
		{Name: "Streaming", Hosts: []string{"example.com"}},
	})

	if cat2, tier2, _ := sc.fusion(); cat2 != cat || tier2 != tier {
		t.Errorf("second fusion = (%q, %q), want the memoized (%q, %q) — the scratch "+
			"re-resolved instead of reusing its answer, so a rule scan pays the "+
			"host→category fusion per rule again", cat2, tier2, cat, tier)
	}
}

// TestHostCatScratch_BoundToItsHost proves a scratch can only ever answer for
// the host it was built for, so a per-request scratch cannot leak one request's
// classification into the next.
func TestHostCatScratch_BoundToItsHost(t *testing.T) {
	swapCatStore(t, []*urlcat.Entry{
		{Name: "Social Media", Hosts: []string{"social.example"}},
		{Name: "Streaming", Hosts: []string{"video.example"}},
	})

	for _, tc := range []struct{ host, want string }{
		{"social.example", "Social Media"},
		{"cdn.video.example", "Streaming"},
		{"unclassified.example", ""},
	} {
		sc := newHostCatScratch(tc.host)
		if got, _, _ := sc.fusion(); got != tc.want {
			t.Errorf("fusion(%q) = %q; want %q", tc.host, got, tc.want)
		}
		if got := sc.matchesCategory(URLCategory(tc.want)); tc.want != "" && !got {
			t.Errorf("matchesCategory(%q) on host %q = false; want true", tc.want, tc.host)
		}
	}
}

// TestEvaluate_CategoryGroupScanSharesOneResolution is the end-to-end shape of
// the hoist: a scan over many category-group rules must reach the same verdict
// as the same rules evaluated one at a time. It guards the wiring (Evaluate →
// matchDestNorm → the scratch), not the memo itself.
func TestEvaluate_CategoryGroupScanSharesOneResolution(t *testing.T) {
	swapCatStore(t, []*urlcat.Entry{
		{Name: "Streaming", Hosts: []string{"video.example"}},
	})

	prevGroups := globalCategoryGroups
	globalCategoryGroups = catgroup.New()
	t.Cleanup(func() { globalCategoryGroups = prevGroups })
	if _, err := globalCategoryGroups.Add("media", []string{"Streaming"}); err != nil {
		t.Fatalf("add category group: %v", err)
	}

	ps := &PolicyStore{}
	rules := make([]PolicyRule, 0, 6)
	// Five rules scoped to groups the host is NOT in, then the one that matches:
	// the scan must traverse every preceding category-group rule first.
	for i := 0; i < 5; i++ {
		rules = append(rules, PolicyRule{
			Priority:          i + 1,
			Name:              fmt.Sprintf("miss-%d", i),
			DestCategoryGroup: fmt.Sprintf("absent-group-%d", i),
			Action:            ActionAllow,
		})
	}
	rules = append(rules, PolicyRule{
		Priority: 6, Name: "media-rule", DestCategoryGroup: "media", Action: ActionBlockPage,
	})
	ps.ReplaceAll(rules)

	m := ps.Evaluate("203.0.113.7", "", "unauth", "cdn.video.example", nil)
	if m == nil || m.Rule.Name != "media-rule" {
		t.Fatalf("Evaluate = %v; want the media-rule match", m)
	}
	if m.Action != ActionBlockPage {
		t.Errorf("action = %q; want %q", m.Action, ActionBlockPage)
	}

	// A host outside the group must still fall through the whole scan.
	if m := ps.Evaluate("203.0.113.7", "", "unauth", "unclassified.example", nil); m != nil {
		t.Errorf("Evaluate(uncategorized) = %q; want no match (default deny)", m.Rule.Name)
	}
}
