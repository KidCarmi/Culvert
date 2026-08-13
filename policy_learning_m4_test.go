package main

// M4 root-level tests: the recommendable-category allowlist seed (fail-closed,
// business categories only) and its wiring into the learning loader.

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/urlcat"
)

// TestRecommendableSeed_BusinessCategoriesOnly: the M4 allowlist seed is the
// embedded SaaS business-category set — never the hardcoded non-business
// built-ins (which an auto-generated Allow rule must not touch without an
// explicit governed decision).
func TestRecommendableSeed_BusinessCategoriesOnly(t *testing.T) {
	names := urlcat.DefaultBusinessCategoryNames()
	if len(names) == 0 {
		t.Fatal("empty business-category seed — the recommendable allowlist would be vacuous")
	}
	if !sort.StringsAreSorted(names) {
		t.Fatalf("seed not sorted (deterministic canonical form): %v", names)
	}
	have := make(map[string]bool, len(names))
	for _, n := range names {
		have[n] = true
	}
	for _, want := range []string{"AI", "Dev Tools", "Finance", "Cloud Storage"} {
		if !have[want] {
			t.Errorf("expected business category %q missing from the seed", want)
		}
	}
	for _, forbidden := range []string{"Social Media", "Malicious", "News", "Streaming", "Gambling", "Adult"} {
		if have[forbidden] {
			t.Errorf("non-business built-in %q leaked into the recommendable seed", forbidden)
		}
	}
}

// TestRecommendableSeed_WiredIntoLoader: the loader passes the business seed as
// the engine's fail-closed allowlist (source pin — the loader itself is
// disabled in production, so wiring is asserted at the source level like the
// wall tests).
func TestRecommendableSeed_WiredIntoLoader(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(pkgSourceDir(), "policy_learning_startup.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "RecommendableCategories: urlcat.DefaultBusinessCategoryNames()") {
		t.Fatal("loader no longer seeds RecommendableCategories from the embedded business-category set — if deliberate, update this pin with the design change")
	}
}
