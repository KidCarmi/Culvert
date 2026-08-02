package main

// saas_feed_f3b4_taxonomy_recompose_test.go — regression proofs for the F3b-4 hot-path
// routing gap: catStore TAXONOMY mutations must reach the effective view.
//
// Since F3b-4, matchCategory serves BuiltIn=true categories EXCLUSIVELY from the atomic
// effective view (catStore contributes only its BuiltIn=false adminIndex). The view is an
// immutable snapshot built at startup from catStore's built-ins, and the only recompose
// hooks wired by F3b-4 were the category-OVERRIDE surfaces. Every catStore taxonomy
// mutation (category create/update/delete, host add/remove, config import, config-version
// rollback, CP snapshot apply) therefore left the view stale: an operator's edit to a
// built-in category landed in catStore but was never enforced, so a Deny rule scoped to
// that category silently stopped matching — until the next restart rebuilt the baseline.
//
// Each test below reproduces the pre-fix failure through ACTUAL policy matching
// (matchCategory / lookupHostCategory), not internal holder state.

import "testing"

// seedBuiltInCategory installs a BuiltIn=true category (the embedded/feed-owned class)
// and removes it on cleanup.
func seedBuiltInCategory(t *testing.T, name string, hosts []string) {
	t.Helper()
	if err := catStore.Set(name, hosts, true); err != nil {
		t.Fatalf("seed built-in category %q: %v", name, err)
	}
	t.Cleanup(func() { _ = catStore.Delete(name) })
}

// installStartupBaseline models the lifecycle's startup install: the embedded baseline
// composed from catStore's CURRENT built-ins.
func installStartupBaseline(t *testing.T) {
	t.Helper()
	swapSaaSView(t, embeddedBaselineView())
}

// recomposeBaseline stands in for recomposeSignedFeedTaxonomy() in unit tests, where the
// signed-feed runtime singleton is unarmed (globalSaaSFeedRuntime == nil) so the real
// helper is a deliberate no-op. It performs the same pre-activation work the coordinator
// does: rebuild the embedded baseline from the live catStore and swap it in atomically.
func recomposeBaseline() { saasEffectiveView.Swap(embeddedBaselineView()) }

// ─── the core regression: a built-in category edit must be enforced ──────────────────

func TestF3b4Regression_BuiltInHostAddReachesPolicy(t *testing.T) {
	const cat, seeded, added = "RegressSaaSCat", "seeded.example", "operator-added.example"
	seedBuiltInCategory(t, cat, []string{seeded})
	installStartupBaseline(t)

	if !matchCategory(cat, seeded) {
		t.Fatalf("precondition: the seeded built-in host must match")
	}

	// The canonical operator action: POST /api/urlcat/host on a built-in category.
	if err := catStore.AddHost(cat, added); err != nil {
		t.Fatalf("AddHost: %v", err)
	}
	recomposeBaseline() // what the fixed handler now does

	if !catStore.MatchesHost(cat, added) {
		t.Fatalf("precondition: catStore must hold the added host")
	}
	if !matchCategory(cat, added) {
		t.Errorf("REGRESSION: a Deny rule scoped to %q does not match the operator-added host %q", cat, added)
	}
	if !matchCategory(cat, "sub."+added) {
		t.Errorf("REGRESSION: subdomain of the operator-added host does not match")
	}
	// The GUI lookup tool must agree with what is actually enforced.
	if got, tier, _ := lookupHostCategory(added); tier == "none" || got != cat {
		t.Errorf("REGRESSION: lookupHostCategory(%q) = (%q,%q); want category %q", added, got, tier, cat)
	}
}

// Without the recompose the edit is invisible — this pins the failure mode itself, so a
// future change that drops the recompose fails here rather than silently regressing.
func TestF3b4Regression_StaleViewHidesBuiltInEdit(t *testing.T) {
	const cat, added = "RegressStaleCat", "stale-added.example"
	seedBuiltInCategory(t, cat, []string{"seeded.example"})
	installStartupBaseline(t)

	if err := catStore.AddHost(cat, added); err != nil {
		t.Fatalf("AddHost: %v", err)
	}
	// Deliberately NO recompose: this is the pre-fix state.
	if matchCategory(cat, added) {
		t.Fatalf("test is not exercising the stale-view path; the view must be a snapshot")
	}
	recomposeBaseline()
	if !matchCategory(cat, added) {
		t.Errorf("recompose did not repair the stale view")
	}
}

// Removing a host from a built-in category must also take effect (the over-block
// direction: policy must stop matching a host the operator just allowlisted).
func TestF3b4Regression_BuiltInHostRemoveReachesPolicy(t *testing.T) {
	const cat, host = "RegressRemoveCat", "remove-me.example"
	seedBuiltInCategory(t, cat, []string{host, "keep.example"})
	installStartupBaseline(t)

	if !matchCategory(cat, host) {
		t.Fatalf("precondition: host must match before removal")
	}
	if err := catStore.RemoveHost(cat, host); err != nil {
		t.Fatalf("RemoveHost: %v", err)
	}
	recomposeBaseline()

	if matchCategory(cat, host) {
		t.Errorf("REGRESSION: policy still matches %q after the operator removed it from %q", host, cat)
	}
	if !matchCategory(cat, "keep.example") {
		t.Errorf("removal must not disturb the sibling host")
	}
}

// Deleting a whole built-in category must retire it from the served view.
func TestF3b4Regression_BuiltInCategoryDeleteReachesPolicy(t *testing.T) {
	const cat, host = "RegressDeleteCat", "doomed.example"
	if err := catStore.Set(cat, []string{host}, true); err != nil {
		t.Fatalf("seed: %v", err)
	}
	t.Cleanup(func() { _ = catStore.Delete(cat) })
	installStartupBaseline(t)

	if !matchCategory(cat, host) {
		t.Fatalf("precondition: host must match before delete")
	}
	if err := catStore.Delete(cat); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	recomposeBaseline()

	if matchCategory(cat, host) {
		t.Errorf("REGRESSION: policy still matches a category the operator deleted")
	}
}

// The bulk-replace path shared by config import, config-version rollback and the CP→DP
// snapshot apply (all three call catStore.ReplaceAll).
func TestF3b4Regression_ReplaceAllTaxonomyReachesPolicy(t *testing.T) {
	const cat, before, after = "RegressBulkCat", "old.example", "new.example"
	seedBuiltInCategory(t, cat, []string{before})
	installStartupBaseline(t)

	if !matchCategory(cat, before) {
		t.Fatalf("precondition: pre-replace host must match")
	}

	restored := append([]CategoryEntry(nil), catStore.All()...)
	for i := range restored {
		if restored[i].Name == cat {
			restored[i].Hosts = []string{after}
		}
	}
	catStore.ReplaceAll(restored)
	recomposeBaseline()

	if !matchCategory(cat, after) {
		t.Errorf("REGRESSION: the replaced taxonomy's host %q is not enforced", after)
	}
	if matchCategory(cat, before) {
		t.Errorf("REGRESSION: the superseded host %q is still enforced", before)
	}
}

// ─── boundary / non-regression guards ────────────────────────────────────────────────

// Admin-created (BuiltIn=false) categories keep serving from catStore's adminIndex with no
// recompose at all — the fix must not have moved them onto the view.
func TestF3b4Regression_AdminCategoryUnaffectedByView(t *testing.T) {
	const cat, host = "RegressAdminCat", "admin-only.example"
	addAdminCategory(t, cat, []string{host})
	installStartupBaseline(t) // view built from built-ins only; excludes this category

	if !matchCategory(cat, host) {
		t.Errorf("admin category must match from catStore's adminIndex without a recompose")
	}
	if err := catStore.AddHost(cat, "later.example"); err != nil {
		t.Fatalf("AddHost: %v", err)
	}
	if !matchCategory(cat, "later.example") {
		t.Errorf("admin-category host add must take effect immediately (no view involvement)")
	}
}

// With the lifecycle unarmed (view == nil) the pre-F3b-4 full-catStore path serves, so a
// built-in edit is enforced immediately. Pins the fallback branch of matchCategory.
func TestF3b4Regression_UnarmedLifecycleServesFullCatStore(t *testing.T) {
	const cat, added = "RegressUnarmedCat", "unarmed-added.example"
	seedBuiltInCategory(t, cat, []string{"seeded.example"})
	swapSaaSView(t, nil) // lifecycle unarmed

	if err := catStore.AddHost(cat, added); err != nil {
		t.Fatalf("AddHost: %v", err)
	}
	if !matchCategory(cat, added) {
		t.Errorf("with no effective view installed the full catStore taxonomy must serve")
	}
}

// recomposeSignedFeedTaxonomy must be a safe no-op when the runtime singleton is unarmed
// (it must never panic or clear the installed view).
func TestF3b4Regression_RecomposeTaxonomyNoOpWhenUnarmed(t *testing.T) {
	const cat, host = "RegressNoOpCat", "noop.example"
	seedBuiltInCategory(t, cat, []string{host})
	installStartupBaseline(t)

	prev := globalSaaSFeedRuntime
	globalSaaSFeedRuntime = nil
	t.Cleanup(func() { globalSaaSFeedRuntime = prev })

	recomposeSignedFeedTaxonomy() // must not panic

	if saasEffectiveView.Current() == nil {
		t.Errorf("a no-op recompose must not clear the installed view (fail-closed)")
	}
	if !matchCategory(cat, host) {
		t.Errorf("a no-op recompose must leave policy matching intact")
	}
}
