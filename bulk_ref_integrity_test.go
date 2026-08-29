package main

// bulk_ref_integrity_test.go — bulk candidate reference-integrity + whole-
// snapshot proofs (final 2D-B correction §§14–20, red families F/G/H).
//
// The bulk installers (config import, config-version rollback, CP→DP
// ConfigSnapshot apply) install whole object graphs at once. Their leaf-first
// apply order guarantees ORDERING, not RESOLVABILITY: at the prior candidate
// a candidate whose rule referenced a category group / decryption profile /
// category the candidate did not define (and no authority resolves) landed
// silently — a DENY/DROP rule that never matches, behind a 2xx. And the
// CP→DP apply rejected an over-cap URL-category slice ALONE
// (ReplaceAllChecked), so one 10,001-host category made a snapshot apply
// MIXED — new rulebase against the old taxonomy (§19).

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestBulkRef_ImportRefusesDanglingGroupRef (family F): an import whose
// effective candidate carries a rule referencing a category group that
// resolves nowhere is refused WHOLE (400), before any store mutation — in
// both modes.
func TestBulkRef_ImportRefusesDanglingGroupRef(t *testing.T) {
	for _, mode := range []string{"merge", "replace"} {
		t.Run(mode, func(t *testing.T) {
			refGateSetup(t)
			csrTaxIsolate(t)
			policyStore.ReplaceAll([]PolicyRule{{Name: "live-rule", Action: ActionAllow, Priority: 1}})

			backup := &configBackup{
				Version: 1,
				PolicyRules: []PolicyRule{
					{Name: "imported", Action: ActionDrop, Priority: 2, DestCategoryGroup: "MISSING"},
				},
			}
			w := httptest.NewRecorder()
			apiConfigImport(w, jsonReq("POST", "/api/config/import?mode="+mode, backup))
			if w.Code/100 == 2 {
				t.Fatalf("BULK DANGLING REFERENCE: import carrying a rule referencing missing group landed with %d — a DENY rule that never matches", w.Code)
			}
			if w.Code != 400 || !strings.Contains(w.Body.String(), "MISSING") {
				t.Fatalf("want a 400 naming the dangling reference, got %d: %s", w.Code, w.Body.String())
			}
			for _, r := range policyStore.List() {
				if r.Name == "imported" {
					t.Fatal("refused import must mutate nothing, but the imported rule landed")
				}
			}
		})
	}
}

// TestBulkRef_ImportRefusesStrandingALiveRule (family F, replace-mode
// stranding): a replace-mode taxonomy/group import that would leave an
// UNTOUCHED live rule referencing a group the new object set no longer
// defines is refused whole — the effective candidate is live rules + incoming
// objects, and its graph dangles.
func TestBulkRef_ImportRefusesStrandingALiveRule(t *testing.T) {
	refGateSetup(t)
	csrTaxIsolate(t) // fresh stores — re-seed the referenced objects below
	prev := saasEffectiveView.Swap(nil)
	t.Cleanup(func() { saasEffectiveView.Swap(prev) })
	catStore.ReplaceAll([]CategoryEntry{{Name: "gate-cat", Hosts: []string{"gc.example.com"}}})
	globalCategoryGroups.ReplaceAll([]CategoryGroup{{Name: "gate-group", Categories: []string{"gate-cat"}}})
	policyStore.ReplaceAll([]PolicyRule{
		{Name: "live-deny", Action: ActionDrop, Priority: 1, DestCategoryGroup: "gate-group"},
	})

	backup := &configBackup{
		Version:        1,
		URLCategories:  []CategoryEntry{{Name: "other-cat", Hosts: []string{"oc.example.com"}}},
		CategoryGroups: []CategoryGroup{{Name: "other-group", Categories: []string{"other-cat"}}},
	}
	w := httptest.NewRecorder()
	apiConfigImport(w, jsonReq("POST", "/api/config/import?mode=replace", backup))
	if w.Code/100 == 2 {
		t.Fatalf("BULK STRANDED REFERENCE: replace-mode object import landed with %d while a live DENY rule references the removed group", w.Code)
	}
	if w.Code != 400 {
		t.Fatalf("want 400, got %d: %s", w.Code, w.Body.String())
	}
	if globalCategoryGroups.GetByName("gate-group") == nil {
		t.Fatal("refused import must leave the live groups unchanged")
	}
}

// TestBulkRef_RollbackRefusesDanglingGroupRef (§17): a historical config
// version whose captured candidate carries a dangling rule→group reference
// (seeded through the pre-correction engine-level path, like the legacy
// over-cap capture) is refused WHOLE — truthful 400, nothing applied.
func TestBulkRef_RollbackRefusesDanglingGroupRef(t *testing.T) {
	refGateSetup(t)
	csrTaxIsolate(t)
	prev := saasEffectiveView.Swap(nil)
	t.Cleanup(func() { saasEffectiveView.Swap(prev) })

	// Simulate a legacy capture: the dangling reference reached the live store
	// through a pre-correction bulk path, and a config version captured it.
	policyStore.ReplaceAll([]PolicyRule{
		{Name: "legacy-deny", Action: ActionDrop, Priority: 1, DestCategoryGroup: "long-gone"},
	})
	saveConfigVersion("bulk-ref-test", "seed-dangling")
	versions := configVersions.List()
	if len(versions) == 0 {
		t.Fatal("no config version captured")
	}
	target := versions[len(versions)-1].Version

	// The live store has since been repaired.
	policyStore.ReplaceAll([]PolicyRule{{Name: "clean", Action: ActionAllow, Priority: 1}})

	w := httptest.NewRecorder()
	apiConfigVersions(w, jsonReq("POST", "/api/config/versions", map[string]any{"version": target}))
	if w.Code/100 == 2 {
		t.Fatalf("BULK DANGLING REFERENCE: rollback restoring a rule referencing missing group %q landed with %d", "long-gone", w.Code)
	}
	if w.Code != 400 || !strings.Contains(w.Body.String(), "rollback refused") {
		t.Fatalf("want the explicit rollback refusal, got %d: %s", w.Code, w.Body.String())
	}
	rules := policyStore.List()
	if len(rules) != 1 || rules[0].Name != "clean" {
		t.Fatalf("refused rollback must apply nothing; live rules = %+v", rules)
	}
}

// TestBulkRef_SnapshotRejectsDanglingGroupRef (family G): a CP→DP
// ConfigSnapshot carrying BOTH sides of the rule→group edge with a dangling
// reference is rejected as a WHOLE snapshot — validateConfigSnapshot errors
// and applyConfigSnapshot mutates nothing.
func TestBulkRef_SnapshotRejectsDanglingGroupRef(t *testing.T) {
	refGateSetup(t)
	prev := saasEffectiveView.Swap(nil)
	t.Cleanup(func() { saasEffectiveView.Swap(prev) })
	policyStore.ReplaceAll([]PolicyRule{{Name: "keep", Action: ActionAllow, Priority: 1}})

	snap := ConfigSnapshot{
		Version: 7,
		PolicyRules: []PolicyRule{
			{Name: "synced-deny", Action: ActionDrop, Priority: 1, DestCategoryGroup: "MISSING"},
		},
		CategoryGroups: []CategoryGroup{{Name: "other-group", Categories: []string{"gate-cat"}}},
		URLCategories:  []CategoryEntry{{Name: "gate-cat", Hosts: []string{"gc.example.com"}}},
	}
	if err := validateConfigSnapshot(snap); err == nil {
		t.Fatal("SNAPSHOT DANGLING REFERENCE: validateConfigSnapshot accepted a rule→group reference the snapshot does not define")
	}
	if err := applyConfigSnapshot(snap); err == nil {
		t.Fatal("applyConfigSnapshot must reject the whole snapshot")
	}
	rules := policyStore.List()
	if len(rules) != 1 || rules[0].Name != "keep" {
		t.Fatalf("rejected snapshot must apply nothing; live rules = %+v", rules)
	}
	if globalCategoryGroups.GetByName("other-group") != nil {
		t.Fatal("rejected snapshot must not install its category groups")
	}
}

// TestBulkRef_SnapshotBothSidesRequired pins the deterministic scoping: a
// snapshot carrying rules but NOT category groups leaves the DP's live groups
// in place, so the rule→group edge is not self-contained and must NOT be
// guessed against transient DP state.
func TestBulkRef_SnapshotBothSidesRequired(t *testing.T) {
	snap := ConfigSnapshot{
		Version: 3,
		PolicyRules: []PolicyRule{
			{Name: "r", Action: ActionAllow, Priority: 1, DestCategoryGroup: "resolved-live-on-the-dp"},
		},
	}
	if err := validateConfigSnapshot(snap); err != nil {
		t.Fatalf("group edge without a carried group slice must not be judged, got: %v", err)
	}
}

// TestBulkRef_SnapshotOverCapCategoryRejectsWholeSnapshot (family H, §§19–20):
// a snapshot carrying a NEW rulebase, a default-action change, a blocklist,
// and ONE over-cap (10,001-host) category must apply NOTHING — at the prior
// candidate only the URL-category slice was rejected (ReplaceAllChecked) and
// the rest applied, leaving the new policy enforced against the old taxonomy.
func TestBulkRef_SnapshotOverCapCategoryRejectsWholeSnapshot(t *testing.T) {
	refGateSetup(t)
	snapshotBlocklistGlobals(t)
	prevAction := defaultPolicyAction()
	setDefaultPolicyAction("deny")
	t.Cleanup(func() { setDefaultPolicyAction(prevAction) })
	policyStore.ReplaceAll([]PolicyRule{{Name: "old-rule", Action: ActionAllow, Priority: 1}})
	catStore.ReplaceAll([]CategoryEntry{{Name: "old-cat", Hosts: []string{"old.example.com"}}})

	over := make([]string, 10001)
	for i := range over {
		over[i] = fmt.Sprintf("h%05d.flood.example", i)
	}
	snap := ConfigSnapshot{
		Version:       9,
		PolicyRules:   []PolicyRule{{Name: "new-rule", Action: ActionAllow, Priority: 1}},
		URLCategories: []CategoryEntry{{Name: "flood", Hosts: over}},
		DefaultAction: "allow",
		BlockedHosts:  []string{"synced-bad.example.com"},
	}
	err := applyConfigSnapshot(snap)
	if err == nil {
		t.Fatal("MIXED SNAPSHOT APPLY: an over-cap category must reject the WHOLE snapshot (version unacknowledged), not just the taxonomy slice")
	}
	rules := policyStore.List()
	if len(rules) != 1 || rules[0].Name != "old-rule" {
		t.Fatalf("policy slice must not apply from a rejected snapshot; live rules = %+v", rules)
	}
	if names := listCategoryNames(t); len(names) != 1 || names[0] != "old-cat" {
		t.Fatalf("taxonomy must be unchanged; live categories = %v", names)
	}
	if got := defaultPolicyAction(); got != "deny" {
		t.Fatalf("default action must be unchanged, got %q", got)
	}
	if bl.IsBlocked("synced-bad.example.com") {
		t.Fatal("blocklist slice must not apply from a rejected snapshot")
	}
}

// TestBulkRef_ValidatorAdmitsAuthorityLayers pins the category closure's
// non-goals: a candidate-carried BuiltIn name, a signed-view class, and a
// UT1-mapped name are all legitimate reference targets — the bulk gate judges
// dangling-ness, and a name any current authority serves is not dangling.
func TestBulkRef_ValidatorAdmitsAuthorityLayers(t *testing.T) {
	prev := saasEffectiveView.Swap(newEffectiveView(map[string]string{"svc.example.com": "AI"},
		effectiveCategoryView{Source: sourceDownloaded, FeedVersion: 4}))
	t.Cleanup(func() { saasEffectiveView.Swap(prev) })

	ok := bulkCategoryClosure([]CategoryEntry{{Name: "Candidate-Cat", BuiltIn: true}})
	if !ok("candidate-cat") {
		t.Fatal("candidate-carried name (case-insensitive) must resolve")
	}
	if !ok("AI") {
		t.Fatal("a class served by the live signed view must resolve")
	}
	if ok("definitely-not-anywhere") {
		t.Fatal("a name no authority serves must not resolve")
	}
}
