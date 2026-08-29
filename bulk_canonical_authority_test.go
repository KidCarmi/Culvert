package main

// bulk_canonical_authority_test.go — final 2D-B bulk canonicalization +
// effective-authority proofs (red families §12.1–§12.5 against f29f652d).
//
// BLOCKER A (§§1–3): the import candidate validator used to judge the
// INCOMING rules as submitted — accepting a reference when the NAME or the
// client-supplied ID resolved — while importPolicyRules later discards the
// IDs and re-derives them from the names (stampObjectRefIDs). A hand-edited
// backup naming a MISSING group/profile while smuggling a valid unrelated
// object's ID therefore passed pre-validation and landed a dangling rule.
// The validator now judges the rule the import will ACTUALLY install:
// incoming rules are canonicalized against the CANDIDATE object sets
// (canonicalizeCandidateRuleRefs — name is intent, IDs server-derived), and
// untouched live rules keep their ID-authoritative semantics.
//
// BLOCKER B (§§4–8): the category closure used to treat every candidate
// URLCategories row as authority regardless of BuiltIn, and unioned the
// CURRENT effective view rather than the POST-APPLY one. It now previews the
// post-apply authority: per-source BuiltIn rules (§8) and the candidate
// override set composed over the RAW pre-override base via the runtime's own
// pure seams (catoverride.ComposeMembership over view.baseClasses / the
// candidate BuiltIn baseline).

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/catoverride"
)

// bulkCanonSetup isolates the stores the 200-path imports mutate and seeds
// the gate objects (refGateSetup) into the ISOLATED taxonomy stores.
func bulkCanonSetup(t *testing.T) {
	t.Helper()
	refGateSetup(t)
	csrTaxIsolate(t) // fresh cat/group/dpi/config-version stores — re-seed below
	snapshotBlocklistGlobals(t)
	prevOv := globalCategoryOverrides
	globalCategoryOverrides = catoverride.New()
	t.Cleanup(func() { globalCategoryOverrides = prevOv })
	catStore.ReplaceAll([]CategoryEntry{{Name: "gate-cat", Hosts: []string{"gc.example.com"}}})
	globalCategoryGroups.ReplaceAll([]CategoryGroup{{Name: "gate-group", Categories: []string{"gate-cat"}}})
	prevView := saasEffectiveView.Swap(nil)
	t.Cleanup(func() { saasEffectiveView.Swap(prevView) })
}

func canonImportBackup(t *testing.T, mode string, b *configBackup) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	apiConfigImport(w, jsonReq("POST", "/api/config/import?mode="+mode, b))
	// apiConfigImport fires a DETACHED adminSettingsSave goroutine that reads
	// package globals; drain it before returning so a caller's t.Cleanup
	// restores can never race it (caught by -race on the 2D-C import tests).
	adminSettingsSaveWG.Wait()
	return w
}

func installedRuleByName(name string) *PolicyRule {
	for _, r := range policyStore.List() {
		if r.Name == name {
			cp := r
			return &cp
		}
	}
	return nil
}

// ─── Blocker A: import ID-trust (§3-A/B/C, red families 1–2) ───────────────

// TestImportIDTrust_GroupIDSmuggling: a backup rule naming a MISSING group
// while carrying a valid unrelated group's ID must refuse the WHOLE import in
// both modes — pre-validation must judge the post-canonical rule, in which
// the client ID no longer exists.
func TestImportIDTrust_GroupIDSmuggling(t *testing.T) {
	for _, mode := range []string{"merge", "replace"} {
		t.Run(mode, func(t *testing.T) {
			bulkCanonSetup(t)
			realID := trustGroupID(t, "gate-group")

			w := canonImportBackup(t, mode, &configBackup{
				Version: 1,
				PolicyRules: []PolicyRule{{
					Name: "smuggle-g", Action: ActionDrop, Priority: 7,
					DestCategoryGroup: "MISSING", DestCategoryGroupID: realID,
				}},
			})
			if w.Code/100 == 2 {
				t.Fatalf("IMPORT ID-SMUGGLING: a valid unrelated group ID satisfied pre-validation for an unresolvable name (%d) — the import then discards the ID and lands a dangling DROP rule", w.Code)
			}
			if w.Code != 400 || !strings.Contains(w.Body.String(), "MISSING") {
				t.Fatalf("want 400 naming the dangling reference, got %d: %s", w.Code, w.Body.String())
			}
			if installedRuleByName("smuggle-g") != nil {
				t.Fatal("refused import must install nothing")
			}
		})
	}
}

// TestImportIDTrust_ProfileIDSmuggling: the decryption-profile edge, same
// trust boundary.
func TestImportIDTrust_ProfileIDSmuggling(t *testing.T) {
	bulkCanonSetup(t)
	globalDecryptionProfiles.ReplaceAll([]DecryptionProfile{{Name: "gate-prof"}})
	p := globalDecryptionProfiles.GetByName("gate-prof")
	if p == nil {
		t.Fatal("gate-prof not seeded")
	}

	w := canonImportBackup(t, "merge", &configBackup{
		Version: 1,
		PolicyRules: []PolicyRule{{
			Name: "smuggle-p", Action: ActionAllow, Priority: 7,
			DecryptionProfile: "MISSING", DecryptionProfileID: p.ID,
		}},
	})
	if w.Code/100 == 2 {
		t.Fatalf("IMPORT ID-SMUGGLING: a valid unrelated profile ID satisfied pre-validation for an unresolvable name (%d)", w.Code)
	}
	if w.Code != 400 || !strings.Contains(w.Body.String(), "MISSING") {
		t.Fatalf("want 400 naming the dangling reference, got %d: %s", w.Code, w.Body.String())
	}
}

// TestImportIDTrust_MismatchedPairBindsToTheName (§3-D, control): a REAL name
// paired with a DIFFERENT real object's ID imports successfully and binds to
// the NAME's object — name is intent; the client ID is ignored, not an error.
func TestImportIDTrust_MismatchedPairBindsToTheName(t *testing.T) {
	bulkCanonSetup(t)
	globalCategoryGroups.ReplaceAll([]CategoryGroup{
		{Name: "gate-group", Categories: []string{"gate-cat"}},
		{Name: "other-group", Categories: []string{"gate-cat"}},
	})
	aID := trustGroupID(t, "gate-group")
	bID := trustGroupID(t, "other-group")

	w := canonImportBackup(t, "merge", &configBackup{
		Version: 1,
		PolicyRules: []PolicyRule{{
			Name: "mismatch", Action: ActionAllow, Priority: 7,
			DestCategoryGroup: "gate-group", DestCategoryGroupID: bID,
		}},
	})
	if w.Code != 200 {
		t.Fatalf("mismatched pair must import and bind to the name, got %d: %s", w.Code, w.Body.String())
	}
	got := installedRuleByName("mismatch")
	if got == nil || got.DestCategoryGroupID != aID {
		t.Fatalf("installed rule must bind to the NAME's object ID %s; got %+v", aID, got)
	}
}

// TestImportIDTrust_SameImportObjectResolves (§3-E, control): a rule whose
// referenced group/profile is supplied by the SAME import must validate
// against the CANDIDATE object (not live yet) and, once installed, bind to
// the installed object's ID.
func TestImportIDTrust_SameImportObjectResolves(t *testing.T) {
	bulkCanonSetup(t)

	w := canonImportBackup(t, "merge", &configBackup{
		Version:            1,
		URLCategories:      []CategoryEntry{{Name: "new-cat", Hosts: []string{"nc.example.com"}}},
		CategoryGroups:     []CategoryGroup{{Name: "new-group", Categories: []string{"new-cat"}}},
		DecryptionProfiles: []DecryptionProfile{{Name: "new-prof"}},
		PolicyRules: []PolicyRule{{
			Name: "uses-new", Action: ActionAllow, Priority: 7,
			DestCategoryGroup: "new-group", DecryptionProfile: "new-prof",
		}},
	})
	if w.Code != 200 {
		t.Fatalf("same-import object references must validate against the candidate, got %d: %s", w.Code, w.Body.String())
	}
	g := globalCategoryGroups.GetByName("new-group")
	p := globalDecryptionProfiles.GetByName("new-prof")
	got := installedRuleByName("uses-new")
	if g == nil || p == nil || got == nil {
		t.Fatalf("import must install the candidate objects and rule (group=%v prof=%v rule=%v)", g, p, got)
	}
	if got.DestCategoryGroupID != g.ID || got.DecryptionProfileID != p.ID {
		t.Fatalf("installed rule must carry the INSTALLED objects' IDs (%s/%s); got %+v", g.ID, p.ID, got)
	}
}

// ─── Blocker B: post-apply category authority (§§4–8, red families 3–5) ────

// installDownloadedView installs a deterministic signed (downloaded) view
// whose RAW pre-override base equals the given classes (no current overrides
// composed), and pins restoration.
func installDownloadedView(t *testing.T, base map[string]string) {
	t.Helper()
	prev := saasEffectiveView.Swap(newEffectiveView(base,
		effectiveCategoryView{Source: sourceDownloaded, FeedVersion: 11}))
	t.Cleanup(func() { saasEffectiveView.Swap(prev) })
}

// TestBulkAuthority_BuiltInOnlyCategoryUnderSignedView (red family 3): under
// a downloaded view NOT serving "Legacy-SaaS", a bulk candidate carrying a
// BuiltIn=true "Legacy-SaaS" row plus a DROP rule referencing it must refuse
// — after apply, the runtime does not serve that BuiltIn category (the admin
// tier is BuiltIn=false only and the signed view owns the rest), so the rule
// would never match. Proven on the import AND the CP snapshot candidate.
func TestBulkAuthority_BuiltInOnlyCategoryUnderSignedView(t *testing.T) {
	t.Run("import", func(t *testing.T) {
		bulkCanonSetup(t)
		installDownloadedView(t, map[string]string{"svc.example.com": "AI"})

		w := canonImportBackup(t, "merge", &configBackup{
			Version:       1,
			URLCategories: []CategoryEntry{{Name: "Legacy-SaaS", Hosts: []string{"legacy.example.com"}, BuiltIn: true}},
			PolicyRules: []PolicyRule{{
				Name: "drop-legacy", Action: ActionDrop, Priority: 7, DestCategory: "Legacy-SaaS",
			}},
		})
		if w.Code/100 == 2 {
			t.Fatalf("BUILTIN-ONLY FALSE ACCEPTANCE: a candidate BuiltIn=true category the signed authority does not serve validated a DROP rule (%d) — after apply the rule never matches", w.Code)
		}
		if w.Code != 400 || !strings.Contains(w.Body.String(), "Legacy-SaaS") {
			t.Fatalf("want 400 naming the category, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("snapshot", func(t *testing.T) {
		bulkCanonSetup(t)
		installDownloadedView(t, map[string]string{"svc.example.com": "AI"})

		snap := ConfigSnapshot{
			Version:       5,
			URLCategories: []CategoryEntry{{Name: "Legacy-SaaS", Hosts: []string{"legacy.example.com"}, BuiltIn: true}},
			PolicyRules: []PolicyRule{{
				Name: "drop-legacy", Action: ActionDrop, Priority: 1, DestCategory: "Legacy-SaaS",
			}},
		}
		if err := validateConfigSnapshot(snap); err == nil {
			t.Fatal("BUILTIN-ONLY FALSE ACCEPTANCE: the snapshot validator accepted a BuiltIn=true category the signed authority does not serve")
		}
	})
}

// TestBulkAuthority_OverrideIntroducedCategoryAccepted (red family 4): a
// candidate override recategorizes a host into a NEW category and a candidate
// rule references it. The post-apply view serves the name, so the candidate
// is VALID — the old validator falsely refused it because the CURRENT
// pre-import view does not carry the name.
func TestBulkAuthority_OverrideIntroducedCategoryAccepted(t *testing.T) {
	bulkCanonSetup(t)
	installDownloadedView(t, map[string]string{"svc.example.com": "AI"})

	ov := CategoryOverrides{Recategorized: map[string]string{"svc.example.com": "CustomCategory"}}
	w := canonImportBackup(t, "merge", &configBackup{
		Version:           1,
		CategoryOverrides: &ov,
		PolicyRules: []PolicyRule{{
			Name: "uses-custom", Action: ActionAllow, Priority: 7, DestCategory: "CustomCategory",
		}},
	})
	if w.Code != 200 {
		t.Fatalf("POST-APPLY FALSE REFUSAL: the candidate override makes CustomCategory a served class after apply, but the import was refused: %d %s", w.Code, w.Body.String())
	}
	if installedRuleByName("uses-custom") == nil {
		t.Fatal("accepted import must install the rule")
	}
}

// TestBulkAuthority_OverrideTombstoneRemovesLastInstance (red family 5): a
// candidate override tombstones the ONLY host of a served category while a
// candidate DROP rule references that category. The post-apply view no longer
// serves the name, so the candidate must refuse — the old validator approved
// it off the CURRENT (pre-tombstone) view.
func TestBulkAuthority_OverrideTombstoneRemovesLastInstance(t *testing.T) {
	t.Run("import", func(t *testing.T) {
		bulkCanonSetup(t)
		installDownloadedView(t, map[string]string{"only.example.com": "FeedOnlyCat"})

		ov := CategoryOverrides{Tombstones: []string{"only.example.com"}}
		w := canonImportBackup(t, "merge", &configBackup{
			Version:           1,
			CategoryOverrides: &ov,
			PolicyRules: []PolicyRule{{
				Name: "drop-feedonly", Action: ActionDrop, Priority: 7, DestCategory: "FeedOnlyCat",
			}},
		})
		if w.Code/100 == 2 {
			t.Fatalf("POST-APPLY FALSE ACCEPTANCE: the candidate tombstone removes FeedOnlyCat's last instance, yet the DROP rule referencing it was accepted (%d)", w.Code)
		}
		if w.Code != 400 || !strings.Contains(w.Body.String(), "FeedOnlyCat") {
			t.Fatalf("want 400 naming the category, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("snapshot", func(t *testing.T) {
		bulkCanonSetup(t)
		installDownloadedView(t, map[string]string{"only.example.com": "FeedOnlyCat"})

		snap := ConfigSnapshot{
			Version:           5,
			URLCategories:     []CategoryEntry{},
			CategoryOverrides: &CategoryOverrides{Tombstones: []string{"only.example.com"}},
			PolicyRules: []PolicyRule{{
				Name: "drop-feedonly", Action: ActionDrop, Priority: 1, DestCategory: "FeedOnlyCat",
			}},
		}
		if err := validateConfigSnapshot(snap); err == nil {
			t.Fatal("POST-APPLY FALSE ACCEPTANCE: the snapshot validator approved a category its own override set removes from the post-apply view")
		}

		// Control (family-4 shape on the snapshot path): the same snapshot
		// with an override INTRODUCING the referenced category is valid.
		snap.CategoryOverrides = &CategoryOverrides{Recategorized: map[string]string{"only.example.com": "FeedOnlyCat"}}
		if err := validateConfigSnapshot(snap); err != nil {
			t.Fatalf("an override-introduced post-apply category must validate on the snapshot path, got: %v", err)
		}
	})
}

// TestBulkAuthority_PreviewComposesOverRawBase (§7 control): the preview must
// compose the CANDIDATE override set over the RAW pre-override base, never
// over the already-composed current view. A view currently serving
// "Custom-Old" via an override reverts to its raw base classes when the
// candidate REPLACES the override set with an empty one.
func TestBulkAuthority_PreviewComposesOverRawBase(t *testing.T) {
	prev := saasEffectiveView.Swap(newEffectiveView(
		map[string]string{"svc.example.com": "Custom-Old"}, // composed (current override applied)
		effectiveCategoryView{
			Source: sourceDownloaded, FeedVersion: 11,
			base: map[string]string{"svc.example.com": "AI"}, // raw signed base
		}))
	t.Cleanup(func() { saasEffectiveView.Swap(prev) })

	ok := postApplyCategoryClosure(nil, CategoryOverrides{}) // candidate wipes the overrides
	if !ok("AI") {
		t.Fatal("wiping the overrides restores the RAW base class — AI must resolve")
	}
	if ok("Custom-Old") {
		t.Fatal("DOUBLE-APPLY: the retired current override's category survived a candidate override wipe — the preview composed over the already-composed view")
	}
}
