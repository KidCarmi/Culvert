package main

// config_import_preview_test.go — coverage for the import dry-run/preview
// endpoint (?dryRun=true on POST /api/config/import, P2 import-preview,
// POLICY-ARCHITECTURE-FUTURE §6).
//
// Contract pinned here:
//   - dry-run returns 200 with {dryRun:true, mode, sections, settings};
//   - dry-run mutates NOTHING (the whole point — it's the safety gate an
//     admin sees BEFORE committing a potentially destructive replace import);
//   - section counts (incoming + current) and effect strings reflect the mode;
//   - absent/empty sections are omitted (import never wipes on absence);
//   - scalar settings are surfaced.

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

type importPreviewResp struct {
	DryRun     bool                   `json:"dryRun"`
	Mode       string                 `json:"mode"`
	ExportedAt string                 `json:"exportedAt"`
	Sections   []importPreviewSection `json:"sections"`
	Settings   []importPreviewSetting `json:"settings"`
}

func importPreview(t *testing.T, path string, backup map[string]any) importPreviewResp {
	t.Helper()
	w := httptest.NewRecorder()
	apiConfigImport(w, jsonReq("POST", path, backup))
	assertStatus(t, w, 200)
	var resp importPreviewResp
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode preview: %v", err)
	}
	if !resp.DryRun {
		t.Fatalf("preview: dryRun = false; want true")
	}
	return resp
}

func previewSection(resp importPreviewResp, name string) (importPreviewSection, bool) {
	for _, s := range resp.Sections {
		if s.Section == name {
			return s, true
		}
	}
	return importPreviewSection{}, false
}

// TestImportPreview_MergeCountsAndEffect: a merge-mode preview reports the
// incoming/current counts and, for policy rules, the upsert-split effect
// ("upsert N: X update, Y add") plus the upsert note (merge no longer
// accumulates duplicates).
func TestImportPreview_MergeCountsAndEffect(t *testing.T) {
	csrTaxIsolate(t)
	snapshotPolicyStoreForTest(t)
	policyStore.ReplaceAll([]PolicyRule{{Name: "existing-1"}, {Name: "existing-2"}})
	catStore.ReplaceAll([]CategoryEntry{{Name: "seed-cat"}})

	resp := importPreview(t, "/api/config/import?dryRun=true", map[string]any{
		"version":    1,
		"exportedAt": "2026-02-02T00:00:00Z",
		"policyRules": []map[string]any{
			{"name": "imp-a", "action": "allow"},
			{"name": "imp-b", "action": "allow"},
			{"name": "imp-c", "action": "allow"},
		},
		"urlCategories": []map[string]any{{"name": "imp-cat"}},
	})

	if resp.Mode != "merge" {
		t.Errorf("mode = %q; want merge", resp.Mode)
	}
	pol, ok := previewSection(resp, "Policy Rules")
	if !ok {
		t.Fatalf("preview missing Policy Rules section: %+v", resp.Sections)
	}
	if pol.Incoming != 3 || pol.Current != 2 {
		t.Errorf("policy counts = incoming %d current %d; want 3/2", pol.Incoming, pol.Current)
	}
	// Merge now upserts by identity: the 3 incoming rules are all new names
	// (no id, no name match against existing-1/2), so the split is 0 update / 3 add.
	if !strings.Contains(pol.Effect, "upsert 3: 0 update, 3 add") {
		t.Errorf("policy effect = %q; want 'upsert 3: 0 update, 3 add'", pol.Effect)
	}
	if !strings.Contains(pol.Note, "upsert") {
		t.Errorf("policy merge note = %q; want mention of upsert", pol.Note)
	}
	cat, ok := previewSection(resp, "URL Categories")
	if !ok || cat.Incoming != 1 || cat.Current != 1 {
		t.Errorf("URL Categories section = %+v ok=%v; want incoming 1 current 1", cat, ok)
	}
	if !strings.Contains(cat.Note, "upsert") {
		t.Errorf("category merge note = %q; want mention of upsert", cat.Note)
	}
}

// TestImportPreview_ReplaceEffect: a replace-mode preview reports a
// "replace M existing with N incoming" effect and carries no merge note.
func TestImportPreview_ReplaceEffect(t *testing.T) {
	snapshotPolicyStoreForTest(t)
	snapshotConfigVersionsDir(t)
	policyStore.ReplaceAll([]PolicyRule{{Name: "old-1"}, {Name: "old-2"}, {Name: "old-3"}})

	resp := importPreview(t, "/api/config/import?dryRun=true&mode=replace", map[string]any{
		"version":    1,
		"exportedAt": "2026-02-02T00:00:00Z",
		"policyRules": []map[string]any{
			{"name": "new-1", "action": "deny"},
		},
	})
	if resp.Mode != "replace" {
		t.Errorf("mode = %q; want replace", resp.Mode)
	}
	pol, ok := previewSection(resp, "Policy Rules")
	if !ok {
		t.Fatalf("preview missing Policy Rules section")
	}
	if !strings.Contains(pol.Effect, "replace 3 existing with 1 incoming") {
		t.Errorf("policy effect = %q; want 'replace 3 existing with 1 incoming'", pol.Effect)
	}
	if pol.Note != "" {
		t.Errorf("replace-mode policy note = %q; want empty", pol.Note)
	}
}

// TestImportPreview_MutatesNothing is the load-bearing safety test: a
// replace-mode dry-run against a payload that WOULD wipe every store must
// leave live state exactly as it was.
func TestImportPreview_MutatesNothing(t *testing.T) {
	csrTaxIsolate(t)
	snapshotPolicyStoreForTest(t)
	snapshotBL(t)

	policyStore.ReplaceAll([]PolicyRule{{Name: "keep-me"}})
	catStore.ReplaceAll([]CategoryEntry{{Name: "keep-cat"}})
	bl.ClearAll()
	bl.Add("keep.example.com")

	polBefore := len(policyStore.List())
	catBefore := len(catStore.All())
	blBefore := bl.Count()

	_ = importPreview(t, "/api/config/import?dryRun=true&mode=replace", map[string]any{
		"version":    1,
		"exportedAt": "2026-02-02T00:00:00Z",
		"policyRules": []map[string]any{
			{"name": "would-replace", "action": "deny"},
		},
		"blocklist":     []string{"would-replace.example.com"},
		"urlCategories": []map[string]any{{"name": "would-replace-cat"}},
	})

	if got := len(policyStore.List()); got != polBefore {
		t.Errorf("policy rules mutated by dry-run: %d != %d", got, polBefore)
	}
	if got := len(catStore.All()); got != catBefore {
		t.Errorf("categories mutated by dry-run: %d != %d", got, catBefore)
	}
	if got := bl.Count(); got != blBefore {
		t.Errorf("blocklist mutated by dry-run: %d != %d", got, blBefore)
	}
	// The seeded names must survive verbatim.
	if rules := policyStore.List(); len(rules) != 1 || rules[0].Name != "keep-me" {
		t.Errorf("policy content changed by dry-run: %+v", rules)
	}
}

// TestImportPreview_OmitsAbsentSectionsAndSurfacesSettings: sections the
// backup does not carry are omitted, and scalar settings are reported.
func TestImportPreview_OmitsAbsentSectionsAndSurfacesSettings(t *testing.T) {
	snapshotPolicyStoreForTest(t)
	snapshotConfigVersionsDir(t)

	resp := importPreview(t, "/api/config/import?dryRun=true", map[string]any{
		"version":       1,
		"exportedAt":    "2026-02-02T00:00:00Z",
		"defaultAction": "deny",
		"rateLimitRPM":  120,
	})

	// No collection fields present ⇒ no sections.
	if len(resp.Sections) != 0 {
		t.Errorf("sections = %+v; want none (no collection fields in backup)", resp.Sections)
	}
	// Two scalar settings present.
	var hasDefault, hasRate bool
	for _, s := range resp.Settings {
		if s.Setting == "Default Policy Action" && s.Value == "deny" {
			hasDefault = true
		}
		if s.Setting == "Rate Limit" && strings.Contains(s.Value, "120") {
			hasRate = true
		}
	}
	if !hasDefault {
		t.Errorf("settings missing Default Policy Action=deny: %+v", resp.Settings)
	}
	if !hasRate {
		t.Errorf("settings missing Rate Limit 120: %+v", resp.Settings)
	}
}

// TestImportPreview_ModeIndependentSections pins the two sections whose apply
// path ignores the import mode (flagged by review): upstream proxies always
// REPLACE (SetProxies) and rate-limit exemptions always APPEND (AddExemption),
// regardless of the mode flag. The preview must report the real effect, not the
// generic mode-derived one — otherwise it tells the admin the opposite of what
// the import will do.
func TestImportPreview_ModeIndependentSections(t *testing.T) {
	snapshotPolicyStoreForTest(t)
	snapshotConfigVersionsDir(t)

	// Merge mode: the upstream row is derived from the 2F-D whole-file plan
	// (counts only) — a legacy list entry unknown to this node is a create.
	respMerge := importPreview(t, "/api/config/import?dryRun=true", map[string]any{
		"version":         1,
		"exportedAt":      "2026-02-02T00:00:00Z",
		"upstreamProxies": []map[string]any{{"url": "http://imp-proxy:8080"}},
		"rateLimitExempt": []string{"10.1.2.3"},
	})
	up, ok := previewSection(respMerge, "Upstream Proxies")
	if !ok {
		t.Fatalf("merge preview missing Upstream Proxies section: %+v", respMerge.Sections)
	}
	if !strings.Contains(up.Effect, "create 1") {
		t.Errorf("upstream merge effect = %q; want the plan counts (create 1)", up.Effect)
	}
	if up.Note == "" {
		t.Errorf("upstream section should carry the plan note")
	}

	// Replace mode: rate-limit exemptions still APPEND, not replace.
	respReplace := importPreview(t, "/api/config/import?dryRun=true&mode=replace", map[string]any{
		"version":         1,
		"exportedAt":      "2026-02-02T00:00:00Z",
		"rateLimitExempt": []string{"10.9.9.9"},
	})
	rle, ok := previewSection(respReplace, "Rate Limit Exemptions")
	if !ok {
		t.Fatalf("replace preview missing Rate Limit Exemptions section: %+v", respReplace.Sections)
	}
	if !strings.HasPrefix(rle.Effect, "add ") {
		t.Errorf("rate-limit-exempt replace-mode effect = %q; want an 'add ...' effect (import always appends)", rle.Effect)
	}
}
