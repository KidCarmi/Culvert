package main

// dc_identity_test.go — 2D-C green contract suite: durable rewrite identity
// through the AdminSettings owner, sentinel-authoritative restore, import
// upsert/uniqueness semantics, rollback + CP→DP identity preservation, the
// v2 coherent state reads, file-profile canonicalization on the bulk paths,
// and the rename cascade onto an active Policy Draft.

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/rewrite"
)

// dcRewriteSetup isolates the live rewriter + admin settings persistence.
func dcRewriteSetup(t *testing.T) (settingsPath string) {
	t.Helper()
	restore := rewriter.Snapshot()
	t.Cleanup(restore)
	rewriter.SetRules(nil)
	settingsPath = filepath.Join(t.TempDir(), "settings.json")
	swapAdminSettingsPath(t, settingsPath)
	return settingsPath
}

func dcCreateRewriteRule(t *testing.T, host string) RewriteRule {
	t.Helper()
	w := httptest.NewRecorder()
	apiRewrite(w, jsonReq("POST", "/api/rewrite",
		map[string]any{"host": host, "req_set": map[string]string{"X-T": "1"}}))
	if w.Code != 200 {
		t.Fatalf("create rewrite rule: %d %s", w.Code, w.Body.String())
	}
	var added RewriteRule
	if err := json.Unmarshal(w.Body.Bytes(), &added); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if added.StableID == "" {
		t.Fatal("created rule must carry a server-assigned stableId")
	}
	return added
}

// TestDC_RewriteSettingsRoundTripPreservesStableIDs (§21): a confirmed create
// is durable WITH its stable identity — the settings file carries it, the
// saved-authoritative sentinel is set, and a restart (restore into a fresh
// Rewriter) re-serves the SAME identity.
func TestDC_RewriteSettingsRoundTripPreservesStableIDs(t *testing.T) {
	settingsPath := dcRewriteSetup(t)
	added := dcCreateRewriteRule(t, "rt.example")

	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("settings must be durable at 200: %v", err)
	}
	var s AdminSettings
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("decode settings: %v", err)
	}
	if !s.RewriteRulesSaved {
		t.Fatal("save must stamp the saved-authoritative sentinel")
	}
	if len(s.RewriteRules) != 1 || s.RewriteRules[0].StableID != added.StableID {
		t.Fatalf("persisted rules must carry the stable identity; got %+v", s.RewriteRules)
	}
	// Restart: restore the persisted set into a fresh Rewriter.
	fresh := rewrite.NewRewriter()
	if backfilled := fresh.SetRules(s.RewriteRules); backfilled != 0 {
		t.Fatalf("a modern persisted set must not need backfill (got %d)", backfilled)
	}
	got := fresh.List()
	if len(got) != 1 || got[0].StableID != added.StableID {
		t.Fatalf("restart must re-serve the SAME stable identity; got %+v", got)
	}
}

// TestDC_RewriteEmptyListSurvivesRestart (sentinel): deleting the last rule
// persists an EMPTY saved-authoritative list, and the restore branch honors
// it — YAML-seeded rules must not resurrect.
func TestDC_RewriteEmptyListSurvivesRestart(t *testing.T) {
	settingsPath := dcRewriteSetup(t)
	added := dcCreateRewriteRule(t, "gone.example")
	w := httptest.NewRecorder()
	apiRewrite(w, jsonReq("DELETE", "/api/rewrite?stableId="+added.StableID, nil))
	if w.Code != 204 {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	var s AdminSettings
	data, _ := os.ReadFile(settingsPath)
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("decode settings: %v", err)
	}
	if !s.RewriteRulesSaved || len(s.RewriteRules) != 0 {
		t.Fatalf("explicit empty set must persist saved-authoritative; got saved=%t rules=%d", s.RewriteRulesSaved, len(s.RewriteRules))
	}
	// Restart simulation: YAML seeds first, then the settings restore.
	publishRewriteRules([]RewriteRule{dcRewriteRule("yaml.example", "X-Y", "1")})
	applyAdminNetworkRewriteForTest(&s)
	if got := rewriter.List(); len(got) != 0 {
		t.Fatalf("saved-authoritative EMPTY set must replace the YAML seed on restore; got %+v", got)
	}
}

// applyAdminNetworkRewriteForTest exercises exactly the restore branch (the
// full applyAdminSecurity path touches unrelated globals).
func applyAdminNetworkRewriteForTest(s *AdminSettings) {
	if s.RewriteRulesSaved || len(s.RewriteRules) > 0 {
		rewriter.SetRules(s.RewriteRules)
	}
}

// TestDC_RewriteStateCoherentRead: /api/rewrite/state returns ordered rules +
// the revision describing exactly them; a mutation changes the revision, and
// the previously-read revision then conflicts.
func TestDC_RewriteStateCoherentRead(t *testing.T) {
	dcRewriteSetup(t)
	a := dcCreateRewriteRule(t, "a.example")
	b := dcCreateRewriteRule(t, "b.example")

	w := httptest.NewRecorder()
	apiRewriteState(w, getReq("/api/rewrite/state"))
	if w.Code != 200 {
		t.Fatalf("state: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		Rules    []RewriteRule `json:"rules"`
		Revision string        `json:"revision"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Rules) != 2 || resp.Rules[0].StableID != a.StableID || resp.Rules[1].StableID != b.StableID {
		t.Fatalf("state must render EVALUATION order; got %+v", resp.Rules)
	}
	if got := rewrite.FingerprintRules(resp.Rules); got != resp.Revision {
		t.Fatalf("revision %q does not describe the returned rules (%q)", resp.Revision, got)
	}
	// Fresh revision admits a fenced mutation; the now-stale one conflicts.
	w = httptest.NewRecorder()
	apiRewrite(w, jsonReq("DELETE", "/api/rewrite?stableId="+a.StableID+"&ifRevision="+resp.Revision, nil))
	if w.Code != 204 {
		t.Fatalf("fenced delete with fresh revision: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	apiRewrite(w, jsonReq("DELETE", "/api/rewrite?stableId="+b.StableID+"&ifRevision="+resp.Revision, nil))
	if w.Code != 409 {
		t.Fatalf("the superseded revision must 409, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"currentRevision"`) {
		t.Fatalf("conflict must carry the current revision: %s", w.Body.String())
	}
}

// TestDC_RewriteLegacyIntDeleteStillWorks: the legacy ?id= addressing remains
// supported, resolved inside the critical section.
func TestDC_RewriteLegacyIntDeleteStillWorks(t *testing.T) {
	dcRewriteSetup(t)
	added := dcCreateRewriteRule(t, "legacy.example")
	w := httptest.NewRecorder()
	apiRewrite(w, jsonReq("DELETE", fmt.Sprintf("/api/rewrite?id=%d", added.ID), nil))
	if w.Code != 204 {
		t.Fatalf("legacy int delete: %d %s", w.Code, w.Body.String())
	}
	if len(rewriter.List()) != 0 {
		t.Fatal("rule must be removed")
	}
}

// TestDC_RewriteImportMergeUpsertsByStableID (§22/§37): merge-mode import
// upserts by stable identity (idempotent re-import) and appends ID-less
// legacy rules with fresh server identity; duplicate incoming IDs refuse the
// whole import.
func TestDC_RewriteImportMergeUpsertsByStableID(t *testing.T) {
	dcRewriteSetup(t)
	csrTaxIsolate(t)
	snapshotBlocklistGlobals(t)
	live := dcCreateRewriteRule(t, "live.example")

	modified := live
	modified.ReqSet = map[string]string{"X-T": "CHANGED"}
	w := canonImportBackup(t, "merge", &configBackup{
		Version: 1,
		RewriteRules: []RewriteRule{
			modified,
			dcRewriteRule("appended.example", "X-N", "1"), // no stableId — legacy
		},
	})
	if w.Code != 200 {
		t.Fatalf("import: %d %s", w.Code, w.Body.String())
	}
	got := rewriter.List()
	if len(got) != 2 {
		t.Fatalf("want upsert+append (2 rules), got %+v", got)
	}
	if got[0].StableID != live.StableID || got[0].ReqSet["X-T"] != "CHANGED" {
		t.Fatalf("merge must upsert IN PLACE by stable identity; got %+v", got[0])
	}
	if got[1].StableID == "" || got[1].StableID == live.StableID {
		t.Fatalf("appended legacy rule must receive fresh server identity; got %+v", got[1])
	}

	// Duplicate stable IDs within the payload: whole import refused.
	dup := dcRewriteRule("d1.example", "X-D", "1")
	dup.StableID = "dup-claim"
	dup2 := dcRewriteRule("d2.example", "X-D", "2")
	dup2.StableID = "dup-claim"
	w = canonImportBackup(t, "merge", &configBackup{Version: 1, RewriteRules: []RewriteRule{dup, dup2}})
	if w.Code != 400 || !strings.Contains(w.Body.String(), "dup-claim") {
		t.Fatalf("duplicate stable IDs must refuse the whole import, got %d: %s", w.Code, w.Body.String())
	}
}

// TestDC_RollbackPreservesRewriteStableIDs (§38): a config version captured
// after the promotion restores the SAME stable identities, durably.
func TestDC_RollbackPreservesRewriteStableIDs(t *testing.T) {
	settingsPath := dcRewriteSetup(t)
	csrTaxIsolate(t)
	added := dcCreateRewriteRule(t, "rb.example")
	saveConfigVersion("dc-test", "seed")
	versions := configVersions.List()
	target := versions[len(versions)-1].Version

	// The rule is then deleted; rollback must restore the SAME identity.
	w := httptest.NewRecorder()
	apiRewrite(w, jsonReq("DELETE", "/api/rewrite?stableId="+added.StableID, nil))
	if w.Code != 204 {
		t.Fatalf("delete: %d", w.Code)
	}
	w = httptest.NewRecorder()
	apiConfigVersions(w, jsonReq("POST", "/api/config/versions", map[string]any{"version": target}))
	if w.Code != 200 {
		t.Fatalf("rollback: %d %s", w.Code, w.Body.String())
	}
	got := rewriter.List()
	if len(got) != 1 || got[0].StableID != added.StableID {
		t.Fatalf("rollback must restore the SAME stable identity, never mint fresh ones; got %+v", got)
	}
	// And durably: the settings file carries the restored set.
	var s AdminSettings
	data, _ := os.ReadFile(settingsPath)
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("decode settings: %v", err)
	}
	if len(s.RewriteRules) != 1 || s.RewriteRules[0].StableID != added.StableID {
		t.Fatalf("rollback's rewrite slice must be DURABLE; settings carry %+v", s.RewriteRules)
	}
}

// TestDC_SnapshotPreservesRewriteStableIDs (§39): the DP apply preserves CP
// identities verbatim; duplicate identities reject the entire snapshot.
func TestDC_SnapshotPreservesRewriteStableIDs(t *testing.T) {
	dcRewriteSetup(t)
	cpRule := dcRewriteRule("cp.example", "X-CP", "1")
	cpRule.StableID = "cp-stable-1"
	snap := ConfigSnapshot{Version: 3, RewriteRules: []RewriteRule{cpRule}}
	if err := validateConfigSnapshot(snap); err != nil {
		t.Fatalf("valid snapshot refused: %v", err)
	}
	if err := applyConfigSnapshot(snap); err != nil {
		t.Fatalf("apply: %v", err)
	}
	got := rewriter.List()
	if len(got) != 1 || got[0].StableID != "cp-stable-1" {
		t.Fatalf("DP must preserve the CP's stable identity verbatim; got %+v", got)
	}

	dup := dcRewriteRule("d.example", "X-D", "1")
	dup.StableID = "cp-dup"
	dup2 := dcRewriteRule("d2.example", "X-D", "2")
	dup2.StableID = "cp-dup"
	if err := validateConfigSnapshot(ConfigSnapshot{Version: 4, RewriteRules: []RewriteRule{dup, dup2}}); err == nil {
		t.Fatal("duplicate stable identities must reject the ENTIRE snapshot")
	}
}

// TestDC_FileProfileStateCoherentRead: /api/fileblock/profiles/state returns
// profiles + the revision describing exactly them, and the revision advances
// on mutation.
func TestDC_FileProfileStateCoherentRead(t *testing.T) {
	dcProfileStoreIsolate(t)
	w := httptest.NewRecorder()
	apiFileblockProfilesState(w, getReq("/api/fileblock/profiles/state"))
	if w.Code != 200 {
		t.Fatalf("state: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		Profiles []FileExtProfile `json:"profiles"`
		Revision string           `json:"revision"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Revision != globalProfileStore.Revision() {
		t.Fatal("state revision must describe the committed set")
	}
	before := resp.Revision
	if _, err := globalProfileStore.Create("Rev-Prof", []string{".exe"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if globalProfileStore.Revision() == before {
		t.Fatal("revision must advance on mutation")
	}
}

// TestDC_FPRenameCascadesRunningAndDraft (§8): a rename cascades the
// denormalized name onto RUNNING rules and an ACTIVE draft candidate by
// stable ID; enforcement identity is unchanged throughout.
func TestDC_FPRenameCascadesRunningAndDraft(t *testing.T) {
	draftTestSetup(t)
	dcProfileStoreIsolate(t)
	prof, err := globalProfileStore.Create("Casc-Prof", []string{".exe"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Running rule (live mode).
	w := httptest.NewRecorder()
	apiPolicyCreate(w, jsonReq("POST", "/api/policy", map[string]any{
		"name": "casc-run", "action": "Allow", "fileFiltering": true, "fileProfile": "Casc-Prof",
	}))
	if w.Code != 200 {
		t.Fatalf("live rule: %d %s", w.Code, w.Body.String())
	}
	// Draft rule (staged).
	setRequireCommit(true)
	w = httptest.NewRecorder()
	apiPolicyCreate(w, jsonReq("POST", "/api/policy", map[string]any{
		"name": "casc-draft", "action": "Allow", "fileFiltering": true, "fileProfile": "Casc-Prof",
	}))
	if w.Code != 200 {
		t.Fatalf("draft rule: %d %s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	apiFileblockProfiles(w, jsonReq("PUT", "/api/fileblock/profiles?id="+prof.ID,
		map[string]any{"name": "Casc-Prof-2", "extensions": []string{".exe"}}))
	if w.Code != 200 {
		t.Fatalf("rename: %d %s", w.Code, w.Body.String())
	}

	for _, r := range policyStore.List() {
		if r.Name == "casc-run" {
			if string(r.FileProfile) != "Casc-Prof-2" || r.FileProfileID != prof.ID {
				t.Fatalf("running cascade: %+v", r)
			}
			if !r.FileProfileBlocked("/x.exe") {
				t.Fatal("running rule must keep enforcing the SAME profile identity")
			}
		}
	}
	foundDraft := false
	for _, r := range policyDraft.candidateList() {
		if r.Name == "casc-draft" {
			foundDraft = true
			if string(r.FileProfile) != "Casc-Prof-2" || r.FileProfileID != prof.ID {
				t.Fatalf("draft cascade: %+v", r)
			}
		}
	}
	if !foundDraft {
		t.Fatal("draft candidate rule vanished")
	}
}

// TestDC_FPImportCanonicalizesNameIntent (§17): import intent is the NAME —
// a smuggled unrelated profile ID never rescues a missing name, and a
// mismatched pair binds to the name's profile.
func TestDC_FPImportCanonicalizesNameIntent(t *testing.T) {
	bulkCanonSetup(t)
	dcProfileStoreIsolate(t)
	a, _ := globalProfileStore.Create("Prof-A", []string{".exe"})
	b, _ := globalProfileStore.Create("Prof-B", []string{".dll"})

	// ID-smuggling: MISSING name + valid unrelated ID ⇒ whole import 400.
	w := canonImportBackup(t, "merge", &configBackup{
		Version: 1,
		PolicyRules: []PolicyRule{{
			Name: "fp-smuggle", Action: ActionDrop, Priority: 7,
			FileFiltering: true, FileProfile: "MISSING-PROF", FileProfileID: a.ID,
		}},
	})
	if w.Code != 400 || !strings.Contains(w.Body.String(), "MISSING-PROF") {
		t.Fatalf("smuggled profile ID must not rescue a missing name, got %d: %s", w.Code, w.Body.String())
	}

	// Mismatched pair binds to the NAME's profile.
	w = canonImportBackup(t, "merge", &configBackup{
		Version: 1,
		PolicyRules: []PolicyRule{{
			Name: "fp-mismatch", Action: ActionAllow, Priority: 7,
			FileFiltering: true, FileProfile: "Prof-A", FileProfileID: b.ID,
		}},
	})
	if w.Code != 200 {
		t.Fatalf("mismatched pair must bind to the name: %d %s", w.Code, w.Body.String())
	}
	got := installedRuleByName("fp-mismatch")
	if got == nil || got.FileProfileID != a.ID {
		t.Fatalf("installed rule must carry the NAME's profile ID %s; got %+v", a.ID, got)
	}
}

// TestDC_FPSnapshotGraphBothSides (§16/§18): the snapshot judges the
// rule→file-profile edge only when both sides are carried; a dangling
// authoritative ID rejects the whole snapshot; a legacy-map name with no ID
// stays valid.
func TestDC_FPSnapshotGraphBothSides(t *testing.T) {
	// Both sides carried, rule's authoritative ID resolves nowhere ⇒ reject.
	snap := ConfigSnapshot{
		Version:      6,
		FileProfiles: []FileExtProfile{{ID: "fp-1", Name: "Synced", Extensions: []string{".exe"}}},
		PolicyRules: []PolicyRule{{
			Name: "dangling-id", Action: ActionDrop, Priority: 1,
			FileFiltering: true, FileProfile: "Synced", FileProfileID: "fp-GONE",
		}},
	}
	if err := validateConfigSnapshot(snap); err == nil {
		t.Fatal("a dangling authoritative file-profile ID must reject the whole snapshot")
	}
	// Same rule, ID resolves ⇒ valid; legacy-map name with no ID ⇒ valid.
	snap.PolicyRules[0].FileProfileID = "fp-1"
	snap.PolicyRules = append(snap.PolicyRules, PolicyRule{
		Name: "legacy-name", Action: ActionAllow, Priority: 2,
		FileFiltering: true, FileProfile: FileProfileExecutables,
	})
	if err := validateConfigSnapshot(snap); err != nil {
		t.Fatalf("valid snapshot refused: %v", err)
	}
	// Rules carried, FileProfiles NOT carried ⇒ edge skipped (DP keeps live).
	if err := validateConfigSnapshot(ConfigSnapshot{
		Version: 7,
		PolicyRules: []PolicyRule{{
			Name: "r", Action: ActionAllow, Priority: 1,
			FileFiltering: true, FileProfile: "resolves-live-on-dp", FileProfileID: "live-id",
		}},
	}); err != nil {
		t.Fatalf("file-profile edge without a carried profile slice must not be judged: %v", err)
	}
}
