package main

// dc_final2_red_test.go — 2D-C FINAL recovery trust-boundary correction: the
// §13 red-before matrix against 161eb79e, written to compile at both the
// candidate and the corrected tree.
//
//	A — a malformed non-empty StableID in settings-owned RewriteRules reaches
//	    the live Rewriter (settings restore bypasses the UUID contract the
//	    trust doors enforce, creating self-inconsistent state).
//	B — a hard persistence failure of the YAML identity-ledger migration
//	    still exposes generated StableIDs as normal durable management
//	    identities (they can re-mint after restart).
//	C — a NEW interactive Policy write can manufacture an ID-less legacy
//	    FileProfile reference through the compiled fileProfileExts map after
//	    the live object was renamed/deleted, bypassing the stable-ID
//	    promotion.

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ─── A: settings-owned rewrite restore must enforce the identity contract ───

// TestDCFin2_MalformedSettingsStableIDNeverPublished (§1–§3): the public
// contract says a non-empty StableID is a valid UUID; import/rollback/
// snapshot enforce it, so a hand-edited/corrupt admin_settings.json restoring
// "hello" as authoritative runtime identity creates state those same doors
// later reject. The settings-owned rewrite slice must be validated before
// publication; a malformed modern identity is refused (never silently
// re-minted — that is not identity preservation), the previously-seeded
// runtime source is preserved, and the degradation is surfaced.
func TestDCFin2_MalformedSettingsStableIDNeverPublished(t *testing.T) {
	settingsPath := dcFinYAMLBootEnv(t)
	if err := os.WriteFile(settingsPath, []byte(
		`{"rewrite_rules_saved":true,"rewrite_rules":[`+
			`{"stableId":"hello","host":"x.example","req_set":{"X-Test":"1"}}]}`), 0o600); err != nil {
		t.Fatalf("seed settings: %v", err)
	}

	got := dcFinBoot(t, settingsPath, nil)
	for _, r := range got {
		if r.StableID == "hello" {
			t.Fatalf("malformed settings-owned stableId %q reached the live Rewriter — runtime now carries identity the trust doors reject", r.StableID)
		}
	}
	if err := validateRewriteStableIDs(got); err != nil {
		t.Fatalf("published runtime identity violates the product contract: %v", err)
	}
	// The refused slice must not be silently replaced by minted identities:
	// nothing from the corrupt slice is published at all (the previously
	// seeded runtime source — none here — is preserved).
	if len(got) != 0 {
		t.Fatalf("refused settings slice must publish nothing, got %+v", got)
	}
	// And the state surface reports the degradation instead of a healthy
	// empty management view.
	w := httptest.NewRecorder()
	apiRewriteState(w, jsonReq("GET", "/api/rewrite/state", nil))
	if w.Code != 503 {
		t.Fatalf("state after a refused settings-owned rewrite slice = %d, want the structured 503 degradation", w.Code)
	}
}

// TestDCFin2_DuplicateSettingsStableIDsRefused (§2): duplicates in the
// settings-owned slice are ambiguous identity — silently regenerating one of
// them (the candidate's SetRules behavior) pretends identity was preserved.
func TestDCFin2_DuplicateSettingsStableIDsRefused(t *testing.T) {
	settingsPath := dcFinYAMLBootEnv(t)
	if err := os.WriteFile(settingsPath, []byte(
		`{"rewrite_rules_saved":true,"rewrite_rules":[`+
			`{"stableId":"3b241101-e2bb-4255-8caf-4136c566a962","host":"a.example","req_remove":["X-A"]},`+
			`{"stableId":"3b241101-e2bb-4255-8caf-4136c566a962","host":"b.example","req_remove":["X-B"]}]}`), 0o600); err != nil {
		t.Fatalf("seed settings: %v", err)
	}
	if got := dcFinBoot(t, settingsPath, nil); len(got) != 0 {
		t.Fatalf("ambiguous settings-owned identity must be refused, got %+v", got)
	}
}

// TestDCFin2_LegacyEmptyIDBackfillStillMigrates (§3 pin, control): the legacy
// empty-ID case remains the one migration input — restored, backfilled once,
// durable. (The full ownership-preservation half is pinned by
// TestDCFin_LegacyInFileMigrationPreservesOwnership.)
func TestDCFin2_LegacyEmptyIDBackfillStillMigrates(t *testing.T) {
	settingsPath := dcFinYAMLBootEnv(t)
	if err := os.WriteFile(settingsPath, []byte(
		`{"rewrite_rules":[{"id":1,"host":"leg2.example","req_remove":["X-L"]}]}`), 0o600); err != nil {
		t.Fatalf("seed settings: %v", err)
	}
	got := dcFinBoot(t, settingsPath, nil)
	if len(got) != 1 || got[0].StableID == "" {
		t.Fatalf("legacy empty-ID rule must restore with a backfilled identity, got %+v", got)
	}
	got2 := dcFinBoot(t, settingsPath, nil)
	if len(got2) != 1 || got2[0].StableID != got[0].StableID {
		t.Fatalf("backfilled identity must be durable across restart, got %+v then %+v", got, got2)
	}
	w := httptest.NewRecorder()
	apiRewriteState(w, jsonReq("GET", "/api/rewrite/state", nil))
	if w.Code != 200 {
		t.Fatalf("healthy migrated state = %d, want 200", w.Code)
	}
}

// ─── B: failed identity migration must degrade management identity ──────────

// TestDCFin2_LedgerPersistFailureDegradesManagementIdentity (§4–§6): with no
// settings file and a HARD write failure on the targeted ledger migration
// (settings path inside a nonexistent directory — the read is a clean
// not-exist, every AtomicWrite fails), the appliance boots and traffic
// rewrite continues, but the generated StableIDs are KNOWN not to be durable:
// the management surface must not present them as normal durable identities,
// and StableID-addressed v2 mutations must refuse until durable identity is
// established.
func TestDCFin2_LedgerPersistFailureDegradesManagementIdentity(t *testing.T) {
	dir := t.TempDir()
	broken := filepath.Join(dir, "no-such-dir", "admin_settings.json")
	prevAction := defaultPolicyAction()
	t.Cleanup(func() { setDefaultPolicyAction(prevAction) })
	restoreRewriter := rewriter.Snapshot()
	t.Cleanup(restoreRewriter)
	rewriter.SetRules(nil)
	swapAdminSettingsPath(t, broken)

	yaml := []RewriteRule{{Host: "eph.example", ReqSet: map[string]string{"X-E": "1"}}}
	rewriter.SetRules(nil)
	loadRewriteAndDefaultAction(rewriteDefaultActionStartupConfig{Rules: yaml, DefaultAction: "allow"}, 0)
	LoadAdminSettings(broken)

	// Traffic enforcement continues: the seeded rule is live.
	if got := rewriter.List(); len(got) != 1 {
		t.Fatalf("data-plane rewrite must keep operating, got %+v", got)
	}
	sid := rewriter.List()[0].StableID

	// The MANAGEMENT surface must not present the ephemeral identity as a
	// normal durable one.
	w := httptest.NewRecorder()
	apiRewriteState(w, jsonReq("GET", "/api/rewrite/state", nil))
	if w.Code != 503 {
		t.Fatalf("state with a failed identity migration = %d body=%s — an identity that can re-mint after restart must not be presented as durable (want structured 503)", w.Code, w.Body.String())
	}
	// StableID-addressed mutations refuse while identity is not durable.
	w = httptest.NewRecorder()
	apiRewrite(w, jsonReq("DELETE", "/api/rewrite?stableId="+sid, nil))
	if w.Code != 503 {
		t.Fatalf("v2 mutation while identity is not durable = %d, want 503", w.Code)
	}

	// RECOVERY: persistence restored — the migration succeeds, identity
	// becomes management-usable, and a restart retains the same ID.
	good := filepath.Join(dir, "admin_settings.json")
	swapAdminSettingsPath(t, good)
	boot := func() []RewriteRule {
		rewriter.SetRules(nil)
		loadRewriteAndDefaultAction(rewriteDefaultActionStartupConfig{Rules: yaml, DefaultAction: "allow"}, 0)
		LoadAdminSettings(good)
		return rewriter.List()
	}
	b1 := boot()
	if len(b1) != 1 || b1[0].StableID == "" {
		t.Fatalf("recovered boot: %+v", b1)
	}
	w = httptest.NewRecorder()
	apiRewriteState(w, jsonReq("GET", "/api/rewrite/state", nil))
	if w.Code != 200 {
		t.Fatalf("recovered state = %d, want 200", w.Code)
	}
	b2 := boot()
	if b2[0].StableID != b1[0].StableID {
		t.Fatalf("recovered identity must be restart-stable: %s vs %s", b1[0].StableID, b2[0].StableID)
	}
}

// ─── C: interactive writes must require LIVE FileProfile identity ───────────

// dcFin2PolicyWriteEnv isolates the policy store + profile store for the
// interactive-door proofs. Returns nothing; cleanup restores.
func dcFin2PolicyWriteEnv(t *testing.T) {
	t.Helper()
	dcProfileStoreIsolate(t)
	prevRules := policyStore.List()
	t.Cleanup(func() { policyStore.ReplaceAll(prevRules) })
	policyStore.ReplaceAll(nil)
	prevRC := requireCommitEnabled()
	setRequireCommit(false)
	t.Cleanup(func() { setRequireCommit(prevRC) })
}

func dcFin2CreateRule(t *testing.T, name, profile string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	apiPolicy(w, jsonReq("POST", "/api/policy", map[string]any{
		"name": name, "action": "Allow", "destFQDN": "fp-door.test",
		"fileFiltering": true, "fileProfile": profile,
	}))
	return w
}

// TestDCFin2_InteractiveWriteRequiresLiveFileProfile (§7–§9): after the
// built-in "Executables" is RENAMED, a NEW interactive write naming
// "Executables" has no live object to bind to — accepting it through the
// compiled legacy map manufactures a modern rule with FileProfileID == ""
// (legacy fallback enforcement), bypassing the stable-ID promotion. The
// modern write door must refuse with the structured dangling-reference 400;
// writing against the NEW name binds to the SAME built-in stable ID.
func TestDCFin2_InteractiveWriteRequiresLiveFileProfile(t *testing.T) {
	dcFin2PolicyWriteEnv(t)
	if err := globalProfileStore.Update("builtin-executables", "Corporate Executables",
		[]string{".exe", ".msi"}); err != nil {
		t.Fatalf("rename built-in: %v", err)
	}

	// A: the OLD name resolves only in the compiled legacy map now.
	w := dcFin2CreateRule(t, "dcfin2-legacy-shape", "Executables")
	if w.Code != 400 {
		t.Fatalf("interactive write against a renamed built-in's OLD name = %d body=%s — the compiled legacy map must never satisfy a NEW interactive write (want structured 400)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "file-profile") {
		t.Fatalf("refusal must be the structured dangling-reference 400, got %s", w.Body.String())
	}
	for _, r := range policyStore.List() {
		if r.Name == "dcfin2-legacy-shape" {
			t.Fatal("refused rule must not be persisted")
		}
	}

	// The NEW name binds to the SAME built-in stable identity.
	w = dcFin2CreateRule(t, "dcfin2-live-shape", "Corporate Executables")
	if w.Code != 200 {
		t.Fatalf("create against the live renamed profile = %d body=%s", w.Code, w.Body.String())
	}
	var created PolicyRule
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if created.FileProfileID != "builtin-executables" {
		t.Fatalf("server must stamp the live object's stable ID, got %q", created.FileProfileID)
	}
}

// TestDCFin2_InteractiveWriteAfterBuiltInDelete (§9-B): deleting an
// unreferenced built-in removes the live object — a NEW write naming it must
// refuse, not fall back to the compiled map.
func TestDCFin2_InteractiveWriteAfterBuiltInDelete(t *testing.T) {
	dcFin2PolicyWriteEnv(t)
	if err := globalProfileStore.Delete("builtin-media"); err != nil {
		t.Fatalf("delete built-in: %v", err)
	}
	w := dcFin2CreateRule(t, "dcfin2-deleted-name", "Media")
	if w.Code != 400 {
		t.Fatalf("interactive write against a deleted built-in's name = %d, want 400", w.Code)
	}
}

// TestDCFin2_LegacyIDLessRuleKeepsCompiledFallback (§9-C, CONTROL — green at
// both trees): a pre-existing LOADED rule with no FileProfileID keeps the
// historical compiled-map enforcement even when the live object is gone.
// Compatibility is preserved for historical state; only the NEW write door
// tightened.
func TestDCFin2_LegacyIDLessRuleKeepsCompiledFallback(t *testing.T) {
	dcFin2PolicyWriteEnv(t)
	if err := globalProfileStore.Delete("builtin-executables"); err != nil {
		t.Fatalf("delete built-in: %v", err)
	}
	r := &PolicyRule{FileFiltering: true, FileProfile: "Executables"} // historical, ID-less
	if !r.FileProfileBlocked("/setup.exe") {
		t.Fatal("historical ID-less rule must keep the compiled-map fallback")
	}
	if r.FileProfileBlocked("/notes.txt") {
		t.Fatal("compiled fallback must keep its exact extension set")
	}
}
