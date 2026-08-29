package main

// dc_final_red_test.go — 2D-C FINAL identity/recovery/fail-closed correction:
// the §19 red-before matrix, written to compile at BOTH trees (the reviewed
// candidate dc638a22 and the corrected tree) so each defect gate can be run
// RED against the candidate and GREEN after the fix.
//
// Matrix rows covered here: A (dangling authoritative FileProfileID fails
// open), B (startup reconciliation ordering), C (YAML-only rewrite StableID
// not durable across restart), E-snapshot (duplicate FileProfile IDs accepted
// by the CP snapshot boundary), F (malformed non-empty rewrite StableID
// accepted at the bulk doors), G (rollback response claims rewrite_rules is
// runtime-only), H (rewrite history diff misses a same-host operation-only
// edit). Row D (fpv1 collision) and E-load live in
// internal/fileblock/fileprofile_final_red_test.go beside the unexported
// fingerprint.

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// ─── A: dangling authoritative FileProfileID must FAIL CLOSED ──────────────

// TestDCFin_DanglingAuthoritativeFileProfileIDFailsClosed (§1–§3-A/B): a rule
// with FileFiltering configured and a non-empty authoritative FileProfileID
// that no longer resolves must produce a RESTRICTIVE file-control decision —
// never a silent allow, and never a retarget onto a same-named store/legacy
// profile. The fail-closed scope is exactly the set of transactions ANY
// profile could ever block: paths carrying a file extension. Extension-less
// transactions stay untouched (no extension set can match them), so blind
// "return true" semantics are equally wrong and equally pinned.
func TestDCFin_DanglingAuthoritativeFileProfileIDFailsClosed(t *testing.T) {
	dcProfileStoreIsolate(t) // fresh store seeded with built-ins; "missing-id" resolves nowhere

	// §3-A: the name happens to match BOTH the store built-in "Executables"
	// AND the compiled legacy map — the two retarget hazards.
	r := &PolicyRule{FileFiltering: true, FileProfile: "Executables", FileProfileID: "missing-id"}
	if !r.FileProfileBlocked("/payload.exe") {
		t.Fatal("dangling authoritative FileProfileID allowed a file transaction: the configured file control failed OPEN (and must never retarget by name)")
	}
	// Fail-closed covers ANY extension — the unresolved profile could have
	// listed it, so the superset is the restrictive answer.
	if !r.FileProfileBlocked("/doc.xyz") {
		t.Fatal("dangling authoritative FileProfileID must fail closed for every extension-bearing path")
	}
	// Non-file transactions: no extension set can ever match an extension-less
	// path, so blocking it would be an invented semantic, not fail-closed.
	if r.FileProfileBlocked("/index") {
		t.Fatal("extension-less path blocked: fail-closed must not block transactions no profile could ever block")
	}
	if r.FileProfileBlocked("/") {
		t.Fatal("root path blocked: fail-closed must not block transactions no profile could ever block")
	}

	// §3-B: the restart shape — the rule references a CUSTOM profile whose
	// name resolves nowhere (store lost/unavailable on restart). Same branch,
	// same restrictive outcome.
	r2 := &PolicyRule{FileFiltering: true, FileProfile: "Custom Set", FileProfileID: "3d1c0000-aaaa-bbbb-cccc-000000000001"}
	if !r2.FileProfileBlocked("/x.bin") {
		t.Fatal("authoritative ID unresolvable after simulated store loss: enforcement must remain restrictive")
	}
}

// TestDCFin_LegacyIDLessRuleKeepsHistoricalResolution (§3-C, CONTROL — green
// at both trees): an ID-less legacy rule keeps the exact pre-promotion
// resolution (dynamic store by name, then the compiled legacy map).
func TestDCFin_LegacyIDLessRuleKeepsHistoricalResolution(t *testing.T) {
	dcProfileStoreIsolate(t)
	r := &PolicyRule{FileFiltering: true, FileProfile: "Executables"} // no ID
	if !r.FileProfileBlocked("/setup.exe") {
		t.Fatal("legacy ID-less rule lost its historical store-name resolution")
	}
	if r.FileProfileBlocked("/readme.txt") {
		t.Fatal("legacy ID-less rule blocked an extension outside its profile")
	}
	// A name resolving ONLY in the compiled map (store isolated fresh keeps
	// the same built-in names, so exercise the miss branch too).
	r2 := &PolicyRule{FileFiltering: true, FileProfile: "no-such-profile"}
	if r2.FileProfileBlocked("/setup.exe") {
		t.Fatal("unresolvable NAME on an ID-less rule must keep the historical no-block outcome")
	}
}

// ─── B: startup order — profiles must load BEFORE the reconcile pass ───────

// TestDCFin_StartupOrderLoadsFileProfilesBeforeReconcile (§4–§5): pins the
// REAL boot order in main.go. reconcileObjectRefNames builds its
// fileProfileNames map from globalProfileStore, so the pass must run AFTER
// initFileBlocking has loaded the store — otherwise the documented
// crash-recovery model for a FileProfile rename never executes against the
// loaded authority and a stale denormalized name survives every restart.
func TestDCFin_StartupOrderLoadsFileProfilesBeforeReconcile(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(pkgSourceDir(), "main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	iLoad := bytes.Index(src, []byte("initFileBlocking(s)"))
	iRec := bytes.Index(src, []byte("reconcileObjectRefNames()"))
	if iLoad < 0 || iRec < 0 {
		t.Fatalf("startup calls not found (initFileBlocking=%d reconcileObjectRefNames=%d)", iLoad, iRec)
	}
	if iRec < iLoad {
		t.Fatal("reconcileObjectRefNames() runs BEFORE initFileBlocking(s): the FileProfile rename-recovery pass executes against an unloaded profile store, so a crashed rename's stale display name survives restart")
	}
}

// TestDCFin_ReconcileBeforeProfileLoadCannotConverge is the permanent DEFECT
// PROOF for row B (green at both trees): it demonstrates WHY the order is
// load-bearing by running the candidate's order — reconcile against an
// unloaded store, then load — and showing the stale name survives, while the
// corrected order converges. A future refactor that quietly reorders main.go
// fails the source pin above; this test keeps the mechanism on record.
func TestDCFin_ReconcileBeforeProfileLoadCannotConverge(t *testing.T) {
	profilesPath, ruleID := dcFinSeedRenamedProfile(t)

	// Candidate order: reconcile FIRST (store not loaded — empty names map,
	// absent IDs are skipped, stale name kept), then load.
	reconcileObjectRefNames()
	if err := globalProfileStore.Load(profilesPath); err != nil {
		t.Fatalf("load profiles: %v", err)
	}
	if got := dcFinRuleFileProfileName(t, ruleID); got != "OLD Name" {
		t.Fatalf("defect mechanism changed: stale name should survive the early reconcile, got %q", got)
	}

	// Corrected order: the store is loaded now — one reconcile converges.
	reconcileObjectRefNames()
	if got := dcFinRuleFileProfileName(t, ruleID); got != "NEW Name" {
		t.Fatalf("reconcile against the loaded store must converge the display name, got %q", got)
	}
}

// TestDCFin_StartupRenameRecoveryRunsAgainstLoadedProfiles (§6): the
// corrected boot sequence — profiles loaded, THEN one reconcile — converges a
// crashed rename on the running rule while the stable identity and the
// enforced extension set stay unchanged.
func TestDCFin_StartupRenameRecoveryRunsAgainstLoadedProfiles(t *testing.T) {
	profilesPath, ruleID := dcFinSeedRenamedProfile(t)

	if err := globalProfileStore.Load(profilesPath); err != nil {
		t.Fatalf("load profiles: %v", err)
	}
	reconcileObjectRefNames()

	if got := dcFinRuleFileProfileName(t, ruleID); got != "NEW Name" {
		t.Fatalf("running rule display name = %q, want the loaded store's NEW Name", got)
	}
	for _, r := range policyStore.List() {
		if r.ID == ruleID && r.FileProfileID != "dcfin-x-profile" {
			t.Fatalf("reconcile must never change the stable identity, got %q", r.FileProfileID)
		}
	}
	// Enforcement follows the ID (the store's extension set), unchanged by the
	// display-name convergence.
	for _, r := range policyStore.List() {
		if r.ID == ruleID {
			rr := r
			if !rr.FileProfileBlocked("/f.qqq") {
				t.Fatal("enforcement must follow the stable ID's extension set")
			}
		}
	}
}

// dcFinSeedRenamedProfile stages the crashed-rename shape: the DURABLE profile
// store carries id=dcfin-x-profile name="NEW Name", while the running policy
// rule still caches the pre-rename display name "OLD Name" with the same
// stable ID. Returns the profiles path (NOT yet loaded) and the rule's ULID.
func dcFinSeedRenamedProfile(t *testing.T) (profilesPath, ruleID string) {
	t.Helper()

	origStore := globalProfileStore
	globalProfileStore = &FileProfileStore{}
	t.Cleanup(func() { globalProfileStore = origStore })

	dir := t.TempDir()
	profilesPath = filepath.Join(dir, "profiles.json")
	if err := os.WriteFile(profilesPath,
		[]byte(`[{"id":"dcfin-x-profile","name":"NEW Name","extensions":[".qqq"]}]`), 0o600); err != nil {
		t.Fatalf("seed profiles file: %v", err)
	}

	prevRules := policyStore.List()
	t.Cleanup(func() { policyStore.ReplaceAll(prevRules) })
	policyStore.ReplaceAll(nil)
	added := policyStore.Add(PolicyRule{
		Name: "dcfin-stale-name", Priority: 4321, Action: ActionAllow,
		FileFiltering: true, FileProfile: "OLD Name", FileProfileID: "dcfin-x-profile",
	})
	return profilesPath, added.ID
}

func dcFinRuleFileProfileName(t *testing.T, ruleID string) string {
	t.Helper()
	for _, r := range policyStore.List() {
		if r.ID == ruleID {
			return string(r.FileProfile)
		}
	}
	t.Fatalf("staged rule %s disappeared", ruleID)
	return ""
}

// ─── C: YAML-only rewrite StableID must survive restart ────────────────────

// TestDCFin_YAMLRewriteStableIDsSurviveRestartWithoutAdminSave (§7–§9): a
// YAML-seeded appliance with NO admin_settings.json and NO admin mutation
// must present the SAME stable rewrite identities after a clean restart —
// management identity cannot be contingent on a later unrelated admin write.
// The boot sequence exercised is the real one: the YAML seed publishes, then
// LoadAdminSettings runs against the (absent) settings file.
func TestDCFin_YAMLRewriteStableIDsSurviveRestartWithoutAdminSave(t *testing.T) {
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "admin_settings.json")
	prevAction := defaultPolicyAction()
	t.Cleanup(func() { setDefaultPolicyAction(prevAction) })
	restoreRewriter := rewriter.Snapshot()
	t.Cleanup(restoreRewriter)
	swapAdminSettingsPath(t, settingsPath)

	yaml := []RewriteRule{
		{Host: "a.example", ReqSet: map[string]string{"X-A": "1"}},
		{Host: "b.example", RespRemove: []string{"X-B"}},
	}

	boot := func() []RewriteRule {
		rewriter.SetRules(nil) // fresh process
		loadRewriteAndDefaultAction(rewriteDefaultActionStartupConfig{Rules: yaml, DefaultAction: "allow"}, 0)
		LoadAdminSettings(settingsPath)
		return rewriter.List()
	}

	b1 := boot()
	if len(b1) != 2 || b1[0].StableID == "" || b1[1].StableID == "" {
		t.Fatalf("boot #1 must publish 2 identified rules, got %+v", b1)
	}
	b2 := boot()
	if len(b2) != 2 {
		t.Fatalf("boot #2 must publish 2 rules, got %+v", b2)
	}
	for i := range b1 {
		if b1[i].StableID != b2[i].StableID {
			t.Fatalf("YAML rule %d re-identified across restart with no admin save: boot1=%s boot2=%s — stable identity must be durable", i, b1[i].StableID, b2[i].StableID)
		}
	}
}

// ─── E (snapshot door): duplicate FileProfile IDs must reject the snapshot ──

// TestDCFin_SnapshotRejectsDuplicateFileProfileIDs (§13–§15): FileProfile IDs
// are enforcement-authoritative, so a CP→DP ConfigSnapshot carrying two
// profiles with one ID is ambiguous identity and must be rejected BEFORE any
// slice applies.
func TestDCFin_SnapshotRejectsDuplicateFileProfileIDs(t *testing.T) {
	snap := ConfigSnapshot{
		Version: 1,
		FileProfiles: []FileExtProfile{
			{ID: "dup-x", Name: "A", Extensions: []string{".a"}},
			{ID: "dup-x", Name: "B", Extensions: []string{".b"}},
		},
	}
	if err := validateConfigSnapshot(snap); err == nil {
		t.Fatal("ConfigSnapshot with duplicate FileProfile IDs accepted: GetByID becomes first-match ambiguity — must reject before any slice applies")
	}
	// Missing ID is corruption for the same reason (every version that ever
	// persisted profiles wrote IDs — see the §14 audit).
	snap.FileProfiles = []FileExtProfile{{Name: "NoID", Extensions: []string{".a"}}}
	if err := validateConfigSnapshot(snap); err == nil {
		t.Fatal("ConfigSnapshot with a missing FileProfile ID accepted — must reject")
	}
}

// ─── F: malformed non-empty rewrite StableID at the bulk doors ──────────────

// TestDCFin_MalformedRewriteStableIDRejected (§16): the contract says
// StableID is a server-owned UUID. Empty = legacy candidate (eligible for
// migration); non-empty must BE a UUID; malformed non-empty rejects the whole
// candidate at every validated door.
func TestDCFin_MalformedRewriteStableIDRejected(t *testing.T) {
	bad := []RewriteRule{{Host: "h.example", StableID: "hello", ReqRemove: []string{"X-Y"}}}
	if err := validateRewriteStableIDs(bad); err == nil {
		t.Fatal(`stableId "hello" accepted: prose says UUID, the validator must enforce it (malformed non-empty rejects the whole candidate)`)
	}
	// Controls that must stay accepted: empty (legacy) and a real UUID.
	ok := []RewriteRule{
		{Host: "l.example", ReqRemove: []string{"X"}},
		{Host: "m.example", StableID: "3b241101-e2bb-4255-8caf-4136c566a962", ReqRemove: []string{"Y"}},
	}
	if err := validateRewriteStableIDs(ok); err != nil {
		t.Fatalf("legacy-empty + valid-UUID candidate must stay accepted: %v", err)
	}
}

// TestDCFin_MalformedRewriteStableIDRejectedAtImportDoor (§16): the same
// contract through the real import door — whole candidate refused, nothing
// installed.
func TestDCFin_MalformedRewriteStableIDRejectedAtImportDoor(t *testing.T) {
	restoreRewriter := rewriter.Snapshot()
	t.Cleanup(restoreRewriter)
	rewriter.SetRules(nil)
	swapAdminSettingsPath(t, filepath.Join(t.TempDir(), "settings.json"))
	csrTaxIsolate(t)
	snapshotBlocklistGlobals(t)

	w := canonImportBackup(t, "replace", &configBackup{
		Version:      1,
		RewriteRules: []RewriteRule{{Host: "h.example", StableID: "not-a-uuid", ReqRemove: []string{"X-Y"}}},
	})
	if w.Code != 400 {
		t.Fatalf("import carrying a malformed rewrite stableId must refuse the WHOLE candidate with 400, got %d: %s", w.Code, w.Body.String())
	}
	if got := rewriter.List(); len(got) != 0 {
		t.Fatalf("refused import must install nothing, got %+v", got)
	}
}

// ─── G: rollback operator truth — rewrite_rules is durable now ─────────────

// TestDCFin_RewriteRollbackIsNotReportedRuntimeOnly (§17): 2D-C made the
// rollback rewrite slice durable (installRewriteRulesDurable through the
// AdminSettings owner), so the rollback response's runtime_only_surfaces list
// claiming it reverts after restart is false operator information.
func TestDCFin_RewriteRollbackIsNotReportedRuntimeOnly(t *testing.T) {
	for _, s := range rollbackRuntimeOnlySurfaces {
		if s == "rewrite_rules" {
			t.Fatal("rollbackRuntimeOnlySurfaces still names rewrite_rules — the rollback rewrite slice persists through AdminSettings since 2D-C, so this is stale operator truth")
		}
	}
}

// ─── H: history diff must see same-host operation-only edits ───────────────

// TestDCFin_RewriteHistoryDiffSeesOperationOnlyEdit (§18): with StableID
// durable, the config-version rewrite diff must be identity-aware — an
// operation change on the same StableID (same host) is a real change.
func TestDCFin_RewriteHistoryDiffSeesOperationOnlyEdit(t *testing.T) {
	a := []RewriteRule{{StableID: "3b241101-e2bb-4255-8caf-4136c566a962", Host: "h.example", ReqSet: map[string]string{"X-T": "1"}}}
	b := []RewriteRule{{StableID: "3b241101-e2bb-4255-8caf-4136c566a962", Host: "h.example", ReqSet: map[string]string{"X-T": "2"}}}
	var out []configChange
	diffRewriteRules(a, b, &out)
	if len(out) == 0 {
		t.Fatal("operation-only edit on the same StableID/host reported as no change — the history diff hides a real rewrite edit")
	}
}

// TestDCFin_RewriteHistoryDiffLegacyConservativeFallback (§18): legacy history
// entries without StableIDs must never claim "no change" when the actual
// rewrite set changed (same hosts, different operations).
func TestDCFin_RewriteHistoryDiffLegacyConservativeFallback(t *testing.T) {
	a := []RewriteRule{{Host: "h.example", RespAdd: map[string]string{"X-L": "1"}}}
	b := []RewriteRule{{Host: "h.example", RespAdd: map[string]string{"X-L": "2"}}}
	var out []configChange
	diffRewriteRules(a, b, &out)
	if len(out) == 0 {
		t.Fatal("legacy (no-stableId) op-only edit reported as no change — the fallback must stay conservative")
	}
}

// TestDCFin_RewriteHistoryDiffOrderingChange (§18): order is semantics — a
// pure reorder of the same identified rules is a reportable change.
func TestDCFin_RewriteHistoryDiffOrderingChange(t *testing.T) {
	r1 := RewriteRule{StableID: "3b241101-e2bb-4255-8caf-4136c566a901", Host: "a.example", ReqRemove: []string{"X"}}
	r2 := RewriteRule{StableID: "3b241101-e2bb-4255-8caf-4136c566a902", Host: "b.example", ReqRemove: []string{"Y"}}
	a := []RewriteRule{r1, r2}
	b := []RewriteRule{r2, r1}
	var out []configChange
	diffRewriteRules(a, b, &out)
	if len(out) == 0 {
		t.Fatal("pure reorder reported as no change — evaluation order is semantics")
	}
}
