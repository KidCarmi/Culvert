package main

// object_durability_test.go — 2D-A.0 handler-level proofs (§26/§27): the
// category-group / decryption-profile mutation surface is durable-or-nothing,
// version-fenced, and the composed rename operation leaves deterministic
// ID-authoritative state at every durable phase, converged by
// reconcileObjectRefNames after a crash. No test inspects memory only —
// durable claims are proven by reloading real stores from disk.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/catgroup"
	"github.com/KidCarmi/Culvert/internal/decryptprofile"
)

// objDurSetup isolates BOTH object stores onto real temp paths (durability is
// part of the contract under test) plus the policy store / draft / config
// versions, and returns the object stores' paths.
func objDurSetup(t *testing.T) (groupPath, profilePath string) {
	t.Helper()
	dir := t.TempDir()

	origGroups := globalCategoryGroups
	freshGroups := catgroup.New()
	groupPath = filepath.Join(dir, "category_groups.json")
	freshGroups.SetPathForTest(groupPath)
	globalCategoryGroups = freshGroups
	t.Cleanup(func() { globalCategoryGroups = origGroups })

	origProfiles := globalDecryptionProfiles
	freshProfiles := decryptprofile.New()
	profilePath = filepath.Join(dir, "decryption_profiles.json")
	freshProfiles.SetPathForTest(profilePath)
	globalDecryptionProfiles = freshProfiles
	t.Cleanup(func() { globalDecryptionProfiles = origProfiles })

	draftTestSetup(t) // policy store snapshot + draft reset + require-commit off
	return groupPath, profilePath
}

// brokenPath returns a path whose parent is a regular FILE, so AtomicWrite's
// temp-file create fails with ENOTDIR — a real filesystem fault, even for root.
func brokenPath(t *testing.T, base string) string {
	t.Helper()
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(blocker, base)
}

func doGroups(t *testing.T, method, target string, body any) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	apiCategoryGroups(w, jsonReq(method, target, body))
	return w
}

func doProfiles(t *testing.T, method, target string, body any) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	apiDecryptionProfiles(w, jsonReq(method, target, body))
	return w
}

// reloadGroups / reloadProfiles are the restart oracles.
func reloadGroups(t *testing.T, path string) *catgroup.Store {
	t.Helper()
	s := catgroup.New()
	if err := s.Load(path); err != nil {
		t.Fatalf("reload groups: %v", err)
	}
	return s
}

func reloadProfiles(t *testing.T, path string) *decryptprofile.Store {
	t.Helper()
	s := decryptprofile.New()
	if err := s.Load(path); err != nil {
		t.Fatalf("reload profiles: %v", err)
	}
	return s
}

// TestObjectHandlers_CreatePersistFailure_NeverConfirms: a persist failure on
// create returns 500, the store rolls back, and the durable truth (the file the
// previous successful mutation wrote) is unchanged — for BOTH object domains.
func TestObjectHandlers_CreatePersistFailure_NeverConfirms(t *testing.T) {
	groupPath, profilePath := objDurSetup(t)

	if w := doGroups(t, http.MethodPost, "/api/category-groups", map[string]any{"name": "Keep", "categories": []string{"news"}}); w.Code != 200 {
		t.Fatalf("seed group: %d %s", w.Code, w.Body.String())
	}
	globalCategoryGroups.SetPathForTest(brokenPath(t, "category_groups.json"))
	if w := doGroups(t, http.MethodPost, "/api/category-groups", map[string]any{"name": "Doomed"}); w.Code != http.StatusInternalServerError {
		t.Fatalf("group create with broken persistence = %d, want 500", w.Code)
	}
	if globalCategoryGroups.GetByName("Doomed") != nil {
		t.Fatal("failed group create must roll back in memory")
	}
	if fresh := reloadGroups(t, groupPath); fresh.GetByName("Doomed") != nil || fresh.GetByName("Keep") == nil {
		t.Fatal("durable group truth changed on a failed create")
	}

	if w := doProfiles(t, http.MethodPost, "/api/decryption-profiles", map[string]any{"name": "keep-prof", "certVerification": "strict"}); w.Code != 200 {
		t.Fatalf("seed profile: %d %s", w.Code, w.Body.String())
	}
	globalDecryptionProfiles.SetPathForTest(brokenPath(t, "decryption_profiles.json"))
	if w := doProfiles(t, http.MethodPost, "/api/decryption-profiles", map[string]any{"name": "doomed-prof"}); w.Code != http.StatusInternalServerError {
		t.Fatalf("profile create with broken persistence = %d, want 500", w.Code)
	}
	if globalDecryptionProfiles.GetByName("doomed-prof") != nil {
		t.Fatal("failed profile create must roll back in memory")
	}
	if fresh := reloadProfiles(t, profilePath); fresh.GetByName("doomed-prof") != nil || fresh.GetByName("keep-prof") == nil {
		t.Fatal("durable profile truth changed on a failed create")
	}
}

// TestObjectHandlers_EditAndDeletePersistFailure_RollBack: edit and delete
// under a broken persistence path fail with 500 and leave memory AND disk at
// the previous truth (both domains).
func TestObjectHandlers_EditAndDeletePersistFailure_RollBack(t *testing.T) {
	groupPath, profilePath := objDurSetup(t)
	doGroups(t, http.MethodPost, "/api/category-groups", map[string]any{"name": "G", "categories": []string{"news"}})
	gid := globalCategoryGroups.GetByName("G").ID
	doProfiles(t, http.MethodPost, "/api/decryption-profiles", map[string]any{"name": "p", "minTlsVersion": "1.2"})
	pid := globalDecryptionProfiles.GetByName("p").ID

	globalCategoryGroups.SetPathForTest(brokenPath(t, "category_groups.json"))
	if w := doGroups(t, http.MethodPut, "/api/category-groups?id="+gid, map[string]any{"name": "G", "categories": []string{"ai"}}); w.Code != 500 {
		t.Fatalf("group edit persist failure = %d, want 500", w.Code)
	}
	if got := globalCategoryGroups.GetByID(gid).Categories; len(got) != 1 || got[0] != "news" {
		t.Fatalf("group edit not rolled back: %v", got)
	}
	if w := doGroups(t, http.MethodDelete, "/api/category-groups?id="+gid, nil); w.Code != 500 {
		t.Fatalf("group delete persist failure = %d, want 500", w.Code)
	}
	if globalCategoryGroups.GetByID(gid) == nil {
		t.Fatal("group delete not rolled back")
	}
	if fresh := reloadGroups(t, groupPath); fresh.GetByID(gid) == nil || fresh.GetByID(gid).Categories[0] != "news" {
		t.Fatal("durable group truth changed")
	}

	globalDecryptionProfiles.SetPathForTest(brokenPath(t, "decryption_profiles.json"))
	if w := doProfiles(t, http.MethodPut, "/api/decryption-profiles?id="+pid, map[string]any{"name": "p", "minTlsVersion": "1.3"}); w.Code != 500 {
		t.Fatalf("profile edit persist failure = %d, want 500", w.Code)
	}
	if got := globalDecryptionProfiles.GetByID(pid).MinTLSVersion; got != "1.2" {
		t.Fatalf("profile edit not rolled back: %q", got)
	}
	if w := doProfiles(t, http.MethodDelete, "/api/decryption-profiles?id="+pid, nil); w.Code != 500 {
		t.Fatalf("profile delete persist failure = %d, want 500", w.Code)
	}
	if globalDecryptionProfiles.GetByID(pid) == nil {
		t.Fatal("profile delete not rolled back")
	}
	if fresh := reloadProfiles(t, profilePath); fresh.GetByID(pid) == nil || fresh.GetByID(pid).MinTLSVersion != "1.2" {
		t.Fatal("durable profile truth changed")
	}
}

// TestObjectHandlers_IfVersionFence: the handlers surface the store fence as
// the product-wide structured 409 ({error, currentVersion, yourVersion}), the
// fenced-out mutation never lands, and a fresh token proceeds.
func TestObjectHandlers_IfVersionFence(t *testing.T) {
	objDurSetup(t)
	doGroups(t, http.MethodPost, "/api/category-groups", map[string]any{"name": "G"})
	gid := globalCategoryGroups.GetByName("G").ID

	w := doGroups(t, http.MethodPut, "/api/category-groups?id="+gid+"&ifVersion=0", map[string]any{"name": "G", "categories": []string{"ai"}})
	if w.Code != http.StatusConflict {
		t.Fatalf("stale ifVersion = %d, want 409", w.Code)
	}
	var payload struct {
		Error          string `json:"error"`
		CurrentVersion int64  `json:"currentVersion"`
		YourVersion    int64  `json:"yourVersion"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("409 body not the structured conflict: %v (%s)", err, w.Body.String())
	}
	if payload.CurrentVersion != 1 || payload.YourVersion != 0 || payload.Error == "" {
		t.Fatalf("conflict payload = %+v", payload)
	}
	if len(globalCategoryGroups.GetByName("G").Categories) != 0 {
		t.Fatal("fenced-out edit must not land")
	}
	cur := strconv.FormatInt(globalCategoryGroups.Version(), 10)
	if w := doGroups(t, http.MethodPut, "/api/category-groups?id="+gid+"&ifVersion="+cur, map[string]any{"name": "G", "categories": []string{"ai"}}); w.Code != 200 {
		t.Fatalf("fresh-token edit = %d %s", w.Code, w.Body.String())
	}

	// Same fence contract on the profile handler (delete flavor).
	doProfiles(t, http.MethodPost, "/api/decryption-profiles", map[string]any{"name": "p"})
	pidCur := globalDecryptionProfiles.Version()
	pid := globalDecryptionProfiles.GetByName("p").ID
	if w := doProfiles(t, http.MethodDelete, "/api/decryption-profiles?id="+pid+"&ifVersion="+strconv.FormatInt(pidCur-1, 10), nil); w.Code != http.StatusConflict {
		t.Fatalf("stale profile delete = %d, want 409", w.Code)
	}
	if globalDecryptionProfiles.GetByID(pid) == nil {
		t.Fatal("fenced-out delete must not land")
	}
}

// TestObjectHandlers_NameCollisionIs409: create-duplicate and rename-onto-taken
// are server-authoritative 409 refusals (checked under the store lock).
func TestObjectHandlers_NameCollisionIs409(t *testing.T) {
	objDurSetup(t)
	doGroups(t, http.MethodPost, "/api/category-groups", map[string]any{"name": "A"})
	doGroups(t, http.MethodPost, "/api/category-groups", map[string]any{"name": "B"})
	if w := doGroups(t, http.MethodPost, "/api/category-groups", map[string]any{"name": "a"}); w.Code != http.StatusConflict {
		t.Fatalf("duplicate create = %d, want 409", w.Code)
	}
	bid := globalCategoryGroups.GetByName("B").ID
	if w := doGroups(t, http.MethodPut, "/api/category-groups?id="+bid, map[string]any{"name": "A"}); w.Code != http.StatusConflict {
		t.Fatalf("rename onto taken name = %d, want 409", w.Code)
	}
	if globalCategoryGroups.GetByID(bid).Name != "B" {
		t.Fatal("refused rename must not change the name")
	}
}

// TestRename_Phase1ObjectPersistFailure: when the OBJECT store cannot persist,
// the rename fails 500 with nothing changed anywhere — no cascade runs.
func TestRename_Phase1ObjectPersistFailure(t *testing.T) {
	groupPath, _ := objDurSetup(t)
	doGroups(t, http.MethodPost, "/api/category-groups", map[string]any{"name": "Old", "categories": []string{"news"}})
	gid := globalCategoryGroups.GetByName("Old").ID
	w := doGroups(t, http.MethodPost, "/api/policy", nil) // (no-op guard: wrong handler never called)
	_ = w
	createRuleReferencingGroup(t, "r1", "Old")

	globalCategoryGroups.SetPathForTest(brokenPath(t, "category_groups.json"))
	if w := doGroups(t, http.MethodPut, "/api/category-groups?id="+gid, map[string]any{"name": "New", "categories": []string{"news"}}); w.Code != 500 {
		t.Fatalf("phase-1 rename failure = %d, want 500", w.Code)
	}
	if globalCategoryGroups.GetByID(gid).Name != "Old" {
		t.Fatal("phase-1 failure must roll the object rename back")
	}
	if rule := findRunningRuleByName(t, "r1"); rule.DestCategoryGroup != "Old" {
		t.Fatalf("cascade must not run after a phase-1 failure: %q", rule.DestCategoryGroup)
	}
	if fresh := reloadGroups(t, groupPath); fresh.GetByID(gid).Name != "Old" {
		t.Fatal("durable object truth changed on a failed rename")
	}
}

// TestRename_Phase2RunningCascadePersistFailure: the object rename is durable,
// the running cascade cannot persist → truthful 500 (never 2xx with a
// known-failed durable domain), in-memory names stay correct (cascaded), the
// stable IDs keep enforcement unchanged, and reconcileObjectRefNames converges
// a stale reload deterministically.
func TestRename_Phase2RunningCascadePersistFailure(t *testing.T) {
	groupPath, _ := objDurSetup(t)
	doGroups(t, http.MethodPost, "/api/category-groups", map[string]any{"name": "Old", "categories": []string{"news"}})
	gid := globalCategoryGroups.GetByName("Old").ID
	createRuleReferencingGroup(t, "r1", "Old")
	ruleID := findRunningRuleByName(t, "r1").ID

	// Break the RUNNING policy store's persistence only.
	policyStore.path = brokenPath(t, "policy.json")

	w := doGroups(t, http.MethodPut, "/api/category-groups?id="+gid, map[string]any{"name": "New", "categories": []string{"news"}})
	if w.Code != 500 {
		t.Fatalf("phase-2 rename failure = %d, want 500 (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "rename is durable") {
		t.Fatalf("phase-2 failure must state the object rename is durable: %s", w.Body.String())
	}
	// Object domain: durable new name.
	if fresh := reloadGroups(t, groupPath); fresh.GetByID(gid).Name != "New" {
		t.Fatal("object rename must be durable after phase 1")
	}
	// In-memory policy: cascade kept (display-correct now), stable link intact.
	rule := findRunningRuleByName(t, "r1")
	if rule.ID != ruleID || rule.DestCategoryGroupID != gid || rule.DestCategoryGroup != "New" {
		t.Fatalf("in-memory cascade wrong: %+v", rule)
	}

	// Deterministic recovery: simulate the restart that reloads STALE policy
	// names from a surviving old file — reconciliation re-derives them from the
	// ID-authoritative object store.
	policyStore.path = ""
	stale := []PolicyRule{{ID: ruleID, Name: "r1", Action: "Allow", DestCategoryGroup: "Old", DestCategoryGroupID: gid, Priority: 10}}
	policyStore.ReplaceAll(stale)
	reconcileObjectRefNames()
	rule = findRunningRuleByName(t, "r1")
	if rule.DestCategoryGroup != "New" || rule.DestCategoryGroupID != gid || rule.ID != ruleID {
		t.Fatalf("reconciliation did not converge: %+v", rule)
	}
}

// TestRename_DraftCascadePersistFailure: with an active draft whose candidate
// references the object and a broken draft persistence path, the rename
// returns a truthful 500 naming the draft domain while the candidate's
// IN-MEMORY names are already correct.
func TestRename_DraftCascadePersistFailure(t *testing.T) {
	_, _ = objDurSetup(t)
	doGroups(t, http.MethodPost, "/api/category-groups", map[string]any{"name": "Old", "categories": []string{"news"}})
	gid := globalCategoryGroups.GetByName("Old").ID

	setRequireCommit(true)
	createRuleReferencingGroup(t, "staged", "Old") // opens the draft, stages the rule
	if !policyDraft.active() {
		t.Fatal("draft must be active")
	}
	policyDraft.mu.Lock()
	policyDraft.path = brokenPath(t, "policy_draft.json")
	policyDraft.mu.Unlock()

	w := doGroups(t, http.MethodPut, "/api/category-groups?id="+gid, map[string]any{"name": "New", "categories": []string{"news"}})
	if w.Code != 500 || !strings.Contains(w.Body.String(), "draft candidate") {
		t.Fatalf("draft-phase failure = %d %s, want truthful 500 naming the draft domain", w.Code, w.Body.String())
	}
	cand := policyDraft.candidateList()
	if len(cand) != 1 || cand[0].DestCategoryGroup != "New" || cand[0].DestCategoryGroupID != gid {
		t.Fatalf("candidate in-memory cascade wrong: %+v", cand)
	}
}

// TestRename_ReferenceIntegrity_RunningAndDraft is the §27 proof for category
// groups: object + running reference + staged draft reference, rename, then
// every identity/name/blocking assertion — and the same via disk reload.
func TestRename_ReferenceIntegrity_RunningAndDraft(t *testing.T) {
	groupPath, _ := objDurSetup(t)
	dir := t.TempDir()
	policyStore.path = filepath.Join(dir, "policy.json")
	policyDraft.mu.Lock()
	policyDraft.path = filepath.Join(dir, "policy_draft.json")
	policyDraft.mu.Unlock()

	doGroups(t, http.MethodPost, "/api/category-groups", map[string]any{"name": "Old", "categories": []string{"news", "ai"}})
	gid := globalCategoryGroups.GetByName("Old").ID

	createRuleReferencingGroup(t, "running-ref", "Old")
	runningID := findRunningRuleByName(t, "running-ref").ID

	setRequireCommit(true)
	createRuleReferencingGroup(t, "draft-ref", "Old")
	if !policyDraft.active() {
		t.Fatal("draft must be active")
	}
	var draftID string
	for _, r := range policyDraft.candidateList() {
		if r.Name == "draft-ref" {
			draftID = r.ID
		}
	}
	if draftID == "" {
		t.Fatal("staged rule missing")
	}

	// Rename via stable ID.
	if w := doGroups(t, http.MethodPut, "/api/category-groups?id="+gid, map[string]any{"name": "New", "categories": []string{"news", "ai"}}); w.Code != 200 {
		t.Fatalf("rename: %d %s", w.Code, w.Body.String())
	}

	// Object: same ID, new name. Match semantics unchanged (ID-keyed).
	g := globalCategoryGroups.GetByID(gid)
	if g == nil || g.Name != "New" {
		t.Fatalf("object after rename: %+v", g)
	}
	if matched, resolved := globalCategoryGroups.MatchesCategoryByID(gid, "news"); !matched || !resolved {
		t.Fatal("ID-keyed match changed across rename")
	}
	// Running rule: same rule ID, same authoritative link, new denormalized name.
	rr := findRunningRuleByName(t, "running-ref")
	if rr.ID != runningID || rr.DestCategoryGroupID != gid || rr.DestCategoryGroup != "New" {
		t.Fatalf("running rule after rename: %+v", rr)
	}
	// Draft candidate rule: same.
	var dr *PolicyRule
	for _, r := range policyDraft.candidateList() {
		if r.Name == "draft-ref" {
			cp := r
			dr = &cp
		}
	}
	if dr == nil || dr.ID != draftID || dr.DestCategoryGroupID != gid || dr.DestCategoryGroup != "New" {
		t.Fatalf("draft rule after rename: %+v", dr)
	}
	// Where Used finds BOTH consumers by the authoritative ID under the NEW name.
	found, refs := objectReferences("category-group", "New")
	if !found || len(refs) != 2 {
		t.Fatalf("where-used after rename = found=%v refs=%+v, want both consumers", found, refs)
	}
	// Delete remains blocked.
	if w := doGroups(t, http.MethodDelete, "/api/category-groups?id="+gid, nil); w.Code != http.StatusConflict {
		t.Fatalf("referenced delete = %d, want 409", w.Code)
	}
	// The running cascade advanced the running generation, so the ACTIVE draft
	// reads base-stale — the truthful commit-fence behavior 2D-A renders (§28).
	if !policyDraft.baseGenerationStale() {
		t.Fatal("running cascade must stale the active draft's base generation")
	}

	// Restart/reload: every durable domain agrees.
	if fresh := reloadGroups(t, groupPath); fresh.GetByID(gid).Name != "New" {
		t.Fatal("reloaded object name wrong")
	}
	freshPolicy := &PolicyStore{}
	if err := freshPolicy.Load(policyStore.path); err != nil {
		t.Fatalf("reload policy: %v", err)
	}
	var freshRule *PolicyRule
	for _, r := range freshPolicy.List() {
		if r.Name == "running-ref" {
			cp := r
			freshRule = &cp
		}
	}
	if freshRule == nil || freshRule.ID != runningID || freshRule.DestCategoryGroupID != gid || freshRule.DestCategoryGroup != "New" {
		t.Fatalf("reloaded running rule: %+v", freshRule)
	}
	var draftFile struct {
		Rules []PolicyRule `json:"rules"`
	}
	policyDraft.mu.Lock()
	draftPath := policyDraft.path
	policyDraft.mu.Unlock()
	data, err := os.ReadFile(draftPath) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatalf("read draft file: %v", err)
	}
	if err := json.Unmarshal(data, &draftFile); err != nil {
		t.Fatal(err)
	}
	okDraft := false
	for _, r := range draftFile.Rules {
		if r.Name == "draft-ref" && r.ID == draftID && r.DestCategoryGroupID == gid && r.DestCategoryGroup == "New" {
			okDraft = true
		}
	}
	if !okDraft {
		t.Fatalf("reloaded draft candidate wrong: %+v", draftFile.Rules)
	}
}

// TestRename_DraftOnlyReference_CommitRemainsValid is the §9 two-client shape:
// the object is referenced ONLY by a staged candidate rule, so the rename
// cascades nothing on running (no generation movement), the candidate follows
// safely, the draft stays commit-able, and the commit lands the SAME object ID.
func TestRename_DraftOnlyReference_CommitRemainsValid(t *testing.T) {
	objDurSetup(t)
	doProfiles(t, http.MethodPost, "/api/decryption-profiles", map[string]any{"name": "old-prof", "onInspectError": "fail-close"})
	pid := globalDecryptionProfiles.GetByName("old-prof").ID

	setRequireCommit(true)
	createRuleReferencingProfile(t, "staged-ref", "old-prof")
	if !policyDraft.active() {
		t.Fatal("draft must be active")
	}

	if w := doProfiles(t, http.MethodPut, "/api/decryption-profiles?id="+pid, map[string]any{"name": "new-prof", "onInspectError": "fail-close"}); w.Code != 200 {
		t.Fatalf("rename: %d %s", w.Code, w.Body.String())
	}
	// Candidate followed; running untouched, so the draft base is NOT stale.
	if policyDraft.baseGenerationStale() {
		t.Fatal("a draft-only rename cascade must not stale the draft base")
	}
	// Commit through the coordinator.
	if _, err := policyDraft.commitActivate(nil); err != nil {
		t.Fatalf("commit after rename: %v", err)
	}
	rule := findRunningRuleByName(t, "staged-ref")
	if rule.DecryptionProfileID != pid || rule.DecryptionProfile != "new-prof" {
		t.Fatalf("committed rule reference wrong: %+v", rule)
	}
	// Runtime resolution lands on the SAME object.
	resolved := resolveDecryptionProfile(&PolicyMatch{Rule: rule})
	if resolved == nil || resolved.ID != pid {
		t.Fatalf("resolver landed on the wrong object: %+v", resolved)
	}
}

// TestReconcileObjectRefNames_NoopOnCleanState: a clean boot reconciles nothing
// (no version movement, no writes).
func TestReconcileObjectRefNames_NoopOnCleanState(t *testing.T) {
	objDurSetup(t)
	doGroups(t, http.MethodPost, "/api/category-groups", map[string]any{"name": "G"})
	gid := globalCategoryGroups.GetByName("G").ID
	createRuleReferencingGroup(t, "r", "G")
	verBefore, _ := policyStore.policyVersion()
	reconcileObjectRefNames()
	if ver, _ := policyStore.policyVersion(); ver != verBefore {
		t.Fatalf("clean reconcile moved the running generation: %d → %d", verBefore, ver)
	}
	if findRunningRuleByName(t, "r").DestCategoryGroupID != gid {
		t.Fatal("reconcile disturbed a clean rule")
	}
}

// TestReconcileObjectRefNames_DanglingIDUntouched: a rule whose object-link ID
// resolves to NO object keeps its denormalized name — that name is the
// documented legacy/name-fallback matching input, so rewriting it would change
// enforcement.
func TestReconcileObjectRefNames_DanglingIDUntouched(t *testing.T) {
	objDurSetup(t)
	stale := []PolicyRule{{ID: "01TESTDANGLINGRULEAAAAAAAA", Name: "dangling", Action: "Allow", DestCategoryGroup: "Ghost", DestCategoryGroupID: "no-such-id", Priority: 5}}
	policyStore.ReplaceAll(stale)
	reconcileObjectRefNames()
	if r := findRunningRuleByName(t, "dangling"); r.DestCategoryGroup != "Ghost" || r.DestCategoryGroupID != "no-such-id" {
		t.Fatalf("dangling reference rewritten: %+v", r)
	}
}

// createRuleReferencingGroup creates a policy rule via the REAL handler (so
// stampObjectRefIDs derives the authoritative link server-side — the browser
// never chooses IDs).
func createRuleReferencingGroup(t *testing.T, name, groupName string) {
	t.Helper()
	w := httptest.NewRecorder()
	apiPolicyCreate(w, jsonReq(http.MethodPost, "/api/policy", map[string]any{
		"name": name, "action": "Allow", "destCategoryGroup": groupName,
	}))
	if w.Code != 200 {
		t.Fatalf("create rule %s: %d %s", name, w.Code, w.Body.String())
	}
}

func createRuleReferencingProfile(t *testing.T, name, profileName string) {
	t.Helper()
	w := httptest.NewRecorder()
	apiPolicyCreate(w, jsonReq(http.MethodPost, "/api/policy", map[string]any{
		"name": name, "action": "Allow", "sslAction": "Inspect", "decryptionProfile": profileName,
	}))
	if w.Code != 200 {
		t.Fatalf("create rule %s: %d %s", name, w.Code, w.Body.String())
	}
}

// findRunningRuleByName returns the EFFECTIVE-write-domain copy of a rule: the running
// store in live mode (the draft candidate is consulted by callers that need it).
func findRunningRuleByName(t *testing.T, name string) *PolicyRule {
	t.Helper()
	for _, r := range policyStore.List() {
		if r.Name == name {
			cp := r
			return &cp
		}
	}
	t.Fatalf("rule %q not found in running store", name)
	return nil
}
