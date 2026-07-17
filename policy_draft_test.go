package main

// policy_draft_test.go — candidate/commit backend (policy-draft / G2, S1).
// Authority: docs/design/POLICY-DRAFT-DESIGN.md §10.
//
// Proves: off-mode is byte-identical live-write; on-mode stages into the
// candidate without touching running/Evaluate or writing per-edit config
// versions; commit activates the whole candidate atomically + one config
// version; revert discards; the guardrails (required comment, disarm-while-dirty,
// candidate-version optimistic concurrency, base-generation staleness) hold; and
// a pending draft survives a restart.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// draftTestSetup isolates the running store, the config-version dir, the
// RequireCommit flag, and the draft coordinator for one test.
func draftTestSetup(t *testing.T) {
	t.Helper()
	snapshotPolicyStoreForTest(t)
	snapshotConfigVersionsDir(t)
	policyStore.ReplaceAll(nil)

	prev := requireCommitEnabled()
	setRequireCommit(false)
	resetDraft := func() {
		policyDraft.mu.Lock()
		policyDraft.cand = &PolicyStore{}
		policyDraft.state = draftState{}
		policyDraft.path = ""
		policyDraft.mu.Unlock()
	}
	resetDraft()
	t.Cleanup(func() { setRequireCommit(prev); resetDraft() })
}

func createRuleViaAPI(t *testing.T, name string, ifVersion string) *httptest.ResponseRecorder {
	t.Helper()
	path := "/api/policy"
	if ifVersion != "" {
		path += "?ifVersion=" + ifVersion
	}
	w := httptest.NewRecorder()
	apiPolicyCreate(w, jsonReq("POST", path, map[string]any{"name": name, "action": "Allow"}))
	return w
}

func countConfigVersions(action string) int {
	n := 0
	for _, v := range configVersions.List() {
		if v.Action == action {
			n++
		}
	}
	return n
}

// TestDraft_OffMode_LiveWrite: with RequireCommit off, a create hits running
// immediately, writes a per-edit config version, and opens no draft.
func TestDraft_OffMode_LiveWrite(t *testing.T) {
	draftTestSetup(t)
	if policyWriteStore("actor") != policyStore {
		t.Fatal("off-mode policyWriteStore must be the running store")
	}
	before := countConfigVersions("policy.add")
	if w := createRuleViaAPI(t, "live-rule", ""); w.Code != http.StatusOK {
		t.Fatalf("create = %d (%s)", w.Code, w.Body.String())
	}
	if len(policyStore.List()) != 1 {
		t.Errorf("off-mode create did not hit running store: %d rules", len(policyStore.List()))
	}
	if policyDraft.active() {
		t.Error("off-mode create opened a draft")
	}
	if countConfigVersions("policy.add") != before+1 {
		t.Error("off-mode create did not write a per-edit config version")
	}
}

// TestDraft_StageIsolation: with RequireCommit on, a create stages into the
// candidate — running and Evaluate are untouched and NO per-edit config version
// is written.
func TestDraft_StageIsolation(t *testing.T) {
	draftTestSetup(t)
	setRequireCommit(true)
	before := countConfigVersions("policy.add")

	if w := createRuleViaAPI(t, "staged-rule", ""); w.Code != http.StatusOK {
		t.Fatalf("staged create = %d (%s)", w.Code, w.Body.String())
	}
	if len(policyStore.List()) != 0 {
		t.Errorf("staged create leaked into running: %d rules", len(policyStore.List()))
	}
	if !policyDraft.active() {
		t.Error("staged create did not open a draft")
	}
	if len(policyDraft.candidateList()) != 1 {
		t.Errorf("candidate missing the staged rule: %d", len(policyDraft.candidateList()))
	}
	if countConfigVersions("policy.add") != before {
		t.Error("staged create wrote a per-edit config version (should defer to commit)")
	}
}

// TestDraft_Commit: commit activates the whole candidate atomically, writes one
// policy.commit config version, and clears the draft.
func TestDraft_Commit(t *testing.T) {
	draftTestSetup(t)
	setRequireCommit(true)
	createRuleViaAPI(t, "r1", "")
	createRuleViaAPI(t, "r2", "")
	if len(policyStore.List()) != 0 {
		t.Fatal("running changed during staging")
	}
	beforeCommits := countConfigVersions("policy.commit")

	w := httptest.NewRecorder()
	apiPolicyDraftCommit(w, jsonReq("POST", "/api/policy/draft/commit", map[string]any{"comment": "ship it"}))
	if w.Code != http.StatusOK {
		t.Fatalf("commit = %d (%s)", w.Code, w.Body.String())
	}
	if len(policyStore.List()) != 2 {
		t.Errorf("commit did not activate the candidate: running has %d rules", len(policyStore.List()))
	}
	if policyDraft.active() {
		t.Error("draft still active after commit")
	}
	if countConfigVersions("policy.commit") != beforeCommits+1 {
		t.Error("commit did not write exactly one policy.commit config version")
	}
}

// TestDraft_Commit_RequiresComment: an empty/absent comment is a 400.
func TestDraft_Commit_RequiresComment(t *testing.T) {
	draftTestSetup(t)
	setRequireCommit(true)
	createRuleViaAPI(t, "r1", "")

	w := httptest.NewRecorder()
	apiPolicyDraftCommit(w, jsonReq("POST", "/api/policy/draft/commit", map[string]any{"comment": "   "}))
	if w.Code != http.StatusBadRequest {
		t.Errorf("commit without comment = %d, want 400", w.Code)
	}
	if !policyDraft.active() {
		t.Error("failed commit cleared the draft")
	}
}

// TestDraft_Revert: revert discards the candidate; running is untouched.
func TestDraft_Revert(t *testing.T) {
	draftTestSetup(t)
	policyStore.Add(PolicyRule{Name: "keep", Action: ActionAllow})
	setRequireCommit(true)
	createRuleViaAPI(t, "throwaway", "")
	if !policyDraft.active() {
		t.Fatal("draft not open")
	}

	w := httptest.NewRecorder()
	apiPolicyDraftRevert(w, jsonReq("POST", "/api/policy/draft/revert", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("revert = %d (%s)", w.Code, w.Body.String())
	}
	if policyDraft.active() {
		t.Error("draft still active after revert")
	}
	if names := ruleNames(policyStore.List()); len(names) != 1 || names[0] != "keep" {
		t.Errorf("revert changed running: %v", names)
	}
}

// TestDraft_DisarmWhileDirty_409: turning RequireCommit off with a pending draft
// is blocked.
func TestDraft_DisarmWhileDirty_409(t *testing.T) {
	draftTestSetup(t)
	setRequireCommit(true)
	createRuleViaAPI(t, "pending", "")

	w := httptest.NewRecorder()
	apiPolicyDraft(w, jsonReq("PUT", "/api/policy/draft", map[string]any{"require_commit": false}))
	if w.Code != http.StatusConflict {
		t.Errorf("disarm-while-dirty = %d, want 409", w.Code)
	}
	if !requireCommitEnabled() {
		t.Error("commit mode was disarmed despite the pending draft")
	}
}

// TestDraft_CandidateVersionConcurrency: while drafting, ?ifVersion echoes the
// CANDIDATE generation — a stale write (another admin staged in between) is 409.
func TestDraft_CandidateVersionConcurrency(t *testing.T) {
	draftTestSetup(t)
	setRequireCommit(true)
	// Open the draft and capture its version.
	createRuleViaAPI(t, "first", "")
	v0, _ := effectivePolicyVersion()
	// A concurrent staged edit bumps the candidate version.
	createRuleViaAPI(t, "second", "")
	// The first admin's write against the now-stale version must 409.
	w := createRuleViaAPI(t, "third", int64ToStr(v0))
	if w.Code != http.StatusConflict {
		t.Errorf("stale candidate write = %d, want 409 (body %s)", w.Code, w.Body.String())
	}
}

// TestDraft_BaseGenerationStale_BlocksCommit: if running changes out-of-band
// (import/rollback) under a draft, commit fails closed.
func TestDraft_BaseGenerationStale_BlocksCommit(t *testing.T) {
	draftTestSetup(t)
	setRequireCommit(true)
	createRuleViaAPI(t, "staged", "")
	// Simulate an out-of-band running mutation (import/rollback bumps running).
	policyStore.Add(PolicyRule{Name: "out-of-band", Action: ActionAllow})

	w := httptest.NewRecorder()
	apiPolicyDraftCommit(w, jsonReq("POST", "/api/policy/draft/commit", map[string]any{"comment": "x"}))
	if w.Code != http.StatusConflict {
		t.Errorf("commit over out-of-band change = %d, want 409", w.Code)
	}
}

// TestDraft_RestartDurability: a pending draft persisted to disk reloads into a
// fresh coordinator.
func TestDraft_RestartDurability(t *testing.T) {
	draftTestSetup(t)
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")

	// Point the live coordinator at a real path and stage a rule.
	policyDraft.mu.Lock()
	policyDraft.path = filepath.Join(dir, "policy_draft.json")
	policyDraft.mu.Unlock()
	setRequireCommit(true)
	createRuleViaAPI(t, "survivor", "")
	if _, err := os.Stat(policyDraft.path); err != nil {
		t.Fatalf("draft file not written: %v", err)
	}

	// Fresh coordinator reloads from the sibling of policyPath.
	orig := policyDraft
	fresh := &policyDraftCoordinator{cand: &PolicyStore{}}
	policyDraft = fresh
	t.Cleanup(func() { policyDraft = orig })
	initPolicyDraft(policyPath)
	if !policyDraft.active() {
		t.Fatal("reloaded coordinator has no active draft")
	}
	if n := ruleNames(policyDraft.candidateList()); len(n) != 1 || n[0] != "survivor" {
		t.Errorf("reloaded candidate = %v, want [survivor]", n)
	}
}

// TestDraft_StrandedDraftOffMode_LiveWriteStaysDurable: if RequireCommit is
// OFF while an active draft exists anyway (a corrupt/defaulted
// admin_settings.json alongside a reloaded policy_draft.json, or the
// disarm-vs-stage race), writes go to RUNNING — so the finalize/read helpers
// must follow the live path too: the mutation persists to disk with a per-edit
// config version, and reads render running, not the stale candidate. Keying
// them on active() alone silently dropped the live Save (mutations — including
// a new Deny — lost on restart).
func TestDraft_StrandedDraftOffMode_LiveWriteStaysDurable(t *testing.T) {
	draftTestSetup(t)

	// Manufacture the divergent state: an active draft with mode OFF.
	setRequireCommit(true)
	createRuleViaAPI(t, "stranded-staged-rule", "")
	if !policyDraft.active() {
		t.Fatal("setup: staging did not open a draft")
	}
	setRequireCommit(false)

	if policyDraftEngaged() {
		t.Fatal("draft must not be engaged while RequireCommit is off")
	}

	// A write in this state is a LIVE write and must stay durable.
	before := countConfigVersions("policy.add")
	if w := createRuleViaAPI(t, "live-deny-after-strand", ""); w.Code != http.StatusOK {
		t.Fatalf("create = %d (%s)", w.Code, w.Body.String())
	}
	if n := ruleNames(policyStore.List()); len(n) != 1 || n[0] != "live-deny-after-strand" {
		t.Fatalf("live write did not hit running: %v", n)
	}
	if countConfigVersions("policy.add") != before+1 {
		t.Error("live write with a stranded draft skipped the per-edit config version (durability regression)")
	}

	// Reads must render RUNNING, not the stale candidate.
	if n := ruleNames(effectivePolicyList()); len(n) != 1 || n[0] != "live-deny-after-strand" {
		t.Errorf("effective list rendered the stale candidate: %v", n)
	}
	ver, _ := effectivePolicyVersion()
	liveVer, _ := policyStore.policyVersion()
	if ver != liveVer {
		t.Errorf("effective version = %d, want running's %d", ver, liveVer)
	}

	// The stranded draft stays recoverable via the draft endpoints (active(),
	// deliberately not engaged()).
	if !policyDraft.active() {
		t.Error("stranded draft must remain visible to /api/policy/draft for commit/revert recovery")
	}
}

// TestDraft_Diff: the diff reports added/removed/modified vs running by ID.
func TestDraft_Diff(t *testing.T) {
	draftTestSetup(t)
	keep := policyStore.Add(PolicyRule{Name: "keep", Action: ActionAllow})
	edit := policyStore.Add(PolicyRule{Name: "edit-me", Action: ActionAllow})
	drop := policyStore.Add(PolicyRule{Name: "drop-me", Action: ActionAllow})
	_ = keep
	setRequireCommit(true)

	// Stage: modify one, delete one, add one (by editing the candidate via handlers).
	// Update "edit-me" content.
	w := httptest.NewRecorder()
	apiPolicyUpdateByID(w, jsonReq("PUT", "/api/policy?id="+edit.ID, map[string]any{"name": "edit-me", "action": "Drop"}), edit.ID)
	if w.Code != http.StatusOK {
		t.Fatalf("stage update = %d (%s)", w.Code, w.Body.String())
	}
	// Delete "drop-me".
	w = httptest.NewRecorder()
	apiPolicyDeleteByID(w, jsonReq("DELETE", "/api/policy?id="+drop.ID, nil), drop.ID)
	if w.Code != http.StatusNoContent {
		t.Fatalf("stage delete = %d", w.Code)
	}
	// Add a new one.
	createRuleViaAPI(t, "brand-new", "")

	d := policyDraft.diffVsRunning()
	if len(d.Added) != 1 || d.Added[0] != "brand-new" {
		t.Errorf("diff.Added = %v, want [brand-new]", d.Added)
	}
	if len(d.Removed) != 1 || d.Removed[0] != "drop-me" {
		t.Errorf("diff.Removed = %v, want [drop-me]", d.Removed)
	}
	if len(d.Modified) != 1 || d.Modified[0] != "edit-me" {
		t.Errorf("diff.Modified = %v, want [edit-me]", d.Modified)
	}
	if d.total() != 3 {
		t.Errorf("diff.total = %d, want 3", d.total())
	}
}

// TestDraft_NoOpEditAutoDiscards: a no-op edit (re-save identical content) must
// NOT leave a zero-diff "active" draft — reconcile auto-discards it, so
// commit-mode can still be disarmed and reads stay on running.
func TestDraft_NoOpEditAutoDiscards(t *testing.T) {
	draftTestSetup(t)
	seed := policyStore.Add(PolicyRule{Name: "noop", Action: ActionAllow})
	setRequireCommit(true)

	// Re-save the rule with identical content by id (a real UI save sends the
	// full rule, incl. enabled — matching the seeded rule's Enabled=true).
	w := httptest.NewRecorder()
	apiPolicyUpdateByID(w, jsonReq("PUT", "/api/policy?id="+seed.ID,
		map[string]any{"name": "noop", "action": "Allow", "enabled": true}), seed.ID)
	if w.Code != http.StatusOK {
		t.Fatalf("no-op update = %d (%s)", w.Code, w.Body.String())
	}
	if policyDraft.active() {
		t.Error("a no-op edit left an active zero-diff draft")
	}
}

// TestDraft_FailedEditDoesNotStickDraft: a failed mutation (delete of an absent
// rule) that opened the draft must reconcile it away, not leave it active.
func TestDraft_FailedEditDoesNotStickDraft(t *testing.T) {
	draftTestSetup(t)
	policyStore.Add(PolicyRule{Name: "present", Action: ActionAllow})
	setRequireCommit(true)

	w := httptest.NewRecorder()
	apiPolicyDelete(w, jsonReq("DELETE", "/api/policy?priority=99999", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("delete of absent rule = %d, want 404", w.Code)
	}
	if policyDraft.active() {
		t.Error("a failed edit left an active draft")
	}
}

// TestDraft_RealEditSurvivesReconcile: a genuine staged change is NOT discarded
// by reconcile (its diff is non-zero).
func TestDraft_RealEditSurvivesReconcile(t *testing.T) {
	draftTestSetup(t)
	seed := policyStore.Add(PolicyRule{Name: "real", Action: ActionAllow})
	setRequireCommit(true)

	w := httptest.NewRecorder()
	apiPolicyUpdateByID(w, jsonReq("PUT", "/api/policy?id="+seed.ID, map[string]any{"name": "real", "action": "Drop"}), seed.ID)
	if w.Code != http.StatusOK {
		t.Fatalf("real update = %d (%s)", w.Code, w.Body.String())
	}
	if !policyDraft.active() {
		t.Error("a real staged edit was discarded by reconcile")
	}
}

// TestDraft_Commit_VersionPrecondition: a commit carrying a stale ?ifVersion
// (another admin staged into the shared candidate since the diff was reviewed)
// is rejected 409; the correct version commits.
func TestDraft_Commit_VersionPrecondition(t *testing.T) {
	draftTestSetup(t)
	setRequireCommit(true)
	createRuleViaAPI(t, "r1", "")
	v, _ := policyDraft.candidateVersion()

	// Stale precondition → 409, draft preserved.
	w := httptest.NewRecorder()
	apiPolicyDraftCommit(w, jsonReq("POST", "/api/policy/draft/commit?ifVersion="+int64ToStr(v-1),
		map[string]any{"comment": "x"}))
	if w.Code != http.StatusConflict {
		t.Fatalf("stale-version commit = %d, want 409 (%s)", w.Code, w.Body.String())
	}
	if !policyDraft.active() {
		t.Error("a rejected commit cleared the draft")
	}

	// Correct precondition → committed.
	w = httptest.NewRecorder()
	apiPolicyDraftCommit(w, jsonReq("POST", "/api/policy/draft/commit?ifVersion="+int64ToStr(v),
		map[string]any{"comment": "x"}))
	if w.Code != http.StatusOK {
		t.Fatalf("correct-version commit = %d, want 200 (%s)", w.Code, w.Body.String())
	}
}

// TestDraft_Commit_StrandedDraftUsesCandidateVersion pins the Codex #736 P2 fix:
// in the stranded-draft recovery state (RequireCommit turned OFF while a draft is
// still active), GET /api/policy/draft advertises the CANDIDATE generation, so a
// recovery commit sends ?ifVersion=<candidate>. The commit's precondition must
// compare against the candidate — not effectivePolicyVersion(), which falls back
// to running when the draft is not "engaged" and would spuriously 409 the commit.
func TestDraft_Commit_StrandedDraftUsesCandidateVersion(t *testing.T) {
	draftTestSetup(t)

	// Manufacture the stranded state: an active draft with mode OFF.
	setRequireCommit(true)
	createRuleViaAPI(t, "stranded-rule", "")
	if !policyDraft.active() {
		t.Fatal("setup: staging did not open a draft")
	}
	candV, _ := policyDraft.candidateVersion()
	runV, _ := policyStore.policyVersion()
	if candV == runV {
		t.Skipf("candidate (%d) and running (%d) versions coincide; cannot exercise the mismatch", candV, runV)
	}
	setRequireCommit(false)
	if policyDraftEngaged() || !policyDraft.active() {
		t.Fatalf("want stranded draft (not engaged, active); engaged=%v active=%v", policyDraftEngaged(), policyDraft.active())
	}

	// The recovery commit carries the candidate version the GET advertised. Before
	// the fix this compared against running (candV != runV) and 409'd.
	w := httptest.NewRecorder()
	apiPolicyDraftCommit(w, jsonReq("POST", "/api/policy/draft/commit?ifVersion="+int64ToStr(candV),
		map[string]any{"comment": "recover stranded draft"}))
	if w.Code != http.StatusOK {
		t.Fatalf("stranded-draft recovery commit with candidate ifVersion = %d, want 200 (%s)", w.Code, w.Body.String())
	}
	if policyDraft.active() {
		t.Error("draft still active after a successful recovery commit")
	}
	if n := ruleNames(policyStore.List()); len(n) != 1 || n[0] != "stranded-rule" {
		t.Errorf("recovery commit did not activate the candidate onto running: %v", n)
	}

	// And a genuinely stale precondition in the same state still 409s.
	setRequireCommit(true)
	createRuleViaAPI(t, "second-rule", "")
	setRequireCommit(false)
	candV2, _ := policyDraft.candidateVersion()
	w = httptest.NewRecorder()
	apiPolicyDraftCommit(w, jsonReq("POST", "/api/policy/draft/commit?ifVersion="+int64ToStr(candV2-1),
		map[string]any{"comment": "stale"}))
	if w.Code != http.StatusConflict {
		t.Fatalf("stale ifVersion in stranded state = %d, want 409 (%s)", w.Code, w.Body.String())
	}
	if !policyDraft.active() {
		t.Error("a rejected recovery commit cleared the draft")
	}
}

// TestDetectShadowedRules covers the commit-time shadow advisory (G4).
func TestDetectShadowedRules(t *testing.T) {
	// A catch-all (all fields empty) shadows a later specific rule.
	got := detectShadowedRules([]PolicyRule{
		{Name: "catchall", Priority: 1, Action: ActionAllow},
		{Name: "specific", Priority: 2, DestFQDN: "example.com", Action: ActionAllow},
	})
	if len(got) != 1 || got[0].Rule != "specific" || got[0].ShadowedBy != "catchall" {
		t.Fatalf("want [specific by catchall], got %+v", got)
	}
	// Distinct FQDNs — no shadow.
	if g := detectShadowedRules([]PolicyRule{
		{Name: "a", Priority: 1, DestFQDN: "a.com", Action: ActionAllow},
		{Name: "b", Priority: 2, DestFQDN: "b.com", Action: ActionAllow},
	}); len(g) != 0 {
		t.Errorf("distinct FQDNs must not shadow: %+v", g)
	}
	// A scheduled earlier rule is not always-active → cannot provably shadow.
	if g := detectShadowedRules([]PolicyRule{
		{Name: "sched", Priority: 1, Schedule: &PolicySchedule{}, Action: ActionAllow},
		{Name: "any", Priority: 2, Action: ActionAllow},
	}); len(g) != 0 {
		t.Errorf("scheduled rule must not shadow: %+v", g)
	}
	// Wildcard FQDN covers a subdomain.
	if g := detectShadowedRules([]PolicyRule{
		{Name: "wild", Priority: 1, DestFQDN: "*.example.com", Action: ActionAllow},
		{Name: "sub", Priority: 2, DestFQDN: "api.example.com", Action: ActionAllow},
	}); len(g) != 1 || g[0].Rule != "sub" {
		t.Errorf("wildcard should shadow subdomain: %+v", g)
	}
	// A disabled earlier rule cannot shadow.
	no := false
	if g := detectShadowedRules([]PolicyRule{
		{Name: "off", Priority: 1, Enabled: &no, Action: ActionAllow},
		{Name: "reachable", Priority: 2, DestFQDN: "x.com", Action: ActionAllow},
	}); len(g) != 0 {
		t.Errorf("disabled rule must not shadow: %+v", g)
	}
}

// TestDraft_CommitPersistsCommentNote: the commit comment is recorded as the
// config-version note (S3 "why this change" in the timeline).
func TestDraft_CommitPersistsCommentNote(t *testing.T) {
	draftTestSetup(t)
	setRequireCommit(true)
	createRuleViaAPI(t, "r1", "")

	w := httptest.NewRecorder()
	apiPolicyDraftCommit(w, jsonReq("POST", "/api/policy/draft/commit", map[string]any{"comment": "reason-xyz"}))
	if w.Code != http.StatusOK {
		t.Fatalf("commit = %d (%s)", w.Code, w.Body.String())
	}
	found := false
	for _, v := range configVersions.List() {
		if v.Action == "policy.commit" && v.Note == "reason-xyz" {
			found = true
		}
	}
	if !found {
		t.Error("commit comment was not persisted as the config-version note")
	}
}

// TestDraft_GetState surfaces the mode + pending count.
func TestDraft_GetState(t *testing.T) {
	draftTestSetup(t)
	setRequireCommit(true)
	createRuleViaAPI(t, "one", "")

	w := httptest.NewRecorder()
	apiPolicyDraft(w, getReq("/api/policy/draft"))
	if w.Code != http.StatusOK {
		t.Fatalf("GET draft = %d", w.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["requireCommit"] != true || resp["active"] != true {
		t.Errorf("draft state = %+v; want requireCommit+active true", resp)
	}
	if pc, _ := resp["pendingCount"].(float64); pc != 1 {
		t.Errorf("pendingCount = %v, want 1", resp["pendingCount"])
	}
}

// ── helpers ────────────────────────────────────────────────────────────────

func ruleNames(rules []PolicyRule) []string {
	out := make([]string, 0, len(rules))
	for i := range rules {
		out = append(out, rules[i].Name)
	}
	return out
}

func int64ToStr(v int64) string {
	return strconv.FormatInt(v, 10)
}
