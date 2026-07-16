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
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
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

func TestDraft_OffMode_SaveFailureReturns500WithoutConfigVersion(t *testing.T) {
	draftTestSetup(t)
	resetAuditLog()
	t.Cleanup(resetAuditLog)
	path := filepath.Join(t.TempDir(), "policy.json")
	policyStore.path = path
	if err := os.Mkdir(path+".meta", 0o700); err != nil {
		t.Fatal(err)
	}
	before := countConfigVersions("policy.add")

	w := createRuleViaAPI(t, "not-durable", "")
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("create with failed policy metadata save = %d, want 500 (body=%s)", w.Code, w.Body.String())
	}
	if countConfigVersions("policy.add") != before {
		t.Fatal("failed durable policy save wrote a policy.add config version")
	}
	if len(policyStore.List()) != 0 {
		t.Fatal("failed durable policy save published the rule in memory")
	}
	for _, entry := range auditGet() {
		if entry.Action == "policy.add" && entry.Object == "not-durable" {
			t.Fatal("failed durable policy save emitted a success-shaped policy.add audit")
		}
	}
}

func TestDraft_StagePersistenceFailureDoesNotPublishOrAudit(t *testing.T) {
	draftTestSetup(t)
	resetAuditLog()
	t.Cleanup(resetAuditLog)
	setRequireCommit(true)
	policyDraft.mu.Lock()
	policyDraft.path = t.TempDir() // AtomicWrite cannot replace a directory.
	policyDraft.mu.Unlock()

	w := createRuleViaAPI(t, "not-staged", "")
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("stage with failed persistence = %d, want 500", w.Code)
	}
	if policyDraft.active() || len(policyDraft.candidateList()) != 0 {
		t.Fatal("failed staged write remained active in memory")
	}
	for _, entry := range auditGet() {
		if entry.Action == "policy.add" && entry.Object == "not-staged" {
			t.Fatal("failed staged write emitted success audit")
		}
	}
}

func TestDraft_CommitSerializesWithStagedMutation(t *testing.T) {
	draftTestSetup(t)
	setRequireCommit(true)
	entered := make(chan struct{})
	release := make(chan struct{})
	mutationDone := make(chan error, 1)
	go func() {
		_, err := mutatePolicy("editor", func(store *PolicyStore) error {
			close(entered)
			<-release
			store.Add(PolicyRule{Name: "concurrent", Action: ActionAllow})
			return nil
		})
		mutationDone <- err
	}()
	<-entered

	commitDone := make(chan error, 1)
	go func() {
		_, err := policyDraft.commit(nil)
		commitDone <- err
	}()
	select {
	case err := <-commitDone:
		t.Fatalf("commit bypassed in-flight staged mutation: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-mutationDone; err != nil {
		t.Fatalf("staged mutation: %v", err)
	}
	if err := <-commitDone; err != nil {
		t.Fatalf("commit: %v", err)
	}
	rules := policyStore.List()
	if len(rules) != 1 || rules[0].Name != "concurrent" {
		t.Fatalf("committed rules = %#v", rules)
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

func TestDraft_CommitSaveFailureReturns500AndRetainsDraft(t *testing.T) {
	draftTestSetup(t)
	setRequireCommit(true)
	if w := createRuleViaAPI(t, "staged", ""); w.Code != http.StatusOK {
		t.Fatalf("stage = %d (%s)", w.Code, w.Body.String())
	}
	path := filepath.Join(t.TempDir(), "policy.json")
	policyStore.path = path
	if err := os.Mkdir(path+".meta", 0o700); err != nil {
		t.Fatal(err)
	}
	before := countConfigVersions("policy.commit")

	w := httptest.NewRecorder()
	apiPolicyDraftCommit(w, jsonReq("POST", "/api/policy/draft/commit", map[string]any{"comment": "must persist"}))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("commit with failed policy metadata save = %d, want 500 (body=%s)", w.Code, w.Body.String())
	}
	if !policyDraft.active() {
		t.Fatal("failed durable policy save cleared the draft")
	}
	if len(policyStore.List()) != 0 {
		t.Fatal("failed durable policy save activated the draft in running memory")
	}
	if policyDraft.baseGenerationStale() {
		t.Fatal("failed durable policy save made the retained draft stale")
	}
	if countConfigVersions("policy.commit") != before {
		t.Fatal("failed durable policy save wrote a policy.commit config version")
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

func TestPolicyMutateExpectedVersionIsAtomic(t *testing.T) {
	ps := &PolicyStore{path: filepath.Join(t.TempDir(), "policy.json")}
	if err := ps.ReplaceAllAndSave([]PolicyRule{{Name: "base", Action: ActionAllow}}); err != nil {
		t.Fatal(err)
	}
	_, version := ps.snapshotWithVersion()
	start := make(chan struct{})
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		i := i
		go func() {
			<-start
			results <- ps.MutateAndSaveAtVersion(&version, func(candidate *PolicyStore) error {
				candidate.Add(PolicyRule{Name: fmt.Sprintf("writer-%d", i), Action: ActionAllow})
				return nil
			})
		}()
	}
	close(start)
	successes, conflicts := 0, 0
	for i := 0; i < 2; i++ {
		err := <-results
		switch {
		case err == nil:
			successes++
		case errors.Is(err, errPolicyVersionConflict):
			conflicts++
		default:
			t.Fatalf("unexpected mutation error: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes=%d conflicts=%d, want one each", successes, conflicts)
	}
}

func TestDraftRevertSerializesWithStagedMutation(t *testing.T) {
	draftTestSetup(t)
	setRequireCommit(true)
	entered := make(chan struct{})
	release := make(chan struct{})
	mutationDone := make(chan error, 1)
	go func() {
		mutationDone <- policyDraft.mutateAndPersist("editor", nil, func(candidate *PolicyStore) error {
			close(entered)
			<-release
			candidate.Add(PolicyRule{Name: "staged", Action: ActionAllow})
			return nil
		})
	}()
	<-entered
	revertDone := make(chan error, 1)
	go func() {
		_, err := policyDraft.revert()
		revertDone <- err
	}()
	select {
	case err := <-revertDone:
		t.Fatalf("revert interleaved with staged mutation: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-mutationDone; err != nil {
		t.Fatal(err)
	}
	if err := <-revertDone; err != nil {
		t.Fatal(err)
	}
	if policyDraft.active() {
		t.Fatal("serialized revert left draft active")
	}
}

func TestDraftRevertTombstoneFailureRetainsDraft(t *testing.T) {
	draftTestSetup(t)
	setRequireCommit(true)
	createRuleViaAPI(t, "pending", "")
	policyDraft.mu.Lock()
	policyDraft.path = filepath.Join(t.TempDir(), "missing", "policy_draft.json")
	policyDraft.mu.Unlock()
	if _, err := policyDraft.revert(); err == nil {
		t.Fatal("expected durable tombstone failure")
	}
	if !policyDraft.active() {
		t.Fatal("failed revert cleared in-memory draft")
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
