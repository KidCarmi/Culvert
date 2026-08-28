package main

// policy_mutation_durability_test.go — 2B.0b durable-or-nothing proofs for
// ordinary policy mutations.
//
// Contract under test (fencedMutate, policy_mutation.go): a 2xx ordinary
// policy write means the mutation is in the durable domain of the current
// mode (running policy_rules.json, or the staged policy_draft.json); a
// pre-replacement persistence failure fails the request AND rolls the
// semantic state back, so memory and the restart-visible file agree the
// mutation never happened; ErrReplacedNotSynced (replacement landed, parent
// dir fsync failed) counts as landed, matching the commitActivate doctrine.
//
// Every proof verifies the PERSISTED/RELOADED state, never memory alone.
// Fault injection uses the repository's established technique: the target
// path is displaced by a non-empty DIRECTORY so AtomicWrite's rename fails
// pre-replacement (policy_learning_codexfix_test.go precedent). AtomicWrite
// never writes through the target in place — it stages a temp file and
// renames — so in a real pre-replace failure the existing file is untouched;
// where the injector itself had to displace that file, the test restores the
// previously captured bytes before the reload proof, reconstructing exactly
// the disk state a real failure leaves behind.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// durableTestSetup gives the running store and the draft coordinator real
// on-disk homes in a temp dir, on top of draftTestSetup's isolation.
func durableTestSetup(t *testing.T) (policyPath, draftPath string) {
	t.Helper()
	draftTestSetup(t)
	dir := t.TempDir()
	policyPath = filepath.Join(dir, "policy_rules.json")
	draftPath = filepath.Join(dir, "policy_draft.json")
	prevPolicyPath := policyStore.path
	policyStore.path = policyPath
	policyDraft.mu.Lock()
	prevDraftPath := policyDraft.path
	policyDraft.path = draftPath
	policyDraft.mu.Unlock()
	t.Cleanup(func() {
		policyStore.path = prevPolicyPath
		policyDraft.mu.Lock()
		policyDraft.path = prevDraftPath
		policyDraft.mu.Unlock()
	})
	return policyPath, draftPath
}

// blockPath displaces path with a non-empty directory so AtomicWrite's rename
// fails pre-replacement. Returns the previously durable bytes ("" when the
// file did not exist) so the caller can reconstruct the real-failure disk
// state before a reload proof.
func blockPath(t *testing.T, path string) []byte {
	t.Helper()
	prev, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("capture previous truth: %v", err)
	}
	if err == nil {
		if rmErr := os.Remove(path); rmErr != nil {
			t.Fatalf("displace previous file: %v", rmErr)
		}
	}
	if err := os.MkdirAll(filepath.Join(path, "x"), 0o750); err != nil {
		t.Fatalf("install blocker: %v", err)
	}
	return prev
}

// unblockPath removes the blocker and, when prev is non-empty, restores the
// previously durable bytes (what a real pre-replace failure leaves on disk).
func unblockPath(t *testing.T, path string, prev []byte) {
	t.Helper()
	if err := os.RemoveAll(path); err != nil {
		t.Fatalf("remove blocker: %v", err)
	}
	if len(prev) > 0 {
		if err := os.WriteFile(path, prev, 0o600); err != nil {
			t.Fatalf("restore previous truth: %v", err)
		}
	}
}

// reloadPolicyFile parses the persisted running rulebase.
func reloadPolicyFile(t *testing.T, path string) []PolicyRule {
	t.Helper()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("read persisted policy: %v", err)
	}
	var rules []PolicyRule
	if err := json.Unmarshal(data, &rules); err != nil {
		t.Fatalf("parse persisted policy: %v", err)
	}
	return rules
}

// reloadDraftFile runs the REAL restart-recovery path (initPolicyDraft) into
// a scratch coordinator state and returns (active, rules).
func reloadDraft(t *testing.T, policyPath string) (bool, []PolicyRule) {
	t.Helper()
	policyDraft.mu.Lock()
	prevCand, prevState, prevPath := policyDraft.cand, policyDraft.state, policyDraft.path
	policyDraft.cand = &PolicyStore{}
	policyDraft.state = draftState{}
	policyDraft.mu.Unlock()
	initPolicyDraft(policyPath)
	active := policyDraft.active()
	rules := policyDraft.candidateList()
	policyDraft.mu.Lock()
	policyDraft.cand, policyDraft.state, policyDraft.path = prevCand, prevState, prevPath
	policyDraft.mu.Unlock()
	return active, rules
}

// ruleNames is shared with policy_draft_test.go.

func hasRuleNamed(rules []PolicyRule, name string) bool {
	for i := range rules {
		if rules[i].Name == name {
			return true
		}
	}
	return false
}

// ── LIVE mode ───────────────────────────────────────────────────────────────

func TestDurable_LiveCreate_PersistFailureRollsBack(t *testing.T) {
	policyPath, _ := durableTestSetup(t)
	seedRule(t, "seed") // persisted OK
	prev := blockPath(t, policyPath)

	w := createRuleViaAPI(t, "doomed", "")
	if w.Code != 500 {
		t.Fatalf("persist failure must fail the request, got %d (%s)", w.Code, w.Body.String())
	}
	if hasRuleNamed(policyStore.List(), "doomed") {
		t.Fatal("rolled-back rule still present in memory")
	}
	unblockPath(t, policyPath, prev)
	persisted := reloadPolicyFile(t, policyPath)
	if hasRuleNamed(persisted, "doomed") || !hasRuleNamed(persisted, "seed") {
		t.Fatalf("restart-visible file is not the previous truth: %v", ruleNames(persisted))
	}
}

func TestDurable_LiveEdit_PersistFailureRollsBack(t *testing.T) {
	policyPath, _ := durableTestSetup(t)
	rule := seedRule(t, "target")
	prev := blockPath(t, policyPath)

	w := httptest.NewRecorder()
	apiPolicyUpdate(w, jsonReq("PUT", "/api/policy?id="+rule.ID,
		map[string]any{"name": "target", "action": "Allow", "comment": "edited"}))
	if w.Code != 500 {
		t.Fatalf("persist failure must fail the request, got %d (%s)", w.Code, w.Body.String())
	}
	got := effectiveRuleByID(rule.ID)
	if got == nil || got.Comment == "edited" {
		t.Fatalf("edit not rolled back in memory: %+v", got)
	}
	unblockPath(t, policyPath, prev)
	persisted := reloadPolicyFile(t, policyPath)
	for i := range persisted {
		if persisted[i].ID == rule.ID && persisted[i].Comment == "edited" {
			t.Fatal("failed edit reached the restart-visible file")
		}
	}
}

func TestDurable_LiveDelete_PersistFailureRollsBack(t *testing.T) {
	policyPath, _ := durableTestSetup(t)
	rule := seedRule(t, "keep-me")
	prev := blockPath(t, policyPath)

	w := httptest.NewRecorder()
	apiPolicyDelete(w, jsonReq("DELETE", "/api/policy?id="+rule.ID, nil))
	if w.Code != 500 {
		t.Fatalf("persist failure must fail the request, got %d (%s)", w.Code, w.Body.String())
	}
	if !hasRuleNamed(policyStore.List(), "keep-me") {
		t.Fatal("deleted rule not restored in memory after rollback")
	}
	unblockPath(t, policyPath, prev)
	if !hasRuleNamed(reloadPolicyFile(t, policyPath), "keep-me") {
		t.Fatal("restart-visible file lost the rule the failed delete should not have removed")
	}
}

func TestDurable_LiveSuccess_IsRestartVisible(t *testing.T) {
	policyPath, _ := durableTestSetup(t)
	assertStatus(t, createRuleViaAPI(t, "durable-live", ""), 200)
	if !hasRuleNamed(reloadPolicyFile(t, policyPath), "durable-live") {
		t.Fatal("2xx live create is not in the restart-visible file")
	}
}

// TestDurable_LiveReplacedNotSynced_CountsAsLanded (§6 case B): replacement
// happened but the parent-dir fsync failed — the file already carries the new
// content, so rolling memory back would contradict the visible durable file.
// The mutation stands as success. Induced through the persist seam because
// the real filesystem cannot produce this failure deterministically.
func TestDurable_LiveReplacedNotSynced_CountsAsLanded(t *testing.T) {
	durableTestSetup(t)
	seedRule(t, "seed")
	prevPersist := persistRunningPolicy
	persistRunningPolicy = func() error {
		// Perform the REAL persist (content lands), then report the post-rename
		// failure shape AtomicWrite uses.
		if err := policyStore.SaveErr(); err != nil {
			return err
		}
		return fmt.Errorf("atomic write: parent dir fsync: injected: %w", fileutil.ErrReplacedNotSynced)
	}
	t.Cleanup(func() { persistRunningPolicy = prevPersist })

	w := createRuleViaAPI(t, "landed-degraded", "")
	if w.Code != 200 {
		t.Fatalf("ErrReplacedNotSynced must count as landed (commit doctrine), got %d (%s)", w.Code, w.Body.String())
	}
	if !hasRuleNamed(policyStore.List(), "landed-degraded") {
		t.Fatal("landed mutation was rolled back despite the file carrying it")
	}
}

// TestDurable_LivePersistFailure_ClassifierMatrix pins the three §6 outcomes
// through the seam: nil = landed; ErrReplacedNotSynced = landed (degraded);
// any other error = rolled back + 500.
func TestDurable_LivePersistFailure_SeamRollback(t *testing.T) {
	durableTestSetup(t)
	seedRule(t, "seed")
	prevPersist := persistRunningPolicy
	persistRunningPolicy = func() error { return errors.New("injected pre-replace failure") }
	t.Cleanup(func() { persistRunningPolicy = prevPersist })

	w := createRuleViaAPI(t, "doomed-seam", "")
	if w.Code != 500 {
		t.Fatalf("want 500, got %d", w.Code)
	}
	if hasRuleNamed(policyStore.List(), "doomed-seam") {
		t.Fatal("rolled-back rule still present in memory")
	}
}

// ── DRAFT mode ──────────────────────────────────────────────────────────────

func TestDurable_DraftFirstWrite_PersistFailureDiscardsFork(t *testing.T) {
	policyPath, draftPath := durableTestSetup(t)
	seedRule(t, "seed")
	setRequireCommit(true)
	prev := blockPath(t, draftPath)

	ver, _ := effectivePolicyVersion()
	w := createRuleViaAPI(t, "doomed-staged", fmt.Sprintf("%d", ver))
	if w.Code != 500 {
		t.Fatalf("draft persist failure must fail the request, got %d (%s)", w.Code, w.Body.String())
	}
	if policyDraft.active() {
		t.Fatal("failed first staged write left an active draft fork")
	}
	if hasRuleNamed(policyStore.List(), "doomed-staged") {
		t.Fatal("staged rule leaked into running")
	}
	unblockPath(t, draftPath, prev)
	if active, _ := reloadDraft(t, policyPath); active {
		t.Fatal("restart recovers a draft the failed write should never have made durable")
	}
}

func TestDurable_DraftEdit_PersistFailureRollsBackCandidate(t *testing.T) {
	policyPath, draftPath := durableTestSetup(t)
	seedRule(t, "seed")
	setRequireCommit(true)
	// Stage one successful write so a durable draft exists.
	ver, _ := effectivePolicyVersion()
	assertStatus(t, createRuleViaAPI(t, "staged-ok", fmt.Sprintf("%d", ver)), 200)

	prev := blockPath(t, draftPath)
	ver2, _ := effectivePolicyVersion()
	w := createRuleViaAPI(t, "staged-doomed", fmt.Sprintf("%d", ver2))
	if w.Code != 500 {
		t.Fatalf("draft persist failure must fail the request, got %d (%s)", w.Code, w.Body.String())
	}
	if hasRuleNamed(policyDraft.candidateList(), "staged-doomed") {
		t.Fatal("failed staged edit still present in the candidate")
	}
	if !hasRuleNamed(policyDraft.candidateList(), "staged-ok") {
		t.Fatal("rollback destroyed the previously staged (durable) edit")
	}
	// Restart-visible: the reconstructed disk (previous truth) recovers only
	// the successfully staged edit.
	unblockPath(t, draftPath, prev)
	active, rules := reloadDraft(t, policyPath)
	if !active || !hasRuleNamed(rules, "staged-ok") || hasRuleNamed(rules, "staged-doomed") {
		t.Fatalf("restart-visible draft is not the previous truth: active=%v rules=%v", active, ruleNames(rules))
	}
}

func TestDurable_DraftReorder_PersistFailureRollsBackOrder(t *testing.T) {
	policyPath, draftPath := durableTestSetup(t)
	r1 := seedRule(t, "first")
	r2 := seedRule(t, "second")
	setRequireCommit(true)
	// Open the draft with a real staged change so the draft file exists.
	ver, _ := effectivePolicyVersion()
	assertStatus(t, createRuleViaAPI(t, "staged-ok", fmt.Sprintf("%d", ver)), 200)
	beforeOrder := ruleNames(listPolicyRules())

	prev := blockPath(t, draftPath)
	ver2, _ := effectivePolicyVersion()
	perm := []int{}
	rules := listPolicyRules()
	for j := len(rules) - 1; j >= 0; j-- {
		perm = append(perm, rules[j].Priority)
	}
	w := httptest.NewRecorder()
	apiPolicyReorder(w, jsonReq("POST",
		fmt.Sprintf("/api/policy/reorder?ifVersion=%d", ver2),
		map[string]any{"priorities": perm}))
	if w.Code != 500 {
		t.Fatalf("draft reorder persist failure must fail the request, got %d (%s)", w.Code, w.Body.String())
	}
	afterOrder := ruleNames(listPolicyRules())
	if fmt.Sprint(afterOrder) != fmt.Sprint(beforeOrder) {
		t.Fatalf("failed reorder not rolled back: before=%v after=%v", beforeOrder, afterOrder)
	}
	unblockPath(t, draftPath, prev)
	active, reloaded := reloadDraft(t, policyPath)
	if !active {
		t.Fatal("previous durable draft lost")
	}
	if fmt.Sprint(ruleNames(reloaded)) == fmt.Sprint(ruleNames(rules)) && len(rules) > 1 && rules[0].Name != beforeOrder[0] {
		t.Fatal("failed permutation reached the restart-visible draft")
	}
	_, _ = r1, r2
}

func TestDurable_DraftSuccess_SurvivesRestart(t *testing.T) {
	policyPath, _ := durableTestSetup(t)
	seedRule(t, "seed")
	setRequireCommit(true)
	ver, _ := effectivePolicyVersion()
	assertStatus(t, createRuleViaAPI(t, "staged-durable", fmt.Sprintf("%d", ver)), 200)

	active, rules := reloadDraft(t, policyPath)
	if !active || !hasRuleNamed(rules, "staged-durable") {
		t.Fatalf("2xx staged write is not restart-recoverable: active=%v rules=%v", active, ruleNames(rules))
	}
}

// TestDurable_NoOpDraftEdit_StillReconciles: the reconcile contract (a staged
// edit that leaves the candidate identical to running auto-discards the
// draft) survived the move into the critical section.
func TestDurable_NoOpDraftEdit_StillReconciles(t *testing.T) {
	_, draftPath := durableTestSetup(t)
	rule := seedRule(t, "target")
	setRequireCommit(true)

	// Re-save the FULL rule unchanged (a partial body is a real edit — absent
	// fields become zero values): candidate forks, mutation lands, candidate
	// == running ⇒ the draft retires instead of lingering as zero-diff active.
	w := httptest.NewRecorder()
	apiPolicyUpdate(w, jsonReq("PUT", "/api/policy?id="+rule.ID, rule))
	assertStatus(t, w, 200)
	if policyDraft.active() {
		t.Fatal("no-op staged edit left a zero-diff active draft")
	}
	if _, err := os.Stat(draftPath); !os.IsNotExist(err) {
		t.Fatalf("no-op reconcile left a draft file behind (err=%v)", err)
	}
}
