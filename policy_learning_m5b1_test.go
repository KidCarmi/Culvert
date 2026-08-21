package main

// M5B.1 tests — draft durability for Accept (persist-before-publish through
// the coordinator primitive) with REAL restart fixtures for both durable
// domains, plus the >16-group truncation loss signal.

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/policylearn"
)

// plDurableDraftHarness layers a REAL draft persistence path over
// plDraftHarness and returns the draft directory.
func plDurableDraftHarness(t *testing.T) string {
	t.Helper()
	plDraftHarness(t)
	dir := t.TempDir()
	policyDraft.mu.Lock()
	prevPath := policyDraft.path
	policyDraft.path = filepath.Join(dir, "policy_draft.json")
	policyDraft.mu.Unlock()
	t.Cleanup(func() {
		policyDraft.mu.Lock()
		policyDraft.path = prevPath
		policyDraft.mu.Unlock()
	})
	return dir
}

// plRestartBoth simulates a full process restart of BOTH durable domains: the
// learning engine reloads from its store, and the draft coordinator is zeroed
// and reloaded from policy_draft.json exactly as initPolicyDraft does at boot.
func plRestartBoth(t *testing.T) {
	t.Helper()
	if eng := policyLearnEngine.Load(); eng != nil {
		_ = eng.Close()
	}
	policyLearnEngine.Store(nil)
	loadPolicyLearning(policyLearnPaths)

	policyDraft.mu.Lock()
	path := policyDraft.path
	policyDraft.cand.ReplaceAll(nil)
	policyDraft.state = draftState{}
	policyDraft.mu.Unlock()
	if path != "" {
		data, err := os.ReadFile(path)
		if err == nil {
			var p struct {
				State draftState   `json:"state"`
				Rules []PolicyRule `json:"rules"`
			}
			if json.Unmarshal(data, &p) == nil && p.State.Active {
				policyDraft.mu.Lock()
				policyDraft.cand.ReplaceAll(p.Rules)
				policyDraft.state = p.State
				policyDraft.mu.Unlock()
			}
		}
	}
}

// assertDurableAcceptedInvariant is the M5B.1 strengthening of §14: a durable
// Accepted state must be backed by the TargetRuleID in a DURABLE domain — the
// persisted draft document or the running policy — never draft memory alone.
func assertDurableAcceptedInvariant(t *testing.T, recID string) {
	t.Helper()
	rec, ok := policyLearnEngine.Load().RecommendationByID(recID)
	if !ok {
		t.Fatalf("recommendation %s vanished", recID)
	}
	if rec.State != policylearn.RecStateAccepted {
		return
	}
	inRunning := policyStore.findByIDCopy(rec.TargetRuleID) != nil
	if !inRunning && !policyDraft.durableTargetPresent(rec.TargetRuleID) {
		t.Fatalf("Accepted %s: target %s not durably recoverable (neither persisted draft nor running)", recID, rec.TargetRuleID)
	}
}

// ── failure injection ────────────────────────────────────────────────────────

// TestM5B1_DraftPersistFailureBlocksFinalize: intent persisted → draft
// persistence FAILS → the mutation is rolled back, FinalizeAccept never runs,
// and a crash leaves the recommendation un-Accepted; retry after storage
// recovery converges on exactly one TargetRuleID.
func TestM5B1_DraftPersistFailureBlocksFinalize(t *testing.T) {
	dir := plDurableDraftHarness(t)
	recID := plSeedRecommendation(t)
	setRequireCommit(true)

	// Break the draft's durable domain: point the path into a missing dir.
	policyDraft.mu.Lock()
	policyDraft.path = filepath.Join(dir, "missing", "policy_draft.json")
	policyDraft.mu.Unlock()

	res := plAcceptPost(t, RoleAdmin, recID, plRecsGET(t).PolicyVersion)
	if res.Code != http.StatusInternalServerError || !strings.Contains(res.Body, "draft persistence failed") {
		t.Fatalf("accept with failing draft persistence: %d %s", res.Code, res.Body)
	}
	rec, _ := policyLearnEngine.Load().RecommendationByID(recID)
	if rec.State != policylearn.RecStateAccepting {
		t.Fatalf("state after persist failure: %+v", rec)
	}
	// The mutation was rolled back: nothing in draft memory, nothing on disk.
	if cand, running := plCountTargetRules(rec.TargetRuleID); cand+running != 0 {
		t.Fatalf("persist failure left %d/%d rules behind", cand, running)
	}

	// Crash: after restart the recommendation must NOT be Accepted.
	plRestartBoth(t)
	rec, _ = policyLearnEngine.Load().RecommendationByID(recID)
	if rec.State == policylearn.RecStateAccepted {
		t.Fatal("crash after persist failure yielded durable Accepted with no durable rule")
	}
	assertDurableAcceptedInvariant(t, recID)

	// Storage recovery: restore the path; retry converges on ONE target.
	policyDraft.mu.Lock()
	policyDraft.path = filepath.Join(dir, "policy_draft.json")
	policyDraft.mu.Unlock()
	res = plAcceptPost(t, RoleAdmin, recID, plRecsGET(t).PolicyVersion)
	if res.Code != 200 {
		t.Fatalf("retry after recovery: %d %s", res.Code, res.Body)
	}
	rec, _ = policyLearnEngine.Load().RecommendationByID(recID)
	if rec.State != policylearn.RecStateAccepted {
		t.Fatalf("retry did not accept: %+v", rec)
	}
	if cand, running := plCountTargetRules(rec.TargetRuleID); cand != 1 || running != 0 {
		t.Fatalf("retry rule count: cand=%d running=%d", cand, running)
	}
	if !policyDraft.durableTargetPresent(rec.TargetRuleID) {
		t.Fatal("accepted rule not durably recoverable from policy_draft.json")
	}
	assertDurableAcceptedInvariant(t, recID)
	assertStrongestInvariant(t, recID)
}

// TestM5B1_DurableWriteThenCrashBeforeFinalize: the durable draft write
// succeeded, the process dies before the latch — a restarted retry discovers
// the EXACT durable rule and finalizes without duplicates.
func TestM5B1_DurableWriteThenCrashBeforeFinalize(t *testing.T) {
	plDurableDraftHarness(t)
	recID := plSeedRecommendation(t)
	setRequireCommit(true)

	eng := policyLearnEngine.Load()
	begun, err := eng.BeginAccept(recID, newRuleID())
	if err != nil {
		t.Fatal(err)
	}
	rule := plTranslateRecommendation(&begun)
	stampRuleMetadataForWrite(&rule, nil, "crash-sim")
	ver, _ := effectivePolicyVersion()
	if _, err := policyDraft.stageDurableAppend("crash-sim", ver, rule); err != nil {
		t.Fatal(err)
	}
	if !policyDraft.durableTargetPresent(begun.TargetRuleID) {
		t.Fatal("durable append did not reach the persisted document")
	}

	plRestartBoth(t) // crash before FinalizeAccept

	rec, _ := policyLearnEngine.Load().RecommendationByID(recID)
	if rec.State != policylearn.RecStateAccepting {
		t.Fatalf("intent lost across restart: %+v", rec)
	}
	res := plAcceptPost(t, RoleAdmin, recID, plRecsGET(t).PolicyVersion)
	if res.Code != 200 {
		t.Fatalf("post-restart retry: %d %s", res.Code, res.Body)
	}
	rec, _ = policyLearnEngine.Load().RecommendationByID(recID)
	if rec.State != policylearn.RecStateAccepted || rec.TargetRuleID != begun.TargetRuleID {
		t.Fatalf("retry did not finalize the durable rule: %+v", rec)
	}
	if cand, _ := plCountTargetRules(rec.TargetRuleID); cand != 1 {
		t.Fatalf("duplicates after restart-retry: %d", cand)
	}
	assertDurableAcceptedInvariant(t, recID)
	assertStrongestInvariant(t, recID)
}

// TestM5B1_FinalizeLatchFailureConverges: durable draft write succeeded but
// the LEARNING-store latch write fails — restart/retry converges on Accepted
// with the one durable rule.
func TestM5B1_FinalizeLatchFailureConverges(t *testing.T) {
	plDurableDraftHarness(t)
	recID := plSeedRecommendation(t)
	setRequireCommit(true)

	// Break the learning store AFTER the intent exists (so only the latch
	// write can fail): begin, durably append, then make the learning store
	// unwritable and drive the resume path.
	eng := policyLearnEngine.Load()
	begun, err := eng.BeginAccept(recID, newRuleID())
	if err != nil {
		t.Fatal(err)
	}
	rule := plTranslateRecommendation(&begun)
	stampRuleMetadataForWrite(&rule, nil, "crash-sim")
	ver, _ := effectivePolicyVersion()
	if _, err := policyDraft.stageDurableAppend("crash-sim", ver, rule); err != nil {
		t.Fatal(err)
	}
	learnStore := policyLearnPaths.StorePath
	if err := os.Rename(learnStore, learnStore+".away"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(learnStore, 0o500); err != nil { // a directory at the file path: AtomicWrite fails
		t.Fatal(err)
	}
	res := plAcceptPost(t, RoleAdmin, recID, plRecsGET(t).PolicyVersion)
	if res.Code == 200 {
		t.Fatalf("finalize succeeded with an unwritable learning store: %s", res.Body)
	}
	rec, _ := policyLearnEngine.Load().RecommendationByID(recID)
	if rec.State != policylearn.RecStateAccepting {
		t.Fatalf("latch failure leaked state: %+v", rec)
	}

	// Recovery + restart: retry converges.
	if err := os.Remove(learnStore); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(learnStore+".away", learnStore); err != nil {
		t.Fatal(err)
	}
	plRestartBoth(t)
	res = plAcceptPost(t, RoleAdmin, recID, plRecsGET(t).PolicyVersion)
	if res.Code != 200 {
		t.Fatalf("retry after latch recovery: %d %s", res.Code, res.Body)
	}
	rec, _ = policyLearnEngine.Load().RecommendationByID(recID)
	if rec.State != policylearn.RecStateAccepted || rec.TargetRuleID != begun.TargetRuleID {
		t.Fatalf("convergence failed: %+v", rec)
	}
	if cand, _ := plCountTargetRules(rec.TargetRuleID); cand != 1 {
		t.Fatalf("duplicates: %d", cand)
	}
	assertDurableAcceptedInvariant(t, recID)
}

// TestM5B1_CommitBetweenDurableCreateAndRetry: the draft (containing the
// target) is committed through the canonical promote path before the retry —
// reconciliation finds the exact TargetRuleID in RUNNING policy and finalizes.
func TestM5B1_CommitBetweenDurableCreateAndRetry(t *testing.T) {
	plDurableDraftHarness(t)
	recID := plSeedRecommendation(t)
	setRequireCommit(true)

	eng := policyLearnEngine.Load()
	begun, err := eng.BeginAccept(recID, newRuleID())
	if err != nil {
		t.Fatal(err)
	}
	rule := plTranslateRecommendation(&begun)
	stampRuleMetadataForWrite(&rule, nil, "crash-sim")
	ver, _ := effectivePolicyVersion()
	if _, err := policyDraft.stageDurableAppend("crash-sim", ver, rule); err != nil {
		t.Fatal(err)
	}
	plRestartBoth(t) // crash before finalize

	// Canonical commit semantics: promote the candidate to running, clear the
	// draft (what apiPolicyDraftCommit does after its own gates).
	policyStore.ReplaceAll(policyDraft.candidateList())
	policyDraft.clear()
	if policyStore.findByIDCopy(begun.TargetRuleID) == nil {
		t.Fatal("commit did not carry the target rule")
	}

	res := plAcceptPost(t, RoleAdmin, recID, plRecsGET(t).PolicyVersion)
	if res.Code != 200 {
		t.Fatalf("retry after commit: %d %s", res.Code, res.Body)
	}
	rec, _ := policyLearnEngine.Load().RecommendationByID(recID)
	if rec.State != policylearn.RecStateAccepted || rec.TargetRuleID != begun.TargetRuleID {
		t.Fatalf("post-commit finalize: %+v", rec)
	}
	// Exactly one rule, now in RUNNING via the canonical path; draft is clear.
	cand, running := plCountTargetRules(rec.TargetRuleID)
	if cand != 0 || running != 1 {
		t.Fatalf("post-commit rule location: cand=%d running=%d", cand, running)
	}
	assertDurableAcceptedInvariant(t, recID)
}

// TestM5B1_PrimitiveFenceAndRollback: the coordinator primitive's atomic
// fence + compensating rollback, unit-level.
func TestM5B1_PrimitiveFenceAndRollback(t *testing.T) {
	plDurableDraftHarness(t)
	setRequireCommit(true)

	ver, _ := effectivePolicyVersion()
	// Wrong fence: refused, nothing opened.
	if _, err := policyDraft.stageDurableAppend("t", ver+7, PolicyRule{ID: newRuleID(), Name: "m5b1-x", Action: ActionAllow}); err == nil {
		t.Fatal("wrong fence accepted")
	}
	if policyDraft.active() {
		t.Fatal("refused append opened a draft")
	}
	// Correct fence: appended + durable.
	id := newRuleID()
	added, err := policyDraft.stageDurableAppend("t", ver, PolicyRule{ID: id, Name: "m5b1-y", Action: ActionAllow})
	if err != nil || added.ID != id {
		t.Fatalf("append: %v %+v", err, added)
	}
	if !policyDraft.durableTargetPresent(id) {
		t.Fatal("append not durable")
	}
	// Persist failure on an ALREADY-OPEN draft: compensating delete only.
	policyDraft.mu.Lock()
	goodPath := policyDraft.path
	policyDraft.path = filepath.Join(filepath.Dir(goodPath), "missing", "policy_draft.json")
	policyDraft.mu.Unlock()
	ver2, _ := effectivePolicyVersion()
	id2 := newRuleID()
	if _, err := policyDraft.stageDurableAppend("t", ver2, PolicyRule{ID: id2, Name: "m5b1-z", Action: ActionAllow}); err == nil {
		t.Fatal("append with failing persist succeeded")
	}
	for _, r := range policyDraft.candidateList() {
		if r.ID == id2 {
			t.Fatal("failed append not rolled back")
		}
	}
	// The earlier durable rule is untouched.
	policyDraft.mu.Lock()
	policyDraft.path = goodPath
	policyDraft.mu.Unlock()
	if !policyDraft.durableTargetPresent(id) {
		t.Fatal("rollback disturbed the previously durable rule")
	}
}

// ── >16 group truncation (M5B.1 qualification) ───────────────────────────────

func TestM5B1_GroupTruncationCountedAndSurfaced(t *testing.T) {
	plHarness(t)
	if err := catStore.Set("m5b1-cat", []string{"m5b1.example"}, false); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = catStore.Delete("m5b1-cat") })
	if w := plDo(apiPolicyLearningConfig, http.MethodPut, "/api/policy-learning/config", RoleAdmin,
		`{"enabled":true,"recommendable_categories":["m5b1-cat"]}`); w.Code != 200 {
		t.Fatalf("enable: %d", w.Code)
	}
	plStartSession(t)

	// An authoritative identity with 20 groups: accepted, truncated to 16,
	// and the truncation is COUNTED — never silent.
	groups := make([]string, 20)
	for i := range groups {
		groups[i] = "grp" + string(rune('a'+i))
	}
	eng := policyLearnEngine.Load()
	ctx, ok := learnDecisionSnapshot()
	if !ok {
		t.Fatal("learnDecisionSnapshot refused with an active session")
	}
	learnObserveDecision(authOutcome{identity: "many@corp.example", source: "idp", groups: groups},
		"m5b1.example", "GET", nil, "OK", "Inspect", ctx, true)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && eng.ObservationStats().Delivered < 1 {
		time.Sleep(time.Millisecond)
	}
	stats := eng.ObservationStats()
	if stats.Accepted != 1 || stats.GroupsTruncated != 1 {
		t.Fatalf("truncation not counted: %+v", stats)
	}

	sessID := plCompleteSession(t)
	// Session window carries the loss fact; Degraded stays false (truncation
	// only ever hides groups — an undercount, never inflation).
	sw := plDo(apiPolicyLearningSessions, http.MethodGet, "/api/policy-learning/sessions?id="+sessID, RoleViewer, "")
	var dto plSessionDTO
	if err := json.Unmarshal(sw.Body.Bytes(), &dto); err != nil {
		t.Fatal(err)
	}
	if dto.Transport.GroupsTruncated != 1 {
		t.Fatalf("session DTO missing truncation fact: %+v", dto.Transport)
	}
	if dto.Transport.Degraded {
		t.Fatalf("truncation must not flag Degraded (undercount-only loss): %+v", dto.Transport)
	}

	// The fact rides every recommendation's coverage (by-value TransportLoss).
	if w := plDo(apiPolicyLearningGenerate, http.MethodPost, "/api/policy-learning/recommendations/generate", RoleOperator,
		`{"session_id":"`+sessID+`"}`); w.Code != 200 {
		t.Fatalf("generate: %d %s", w.Code, w.Body.String())
	}
	recs := plRecsGET(t)
	if len(recs.Recommendations) == 0 {
		t.Fatal("no recommendations")
	}
	cov := recs.Recommendations[0].Coverage
	if cov.TransportLoss.GroupsTruncated != 1 {
		t.Fatalf("coverage does not carry the truncation fact: %+v", cov)
	}
	if cov.TransportDegraded {
		t.Fatal("truncation wrongly degraded coverage")
	}
	// Only the first 16 groups received evidence — cells for the tail must not
	// exist (they got no evidence, and that loss is now accounted above).
	if o, ok := eng.SessionOverview(sessID); !ok || o.Cells != 16 {
		t.Fatalf("expected 16 group cells, got %+v", o)
	}
	// GUI renders the fact.
	raw, err := os.ReadFile(filepath.Join(pkgSourceDir(), "static", "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "group context truncated") || !strings.Contains(string(raw), "group context incomplete") {
		t.Fatal("GUI does not surface group-context truncation")
	}
}
