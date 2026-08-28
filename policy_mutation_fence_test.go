package main

// policy_mutation_fence_test.go — 2B.0a atomic expected-version fencing proofs.
//
// The pre-2B.0a contract checked ?ifVersion= in the handler, OUTSIDE the
// mutation critical section, and documented the residual race: two writers
// could both read v5, both pass, and both mutate — the second silently
// overwriting the first despite both asserting the same expected version.
// fencedMutate closes that window: fence + draft-fork + mutation run under one
// coordinator lock. These tests prove the closure with barrier-started
// concurrent handler pairs whose OUTCOME is deterministic by atomicity
// (exactly one writer of a fenced pair succeeds; the other receives the
// structured 409), plus a deterministic sequential regression for the
// first-write-opens-draft version-collision hazard (§3).

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"sync"
	"testing"
)

const fenceRaceIterations = 40

// runConcurrentPair fires two handler calls through a start barrier and
// returns their recorders. Outcomes are asserted by the callers; the barrier
// only guarantees genuine concurrency, never a specific interleaving — the
// atomic fence makes the OUTCOME deterministic regardless of order.
func runConcurrentPair(a, b func() *httptest.ResponseRecorder) (ra, rb *httptest.ResponseRecorder) {
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); <-start; ra = a() }()
	go func() { defer wg.Done(); <-start; rb = b() }()
	close(start)
	wg.Wait()
	return ra, rb
}

// decodeConflict asserts the recorder carries the structured 409 body.
func decodeConflict(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	var body struct {
		Error          string `json:"error"`
		CurrentVersion *int64 `json:"currentVersion"`
		YourVersion    *int64 `json:"yourVersion"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("409 body is not the structured conflict JSON: %v (%s)", err, w.Body.String())
	}
	if body.Error == "" || body.CurrentVersion == nil || body.YourVersion == nil {
		t.Fatalf("409 body missing structured fields: %s", w.Body.String())
	}
}

func seedRule(t *testing.T, name string) PolicyRule {
	t.Helper()
	w := createRuleViaAPI(t, name, "")
	assertStatus(t, w, 200)
	var added PolicyRule
	if err := json.Unmarshal(w.Body.Bytes(), &added); err != nil {
		t.Fatalf("decode created rule: %v", err)
	}
	return added
}

func updateRuleReq(id string, ifVersion int64, comment string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	apiPolicyUpdate(w, jsonReq("PUT",
		fmt.Sprintf("/api/policy?id=%s&ifVersion=%d", id, ifVersion),
		map[string]any{"name": "fence-target", "action": "Allow", "comment": comment}))
	return w
}

// TestFence_A_ConcurrentEditsSameVersion: same rule, two concurrent PUTs with
// the same ifVersion — exactly one mutation succeeds, the other receives the
// structured conflict, and the surviving content is the winner's (no silent
// last-writer overwrite).
func TestFence_A_ConcurrentEditsSameVersion(t *testing.T) {
	draftTestSetup(t)
	rule := seedRule(t, "fence-target")

	for i := 0; i < fenceRaceIterations; i++ {
		ver, _ := effectivePolicyVersion()
		cA := fmt.Sprintf("writer-A-%d", i)
		cB := fmt.Sprintf("writer-B-%d", i)
		ra, rb := runConcurrentPair(
			func() *httptest.ResponseRecorder { return updateRuleReq(rule.ID, ver, cA) },
			func() *httptest.ResponseRecorder { return updateRuleReq(rule.ID, ver, cB) },
		)
		codes := []int{ra.Code, rb.Code}
		okCount, conflictCount := 0, 0
		for _, c := range codes {
			switch c {
			case 200:
				okCount++
			case 409:
				conflictCount++
			default:
				t.Fatalf("iter %d: unexpected status %v", i, codes)
			}
		}
		if okCount != 1 || conflictCount != 1 {
			t.Fatalf("iter %d: want exactly one success and one conflict, got %v", i, codes)
		}
		loser := ra
		winnerComment := cA
		if ra.Code == 200 {
			loser = rb
		} else {
			winnerComment = cB
		}
		decodeConflict(t, loser)
		got := effectiveRuleByID(rule.ID)
		if got == nil || got.Comment != winnerComment {
			t.Fatalf("iter %d: surviving content is not the fenced winner's (got %+v, want comment %q)", i, got, winnerComment)
		}
		newVer, _ := effectivePolicyVersion()
		if newVer != ver+1 {
			t.Fatalf("iter %d: version advanced by %d, want exactly 1 (one mutation)", i, newVer-ver)
		}
	}
}

// TestFence_B_ConcurrentCreatesSameVersion: two concurrent creates asserting
// the same version — one succeeds, one conflicts, exactly one rule is added.
func TestFence_B_ConcurrentCreatesSameVersion(t *testing.T) {
	draftTestSetup(t)
	seedRule(t, "existing")

	for i := 0; i < fenceRaceIterations; i++ {
		before := len(policyStore.List())
		ver, _ := effectivePolicyVersion()
		verStr := fmt.Sprintf("%d", ver)
		ra, rb := runConcurrentPair(
			func() *httptest.ResponseRecorder { return createRuleViaAPI(t, fmt.Sprintf("create-A-%d", i), verStr) },
			func() *httptest.ResponseRecorder { return createRuleViaAPI(t, fmt.Sprintf("create-B-%d", i), verStr) },
		)
		if !((ra.Code == 200 && rb.Code == 409) || (ra.Code == 409 && rb.Code == 200)) {
			t.Fatalf("iter %d: want one 200 + one 409, got %d/%d", i, ra.Code, rb.Code)
		}
		if got := len(policyStore.List()); got != before+1 {
			t.Fatalf("iter %d: %d rules added, want exactly 1", i, got-before)
		}
	}
}

// TestFence_C_ConcurrentReorderAndEditSameVersion: a reorder and an edit
// asserting the same version — exactly one succeeds.
func TestFence_C_ConcurrentReorderAndEditSameVersion(t *testing.T) {
	draftTestSetup(t)
	r1 := seedRule(t, "fence-target")
	r2 := seedRule(t, "second")

	for i := 0; i < fenceRaceIterations; i++ {
		ver, _ := effectivePolicyVersion()
		// Current access priorities, reversed.
		perm := []int{}
		rules := listPolicyRules()
		for j := len(rules) - 1; j >= 0; j-- {
			perm = append(perm, rules[j].Priority)
		}
		ra, rb := runConcurrentPair(
			func() *httptest.ResponseRecorder {
				w := httptest.NewRecorder()
				apiPolicyReorder(w, jsonReq("POST",
					fmt.Sprintf("/api/policy/reorder?ifVersion=%d", ver),
					map[string]any{"priorities": perm}))
				return w
			},
			func() *httptest.ResponseRecorder {
				return updateRuleReq(r1.ID, ver, fmt.Sprintf("edit-%d", i))
			},
		)
		// Exactly ONE mutation may land — that is the atomic-fence guarantee.
		// The loser normally receives the structured 409; in the narrow window
		// where the winner's permutation lands between the loser's OPTIMISTIC
		// pre-validation reads (validatePolicyRule runs outside the critical
		// section by design), the loser can instead be refused 400 by that
		// validation computed against the shifted slots. Both are explicit
		// fail-closed refusals; a silent second mutation is the only failure.
		okCount := 0
		for _, rec := range []*httptest.ResponseRecorder{ra, rb} {
			switch rec.Code {
			case 200:
				okCount++
			case 409, 400:
				// refused — fail-closed
			default:
				t.Fatalf("iter %d: unexpected statuses reorder=%d edit=%d", i, ra.Code, rb.Code)
			}
		}
		if okCount != 1 {
			t.Fatalf("iter %d: want exactly one success, got reorder=%d edit=%d", i, ra.Code, rb.Code)
		}
	}
	_ = r2
}

// TestFence_D_FirstWriteOpensDraftRace (§3): with Require Commit armed and no
// active draft, two clients both hold the running generation vN. Exactly ONE
// may use vN for the first staged mutation; after that mutation opens and
// advances the shared candidate, the second vN request must conflict — never
// silently mutate the newly opened candidate.
func TestFence_D_FirstWriteOpensDraftRace(t *testing.T) {
	draftTestSetup(t)
	seedRule(t, "baseline")
	setRequireCommit(true)

	for i := 0; i < fenceRaceIterations; i++ {
		if policyDraft.active() {
			policyDraft.clear() // fresh no-draft state each round
		}
		baseCount := len(policyStore.List())
		ver, _ := effectivePolicyVersion() // running: no draft is active
		verStr := fmt.Sprintf("%d", ver)
		ra, rb := runConcurrentPair(
			func() *httptest.ResponseRecorder { return createRuleViaAPI(t, fmt.Sprintf("stage-A-%d", i), verStr) },
			func() *httptest.ResponseRecorder { return createRuleViaAPI(t, fmt.Sprintf("stage-B-%d", i), verStr) },
		)
		if !((ra.Code == 200 && rb.Code == 409) || (ra.Code == 409 && rb.Code == 200)) {
			t.Fatalf("iter %d: want one 200 + one 409, got %d/%d", i, ra.Code, rb.Code)
		}
		if !policyDraft.active() {
			t.Fatalf("iter %d: winning staged write did not open the draft", i)
		}
		if got := len(policyDraft.candidateList()); got != baseCount+1 {
			t.Fatalf("iter %d: candidate holds %d rules, want exactly %d (one staged add)", i, got, baseCount+1)
		}
		if got := len(policyStore.List()); got != baseCount {
			t.Fatalf("iter %d: running mutated (%d rules) — staged write leaked", i, got)
		}
		// Version-stream continuity: the candidate CONTINUES the running stream.
		candVer, _ := policyDraft.candidateVersion()
		if candVer != ver+1 {
			t.Fatalf("iter %d: candidate generation %d, want %d (running %d + 1)", i, candVer, ver+1, ver)
		}
	}
}

// TestFence_D2_ForkVersionCollisionRegression is the DETERMINISTIC §3 shape:
// before 2B.0a the candidate's counter restarted from its own zero, so a fork
// plus first staged write could land the candidate at a generation numerically
// EQUAL to the stale running token (running v2 → fork(ReplaceAll bump)+Add = 2)
// and the second writer's stale ifVersion silently mutated the shared
// candidate. With fork seeding, the first staged write lands at vN+1 and the
// stale vN always conflicts.
func TestFence_D2_ForkVersionCollisionRegression(t *testing.T) {
	draftTestSetup(t)
	// Bring RUNNING to exactly version 2 (two bumps from the reset store).
	seedRule(t, "r1")
	seedRule(t, "r2")
	ver, _ := policyStore.policyVersion()
	setRequireCommit(true)

	verStr := fmt.Sprintf("%d", ver)
	w1 := createRuleViaAPI(t, "first-staged", verStr)
	assertStatus(t, w1, 200)
	if !policyDraft.active() {
		t.Fatal("first staged write did not open the draft")
	}
	w2 := createRuleViaAPI(t, "second-staged-stale", verStr)
	if w2.Code != 409 {
		candVer, _ := policyDraft.candidateVersion()
		t.Fatalf("stale pre-fork token passed the fence (status %d, candidate generation %d, stale token %d)", w2.Code, candVer, ver)
	}
	decodeConflict(t, w2)
	// The stale writer's rule must not exist in the candidate.
	for _, r := range policyDraft.candidateList() {
		if r.Name == "second-staged-stale" {
			t.Fatal("stale writer's rule reached the shared candidate")
		}
	}
}

// TestFence_E_CommitVsDraftMutation: a commit reviewed at candidate vN racing
// an ordinary staged mutation asserting the same vN — exactly one wins. If the
// mutation wins, the commit must conflict (unreviewed change); if the commit
// wins, the mutation must conflict (the candidate it targeted is gone and
// running has moved past every candidate generation).
func TestFence_E_CommitVsDraftMutation(t *testing.T) {
	draftTestSetup(t)
	seedRule(t, "baseline")
	setRequireCommit(true)

	for i := 0; i < fenceRaceIterations; i++ {
		if policyDraft.active() {
			policyDraft.clear()
		}
		// Open a draft with one staged change.
		ver, _ := effectivePolicyVersion()
		w := createRuleViaAPI(t, fmt.Sprintf("staged-%d", i), fmt.Sprintf("%d", ver))
		assertStatus(t, w, 200)
		candVer, _ := policyDraft.candidateVersion()

		commit := func() *httptest.ResponseRecorder {
			rec := httptest.NewRecorder()
			apiPolicyDraftCommit(rec, jsonReq("POST",
				fmt.Sprintf("/api/policy/draft/commit?ifVersion=%d", candVer),
				map[string]any{"comment": fmt.Sprintf("commit-%d", i)}))
			return rec
		}
		stage := func() *httptest.ResponseRecorder {
			return createRuleViaAPI(t, fmt.Sprintf("late-stage-%d", i), fmt.Sprintf("%d", candVer))
		}
		ra, rb := runConcurrentPair(commit, stage)
		if !((ra.Code == 200 && rb.Code == 409) || (ra.Code == 409 && rb.Code == 200)) {
			t.Fatalf("iter %d: want one 200 + one 409, got commit=%d stage=%d", i, ra.Code, rb.Code)
		}
		if ra.Code == 200 {
			// Commit won: draft cleared, running carries the staged rule, and the
			// late mutation did NOT silently land anywhere.
			if policyDraft.active() {
				t.Fatalf("iter %d: draft still active after successful commit", i)
			}
			for _, r := range policyStore.List() {
				if r.Name == fmt.Sprintf("late-stage-%d", i) {
					t.Fatalf("iter %d: conflicted late mutation reached running", i)
				}
			}
		} else {
			// Mutation won: the commit must NOT have activated the (now
			// unreviewed) candidate; the draft remains active with both rules.
			if !policyDraft.active() {
				t.Fatalf("iter %d: draft cleared by a conflicted commit", i)
			}
			policyDraft.clear()
		}
	}
}

// TestFence_F_LegacyNoIfVersionUnchanged: writers that assert no version keep
// today's last-write-wins behavior — both succeed, no conflict is produced.
func TestFence_F_LegacyNoIfVersionUnchanged(t *testing.T) {
	draftTestSetup(t)
	rule := seedRule(t, "fence-target")

	for i := 0; i < fenceRaceIterations; i++ {
		cA := fmt.Sprintf("legacy-A-%d", i)
		cB := fmt.Sprintf("legacy-B-%d", i)
		put := func(comment string) func() *httptest.ResponseRecorder {
			return func() *httptest.ResponseRecorder {
				w := httptest.NewRecorder()
				apiPolicyUpdate(w, jsonReq("PUT", "/api/policy?id="+rule.ID,
					map[string]any{"name": "fence-target", "action": "Allow", "comment": comment}))
				return w
			}
		}
		ra, rb := runConcurrentPair(put(cA), put(cB))
		if ra.Code != 200 || rb.Code != 200 {
			t.Fatalf("iter %d: legacy unfenced writes must both succeed, got %d/%d", i, ra.Code, rb.Code)
		}
		got := effectiveRuleByID(rule.ID)
		if got == nil || (got.Comment != cA && got.Comment != cB) {
			t.Fatalf("iter %d: surviving content is neither writer's (%+v)", i, got)
		}
	}
}

// TestFence_RetiredCandidateTokenNeverRevives: after a revert, a stale
// candidate-era token must conflict even once running's counter would have
// caught up numerically (candidate retirement advances running past every
// candidate generation).
func TestFence_RetiredCandidateTokenNeverRevives(t *testing.T) {
	draftTestSetup(t)
	seedRule(t, "baseline")
	setRequireCommit(true)

	ver, _ := effectivePolicyVersion()
	assertStatus(t, createRuleViaAPI(t, "staged-1", fmt.Sprintf("%d", ver)), 200)
	candVer, _ := policyDraft.candidateVersion() // vN+1, observed by a client
	policyDraft.clear()                          // revert

	// Running must now be PAST the candidate generation, so the stale token
	// conflicts instead of matching a future running generation.
	runVer, _ := policyStore.policyVersion()
	if runVer <= candVer {
		t.Fatalf("running generation %d did not retire past candidate generation %d", runVer, candVer)
	}
	w := createRuleViaAPI(t, "stale-candidate-token", fmt.Sprintf("%d", candVer))
	if w.Code != 409 {
		t.Fatalf("stale candidate-era token passed after revert (status %d)", w.Code)
	}
}
