package main

// authpolicy_mutation_durability_test.go — 2C.0b durable-or-nothing proofs
// for Stage-1 auth-policy mutations, plus the stable-ID reorder contract.
//
// Contract under test (fencedRunningMutate → runningMutateLocked): a 2xx auth
// mutation means the change is in the durable running rulebase
// (policy_rules.json); a pre-replacement persistence failure fails the request
// AND rolls the semantic state back, so memory and the restart-visible file
// agree the mutation never happened; ErrReplacedNotSynced counts as landed
// (commit doctrine). Every proof verifies the PERSISTED/RELOADED state, never
// memory alone, reusing the 2B.0b fault-injection harness (blockPath /
// unblockPath / reloadPolicyFile).

import (
	"errors"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

func authReorderReq(body map[string]any, query string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	apiAuthPolicyReorder(w, jsonReq("POST", "/api/authpolicy/reorder"+query, body))
	return w
}

func authRuleReason(t *testing.T, rules []PolicyRule, name string) string {
	t.Helper()
	for i := range rules {
		if rules[i].Name == name {
			if rules[i].Auth == nil {
				t.Fatalf("rule %q has no auth spec", name)
			}
			return rules[i].Auth.Reason
		}
	}
	t.Fatalf("rule %q not found", name)
	return ""
}

func rulePriority(t *testing.T, rules []PolicyRule, name string) int {
	t.Helper()
	for i := range rules {
		if rules[i].Name == name {
			return rules[i].Priority
		}
	}
	t.Fatalf("rule %q not found", name)
	return 0
}

// ── Durable-or-nothing ──────────────────────────────────────────────────────

func TestAuthDurable_CreatePersistFailureRollsBack(t *testing.T) {
	policyPath, _ := durableTestSetup(t)
	seedAuthRule(t, "auth-seed")
	prev := blockPath(t, policyPath)

	w := createAuthRuleViaAPI(t, "auth-doomed", "")
	if w.Code != 500 {
		t.Fatalf("persist failure must fail the request, got %d (%s)", w.Code, w.Body.String())
	}
	if hasRuleNamed(policyStore.List(), "auth-doomed") {
		t.Fatal("failed create left the rule in memory")
	}
	unblockPath(t, policyPath, prev)
	if hasRuleNamed(reloadPolicyFile(t, policyPath), "auth-doomed") {
		t.Fatal("failed create is restart-visible")
	}
}

func TestAuthDurable_EditPersistFailureRollsBack(t *testing.T) {
	policyPath, _ := durableTestSetup(t)
	rule := seedAuthRule(t, "auth-fence-target")
	prevReason := rule.Auth.Reason
	prev := blockPath(t, policyPath)

	ver, _ := policyStore.policyVersion()
	w := updateAuthRuleReq(rule.ID, ver, "poisoned-edit")
	if w.Code != 500 {
		t.Fatalf("persist failure must fail the request, got %d (%s)", w.Code, w.Body.String())
	}
	if got := authRuleReason(t, policyStore.List(), "auth-fence-target"); got != prevReason {
		t.Fatalf("failed edit mutated memory: reason %q, want %q", got, prevReason)
	}
	unblockPath(t, policyPath, prev)
	if got := authRuleReason(t, reloadPolicyFile(t, policyPath), "auth-fence-target"); got != prevReason {
		t.Fatalf("failed edit is restart-visible: reason %q, want %q", got, prevReason)
	}
}

func TestAuthDurable_DeletePersistFailureRollsBack(t *testing.T) {
	policyPath, _ := durableTestSetup(t)
	rule := seedAuthRule(t, "auth-keep-me")
	prev := blockPath(t, policyPath)

	w := httptest.NewRecorder()
	apiAuthPolicyDelete(w, jsonReq("DELETE", "/api/authpolicy?id="+rule.ID, nil))
	if w.Code != 500 {
		t.Fatalf("persist failure must fail the request, got %d (%s)", w.Code, w.Body.String())
	}
	if !hasRuleNamed(policyStore.List(), "auth-keep-me") {
		t.Fatal("failed delete removed the rule from memory")
	}
	unblockPath(t, policyPath, prev)
	if !hasRuleNamed(reloadPolicyFile(t, policyPath), "auth-keep-me") {
		t.Fatal("failed delete is restart-visible")
	}
}

func TestAuthDurable_ReorderPersistFailureRollsBack(t *testing.T) {
	policyPath, _ := durableTestSetup(t)
	a := seedAuthRule(t, "auth-first")
	b := seedAuthRule(t, "auth-second")
	prev := blockPath(t, policyPath)

	w := authReorderReq(map[string]any{"ids": []string{b.ID, a.ID}}, "")
	if w.Code != 500 {
		t.Fatalf("persist failure must fail the request, got %d (%s)", w.Code, w.Body.String())
	}
	mem := policyStore.List()
	if rulePriority(t, mem, "auth-first") != a.Priority || rulePriority(t, mem, "auth-second") != b.Priority {
		t.Fatal("failed reorder mutated the in-memory order")
	}
	unblockPath(t, policyPath, prev)
	disk := reloadPolicyFile(t, policyPath)
	if rulePriority(t, disk, "auth-first") != a.Priority || rulePriority(t, disk, "auth-second") != b.Priority {
		t.Fatal("failed reorder is restart-visible")
	}
}

func TestAuthDurable_SuccessIsRestartVisible(t *testing.T) {
	policyPath, _ := durableTestSetup(t)
	a := seedAuthRule(t, "auth-first")
	b := seedAuthRule(t, "auth-second")

	ver, _ := policyStore.policyVersion()
	if w := updateAuthRuleReq(a.ID, ver, "edited-durably"); w.Code != 200 {
		t.Fatalf("edit = %d (%s)", w.Code, w.Body.String())
	}
	if w := authReorderReq(map[string]any{"ids": []string{b.ID, a.ID}}, ""); w.Code != 200 {
		t.Fatalf("reorder = %d (%s)", w.Code, w.Body.String())
	}

	disk := reloadPolicyFile(t, policyPath)
	// The edit renamed a to the shared edit-body name; its reason proves the edit.
	if got := authRuleReason(t, disk, "auth-fence-target"); got != "edited-durably" {
		t.Fatalf("edit not restart-visible: reason %q", got)
	}
	// The reorder swapped the two auth priorities (same value multiset).
	if rulePriority(t, disk, "auth-second") != a.Priority || rulePriority(t, disk, "auth-fence-target") != b.Priority {
		t.Fatal("reorder not restart-visible")
	}
}

func TestAuthDurable_ErrReplacedNotSyncedCountsAsLanded(t *testing.T) {
	durableTestSetup(t)
	prevPersist := persistRunningPolicy
	persistRunningPolicy = func() error {
		if err := policyStore.SaveErr(); err != nil {
			return err
		}
		return fmt.Errorf("atomic write: parent dir fsync: injected: %w", fileutil.ErrReplacedNotSynced)
	}
	t.Cleanup(func() { persistRunningPolicy = prevPersist })

	w := createAuthRuleViaAPI(t, "auth-landed-degraded", "")
	if w.Code != 200 {
		t.Fatalf("ErrReplacedNotSynced must count as landed (commit doctrine), got %d (%s)", w.Code, w.Body.String())
	}
	if !hasRuleNamed(policyStore.List(), "auth-landed-degraded") {
		t.Fatal("landed mutation was rolled back despite the file carrying it")
	}
}

func TestAuthDurable_SeamRollback(t *testing.T) {
	durableTestSetup(t)
	seedAuthRule(t, "auth-seed")
	prevPersist := persistRunningPolicy
	persistRunningPolicy = func() error { return errors.New("injected pre-replace failure") }
	t.Cleanup(func() { persistRunningPolicy = prevPersist })

	w := createAuthRuleViaAPI(t, "auth-doomed-seam", "")
	if w.Code != 500 {
		t.Fatalf("want 500, got %d (%s)", w.Code, w.Body.String())
	}
	if hasRuleNamed(policyStore.List(), "auth-doomed-seam") {
		t.Fatal("failed create left the rule in memory")
	}
}

// ── Stable-ID reorder contract ──────────────────────────────────────────────

// TestAuthReorder_ByIDs_ContractMatrix pins the {ids:[...]} shape: happy-path
// swap; every-rule-exactly-once; duplicate/unknown/access-rule/partial and
// malformed entries rejected 400; ids+priorities together rejected; the empty
// body rejected; access-rule ordering never disturbed.
func TestAuthReorder_ByIDs_ContractMatrix(t *testing.T) {
	durableTestSetup(t)
	// Access rules AROUND the auth rules so a disturbed access order is visible.
	acc1 := seedRule(t, "access-one")
	a := seedAuthRule(t, "auth-first")
	b := seedAuthRule(t, "auth-second")
	acc2 := seedRule(t, "access-two")

	// Happy path: reversed ids swap the two auth priorities.
	w := authReorderReq(map[string]any{"ids": []string{b.ID, a.ID}}, "")
	assertStatus(t, w, 200)
	mem := policyStore.List()
	if rulePriority(t, mem, "auth-second") != a.Priority || rulePriority(t, mem, "auth-first") != b.Priority {
		t.Fatal("ids reorder did not swap the auth priorities")
	}
	// Access rules untouched (priority AND relative order).
	if rulePriority(t, mem, "access-one") != acc1.Priority || rulePriority(t, mem, "access-two") != acc2.Priority {
		t.Fatal("ids reorder disturbed access-rule priorities")
	}

	// Restore original order for the rejection matrix.
	w = authReorderReq(map[string]any{"ids": []string{a.ID, b.ID}}, "")
	assertStatus(t, w, 200)

	// Status semantics (2E-C concurrency-status correction): a list that is
	// malformed on its own terms (duplicate entry, bad ULID grammar, both or
	// neither shape, an id that belongs to an ACCESS rule — an id never
	// changes type) is 400 whatever the rulebase holds; a list that fails
	// against the CURRENT rulebase (partial, wrong count, an id that is not a
	// current auth rule) is a state conflict — 409 carrying currentVersion
	// when the client asserted no generation, 400 when it asserted the
	// matching one (nothing changed, the list is simply wrong).
	rejected := []struct {
		body map[string]any
		want int
	}{
		{map[string]any{"ids": []string{a.ID, a.ID}}, 400},                            // duplicate (structural)
		{map[string]any{"ids": []string{a.ID}}, 409},                                  // partial (state)
		{map[string]any{"ids": []string{a.ID, b.ID, acc1.ID}}, 409},                   // wrong count (state)
		{map[string]any{"ids": []string{a.ID, acc1.ID}}, 400},                         // access-rule id (invariant)
		{map[string]any{"ids": []string{a.ID, "01ARZ3NDEKTSV4RRFFQ69G5FAV"}}, 409},    // unknown ULID (state)
		{map[string]any{"ids": []string{a.ID, "not-a-ulid"}}, 400},                    // malformed (structural)
		{map[string]any{"ids": []string{a.ID, b.ID}, "priorities": []int{1, 2}}, 400}, // both shapes
		{map[string]any{}, 400}, // neither shape
	}
	for i, tc := range rejected {
		if w := authReorderReq(tc.body, ""); w.Code != tc.want {
			t.Fatalf("rejection case %d: want %d, got %d (%s)", i, tc.want, w.Code, w.Body.String())
		}
		// The same state-dependent list against the ASSERTED matching
		// generation is the request's own fault: 400.
		if tc.want == 409 {
			ver, _ := policyStore.policyVersion()
			if w := authReorderReq(tc.body, fmt.Sprintf("?ifVersion=%d", ver)); w.Code != 400 {
				t.Fatalf("rejection case %d asserted: want 400, got %d (%s)", i, w.Code, w.Body.String())
			}
		}
	}
	// Nothing moved during the rejections.
	mem = policyStore.List()
	if rulePriority(t, mem, "auth-first") != a.Priority || rulePriority(t, mem, "auth-second") != b.Priority ||
		rulePriority(t, mem, "access-one") != acc1.Priority || rulePriority(t, mem, "access-two") != acc2.Priority {
		t.Fatal("a rejected reorder mutated the rulebase")
	}
}

// TestAuthReorder_Fenced: reorder accepts ?ifVersion= and conflicts 409 on a
// stale assertion without mutating.
func TestAuthReorder_Fenced(t *testing.T) {
	durableTestSetup(t)
	a := seedAuthRule(t, "auth-first")
	b := seedAuthRule(t, "auth-second")

	ver, _ := policyStore.policyVersion()
	// Stale assertion (ver-1) → structured 409, order unchanged.
	w := authReorderReq(map[string]any{"ids": []string{b.ID, a.ID}}, fmt.Sprintf("?ifVersion=%d", ver-1))
	assertStatus(t, w, 409)
	decodeConflict(t, w)
	mem := policyStore.List()
	if rulePriority(t, mem, "auth-first") != a.Priority {
		t.Fatal("conflicted reorder mutated the rulebase")
	}
	// Correct assertion → applied.
	w = authReorderReq(map[string]any{"ids": []string{b.ID, a.ID}}, fmt.Sprintf("?ifVersion=%d", ver))
	assertStatus(t, w, 200)
	mem = policyStore.List()
	if rulePriority(t, mem, "auth-second") != a.Priority {
		t.Fatal("fenced reorder did not apply")
	}
}

// TestAuthReorder_LegacyPriorities: the legacy {priorities:[...]} shape keeps
// its exact pre-2C semantics (exactly-once set of auth priorities, redistributed
// in the requested order).
func TestAuthReorder_LegacyPriorities(t *testing.T) {
	durableTestSetup(t)
	a := seedAuthRule(t, "auth-first")
	b := seedAuthRule(t, "auth-second")

	w := authReorderReq(map[string]any{"priorities": []int{b.Priority, a.Priority}}, "")
	assertStatus(t, w, 200)
	mem := policyStore.List()
	if rulePriority(t, mem, "auth-second") != a.Priority || rulePriority(t, mem, "auth-first") != b.Priority {
		t.Fatal("legacy priorities reorder did not swap")
	}
	// Access-rule priority in the list → refused against the current
	// rulebase: 409 (+currentVersion) unasserted, 400 against the asserted
	// matching generation (2E-C concurrency-status correction).
	acc := seedRule(t, "access-one")
	if w := authReorderReq(map[string]any{"priorities": []int{acc.Priority, a.Priority}}, ""); w.Code != 409 {
		t.Fatalf("access priority in legacy list: want 409, got %d", w.Code)
	}
	ver, _ := policyStore.policyVersion()
	if w := authReorderReq(map[string]any{"priorities": []int{acc.Priority, a.Priority}}, fmt.Sprintf("?ifVersion=%d", ver)); w.Code != 400 {
		t.Fatalf("access priority in legacy list (asserted): want 400, got %d", w.Code)
	}
}
