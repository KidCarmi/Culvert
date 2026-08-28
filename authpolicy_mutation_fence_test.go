package main

// authpolicy_mutation_fence_test.go — 2C.0a Stage-1 auth-policy hardening
// proofs: stable-ID addressing, the RUNNING-generation version contract, and
// atomic ?ifVersion= fencing through fencedRunningMutate.
//
// The pre-2C.0 endpoint addressed rules by mutable priority, carried no
// version contract, and persisted best-effort (PolicyStore.Save discarding the
// error), so two auth-policy admins could silently last-write-win. These tests
// prove the closure with barrier-started concurrent handler pairs (exactly one
// writer of a fenced pair succeeds; the other is refused fail-closed), the
// strict id-addressing contract, and the running-domain invariant: an auth
// mutation lands in RUNNING even while a Stage-2 draft is engaged, stales that
// draft's base generation, and the draft's commit then fails closed.

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

// authRuleBody builds a minimal VALID auth-rule payload (decodeJSON runs with
// DisallowUnknownFields, so only real PolicyRule JSON keys may appear).
func authRuleBody(name, destFQDN string) map[string]any {
	return map[string]any{
		"name":     name,
		"ruleType": "auth",
		"destFQDN": destFQDN,
		"subjectMatch": map[string]any{
			"schemaVersion": 1,
			"all":           []map[string]any{{"type": "cidr", "values": []string{"10.42.0.0/24"}}},
		},
		"auth": map[string]any{"outcome": "Exempt", "owner": "fence-test", "reason": "2C.0a proof"},
	}
}

func createAuthRuleViaAPI(t *testing.T, name, ifVersion string) *httptest.ResponseRecorder {
	t.Helper()
	path := "/api/authpolicy"
	if ifVersion != "" {
		path += "?ifVersion=" + ifVersion
	}
	w := httptest.NewRecorder()
	apiAuthPolicyCreate(w, jsonReq("POST", path, authRuleBody(name, strings.ToLower(name)+".test")))
	return w
}

func seedAuthRule(t *testing.T, name string) PolicyRule {
	t.Helper()
	w := createAuthRuleViaAPI(t, name, "")
	assertStatus(t, w, 200)
	var added PolicyRule
	if err := json.Unmarshal(w.Body.Bytes(), &added); err != nil {
		t.Fatalf("decode created auth rule: %v", err)
	}
	return added
}

func updateAuthRuleReq(id string, ifVersion int64, reason string) *httptest.ResponseRecorder {
	body := authRuleBody("auth-fence-target", "auth-fence-target.test")
	body["auth"] = map[string]any{"outcome": "Exempt", "owner": "fence-test", "reason": reason}
	w := httptest.NewRecorder()
	apiAuthPolicyUpdate(w, jsonReq("PUT",
		fmt.Sprintf("/api/authpolicy?id=%s&ifVersion=%d", id, ifVersion), body))
	return w
}

func deleteAuthRuleReq(id string, ifVersion int64) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	apiAuthPolicyDelete(w, jsonReq("DELETE",
		fmt.Sprintf("/api/authpolicy?id=%s&ifVersion=%d", id, ifVersion), nil))
	return w
}

func getAuthPolicyEnvelope(t *testing.T) map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	apiAuthPolicy(w, getReq("/api/authpolicy"))
	assertStatus(t, w, 200)
	var env map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode /api/authpolicy envelope: %v", err)
	}
	return env
}

// TestAuthFence_GET_VersionIsRunningGeneration: the envelope's version/updatedAt
// are the RUNNING PolicyStore generation — including while a Stage-2 draft is
// engaged, when effectivePolicyVersion() would report the candidate's.
func TestAuthFence_GET_VersionIsRunningGeneration(t *testing.T) {
	draftTestSetup(t)
	seedAuthRule(t, "auth-fence-target")

	env := getAuthPolicyEnvelope(t)
	runVer, runAt := policyStore.policyVersion()
	if got := int64(env["version"].(float64)); got != runVer {
		t.Fatalf("GET version = %d, want running %d", got, runVer)
	}
	if got := env["updatedAt"].(string); got != runAt {
		t.Fatalf("GET updatedAt = %q, want running %q", got, runAt)
	}

	// Engage a Stage-2 draft: candidate generation diverges from running.
	setRequireCommit(true)
	if w := createRuleViaAPI(t, "stage2-staged", ""); w.Code != 200 {
		t.Fatalf("staged access create = %d (%s)", w.Code, w.Body.String())
	}
	if !policyDraft.active() {
		t.Fatal("draft did not open")
	}
	candVer, _ := policyDraft.candidateVersion()
	runVer, _ = policyStore.policyVersion()
	if candVer == runVer {
		t.Fatalf("test premise broken: candidate (%d) and running (%d) generations must differ", candVer, runVer)
	}
	env = getAuthPolicyEnvelope(t)
	if got := int64(env["version"].(float64)); got != runVer {
		t.Fatalf("GET version while draft engaged = %d, want running %d (candidate %d must never leak)", got, runVer, candVer)
	}
}

// TestAuthFence_A_ConcurrentEditsSameVersion: two concurrent id-addressed PUTs
// asserting the same running version — exactly one mutation lands, the loser
// receives the structured 409, and the surviving content is the winner's.
func TestAuthFence_A_ConcurrentEditsSameVersion(t *testing.T) {
	draftTestSetup(t)
	rule := seedAuthRule(t, "auth-fence-target")

	for i := 0; i < fenceRaceIterations; i++ {
		ver, _ := policyStore.policyVersion()
		rA := fmt.Sprintf("writer-A-%d", i)
		rB := fmt.Sprintf("writer-B-%d", i)
		ra, rb := runConcurrentPair(
			func() *httptest.ResponseRecorder { return updateAuthRuleReq(rule.ID, ver, rA) },
			func() *httptest.ResponseRecorder { return updateAuthRuleReq(rule.ID, ver, rB) },
		)
		okCount, conflictCount := 0, 0
		for _, c := range []int{ra.Code, rb.Code} {
			switch c {
			case 200:
				okCount++
			case 409:
				conflictCount++
			default:
				t.Fatalf("iter %d: unexpected statuses %d/%d", i, ra.Code, rb.Code)
			}
		}
		if okCount != 1 || conflictCount != 1 {
			t.Fatalf("iter %d: want exactly one success and one conflict, got %d/%d", i, ra.Code, rb.Code)
		}
		loser, winnerReason := ra, rA
		if ra.Code == 200 {
			loser = rb
		} else {
			winnerReason = rB
		}
		decodeConflict(t, loser)
		got := policyStore.findByIDCopy(rule.ID)
		if got == nil || got.Auth == nil || got.Auth.Reason != winnerReason {
			t.Fatalf("iter %d: surviving content is not the fenced winner's (want reason %q)", i, winnerReason)
		}
		newVer, _ := policyStore.policyVersion()
		if newVer != ver+1 {
			t.Fatalf("iter %d: version advanced by %d, want exactly 1", i, newVer-ver)
		}
	}
}

// TestAuthFence_B_ConcurrentCreatesSameVersion: two concurrent creates
// asserting the same version — one succeeds, one conflicts, exactly one rule
// is added.
func TestAuthFence_B_ConcurrentCreatesSameVersion(t *testing.T) {
	draftTestSetup(t)
	seedAuthRule(t, "auth-existing")

	for i := 0; i < fenceRaceIterations; i++ {
		before := len(policyStore.List())
		ver, _ := policyStore.policyVersion()
		verStr := fmt.Sprintf("%d", ver)
		ra, rb := runConcurrentPair(
			func() *httptest.ResponseRecorder {
				return createAuthRuleViaAPI(t, fmt.Sprintf("auth-create-A-%d", i), verStr)
			},
			func() *httptest.ResponseRecorder {
				return createAuthRuleViaAPI(t, fmt.Sprintf("auth-create-B-%d", i), verStr)
			},
		)
		if !((ra.Code == 200 && rb.Code == 409) || (ra.Code == 409 && rb.Code == 200)) {
			t.Fatalf("iter %d: want one 200 + one 409, got %d/%d", i, ra.Code, rb.Code)
		}
		if got := len(policyStore.List()); got != before+1 {
			t.Fatalf("iter %d: %d rules added, want exactly 1", i, got-before)
		}
	}
}

// TestAuthFence_C_ConcurrentDeleteAndEditSameVersion: a delete and an edit of
// the same rule asserting the same version — exactly one mutation lands; the
// loser is refused fail-closed (409 from the fence, or 404 when the winner's
// delete removed the target before the loser's optimistic resolution).
func TestAuthFence_C_ConcurrentDeleteAndEditSameVersion(t *testing.T) {
	draftTestSetup(t)

	for i := 0; i < fenceRaceIterations; i++ {
		rule := seedAuthRule(t, fmt.Sprintf("auth-fence-target-%d", i))
		// Rename to the shared edit-body name space so updateAuthRuleReq's fixed
		// name never collides across iterations (the rule is deleted or renamed
		// each round; a deleted round leaves nothing behind).
		ver, _ := policyStore.policyVersion()
		ra, rb := runConcurrentPair(
			func() *httptest.ResponseRecorder { return deleteAuthRuleReq(rule.ID, ver) },
			func() *httptest.ResponseRecorder { return updateAuthRuleReq(rule.ID, ver, fmt.Sprintf("edit-%d", i)) },
		)
		okCount := 0
		for _, rec := range []*httptest.ResponseRecorder{ra, rb} {
			switch rec.Code {
			case 200, 204:
				okCount++
			case 409, 404:
				// refused — fail-closed
			default:
				t.Fatalf("iter %d: unexpected statuses delete=%d edit=%d", i, ra.Code, rb.Code)
			}
		}
		if okCount != 1 {
			t.Fatalf("iter %d: want exactly one success, got delete=%d edit=%d", i, ra.Code, rb.Code)
		}
		// Clean up the survivor (edit-winner rounds) with an UNFENCED delete so
		// the shared edit-body name is free for the next iteration.
		if cur := policyStore.findByIDCopy(rule.ID); cur != nil {
			w := httptest.NewRecorder()
			apiAuthPolicyDelete(w, jsonReq("DELETE", "/api/authpolicy?id="+rule.ID, nil))
			assertStatus(t, w, 204)
		}
	}
}

// TestAuthFence_D_StableIDAddressing: the strict id contract — malformed 400,
// unknown 404, access-rule 400 — and no fall-through to a priority guess even
// when a valid ?priority= rides alongside a rejected ?id=.
func TestAuthFence_D_StableIDAddressing(t *testing.T) {
	draftTestSetup(t)
	auth := seedAuthRule(t, "auth-fence-target")
	// A live-mode access rule for the wrong-type refusal.
	aw := createRuleViaAPI(t, "an-access-rule", "")
	assertStatus(t, aw, 200)
	var access PolicyRule
	if err := json.Unmarshal(aw.Body.Bytes(), &access); err != nil {
		t.Fatalf("decode access rule: %v", err)
	}

	body := authRuleBody("auth-fence-target", "auth-fence-target.test")

	// Happy path: id-addressed edit.
	w := httptest.NewRecorder()
	apiAuthPolicyUpdate(w, jsonReq("PUT", "/api/authpolicy?id="+auth.ID, body))
	assertStatus(t, w, 200)

	// Malformed id → 400 (never a priority fall-through).
	w = httptest.NewRecorder()
	apiAuthPolicyUpdate(w, jsonReq("PUT", "/api/authpolicy?id=not-a-ulid", body))
	assertStatus(t, w, 400)

	// Unknown (valid-shape) ULID → 404.
	w = httptest.NewRecorder()
	apiAuthPolicyUpdate(w, jsonReq("PUT", "/api/authpolicy?id=01ARZ3NDEKTSV4RRFFQ69G5FAV", body))
	assertStatus(t, w, 404)

	// Access-rule id → 400, even with a VALID auth priority riding alongside:
	// the id path must never fall through to the priority guess.
	w = httptest.NewRecorder()
	apiAuthPolicyUpdate(w, jsonReq("PUT",
		fmt.Sprintf("/api/authpolicy?id=%s&priority=%d", access.ID, auth.Priority), body))
	assertStatus(t, w, 400)
	if got := policyStore.findByIDCopy(auth.ID); got == nil {
		t.Fatal("auth rule vanished — the rejected id addressing must not touch the priority target")
	}
	if got := policyStore.findByIDCopy(access.ID); got == nil || ruleTypeOf(got) != ruleTypeAccess {
		t.Fatal("access rule was touched by the auth endpoint")
	}

	// Same strictness on DELETE.
	w = httptest.NewRecorder()
	apiAuthPolicyDelete(w, jsonReq("DELETE", "/api/authpolicy?id=zzz", nil))
	assertStatus(t, w, 400)
	w = httptest.NewRecorder()
	apiAuthPolicyDelete(w, jsonReq("DELETE", "/api/authpolicy?id=01ARZ3NDEKTSV4RRFFQ69G5FAV", nil))
	assertStatus(t, w, 404)
	w = httptest.NewRecorder()
	apiAuthPolicyDelete(w, jsonReq("DELETE",
		fmt.Sprintf("/api/authpolicy?id=%s&priority=%d", access.ID, auth.Priority), nil))
	assertStatus(t, w, 400)
	if got := policyStore.findByIDCopy(auth.ID); got == nil {
		t.Fatal("auth rule deleted through a rejected id addressing")
	}
}

// TestAuthFence_E_LegacyClientsUnfenced: requests without ?ifVersion= keep the
// pre-2C last-write-wins behavior — both sequential edits succeed.
func TestAuthFence_E_LegacyClientsUnfenced(t *testing.T) {
	draftTestSetup(t)
	rule := seedAuthRule(t, "auth-fence-target")

	body := authRuleBody("auth-fence-target", "auth-fence-target.test")
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		apiAuthPolicyUpdate(w, jsonReq("PUT", "/api/authpolicy?id="+rule.ID, body))
		assertStatus(t, w, 200)
	}
	// Legacy priority addressing still works too.
	w := httptest.NewRecorder()
	apiAuthPolicyUpdate(w, jsonReq("PUT", fmt.Sprintf("/api/authpolicy?priority=%d", rule.Priority), body))
	assertStatus(t, w, 200)
}

// TestAuthFence_F_RunningDomainNeverCandidate is the §7 running-domain proof:
// with Require Commit armed and a Stage-2 draft ACTIVE, an auth mutation
// asserting the RUNNING version (a) succeeds against that running version, (b)
// lands in the running store immediately — never in the candidate, (c) leaves
// the draft active but base-STALE (GET /api/policy/draft baseStale=true), and
// (d) makes the draft's commit fail closed until it is reverted.
func TestAuthFence_F_RunningDomainNeverCandidate(t *testing.T) {
	draftTestSetup(t)
	setRequireCommit(true)

	// Open the Stage-2 draft with a staged access-rule create.
	if w := createRuleViaAPI(t, "stage2-staged", ""); w.Code != 200 {
		t.Fatalf("staged access create = %d (%s)", w.Code, w.Body.String())
	}
	if !policyDraft.active() {
		t.Fatal("draft did not open")
	}
	candBefore := len(policyDraft.candidateList())

	// Auth create fenced on the RUNNING generation (not the candidate's).
	runVer, _ := policyStore.policyVersion()
	w := createAuthRuleViaAPI(t, "auth-live-now", fmt.Sprintf("%d", runVer))
	assertStatus(t, w, 200)
	var added PolicyRule
	if err := json.Unmarshal(w.Body.Bytes(), &added); err != nil {
		t.Fatalf("decode created auth rule: %v", err)
	}

	// (b) Running holds it; the candidate is untouched.
	if got := policyStore.findByIDCopy(added.ID); got == nil {
		t.Fatal("auth rule did not land in the RUNNING store")
	}
	for _, cr := range policyDraft.candidateList() {
		if cr.ID == added.ID {
			t.Fatal("auth rule leaked into the draft candidate")
		}
	}
	if got := len(policyDraft.candidateList()); got != candBefore {
		t.Fatalf("candidate size changed under an auth mutation: %d → %d", candBefore, got)
	}

	// (c) Draft still active, now base-stale — surfaced on the draft GET.
	if !policyDraft.active() {
		t.Fatal("draft was closed by the auth mutation")
	}
	dw := httptest.NewRecorder()
	apiPolicyDraft(dw, getReq("/api/policy/draft"))
	assertStatus(t, dw, 200)
	var draftEnv map[string]any
	if err := json.Unmarshal(dw.Body.Bytes(), &draftEnv); err != nil {
		t.Fatalf("decode draft envelope: %v", err)
	}
	if stale, ok := draftEnv["baseStale"].(bool); !ok || !stale {
		t.Fatalf("draft GET baseStale = %v, want true after a live auth mutation", draftEnv["baseStale"])
	}

	// (d) Commit fails closed on the stale base.
	cw := httptest.NewRecorder()
	apiPolicyDraftCommit(cw, jsonReq("POST", "/api/policy/draft/commit", map[string]any{"comment": "should fail"}))
	assertStatus(t, cw, 409)

	// The auth rule is still live and the candidate still holds its staged edit.
	if got := policyStore.findByIDCopy(added.ID); got == nil {
		t.Fatal("auth rule lost after refused commit")
	}
	if !policyDraft.active() {
		t.Fatal("refused commit must leave the draft active for revert/re-stage")
	}
}

// TestAuthFence_G_InactiveDraftGETOmitsBaseStale: baseStale is present only
// while a draft is active (it is a fact about an active draft's fork point).
func TestAuthFence_G_InactiveDraftGETOmitsBaseStale(t *testing.T) {
	draftTestSetup(t)
	dw := httptest.NewRecorder()
	apiPolicyDraft(dw, getReq("/api/policy/draft"))
	assertStatus(t, dw, 200)
	var draftEnv map[string]any
	if err := json.Unmarshal(dw.Body.Bytes(), &draftEnv); err != nil {
		t.Fatalf("decode draft envelope: %v", err)
	}
	if _, present := draftEnv["baseStale"]; present {
		t.Fatal("baseStale must be absent when no draft is active")
	}
}
