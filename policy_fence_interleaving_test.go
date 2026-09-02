package main

// policy_fence_interleaving_test.go — 2E-C concurrency-status correction:
// deterministic interleaving proofs for every rule-mutation handler.
//
// Observed product evidence (e2e policy-2c, two-client auth fencing): a
// concurrent reorder-versus-edit returned [200, 400] instead of the fenced
// [200, 409]. Exactly one mutation landed — the coordinator fence held — but
// the losing edit had resolved its target and validated the body OUTSIDE the
// fence, against a rulebase the reorder then changed; the stale exclusion
// slot made the duplicate-NAME check see the rule itself at its new priority
// and report "rule name already exists" (400: "your request is malformed")
// for a request that had merely lost a state race (409: "reload and retry").
//
// These proofs control the interleaving with the policyWriteStateDecision
// seam (no sleeps): the held request finishes its structural work, parks at
// the named stage, the competitor commits through the real handler, the held
// request resumes against the new state. Every case pins: exactly one
// mutation landed (the generation advanced by exactly the winner's writes,
// the rulebase content is the winner's), the loser performed ZERO mutation
// and produced NO success audit, and the loser's status is the truthful one
// (409 with the current version for a state race, 404 for a vanished target,
// 400 only for malformed input). The pre-fix outcomes each case documents
// are the defects this file was RED against.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	holdHeader = "X-Culvert-Test-Hold-Stage"
	loserAddr  = "198.51.100.77:4242" // TEST-NET-2: the loser's audit-actor discriminator
	loserActor = "198.51.100.77"
)

// heldReq builds an admin request that the seam will park at `stage`.
func heldReq(method, path string, body any, stage string) *http.Request {
	r := jsonReq(method, path, body)
	r.Header.Set(holdHeader, stage)
	r.RemoteAddr = loserAddr
	return r
}

// runInterleaved parks `held` at `stage`, runs `competitor` to completion,
// releases `held`, and returns both recorders. Pure channel ordering.
func runInterleaved(t *testing.T, stage string, held, competitor func() *httptest.ResponseRecorder) (rh, rc *httptest.ResponseRecorder) {
	t.Helper()
	parked := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	prev := policyWriteStateDecisionHook
	policyWriteStateDecisionHook = func(r *http.Request, s string) {
		if s == stage && r.Header.Get(holdHeader) == stage {
			once.Do(func() { close(parked) })
			<-release
		}
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- held() }()
	select {
	case <-parked:
	case <-time.After(30 * time.Second):
		t.Fatal("held request never reached the hold stage")
	}
	rc = competitor()
	close(release)
	rh = <-done
	policyWriteStateDecisionHook = prev
	return rh, rc
}

func ruleByName(name string) *PolicyRule {
	rules := policyStore.List()
	for i := range rules {
		if rules[i].Name == name {
			r := rules[i]
			return &r
		}
	}
	return nil
}

func ilCountRulesNamed(name string) int {
	n := 0
	for _, r := range policyStore.List() {
		if strings.EqualFold(r.Name, name) {
			n++
		}
	}
	return n
}

// assertLoser: the loser's verdict is a state race (409 carrying the current
// version so the client can refresh) or a vanished target (404) — never 400.
func assertLoser(t *testing.T, w *httptest.ResponseRecorder, want ...int) {
	t.Helper()
	ok := false
	for _, c := range want {
		if w.Code == c {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("loser status = %d, want one of %v; body: %s", w.Code, want, w.Body.String())
	}
	if w.Code == http.StatusConflict {
		var body struct {
			Error          string `json:"error"`
			CurrentVersion *int64 `json:"currentVersion"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.Error == "" || body.CurrentVersion == nil {
			t.Fatalf("409 must carry {error, currentVersion} for a safe refresh; got %s", w.Body.String())
		}
	}
}

// assertNoLoserAudit: no SUCCESS audit entry for the loser's action was
// recorded since `since` (content-scan, never a len() delta).
func assertNoLoserAudit(t *testing.T, action string, since int64) {
	t.Helper()
	for _, e := range auditGet() {
		if e.TS >= since && e.Action == action && strings.Contains(e.Actor, loserActor) {
			t.Fatalf("loser produced a success audit %q on %q", e.Action, e.Object)
		}
	}
}

func assertVersionDelta(t *testing.T, before int64, want int64) {
	t.Helper()
	cur, _ := policyStore.policyVersion()
	if cur != before+want {
		t.Fatalf("generation advanced by %d, want exactly %d (winner only)", cur-before, want)
	}
}

func ilAuthReorderReq(ids []string, ifVersion int64) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	path := "/api/authpolicy/reorder"
	if ifVersion >= 0 {
		path += fmt.Sprintf("?ifVersion=%d", ifVersion)
	}
	apiAuthPolicyReorder(w, jsonReq("POST", path, map[string]any{"ids": ids}))
	return w
}

func accessReorderReq(priorities []int, ifVersion int64) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	path := "/api/policy/reorder"
	if ifVersion >= 0 {
		path += fmt.Sprintf("?ifVersion=%d", ifVersion)
	}
	apiPolicyReorder(w, jsonReq("POST", path, map[string]any{"priorities": priorities}))
	return w
}

func createAccessRuleAt(t *testing.T, name string, priority int) PolicyRule {
	t.Helper()
	w := httptest.NewRecorder()
	body := map[string]any{"name": name, "action": "Allow"}
	if priority > 0 {
		body["priority"] = priority
	}
	apiPolicyCreate(w, jsonReq("POST", "/api/policy", body))
	assertStatus(t, w, 200)
	var added PolicyRule
	if err := json.Unmarshal(w.Body.Bytes(), &added); err != nil {
		t.Fatalf("decode created rule: %v", err)
	}
	return added
}

// ── Stage-1: /api/authpolicy ────────────────────────────────────────────────

// The observed defect: an id-addressed auth edit whose competitor reorders the
// auth rules between its target resolution and its validation. Pre-fix: 400
// "rule name already exists". Correct: the structured 409.
func TestFenceInterleave_AuthUpdate_VsReorder_LoserIs409(t *testing.T) {
	for _, tc := range []struct {
		name, stage string
		byPriority  bool
	}{
		{"id-addressed/resolved", "resolved", false},
		{"priority-addressed/resolved", "resolved", true},
		{"id-addressed/fence", "fence", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			draftTestSetup(t)
			a := seedAuthRule(t, "auth-il-a")
			b := seedAuthRule(t, "auth-il-b")
			ver, _ := policyStore.policyVersion()
			since := time.Now().UnixMilli()
			addr := fmt.Sprintf("id=%s", b.ID)
			if tc.byPriority {
				addr = fmt.Sprintf("priority=%d", b.Priority)
			}
			body := authRuleBody("auth-il-b", "auth-il-b.test")
			body["auth"] = map[string]any{"outcome": "Exempt", "owner": "fence-test", "reason": "racer"}
			rh, rc := runInterleaved(t, tc.stage,
				func() *httptest.ResponseRecorder {
					w := httptest.NewRecorder()
					apiAuthPolicyUpdate(w, heldReq("PUT", fmt.Sprintf("/api/authpolicy?%s&ifVersion=%d", addr, ver), body, tc.stage))
					return w
				},
				func() *httptest.ResponseRecorder { return ilAuthReorderReq([]string{b.ID, a.ID}, ver) },
			)
			assertStatus(t, rc, 200)
			assertLoser(t, rh, http.StatusConflict)
			assertVersionDelta(t, ver, 1)
			if got := policyStore.findByIDCopy(b.ID); got == nil || got.Auth == nil || got.Auth.Reason != "2C.0a proof" {
				t.Fatalf("loser mutated the rulebase (reason=%v)", got)
			}
			if pa, pb := policyStore.findByIDCopy(a.ID).Priority, policyStore.findByIDCopy(b.ID).Priority; pb >= pa {
				t.Fatalf("winner's reorder not intact: a=%d b=%d", pa, pb)
			}
			assertNoLoserAudit(t, "authpolicy.update", since)
		})
	}
}

// A create that loses a same-name race: the loser must be told the rulebase
// conflicts (409 + current version), never that its input is malformed, and
// exactly one rule with the name may exist afterwards. Pre-fix at "resolved":
// 400; pre-fix at "fence" (validation already passed): BOTH creates succeed
// and the rulebase carries two rules with one name.
func TestFenceInterleave_AuthCreate_VsSameNameCreate(t *testing.T) {
	for _, stage := range []string{"resolved", "fence"} {
		t.Run(stage, func(t *testing.T) {
			draftTestSetup(t)
			seedAuthRule(t, "auth-il-existing")
			ver, _ := policyStore.policyVersion()
			since := time.Now().UnixMilli()
			rh, rc := runInterleaved(t, stage,
				func() *httptest.ResponseRecorder {
					w := httptest.NewRecorder()
					apiAuthPolicyCreate(w, heldReq("POST", "/api/authpolicy", authRuleBody("auth-il-dup", "auth-il-dup.test"), stage))
					return w
				},
				func() *httptest.ResponseRecorder { return createAuthRuleViaAPI(t, "auth-il-dup", "") },
			)
			assertStatus(t, rc, 200)
			assertLoser(t, rh, http.StatusConflict)
			if n := ilCountRulesNamed("auth-il-dup"); n != 1 {
				t.Fatalf("%d rules named auth-il-dup, want exactly 1 (duplicate-name integrity)", n)
			}
			assertVersionDelta(t, ver, 1)
			assertNoLoserAudit(t, "authpolicy.add", since)
		})
	}
}

// A legacy priority-addressed delete whose competitor reorders first: the
// audit must name the rule that actually vanished. Pre-fix the handler audits
// the rule it resolved BEFORE the fence while deleting whichever rule the
// reorder moved onto that priority.
func TestFenceInterleave_AuthDeleteByPriority_VsReorder_AuditIsTruthful(t *testing.T) {
	draftTestSetup(t)
	a := seedAuthRule(t, "auth-il-a")
	b := seedAuthRule(t, "auth-il-b")
	ver, _ := policyStore.policyVersion()
	since := time.Now().UnixMilli()
	rh, rc := runInterleaved(t, "fence",
		func() *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			apiAuthPolicyDelete(w, heldReq("DELETE", fmt.Sprintf("/api/authpolicy?priority=%d", b.Priority), nil, "fence"))
			return w
		},
		func() *httptest.ResponseRecorder { return ilAuthReorderReq([]string{b.ID, a.ID}, ver) },
	)
	assertStatus(t, rc, 200)
	if rh.Code != http.StatusNoContent && rh.Code != http.StatusConflict {
		t.Fatalf("unasserted priority delete = %d, want 204 (deleted the rule now at that priority) or 409", rh.Code)
	}
	assertVersionDelta(t, ver, map[int]int64{http.StatusNoContent: 2, http.StatusConflict: 1}[rh.Code])
	if rh.Code == http.StatusNoContent {
		vanished := "auth-il-a"
		if policyStore.findByIDCopy(a.ID) != nil {
			vanished = "auth-il-b"
		}
		found := false
		for _, e := range auditGet() {
			if e.TS >= since && e.Action == "authpolicy.remove" && strings.Contains(e.Actor, loserActor) {
				found = true
				if e.Object != vanished {
					t.Fatalf("audit names %q but the rule that vanished is %q", e.Object, vanished)
				}
			}
		}
		if !found {
			t.Fatal("no authpolicy.remove audit recorded for the delete")
		}
	}
}

// ── Stage-2: /api/policy ────────────────────────────────────────────────────

func TestFenceInterleave_AccessUpdate_VsReorder_LoserIs409(t *testing.T) {
	for _, tc := range []struct {
		name       string
		byPriority bool
	}{
		{"id-addressed", false},
		{"priority-addressed", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			draftTestSetup(t)
			x := createAccessRuleAt(t, "acc-il-x", 0)
			y := createAccessRuleAt(t, "acc-il-y", 0)
			ver, _ := policyStore.policyVersion()
			since := time.Now().UnixMilli()
			addr := fmt.Sprintf("id=%s", y.ID)
			if tc.byPriority {
				addr = fmt.Sprintf("priority=%d", y.Priority)
			}
			rh, rc := runInterleaved(t, "resolved",
				func() *httptest.ResponseRecorder {
					w := httptest.NewRecorder()
					apiPolicyUpdate(w, heldReq("PUT", fmt.Sprintf("/api/policy?%s&ifVersion=%d", addr, ver),
						map[string]any{"name": "acc-il-y", "action": "Drop"}, "resolved"))
					return w
				},
				func() *httptest.ResponseRecorder { return accessReorderReq([]int{y.Priority, x.Priority}, ver) },
			)
			assertStatus(t, rc, 200)
			assertLoser(t, rh, http.StatusConflict)
			assertVersionDelta(t, ver, 1)
			if got := policyStore.findByIDCopy(y.ID); got == nil || got.Action != ActionAllow {
				t.Fatalf("loser mutated the rulebase: %+v", got)
			}
			assertNoLoserAudit(t, "policy.update", since)
		})
	}
}

func TestFenceInterleave_AccessCreate_VsSameNameCreate(t *testing.T) {
	for _, stage := range []string{"resolved", "fence"} {
		t.Run(stage, func(t *testing.T) {
			draftTestSetup(t)
			createAccessRuleAt(t, "acc-il-existing", 0)
			ver, _ := policyStore.policyVersion()
			since := time.Now().UnixMilli()
			rh, rc := runInterleaved(t, stage,
				func() *httptest.ResponseRecorder {
					w := httptest.NewRecorder()
					apiPolicyCreate(w, heldReq("POST", "/api/policy", map[string]any{"name": "acc-il-dup", "action": "Allow"}, stage))
					return w
				},
				func() *httptest.ResponseRecorder { return createRuleViaAPI(t, "acc-il-dup", "") },
			)
			assertStatus(t, rc, 200)
			assertLoser(t, rh, http.StatusConflict)
			if n := ilCountRulesNamed("acc-il-dup"); n != 1 {
				t.Fatalf("%d rules named acc-il-dup, want exactly 1", n)
			}
			assertVersionDelta(t, ver, 1)
			assertNoLoserAudit(t, "policy.add", since)
		})
	}
}

// An unasserted access reorder whose competitor adds a rule first: the list
// no longer covers the access set at the authoritative moment, so the reorder
// is a state conflict (409), never a silently applied stale permutation.
func TestFenceInterleave_AccessReorder_VsCreate_LoserIs409(t *testing.T) {
	draftTestSetup(t)
	x := createAccessRuleAt(t, "acc-il-x", 0)
	y := createAccessRuleAt(t, "acc-il-y", 0)
	ver, _ := policyStore.policyVersion()
	since := time.Now().UnixMilli()
	rh, rc := runInterleaved(t, "fence",
		func() *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			apiPolicyReorder(w, heldReq("POST", "/api/policy/reorder", map[string]any{"priorities": []int{y.Priority, x.Priority}}, "fence"))
			return w
		},
		func() *httptest.ResponseRecorder { return createRuleViaAPI(t, "acc-il-z", "") },
	)
	assertStatus(t, rc, 200)
	assertLoser(t, rh, http.StatusConflict)
	assertVersionDelta(t, ver, 1)
	if px, py := policyStore.findByIDCopy(x.ID).Priority, policyStore.findByIDCopy(y.ID).Priority; px != x.Priority || py != y.Priority {
		t.Fatalf("loser permuted the rulebase: x %d→%d y %d→%d", x.Priority, px, y.Priority, py)
	}
	assertNoLoserAudit(t, "policy.reorder", since)
}

// The privilege boundary: an operator-level bulk delete addresses a priority
// that, by the authoritative moment, belongs to an admin-managed AUTH rule
// (the access rule was deleted and an auth rule took the freed slot). The
// pre-fence guard cannot see that; pre-fix the auth rule is deleted through
// the operator endpoint.
func TestFenceInterleave_AccessBulkDelete_VsAuthTakeover_RefusesEscalation(t *testing.T) {
	draftTestSetup(t)
	x := createAccessRuleAt(t, "acc-il-x", 50)
	ver, _ := policyStore.policyVersion()
	since := time.Now().UnixMilli()
	rh, rc := runInterleaved(t, "fence",
		func() *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			apiPolicyDelete(w, heldReq("DELETE", "/api/policy", map[string]any{"priorities": []int{50}}, "fence"))
			return w
		},
		func() *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			apiPolicyDelete(w, jsonReq("DELETE", fmt.Sprintf("/api/policy?id=%s", x.ID), nil))
			if w.Code != http.StatusNoContent {
				t.Fatalf("competitor delete = %d", w.Code)
			}
			w2 := httptest.NewRecorder()
			body := authRuleBody("auth-il-takeover", "auth-il-takeover.test")
			body["priority"] = 50
			apiAuthPolicyCreate(w2, jsonReq("POST", "/api/authpolicy", body))
			if auth := ruleByName("auth-il-takeover"); w2.Code != 200 || auth == nil || auth.Priority != 50 {
				t.Fatalf("test premise: auth rule must occupy priority 50 before the held delete resumes (status %d, rule %+v)", w2.Code, auth)
			}
			return w2
		},
	)
	assertStatus(t, rc, 200)
	if auth := ruleByName("auth-il-takeover"); auth == nil {
		t.Fatal("the operator-level bulk delete removed an admin-managed AUTH rule (privilege escalation through a stale pre-fence guard)")
	}
	assertLoser(t, rh, http.StatusConflict, http.StatusNotFound)
	assertVersionDelta(t, ver, 2)
	assertNoLoserAudit(t, "policy.bulk_remove", since)
}

// An unasserted, PRIORITY-addressed move ("the rule at 10 after R3") whose
// competitor reorders first: priority addressing cannot carry identity intent
// across a reorder (priority 10 is now a different rule), so the move must be
// resolved against the authoritative order and REFUSED when the relation no
// longer resolves (404: the addressed identity is gone / 409: state conflict)
// — never a permutation computed on the stale order and applied over the new
// one, which is what pre-fix produced (200, with R1 landing elsewhere).
func TestFenceInterleave_AccessMove_VsReorder_HonoursIntent(t *testing.T) {
	draftTestSetup(t)
	createAccessRuleAt(t, "R1", 10)
	createAccessRuleAt(t, "R2", 20)
	createAccessRuleAt(t, "R3", 30)
	ver, _ := policyStore.policyVersion()
	rh, rc := runInterleaved(t, "fence",
		func() *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			apiPolicyMove(w, heldReq("POST", "/api/policy/move", map[string]any{"priority": 10, "position": "after", "targetName": "R3"}, "fence"))
			return w
		},
		func() *httptest.ResponseRecorder { return accessReorderReq([]int{30, 20, 10}, ver) },
	)
	assertStatus(t, rc, 200)
	order := []string{}
	for _, r := range policyStore.List() {
		order = append(order, r.Name)
	}
	if rh.Code == 200 {
		// Only acceptable if the relation actually holds against the
		// authoritative order (R1 immediately after R3).
		if strings.Join(order, ",") != "R3,R1,R2" {
			t.Fatalf("move returned 200 but did not honour 'after R3' against the authoritative order: %v", order)
		}
		assertVersionDelta(t, ver, 2)
		return
	}
	assertLoser(t, rh, http.StatusNotFound, http.StatusConflict)
	if strings.Join(order, ",") != "R3,R2,R1" {
		t.Fatalf("refused move must leave the winner's order intact, got %v", order)
	}
	assertVersionDelta(t, ver, 1)
}

// Control (already fenced): two unasserted deletes of the same id — the loser
// finds its target gone inside the fence and gets 404.
func TestFenceInterleave_AccessDeleteByID_VsSameDelete_LoserIs404(t *testing.T) {
	draftTestSetup(t)
	x := createAccessRuleAt(t, "acc-il-x", 0)
	ver, _ := policyStore.policyVersion()
	since := time.Now().UnixMilli()
	rh, rc := runInterleaved(t, "fence",
		func() *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			apiPolicyDelete(w, heldReq("DELETE", fmt.Sprintf("/api/policy?id=%s", x.ID), nil, "fence"))
			return w
		},
		func() *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			apiPolicyDelete(w, jsonReq("DELETE", fmt.Sprintf("/api/policy?id=%s", x.ID), nil))
			return w
		},
	)
	assertStatus(t, rc, http.StatusNoContent)
	assertLoser(t, rh, http.StatusNotFound)
	assertVersionDelta(t, ver, 1)
	assertNoLoserAudit(t, "policy.remove", since)
}
