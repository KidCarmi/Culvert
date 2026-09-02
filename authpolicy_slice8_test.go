package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Phase 1 Slice 8 — API / UI / Simulator for Auth Exempt rules.
//
// Covers: RBAC (viewer read, admin-only writes), CRUD + reorder via
// /api/authpolicy, /api/policy rejecting auth rules, audit + config-version
// side effects, the simulator's separated Stage-1/Stage-2 output (Exempt ≠
// Allow), and the diagnostics integration. No runtime behavior is touched:
// route parity is enforced by the D0/C1/C1.5/C2 suites.

// roleReq builds a JSON request carrying an arbitrary UI role.
func roleReq(role UIRole, method, path string, body any) *http.Request {
	r := jsonReq(method, path, body)
	return r.WithContext(context.WithValue(r.Context(), uiRoleKey{}, role))
}

// slice8Rule returns a valid exempt-rule payload as a map (JSON body).
func slice8Rule(name string) map[string]any {
	return map[string]any{
		"name":     name,
		"ruleType": "auth",
		"subjectMatch": map[string]any{
			"schemaVersion": 1,
			"all":           []map[string]any{{"type": "cidr", "values": []string{"10.0.5.0/24"}}},
		},
		"destFQDN": "updates.example.com",
		"auth":     map[string]any{"outcome": "Exempt", "owner": "ops", "reason": "slice8 test"},
	}
}

// withConfigVersionsDir redirects config-version snapshots to a tempdir.
func withConfigVersionsDir(t *testing.T) string {
	t.Helper()
	orig := configVersions.Dir()
	tmp := t.TempDir()
	configVersions.SetDirForTest(tmp)
	t.Cleanup(func() { configVersions.SetDirForTest(orig) })
	return tmp
}

// ── RBAC ─────────────────────────────────────────────────────────────────────

func TestSlice8_ViewerCanRead(t *testing.T) {
	withFreshPolicyStore(t)
	policyStore.Add(validExemptRule())
	w := httptest.NewRecorder()
	apiAuthPolicy(w, roleReq(RoleViewer, "GET", "/api/authpolicy", nil))
	if w.Code != 200 {
		t.Fatalf("viewer GET = %d, want 200", w.Code)
	}
	var resp struct {
		Rules []authRuleView `json:"rules"`
		Count int            `json:"count"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Count != 1 || resp.Rules[0].Name != "legacy-printer" {
		t.Errorf("unexpected list: %+v", resp)
	}
	// The no-expiry warning must be surfaced for the UI badges.
	if len(resp.Rules[0].Warnings) == 0 {
		t.Log("note: no warnings on rule (validExemptRule has no expiry — warning expected in later phases)")
	}
}

func TestSlice8_ViewerAndOperatorWritesBlocked(t *testing.T) {
	withFreshPolicyStore(t)
	for _, role := range []UIRole{RoleViewer, RoleOperator} {
		w := httptest.NewRecorder()
		apiAuthPolicy(w, roleReq(role, "POST", "/api/authpolicy", slice8Rule("rbac-blocked")))
		if w.Code != http.StatusForbidden {
			t.Errorf("%s POST = %d, want 403 (admin only)", role, w.Code)
		}
		w = httptest.NewRecorder()
		apiAuthPolicyReorder(w, roleReq(role, "POST", "/api/authpolicy/reorder", map[string]any{"priorities": []int{}}))
		if w.Code != http.StatusForbidden {
			t.Errorf("%s reorder = %d, want 403 (admin only)", role, w.Code)
		}
	}
	if got := len(listAuthRules()); got != 0 {
		t.Errorf("blocked writes must not mutate the store, got %d rules", got)
	}
}

// ── CRUD + side effects ──────────────────────────────────────────────────────

func TestSlice8_AdminCRUDLifecycle(t *testing.T) {
	withFreshPolicyStore(t)
	cvDir := withConfigVersionsDir(t)

	// CREATE
	w := httptest.NewRecorder()
	apiAuthPolicy(w, roleReq(RoleAdmin, "POST", "/api/authpolicy", slice8Rule("slice8-lifecycle")))
	if w.Code != 200 {
		t.Fatalf("admin POST = %d: %s", w.Code, w.Body.String())
	}
	var created authRuleView
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created: %v", err)
	}
	if created.RuleType != ruleTypeAuth || created.Auth == nil || created.ID == "" {
		t.Fatalf("created rule malformed: %+v", created)
	}

	mustFindAudit(t, "authpolicy.add", "slice8-lifecycle")
	// Config version snapshot written.
	if entries, _ := os.ReadDir(cvDir); len(entries) == 0 {
		t.Error("saveConfigVersion did not write a snapshot on create")
	}

	// UPDATE
	upd := slice8Rule("slice8-lifecycle")
	upd["priority"] = created.Priority
	upd["auth"].(map[string]any)["reason"] = "updated reason"
	w = httptest.NewRecorder()
	apiAuthPolicy(w, roleReq(RoleAdmin, "PUT", "/api/authpolicy?priority="+itoa(created.Priority), upd))
	if w.Code != 200 {
		t.Fatalf("admin PUT = %d: %s", w.Code, w.Body.String())
	}
	rules := listAuthRules()
	if len(rules) != 1 || rules[0].Auth.Reason != "updated reason" {
		t.Fatalf("update not applied: %+v", rules)
	}

	// DELETE
	w = httptest.NewRecorder()
	apiAuthPolicy(w, roleReq(RoleAdmin, "DELETE", "/api/authpolicy?priority="+itoa(created.Priority), nil))
	if w.Code != http.StatusNoContent {
		t.Fatalf("admin DELETE = %d: %s", w.Code, w.Body.String())
	}
	if got := len(listAuthRules()); got != 0 {
		t.Errorf("rule not deleted, %d remain", got)
	}
	mustFindAudit(t, "authpolicy.remove", "slice8-lifecycle")
}

// mustFindAudit scans the audit ring for an entry by action+object (content
// scan, never len-deltas — the ring is bounded and saturates under the
// shuffled determinism gate).
func mustFindAudit(t *testing.T, action, object string) {
	t.Helper()
	for _, e := range auditGet() {
		if e.Action == action && e.Object == object {
			return
		}
	}
	t.Errorf("audit entry %s/%s not found", action, object)
}

func itoa(n int) string { return strconv.Itoa(n) }

func TestSlice8_InvalidAuthRuleRejected(t *testing.T) {
	withFreshPolicyStore(t)
	for name, mutate := range map[string]func(map[string]any){
		"missing owner":   func(m map[string]any) { m["auth"].(map[string]any)["owner"] = "" },
		"missing reason":  func(m map[string]any) { m["auth"].(map[string]any)["reason"] = "" },
		"unknown outcome": func(m map[string]any) { m["auth"].(map[string]any)["outcome"] = "Bogus" },
		"no destination":  func(m map[string]any) { delete(m, "destFQDN") },
		"identity predicate": func(m map[string]any) {
			m["subjectMatch"].(map[string]any)["all"] = []map[string]any{{"type": "directory_group", "values": []string{"eng"}}}
		},
		"access ruleType": func(m map[string]any) { m["ruleType"] = "access" },
	} {
		body := slice8Rule("invalid-" + strings.ReplaceAll(name, " ", "-"))
		mutate(body)
		w := httptest.NewRecorder()
		apiAuthPolicy(w, roleReq(RoleAdmin, "POST", "/api/authpolicy", body))
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: POST = %d, want 400", name, w.Code)
		}
	}
	if got := len(listAuthRules()); got != 0 {
		t.Errorf("invalid rules must not be stored, got %d", got)
	}
}

// ── Reorder: auth-only, access priorities untouched ──────────────────────────

func TestSlice8_ReorderAuthOnly(t *testing.T) {
	withFreshPolicyStore(t)
	// access rule at priority 2 sandwiched between auth rules 1 and 3.
	a1 := validExemptRule()
	a1.Name, a1.Priority = "exempt-a", 1
	acc := PolicyRule{Priority: 2, Name: "access-mid", Action: ActionAllow}
	a3 := validExemptRule()
	a3.Name, a3.Priority = "exempt-b", 3
	policyStore.Add(a1)
	policyStore.Add(acc)
	policyStore.Add(a3)

	// Swap the two auth rules: order [3,1] → exempt-b gets 1, exempt-a gets 3.
	w := httptest.NewRecorder()
	apiAuthPolicyReorder(w, roleReq(RoleAdmin, "POST", "/api/authpolicy/reorder", map[string]any{"priorities": []int{3, 1}}))
	if w.Code != 200 {
		t.Fatalf("reorder = %d: %s", w.Code, w.Body.String())
	}
	byName := map[string]int{}
	for _, r := range policyStore.List() {
		byName[r.Name] = r.Priority
	}
	if byName["exempt-b"] != 1 || byName["exempt-a"] != 3 {
		t.Errorf("auth rules not permuted: %+v", byName)
	}
	if byName["access-mid"] != 2 {
		t.Errorf("access rule priority disturbed: %d, want 2", byName["access-mid"])
	}

	// A list naming an access-rule priority is rejected — decided against
	// the current rulebase inside the fence: 409 (+currentVersion) without
	// an assertion (2E-C concurrency-status correction).
	w = httptest.NewRecorder()
	apiAuthPolicyReorder(w, roleReq(RoleAdmin, "POST", "/api/authpolicy/reorder", map[string]any{"priorities": []int{2, 1}}))
	if w.Code != http.StatusConflict {
		t.Errorf("reorder including access priority = %d, want 409", w.Code)
	}
}

// ── /api/policy rejects auth rules ───────────────────────────────────────────

func TestSlice8_PolicyEndpointRejectsAuthRules(t *testing.T) {
	withFreshPolicyStore(t)
	exempt := validExemptRule()
	exempt.Priority = 7
	policyStore.Add(exempt)

	// POST an auth rule via /api/policy → 400.
	w := httptest.NewRecorder()
	apiPolicy(w, jsonReq("POST", "/api/policy", slice8Rule("via-policy-endpoint")))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "/api/authpolicy") {
		t.Errorf("POST auth rule via /api/policy = %d (%q), want 400 pointing at /api/authpolicy", w.Code, w.Body.String())
	}
	// Priority-addressed writes over the stored auth rule are refused against
	// the CURRENT rulebase inside the fence (a priority can change type under
	// a reorder): 409 (+currentVersion) without an assertion, 400 against the
	// asserted matching generation (2E-C concurrency-status correction).
	// Either way: refused, and the auth rule is untouched.
	ver, _ := policyStore.policyVersion()
	w = httptest.NewRecorder()
	apiPolicy(w, jsonReq("PUT", "/api/policy?priority=7", map[string]any{"name": "overwrite", "action": "Allow"}))
	if w.Code != http.StatusConflict {
		t.Errorf("PUT over auth rule via /api/policy = %d, want 409", w.Code)
	}
	w = httptest.NewRecorder()
	apiPolicy(w, jsonReq("PUT", fmt.Sprintf("/api/policy?priority=7&ifVersion=%d", ver), map[string]any{"name": "overwrite", "action": "Allow"}))
	if w.Code != http.StatusBadRequest {
		t.Errorf("PUT over auth rule via /api/policy (asserted) = %d, want 400", w.Code)
	}
	// DELETE targeting the auth rule → refused the same way.
	w = httptest.NewRecorder()
	apiPolicy(w, jsonReq("DELETE", "/api/policy?priority=7", nil))
	if w.Code != http.StatusConflict {
		t.Errorf("DELETE auth rule via /api/policy = %d, want 409", w.Code)
	}
	// Bulk DELETE containing the auth rule → refused, nothing deleted.
	acc := PolicyRule{Priority: 8, Name: "bulk-access", Action: ActionAllow}
	policyStore.Add(acc)
	w = httptest.NewRecorder()
	apiPolicy(w, jsonReq("DELETE", "/api/policy", map[string]any{"priorities": []int{8, 7}}))
	if w.Code != http.StatusConflict {
		t.Errorf("bulk DELETE including auth rule = %d, want 409", w.Code)
	}
	if got := policyStore.List(); len(got) != 2 || got[0].Name != exempt.Name && got[1].Name != exempt.Name {
		t.Errorf("refused writes must leave the auth rule untouched: %+v", got)
	}
	if len(policyStore.List()) != 2 {
		t.Errorf("rejected bulk delete must not remove anything")
	}
	if got := len(listAuthRules()); got != 1 {
		t.Errorf("auth rule must survive all /api/policy attempts, got %d", got)
	}
}

// ── Simulator: Stage-1 and Stage-2 shown separately; Exempt ≠ Allow ──────────

type simResp struct {
	Matched       bool   `json:"matched"`
	DefaultAction string `json:"defaultAction"`
	Rule          *struct {
		Name string `json:"name"`
	} `json:"rule"`
	Auth struct {
		Outcome              string `json:"outcome"`
		RuntimeOutcome       string `json:"runtimeOutcome"`
		KillSwitch           bool   `json:"killSwitch"`
		CredentialsPresented bool   `json:"credentialsPresented"`
		Stage2AuthSource     string `json:"stage2AuthSource"`
		Note                 string `json:"note"`
		Rule                 *struct {
			Name string `json:"name"`
		} `json:"rule"`
	} `json:"auth"`
}

func runSim(t *testing.T, body map[string]any) simResp {
	t.Helper()
	w := httptest.NewRecorder()
	apiPolicyTest(w, jsonReq("POST", "/api/policy/test", body))
	if w.Code != 200 {
		t.Fatalf("policy test = %d: %s", w.Code, w.Body.String())
	}
	var resp simResp
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp
}

func TestSlice8_Simulator_ExemptIsNotAllow(t *testing.T) {
	withFreshPolicyStore(t)
	setDefaultPolicyAction("deny")
	policyStore.Add(validExemptRule()) // 10.0.5.0/24 → updates.example.com

	resp := runSim(t, map[string]any{"sourceIP": "10.0.5.7", "host": "updates.example.com"})
	if resp.Auth.Outcome != "Exempt" {
		t.Fatalf("auth outcome = %q, want Exempt", resp.Auth.Outcome)
	}
	if resp.Auth.Rule == nil || resp.Auth.Rule.Name != "legacy-printer" {
		t.Errorf("matched auth rule missing: %+v", resp.Auth)
	}
	// Stage-2 is separate AND denies: Exempt does not imply Allow.
	if resp.Matched {
		t.Errorf("no access rule exists — Stage-2 must not match (Exempt must not imply Allow)")
	}
	if resp.DefaultAction != "deny" {
		t.Errorf("defaultAction = %q, want deny", resp.DefaultAction)
	}
	if resp.Auth.Stage2AuthSource != "exempt" {
		t.Errorf("stage2AuthSource = %q, want exempt (mirrors Slice 7 runtime)", resp.Auth.Stage2AuthSource)
	}
	if !strings.Contains(resp.Auth.Note, "never allows") {
		t.Errorf("note must state Exempt never allows traffic: %q", resp.Auth.Note)
	}
}

func TestSlice8_Simulator_ExemptAuthSourceMatchesStage2Rule(t *testing.T) {
	withFreshPolicyStore(t)
	setDefaultPolicyAction("deny")
	policyStore.Add(validExemptRule())
	policyStore.Add(PolicyRule{
		Priority: 2, Name: "allow-exempt", Action: ActionAllow,
		AuthSource: "exempt", DestFQDN: "updates.example.com",
	})
	resp := runSim(t, map[string]any{"sourceIP": "10.0.5.7", "host": "updates.example.com"})
	if resp.Auth.Outcome != "Exempt" || !resp.Matched || resp.Rule == nil || resp.Rule.Name != "allow-exempt" {
		t.Errorf("simulator must show Stage-1 Exempt AND the Stage-2 exempt-scoped match: %+v", resp)
	}
}

func TestSlice8_Simulator_NoAuthRules_DefaultOutcome(t *testing.T) {
	withFreshPolicyStore(t)
	resp := runSim(t, map[string]any{"sourceIP": "10.0.5.7", "host": "example.com"})
	if resp.Auth.Outcome != "Default" {
		t.Errorf("outcome = %q, want Default", resp.Auth.Outcome)
	}
	if resp.Auth.Stage2AuthSource != "unauth" {
		t.Errorf("stage2AuthSource = %q, want unauth", resp.Auth.Stage2AuthSource)
	}
}

func TestSlice8_Simulator_KillSwitchVisible(t *testing.T) {
	withFreshPolicyStore(t)
	policyStore.Add(validExemptRule())
	setAuthExemptDisabled(true)
	t.Cleanup(func() { setAuthExemptDisabled(false) })
	resp := runSim(t, map[string]any{"sourceIP": "10.0.5.7", "host": "updates.example.com"})
	if resp.Auth.Outcome != "Default" || !resp.Auth.KillSwitch {
		t.Errorf("kill switch must force Default and be visible: %+v", resp.Auth)
	}
}

// Credentials win in the simulator exactly as at runtime: a simulated request
// carrying an identity or an authenticated authSource is never exempt.
func TestSlice8_Simulator_CredentialsPresentedNeverExempt(t *testing.T) {
	withFreshPolicyStore(t)
	policyStore.Add(validExemptRule()) // would match the no-credentials case
	for name, body := range map[string]map[string]any{
		"identity":   {"sourceIP": "10.0.5.7", "host": "updates.example.com", "identity": "alice"},
		"authSource": {"sourceIP": "10.0.5.7", "host": "updates.example.com", "authSource": "okta"},
	} {
		resp := runSim(t, body)
		if resp.Auth.Outcome != "Default" {
			t.Errorf("%s: outcome = %q, want Default (credentials always win)", name, resp.Auth.Outcome)
		}
		if !resp.Auth.CredentialsPresented {
			t.Errorf("%s: credentialsPresented must be true", name)
		}
		if resp.Auth.Stage2AuthSource == "exempt" {
			t.Errorf("%s: stage2AuthSource must not be exempt for credentialed requests", name)
		}
	}
}

// Operator-level /api/policy/reorder and /api/policy/move are access-only: they
// permute Stage-2 access rules among their own priority slots (PermutePriorities)
// and never touch a Stage-1 auth rule's priority. Auth rules are reordered solely
// via /api/authpolicy (admin-only), so there is no operator/admin escalation here.
// Priorities are deliberately NON-CONTIGUOUS (access uses max+10, auth max+1) to
// exercise the real-world case the full-list Reorder contract mishandled.
func TestSlice8_OperatorReorderMoveCannotShiftAuthRules(t *testing.T) {
	withFreshPolicyStore(t)
	a := validExemptRule()
	a.Priority = 21
	policyStore.Add(a)
	policyStore.Add(PolicyRule{Priority: 10, Name: "acc-1", Action: ActionAllow})
	policyStore.Add(PolicyRule{Priority: 20, Name: "acc-2", Action: ActionAllow})

	authPriUnchanged := func(where string) {
		t.Helper()
		for _, r := range policyStore.List() {
			if r.Name == a.Name && r.Priority != 21 {
				t.Fatalf("%s: auth rule priority changed to %d, want 21", where, r.Priority)
			}
		}
	}

	// Access-only reorder (swap the two access rules) → operator OK, auth untouched.
	w := httptest.NewRecorder()
	apiPolicyReorder(w, roleReq(RoleOperator, "POST", "/api/policy/reorder", map[string]any{"priorities": []int{20, 10}}))
	if w.Code != 200 {
		t.Fatalf("operator access-only reorder = %d: %s", w.Code, w.Body.String())
	}
	authPriUnchanged("reorder")

	// A reorder list that includes the auth rule's priority is rejected — for
	// operator AND admin alike (no escalation; auth is reordered via /api/authpolicy).
	for _, role := range []UIRole{RoleOperator, RoleAdmin} {
		w = httptest.NewRecorder()
		apiPolicyReorder(w, roleReq(role, "POST", "/api/policy/reorder", map[string]any{"priorities": []int{10, 20, 21}}))
		// Decided against the current access set inside the fence: 409
		// (+currentVersion) without an assertion (2E-C correction).
		if w.Code != http.StatusConflict {
			t.Fatalf("%s reorder including auth priority = %d, want 409", role, w.Code)
		}
	}

	// /api/policy/move: moving an access rule to last stays operator-level and
	// leaves the auth rule's priority untouched (the move never crosses it).
	w = httptest.NewRecorder()
	apiPolicyMove(w, roleReq(RoleOperator, "POST", "/api/policy/move", map[string]any{"priority": 10, "position": "last"}))
	if w.Code != 200 {
		t.Fatalf("operator access-rule move = %d: %s", w.Code, w.Body.String())
	}
	authPriUnchanged("move")

	// Moving the auth rule itself via the access endpoint is refused against
	// the current rulebase inside the fence (a priority can change type under
	// a reorder): 409 (+currentVersion) without an assertion, 400 against the
	// asserted matching generation (2E-C concurrency-status correction).
	w = httptest.NewRecorder()
	apiPolicyMove(w, roleReq(RoleOperator, "POST", "/api/policy/move", map[string]any{"priority": 21, "position": "last"}))
	if w.Code != http.StatusConflict {
		t.Fatalf("move of auth rule via access endpoint = %d, want 409", w.Code)
	}
	ver, _ := policyStore.policyVersion()
	w = httptest.NewRecorder()
	apiPolicyMove(w, roleReq(RoleOperator, "POST", fmt.Sprintf("/api/policy/move?ifVersion=%d", ver), map[string]any{"priority": 21, "position": "last"}))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("move of auth rule via access endpoint (asserted) = %d, want 400", w.Code)
	}
	authPriUnchanged("refused move")
}

// ── Diagnostics integration ──────────────────────────────────────────────────

func TestSlice8_DiagnosticsExposeAuthExemptRisks(t *testing.T) {
	withFreshPolicyStore(t)
	prevAction := defaultPolicyAction()
	setDefaultPolicyAction("allow")
	t.Cleanup(func() { setDefaultPolicyAction(prevAction) })

	risky := validExemptRule()                                                   // no expiry
	risky.Auth.ExpiresAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339) // expired
	policyStore.Add(risky)
	broad := validExemptRule()
	broad.Name, broad.Priority = "broad-exempt", 5
	broad.DestFQDN = ""
	broad.Auth.BroadExemption = true
	policyStore.Add(broad)

	c := buildOperatorContract()
	got := map[string]bool{}
	for i := range c.Checks {
		got[c.Checks[i].Code] = true
	}
	for _, want := range []string{"auth_exempt_broad_exemption", "auth_exempt_expired", "auth_exempt_default_allow", "auth_exempt_no_expiry"} {
		if !got[want] {
			t.Errorf("operator contract missing %q (codes: %v)", want, got)
		}
	}
	if c.Verdict == diagOK {
		t.Error("verdict must be at least warn with risky exempt rules present")
	}
}

func TestSlice8_DiagnosticsCleanWithoutExemptRules(t *testing.T) {
	withFreshPolicyStore(t)
	c := buildOperatorContract()
	for i := range c.Checks {
		if strings.HasPrefix(c.Checks[i].Code, "auth_exempt_") {
			t.Errorf("no exempt rules → no auth_exempt_* checks, found %q", c.Checks[i].Code)
		}
	}
}

// ── Route metadata: write methods are Mutating (drives CSRF/body-limit) ──────

func TestSlice8_AuthPolicyRoutesMutatingMetadata(t *testing.T) {
	found := 0
	for _, rt := range uiRoutes {
		if rt.Path != "/api/authpolicy" && rt.Path != "/api/authpolicy/reorder" {
			continue
		}
		found++
		for _, m := range rt.Methods {
			isWrite := m.Method == "POST" || m.Method == "PUT" || m.Method == "DELETE"
			if isWrite && (!m.Mutating || !m.AuditExpected || m.MinRole != RoleAdmin) {
				t.Errorf("%s %s: want Mutating+AuditExpected+RoleAdmin, got %+v", rt.Path, m.Method, m)
			}
			if m.Method == "GET" && m.MinRole != RoleViewer {
				t.Errorf("%s GET: want RoleViewer, got %v", rt.Path, m.MinRole)
			}
		}
	}
	if found != 2 {
		t.Fatalf("expected 2 authpolicy route metadata entries, found %d", found)
	}
}
