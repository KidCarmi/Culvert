package main

// policy_category_validation_test.go — POL-005 (owner decision B): new and
// modified rules may not spell the reserved wildcard "Any" in another case and
// may not commit an unresolvable category reference; STORED rules keep loading
// and enforcing exactly as before and are reported instead (log line, gauge,
// diagnostics row). Never canonicalized: a stored "any" must not become the
// wildcard.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// pol005Setup isolates running + draft policy, catStore, category groups and
// the effective view, and disarms the unresolved-reference reporter.
func pol005Setup(t *testing.T) {
	t.Helper()
	draftTestSetup(t)
	snapshotCatStore(t)
	snapshotGlobalCategoryGroups(t)
	prevView := saasEffectiveView.Swap(nil)
	t.Cleanup(func() { saasEffectiveView.Swap(prevView) })
	pol005ResetReporter(t)
}

// pol005ResetReporter disarms the reporter and forgets what it logged, for
// this test and again on cleanup (it is process-global state main arms once).
func pol005ResetReporter(t *testing.T) {
	t.Helper()
	reset := func() {
		unresolvedRefReporter.mu.Lock()
		unresolvedRefReporter.armed = false
		unresolvedRefReporter.logged = nil
		unresolvedRefReporter.mu.Unlock()
	}
	reset()
	t.Cleanup(reset)
}

// pol005AuditMark records the audit entries already in the shared ring, so a
// later pol005AuditHas sees only entries written after the mark. Another test
// may legitimately audit the same action/object (the negative control below
// edits a pre-existing category named "Any"), and a millisecond TS cutoff can
// still collide with it, so "new" means "not present at the mark".
func pol005AuditMark() map[AuditEntry]struct{} {
	before := auditGet()
	seen := make(map[AuditEntry]struct{}, len(before))
	for i := range before {
		seen[before[i]] = struct{}{}
	}
	return seen
}

func pol005AuditHas(mark map[AuditEntry]struct{}, action, object string) bool {
	entries := auditGet()
	for i := range entries {
		if _, old := mark[entries[i]]; old {
			continue
		}
		if entries[i].Action == action && entries[i].Object == object {
			return true
		}
	}
	return false
}

func pol005WantReservedRefusal(t *testing.T, w *httptest.ResponseRecorder, value, what string) {
	t.Helper()
	if w.Code != http.StatusBadRequest {
		t.Fatalf("%s with destCategory %q: got %d (%s), want 400", what, value, w.Code, w.Body.String())
	}
	want := `destCategory "` + value + `" is not a category; use "Any" (exact) or omit destCategory for any destination`
	if !strings.Contains(w.Body.String(), want) {
		t.Fatalf("%s: body %q does not carry %q", what, w.Body.String(), want)
	}
}

// TestPOL005_ReservedAnyVariantRefusedOnEveryRuleDoor: "any"/"ANY"/"aNy" are
// refused on access-rule create, update by priority and update by ID, and on
// auth-rule create and update; the refused write mutates nothing and audits
// nothing; exact "Any" is accepted.
func TestPOL005_ReservedAnyVariantRefusedOnEveryRuleDoor(t *testing.T) {
	pol005Setup(t)
	catStore.ReplaceAll([]CategoryEntry{{Name: "pol005-cat", Hosts: []string{"pol005.example"}}})

	// Exact "Any" is the wildcard and stays accepted.
	w := httptest.NewRecorder()
	apiPolicyCreate(w, jsonReq("POST", "/api/policy", map[string]any{"name": "pol005-exact", "action": "Drop", "destCategory": "Any"}))
	if w.Code != http.StatusOK {
		t.Fatalf(`exact "Any" must be accepted: %d %s`, w.Code, w.Body.String())
	}
	var seed PolicyRule
	if err := json.Unmarshal(w.Body.Bytes(), &seed); err != nil {
		t.Fatalf("decode created rule: %v", err)
	}
	authSeed := seedAuthRule(t, "pol005-auth-seed")
	mark := pol005AuditMark()

	for _, v := range []string{"any", "ANY", "aNy"} {
		t.Run(v, func(t *testing.T) {
			name := "pol005-create-" + v
			w := httptest.NewRecorder()
			apiPolicyCreate(w, jsonReq("POST", "/api/policy", map[string]any{"name": name, "action": "Drop", "destCategory": v}))
			pol005WantReservedRefusal(t, w, v, "access create")
			if pol005AuditHas(mark, "policy.add", name) {
				t.Fatalf("refused create %q was audited", name)
			}

			w = httptest.NewRecorder()
			apiPolicyUpdate(w, jsonReq("PUT", "/api/policy?priority="+int64ToStr(int64(seed.Priority)),
				map[string]any{"name": seed.Name, "action": "Drop", "destCategory": v}))
			pol005WantReservedRefusal(t, w, v, "access update ?priority=")

			w = httptest.NewRecorder()
			apiPolicyUpdate(w, jsonReq("PUT", "/api/policy?id="+seed.ID,
				map[string]any{"name": seed.Name, "action": "Drop", "destCategory": v}))
			pol005WantReservedRefusal(t, w, v, "access update ?id=")

			body := authRuleBody("pol005-auth-"+v, "pol005-auth.test")
			body["destCategory"] = v
			w = httptest.NewRecorder()
			apiAuthPolicyCreate(w, jsonReq("POST", "/api/authpolicy", body))
			pol005WantReservedRefusal(t, w, v, "auth create")

			body = authRuleBody(authSeed.Name, "pol005-auth.test")
			body["destCategory"] = v
			w = httptest.NewRecorder()
			apiAuthPolicyUpdate(w, jsonReq("PUT", "/api/authpolicy?id="+authSeed.ID, body))
			pol005WantReservedRefusal(t, w, v, "auth update ?id=")
		})
	}

	for _, r := range policyStore.List() {
		if strings.EqualFold(string(r.DestCategory), "any") && r.DestCategory != CategoryAny {
			t.Fatalf("a refused write left rule %q with destCategory %q", r.Name, r.DestCategory)
		}
		if strings.HasPrefix(r.Name, "pol005-create-") || strings.HasPrefix(r.Name, "pol005-auth-a") {
			t.Fatalf("a refused create landed: %q", r.Name)
		}
	}
}

// TestPOL005_ReservedCategoryNameRefusedAtCreation: creating a category whose
// name case-folds to "Any" is refused on the legacy POST, the fenced v2 POST
// and the upserting legacy PUT; an ordinary name is unaffected.
func TestPOL005_ReservedCategoryNameRefusedAtCreation(t *testing.T) {
	pol005Setup(t)
	snapshotConfigVersionsDir(t)
	mark := pol005AuditMark()

	for _, name := range []string{"aNy", "ANY", "Any", "any"} {
		w := httptest.NewRecorder()
		apiURLCat(w, jsonReq("POST", "/api/urlcat", map[string]any{"name": name, "hosts": []string{"x.example"}}))
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "is reserved") {
			t.Fatalf("POST category %q: got %d %q, want 400 reserved", name, w.Code, w.Body.String())
		}
		w = httptest.NewRecorder()
		apiURLCat(w, jsonReq("POST", "/api/urlcat?ifRevision="+catStore.ContentFingerprint(),
			map[string]any{"name": name, "hosts": []string{"x.example"}}))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("v2 POST category %q: got %d %q, want 400", name, w.Code, w.Body.String())
		}
		w = httptest.NewRecorder()
		apiURLCat(w, jsonReq("PUT", "/api/urlcat?name="+name, map[string]any{"hosts": []string{"x.example"}}))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("legacy PUT (upsert) category %q: got %d %q, want 400", name, w.Code, w.Body.String())
		}
		if _, found := catStore.BuiltInFlag(name); found {
			t.Fatalf("a refused request created category %q", name)
		}
		if pol005AuditHas(mark, "urlcat.create", name) || pol005AuditHas(mark, "urlcat.update", name) {
			t.Fatalf("refused category write %q was audited", name)
		}
	}

	w := httptest.NewRecorder()
	apiURLCat(w, jsonReq("POST", "/api/urlcat", map[string]any{"name": "pol005-anything", "hosts": []string{"y.example"}}))
	if w.Code != http.StatusOK {
		t.Fatalf("an ordinary category name must still be accepted: %d %s", w.Code, w.Body.String())
	}
}

// TestPOL005_PreexistingAnyCategoryKeepsTodaysBehaviour is the negative
// control: an admin category named "Any" that predates the reserved-name check
// stays editable and deletable, a STORED rule spelled "any" keeps matching
// that category's hosts (it is a category reference, not the wildcard), exact
// "Any" stays the wildcard, and a NEW "any" write is still refused.
func TestPOL005_PreexistingAnyCategoryKeepsTodaysBehaviour(t *testing.T) {
	pol005Setup(t)
	snapshotConfigVersionsDir(t)
	catStore.ReplaceAll([]CategoryEntry{{Name: "Any", Hosts: []string{"anycat.example"}}})
	policyStore.ReplaceAll([]PolicyRule{
		{Priority: 1, Name: "stored-lower-any", Action: ActionDrop, DestCategory: "any"},
	})

	if m := policyStore.Evaluate("10.0.0.1", "", "unauth", "anycat.example", nil); m == nil || m.Rule.Name != "stored-lower-any" || m.Action != ActionDrop {
		t.Fatalf(`stored "any" must keep matching the admin category named Any: %+v`, m)
	}
	if m := policyStore.Evaluate("10.0.0.1", "", "unauth", "elsewhere.example", nil); m != nil {
		t.Fatalf(`stored "any" must NOT act as the wildcard: matched %q`, m.Rule.Name)
	}

	w := httptest.NewRecorder()
	apiURLCat(w, jsonReq("PUT", "/api/urlcat?name=Any", map[string]any{"hosts": []string{"anycat.example", "anycat2.example"}}))
	if w.Code != http.StatusOK {
		t.Fatalf("an existing Any category must stay editable: %d %s", w.Code, w.Body.String())
	}
	if m := policyStore.Evaluate("10.0.0.1", "", "unauth", "anycat2.example", nil); m == nil || m.Rule.Name != "stored-lower-any" {
		t.Fatalf("stored rule must follow the edited category: %+v", m)
	}

	w = httptest.NewRecorder()
	apiPolicyCreate(w, jsonReq("POST", "/api/policy", map[string]any{"name": "pol005-new-any", "action": "Drop", "destCategory": "any"}))
	pol005WantReservedRefusal(t, w, "any", "create while an Any category exists")

	// Exact "Any" stays the wildcard even with a category of that name.
	policyStore.ReplaceAll([]PolicyRule{{Priority: 1, Name: "exact-any", Action: ActionDrop, DestCategory: CategoryAny}})
	if m := policyStore.Evaluate("10.0.0.1", "", "unauth", "elsewhere.example", nil); m == nil || m.Rule.Name != "exact-any" {
		t.Fatalf(`exact "Any" must stay the wildcard: %+v`, m)
	}

	policyStore.ReplaceAll(nil)
	w = httptest.NewRecorder()
	apiURLCat(w, jsonReq("DELETE", "/api/urlcat?name=Any", nil))
	if w.Code/100 != 2 {
		t.Fatalf("an existing Any category must stay deletable: %d %s", w.Code, w.Body.String())
	}
}

// TestPOL005_StoredAnyNeverBecomesTheWildcard: a stored "any" with no category
// of that name loads verbatim, is never rewritten, matches no traffic, and is
// REPORTED as unresolved.
func TestPOL005_StoredAnyNeverBecomesTheWildcard(t *testing.T) {
	pol005Setup(t)
	path := filepath.Join(t.TempDir(), "policy.json")
	raw := `[{"priority":1,"name":"stored-any-drop","action":"Drop","destCategory":"any"}]`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := policyStore.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	rules := policyStore.List()
	if len(rules) != 1 || rules[0].DestCategory != "any" {
		t.Fatalf(`stored "any" must load verbatim, got %+v`, rules)
	}
	for _, host := range []string{"example.com", "www.facebook.com", "anything.test"} {
		if m := policyStore.Evaluate("10.0.0.1", "", "unauth", host, nil); m != nil {
			t.Fatalf(`stored "any" Drop matched %s as a wildcard (rule %q)`, host, m.Rule.Name)
		}
	}
	refs := unresolvedCategoryRefs(policyStore.List())
	if len(refs) != 1 || refs[0].Name != "any" || refs[0].Type != unresolvedRefCategory {
		t.Fatalf(`stored "any" must be reported unresolved, got %+v`, refs)
	}
	if rules = policyStore.List(); rules[0].DestCategory != "any" {
		t.Fatalf("reporting rewrote the stored value to %q", rules[0].DestCategory)
	}
}

// TestPOL005_StoredDanglingRuleReportedAfterCategoriesLoad: a stored rule with
// a dangling category loads unchanged; no warning is logged until the
// reporter is armed (which main does after initURLCategories); then exactly
// one line, the gauge reads 1, the diagnostics row warns; restoring the
// category clears gauge and row without a restart.
func TestPOL005_StoredDanglingRuleReportedAfterCategoriesLoad(t *testing.T) {
	pol005Setup(t)
	path := filepath.Join(t.TempDir(), "policy.json")
	raw := `[{"priority":1,"name":"stored-dangling","action":"Drop","destCategory":"late-cat"}]`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	const line = `Policy: rule "stored-dangling" references category "late-cat" which no current category authority resolves; it matches no traffic`

	out := captureLogger(t, func() {
		if err := policyStore.Load(path); err != nil {
			t.Fatalf("Load: %v", err)
		}
		reportUnresolvedCategoryRefs() // e.g. an early view install: disarmed
	})
	if strings.Contains(out, "no current category authority resolves") {
		t.Fatalf("warned before the category authorities loaded:\n%s", out)
	}
	if r := policyStore.List(); len(r) != 1 || r[0].DestCategory != "late-cat" || r[0].Action != ActionDrop {
		t.Fatalf("stored dangling rule must load unchanged, got %+v", r)
	}

	out = captureLogger(t, func() {
		armUnresolvedCategoryRefReporting()
		reportUnresolvedCategoryRefs() // a second check must not repeat the line
	})
	if strings.Count(out, line) != 1 {
		t.Fatalf("want the warning exactly once after arming, got:\n%s", out)
	}

	if got := pol005Metrics(t); !strings.Contains(got, `culvert_policy_rules_unresolved_refs{type="category"} 1`) ||
		!strings.Contains(got, `culvert_policy_rules_unresolved_refs{type="category_group"} 0`) ||
		!strings.Contains(got, "# TYPE culvert_policy_rules_unresolved_refs gauge") {
		t.Fatalf("gauge missing or wrong on /metrics")
	}
	row := pol005DiagRow(t)
	if row.Status != diagWarn || !strings.Contains(row.Message, `"stored-dangling" (category "late-cat")`) || row.OperatorAction == "" {
		t.Fatalf("diagnostics row must warn naming the rule: %+v", row)
	}

	catStore.ReplaceAll([]CategoryEntry{{Name: "late-cat", Hosts: []string{"late.example"}}})
	if got := pol005Metrics(t); !strings.Contains(got, `culvert_policy_rules_unresolved_refs{type="category"} 0`) {
		t.Fatal("gauge must clear once the category exists")
	}
	if row := pol005DiagRow(t); row.Status != diagOK {
		t.Fatalf("row must clear once the category exists: %+v", row)
	}
	if m := policyStore.Evaluate("10.0.0.1", "", "unauth", "late.example", nil); m == nil || m.Rule.Name != "stored-dangling" {
		t.Fatalf("the stored rule must start matching once its category exists: %+v", m)
	}
}

// TestPOL005_ViewTransitionReportsDriftedRule: a feed transition that drops a
// class a running rule references is reported by the Swap hook (once armed),
// and a dangling category GROUP is counted under its own label.
func TestPOL005_ViewTransitionReportsDriftedRule(t *testing.T) {
	pol005Setup(t)
	saasEffectiveView.Swap(newEffectiveView(map[string]string{"feed.example": "Feed-Class"},
		effectiveCategoryView{Source: sourceDownloaded, FeedVersion: 1}))
	policyStore.ReplaceAll([]PolicyRule{
		{Priority: 1, Name: "feed-drop", Action: ActionDrop, DestCategory: "Feed-Class"},
		{Priority: 2, Name: "group-drop", Action: ActionDrop, DestCategoryGroup: "gone-group"},
	})
	out := captureLogger(t, armUnresolvedCategoryRefReporting)
	if strings.Contains(out, `"feed-drop"`) {
		t.Fatalf("a resolvable reference was reported:\n%s", out)
	}
	if !strings.Contains(out, `Policy: rule "group-drop" references category group "gone-group" which no current category authority resolves`) {
		t.Fatalf("dangling group not reported:\n%s", out)
	}

	out = captureLogger(t, func() {
		saasEffectiveView.Swap(newEffectiveView(map[string]string{"other.example": "Other-Class"},
			effectiveCategoryView{Source: sourceDownloaded, FeedVersion: 2}))
	})
	if !strings.Contains(out, `Policy: rule "feed-drop" references category "Feed-Class" which no current category authority resolves; it matches no traffic`) {
		t.Fatalf("a feed transition that drops the class must report the rule:\n%s", out)
	}
	if strings.Contains(out, `"group-drop"`) {
		t.Fatalf("an already-reported reference was logged again:\n%s", out)
	}
	got := pol005Metrics(t)
	if !strings.Contains(got, `culvert_policy_rules_unresolved_refs{type="category"} 1`) ||
		!strings.Contains(got, `culvert_policy_rules_unresolved_refs{type="category_group"} 1`) {
		t.Fatal("gauge must count one category and one category_group rule")
	}
	if r := policyStore.List(); len(r) != 2 || r[0].DestCategory != "Feed-Class" {
		t.Fatalf("reporting must not touch the stored rules: %+v", r)
	}
}

// TestPOL005_DraftCommitRefusedAfterReferencedClassDisappears: a rule staged
// while its feed class was served is refused at commit once the class is gone
// (structured 400 naming the rule, nothing activated, draft retained); a
// RUNNING rule that drifted and the draft does not change does not block a
// commit.
func TestPOL005_DraftCommitRefusedAfterReferencedClassDisappears(t *testing.T) {
	pol005Setup(t)
	saasEffectiveView.Swap(newEffectiveView(map[string]string{"feed.example": "Feed-Class"},
		effectiveCategoryView{Source: sourceDownloaded, FeedVersion: 1}))
	setRequireCommit(true)

	w := httptest.NewRecorder()
	apiPolicyCreate(w, jsonReq("POST", "/api/policy", map[string]any{"name": "staged-feed-drop", "action": "Drop", "destCategory": "Feed-Class"}))
	if w.Code != http.StatusOK {
		t.Fatalf("staging against a served class must succeed: %d %s", w.Code, w.Body.String())
	}
	saasEffectiveView.Swap(newEffectiveView(map[string]string{"other.example": "Other-Class"},
		effectiveCategoryView{Source: sourceDownloaded, FeedVersion: 2}))

	w = httptest.NewRecorder()
	apiPolicyDraftCommit(w, jsonReq("POST", "/api/policy/draft/commit", map[string]any{"comment": "pol005-drift-commit"}))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("commit with a drifted reference: got %d %s, want 400", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("commit refusal must be the structured integrity 400: %v (%s)", err, w.Body.String())
	}
	if body["referenceType"] != "category" || body["name"] != "Feed-Class" || body["rule"] != "staged-feed-drop" {
		t.Fatalf("refusal must name the reference and the candidate rule: %+v", body)
	}
	if len(policyStore.List()) != 0 || !policyDraft.active() {
		t.Fatal("a refused commit must activate nothing and keep the draft")
	}
	for _, e := range auditGet() {
		if e.Action == "policy.commit" && strings.Contains(e.Detail, "pol005-drift-commit") {
			t.Fatal("a refused commit was audited")
		}
	}

	// Negative control: the running rule drifts, the draft leaves it alone
	// and adds an ordinary rule — the commit goes through and the drifted
	// rule is carried verbatim.
	policyDraft.clear()
	setRequireCommit(false)
	policyStore.ReplaceAll([]PolicyRule{{Priority: 1, Name: "running-drifted", Action: ActionDrop, DestCategory: "Feed-Class"}})
	setRequireCommit(true)
	w = httptest.NewRecorder()
	apiPolicyCreate(w, jsonReq("POST", "/api/policy", map[string]any{"name": "pol005-ordinary", "action": "Allow", "destFQDN": "ok.example"}))
	if w.Code != http.StatusOK {
		t.Fatalf("stage ordinary rule: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	apiPolicyDraftCommit(w, jsonReq("POST", "/api/policy/draft/commit", map[string]any{"comment": "pol005-carry-commit"}))
	if w.Code != http.StatusOK {
		t.Fatalf("an unchanged drifted running rule must not block the commit: %d %s", w.Code, w.Body.String())
	}
	found := false
	for _, r := range policyStore.List() {
		if r.Name == "running-drifted" {
			found = r.DestCategory == "Feed-Class"
		}
	}
	if !found {
		t.Fatalf("the drifted running rule must be carried verbatim: %+v", policyStore.List())
	}
}

func pol005Metrics(t *testing.T) string {
	t.Helper()
	w := httptest.NewRecorder()
	handleMetrics(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", http.NoBody))
	return w.Body.String()
}

func pol005DiagRow(t *testing.T) OperatorContractCheck {
	t.Helper()
	for _, c := range buildOperatorContract().Checks {
		if c.Code == "policy_category_resolution" {
			return c
		}
	}
	t.Fatal("policy_category_resolution missing from /api/diagnostics contract")
	return OperatorContractCheck{}
}
