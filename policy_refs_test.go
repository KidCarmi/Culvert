package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// policy_refs_test.go — the generic objectReferences walk, the
// GET /api/objects/references endpoint, and the two fail-open delete guards
// closed in policy-refs slice 1 (authority roadmap/POLICY-REFS-PLAN.md).

// refTestRule builds a minimal access rule with a stable id/name.
func refTestRule(id, name string) PolicyRule {
	return PolicyRule{ID: id, Name: name, Action: ActionAllow}
}

func TestObjectReferences_UnknownTypeVsEmpty(t *testing.T) {
	snapshotPolicyStoreForTest(t)
	policyStore.ReplaceAll(nil)

	// Unknown type: found=false so a delete caller must NOT treat it as
	// "safe to delete".
	if found, refs := objectReferences("service", "x"); found || refs != nil {
		t.Fatalf("unknown type: got found=%v refs=%v; want false,nil", found, refs)
	}
	// Known type, no referents: found=true, empty — distinct from unknown.
	if found, refs := objectReferences("category", "Gambling"); !found || len(refs) != 0 {
		t.Fatalf("known+empty: got found=%v len=%d; want true,0", found, len(refs))
	}
}

func TestObjectReferences_CategoryCoversRulesAndGroups(t *testing.T) {
	snapshotPolicyStoreForTest(t)
	snapshotGlobalCategoryGroups(t)

	r := refTestRule("rule-ulid-1", "block-gambling")
	r.DestCategory = "Gambling"
	policyStore.ReplaceAll([]PolicyRule{r})

	// A group that also contains the category — the walk must surface BOTH
	// consumer kinds, or the Where-Used endpoint under-reports.
	if _, err := globalCategoryGroups.Add("risky", []string{"Gambling", "Malware"}); err != nil {
		t.Fatalf("create group: %v", err)
	}

	found, refs := objectReferences("category", "gambling") // case-insensitive
	if !found {
		t.Fatal("found=false for a known type")
	}
	if len(refs) != 2 {
		t.Fatalf("got %d refs; want 2 (rule + group): %+v", len(refs), refs)
	}
	var sawRule, sawGroup bool
	for _, ref := range refs {
		switch ref.ConsumerType {
		case "access-rule":
			sawRule = ref.Name == "block-gambling" && ref.Detail == "destCategory"
		case "category-group":
			sawGroup = ref.Name == "risky" && ref.View == "catgroups"
		}
	}
	if !sawRule || !sawGroup {
		t.Fatalf("missing a consumer kind (rule=%v group=%v): %+v", sawRule, sawGroup, refs)
	}
}

func TestObjectReferences_AuthAndAccessConsumerTypes(t *testing.T) {
	snapshotPolicyStoreForTest(t)

	access := refTestRule("a1", "access-rule-x")
	access.DestCategoryGroup = "corp"
	auth := PolicyRule{ID: "u1", Name: "auth-rule-x", RuleType: ruleTypeAuth, DestCategoryGroup: "corp",
		SubjectMatch: &SubjectMatch{SchemaVersion: 1,
			All: []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{"10.0.0.0/8"}}}},
		Auth: &AuthRuleSpec{Outcome: OutcomeExempt, Owner: "ops", Reason: "lab"}}
	policyStore.ReplaceAll([]PolicyRule{access, auth})

	_, refs := objectReferences("category-group", "corp")
	if len(refs) != 2 {
		t.Fatalf("got %d refs; want 2: %+v", len(refs), refs)
	}
	types := map[string]string{refs[0].ConsumerType: refs[0].View, refs[1].ConsumerType: refs[1].View}
	if types["access-rule"] != "policy" || types["auth-rule"] != "authpolicy" {
		t.Fatalf("consumerType→view wrong: %+v", types)
	}
}

// A rule referencing the object via two DIFFERENT fields yields two entries;
// the count message must reflect that without mislabeling.
func TestObjectReferences_MultiFieldDoesNotCorruptCount(t *testing.T) {
	snapshotPolicyStoreForTest(t)

	// One rule references the file-profile "P" and another references it too,
	// so len==2 and the message names one + "1 other".
	r1 := refTestRule("r1", "aaa")
	r1.FileProfile = "P"
	r2 := refTestRule("r2", "bbb")
	r2.FileProfile = "p" // case-insensitive
	policyStore.ReplaceAll([]PolicyRule{r1, r2})

	_, refs := objectReferences("file-profile", "P")
	if len(refs) != 2 {
		t.Fatalf("got %d refs; want 2", len(refs))
	}
	msg := referenceBlockMessage("file-profile", "P", refs)
	if !strings.Contains(msg, "aaa") || !strings.Contains(msg, "1 other") {
		t.Fatalf("block message = %q; want first referent + '1 other'", msg)
	}
}

func TestApiObjectReferences_Endpoint(t *testing.T) {
	snapshotPolicyStoreForTest(t)
	r := refTestRule("id-1", "block-exe")
	r.FileProfile = "Executables"
	policyStore.ReplaceAll([]PolicyRule{r})

	// Bad type → 400.
	rec := httptest.NewRecorder()
	apiObjectReferences(rec, viewerReq(t, "/api/objects/references?type=nope&name=x"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad type: got %d; want 400", rec.Code)
	}
	// Missing name → 400.
	rec = httptest.NewRecorder()
	apiObjectReferences(rec, viewerReq(t, "/api/objects/references?type=file-profile"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing name: got %d; want 400", rec.Code)
	}
	// Happy path → 200 with the structured envelope.
	rec = httptest.NewRecorder()
	apiObjectReferences(rec, viewerReq(t, "/api/objects/references?type=file-profile&name=Executables"))
	if rec.Code != http.StatusOK {
		t.Fatalf("happy: got %d; want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var out struct {
		Object       map[string]string `json:"object"`
		ReferencedBy []objectRef       `json:"referencedBy"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Object["name"] != "Executables" || len(out.ReferencedBy) != 1 ||
		out.ReferencedBy[0].Name != "block-exe" || out.ReferencedBy[0].Detail != "fileProfile" {
		t.Fatalf("envelope wrong: %+v", out)
	}
}

// viewerReq builds a GET request pre-authorized at viewer role for a direct
// handler call (bypasses the middleware chain; requireRole reads the role
// from context set by uiAuthMiddleware, so inject it here).
func viewerReq(t *testing.T, target string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, http.NoBody)
	return req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleViewer))
}

// operatorReq builds an operator-role request for a mutating handler call.
func operatorReq(t *testing.T, method, target, actorIP string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, target, http.NoBody)
	req.RemoteAddr = actorIP + ":0"
	return req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleOperator))
}

// A category delete is blocked (409 + audit) while a rule references it, and
// succeeds once the reference is gone — the fail-open close.
func TestApiURLCat_DeleteBlockedWhileReferenced(t *testing.T) {
	snapshotCatStore(t)
	snapshotPolicyStoreForTest(t)
	snapshotGlobalCategoryGroups(t)

	if err := catStore.Set("Gambling", []string{"bet.example"}, false); err != nil {
		t.Fatalf("seed category: %v", err)
	}
	r := refTestRule("id-blk", "deny-gambling")
	r.Action = ActionDrop
	r.DestCategory = "Gambling"
	policyStore.ReplaceAll([]PolicyRule{r})

	baselineTS := time.Now().UnixMilli()
	rec := httptest.NewRecorder()
	apiURLCat(rec, operatorReq(t, http.MethodDelete, "/api/urlcat?name=Gambling", "198.51.100.60"))
	if rec.Code != http.StatusConflict {
		t.Fatalf("delete-referenced: got %d; want 409 (body=%s)", rec.Code, rec.Body.String())
	}
	var body struct {
		ReferencedBy []objectRef `json:"referencedBy"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("409 body not JSON: %v (%s)", err, rec.Body.String())
	}
	if len(body.ReferencedBy) != 1 || body.ReferencedBy[0].Name != "deny-gambling" {
		t.Fatalf("409 referencedBy wrong: %+v", body.ReferencedBy)
	}
	if !hasMatchingAuditEntry(auditGet(), "198.51.100.60", "urlcat.delete.blocked", "Gambling", baselineTS) {
		t.Fatal("blocked delete not audited")
	}
	if catStore.GetByName("Gambling") == nil {
		t.Fatal("category was deleted despite the block")
	}

	// Repoint the rule; delete now succeeds.
	policyStore.ReplaceAll(nil)
	rec = httptest.NewRecorder()
	apiURLCat(rec, operatorReq(t, http.MethodDelete, "/api/urlcat?name=Gambling", "198.51.100.60"))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete-unreferenced: got %d; want 204 (body=%s)", rec.Code, rec.Body.String())
	}
}

// A file-profile delete addressed by a bad id falls through to the store's
// 404 — never a spurious 409 from the reference walk.
func TestApiFileblockProfiles_DeleteBadIDFallsThroughTo404(t *testing.T) {
	orig := globalProfileStore
	t.Cleanup(func() { globalProfileStore = orig })
	globalProfileStore = &FileProfileStore{}

	rec := httptest.NewRecorder()
	apiFileblockProfiles(rec, operatorReq(t, http.MethodDelete, "/api/fileblock/profiles?id=nonesuch", "198.51.100.61"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("bad-id delete: got %d; want 404 (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestObjectReferences_StableWhenRuleIDEmpty(t *testing.T) {
	// A rule with an empty ID (freshly created in-memory before a reload)
	// still produces a usable ref keyed on name/view — id is best-effort
	// until the policy-identity slice makes it load-bearing.
	snapshotPolicyStoreForTest(t)
	r := refTestRule("", "no-id-rule")
	r.DestCategory = "News"
	policyStore.ReplaceAll([]PolicyRule{r})
	_, refs := objectReferences("category", "News")
	if len(refs) != 1 || refs[0].Name != "no-id-rule" {
		t.Fatalf("empty-id rule not surfaced: %+v", refs)
	}
}
