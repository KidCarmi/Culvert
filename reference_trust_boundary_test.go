package main

// reference_trust_boundary_test.go — trust-boundary + category-authority
// proofs (final 2D-B correction §§1–5).
//
// ID-TRUST (§§1–3): on the interactive write path the NAME is client intent
// and object IDs are SERVER-DERIVED ONLY (stampObjectRefIDs discards client
// IDs). At the prior candidate the reference validator ran BEFORE that
// canonicalization and accepted "supplied ID exists OR supplied name exists"
// — so a payload naming a MISSING object while smuggling a valid unrelated
// object's ID passed validation, the stamp then threw the ID away, and a
// dangling rule landed. The pipeline is now decode → structural validation →
// server canonicalization → reference validation of the FINAL canonical rule
// → persistence, with no restamp after validation.
//
// CATEGORY AUTHORITY (§§4–5): the resolvability predicate mirrors the REAL
// hot-path source model (resolveFusion): with an effective view installed the
// admin tier is BuiltIn=false only — a BuiltIn=true catStore-only name the
// view does not serve is NOT a live authority and a new reference to it must
// refuse; the same name becomes referenceable when the view serves it, and
// under no view the full catStore resolves.

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func trustGroupID(t *testing.T, name string) string {
	t.Helper()
	g := globalCategoryGroups.GetByName(name)
	if g == nil {
		t.Fatalf("group %q not found", name)
	}
	return g.ID
}

func TestIDTrust_AccessCreateIgnoresClientGroupID(t *testing.T) {
	deleteFirstSetup(t) // seeds gate-group/gate-prof/gate-cat, nil view
	realID := trustGroupID(t, "gate-group")

	w := httptest.NewRecorder()
	apiPolicyCreate(w, jsonReq("POST", "/api/policy", map[string]any{
		"name": "idtrust-a", "action": "Allow",
		"destCategoryGroup":   "MISSING",
		"destCategoryGroupId": realID, // valid but UNRELATED — must not satisfy validation
	}))
	assertDanglingRefused(t, w, "category-group")
	for _, r := range policyStore.List() {
		if r.Name == "idtrust-a" {
			t.Fatalf("dangling rule landed via a client-supplied object ID: %+v", r)
		}
	}
}

func TestIDTrust_AccessEditIgnoresClientGroupID(t *testing.T) {
	deleteFirstSetup(t)
	realID := trustGroupID(t, "gate-group")

	w := httptest.NewRecorder()
	apiPolicyCreate(w, jsonReq("POST", "/api/policy", map[string]any{"name": "idtrust-b", "action": "Allow"}))
	if w.Code != 200 {
		t.Fatalf("seed rule: %d %s", w.Code, w.Body.String())
	}
	var created PolicyRule
	mustDecodeJSONBody(t, w, &created)

	w = httptest.NewRecorder()
	apiPolicyUpdate(w, jsonReq("PUT", "/api/policy?id="+created.ID, map[string]any{
		"name": "idtrust-b", "action": "Allow",
		"destCategoryGroup":   "MISSING",
		"destCategoryGroupId": realID,
	}))
	assertDanglingRefused(t, w, "category-group")
	if got := policyStore.findByIDCopy(created.ID); got == nil || got.DestCategoryGroup != "" {
		t.Fatalf("refused edit must leave the rule unchanged: %+v", got)
	}
}

func TestIDTrust_DecryptionProfileIgnoresClientID(t *testing.T) {
	deleteFirstSetup(t)
	p := globalDecryptionProfiles.GetByName("gate-prof")
	if p == nil {
		t.Fatal("gate-prof not found")
	}
	w := httptest.NewRecorder()
	apiPolicyCreate(w, jsonReq("POST", "/api/policy", map[string]any{
		"name": "idtrust-c", "action": "Allow",
		"decryptionProfile":   "MISSING",
		"decryptionProfileId": p.ID,
	}))
	assertDanglingRefused(t, w, "decryption-profile")
}

func TestIDTrust_AuthCreateIgnoresClientGroupID(t *testing.T) {
	deleteFirstSetup(t)
	realID := trustGroupID(t, "gate-group")

	w := httptest.NewRecorder()
	apiAuthPolicyCreate(w, jsonReq("POST", "/api/authpolicy", map[string]any{
		"name": "idtrust-d", "ruleType": "auth",
		"destCategoryGroup":   "MISSING",
		"destCategoryGroupId": realID,
		"subjectMatch": map[string]any{
			"schemaVersion": 1,
			"all":           []map[string]any{{"type": "cidr", "values": []string{"10.0.0.0/8"}}},
		},
		"auth": map[string]any{"outcome": "Exempt", "owner": "ops", "reason": "lab"},
	}))
	assertDanglingRefused(t, w, "category-group")
}

// TestIDTrust_MismatchedPairBindsToTheName pins the §3-E doctrine: name is
// intent, so a real name paired with a DIFFERENT object's ID binds to the
// NAME's object — the client-provided ID is ignored, not an error.
func TestIDTrust_MismatchedPairBindsToTheName(t *testing.T) {
	deleteFirstSetup(t)
	if w := httptest.NewRecorder(); true {
		apiCategoryGroups(w, jsonReq("POST", "/api/category-groups",
			map[string]any{"name": "other-group", "categories": []string{"gate-cat"}}))
		if w.Code != 200 {
			t.Fatalf("seed other-group: %d %s", w.Code, w.Body.String())
		}
	}
	aID := trustGroupID(t, "gate-group")
	bID := trustGroupID(t, "other-group")

	w := httptest.NewRecorder()
	apiPolicyCreate(w, jsonReq("POST", "/api/policy", map[string]any{
		"name": "idtrust-e", "action": "Allow",
		"destCategoryGroup":   "gate-group", // real Group-A
		"destCategoryGroupId": bID,          // Group-B's ID — ignored
	}))
	if w.Code != 200 {
		t.Fatalf("mismatched pair must bind to the name, got %d: %s", w.Code, w.Body.String())
	}
	var got *PolicyRule
	for _, r := range policyStore.List() {
		if r.Name == "idtrust-e" {
			cp := r
			got = &cp
		}
	}
	if got == nil || got.DestCategoryGroupID != aID {
		t.Fatalf("server must bind to the NAME's object ID %s; got %+v", aID, got)
	}
	if got.DestCategoryGroupID == bID {
		t.Fatal("client-supplied ID survived the canonicalization")
	}
}

// TestCategoryAuthority_BuiltInOnlyNameTracksTheEffectiveView is the §5
// proof: a BuiltIn=true catStore-only category is a live authority ONLY while
// no effective view is installed OR the current view serves that name.
func TestCategoryAuthority_BuiltInOnlyNameTracksTheEffectiveView(t *testing.T) {
	refGateSetup(t)
	globalCategoryGroups.ReplaceAll(nil)
	catStore.ReplaceAll([]CategoryEntry{
		{Name: "Legacy-SaaS", Hosts: []string{"legacy.example.com"}, BuiltIn: true},
	})

	create := func(name string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		apiPolicyCreate(w, jsonReq("POST", "/api/policy",
			map[string]any{"name": name, "action": "Allow", "destCategory": "Legacy-SaaS"}))
		return w
	}

	// No view: full catStore is the authority — referenceable.
	prev := saasEffectiveView.Swap(nil)
	t.Cleanup(func() { saasEffectiveView.Swap(prev) })
	if w := create("auth-a"); w.Code != 200 {
		t.Fatalf("no-view reference must be legal, got %d: %s", w.Code, w.Body.String())
	}

	// Downloaded view WITHOUT Legacy-SaaS: the admin tier is BuiltIn=false
	// only and the view does not serve the name — NOT referenceable.
	saasEffectiveView.Swap(newEffectiveView(map[string]string{"svc.example.com": "AI"},
		effectiveCategoryView{Source: sourceDownloaded, FeedVersion: 9}))
	w := create("auth-b")
	assertDanglingRefused(t, w, "category")

	// Group membership variant: same refusal.
	w = httptest.NewRecorder()
	apiCategoryGroups(w, jsonReq("POST", "/api/category-groups",
		map[string]any{"name": "auth-g", "categories": []string{"Legacy-SaaS"}}))
	assertDanglingRefused(t, w, "category")

	// The view now SERVES Legacy-SaaS: referenceable again.
	saasEffectiveView.Swap(newEffectiveView(map[string]string{"legacy.example.com": "Legacy-SaaS"},
		effectiveCategoryView{Source: sourceDownloaded, FeedVersion: 10}))
	if w := create("auth-c"); w.Code != 200 {
		t.Fatalf("view-served name must be legal, got %d: %s", w.Code, w.Body.String())
	}
}

func mustDecodeJSONBody(t *testing.T, w *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(w.Body.Bytes(), v); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}
