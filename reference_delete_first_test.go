package main

// reference_delete_first_test.go — Blocker B (§§6–11): the DELETE-FIRST
// serial order. The gate alone made writer-first safe (a committed reference
// blocks the delete's scan), but a writer that woke AFTER a successful delete
// committed a reference to the just-deleted object — both requests 2xx, a
// dangling reference, and a Deny rule scoped to the deleted category silently
// stops matching. Reference writers now validate their targets UNDER the
// shared gate before committing, so both serial orders are safe:
//
//	writer first → delete 409 (existing proofs, retained)
//	delete first → writer 400 with the structured integrity error
//
// All tests here fail against e221106d (both operations returned 2xx and the
// dangling reference existed). The lifecycle view is pinned nil so the
// resolvability predicate judges exactly the seeded stores.

import (
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
)

// deleteFirstSetup is refGateSetup plus a nil effective view (no signed/UT1
// authority can resurrect a deleted admin category name in these proofs).
func deleteFirstSetup(t *testing.T) {
	t.Helper()
	refGateSetup(t)
	prev := saasEffectiveView.Swap(nil)
	t.Cleanup(func() { saasEffectiveView.Swap(prev) })
}

func assertDanglingRefused(t *testing.T, w *httptest.ResponseRecorder, wantType string) {
	t.Helper()
	if w.Code/100 == 2 {
		t.Fatalf("DELETE-FIRST DANGLING REFERENCE: the reference writer returned %d after the target was deleted — both operations succeeded serially and the committed reference points at a missing %s", w.Code, wantType)
	}
	if w.Code != 400 {
		t.Fatalf("want the structured 400 integrity refusal, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"referenceType":"`+wantType+`"`) {
		t.Fatalf("refusal must carry the structured referenceType %q; got: %s", wantType, w.Body.String())
	}
}

func TestDeleteFirst_CategoryThenRuleCreateRefused(t *testing.T) {
	deleteFirstSetup(t)
	globalCategoryGroups.ReplaceAll(nil) // unreference gate-cat so its delete succeeds

	if w := httptest.NewRecorder(); true {
		apiURLCat(w, jsonReq("DELETE", "/api/urlcat?name=gate-cat", nil))
		if w.Code != 204 {
			t.Fatalf("category delete: %d %s", w.Code, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	apiPolicyCreate(w, jsonReq("POST", "/api/policy",
		map[string]any{"name": "df-a", "action": "Allow", "destCategory": "gate-cat"}))
	assertDanglingRefused(t, w, "category")
	for _, r := range policyStore.List() {
		if strings.EqualFold(string(r.DestCategory), "gate-cat") {
			t.Fatalf("a rule referencing the deleted category was committed: %+v", r)
		}
	}
}

// TestDeleteFirst_RacedWriterWakesAfterDeletion is the §11 raced shape: the
// writer queues behind the exclusive side while the deletion happens, and on
// waking must validate against the post-delete tree.
func TestDeleteFirst_RacedWriterWakesAfterDeletion(t *testing.T) {
	deleteFirstSetup(t)
	globalCategoryGroups.ReplaceAll(nil)

	refScanDeleteLock() // this test IS the delete's scan-and-delete critical section
	w := httptest.NewRecorder()
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		apiPolicyCreate(w, jsonReq("POST", "/api/policy",
			map[string]any{"name": "df-race", "action": "Allow", "destCategory": "gate-cat"}))
	}()
	for i := 0; i < 200000; i++ {
		runtime.Gosched()
	}
	select {
	case <-writerDone:
		refScanDeleteUnlock()
		<-writerDone
		t.Fatal("writer escaped the gate while the delete held it (covered by the mutual-exclusion suite; failing here means the gate regressed)")
	default:
	}
	// Perform the deletion inside the exclusive section, exactly as the
	// handler does, then release — the queued writer wakes after it.
	if err := catStore.DeleteDurable(nil, "gate-cat"); err != nil {
		refScanDeleteUnlock()
		t.Fatalf("delete: %v", err)
	}
	refScanDeleteUnlock()
	<-writerDone
	assertDanglingRefused(t, w, "category")
}

func TestDeleteFirst_CategoryThenGroupMembershipRefused(t *testing.T) {
	deleteFirstSetup(t)
	globalCategoryGroups.ReplaceAll(nil)

	if w := httptest.NewRecorder(); true {
		apiURLCat(w, jsonReq("DELETE", "/api/urlcat?name=gate-cat", nil))
		if w.Code != 204 {
			t.Fatalf("category delete: %d %s", w.Code, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	apiCategoryGroups(w, jsonReq("POST", "/api/category-groups",
		map[string]any{"name": "df-b", "categories": []string{"gate-cat"}}))
	assertDanglingRefused(t, w, "category")
	if globalCategoryGroups.GetByName("df-b") != nil {
		t.Fatal("a group referencing the deleted category was committed")
	}
}

func TestDeleteFirst_GroupThenRuleCreateRefused(t *testing.T) {
	deleteFirstSetup(t)

	if w := httptest.NewRecorder(); true {
		apiCategoryGroups(w, jsonReq("DELETE", "/api/category-groups?name=gate-group", nil))
		if w.Code != 200 {
			t.Fatalf("group delete: %d %s", w.Code, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	apiPolicyCreate(w, jsonReq("POST", "/api/policy",
		map[string]any{"name": "df-c", "action": "Allow", "destCategoryGroup": "gate-group"}))
	assertDanglingRefused(t, w, "category-group")
}

func TestDeleteFirst_ProfileThenRuleCreateRefused(t *testing.T) {
	deleteFirstSetup(t)

	if w := httptest.NewRecorder(); true {
		apiDecryptionProfiles(w, jsonReq("DELETE", "/api/decryption-profiles?name=gate-prof", nil))
		if w.Code != 200 {
			t.Fatalf("profile delete: %d %s", w.Code, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	apiPolicyCreate(w, jsonReq("POST", "/api/policy",
		map[string]any{"name": "df-d", "action": "Allow", "decryptionProfile": "gate-prof"}))
	assertDanglingRefused(t, w, "decryption-profile")
}

func TestDeleteFirst_StagedCreateCannotDangleTheCandidate(t *testing.T) {
	deleteFirstSetup(t)
	globalCategoryGroups.ReplaceAll(nil)
	setRequireCommit(true) // staged mode: creates land in the DRAFT candidate

	if w := httptest.NewRecorder(); true {
		apiURLCat(w, jsonReq("DELETE", "/api/urlcat?name=gate-cat", nil))
		if w.Code != 204 {
			t.Fatalf("category delete: %d %s", w.Code, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	apiPolicyCreate(w, jsonReq("POST", "/api/policy",
		map[string]any{"name": "df-e", "action": "Allow", "destCategory": "gate-cat"}))
	assertDanglingRefused(t, w, "category")
	if policyDraft.active() {
		for _, r := range policyDraft.candidateList() {
			if strings.EqualFold(string(r.DestCategory), "gate-cat") {
				t.Fatalf("a DANGLING CANDIDATE rule was staged: %+v", r)
			}
		}
	}
}

// TestDeleteFirst_FeedAuthorityStillResolvesDeletedAdminName pins the §9
// vocabulary decision: a name is refused only when NO current authority
// resolves it. Here the live signed view still serves a class with the
// deleted admin object's name, so the new reference stays legal.
func TestDeleteFirst_FeedAuthorityStillResolvesDeletedAdminName(t *testing.T) {
	refGateSetup(t)
	globalCategoryGroups.ReplaceAll(nil)
	prev := saasEffectiveView.Swap(newEffectiveView(map[string]string{"svc.example.com": "gate-cat"},
		effectiveCategoryView{Source: sourceDownloaded, FeedVersion: 7}))
	t.Cleanup(func() { saasEffectiveView.Swap(prev) })

	// The admin object is BuiltIn=false here, so the delete is legal even
	// under signed ownership; the NAME keeps category authority via the view.
	if w := httptest.NewRecorder(); true {
		apiURLCat(w, jsonReq("DELETE", "/api/urlcat?name=gate-cat", nil))
		if w.Code != 204 {
			t.Fatalf("category delete: %d %s", w.Code, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	apiPolicyCreate(w, jsonReq("POST", "/api/policy",
		map[string]any{"name": "df-f", "action": "Allow", "destCategory": "gate-cat"}))
	if w.Code != 200 {
		t.Fatalf("a reference to a live signed-feed class must stay legal after the admin object's deletion; got %d: %s", w.Code, w.Body.String())
	}
}
