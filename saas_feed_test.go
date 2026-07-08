package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/saasfeed"
)

// TestMergeSaaSCategories pins main's merge-closure semantics over catStore:
// new categories are created with all hosts; existing ones get only new
// hosts (additive — duplicates by case-insensitive match are skipped).
// The fetch/parse/dispatch half lives in internal/saasfeed's own suite.
func TestMergeSaaSCategories_AdditiveMerge(t *testing.T) {
	// Isolate the package-global catStore (fresh store, tmp Save path):
	// without this the created category leaks into later runs and the
	// first-merge count assertion fails under -count=2 / -shuffle=on.
	snapshotCatStore(t)

	feed := []saasfeed.Category{{
		Name:  "MergeTestCat",
		Hosts: []string{"merge1.com", "merge2.com"},
	}}

	added := mergeSaaSCategories(feed)
	if added != 2 {
		t.Fatalf("first merge added = %d, want 2", added)
	}
	entry := catStore.GetByName("MergeTestCat")
	if entry == nil || len(entry.Hosts) < 2 {
		t.Fatalf("MergeTestCat not created with hosts: %+v", entry)
	}

	// Second merge with one duplicate (different case) and one new host.
	feed[0].Hosts = []string{"MERGE1.com", "merge3.com"}
	added = mergeSaaSCategories(feed)
	if added != 1 {
		t.Errorf("second merge added = %d, want 1 (dup skipped case-insensitively)", added)
	}
}

// TestCategoryStore_GetByName moved to internal/urlcat (ADR-0002, policy.go
// decomposition Phase A) with GetByName itself.

func TestApiCategoryGroups_CRUD(t *testing.T) {
	setupProxyTest(t)

	// GET - empty.
	w := httptest.NewRecorder()
	r := getReq("/api/category-groups")
	apiCategoryGroups(w, r)
	if w.Code != 200 {
		t.Fatalf("GET status = %d", w.Code)
	}

	// POST - create.
	body := `{"name":"Test Group","categories":["AI","News"]}`
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/api/category-groups", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r = adminCtx(r)
	apiCategoryGroups(w, r)
	if w.Code != 200 {
		t.Fatalf("POST status = %d, body = %s", w.Code, w.Body.String())
	}

	// Verify it exists.
	g := globalCategoryGroups.GetByName("Test Group")
	if g == nil {
		t.Fatal("group not found after POST")
	}

	// PUT - update.
	body = `{"name":"Test Group","categories":["AI","News","Streaming"]}`
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPut, "/api/category-groups", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r = adminCtx(r)
	apiCategoryGroups(w, r)
	if w.Code != 200 {
		t.Fatalf("PUT status = %d", w.Code)
	}

	// DELETE.
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodDelete, "/api/category-groups?name=Test+Group", nil)
	r = adminCtx(r)
	apiCategoryGroups(w, r)
	if w.Code != 200 {
		t.Fatalf("DELETE status = %d, body = %s", w.Code, w.Body.String())
	}
}
