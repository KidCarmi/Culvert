package main

// urlcat_state_api_test.go — 2D-B.0a handler contract: the v2 read seam
// (GET /api/urlcat/state) and the fenced ?ifRevision= mutation paths
// (strict create, structured 409, store-boundary cap, durable single-host
// ops). The deep durability/rollback/publication matrix lives in
// internal/urlcat/urlcat_durable_test.go; these tests pin the HTTP contract.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/KidCarmi/Culvert/internal/urlcat"
)

// urlcatAPISetup swaps in a FRESH, file-backed, EMPTY catStore.
func urlcatAPISetup(t *testing.T) string {
	t.Helper()
	orig := catStore
	fresh := urlcat.New(nil)
	path := filepath.Join(t.TempDir(), "url_categories.json")
	fresh.SetPathForTest(path)
	catStore = fresh
	t.Cleanup(func() { catStore = orig })
	return path
}

func doURLCat(t *testing.T, method, target string, body any) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	apiURLCat(w, jsonReq(method, target, body))
	return w
}

func doURLCatHost(t *testing.T, method, target string, body any) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	apiURLCatHost(w, jsonReq(method, target, body))
	return w
}

func urlcatStateRevision(t *testing.T) string {
	t.Helper()
	w := httptest.NewRecorder()
	apiURLCatState(w, getReq("/api/urlcat/state"))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/urlcat/state = %d", w.Code)
	}
	var state struct {
		Categories []map[string]any `json:"categories"`
		Revision   string           `json:"revision"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &state); err != nil {
		t.Fatalf("state decode: %v", err)
	}
	if state.Revision == "" {
		t.Fatal("state revision must never be empty")
	}
	return state.Revision
}

func TestApiURLCatState_ContractMatchesLegacyRead(t *testing.T) {
	urlcatAPISetup(t)
	if w := doURLCat(t, http.MethodPost, "/api/urlcat", map[string]any{"name": "Social", "hosts": []string{"a.example"}}); w.Code != http.StatusOK {
		t.Fatalf("legacy POST = %d: %s", w.Code, w.Body.String())
	}
	rev := urlcatStateRevision(t)
	if rev != catStore.ContentFingerprint() {
		t.Fatal("state revision must be the server-owned ContentFingerprint")
	}
	// The v2 state read and the legacy raw-array read serve the SAME rows.
	w := httptest.NewRecorder()
	apiURLCat(w, getReq("/api/urlcat"))
	var legacy []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &legacy); err != nil {
		t.Fatalf("legacy GET must stay a raw array: %v (%s)", err, w.Body.String())
	}
	if len(legacy) != 1 || legacy[0]["name"] != "Social" || legacy[0]["feedBacked"] != false {
		t.Fatalf("legacy rows = %v", legacy)
	}
}

func TestApiURLCat_FencedCreate_StrictAndStructured409(t *testing.T) {
	urlcatAPISetup(t)
	rev := urlcatStateRevision(t)

	w := doURLCat(t, http.MethodPost, "/api/urlcat?ifRevision="+url.QueryEscape(rev), map[string]any{"name": "Media", "hosts": []string{"m.example"}})
	if w.Code != http.StatusOK {
		t.Fatalf("fenced create = %d: %s", w.Code, w.Body.String())
	}
	var created struct {
		Name     string `json:"name"`
		Revision string `json:"revision"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	if created.Revision != catStore.ContentFingerprint() {
		t.Fatal("fenced create must return the NEW revision")
	}

	// STRICT create: same name (case-insensitive), CURRENT revision → 409.
	w = doURLCat(t, http.MethodPost, "/api/urlcat?ifRevision="+url.QueryEscape(created.Revision), map[string]any{"name": "media", "hosts": []string{"x.example"}})
	if w.Code != http.StatusConflict {
		t.Fatalf("strict-create collision = %d, want 409", w.Code)
	}

	// Stale fence → structured 409 {error, currentRevision, yourRevision}.
	w = doURLCat(t, http.MethodPost, "/api/urlcat?ifRevision="+url.QueryEscape(rev), map[string]any{"name": "Other", "hosts": []string{}})
	if w.Code != http.StatusConflict {
		t.Fatalf("stale fence = %d, want 409", w.Code)
	}
	var conflict struct {
		Error           string `json:"error"`
		CurrentRevision string `json:"currentRevision"`
		YourRevision    string `json:"yourRevision"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &conflict); err != nil {
		t.Fatalf("conflict body: %v (%s)", err, w.Body.String())
	}
	if conflict.CurrentRevision != catStore.ContentFingerprint() || conflict.YourRevision != rev || conflict.Error == "" {
		t.Fatalf("structured conflict = %+v", conflict)
	}
	if catStore.GetByName("Other") != nil {
		t.Fatal("stale mutation must not apply")
	}
}

func TestApiURLCat_FencedPut_CapEnforcedAtStoreBoundary(t *testing.T) {
	urlcatAPISetup(t)
	rev := urlcatStateRevision(t)
	if w := doURLCat(t, http.MethodPost, "/api/urlcat?ifRevision="+url.QueryEscape(rev), map[string]any{"name": "Big", "hosts": []string{"a.example"}}); w.Code != http.StatusOK {
		t.Fatalf("create: %d", w.Code)
	}
	over := make([]string, urlcat.MaxHostsPerCategory+1)
	for i := range over {
		over[i] = fmt.Sprintf("h%05d.example", i)
	}
	rev = urlcatStateRevision(t)
	// The legacy PUT had NO cap — the fenced path enforces it at the store.
	w := doURLCat(t, http.MethodPut, "/api/urlcat?name=Big&ifRevision="+url.QueryEscape(rev), map[string]any{"hosts": over})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("over-cap fenced PUT = %d, want 400", w.Code)
	}
	// The LEGACY PUT is now bounded too (store boundary, §11).
	w = doURLCat(t, http.MethodPut, "/api/urlcat?name=Big", map[string]any{"hosts": over})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("over-cap legacy PUT = %d, want 400", w.Code)
	}
}

func TestApiURLCatHost_FencedAddRemove(t *testing.T) {
	urlcatAPISetup(t)
	rev := urlcatStateRevision(t)
	if w := doURLCat(t, http.MethodPost, "/api/urlcat?ifRevision="+url.QueryEscape(rev), map[string]any{"name": "Seed", "hosts": []string{"a.example"}}); w.Code != http.StatusOK {
		t.Fatalf("create: %d", w.Code)
	}
	rev = urlcatStateRevision(t)
	w := doURLCatHost(t, http.MethodPost, "/api/urlcat/host?ifRevision="+url.QueryEscape(rev), map[string]any{"category": "Seed", "host": "b.example"})
	if w.Code != http.StatusOK {
		t.Fatalf("fenced host add = %d: %s", w.Code, w.Body.String())
	}
	// The consumed token is stale now.
	w = doURLCatHost(t, http.MethodPost, "/api/urlcat/host?ifRevision="+url.QueryEscape(rev), map[string]any{"category": "Seed", "host": "c.example"})
	if w.Code != http.StatusConflict {
		t.Fatalf("stale host add = %d, want 409", w.Code)
	}
	rev = urlcatStateRevision(t)
	w = doURLCatHost(t, http.MethodDelete, "/api/urlcat/host?category=Seed&host=b.example&ifRevision="+url.QueryEscape(rev), nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("fenced host remove = %d: %s", w.Code, w.Body.String())
	}
}

func TestApiURLCat_FencedDelete(t *testing.T) {
	urlcatAPISetup(t)
	rev := urlcatStateRevision(t)
	if w := doURLCat(t, http.MethodPost, "/api/urlcat?ifRevision="+url.QueryEscape(rev), map[string]any{"name": "Gone", "hosts": []string{}}); w.Code != http.StatusOK {
		t.Fatalf("create: %d", w.Code)
	}
	rev = urlcatStateRevision(t)
	w := doURLCat(t, http.MethodDelete, "/api/urlcat?name=Gone&ifRevision="+url.QueryEscape(rev), nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("fenced delete = %d: %s", w.Code, w.Body.String())
	}
	if catStore.GetByName("Gone") != nil {
		t.Fatal("category still present")
	}
	// Stale delete of a missing name: the fence is checked in-domain — the
	// stale token conflicts before the not-found is reached.
	w = doURLCat(t, http.MethodDelete, "/api/urlcat?name=Gone&ifRevision="+url.QueryEscape(rev), nil)
	if w.Code != http.StatusConflict {
		t.Fatalf("stale fenced delete = %d, want 409", w.Code)
	}
}
