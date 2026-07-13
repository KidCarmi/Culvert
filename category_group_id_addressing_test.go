package main

// category_group_id_addressing_test.go — the category-group API supports
// rename-safe ?id= addressing for update and delete (P3 object-identity seam,
// mirroring the policy rule ?id= path). Addressing by the mutable name is
// fragile; the ULID is stable.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestApiCategoryGroup_UpdateByID(t *testing.T) {
	snapshotGlobalCategoryGroups(t)
	snapshotConfigVersionsDir(t)
	globalCategoryGroups.ReplaceAll(nil)
	g, err := globalCategoryGroups.Add("grp", []string{"ai"})
	if err != nil {
		t.Fatal(err)
	}
	if g.ID == "" {
		t.Fatal("added group has no ID")
	}

	body := `{"name":"grp","categories":["ai","marketing"]}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/api/category-groups?id="+g.ID, strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	apiCategoryGroups(w, adminCtx(req))
	if w.Code != http.StatusOK {
		t.Fatalf("PUT ?id= returned %d (%s)", w.Code, w.Body.String())
	}
	got := globalCategoryGroups.GetByID(g.ID)
	if got == nil || len(got.Categories) != 2 {
		t.Errorf("update by id did not apply: %+v", got)
	}
}

func TestApiCategoryGroup_DeleteByID(t *testing.T) {
	snapshotGlobalCategoryGroups(t)
	snapshotConfigVersionsDir(t)
	globalCategoryGroups.ReplaceAll(nil)
	g, _ := globalCategoryGroups.Add("grp-del", []string{"ai"})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/api/category-groups?id="+g.ID, http.NoBody)
	req.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	apiCategoryGroups(w, adminCtx(req))
	if w.Code != http.StatusOK {
		t.Fatalf("DELETE ?id= returned %d (%s)", w.Code, w.Body.String())
	}
	if globalCategoryGroups.GetByID(g.ID) != nil {
		t.Error("group still present after delete by id")
	}
}

func TestApiCategoryGroup_UpdateByID_NotFound(t *testing.T) {
	snapshotGlobalCategoryGroups(t)
	snapshotConfigVersionsDir(t)
	globalCategoryGroups.ReplaceAll(nil)

	body := `{"name":"x","categories":["ai"]}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/api/category-groups?id=deadbeef0000", strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	apiCategoryGroups(w, adminCtx(req))
	if w.Code != http.StatusNotFound {
		t.Errorf("PUT ?id= for unknown group = %d, want 404", w.Code)
	}
}
