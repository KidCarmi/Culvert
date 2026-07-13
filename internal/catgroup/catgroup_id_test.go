package catgroup

// catgroup_id_test.go — stable-ID addressing for category groups: backfill on
// load, GetByID, UpdateByID, DeleteByID. The store keys by mutable name, so ID
// addressing is what makes edit/delete rename-safe (P3 object-identity seam,
// mirroring the policy rule ?id= work).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_BackfillsMissingIDs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "groups.json")
	// A legacy file with a group that has NO id.
	legacy := `[{"name":"Legacy","categories":["ai"]}]`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}

	s := New()
	if err := s.Load(path); err != nil {
		t.Fatalf("load: %v", err)
	}
	g := s.GetByName("Legacy")
	if g == nil || g.ID == "" {
		t.Fatalf("legacy group should have a backfilled ID, got %+v", g)
	}
	id := g.ID

	// The backfill must have PERSISTED, so a reload keeps the same ID (stable
	// across restart).
	s2 := New()
	if err := s2.Load(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if g2 := s2.GetByName("Legacy"); g2 == nil || g2.ID != id {
		t.Errorf("reloaded ID = %v, want the persisted %q (stable across restart)", g2, id)
	}
	// The file on disk must now carry the id.
	data, _ := os.ReadFile(path)
	var raw []map[string]any
	_ = json.Unmarshal(data, &raw)
	if len(raw) != 1 || raw[0]["id"] != id {
		t.Errorf("persisted file missing backfilled id: %s", data)
	}
}

func TestUpdateByID_RenameSafe(t *testing.T) {
	s := New()
	g, err := s.Add("Original", []string{"ai"})
	if err != nil {
		t.Fatal(err)
	}
	id := g.ID

	// Update the categories by ID — must land on the group regardless of name.
	if err := s.UpdateByID(id, []string{"ai", "marketing"}); err != nil {
		t.Fatalf("UpdateByID: %v", err)
	}
	got := s.GetByID(id)
	if got == nil || len(got.Categories) != 2 {
		t.Errorf("UpdateByID did not apply: %+v", got)
	}
	if s.UpdateByID("nonexistent", []string{"x"}) == nil {
		t.Error("UpdateByID on unknown id should error")
	}
	if s.UpdateByID("", nil) == nil {
		t.Error("UpdateByID with empty id should error")
	}
}

func TestDeleteByID(t *testing.T) {
	s := New()
	g, _ := s.Add("ToDelete", []string{"ai"})
	s.Add("Keep", []string{"marketing"}) //nolint:errcheck // test setup

	name, err := s.DeleteByID(g.ID)
	if err != nil {
		t.Fatalf("DeleteByID: %v", err)
	}
	if name != "ToDelete" {
		t.Errorf("DeleteByID returned name %q, want ToDelete", name)
	}
	if s.GetByID(g.ID) != nil {
		t.Error("group still present after DeleteByID")
	}
	if s.GetByName("Keep") == nil {
		t.Error("DeleteByID removed the wrong group")
	}
	if _, err := s.DeleteByID("nonexistent"); err == nil {
		t.Error("DeleteByID on unknown id should error")
	}
}

func TestGetByID_EmptyReturnsNil(t *testing.T) {
	s := New()
	if s.GetByID("") != nil {
		t.Error("GetByID(\"\") must be nil")
	}
}
