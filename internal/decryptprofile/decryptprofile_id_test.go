package decryptprofile

// decryptprofile_id_test.go — stable-ID addressing: backfill persisted on load,
// GetByID / UpdateByID / DeleteByID (rename-safe, P3 object-identity seam).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_BackfillsAndPersistsIDs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.json")
	// Legacy profile with no id.
	if err := os.WriteFile(path, []byte(`[{"name":"Legacy"}]`), 0o600); err != nil {
		t.Fatal(err)
	}

	s := New()
	if err := s.Load(path); err != nil {
		t.Fatalf("load: %v", err)
	}
	g := s.GetByName("Legacy")
	if g == nil || g.ID == "" {
		t.Fatalf("legacy profile should have a backfilled ID, got %+v", g)
	}
	id := g.ID

	// Backfill must persist → stable across restart.
	s2 := New()
	if err := s2.Load(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if g2 := s2.GetByName("Legacy"); g2 == nil || g2.ID != id {
		t.Errorf("reloaded ID = %v, want persisted %q", g2, id)
	}
	data, _ := os.ReadFile(path)
	var raw []map[string]any
	_ = json.Unmarshal(data, &raw)
	if len(raw) != 1 || raw[0]["id"] != id {
		t.Errorf("persisted file missing backfilled id: %s", data)
	}
}

func TestUpdateByID_RenameSafe(t *testing.T) {
	s := New()
	p, err := s.Add(Profile{Name: "Orig", CertVerification: "strict"})
	if err != nil {
		t.Fatal(err)
	}
	id := p.ID

	if err := s.UpdateByID(id, Profile{Name: "ignored", CertVerification: "skip"}); err != nil {
		t.Fatalf("UpdateByID: %v", err)
	}
	got := s.GetByID(id)
	if got == nil || got.CertVerification != "skip" {
		t.Errorf("UpdateByID did not apply content: %+v", got)
	}
	if got.Name != "Orig" {
		t.Errorf("UpdateByID must keep the current name, got %q", got.Name)
	}
	if s.UpdateByID("nope", Profile{Name: "x"}) == nil {
		t.Error("UpdateByID on unknown id should error")
	}
}

func TestDeleteByID(t *testing.T) {
	s := New()
	p, _ := s.Add(Profile{Name: "ToDelete"})
	s.Add(Profile{Name: "Keep"}) //nolint:errcheck // test setup

	name, err := s.DeleteByID(p.ID)
	if err != nil {
		t.Fatalf("DeleteByID: %v", err)
	}
	if name != "ToDelete" {
		t.Errorf("DeleteByID name = %q, want ToDelete", name)
	}
	if s.GetByID(p.ID) != nil {
		t.Error("profile still present after DeleteByID")
	}
	if s.GetByName("Keep") == nil {
		t.Error("DeleteByID removed the wrong profile")
	}
	if _, err := s.DeleteByID("nope"); err == nil {
		t.Error("DeleteByID on unknown id should error")
	}
}

func TestGetByID_EmptyNil(t *testing.T) {
	s := New()
	if s.GetByID("") != nil {
		t.Error("GetByID(\"\") must be nil")
	}
}
