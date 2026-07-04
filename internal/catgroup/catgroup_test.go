package catgroup

// Engine tests, moved in-package from package main's categorygroup_test.go
// with the extraction. The host-level match (categoryGroupMatchesHost) is
// tested in main, where the two-tier category fusion lives.

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCategoryGroupStore_AddListDelete(t *testing.T) {
	s := New()

	g, err := s.Add("Prod Allowed", []string{"AI", "Marketing", "Messaging"})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if g.Name != "Prod Allowed" {
		t.Errorf("name = %q, want 'Prod Allowed'", g.Name)
	}
	if len(g.Categories) != 3 {
		t.Errorf("categories count = %d, want 3", len(g.Categories))
	}

	// List.
	list := s.List()
	if len(list) != 1 {
		t.Fatalf("list count = %d, want 1", len(list))
	}

	// Duplicate name should fail.
	_, err = s.Add("prod allowed", []string{"AI"})
	if err == nil {
		t.Error("expected error for duplicate name")
	}

	// Delete.
	if err := s.Delete("Prod Allowed"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if len(s.List()) != 0 {
		t.Error("expected 0 groups after delete")
	}
}

func TestCategoryGroupStore_Update(t *testing.T) {
	s := New()
	_, _ = s.Add("Test", []string{"AI", "Marketing"})

	if err := s.Update("Test", []string{"AI", "Messaging", "DevTools"}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	g := s.GetByName("test") // case-insensitive
	if g == nil {
		t.Fatal("GetByName returned nil")
	}
	if len(g.Categories) != 3 {
		t.Errorf("categories count = %d, want 3", len(g.Categories))
	}

	// Update non-existent.
	if err := s.Update("NonExistent", []string{}); err == nil {
		t.Error("expected error for non-existent group")
	}
}

func TestCategoryGroupStore_CatSetO1(t *testing.T) {
	s := New()
	_, _ = s.Add("Test", []string{"AI", "Marketing", "MESSAGING"})

	g := s.GetByName("test")
	if g == nil {
		t.Fatal("GetByName returned nil")
	}

	// catSet should be lowercase.
	if !g.catSet["ai"] {
		t.Error("catSet missing 'ai'")
	}
	if !g.catSet["messaging"] {
		t.Error("catSet missing 'messaging' (should be lowercased)")
	}
	if g.catSet["MESSAGING"] {
		t.Error("catSet should not have uppercase 'MESSAGING'")
	}
}

func TestCategoryGroupStore_ContainsCategory(t *testing.T) {
	s := New()
	_, _ = s.Add("Prod", []string{"AI", "Marketing"})

	name, found := s.ContainsCategory("AI")
	if !found || name != "Prod" {
		t.Errorf("ContainsCategory('AI') = (%q, %v), want ('Prod', true)", name, found)
	}

	_, found = s.ContainsCategory("Gambling")
	if found {
		t.Error("ContainsCategory('Gambling') should be false")
	}
}

func TestCategoryGroupStore_ReplaceAll(t *testing.T) {
	s := New()
	_, _ = s.Add("Old", []string{"AI"})

	s.ReplaceAll([]Group{
		{ID: "1", Name: "New1", Categories: []string{"Marketing"}},
		{ID: "2", Name: "New2", Categories: []string{"Messaging", "AI"}},
	})

	if s.GetByName("Old") != nil {
		t.Error("old group should be gone after ReplaceAll")
	}
	if s.GetByName("New1") == nil {
		t.Error("New1 should exist")
	}
	g2 := s.GetByName("New2")
	if g2 == nil || !g2.catSet["ai"] {
		t.Error("New2 should have ai in catSet")
	}
}

func TestCategoryGroupStore_Persistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catgroups.json")

	s1 := New()
	s1.path = path
	_, _ = s1.Add("Persist", []string{"AI", "Marketing"})
	s1.Save()

	// Verify file exists.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file not created: %v", err)
	}

	// Load into new store.
	s2 := New()
	if err := s2.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	g := s2.GetByName("Persist")
	if g == nil {
		t.Fatal("group not found after reload")
	}
	if !g.catSet["ai"] {
		t.Error("catSet not rebuilt after Load")
	}
}

func TestCategoryGroupStore_Names(t *testing.T) {
	s := New()
	_, _ = s.Add("Alpha", []string{"AI"})
	_, _ = s.Add("Beta", []string{"Marketing"})

	names := s.Names()
	if len(names) != 2 {
		t.Errorf("names count = %d, want 2", len(names))
	}
}

func TestCategoryGroupStore_NormCats(t *testing.T) {
	result := normCats([]string{"AI", " marketing ", "AI", "", "  MESSAGING"})
	if len(result) != 3 {
		t.Errorf("normCats returned %d items, want 3 (deduplicated)", len(result))
	}
	for _, c := range result {
		if c != "ai" && c != "marketing" && c != "messaging" {
			t.Errorf("unexpected category %q", c)
		}
	}
}

func TestCategoryGroupStore_DeleteNonExistent(t *testing.T) {
	s := New()
	if err := s.Delete("nope"); err == nil {
		t.Error("expected error deleting non-existent group")
	}
}
