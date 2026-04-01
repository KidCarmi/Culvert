package main

import (
	"os"
	"testing"
)

// ─── CategoryStore tests ──────────────────────────────────────────────────────

func newTestCatStore() *CategoryStore {
	return newCategoryStore(defaultCategoryEntries())
}

func TestCategoryStore_All(t *testing.T) {
	cs := newTestCatStore()
	all := cs.All()
	if len(all) == 0 {
		t.Error("All() should return default categories")
	}
	// Verify it's a copy: modifying the returned slice must not affect the store.
	all[0].Name = "MODIFIED"
	if cs.All()[0].Name == "MODIFIED" {
		t.Error("All() should return a defensive copy")
	}
}

func TestCategoryStore_Set_Create(t *testing.T) {
	cs := newTestCatStore()
	if err := cs.Set("TestCat", []string{"test.example.com"}, false); err != nil {
		t.Fatalf("Set create: %v", err)
	}
	all := cs.All()
	for _, e := range all {
		if e.Name == "TestCat" {
			if len(e.Hosts) != 1 || e.Hosts[0] != "test.example.com" {
				t.Errorf("unexpected hosts: %v", e.Hosts)
			}
			return
		}
	}
	t.Error("TestCat not found after Set")
}

func TestCategoryStore_Set_Update(t *testing.T) {
	cs := newTestCatStore()
	// Social is a built-in category; overwrite its hosts.
	if err := cs.Set("Social", []string{"only.example.com"}, true); err != nil {
		t.Fatalf("Set update: %v", err)
	}
	for _, e := range cs.All() {
		if e.Name == "Social" {
			if len(e.Hosts) != 1 || e.Hosts[0] != "only.example.com" {
				t.Errorf("Social hosts not updated: %v", e.Hosts)
			}
			return
		}
	}
	t.Error("Social not found after Set")
}

func TestCategoryStore_Set_EmptyName(t *testing.T) {
	cs := newTestCatStore()
	if err := cs.Set("", []string{"x.com"}, false); err == nil {
		t.Error("Set with empty name should return error")
	}
}

func TestCategoryStore_Set_NilHosts(t *testing.T) {
	cs := newTestCatStore()
	// nil hosts should not cause a panic (gets normalised to empty slice internally).
	if err := cs.Set("NilCat", nil, false); err != nil {
		t.Fatalf("Set nil hosts: %v", err)
	}
	found := false
	for _, e := range cs.All() {
		if e.Name == "NilCat" {
			found = true
			break
		}
	}
	if !found {
		t.Error("NilCat not found after Set with nil hosts")
	}
}

func TestCategoryStore_Delete(t *testing.T) {
	cs := newTestCatStore()
	_ = cs.Set("ToDelete", []string{"del.example.com"}, false)
	if err := cs.Delete("ToDelete"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	for _, e := range cs.All() {
		if e.Name == "ToDelete" {
			t.Error("ToDelete should be gone after Delete")
		}
	}
}

func TestCategoryStore_Delete_NotFound(t *testing.T) {
	cs := newTestCatStore()
	if err := cs.Delete("DoesNotExist"); err == nil {
		t.Error("Delete non-existent category should return error")
	}
}

func TestCategoryStore_AddHost(t *testing.T) {
	cs := newTestCatStore()
	_ = cs.Set("Hosters", []string{}, false)
	if err := cs.AddHost("Hosters", "new.example.com"); err != nil {
		t.Fatalf("AddHost: %v", err)
	}
	for _, e := range cs.All() {
		if e.Name == "Hosters" {
			for _, h := range e.Hosts {
				if h == "new.example.com" {
					return
				}
			}
			t.Errorf("new.example.com not added to Hosters: %v", e.Hosts)
			return
		}
	}
	t.Error("Hosters not found")
}

func TestCategoryStore_AddHost_Duplicate(t *testing.T) {
	cs := newTestCatStore()
	_ = cs.Set("Dupes", []string{"existing.com"}, false)
	// Adding the same host a second time should be a no-op.
	if err := cs.AddHost("Dupes", "existing.com"); err != nil {
		t.Fatalf("AddHost duplicate: %v", err)
	}
	for _, e := range cs.All() {
		if e.Name == "Dupes" {
			count := 0
			for _, h := range e.Hosts {
				if h == "existing.com" {
					count++
				}
			}
			if count > 1 {
				t.Errorf("duplicate host added: count=%d", count)
			}
			return
		}
	}
}

func TestCategoryStore_AddHost_NotFound(t *testing.T) {
	cs := newTestCatStore()
	if err := cs.AddHost("NoSuchCat", "host.example.com"); err == nil {
		t.Error("AddHost on non-existent category should return error")
	}
}

func TestCategoryStore_RemoveHost(t *testing.T) {
	cs := newTestCatStore()
	_ = cs.Set("RemoveCat", []string{"keep.com", "remove.com"}, false)
	if err := cs.RemoveHost("RemoveCat", "remove.com"); err != nil {
		t.Fatalf("RemoveHost: %v", err)
	}
	for _, e := range cs.All() {
		if e.Name == "RemoveCat" {
			for _, h := range e.Hosts {
				if h == "remove.com" {
					t.Error("remove.com still present after RemoveHost")
				}
			}
			return
		}
	}
}

func TestCategoryStore_RemoveHost_NotFound(t *testing.T) {
	cs := newTestCatStore()
	_ = cs.Set("RemoveCat2", []string{"keep.com"}, false)
	if err := cs.RemoveHost("RemoveCat2", "nothere.com"); err == nil {
		t.Error("RemoveHost non-existent host should return error")
	}
}

func TestCategoryStore_RemoveHost_CatNotFound(t *testing.T) {
	cs := newTestCatStore()
	if err := cs.RemoveHost("NoSuchCat", "host.com"); err == nil {
		t.Error("RemoveHost on non-existent category should return error")
	}
}

func TestCategoryStore_Load_NewFile(t *testing.T) {
	f, err := os.CreateTemp("", "cats*.json")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	os.Remove(f.Name())       //nolint:errcheck // test cleanup
	defer os.Remove(f.Name()) //nolint:errcheck // test cleanup

	cs := &CategoryStore{}
	if err := cs.Load(f.Name()); err != nil {
		t.Fatalf("Load new file: %v", err)
	}
	if len(cs.All()) == 0 {
		t.Error("Load on new file should seed default categories")
	}
}

func TestCategoryStore_Load_ExistingFile(t *testing.T) {
	f, err := os.CreateTemp("", "cats*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())          //nolint:errcheck // test cleanup
	defer os.Remove(f.Name() + ".tmp") //nolint:errcheck // test cleanup

	// Write a simple category list.
	_, _ = f.WriteString(`[{"name":"TestOnly","hosts":["t.example.com"],"builtIn":false}]`)
	f.Close()

	cs := &CategoryStore{}
	if err := cs.Load(f.Name()); err != nil {
		t.Fatalf("Load existing file: %v", err)
	}
	all := cs.All()
	if len(all) != 1 || all[0].Name != "TestOnly" {
		t.Errorf("Load existing: got %v", all)
	}
}

func TestCategoryStore_Save_NoPath(_ *testing.T) {
	// Save with no path should be a no-op (no panic).
	cs := &CategoryStore{entries: defaultCategoryEntries()}
	cs.Save()
}
