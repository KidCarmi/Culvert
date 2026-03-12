package main

import (
	"testing"
)

// ─── stringsEqualFold ─────────────────────────────────────────────────────────

func TestStringsEqualFold(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"hello", "HELLO", true},
		{"CORP.COM", "corp.com", true},
		{"abc", "abcd", false},
		{"", "", true},
		{"abc", "xyz", false},
	}
	for _, tt := range tests {
		if got := stringsEqualFold(tt.a, tt.b); got != tt.want {
			t.Errorf("stringsEqualFold(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

// ─── IdPRegistry in-memory operations ────────────────────────────────────────

func newTestRegistry() *IdPRegistry {
	return &IdPRegistry{live: make(map[string]IdentityProvider)}
}

// samlProfile creates a disabled SAML profile with no MetadataURL so URL
// validation is skipped — making it suitable for unit tests without network.
func samlProfile(id, name string) *IdPProfile {
	return &IdPProfile{
		ID:      id,
		Name:    name,
		Type:    IdPTypeSAML,
		Enabled: false,
		SAML:    &SAMLProfileConfig{MetadataXML: "<xml/>"},
	}
}

func TestIdPRegistry_Load_EmptyPath(t *testing.T) {
	r := newTestRegistry()
	if err := r.Load(""); err != nil {
		t.Errorf("Load('') returned error: %v", err)
	}
}

func TestIdPRegistry_Upsert_ValidationErrors(t *testing.T) {
	r := newTestRegistry()

	// Missing name
	if err := r.Upsert(&IdPProfile{Type: IdPTypeOIDC}); err == nil {
		t.Error("Upsert with empty name should fail")
	}

	// Bad type
	if err := r.Upsert(&IdPProfile{Name: "test", Type: "unknown"}); err == nil {
		t.Error("Upsert with unknown type should fail")
	}
}

func TestIdPRegistry_Upsert_InMemory_Disabled(t *testing.T) {
	r := newTestRegistry()
	p := samlProfile("test-id-1", "Test IdP")
	if err := r.Upsert(p); err != nil {
		t.Fatalf("Upsert disabled SAML profile: %v", err)
	}
	got := r.Get("test-id-1")
	if got == nil {
		t.Fatal("Get should return the upserted profile")
	}
	if got.Name != "Test IdP" {
		t.Errorf("profile name = %q, want Test IdP", got.Name)
	}
}

func TestIdPRegistry_Get_NotFound(t *testing.T) {
	r := newTestRegistry()
	if p := r.Get("nonexistent"); p != nil {
		t.Error("Get for unknown ID should return nil")
	}
}

func TestIdPRegistry_All(t *testing.T) {
	r := newTestRegistry()
	r.Upsert(samlProfile("id1", "First"))  //nolint:errcheck
	r.Upsert(samlProfile("id2", "Second")) //nolint:errcheck

	all := r.All()
	if len(all) != 2 {
		t.Errorf("All() returned %d profiles, want 2", len(all))
	}
}

func TestIdPRegistry_Delete(t *testing.T) {
	r := newTestRegistry()
	r.Upsert(samlProfile("del-id", "ToDelete")) //nolint:errcheck

	if err := r.Delete("del-id"); err != nil {
		t.Fatalf("Delete error: %v", err)
	}
	if r.Get("del-id") != nil {
		t.Error("profile should be gone after Delete")
	}
}

func TestIdPRegistry_Delete_NotFound(t *testing.T) {
	r := newTestRegistry()
	if err := r.Delete("ghost"); err == nil {
		t.Error("Delete of non-existent ID should return error")
	}
}

func TestIdPRegistry_Upsert_Replace(t *testing.T) {
	r := newTestRegistry()
	r.Upsert(samlProfile("same-id", "Original")) //nolint:errcheck

	updated := samlProfile("same-id", "Updated")
	r.Upsert(updated) //nolint:errcheck

	got := r.Get("same-id")
	if got == nil {
		t.Fatal("profile should exist after replace")
	}
	if got.Name != "Updated" {
		t.Errorf("Upsert should replace existing profile; got name=%q", got.Name)
	}
	if len(r.All()) != 1 {
		t.Errorf("expected 1 profile after replace, got %d", len(r.All()))
	}
}

func TestIdPRegistry_RouteByDomain_NoMatch(t *testing.T) {
	r := newTestRegistry()
	p := samlProfile("route-id", "Corp IdP")
	p.EmailDomains = []string{"corp.com"}
	r.Upsert(p) //nolint:errcheck

	// No live provider (disabled) — should return nil
	if prov := r.RouteByDomain("corp.com"); prov != nil {
		t.Error("RouteByDomain should return nil for disabled (no live) provider")
	}
}

func TestIdPRegistry_LiveProvider(t *testing.T) {
	r := newTestRegistry()
	_, ok := r.LiveProvider("nonexistent")
	if ok {
		t.Error("LiveProvider for unknown ID should return false")
	}
}

func TestIdPRegistry_EnabledProviders_Empty(t *testing.T) {
	r := newTestRegistry()
	providers := r.EnabledProviders()
	if len(providers) != 0 {
		t.Errorf("EnabledProviders() should be empty for fresh registry, got %d", len(providers))
	}
}

func TestIdPRegistry_Upsert_GeneratesID(t *testing.T) {
	r := newTestRegistry()
	p := &IdPProfile{
		// No ID — should be generated
		Name:    "Auto ID",
		Type:    IdPTypeSAML,
		Enabled: false,
		SAML:    &SAMLProfileConfig{MetadataXML: "<xml/>"},
	}
	if err := r.Upsert(p); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if p.ID == "" {
		t.Error("Upsert should generate an ID when none is given")
	}
	if r.Get(p.ID) == nil {
		t.Error("profile with generated ID should be retrievable")
	}
}
