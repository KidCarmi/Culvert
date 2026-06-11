package main

// auth_idp_persistence_test.go — IdP registry persistence guarantees:
// atomic on-disk save (no torn writes, no temp leftovers), 0600 mode
// (profiles contain OIDC client secrets), restart durability, and the
// Persisted() signal surfaced to the admin UI via GET /api/idp.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testOktaProfile() *IdPProfile {
	return &IdPProfile{
		Name:    "Okta",
		Type:    IdPTypeOIDC,
		Enabled: false,
		OIDC: &OIDCProfileConfig{
			Issuer:       "https://example.okta.com",
			ClientID:     "client",
			ClientSecret: "super-secret",
		},
	}
}

func TestIdPRegistry_UpsertPersistsAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "idp_profiles.json")
	r := &IdPRegistry{live: make(map[string]IdentityProvider)}
	if err := r.Load(path); err != nil { // first run: records path, no file yet
		t.Fatalf("Load: %v", err)
	}
	if err := r.Upsert(testOktaProfile()); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Errorf("file mode = %o, want 0600 (file holds client secrets)", perm)
	}

	// atomicWriteFile must not leave *.tmp.* siblings behind.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Errorf("leftover temp file %q after save", e.Name())
		}
	}

	// On-disk JSON parses and keeps the secret (restart durability).
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var onDisk []*IdPProfile
	if err := json.Unmarshal(data, &onDisk); err != nil {
		t.Fatalf("on-disk JSON corrupt: %v", err)
	}
	if len(onDisk) != 1 || onDisk[0].OIDC == nil || onDisk[0].OIDC.ClientSecret != "super-secret" {
		t.Fatalf("on-disk profiles = %+v, want 1 Okta profile with secret", onDisk)
	}

	// A fresh registry loading the same file sees the profile — the
	// restart/update path that used to lose all IdP config.
	r2 := &IdPRegistry{live: make(map[string]IdentityProvider)}
	if err := r2.Load(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	got := r2.All()
	if len(got) != 1 || got[0].Name != "Okta" {
		t.Fatalf("reloaded profiles = %+v, want the Okta profile", got)
	}
}

func TestIdPRegistry_DeletePersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "idp.json")
	r := &IdPRegistry{live: make(map[string]IdentityProvider)}
	if err := r.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	p := testOktaProfile()
	if err := r.Upsert(p); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if err := r.Delete(p.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var onDisk []*IdPProfile
	if err := json.Unmarshal(data, &onDisk); err != nil {
		t.Fatalf("on-disk JSON corrupt: %v", err)
	}
	if len(onDisk) != 0 {
		t.Fatalf("on-disk profiles after delete = %+v, want empty", onDisk)
	}
}

func TestIdPRegistry_Persisted(t *testing.T) {
	mem := &IdPRegistry{live: make(map[string]IdentityProvider)}
	if mem.Persisted() {
		t.Error("in-memory registry reports Persisted() = true")
	}
	disk := &IdPRegistry{live: make(map[string]IdentityProvider)}
	if err := disk.Load(filepath.Join(t.TempDir(), "idp.json")); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !disk.Persisted() {
		t.Error("file-backed registry reports Persisted() = false")
	}
}

func TestAPIIdPListGet_ReportsPersistedTrue(t *testing.T) {
	orig := idpRegistry
	r := &IdPRegistry{live: make(map[string]IdentityProvider)}
	if err := r.Load(filepath.Join(t.TempDir(), "idp.json")); err != nil {
		t.Fatalf("Load: %v", err)
	}
	idpRegistry = r
	t.Cleanup(func() { idpRegistry = orig })

	w := httptest.NewRecorder()
	req := adminCtx(httptest.NewRequest(http.MethodGet, "/api/idp", http.NoBody))
	apiIdPList(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	var env struct {
		Persisted bool         `json:"persisted"`
		Profiles  []IdPProfile `json:"profiles"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !env.Persisted {
		t.Fatal("persisted = false, want true for file-backed registry")
	}
	if env.Profiles == nil {
		t.Fatal("profiles missing from envelope")
	}
}
