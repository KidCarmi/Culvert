package main

// pac_profiles_root_test.go — root-level tests for PAC steering profiles and
// proxy pools (initiative PR 2): API CRUD + RBAC, the /proxy.pac ↔
// /pac/default.pac alias, per-profile serving, cluster snapshot sync
// (including the empty-wipe fix), export/import, and rollback.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/pac"
)

// resetPACProfilesGlobals snapshots/restores both PAC stores for -shuffle
// hermeticity.
func resetPACProfilesGlobals(t *testing.T) {
	t.Helper()
	origCfg := pacStore.Snapshot()
	origProf := pacProfiles.Snapshot()
	t.Cleanup(func() {
		pacStore.Restore(origCfg)
		pacProfiles.Restore(origProf)
	})
}

func seedProfilesConfig(t *testing.T) {
	t.Helper()
	err := pacProfiles.Set(pac.ProfilesConfig{
		Profiles: []pac.Profile{{
			ID: "branch-il", Name: "Branch IL", Enabled: true, PoolID: "il",
			PrivateNetworks: pac.PrivateDirect, AvailabilityMode: pac.ModeAvailability, Revision: 1,
			Rules: []pac.Rule{{Kind: pac.RuleKindSuffix, Pattern: "corp.example", Action: pac.ActionDirect}},
		}},
		Pools: []pac.Pool{{ID: "il", Name: "IL", Endpoints: []pac.PoolEndpoint{
			{Host: "proxy-il.example", Port: 8080}, {Host: "proxy-eu.example", Port: 8080}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func pacAPIReq(t *testing.T, method, path, body string, role UIRole, remoteIP string) *httptest.ResponseRecorder {
	t.Helper()
	var rd *bytes.Reader
	if body == "" {
		rd = bytes.NewReader(nil)
	} else {
		rd = bytes.NewReader([]byte(body))
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = remoteIP
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, role))
	rec := httptest.NewRecorder()
	switch {
	case path == "/api/pac/profiles":
		apiPACProfiles(rec, req)
	case strings.HasPrefix(path, "/api/pac/profiles/"):
		apiPACProfileItem(rec, req)
	case path == "/api/pac/pools":
		apiPACPools(rec, req)
	case strings.HasPrefix(path, "/api/pac/pools/"):
		apiPACPoolItem(rec, req)
	default:
		t.Fatalf("unmapped path %s", path)
	}
	return rec
}

// ─── RBAC ─────────────────────────────────────────────────────────────────────

func TestPACProfilesAPI_RBAC(t *testing.T) {
	resetPACProfilesGlobals(t)
	for _, tc := range []struct {
		role UIRole
		want int
	}{{RoleViewer, http.StatusForbidden}, {RoleOperator, http.StatusForbidden}} {
		rec := pacAPIReq(t, http.MethodPost, "/api/pac/pools",
			`{"id":"x","name":"X","endpoints":[{"host":"p.example","port":8080}]}`, tc.role, "198.51.100.70:0")
		if rec.Code != tc.want {
			t.Errorf("role %v POST pools: got %d, want %d", tc.role, rec.Code, tc.want)
		}
		rec = pacAPIReq(t, http.MethodDelete, "/api/pac/profiles/branch-il", "", tc.role, "198.51.100.70:0")
		if rec.Code != tc.want {
			t.Errorf("role %v DELETE profile: got %d, want %d", tc.role, rec.Code, tc.want)
		}
	}
	// Viewer GET list stays open.
	rec := pacAPIReq(t, http.MethodGet, "/api/pac/profiles", "", RoleViewer, "198.51.100.71:0")
	if rec.Code != http.StatusOK {
		t.Errorf("viewer GET list: got %d, want 200", rec.Code)
	}
}

// ─── CRUD + audit ─────────────────────────────────────────────────────────────

func TestPACProfilesAPI_CRUDAndAudit(t *testing.T) {
	resetPACProfilesGlobals(t)
	baseline := time.Now().UnixMilli()

	// Create pool.
	rec := pacAPIReq(t, http.MethodPost, "/api/pac/pools",
		`{"id":"il-prod","name":"IL","endpoints":[{"host":"proxy-il.example","port":8080},{"host":"proxy-eu.example","port":8080}]}`,
		RoleAdmin, "198.51.100.72:0")
	if rec.Code != http.StatusOK {
		t.Fatalf("create pool: %d (%s)", rec.Code, rec.Body.String())
	}
	// Create profile referencing it.
	rec = pacAPIReq(t, http.MethodPost, "/api/pac/profiles",
		`{"id":"hq","name":"HQ","enabled":true,"poolId":"il-prod","privateNetworks":"direct","availabilityMode":"balanced"}`,
		RoleAdmin, "198.51.100.72:0")
	if rec.Code != http.StatusOK {
		t.Fatalf("create profile: %d (%s)", rec.Code, rec.Body.String())
	}

	// Update bumps revision.
	rec = pacAPIReq(t, http.MethodPut, "/api/pac/profiles/hq",
		`{"name":"HQ v2","enabled":true,"poolId":"il-prod","privateNetworks":"direct","availabilityMode":"availability"}`,
		RoleAdmin, "198.51.100.72:0")
	if rec.Code != http.StatusOK {
		t.Fatalf("update profile: %d (%s)", rec.Code, rec.Body.String())
	}
	p, ok := pacProfiles.ProfileByID("hq")
	if !ok || p.Revision != 2 || p.Name != "HQ v2" {
		t.Errorf("update not applied or revision not bumped: %+v", p)
	}

	// Pool referenced by profile cannot be deleted.
	rec = pacAPIReq(t, http.MethodDelete, "/api/pac/pools/il-prod", "", RoleAdmin, "198.51.100.72:0")
	if rec.Code != http.StatusConflict {
		t.Errorf("delete referenced pool: got %d, want 409", rec.Code)
	}

	// Delete profile then pool.
	rec = pacAPIReq(t, http.MethodDelete, "/api/pac/profiles/hq", "", RoleAdmin, "198.51.100.72:0")
	if rec.Code != http.StatusNoContent {
		t.Errorf("delete profile: got %d", rec.Code)
	}
	rec = pacAPIReq(t, http.MethodDelete, "/api/pac/pools/il-prod", "", RoleAdmin, "198.51.100.72:0")
	if rec.Code != http.StatusNoContent {
		t.Errorf("delete pool after profile removal: got %d", rec.Code)
	}

	// Audit entries exist (TEST-NET-2 discriminator; content-scan, not len).
	found := false
	for _, e := range auditGet() {
		if e.Actor == "198.51.100.72" && e.Action == "pac.profile_create" && e.TS >= baseline {
			found = true
		}
	}
	if !found {
		t.Error("expected pac.profile_create audit entry from 198.51.100.72")
	}
}

func TestPACProfilesAPI_ValidationRejects(t *testing.T) {
	resetPACProfilesGlobals(t)
	rec := pacAPIReq(t, http.MethodPost, "/api/pac/profiles",
		`{"id":"bad","name":"Bad","enabled":true,"poolId":"missing","privateNetworks":"direct","availabilityMode":"balanced"}`,
		RoleAdmin, "198.51.100.73:0")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("dangling pool ref: got %d, want 400 (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "unknown_pool") {
		t.Errorf("400 body must carry structured issues: %s", rec.Body.String())
	}
	if _, exists := pacProfiles.ProfileByID("bad"); exists {
		t.Error("rejected create must not mutate the store")
	}

	// The virtual default profile is not editable here.
	rec = pacAPIReq(t, http.MethodPut, "/api/pac/profiles/default", `{"name":"x"}`, RoleAdmin, "198.51.100.73:0")
	if rec.Code != http.StatusConflict {
		t.Errorf("PUT default: got %d, want 409", rec.Code)
	}
}

// ─── Alias + serving ──────────────────────────────────────────────────────────

func TestPACAlias_DefaultByteIdentical(t *testing.T) {
	resetPACProfilesGlobals(t)
	if err := pacStore.Set(PACConfig{ProxyHost: "proxy.corp.example", ProxyPort: 3128,
		Exclusions: []string{"corp.local"}}); err != nil {
		t.Fatal(err)
	}

	get := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, http.NoBody)
		req.Host = "ui.example:9090"
		rec := httptest.NewRecorder()
		if path == "/proxy.pac" {
			servePACFile(rec, req)
		} else {
			servePACProfileFile(rec, req)
		}
		return rec
	}
	legacy := get("/proxy.pac")
	alias := get("/pac/default.pac")
	if legacy.Body.String() != alias.Body.String() {
		t.Error("/pac/default.pac must serve byte-identical output to /proxy.pac")
	}
	if legacy.Header().Get("ETag") != alias.Header().Get("ETag") {
		t.Error("alias must carry the same ETag")
	}
}

func TestServePACProfileFile_CustomProfile(t *testing.T) {
	resetPACProfilesGlobals(t)
	seedProfilesConfig(t)

	req := httptest.NewRequest(http.MethodGet, "/pac/branch-il.pac", http.NoBody)
	rec := httptest.NewRecorder()
	servePACProfileFile(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("profile PAC: got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `return "PROXY proxy-il.example:8080; PROXY proxy-eu.example:8080; DIRECT";`) {
		t.Errorf("availability-mode chain missing:\n%s", body)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "max-age=0, must-revalidate" {
		t.Errorf("profile PAC must use revalidation caching, got %q", cc)
	}

	// Unknown, invalid, and disabled IDs 404.
	for _, path := range []string{"/pac/nope.pac", "/pac/../etc.pac", "/pac/branch-il", "/pac/.pac"} {
		req := httptest.NewRequest(http.MethodGet, path, http.NoBody)
		rec := httptest.NewRecorder()
		servePACProfileFile(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: got %d, want 404", path, rec.Code)
		}
	}
	cfg := pacProfiles.Get()
	cfg.Profiles[0].Enabled = false
	if err := pacProfiles.Set(cfg); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodGet, "/pac/branch-il.pac", http.NoBody)
	rec = httptest.NewRecorder()
	servePACProfileFile(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("disabled profile must 404, got %d", rec.Code)
	}
}

// ─── Cluster sync ─────────────────────────────────────────────────────────────

func TestClusterSnapshot_PACProfilesSyncAndWipe(t *testing.T) {
	resetPACProfilesGlobals(t)
	seedProfilesConfig(t)
	if err := pacStore.Set(PACConfig{ProxyHost: "cp.example", ProxyPort: 8080,
		Exclusions: []string{"keep.example"}}); err != nil {
		t.Fatal(err)
	}

	// CP capture: all three PAC slices non-nil even when empty.
	snap := CurrentConfigSnapshot()
	if snap.PACProfiles == nil || snap.PACPools == nil || snap.PACExclusions == nil {
		t.Fatal("capture must force non-nil PAC slices (wire-wipe capability)")
	}
	if len(snap.PACProfiles) != 1 || snap.PACProfiles[0].ID != "branch-il" {
		t.Fatalf("profiles not captured: %+v", snap.PACProfiles)
	}

	// Wire round-trip preserves [] (no omitempty).
	if err := pacProfiles.Set(pac.ProfilesConfig{}); err != nil {
		t.Fatal(err)
	}
	if err := pacStore.Set(PACConfig{ProxyHost: "cp.example", ProxyPort: 8080}); err != nil {
		t.Fatal(err)
	}
	wipeSnap := CurrentConfigSnapshot()
	data, err := json.Marshal(wipeSnap)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"pac_profiles":[]`, `"pac_pools":[]`, `"pac_exclusions":[]`} {
		if !strings.Contains(string(data), key) {
			t.Errorf("wire wipe %s missing from serialized snapshot", key)
		}
	}

	// DP apply: stale DP state converges to the (empty) CP state.
	seedProfilesConfig(t) // DP has stale profiles
	var decoded ConfigSnapshot
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	applyConfigSnapshot(decoded)
	if got := pacProfiles.Get(); len(got.Profiles) != 0 || len(got.Pools) != 0 {
		t.Errorf("empty-wipe must clear stale DP profiles/pools: %+v", got)
	}
	if got := pacStore.Get(); len(got.Exclusions) != 0 {
		t.Errorf("empty-wipe must clear stale DP exclusions: %v", got.Exclusions)
	}

	// DP apply: populated snapshot installs profiles.
	snapData, _ := json.Marshal(snap) //nolint:errcheck // fixed shape cannot fail
	var populated ConfigSnapshot
	if err := json.Unmarshal(snapData, &populated); err != nil {
		t.Fatal(err)
	}
	applyConfigSnapshot(populated)
	if got := pacProfiles.Get(); len(got.Profiles) != 1 || got.Profiles[0].ID != "branch-il" {
		t.Errorf("DP did not converge to CP profiles: %+v", got)
	}
}

// ─── Export / import ──────────────────────────────────────────────────────────

func TestConfigExportImport_PACProfiles(t *testing.T) {
	resetPACProfilesGlobals(t)
	seedProfilesConfig(t)

	// Export section "pac" carries profiles + pools.
	req := httptest.NewRequest(http.MethodGet, "/api/config/export?section=pac", http.NoBody)
	req.RemoteAddr = "198.51.100.74:0"
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleAdmin))
	rec := httptest.NewRecorder()
	apiConfigExport(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("export: %d", rec.Code)
	}
	var exported configBackup
	if err := json.Unmarshal(rec.Body.Bytes(), &exported); err != nil {
		t.Fatal(err)
	}
	if len(exported.PACProfiles) != 1 || len(exported.PACPools) != 1 {
		t.Fatalf("export missing profiles/pools: %+v", exported.PACProfiles)
	}

	// Wipe local state, import back (merge mode) — round-trip restores.
	if err := pacProfiles.Set(pac.ProfilesConfig{}); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(exported) //nolint:errcheck // fixed shape cannot fail
	ireq := httptest.NewRequest(http.MethodPost, "/api/config/import", bytes.NewReader(body))
	ireq.Header.Set("Content-Type", "application/json")
	ireq.RemoteAddr = "198.51.100.74:0"
	ireq = ireq.WithContext(context.WithValue(ireq.Context(), uiRoleKey{}, RoleAdmin))
	irec := httptest.NewRecorder()
	apiConfigImport(irec, ireq)
	if irec.Code != http.StatusOK {
		t.Fatalf("import: %d (%s)", irec.Code, irec.Body.String())
	}
	if got := pacProfiles.Get(); len(got.Profiles) != 1 || got.Profiles[0].ID != "branch-il" {
		t.Errorf("import did not restore profiles: %+v", got)
	}

	// Import with a dangling pool reference is rejected before mutation.
	if err := pacProfiles.Set(pac.ProfilesConfig{}); err != nil {
		t.Fatal(err)
	}
	bad := `{"version":1,"pacProfiles":[{"id":"x","name":"X","enabled":true,"poolId":"ghost","privateNetworks":"direct","availabilityMode":"balanced"}]}`
	breq := httptest.NewRequest(http.MethodPost, "/api/config/import", bytes.NewReader([]byte(bad)))
	breq.Header.Set("Content-Type", "application/json")
	breq.RemoteAddr = "198.51.100.75:0"
	breq = breq.WithContext(context.WithValue(breq.Context(), uiRoleKey{}, RoleAdmin))
	brec := httptest.NewRecorder()
	apiConfigImport(brec, breq)
	if brec.Code != http.StatusBadRequest {
		t.Fatalf("dangling import: got %d, want 400 (%s)", brec.Code, brec.Body.String())
	}
	if got := pacProfiles.Get(); len(got.Profiles) != 0 {
		t.Error("rejected import must not mutate the profile store")
	}
}

// ─── Rollback ─────────────────────────────────────────────────────────────────

func TestConfigRollback_PACProfiles(t *testing.T) {
	resetPACProfilesGlobals(t)
	seedProfilesConfig(t)

	captured := captureConfigBackup()
	if len(captured.PACProfiles) != 1 || captured.PACPools == nil {
		t.Fatalf("capture missing profiles: %+v", captured.PACProfiles)
	}

	// Mutate live state, then roll back.
	if err := pacProfiles.Set(pac.ProfilesConfig{}); err != nil {
		t.Fatal(err)
	}
	applyConfigBackup(captured)
	if got := pacProfiles.Get(); len(got.Profiles) != 1 || got.Profiles[0].ID != "branch-il" {
		t.Errorf("rollback did not restore profiles: %+v", got)
	}

	// A pre-extension snapshot (nil fields) skips — live profiles survive.
	old := *captured
	old.PACProfiles = nil
	old.PACPools = nil
	applyConfigBackup(&old)
	if got := pacProfiles.Get(); len(got.Profiles) != 1 {
		t.Errorf("nil-field rollback must skip, not wipe: %+v", got)
	}

	// An explicit [] wipes.
	wipe := *captured
	wipe.PACProfiles = []pac.Profile{}
	wipe.PACPools = []pac.Pool{}
	applyConfigBackup(&wipe)
	if got := pacProfiles.Get(); len(got.Profiles) != 0 || len(got.Pools) != 0 {
		t.Errorf("[]-rollback must wipe: %+v", got)
	}
}
