package main

// pac_profiles_root_test.go — root-level tests for PAC steering profiles and
// proxy pools (initiative PR 2): API CRUD + RBAC, the /proxy.pac ↔
// /pac/default.pac alias, per-profile serving, cluster snapshot sync
// (including the empty-wipe fix), export/import, and rollback.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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
	req := httptest.NewRequest(method, pacTestWithTokens(method, path, body), rd)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = remoteIP
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, role))
	rec := httptest.NewRecorder()
	// Dispatch on the URL path (query-string safe — e.g. ?confirmDirect=).
	switch p := req.URL.Path; {
	case p == "/api/pac/profiles":
		apiPACProfiles(rec, req)
	case strings.HasPrefix(p, "/api/pac/profiles/"):
		apiPACProfileItem(rec, req)
	case p == "/api/pac/pools":
		apiPACPools(rec, req)
	case strings.HasPrefix(p, "/api/pac/pools/"):
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
	// Create profile referencing it. private-networks=direct is a new DIRECT
	// (full security-path bypass) path, so the unified guardrail requires the
	// typed ?confirmDirect= confirmation — same gate as the publish lifecycle.
	// 2F-B: the typed confirmation is the server's candidate-bound challenge
	// (issued on the first attempt), echoed with the typed confirmValue.
	create := `{"id":"hq","name":"HQ","enabled":true,"poolId":"il-prod","privateNetworks":"direct","availabilityMode":"balanced"}`
	rec = pacAPIReq(t, http.MethodPost, "/api/pac/profiles", create, RoleAdmin, "198.51.100.72:0")
	rec = pacAPIReq(t, http.MethodPost, "/api/pac/profiles", pacTestWithConfirm(create, pacTestConfirmFragment(t, rec)), RoleAdmin, "198.51.100.72:0")
	if rec.Code != http.StatusOK {
		t.Fatalf("create profile: %d (%s)", rec.Code, rec.Body.String())
	}

	// Update bumps revision (availability mode also introduces DIRECT → confirm).
	update := `{"name":"HQ v2","enabled":true,"poolId":"il-prod","privateNetworks":"direct","availabilityMode":"availability"}`
	rec = pacAPIReq(t, http.MethodPut, "/api/pac/profiles/hq", update, RoleAdmin, "198.51.100.72:0")
	rec = pacAPIReq(t, http.MethodPut, "/api/pac/profiles/hq", pacTestWithConfirm(update, pacTestConfirmFragment(t, rec)), RoleAdmin, "198.51.100.72:0")
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

// TestPACProfilesAPI_DirectGuardrail pins that the direct CRUD create/update
// path enforces the SAME typed-DIRECT confirmation as the publish lifecycle —
// the guardrail cannot be bypassed by saving through the editor/API.
func TestPACProfilesAPI_DirectGuardrail(t *testing.T) {
	resetPACProfilesGlobals(t)
	rec := pacAPIReq(t, http.MethodPost, "/api/pac/pools",
		`{"id":"p","name":"P","endpoints":[{"host":"proxy.example","port":8080}]}`,
		RoleAdmin, "198.51.100.80:0")
	if rec.Code != http.StatusOK {
		t.Fatalf("create pool: %d (%s)", rec.Code, rec.Body.String())
	}

	// A proxy-only profile (no DIRECT) needs no confirmation.
	rec = pacAPIReq(t, http.MethodPost, "/api/pac/profiles",
		`{"id":"safe","name":"Safe","enabled":true,"poolId":"p","privateNetworks":"proxy","availabilityMode":"balanced"}`,
		RoleAdmin, "198.51.100.80:0")
	if rec.Code != http.StatusOK {
		t.Fatalf("proxy-only create should not require confirmation: %d (%s)", rec.Code, rec.Body.String())
	}

	// A DIRECT-introducing create is refused with 409 + newDirectPaths.
	body := `{"id":"byp","name":"Byp","enabled":true,"poolId":"p","privateNetworks":"proxy","availabilityMode":"balanced","rules":[{"kind":"domain","pattern":"x.example","action":"direct"}]}`
	rec = pacAPIReq(t, http.MethodPost, "/api/pac/profiles", body, RoleAdmin, "198.51.100.80:0")
	if rec.Code != http.StatusConflict {
		t.Fatalf("DIRECT create without confirmation must be 409, got %d (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "newDirectPaths") || !strings.Contains(rec.Body.String(), `"challenge"`) {
		t.Errorf("409 body must carry newDirectPaths + the bound challenge: %s", rec.Body.String())
	}
	if _, exists := pacProfiles.ProfileByID("byp"); exists {
		t.Error("unconfirmed DIRECT create must not mutate the store")
	}
	confirm := pacTestConfirmFragment(t, rec)

	// The retired profile-id query parameter does not satisfy the gate, and
	// neither does a wrong typed value.
	rec = pacAPIReq(t, http.MethodPost, "/api/pac/profiles?confirmDirect=byp", body, RoleAdmin, "198.51.100.80:0")
	if rec.Code != http.StatusConflict {
		t.Errorf("legacy confirmDirect must still 409, got %d", rec.Code)
	}
	rec = pacAPIReq(t, http.MethodPost, "/api/pac/profiles", pacTestWithConfirm(body, strings.Replace(confirm, `"value":"byp:`, `"value":"byp:wrong-`, 1)), RoleAdmin, "198.51.100.80:0")
	if rec.Code != http.StatusConflict {
		t.Errorf("wrong typed value must still 409, got %d", rec.Code)
	}

	// The correct typed confirmation publishes.
	rec = pacAPIReq(t, http.MethodPost, "/api/pac/profiles", pacTestWithConfirm(body, confirm), RoleAdmin, "198.51.100.80:0")
	if rec.Code != http.StatusOK {
		t.Fatalf("confirmed DIRECT create: %d (%s)", rec.Code, rec.Body.String())
	}
	if _, exists := pacProfiles.ProfileByID("byp"); !exists {
		t.Error("confirmed DIRECT create must persist the profile")
	}

	// Dormant-enable: a DISABLED profile that already carries DIRECT serves
	// nothing, so creating it needs no confirmation — but flipping it to
	// enabled makes the DIRECT path reachable for the first time and MUST
	// require the typed confirmation (the disabled spec is not a live baseline).
	dormant := `{"id":"dorm","name":"Dorm","enabled":false,"poolId":"p","privateNetworks":"proxy","availabilityMode":"balanced","rules":[{"kind":"domain","pattern":"z.example","action":"direct"}]}`
	rec = pacAPIReq(t, http.MethodPost, "/api/pac/profiles", dormant, RoleAdmin, "198.51.100.82:0")
	if rec.Code != http.StatusOK {
		t.Fatalf("disabled DIRECT create should not require confirmation: %d (%s)", rec.Code, rec.Body.String())
	}
	enable := `{"id":"dorm","name":"Dorm","enabled":true,"poolId":"p","privateNetworks":"proxy","availabilityMode":"balanced","rules":[{"kind":"domain","pattern":"z.example","action":"direct"}]}`
	rec = pacAPIReq(t, http.MethodPut, "/api/pac/profiles/dorm", enable, RoleAdmin, "198.51.100.82:0")
	if rec.Code != http.StatusConflict {
		t.Fatalf("enabling a dormant DIRECT profile must require confirmation (409), got %d (%s)", rec.Code, rec.Body.String())
	}
	rec = pacAPIReq(t, http.MethodPut, "/api/pac/profiles/dorm", pacTestWithConfirm(enable, pacTestConfirmFragment(t, rec)), RoleAdmin, "198.51.100.82:0")
	if rec.Code != http.StatusOK {
		t.Fatalf("confirmed dormant-enable: %d (%s)", rec.Code, rec.Body.String())
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

// ─── Proxy-listener routing (Palo QA #2, #11) ──────────────────────────────────

func TestRouteProxyListenerBuiltin_PAC(t *testing.T) {
	resetPACProfilesGlobals(t)
	seedProfilesConfig(t)
	if err := pacStore.Set(PACConfig{ProxyHost: "proxy.example", ProxyPort: 8080}); err != nil {
		t.Fatal(err)
	}

	// (a) Direct GET /pac/{id}.pac on the proxy listener is served.
	req := httptest.NewRequest(http.MethodGet, "/pac/branch-il.pac", http.NoBody)
	rec := httptest.NewRecorder()
	if !routeProxyListenerBuiltin(rec, req) {
		t.Fatal("direct /pac/{id}.pac must be handled by the proxy listener")
	}
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "FindProxyForURL") {
		t.Errorf("profile PAC not served on proxy listener: %d", rec.Code)
	}

	// (b) Direct GET /proxy.pac is served.
	req = httptest.NewRequest(http.MethodGet, "/proxy.pac", http.NoBody)
	rec = httptest.NewRecorder()
	if !routeProxyListenerBuiltin(rec, req) || rec.Code != http.StatusOK {
		t.Errorf("/proxy.pac must be served on the proxy listener: %d", rec.Code)
	}

	// (c) A PROXIED absolute-URI request for /pac/... (URL.Host set) must NOT
	// be hijacked — it falls through to handleRequest.
	proxied := httptest.NewRequest(http.MethodGet, "http://origin.example/pac/branch-il.pac", http.NoBody)
	if proxied.URL.Host == "" {
		t.Fatal("test setup: absolute-URI request must carry URL.Host")
	}
	rec = httptest.NewRecorder()
	if routeProxyListenerBuiltin(rec, proxied) {
		t.Error("proxied absolute-URI /pac/ request must fall through to handleRequest, not be served locally")
	}

	// (d) An ordinary proxied request falls through.
	ordinary := httptest.NewRequest(http.MethodGet, "http://example.com/index.html", http.NoBody)
	rec = httptest.NewRecorder()
	if routeProxyListenerBuiltin(rec, ordinary) {
		t.Error("ordinary proxied request must fall through")
	}
}

// TestRouteProxyListenerBuiltin_StatusEndpointsNotHijacked pins the same
// Host-guard contract as TestRouteProxyListenerBuiltin_PAC for the built-in
// status endpoints. A forward proxy must not shadow an upstream origin's own
// /health, /ready, or /metrics path: a client proxying an absolute-URI
// request to such a path on a real destination must be forwarded to that
// destination, not served Culvert's own local status response.
func TestRouteProxyListenerBuiltin_StatusEndpointsNotHijacked(t *testing.T) {
	for _, path := range []string{"/health", "/ready", "/metrics"} {
		// Direct (non-proxied) request on the proxy listener is still served locally.
		direct := httptest.NewRequest(http.MethodGet, path, http.NoBody)
		rec := httptest.NewRecorder()
		if !routeProxyListenerBuiltin(rec, direct) {
			t.Errorf("direct GET %s must be handled by the proxy listener", path)
		}

		// A PROXIED absolute-URI request for the same path on a real origin
		// (URL.Host set) must NOT be hijacked — it must fall through to
		// handleRequest so the origin's own endpoint is reached.
		proxied := httptest.NewRequest(http.MethodGet, "http://origin.example"+path, http.NoBody)
		if proxied.URL.Host == "" {
			t.Fatal("test setup: absolute-URI request must carry URL.Host")
		}
		rec = httptest.NewRecorder()
		if routeProxyListenerBuiltin(rec, proxied) {
			t.Errorf("proxied absolute-URI request to origin.example%s must fall through to handleRequest, not be hijacked by the local handler (got body=%s)", path, rec.Body.String())
		}
	}
}

// ─── Concurrent mutation safety (Palo QA #1, #12) ──────────────────────────────

func TestPACProfilesAPI_ConcurrentMutationsNoLostUpdate(t *testing.T) {
	resetPACProfilesGlobals(t)
	// Seed a pool so profiles validate.
	if err := pacProfiles.Set(pac.ProfilesConfig{
		Pools: []pac.Pool{{ID: "p", Name: "P", Endpoints: []pac.PoolEndpoint{{Host: "x.example", Port: 8080}}}},
	}); err != nil {
		t.Fatal(err)
	}
	const n = 12
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := fmt.Sprintf(`{"id":"prof-%02d","name":"P%02d","enabled":true,"poolId":"p","privateNetworks":"proxy","availabilityMode":"balanced"}`, i, i)
			// 2F-A: every create echoes the collection token it loaded, so
			// concurrent creates are serialized by the fence — a loser gets a
			// structured 409 and, like any well-formed client, reloads and
			// retries. The property under test is unchanged: no create that
			// was ACCEPTED is ever lost.
			var rec *httptest.ResponseRecorder
			for attempt := 0; attempt < 200; attempt++ {
				rec = pacAPIReq(t, http.MethodPost, "/api/pac/profiles", body, RoleAdmin, fmt.Sprintf("198.51.100.%d:0", 100+i))
				if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), `"stale"`) {
					break
				}
			}
			if rec.Code != http.StatusOK {
				t.Errorf("concurrent create %d: %d (%s)", i, rec.Code, rec.Body.String())
			}
		}(i)
	}
	wg.Wait()
	// Every successful create must survive — no lost updates from the RMW.
	got := pacProfiles.Get()
	if len(got.Profiles) != n {
		t.Errorf("lost update: expected %d profiles, got %d", n, len(got.Profiles))
	}
}

// ─── Optimistic concurrency (Palo API #1) ──────────────────────────────────────

func TestPACProfilesAPI_StaleRevisionRejected(t *testing.T) {
	resetPACProfilesGlobals(t)
	if err := pacProfiles.Set(pac.ProfilesConfig{
		Profiles: []pac.Profile{{ID: "hq", Name: "HQ", Enabled: true, PoolID: "p",
			PrivateNetworks: pac.PrivateProxy, AvailabilityMode: pac.ModeBalanced, Revision: 5}},
		Pools: []pac.Pool{{ID: "p", Name: "P", Endpoints: []pac.PoolEndpoint{{Host: "x.example", Port: 8080}}}},
	}); err != nil {
		t.Fatal(err)
	}
	// Stale revision (3 != current 5) → 409.
	rec := pacAPIReq(t, http.MethodPut, "/api/pac/profiles/hq",
		`{"name":"HQ","enabled":true,"poolId":"p","privateNetworks":"proxy","availabilityMode":"balanced","revision":3}`,
		RoleAdmin, "198.51.100.80:0")
	if rec.Code != http.StatusConflict {
		t.Errorf("stale revision must 409, got %d", rec.Code)
	}
	// Correct revision (5) → OK, bumps to 6.
	rec = pacAPIReq(t, http.MethodPut, "/api/pac/profiles/hq",
		`{"name":"HQ2","enabled":true,"poolId":"p","privateNetworks":"proxy","availabilityMode":"balanced","revision":5}`,
		RoleAdmin, "198.51.100.80:0")
	if rec.Code != http.StatusOK {
		t.Fatalf("matching revision must succeed, got %d (%s)", rec.Code, rec.Body.String())
	}
	if p, _ := pacProfiles.ProfileByID("hq"); p.Revision != 6 {
		t.Errorf("revision must bump to 6, got %d", p.Revision)
	}
	// 2F-A: revision 0 no longer skips the check — an explicit zero token is
	// refused with 428 carrying the current revision, and nothing changes.
	rec = pacAPIReq(t, http.MethodPut, "/api/pac/profiles/hq",
		`{"name":"HQ3","enabled":true,"poolId":"p","privateNetworks":"proxy","availabilityMode":"balanced","revision":0}`,
		RoleAdmin, "198.51.100.80:0")
	if rec.Code != http.StatusPreconditionRequired || !strings.Contains(rec.Body.String(), `"revision":6`) {
		t.Errorf("revision 0 must be refused with 428 + current revision, got %d (%s)", rec.Code, rec.Body.String())
	}
	if p, _ := pacProfiles.ProfileByID("hq"); p.Name != "HQ2" {
		t.Errorf("refused zero-token PUT must not mutate: name=%q", p.Name)
	}
}

// ─── HEAD + 304 on the profile endpoint (Palo QA #4) ───────────────────────────

func TestServePACProfileFile_HeadAnd304(t *testing.T) {
	resetPACProfilesGlobals(t)
	seedProfilesConfig(t)

	get := httptest.NewRequest(http.MethodGet, "/pac/branch-il.pac", http.NoBody)
	rec := httptest.NewRecorder()
	servePACProfileFile(rec, get)
	etag := rec.Header().Get("ETag")
	if etag == "" || rec.Code != http.StatusOK {
		t.Fatalf("expected 200 + ETag, got %d %q", rec.Code, etag)
	}

	// HEAD: headers, no body.
	head := httptest.NewRequest(http.MethodHead, "/pac/branch-il.pac", http.NoBody)
	rec = httptest.NewRecorder()
	servePACProfileFile(rec, head)
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Errorf("HEAD must return 200 with no body, got %d len=%d", rec.Code, rec.Body.Len())
	}
	if rec.Header().Get("ETag") != etag {
		t.Error("HEAD must carry the same ETag")
	}

	// Conditional GET → 304.
	cond := httptest.NewRequest(http.MethodGet, "/pac/branch-il.pac", http.NoBody)
	cond.Header.Set("If-None-Match", etag)
	rec = httptest.NewRecorder()
	servePACProfileFile(rec, cond)
	if rec.Code != http.StatusNotModified {
		t.Errorf("matching If-None-Match must 304, got %d", rec.Code)
	}
}

// ─── DP-local mutation gate (Palo ops #3) ──────────────────────────────────────

func TestPACProfilesAPI_DataPlaneMutationBlocked(t *testing.T) {
	resetPACProfilesGlobals(t)
	clusterRoleMu.Lock()
	prev := clusterRole.role
	clusterRole.role = "data-plane"
	clusterRoleMu.Unlock()
	t.Cleanup(func() {
		clusterRoleMu.Lock()
		clusterRole.role = prev
		clusterRoleMu.Unlock()
	})

	rec := pacAPIReq(t, http.MethodPost, "/api/pac/pools",
		`{"id":"x","name":"X","endpoints":[{"host":"p.example","port":8080}]}`, RoleAdmin, "198.51.100.90:0")
	if rec.Code != http.StatusConflict {
		t.Errorf("DP-local pool mutation must be 409 (CP-managed), got %d", rec.Code)
	}
	// Reads still work on a DP.
	rec = pacAPIReq(t, http.MethodGet, "/api/pac/profiles", "", RoleViewer, "198.51.100.90:0")
	if rec.Code != http.StatusOK {
		t.Errorf("DP read must still work, got %d", rec.Code)
	}
}

// ─── Import replace-mode for profiles (Palo QA #3) ─────────────────────────────

func TestConfigImport_PACProfilesReplaceMode(t *testing.T) {
	resetPACProfilesGlobals(t)
	// Pre-existing state that replace mode must overwrite.
	if err := pacProfiles.Set(pac.ProfilesConfig{
		Profiles: []pac.Profile{{ID: "old", Name: "Old", Enabled: true, PoolID: "oldp",
			PrivateNetworks: pac.PrivateProxy, AvailabilityMode: pac.ModeBalanced}},
		Pools: []pac.Pool{{ID: "oldp", Name: "OldP", Endpoints: []pac.PoolEndpoint{{Host: "old.example", Port: 8080}}}},
	}); err != nil {
		t.Fatal(err)
	}
	body := `{"version":1,"pacProfiles":[{"id":"new","name":"New","enabled":true,"poolId":"newp","privateNetworks":"proxy","availabilityMode":"balanced"}],"pacPools":[{"id":"newp","name":"NewP","endpoints":[{"host":"new.example","port":8080}]}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/config/import?mode=replace", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.91:0"
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleAdmin))
	rec := httptest.NewRecorder()
	apiConfigImport(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("replace import: %d (%s)", rec.Code, rec.Body.String())
	}
	got := pacProfiles.Get()
	if len(got.Profiles) != 1 || got.Profiles[0].ID != "new" {
		t.Errorf("replace mode must swap the whole set, got %+v", got.Profiles)
	}
	if len(got.Pools) != 1 || got.Pools[0].ID != "newp" {
		t.Errorf("replace mode must swap pools, got %+v", got.Pools)
	}
}
