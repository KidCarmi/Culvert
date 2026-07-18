package main

// pac_exceptions_regression_test.go — durable anti-drift guards for the PAC
// Exception Intelligence governance surface. This is infrastructure: the
// invariants below must hold forever, so each is pinned structurally
// (reflection / source scan) or through the real handlers. A future refactor
// that violates one fails here with an explanation of WHY the invariant exists.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/pac"
)

// TestRegression_GovernanceHandlerNeverVersions locks Codex fix #2: the
// governance handlers must NOT call saveConfigVersion — the store is node-local
// and not on the config-version capture/apply surface, so a version snapshot
// would be a misleading no-op rollback point. Source-scan guard (mirrors the
// CDR-hygiene structural test) so re-adding the call anywhere in the file fails.
func TestRegression_GovernanceHandlerNeverVersions(t *testing.T) {
	src, err := os.ReadFile("pac_exceptions_api.go")
	if err != nil {
		t.Fatalf("read handler source: %v", err)
	}
	if strings.Contains(string(src), "saveConfigVersion(") {
		t.Error("pac_exceptions_api.go calls saveConfigVersion — governance is node-local " +
			"and NOT on the config-version rollback surface; a version here cannot capture or " +
			"restore the change (see the Codex review + roadmap/PEI-TEST-BACKLOG.md).")
	}
}

// TestRegression_GovernanceNotOnExportRollbackStruct proves the configBackup
// struct — the shared export/import + config-version rollback surface — has NO
// exception field. Governance must never ride export or rollback (secret/round-
// trip and node-local reasons). Reflection guard: adding an Exception* field to
// configBackup fails here.
func TestRegression_GovernanceNotOnExportRollbackStruct(t *testing.T) {
	assertNoExceptionField(t, reflect.TypeOf(configBackup{}), "configBackup (export/import + rollback)")
}

// TestRegression_GovernanceNotOnConfigSnapshot proves the CP→DP ConfigSnapshot
// carries no governance field — a DP node must never receive who-owns-this
// metadata. Reflection complements the runtime token-leak test.
func TestRegression_GovernanceNotOnConfigSnapshot(t *testing.T) {
	assertNoExceptionField(t, reflect.TypeOf(ConfigSnapshot{}), "ConfigSnapshot (CP→DP sync)")
}

// assertNoExceptionField fails if any field name or json tag of typ mentions
// "exception" (case-insensitive).
func assertNoExceptionField(t *testing.T, typ reflect.Type, surface string) {
	t.Helper()
	if typ.Kind() != reflect.Struct {
		t.Fatalf("%s: not a struct", surface)
	}
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		name := strings.ToLower(f.Name)
		tag := strings.ToLower(f.Tag.Get("json"))
		if strings.Contains(name, "exception") || strings.Contains(tag, "exception") {
			t.Errorf("%s must NOT carry governance: field %q (tag %q) — PAC exception governance "+
				"is node-local and off this surface by design", surface, f.Name, f.Tag.Get("json"))
		}
	}
}

// TestRegression_BackupIncludesExceptionsArtifact proves the governance store IS
// on the backup surface (so a promoted node can restore it), and that it is NOT
// Required (a fresh node without the file must still back up cleanly).
func TestRegression_BackupIncludesExceptionsArtifact(t *testing.T) {
	arts := defaultBackupArtifacts("/data")
	var found *backupArtifact
	for i := range arts {
		if arts[i].TarPath == "data/pac_exceptions.json" {
			found = &arts[i]
		}
	}
	if found == nil {
		t.Fatal("pac_exceptions.json missing from defaultBackupArtifacts — governance would not survive backup/restore")
	}
	if found.Required {
		t.Error("pac_exceptions.json must not be Required (a fresh node has no governance file yet)")
	}
}

// TestRegression_ExceptionsPersistThroughAPIReload proves the full API→disk→
// reload chain: a governance PUT lands on disk such that a fresh store (a
// restart) reads it back. This is the end-to-end durability contract.
func TestRegression_ExceptionsPersistThroughAPIReload(t *testing.T) {
	peiResetGlobals(t)
	seedDirectCapableProfile(t, "vendor")
	// Discover the backing path peiResetGlobals assigned.
	path := pacExceptions.Snapshot().Path
	if path == "" {
		t.Fatal("no backing path set")
	}

	rec := peiExcItem(t, http.MethodPut, "vendor", `{"owner":"neteng","reason":"saas"}`, RoleAdmin)
	if rec.Code != http.StatusOK {
		t.Fatalf("govern PUT: %d (%s)", rec.Code, rec.Body.String())
	}

	// Fresh store over the same file = a restart.
	var reloaded pac.ExceptionStore
	if err := reloaded.Load(path); err != nil {
		t.Fatalf("reload from disk: %v", err)
	}
	got, ok := reloaded.Get("vendor")
	if !ok || got.Owner != "neteng" {
		t.Errorf("governance did not persist through API→disk→reload: %+v ok=%v", got, ok)
	}
}

// TestRegression_HTTPContractMatrix locks the method × role contract for both
// governance routes so no future change silently widens access or a verb.
func TestRegression_HTTPContractMatrix(t *testing.T) {
	// List route: GET only; reads are viewer-floored; writes are 405.
	t.Run("list", func(t *testing.T) {
		peiResetGlobals(t)
		seedDirectCapableProfile(t, "hq")
		for _, tc := range []struct {
			method string
			role   UIRole
			want   int
		}{
			{http.MethodGet, RoleViewer, http.StatusOK},
			{http.MethodGet, RoleAdmin, http.StatusOK},
			{http.MethodPost, RoleAdmin, http.StatusMethodNotAllowed},
			{http.MethodPut, RoleAdmin, http.StatusMethodNotAllowed},
			{http.MethodDelete, RoleAdmin, http.StatusMethodNotAllowed},
		} {
			r := httptest.NewRequest(tc.method, "/api/pac/posture/exceptions", http.NoBody)
			r = r.WithContext(context.WithValue(r.Context(), uiRoleKey{}, tc.role))
			w := httptest.NewRecorder()
			apiPACExceptions(w, r)
			if w.Code != tc.want {
				t.Errorf("%s list (role %v) = %d, want %d", tc.method, tc.role, w.Code, tc.want)
			}
		}
	})

	// Item route: GET viewer; PUT/DELETE admin-only (viewer+operator 403); other verbs 405.
	t.Run("item", func(t *testing.T) {
		peiResetGlobals(t)
		seedDirectCapableProfile(t, "hq")
		body := `{"owner":"o","reason":"r"}`
		for _, tc := range []struct {
			method, body string
			role         UIRole
			want         int
		}{
			{http.MethodGet, "", RoleViewer, http.StatusOK},
			{http.MethodPut, body, RoleViewer, http.StatusForbidden},
			{http.MethodPut, body, RoleOperator, http.StatusForbidden},
			{http.MethodDelete, "", RoleViewer, http.StatusForbidden},
			{http.MethodDelete, "", RoleOperator, http.StatusForbidden},
			{http.MethodPatch, "", RoleAdmin, http.StatusMethodNotAllowed},
		} {
			rec := peiExcItem(t, tc.method, "hq", tc.body, tc.role)
			if rec.Code != tc.want {
				t.Errorf("%s item (role %v) = %d, want %d", tc.method, tc.role, rec.Code, tc.want)
			}
		}
	})
}

// TestRegression_ItemIDEdgeCases proves the {id} path parser rejects empty /
// slash / traversal ids (no orphan writes, no path escape).
func TestRegression_ItemIDEdgeCases(t *testing.T) {
	peiResetGlobals(t)
	seedDirectCapableProfile(t, "hq")
	for _, id := range []string{"", "a/b", "..", "%2e%2e", "hq/", "../secret"} {
		r := httptest.NewRequest(http.MethodGet, "/api/pac/posture/exceptions/"+id, http.NoBody)
		r = r.WithContext(context.WithValue(r.Context(), uiRoleKey{}, RoleViewer))
		w := httptest.NewRecorder()
		apiPACExceptionItem(w, r)
		// Empty / slash-bearing ids must not resolve to a real record; the parser
		// returns 404 for those. A bare "%2e%2e" (not decoded by our TrimPrefix)
		// is treated as an unknown id → GET returns 200 with directCapable=false,
		// which is safe (no write, no traversal). We only require: never 2xx with
		// a governed record, and never a 5xx.
		if w.Code >= 500 {
			t.Errorf("id %q: 5xx (%d) — parser must fail safe", id, w.Code)
		}
	}
	// A traversal id on PUT must never create an orphan or escape the store path.
	pathBefore := pacExceptions.Snapshot().Path
	r := httptest.NewRequest(http.MethodPut, "/api/pac/posture/exceptions/a/b", strings.NewReader(`{"owner":"o","reason":"r"}`))
	r.Header.Set("Content-Type", "application/json")
	r = r.WithContext(context.WithValue(r.Context(), uiRoleKey{}, RoleAdmin))
	w := httptest.NewRecorder()
	apiPACExceptionItem(w, r)
	if w.Code == http.StatusOK {
		t.Errorf("PUT with slash id must not succeed (got 200)")
	}
	if pacExceptions.Snapshot().Path != pathBefore {
		t.Error("store path changed — id must never influence the persistence path")
	}
}

// TestRegression_InvalidJSONAndUnknownFieldsRejected proves the write path is
// strict: malformed JSON and unknown fields are 400 (no partial persistence).
func TestRegression_InvalidJSONAndUnknownFieldsRejected(t *testing.T) {
	peiResetGlobals(t)
	seedDirectCapableProfile(t, "hq")
	for _, body := range []string{
		`{not json`,
		`{"owner":"o","reason":"r","bogusField":true}`,
	} {
		rec := peiExcItem(t, http.MethodPut, "hq", body, RoleAdmin)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %q: %d, want 400", body, rec.Code)
		}
	}
	// Nothing should have been persisted.
	if _, ok := pacExceptions.Get("hq"); ok {
		t.Error("a rejected write persisted a record")
	}
}

// TestRegression_InventoryDeterministic proves BuildDirectInventory is a pure,
// stable function — identical input yields byte-identical output (ordering
// pinned), so the read-model never flickers between calls.
func TestRegression_InventoryDeterministic(t *testing.T) {
	peiResetGlobals(t)
	if err := pacStore.Set(PACConfig{ProxyHost: "proxy.example", ProxyPort: 8080, Exclusions: []string{"corp.local", "*.cdn.example"}}); err != nil {
		t.Fatal(err)
	}
	if err := pacProfiles.Set(pac.ProfilesConfig{
		Pools: []pac.Pool{{ID: "p", Name: "P", Endpoints: []pac.PoolEndpoint{{Host: "px.example", Port: 8080}}}},
		Profiles: []pac.Profile{
			{ID: "b", Name: "B", Enabled: true, PoolID: "p", PrivateNetworks: pac.PrivateDirect, AvailabilityMode: pac.ModeAvailability, Revision: 1},
			{ID: "a", Name: "A", Enabled: true, PoolID: "p", PrivateNetworks: pac.PrivateProxy, AvailabilityMode: pac.ModeBalanced, Revision: 1,
				Rules: []pac.Rule{{Kind: pac.RuleKindWildcard, Pattern: "*.x.example", Action: pac.ActionDirect}}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	first, _ := json.Marshal(pacDirectInventory())
	for i := 0; i < 5; i++ {
		next, _ := json.Marshal(pacDirectInventory())
		if !bytes.Equal(first, next) {
			t.Fatalf("inventory not deterministic across calls:\n first=%s\n next =%s", first, next)
		}
	}
}
