package main

// config_import_pac_direct_test.go — regression guard for the security fix that
// extended the DIRECT (full security-path bypass) typed-confirmation guardrail to
// the config-IMPORT path.
//
// Before the fix, POST /api/config/import installed PAC steering profiles behind
// only a STRUCTURAL validation check. The interactive CRUD/publish/rollback paths
// all demand a typed DIRECT confirmation before a profile that routes traffic
// DIRECT (evading TLS inspection + policy) can go live, but import — the path most
// likely to carry untrusted / hand-edited backup content, and one that then
// cluster-syncs to every DP — skipped that gate entirely. The fix rejects a
// DIRECT-introducing import fail-closed unless the admin opts in with
// confirmDirect=true.

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/KidCarmi/Culvert/internal/pac"
)

func pacDirectImportIsolate(t *testing.T) {
	t.Helper()
	op := pacProfiles.Snapshot()
	t.Cleanup(func() { pacProfiles.Restore(op) })
	snapshotConfigVersionsDir(t)
	// Start from an empty PAC profile/pool set so any imported DIRECT profile is
	// unambiguously NEW relative to the live state.
	if err := pacProfiles.Set(pac.ProfilesConfig{}); err != nil {
		t.Fatalf("reset pacProfiles: %v", err)
	}
}

// directImportBackup is a version-1 backup carrying one ENABLED availability-mode
// profile (availability appends DIRECT to the terminal chain) and its pool.
func directImportBackup() map[string]any {
	return map[string]any{
		"version": 1,
		"pacPools": []map[string]any{
			{"id": "main", "name": "main", "endpoints": []map[string]any{{"host": "p.example", "port": 8080}}},
		},
		"pacProfiles": []map[string]any{
			{"id": "hq", "name": "HQ", "enabled": true, "poolId": "main",
				"privateNetworks": "proxy", "availabilityMode": "availability"},
		},
	}
}

// TestConfigImport_DirectProfileRequiresConfirm: an import that newly makes DIRECT
// reachable is rejected with 409 and does not mutate the store.
func TestConfigImport_DirectProfileRequiresConfirm(t *testing.T) {
	pacDirectImportIsolate(t)

	w := httptest.NewRecorder()
	apiConfigImport(w, jsonReq("POST", "/api/config/import", directImportBackup()))
	if w.Code != 409 {
		t.Fatalf("DIRECT-introducing import without confirmDirect: status = %d, want 409; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		NewDirectPaths []string `json:"newDirectPaths"`
		ConfirmField   string   `json:"confirmField"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode 409 body: %v", err)
	}
	if len(resp.NewDirectPaths) == 0 {
		t.Error("409 body must enumerate the newly-introduced DIRECT paths")
	}
	if resp.ConfirmField != "confirmDirect" {
		t.Errorf("409 body confirmField = %q, want confirmDirect", resp.ConfirmField)
	}
	// Fail-closed: nothing installed.
	if _, ok := pacProfiles.ProfileByID("hq"); ok {
		t.Fatal("a refused DIRECT import must NOT install the profile")
	}
}

// TestConfigImport_DirectProfileConfirmed: with confirmDirect=true the same import
// is accepted and the profile is installed.
func TestConfigImport_DirectProfileConfirmed(t *testing.T) {
	pacDirectImportIsolate(t)

	w := httptest.NewRecorder()
	apiConfigImport(w, jsonReq("POST", "/api/config/import?confirmDirect=true", directImportBackup()))
	if w.Code != 200 {
		t.Fatalf("confirmed DIRECT import: status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if _, ok := pacProfiles.ProfileByID("hq"); !ok {
		t.Fatal("confirmed DIRECT import must install the profile")
	}
}

// TestConfigImport_DisabledDirectProfileNoConfirm: importing the same DIRECT
// profile DISABLED introduces no reachable bypass (servePACProfileFile 404s a
// disabled profile), so no confirmation is demanded — the guardrail adds no
// friction where none is due.
func TestConfigImport_DisabledDirectProfileNoConfirm(t *testing.T) {
	pacDirectImportIsolate(t)

	b := directImportBackup()
	b["pacProfiles"].([]map[string]any)[0]["enabled"] = false

	w := httptest.NewRecorder()
	apiConfigImport(w, jsonReq("POST", "/api/config/import", b))
	if w.Code != 200 {
		t.Fatalf("disabled DIRECT import: status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if _, ok := pacProfiles.ProfileByID("hq"); !ok {
		t.Fatal("disabled DIRECT import should still install (just not reachable)")
	}
}
