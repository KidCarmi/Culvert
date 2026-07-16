package main

// autoexclude_tunables_api_test.go — F10 PR3: the admin API for the auto-exclusion
// tunables (the first reachable-by-product surface). Covers RBAC, malformed input,
// partial patches, reset-to-default, and the consistency model (persist failure ⇒
// rollback, no runtime/disk divergence).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/autoexclude"
)

// TestTunablesAPI_MethodNotAllowed — anything but GET/PUT is 405.
func TestTunablesAPI_MethodNotAllowed(t *testing.T) {
	swapAutoExclude(t, autoexclude.Config{})
	if w := callTunables(RoleAdmin, http.MethodPost, nil); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: got %d, want 405", w.Code)
	}
}

func callTunables(role UIRole, method string, body any) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	apiDecryptionExclusionTunables(w, roleReq(role, method, "/api/decryption-exclusions/tunables", body))
	return w
}

// TestTunablesAPI_GET_DefaultsAndBoundsOnly — GET (viewer) returns defaults + bounds
// + schema, and does NOT duplicate the current effective values (those stay on the
// existing Stats surface — single source of truth).
func TestTunablesAPI_GET_DefaultsAndBoundsOnly(t *testing.T) {
	swapAutoExclude(t, autoexclude.Config{})
	w := callTunables(RoleViewer, http.MethodGet, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET viewer: got %d, want 200", w.Code)
	}
	var resp map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := resp["defaults"]; !ok {
		t.Error("GET must include defaults")
	}
	if _, ok := resp["bounds"]; !ok {
		t.Error("GET must include bounds")
	}
	// Must NOT re-emit live values under a 'current'/'stats' key (single source of truth).
	for _, k := range []string{"current", "stats", "active", "pending"} {
		if _, ok := resp[k]; ok {
			t.Errorf("GET must not duplicate current values (found key %q)", k)
		}
	}
}

// TestTunablesAPI_RBAC — GET=viewer, PUT=admin; lower roles are rejected 403.
func TestTunablesAPI_RBAC(t *testing.T) {
	swapAutoExclude(t, autoexclude.Config{})
	path := filepath.Join(t.TempDir(), "admin_settings.json")
	swapAdminSettingsPath(t, path)

	if w := callTunables(RoleViewer, http.MethodGet, nil); w.Code != http.StatusOK {
		t.Errorf("GET viewer: got %d, want 200", w.Code)
	}
	body := autoExcludeTunables{ConfirmN: 3, TTLSecs: 3600, PinnedTTLSecs: 600, WindowSecs: 300, MaxEntries: 1000}
	for _, role := range []UIRole{RoleViewer, RoleOperator} {
		if w := callTunables(role, http.MethodPut, body); w.Code != http.StatusForbidden {
			t.Errorf("PUT as %v: got %d, want 403 (admin-only)", role, w.Code)
		}
	}
	if w := callTunables(RoleAdmin, http.MethodPut, body); w.Code != http.StatusOK {
		t.Errorf("PUT admin: got %d, want 200", w.Code)
	}
}

// TestTunablesAPI_PUT_AppliesAndPersists — a valid PUT applies to the live cache and
// persists (sentinel + values on disk).
func TestTunablesAPI_PUT_AppliesAndPersists(t *testing.T) {
	swapAutoExclude(t, autoexclude.Config{})
	path := filepath.Join(t.TempDir(), "admin_settings.json")
	swapAdminSettingsPath(t, path)

	w := callTunables(RoleAdmin, http.MethodPut, customTunables)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT: got %d, want 200 (body %s)", w.Code, w.Body)
	}
	if got := currentAutoExcludeTunables(); got != customTunables {
		t.Fatalf("runtime not applied: %+v, want %+v", got, customTunables)
	}
	var s AdminSettings
	data, _ := os.ReadFile(path)
	if json.Unmarshal(data, &s) != nil || !s.AutoExcludeTunablesSaved || s.AutoExcludeConfirmN != 4 {
		t.Fatalf("not persisted: %+v", s)
	}
}

// TestTunablesAPI_PUT_MalformedAndOutOfBounds — invalid JSON and out-of-range values
// are 400, and an out-of-bounds PUT does NOT change the live cache.
func TestTunablesAPI_PUT_MalformedAndOutOfBounds(t *testing.T) {
	swapAutoExclude(t, autoexclude.Config{})
	path := filepath.Join(t.TempDir(), "admin_settings.json")
	swapAdminSettingsPath(t, path)
	before := currentAutoExcludeTunables()

	// Malformed JSON body ⇒ 400.
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/api/decryption-exclusions/tunables", strings.NewReader("{bad json"))
	r = r.WithContext(context.WithValue(r.Context(), uiRoleKey{}, RoleAdmin))
	apiDecryptionExclusionTunables(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("malformed JSON: got %d, want 400", w.Code)
	}

	// confirm_n=1 (defeats anti-poison) ⇒ 400, runtime unchanged.
	if w := callTunables(RoleAdmin, http.MethodPut, autoExcludeTunables{ConfirmN: 1, TTLSecs: 3600, PinnedTTLSecs: 600, WindowSecs: 300, MaxEntries: 1000}); w.Code != http.StatusBadRequest {
		t.Errorf("confirm_n=1: got %d, want 400", w.Code)
	}
	if got := currentAutoExcludeTunables(); got != before {
		t.Errorf("out-of-bounds PUT changed the live cache: %+v", got)
	}
}

// TestTunablesAPI_PUT_PartialPatchResetsOmitted — a partial PUT resets omitted/zero
// fields to their defaults (full-set replacement semantic; zero ⇒ default).
func TestTunablesAPI_PUT_PartialPatchResetsOmitted(t *testing.T) {
	swapAutoExclude(t, autoexclude.Config{})
	swapAdminSettingsPath(t, filepath.Join(t.TempDir(), "admin_settings.json"))
	d := defaultAutoExcludeTunables()

	// Only confirm_n set ⇒ everything else resets to default.
	if w := callTunables(RoleAdmin, http.MethodPut, autoExcludeTunables{ConfirmN: 6}); w.Code != http.StatusOK {
		t.Fatalf("partial PUT: got %d", w.Code)
	}
	got := currentAutoExcludeTunables()
	if got.ConfirmN != 6 || got.TTLSecs != d.TTLSecs || got.MaxEntries != d.MaxEntries {
		t.Fatalf("partial PUT did not reset omitted fields to default: %+v", got)
	}

	// A partial that makes pinned(default 1h) > ttl(30m) is rejected.
	if w := callTunables(RoleAdmin, http.MethodPut, autoExcludeTunables{TTLSecs: 1800}); w.Code != http.StatusBadRequest {
		t.Fatalf("partial pinned>ttl: got %d, want 400", w.Code)
	}
}

// TestTunablesAPI_PUT_ResetToDefault — PUT all-zeros restores every default.
func TestTunablesAPI_PUT_ResetToDefault(t *testing.T) {
	swapAutoExclude(t, autoexclude.Config{ConfirmN: 7, MaxEntries: 5000})
	swapAdminSettingsPath(t, filepath.Join(t.TempDir(), "admin_settings.json"))

	if w := callTunables(RoleAdmin, http.MethodPut, autoExcludeTunables{}); w.Code != http.StatusOK {
		t.Fatalf("reset PUT: got %d", w.Code)
	}
	if got := currentAutoExcludeTunables(); got != defaultAutoExcludeTunables() {
		t.Fatalf("reset-to-default PUT did not restore defaults: %+v", got)
	}
}

// TestTunablesAPI_PUT_PersistFailureRollsBack — the consistency model: if the
// durable write fails after the runtime was applied, the runtime is rolled back so
// runtime and disk agree (both the OLD value). A 500 is returned; nothing diverges.
func TestTunablesAPI_PUT_PersistFailureRollsBack(t *testing.T) {
	swapAutoExclude(t, autoexclude.Config{}) // engine at defaults
	before := currentAutoExcludeTunables()
	// Point persistence at a path whose parent does not exist ⇒ AtomicWrite fails.
	swapAdminSettingsPath(t, filepath.Join(t.TempDir(), "missing-dir", "admin_settings.json"))

	w := callTunables(RoleAdmin, http.MethodPut, customTunables)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("persist failure: got %d, want 500", w.Code)
	}
	if got := currentAutoExcludeTunables(); got != before {
		t.Fatalf("runtime not rolled back after persist failure: got %+v, want %+v (no runtime/disk divergence)", got, before)
	}
}

// TestTunablesAPI_RuntimeApplyIsInfallible documents the transaction model's one
// asymmetry: Reconfigure cannot fail (it always yields a valid state), so a
// "runtime-application failure" is unreachable — the only divergence risk is
// persistence, covered by TestTunablesAPI_PUT_PersistFailureRollsBack. This test
// pins that a valid apply never errors the request even at the bounds extremes.
func TestTunablesAPI_RuntimeApplyIsInfallible(t *testing.T) {
	swapAutoExclude(t, autoexclude.Config{})
	swapAdminSettingsPath(t, filepath.Join(t.TempDir(), "admin_settings.json"))
	// Extremes of the valid range apply cleanly.
	extreme := autoExcludeTunables{
		ConfirmN: autoExcludeConfirmNMax, TTLSecs: autoExcludeTTLSecsMax,
		PinnedTTLSecs: autoExcludeTTLSecsMax, WindowSecs: autoExcludeWindowSecsMax,
		MaxEntries: autoExcludeMaxEntriesMax,
	}
	if w := callTunables(RoleAdmin, http.MethodPut, extreme); w.Code != http.StatusOK {
		t.Fatalf("valid extreme PUT: got %d, want 200", w.Code)
	}
}
