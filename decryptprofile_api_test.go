package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/decryptprofile"
)

// swapDecProfileStore installs a fresh store for a test and restores it.
func swapDecProfileStore(t *testing.T) {
	t.Helper()
	prev := globalDecryptionProfiles
	globalDecryptionProfiles = decryptprofile.New()
	t.Cleanup(func() { globalDecryptionProfiles = prev })
}

// TestSeedDefaultDecryptionProfiles pins the on-ramp seed (non-auto-bound).
func TestSeedDefaultDecryptionProfiles(t *testing.T) {
	swapDecProfileStore(t)
	seedDefaultDecryptionProfiles()
	p := globalDecryptionProfiles.GetByName("recommended-h2")
	if p == nil || p.InspectHTTP2 == nil || !*p.InspectHTTP2 {
		t.Fatalf("recommended-h2 seed missing or not Inspect-as-HTTP/2: %+v", p)
	}
	// It is NOT bound to any rule (nothing references it by construction).
	found, refs := objectReferences("decryption-profile", "recommended-h2")
	if !found || len(refs) != 0 {
		t.Fatalf("seed must be non-auto-bound: found=%v refs=%v", found, refs)
	}
}

// TestApiDecryptionProfiles_Validation confirms the engine validation surfaces as a
// 400 through the handler (not just the store), covering the config-import/apply
// bypass concern the UI/security reviewer raised.
func TestApiDecryptionProfiles_Validation(t *testing.T) {
	swapDecProfileStore(t)
	// Invalid enum → 400.
	req := httptest.NewRequest(http.MethodPost, "/api/decryption-profiles", strings.NewReader(`{"name":"bad","minTlsVersion":"9.9"}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleOperator))
	rw := httptest.NewRecorder()
	apiDecryptionProfiles(rw, req)
	if rw.Code != http.StatusBadRequest {
		t.Fatalf("invalid profile: status = %d, want 400", rw.Code)
	}
	if globalDecryptionProfiles.GetByName("bad") != nil {
		t.Fatal("invalid profile must not be stored")
	}
}
