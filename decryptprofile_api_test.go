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

// TestDiffDecryptionProfiles_Changed pins that a same-name-different-content edit
// surfaces as "changed" (the diff comparator covers every operator field, incl.
// the *bool InspectHTTP2) — config-arch reviewer hardening.
func TestDiffDecryptionProfiles_Changed(t *testing.T) {
	on, off := true, false
	a := []DecryptionProfile{{Name: "p", InspectHTTP2: &on, MinTLSVersion: "1.2"}}
	b := []DecryptionProfile{{Name: "p", InspectHTTP2: &off, MinTLSVersion: "1.3"}}
	var changes []configChange
	diffDecryptionProfiles(a, b, &changes)
	if len(changes) != 1 || changes[0].Field != "decryption_profiles" {
		t.Fatalf("expected one decryption_profiles change, got %+v", changes)
	}
	// A no-op (identical content) must NOT diff.
	var none []configChange
	diffDecryptionProfiles(a, a, &none)
	if len(none) != 0 {
		t.Fatalf("identical profiles must not diff, got %+v", none)
	}
}

// TestDecryptionProfiles_EmptyWipePropagates pins the WireWipeCapable posture: a
// non-nil empty slice (what an empty CP store serializes with no omitempty) wipes
// the store, so deleting the last profile clears stale copies on DP nodes rather
// than leaving them to apply looser security settings than the CP intends.
func TestDecryptionProfiles_EmptyWipePropagates(t *testing.T) {
	swapDecProfileStore(t)
	on := true
	globalDecryptionProfiles.ReplaceAll([]DecryptionProfile{{Name: "stale", InspectHTTP2: &on}})
	if len(globalDecryptionProfiles.Names()) != 1 {
		t.Fatalf("seed failed")
	}
	// The CP→DP apply path is: if snap.DecryptionProfiles != nil { ReplaceAll }. A
	// non-nil empty slice (serialized because the field has NO omitempty) wipes.
	globalDecryptionProfiles.ReplaceAll([]DecryptionProfile{})
	if n := len(globalDecryptionProfiles.Names()); n != 0 {
		t.Fatalf("empty ReplaceAll must wipe the store, %d profiles remain", n)
	}
	// Registry declares the WireWipeCapable posture so the empty slice reaches the wire.
	var row *configSurfaceRow
	for i := range configSurfaces {
		if configSurfaces[i].ID == "decryption_profiles" {
			row = &configSurfaces[i]
		}
	}
	if row == nil || !row.WireWipeCapable {
		t.Fatal("decryption_profiles must be WireWipeCapable so the []-wipe propagates CP→DP")
	}
}
