package main

// decryption_profile_id_addressing_test.go — the decryption-profile API supports
// rename-safe ?id= addressing for update and delete (P3 object-identity seam,
// mirroring the category-group ?id= path).

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func snapshotDecProfilesForTest(t *testing.T) {
	t.Helper()
	orig := globalDecryptionProfiles.List()
	t.Cleanup(func() { globalDecryptionProfiles.ReplaceAll(orig) })
	globalDecryptionProfiles.ReplaceAll(nil)
}

func TestApiDecryptionProfile_UpdateByID(t *testing.T) {
	snapshotDecProfilesForTest(t)
	snapshotConfigVersionsDir(t)
	p, err := globalDecryptionProfiles.Add(DecryptionProfile{Name: "prof", CertVerification: "strict"})
	if err != nil {
		t.Fatal(err)
	}
	if p.ID == "" {
		t.Fatal("added profile has no ID")
	}

	body := `{"name":"prof","certVerification":"skip"}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/api/decryption-profiles?id="+p.ID, strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	apiDecryptionProfiles(w, adminCtx(req))
	if w.Code != http.StatusOK {
		t.Fatalf("PUT ?id= returned %d (%s)", w.Code, w.Body.String())
	}
	got := globalDecryptionProfiles.GetByID(p.ID)
	if got == nil || got.CertVerification != "skip" {
		t.Errorf("update by id did not apply: %+v", got)
	}
}

func TestApiDecryptionProfile_DeleteByID(t *testing.T) {
	snapshotDecProfilesForTest(t)
	snapshotConfigVersionsDir(t)
	p, _ := globalDecryptionProfiles.Add(DecryptionProfile{Name: "prof-del"})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/api/decryption-profiles?id="+p.ID, http.NoBody)
	req.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	apiDecryptionProfiles(w, adminCtx(req))
	if w.Code != http.StatusOK {
		t.Fatalf("DELETE ?id= returned %d (%s)", w.Code, w.Body.String())
	}
	if globalDecryptionProfiles.GetByID(p.ID) != nil {
		t.Error("profile still present after delete by id")
	}
}

func TestApiDecryptionProfile_UpdateByID_NotFound(t *testing.T) {
	snapshotDecProfilesForTest(t)
	snapshotConfigVersionsDir(t)

	body := `{"name":"x"}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/api/decryption-profiles?id=deadbeef0000", strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	apiDecryptionProfiles(w, adminCtx(req))
	if w.Code != http.StatusNotFound {
		t.Errorf("PUT ?id= for unknown profile = %d, want 404", w.Code)
	}
}
