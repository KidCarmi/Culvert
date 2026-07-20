package main

// Runtime conformance for the M6 support endpoints reconciled from main during
// the final OpenAPI landing: GET /api/support/tac-trust, GET/PUT
// /api/support/upload/config. These exercise the REAL handlers (not just the
// schema) for the highest-risk newly-documented surface: TAC recipient trust and
// the support-bundle upload posture. All writes go to a per-test temp dataDir so
// nothing touches real state and there is no outbound network.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// This suite reuses the package-level withTempDataDir(t) helper (fileblock_startup_test.go),
// which points dataDir at a throwaway directory for the test so handlers that
// persist local JSON (upload config) are rollback-safe.

// GET responses conform through the real handlers (read-only).
func TestConformance_M6_Response(t *testing.T) {
	withTempDataDir(t)
	// TAC trust set (viewer) — public key material only; with no env keys the
	// handler returns configured=false + an empty list, which must still conform.
	assertResponseConforms(t, http.MethodGet, "/api/support/tac-trust", apiSupportTACTrust)
	// Upload posture (viewer) — default not_enabled.
	assertResponseConforms(t, http.MethodGet, "/api/support/upload/config", apiSupportUploadConfig)
	// Upload queue (viewer) — empty queue still conforms to UploadQueue.
	assertResponseConforms(t, http.MethodGet, "/api/support/uploads", apiSupportUploads)
}

// The per-bundle upload consent body validates against the contract (the POST
// path is a high-risk egress op; its request shape is pinned here without driving
// the many-precondition handler).
func TestConformance_M6_UploadConsent_Request(t *testing.T) {
	spec := loadContract(t)
	path := "/api/support/bundles/{id}/upload"
	if err := spec.ValidateJSONRequest(http.MethodPost, path, []byte(`{"case_id":"00123456","confirm":true}`)); err != nil {
		t.Fatalf("valid consent body rejected: %v", err)
	}
	for _, bad := range []string{
		`{"confirm":true}`,                         // missing required case_id
		`{"case_id":"x"}`,                          // missing required confirm
		`{"case_id":"x","confirm":true,"bogus":1}`, // unknown field
		`{"case_id":"x","confirm":"yes"}`,          // wrong type
	} {
		if err := spec.ValidateJSONRequest(http.MethodPost, path, []byte(bad)); err == nil {
			t.Fatalf("contract accepted invalid consent body: %s", bad)
		}
	}
}

// PUT request bodies validate against the contract (unknown fields, wrong types).
func TestConformance_M6_UploadConfig_Request(t *testing.T) {
	spec := loadContract(t)
	good := []string{
		`{"enabled":false}`,
		`{"enabled":true,"origin":"https://tac.example.com/upload"}`,
		`{}`,
	}
	for _, g := range good {
		if err := spec.ValidateJSONRequest(http.MethodPut, "/api/support/upload/config", []byte(g)); err != nil {
			t.Fatalf("valid upload-config body rejected: %s -> %v", g, err)
		}
	}
	bad := []string{
		`{"enabled":"yes"}`,          // wrong type
		`{"enabled":true,"bogus":1}`, // unknown field (additionalProperties:false)
		`{"origin":123}`,             // wrong type
	}
	for _, b := range bad {
		if err := spec.ValidateJSONRequest(http.MethodPut, "/api/support/upload/config", []byte(b)); err == nil {
			t.Fatalf("contract accepted invalid upload-config body: %s", b)
		}
	}
}

// The real PUT handler (admin) accepts a bare disable, persists to the temp
// dataDir, and its 200 response conforms; an enable without an origin is rejected
// 400 exactly as documented.
func TestConformance_M6_UploadConfig_PUT_Handler(t *testing.T) {
	withTempDataDir(t)
	spec := loadContract(t)

	// Bare disable — always allowed; response must conform.
	rec := httptest.NewRecorder()
	req := withRole(httptest.NewRequestWithContext(context.Background(), http.MethodPut,
		"/api/support/upload/config", strings.NewReader(`{"enabled":false}`)), RoleAdmin)
	apiSupportUploadConfig(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("disable PUT: status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if err := spec.ValidateJSONResponse(http.MethodPut, "/api/support/upload/config", 200, rec.Body.Bytes()); err != nil {
		t.Fatalf("disable PUT response violates contract: %v\nbody: %s", err, rec.Body.String())
	}

	// Enable without an origin — documented 400.
	rec = httptest.NewRecorder()
	req = withRole(httptest.NewRequestWithContext(context.Background(), http.MethodPut,
		"/api/support/upload/config", strings.NewReader(`{"enabled":true}`)), RoleAdmin)
	apiSupportUploadConfig(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("enable-without-origin PUT: status = %d, want 400 (body: %s)", rec.Code, rec.Body.String())
	}
}

// RBAC: the write posture is admin-only; a viewer PUT is denied (defense in depth
// in the handler, matching the manifest min_role=admin the coverage gate binds).
func TestConformance_M6_Authz(t *testing.T) {
	withTempDataDir(t)
	rec := httptest.NewRecorder()
	req := withRole(httptest.NewRequestWithContext(context.Background(), http.MethodPut,
		"/api/support/upload/config", strings.NewReader(`{"enabled":false}`)), RoleViewer)
	apiSupportUploadConfig(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("viewer PUT upload-config: status = %d, want 403", rec.Code)
	}
	// A viewer PUT to tac-trust is method-not-allowed (GET-only), never a write.
	rec = httptest.NewRecorder()
	req = withRole(httptest.NewRequestWithContext(context.Background(), http.MethodPut,
		"/api/support/tac-trust", http.NoBody), RoleAdmin)
	apiSupportTACTrust(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT tac-trust: status = %d, want 405", rec.Code)
	}
}
