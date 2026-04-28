package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ── apiPACConfig POST authorization ───────────────────────────────────────
//
// These tests pin the requireRole(RoleAdmin) check on apiPACConfig POST.
// Before the C1.5 follow-up audit (docs/C15_UNKNOWN_AUDIT.md §3.1), POST
// had NO role check, so any authenticated UI user — including a
// RoleViewer account — could rewrite PAC config and redirect every
// proxy client. The audit caught the gap; these tests pin the fix.
//
// The C1.5 metadata table already declared MinRole=RoleAdmin for
// /api/pac-config POST, so this commit aligns handler behavior with
// the documented contract. No metadata change.

// pacAuthzPostBody is a minimum-shape PAC config the handler accepts
// past JSON decoding so the test reaches the role check.
const pacAuthzPostBody = `{"proxyHost":"localhost","proxyPort":8080,"exclusions":[]}`

// pacAuthzPostReq builds a POST /api/pac-config request with the given
// role injected into the request context (mirrors what uiAuthMiddleware
// does after a successful session check). Each test uses a unique
// RemoteAddr so rate-limit state from other suites doesn't bleed in.
func pacAuthzPostReq(role UIRole, remoteIP string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/pac-config",
		bytes.NewReader([]byte(pacAuthzPostBody)))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = remoteIP
	ctx := context.WithValue(req.Context(), uiRoleKey{}, role)
	return req.WithContext(ctx)
}

// TestPACConfig_POST_RejectsViewer is the regression lock for the
// audit finding: a Viewer-role caller MUST receive 403 from the
// requireRole gate, and the handler MUST NOT call pacStore.Set().
func TestPACConfig_POST_RejectsViewer(t *testing.T) {
	req := pacAuthzPostReq(RoleViewer, "198.51.100.40:0")
	rec := httptest.NewRecorder()
	apiPACConfig(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("Viewer POST: got %d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestPACConfig_POST_RejectsOperator confirms the gate is admin-only,
// not "anyone above viewer". Operator must also be rejected.
func TestPACConfig_POST_RejectsOperator(t *testing.T) {
	req := pacAuthzPostReq(RoleOperator, "198.51.100.41:0")
	rec := httptest.NewRecorder()
	apiPACConfig(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("Operator POST: got %d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestPACConfig_POST_AcceptsAdmin is the positive-path counterpart:
// an Admin-role caller is NOT blocked by the new requireRole gate.
// The full handler logic runs (decode, pacStore.Set, audit, response).
// We only assert "not 403" — other status codes are legitimate
// downstream outcomes.
func TestPACConfig_POST_AcceptsAdmin(t *testing.T) {
	req := pacAuthzPostReq(RoleAdmin, "198.51.100.42:0")
	rec := httptest.NewRecorder()
	apiPACConfig(rec, req)

	if rec.Code == http.StatusForbidden {
		t.Errorf("Admin POST: got 403 (RBAC over-rejects admin); body=%s", rec.Body.String())
	}
}

// TestPACConfig_GET_AcceptsViewer confirms the new POST gate did not
// accidentally tighten the GET branch. /api/pac-config GET is intended
// to be readable by any authenticated user (and the handler today has
// no requireRole at all on GET — the metadata records that as
// uiAuthMiddleware-only protection). A Viewer-role GET should produce
// a 200 JSON response.
func TestPACConfig_GET_AcceptsViewer(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/pac-config", nil)
	req.RemoteAddr = "198.51.100.43:0"
	ctx := context.WithValue(req.Context(), uiRoleKey{}, RoleViewer)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	apiPACConfig(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Viewer GET: got %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var got PACConfig
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("response is not a valid PACConfig JSON: %v; body=%s", err, rec.Body.String())
	}
}
