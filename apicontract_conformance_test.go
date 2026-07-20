package main

// Gates 4/5/6 — request, response, and authorization conformance driven through
// REAL handlers via httptest. These exercise a representative, security-spanning
// subset of documented operations against the actual contract schemas, so a
// handler that drifts from its documented shape (or its documented RBAC) fails
// CI. Only side-effect-free operations are invoked live.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/apicontract"
)

func loadContract(t *testing.T) *apicontract.Spec {
	t.Helper()
	spec, err := apicontract.LoadSpec(openapiSpecPath)
	if err != nil {
		t.Fatalf("load contract: %v", err)
	}
	return spec
}

// withRole injects the RBAC role the middleware would normally set, so handler
// requireRole checks are exercised exactly as in production.
func withRole(r *http.Request, role UIRole) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), uiRoleKey{}, role))
}

// ── Gate 5: response conformance (read-only handlers) ────────────────────────

func TestConformance_Response_SetupStatus(t *testing.T) {
	spec := loadContract(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/setup/status", http.NoBody)
	apiSetupStatus(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("content-type = %q, want application/json", ct)
	}
	if err := spec.ValidateJSONResponse("GET", "/api/setup/status", 200, rec.Body.Bytes()); err != nil {
		t.Fatalf("response violates contract: %v\nbody: %s", err, rec.Body.String())
	}
}

func TestConformance_Response_AuthStatus(t *testing.T) {
	spec := loadContract(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/status", http.NoBody)
	apiAuthStatus(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if err := spec.ValidateJSONResponse("GET", "/api/auth/status", 200, rec.Body.Bytes()); err != nil {
		t.Fatalf("response violates contract: %v\nbody: %s", err, rec.Body.String())
	}
}

func TestConformance_Response_Healthz(t *testing.T) {
	spec := loadContract(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody)
	apiHealthz(rec, req)
	// Standalone node (zero-value globalHA) → 200.
	if rec.Code != http.StatusOK && rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unexpected status %d", rec.Code)
	}
	if err := spec.ValidateJSONResponse("GET", "/healthz", rec.Code, rec.Body.Bytes()); err != nil {
		t.Fatalf("healthz response violates contract: %v\nbody: %s", err, rec.Body.String())
	}
}

func TestConformance_Response_Stats(t *testing.T) {
	spec := loadContract(t)
	rec := httptest.NewRecorder()
	req := withRole(httptest.NewRequest(http.MethodGet, "/api/stats", http.NoBody), RoleViewer)
	apiStats(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if err := spec.ValidateJSONResponse("GET", "/api/stats", 200, rec.Body.Bytes()); err != nil {
		t.Fatalf("stats response violates contract: %v\nbody: %s", err, rec.Body.String())
	}
}

func TestConformance_Response_Governance(t *testing.T) {
	spec := loadContract(t)
	rec := httptest.NewRecorder()
	req := withRole(httptest.NewRequest(http.MethodGet, "/api/governance/control-plane", http.NoBody), RoleAdmin)
	apiGovernanceControlPlane(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if err := spec.ValidateJSONResponse("GET", "/api/governance/control-plane", 200, rec.Body.Bytes()); err != nil {
		t.Fatalf("governance response violates contract: %v\nbody: %s", err, rec.Body.String())
	}
}

// ── Gate 4: request conformance ──────────────────────────────────────────────

func TestConformance_Request_Login(t *testing.T) {
	spec := loadContract(t)
	// A well-formed request body validates against the documented schema.
	good := []byte(`{"user":"admin","pass":"secret","totp":"123456"}`)
	if err := spec.ValidateJSONRequest("POST", "/api/auth/login", good); err != nil {
		t.Fatalf("valid login body rejected by contract: %v", err)
	}
	// Missing required 'pass' must be rejected by the contract.
	bad := []byte(`{"user":"admin"}`)
	if err := spec.ValidateJSONRequest("POST", "/api/auth/login", bad); err == nil {
		t.Fatal("contract accepted a login body missing the required 'pass' field")
	}
	// And the real handler rejects malformed JSON with 400 (documented).
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader("{not json"))
	apiAuthLogin(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed login body: status = %d, want 400", rec.Code)
	}
}

// ── Gate 6: authorization conformance ────────────────────────────────────────

// TestConformance_Authz_MatchesContract asserts, for each protected documented
// operation, that a caller BELOW the documented x-culvert-permission is denied
// (403) and a caller AT the documented role is not denied on the RBAC axis.
func TestConformance_Authz_MatchesContract(t *testing.T) {
	// apiAuthUsers GET is documented admin-only.
	t.Run("users_viewer_denied", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := withRole(httptest.NewRequest(http.MethodGet, "/api/auth/users", http.NoBody), RoleViewer)
		apiAuthUsers(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("viewer on admin route: status = %d, want 403", rec.Code)
		}
	})
	t.Run("users_admin_allowed", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := withRole(httptest.NewRequest(http.MethodGet, "/api/auth/users", http.NoBody), RoleAdmin)
		apiAuthUsers(rec, req)
		if rec.Code == http.StatusForbidden {
			t.Fatalf("admin on admin route was forbidden (RBAC contract mismatch)")
		}
	})
	// governance control-plane is documented admin-only.
	t.Run("governance_viewer_denied", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := withRole(httptest.NewRequest(http.MethodGet, "/api/governance/control-plane", http.NoBody), RoleViewer)
		apiGovernanceControlPlane(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("viewer on admin governance route: status = %d, want 403", rec.Code)
		}
	})
}

// TestConformance_Authz_PermissionMatchesManifest cross-checks the documented
// x-culvert-permission against the classification manifest min_role for every
// documented row — the contract's stated permission cannot silently diverge from
// the router's recorded role.
func TestConformance_Authz_PermissionMatchesManifest(t *testing.T) {
	spec := loadContract(t)
	c, err := apicontract.LoadClassification(classificationPath)
	if err != nil {
		t.Fatalf("load classification: %v", err)
	}
	// Build documented row lookup: path+method → min_role.
	for _, row := range c.Rows {
		if !row.Documented {
			continue
		}
		op := spec.OpForRow(row)
		if op == nil {
			continue // covered by the coverage gate
		}
		perm := apicontract.Ext(op, "x-culvert-permission")
		want := roleToPermission(row.MinRole)
		if perm != want {
			t.Errorf("%s %s: contract x-culvert-permission=%q but manifest min_role=%q (want permission %q)",
				row.Method, row.Route, perm, row.MinRole, want)
		}
	}
}

func roleToPermission(minRole string) string {
	switch minRole {
	case "public":
		return "public"
	case "viewer":
		return "viewer"
	case "operator":
		return "operator"
	case "admin":
		return "admin"
	}
	return minRole
}
