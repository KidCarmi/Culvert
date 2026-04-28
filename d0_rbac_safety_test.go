package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// d0AdminOnlyCase pins one (handler, method, path) tuple that the audit
// flagged in §3.1 as critical admin-only — the dangerous-if-leaked end of
// the surface. The body is the smallest payload the handler will accept
// past JSON decoding so the test reaches requireRole(RoleAdmin); we don't
// care about the success path, only that viewer/operator are rejected.
type d0AdminOnlyCase struct {
	name    string
	method  string
	path    string
	body    string
	handler http.HandlerFunc
}

// d0AdminOnlyCases enumerates the critical write endpoints from
// docs/UI_REFACTOR_AUDIT.md §3.1. Each carries a real-shape JSON body so
// the handler advances past decodeJSON and reaches the role check; that
// is the path D0 needs to pin in place.
var d0AdminOnlyCases = []d0AdminOnlyCase{
	{
		name:    "session-secret POST",
		method:  http.MethodPost,
		path:    "/api/session-secret",
		body:    `{"secret":"0000000000000000000000000000000000000000000000000000000000000000"}`,
		handler: apiSessionSecret,
	},
	{
		name:    "unauth-mode PUT",
		method:  http.MethodPut,
		path:    "/api/settings/unauth-mode",
		body:    `{"enabled":false}`,
		handler: apiUnauthMode,
	},
	{
		name:    "ca/rotate POST",
		method:  http.MethodPost,
		path:    "/api/ca/rotate",
		body:    `{}`,
		handler: apiCARotate,
	},
	{
		name:    "cluster/mode POST",
		method:  http.MethodPost,
		path:    "/api/cluster/mode",
		body:    `{"grpc_addr":":0"}`,
		handler: apiClusterMode,
	},
	{
		name:    "cluster/revoke POST",
		method:  http.MethodPost,
		path:    "/api/cluster/revoke",
		body:    `{"node_id":"n0"}`,
		handler: apiClusterRevoke,
	},
	{
		name:    "config/import POST",
		method:  http.MethodPost,
		path:    "/api/config/import",
		body:    `{}`,
		handler: apiConfigImport,
	},
	{
		name:    "auth/users POST",
		method:  http.MethodPost,
		path:    "/api/auth/users",
		body:    `{"username":"x","password":"Passw0rd!","role":"viewer"}`,
		handler: apiAuthUsers,
	},
}

// withRoleCtx attaches the given UIRole to the request context, mirroring
// what uiAuthMiddleware does after a successful session check.
func withRoleCtx(r *http.Request, role UIRole) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), uiRoleKey{}, role))
}

// TestD0_AdminOnly_RejectsViewerAndOperator pins the RBAC contract on the
// critical admin-only handlers from the audit. Each case is invoked
// directly (no middleware chain) with viewer and operator roles in
// context; both must receive 403 from the handler's own requireRole call.
//
// A regression here means a previously admin-only mutation became
// reachable by a lower-privilege role — privilege escalation.
func TestD0_AdminOnly_RejectsViewerAndOperator(t *testing.T) {
	for _, tc := range d0AdminOnlyCases {
		for _, role := range []UIRole{RoleViewer, RoleOperator} {
			t.Run(tc.name+"/"+string(role), func(t *testing.T) {
				req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
				req.Header.Set("Content-Type", "application/json")
				req.RemoteAddr = "198.51.100.20:0"
				req = withRoleCtx(req, role)

				rec := httptest.NewRecorder()
				tc.handler(rec, req)

				if rec.Code != http.StatusForbidden {
					t.Errorf("%s as %s: got %d, want 403 (body=%s)",
						tc.name, role, rec.Code, rec.Body.String())
				}
			})
		}
	}
}

// TestD0_AdminOnly_AcceptsAdmin is a positive-path counterpart that
// confirms the same handlers do NOT reject an admin role with 403. We
// allow any non-403 status: the handler may legitimately return 200/4xx
// for unrelated reasons (missing nodes, no CA initialised, etc.). The
// only assertion is "RBAC did not block".
func TestD0_AdminOnly_AcceptsAdmin(t *testing.T) {
	for _, tc := range d0AdminOnlyCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			req.RemoteAddr = "198.51.100.21:0"
			req = withRoleCtx(req, RoleAdmin)

			rec := httptest.NewRecorder()
			tc.handler(rec, req)

			if rec.Code == http.StatusForbidden {
				t.Errorf("%s as admin: got 403 (RBAC over-rejects admin); body=%s",
					tc.name, rec.Body.String())
			}
		})
	}
}
