package main

// Slice 3 — response conformance for the documented read endpoints, driven
// through the REAL handlers via httptest. Each asserts 200 + application/json +
// the body validating against the documented schema. All handlers here were
// verified nil-global-safe on their GET path; viewer role is injected so the
// six viewer-gated handlers return 200 rather than 403.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func assertResponseConforms(t *testing.T, method, path string, h http.HandlerFunc) {
	t.Helper()
	spec := loadContract(t)
	rec := httptest.NewRecorder()
	req := withRole(httptest.NewRequest(method, path, nil), RoleViewer)
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s %s: status = %d, want 200 (body: %s)", method, path, rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("%s %s: content-type = %q, want application/json", method, path, ct)
	}
	if err := spec.ValidateJSONResponse(method, path, 200, rec.Body.Bytes()); err != nil {
		t.Fatalf("%s %s response violates contract: %v\nbody: %s", method, path, err, rec.Body.String())
	}
}

func TestConformance_Response_Slice3(t *testing.T) {
	cases := []struct {
		name, path string
		h          http.HandlerFunc
	}{
		{"policy", "/api/policy", apiPolicy},
		{"authpolicy", "/api/authpolicy", apiAuthPolicy},
		{"default-action", "/api/default-action", apiDefaultAction},
		{"blocklist-mode", "/api/blocklist/mode", apiBlocklistMode},
		{"ssl-bypass", "/api/ssl-bypass", apiSSLBypass},
		{"decryption-health", "/api/decryption/health", apiDecryptionHealth},
		{"security", "/api/security", apiSecurity},
		{"ocsp", "/api/ocsp", apiOCSPConfig},
		{"session-timeout", "/api/session-timeout", apiSessionTimeout},
		{"connlimit", "/api/connlimit", apiConnLimit},
		{"logger", "/api/logger", apiLoggerConfig},
		{"pac-config", "/api/pac-config", apiPACConfig},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertResponseConforms(t, http.MethodGet, c.path, c.h)
		})
	}
}
