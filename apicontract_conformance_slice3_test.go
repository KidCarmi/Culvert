package main

// Slice 3 — response conformance for the documented read endpoints, driven
// through the REAL handlers via httptest. Each asserts 200 + application/json +
// the body validating against the documented schema. All handlers here were
// verified nil-global-safe on their GET path; viewer role is injected so the
// six viewer-gated handlers return 200 rather than 403.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/apicontract"
)

// assertResponseConforms drives the handler at the viewer role and fails the
// test unless it answers 200 + application/json with a body the contract
// accepts.
//
// The spec is passed in, not loaded here: apicontract.LoadSpec parses and
// validates the whole contract (≈0.2 s), and loading it per subtest made
// fixture preparation most of this family's run time. Callers load it once per
// top-level test invocation (so -count=2 still gets a fresh fixture) and share
// it across that test's subtests; validation only reads it
// (TestConformance_SharedSpecFixture pins that).
func assertResponseConforms(t *testing.T, spec *apicontract.Spec, method, path string, h http.HandlerFunc) {
	t.Helper()
	if err := checkResponseConforms(spec, method, path, RoleViewer, h); err != nil {
		t.Fatal(err)
	}
}

// checkResponseConforms drives h at role and returns the first contract
// violation: a status other than 200, a non-JSON content type, or a body the
// documented 200 schema rejects. nil means the response conforms.
func checkResponseConforms(spec *apicontract.Spec, method, path string, role UIRole, h http.HandlerFunc) error {
	rec := httptest.NewRecorder()
	req := withRole(httptest.NewRequestWithContext(context.Background(), method, path, http.NoBody), role)
	h(rec, req)
	if rec.Code != http.StatusOK {
		return fmt.Errorf("%s %s: status = %d, want 200 (body: %s)", method, path, rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		return fmt.Errorf("%s %s: content-type = %q, want application/json", method, path, ct)
	}
	if err := spec.ValidateJSONResponse(method, path, 200, rec.Body.Bytes()); err != nil {
		return fmt.Errorf("%s %s response violates contract: %w\nbody: %s", method, path, err, rec.Body.String())
	}
	return nil
}

func TestConformance_Response_Slice3(t *testing.T) {
	spec := loadContract(t)
	cases := []struct {
		name, path string
		h          http.HandlerFunc
	}{
		{"policy", "/api/policy", apiPolicy},
		{"authpolicy", "/api/authpolicy", apiAuthPolicy},
		{"authpolicy-killswitch", "/api/authpolicy/killswitch", apiAuthPolicyKillSwitch},
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
			assertResponseConforms(t, spec, http.MethodGet, c.path, c.h)
		})
	}
}
