package main

// Mutating-response conformance (adversarial-review HIGH finding). The rest of
// the conformance suite validated only GET responses against the contract; a
// POST/PUT/DELETE handler could return a body violating its documented 2xx
// schema with every gate green. This suite drives REAL write handlers for the
// security-relevant surface and validates their actual response bodies against
// the contract via Spec.ValidateJSONResponse.
//
// ROLLBACK-SAFE: every global these handlers mutate (UI-allow CIDRs, block-page
// HTML, the policy store) is snapshotted and restored via t.Cleanup, and all
// on-disk writes go to a per-test temp dataDir. Without this, a handler like
// POST /api/ui-allow-ips would set a process-wide IP restriction that poisons
// every later test in the package (403 admin-panel-restricted-by-IP). No
// outbound network.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// isolateMutableStores snapshots the process-global stores the mutating-response
// cases touch and restores them when the test ends, so the batch cannot leak
// state into sibling tests.
func isolateMutableStores(t *testing.T) {
	t.Helper()
	withTempDataDir(t)

	cidrs := ListUIAllowedCIDRs()
	blockHTML := getBlockPageHTML()
	rules := policyStore.List()
	t.Cleanup(func() {
		_ = SetUIAllowedCIDRs(cidrs)
		_ = setBlockPageHTML(blockHTML)
		policyStore.ReplaceAll(rules)
	})
}

// mutatingResponseCase drives a real write handler at `role`, asserts the
// documented status, and validates the JSON body against the contract for that
// status.
func mutatingResponseCase(t *testing.T, method, path, body string, role UIRole, h http.HandlerFunc, wantStatus int) {
	t.Helper()
	sp := loadContract(t)
	rec := httptest.NewRecorder()
	req := withRole(httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body)), role)
	h(rec, req)
	if rec.Code != wantStatus {
		t.Fatalf("%s %s: status = %d, want %d (body: %s)", method, path, rec.Code, wantStatus, rec.Body.String())
	}
	if wantStatus == http.StatusNoContent {
		return // no body to validate
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("%s %s: content-type = %q, want application/json", method, path, ct)
	}
	if err := sp.ValidateJSONResponse(method, path, wantStatus, rec.Body.Bytes()); err != nil {
		t.Fatalf("%s %s response violates contract: %v\nbody: %s", method, path, err, rec.Body.String())
	}
}

// High-risk write handlers: their real 2xx responses must conform to the
// documented schema. All mutated state is snapshotted + restored.
func TestConformance_MutatingResponses(t *testing.T) {
	isolateMutableStores(t)
	cases := []struct {
		name, method, path, body string
		role                     UIRole
		h                        http.HandlerFunc
		status                   int
	}{
		{"blockpage-set", http.MethodPut, "/api/blockpage", `{"html":"<h1>Blocked</h1>"}`, RoleAdmin, apiBlockPage, http.StatusOK},
		{"ui-allow-ips-add", http.MethodPost, "/api/ui-allow-ips", `{"ips":["10.0.0.0/8"]}`, RoleAdmin, apiUIAllowIPs, http.StatusOK},
		{"policy-create", http.MethodPost, "/api/policy", `{"priority":10,"name":"allow-eng","sourceGroup":"engineering","destFQDN":"*.github.com","sslAction":"Inspect","action":"Allow","enabled":true}`, RoleOperator, apiPolicy, http.StatusOK},
		{"upload-config-disable", http.MethodPut, "/api/support/upload/config", `{"enabled":false}`, RoleAdmin, apiSupportUploadConfig, http.StatusOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mutatingResponseCase(t, c.method, c.path, c.body, c.role, c.h, c.status)
		})
	}
}
