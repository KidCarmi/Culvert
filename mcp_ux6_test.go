package main

import (
	"net/http"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// PR-UX-6 handler contracts: the read-only evidence endpoint (viewer-readable,
// GET-only, capability-isolated, no mutation) and the unified approvals read
// contract. The pure evidence projection and its typed-state contracts are
// owned and tested by internal/mcp/evidenceview (IM-009).

// TestMCPUX6_ApprovalListsReadContract pins the read contract the unified approvals
// list depends on: a viewer may read BOTH the operational and publication lists
// (tenant-scoped), the tenant is required, and decisions stay admin-only (the UI
// combines the two lists client-side, so both must be independently readable).
func TestMCPUX6_ApprovalListsReadContract(t *testing.T) {
	for _, path := range []string{"/api/mcp/approvals?tenant=acme", "/api/mcp/publications?tenant=acme"} {
		if got := mcpReq(http.MethodGet, path, RoleViewer, "").Code; got != http.StatusOK {
			t.Fatalf("viewer GET %s = %d, want 200", path, got)
		}
	}
	// Tenant is required (no cross-tenant/global read).
	if got := mcpReq(http.MethodGet, "/api/mcp/approvals", RoleViewer, "").Code; got == http.StatusOK {
		t.Fatalf("approvals GET without tenant must not be 200")
	}
	if got := mcpReq(http.MethodGet, "/api/mcp/publications", RoleViewer, "").Code; got == http.StatusOK {
		t.Fatalf("publications GET without tenant must not be 200")
	}
	// Decisions remain admin-only (defense-in-depth beyond the durability gate).
	if got := mcpReq(http.MethodPost, "/api/mcp/approval-decision", RoleViewer, `{"request_id":"x","tenant":"acme","action":"approve"}`).Code; got != http.StatusForbidden {
		t.Fatalf("viewer approval-decision = %d, want 403", got)
	}
}

// TestMCPUX6_EvidenceHandler proves the endpoint is viewer-readable, GET-only,
// capability-isolated, and performs NO mutation on a read.
func TestMCPUX6_EvidenceHandler(t *testing.T) {
	// Seed a distinct rehearsal marker on management, then confirm a GET never flips it.
	getMCPRollout().stateFor(rollout.CapabilityManagement).UpdateEvidence(func(e *rollout.EvidenceSummary) { e.RollbackRehearsed = false })
	before := getMCPRollout().stateFor(rollout.CapabilityGateway).Evidence()

	rec := mcpReq(http.MethodGet, "/api/mcp/rollout/evidence?capability=gateway", RoleViewer, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("viewer GET evidence = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{`"capability":"gateway"`, `"production_locked":true`, `"requirements"`, `"summary"`, `"shadow_state"`, `"unsupported_categories"`, `"as_of_unix_nano"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("evidence body missing %q: %s", want, body)
		}
	}
	// Capability isolation: management is a distinct read.
	m := mcpReq(http.MethodGet, "/api/mcp/rollout/evidence?capability=management", RoleViewer, "").Body.String()
	if !strings.Contains(m, `"capability":"management"`) {
		t.Fatalf("management evidence not capability-bound: %s", m)
	}
	// No mutation: the GET must not have changed gateway evidence.
	after := getMCPRollout().stateFor(rollout.CapabilityGateway).Evidence()
	if before != after {
		t.Fatalf("evidence GET mutated state: before=%+v after=%+v", before, after)
	}
	if got := mcpReq(http.MethodPost, "/api/mcp/rollout/evidence", RoleAdmin, "").Code; got != http.StatusMethodNotAllowed {
		t.Fatalf("POST evidence = %d, want 405", got)
	}
}
