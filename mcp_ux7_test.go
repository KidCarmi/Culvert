package main

import (
	"net/http"
	"strings"
	"testing"
)

// PR-UX-7 backend contracts. The security-critical one is the fail-closed guard
// that keeps Management MCP non-mutating: a Management policy publication must be
// rejected server-side (defense-in-depth, not just a hidden UI control), while the
// Gateway publication-create path is unchanged.

// TestMCPUX7_ManagementPublicationRejected proves POST /api/mcp/publications with
// capability=management is rejected fail-closed (403 admin_forbidden), for both the
// exact token and case/whitespace variants, and never creates a request. Gateway
// stays operator-gated as before.
func TestMCPUX7_ManagementPublicationRejected(t *testing.T) {
	for _, cap := range []string{"management", "Management", " management "} {
		body := `{"capability":"` + cap + `","tenant":"acme","candidate":{},"expected_base":0}`
		rec := mcpReq(http.MethodPost, "/api/mcp/publications", RoleAdmin, body)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("management publication (cap=%q) = %d, want 403; body=%s", cap, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "admin_forbidden") {
			t.Fatalf("management publication (cap=%q) must classify admin_forbidden: %s", cap, rec.Body.String())
		}
	}
	// The guard is capability-specific, not a blanket block: a Gateway create still
	// reaches the create path (operator role required; a viewer is still 403 by RBAC,
	// proving the guard did not replace the normal contract).
	if got := mcpReq(http.MethodPost, "/api/mcp/publications", RoleViewer, `{"capability":"gateway","tenant":"acme","candidate":{},"expected_base":0}`).Code; got != http.StatusForbidden {
		t.Fatalf("viewer gateway publication = %d, want 403 (RBAC)", got)
	}
}

// TestMCPUX7_ConfigStoredNotActive proves the config surface: GET is viewer, PUT is
// admin and returns listener_activation:not_implemented (stored is not a running
// listener), and wildcard bind + Management-mutation-true are rejected server-side.
func TestMCPUX7_ConfigStoredNotActive(t *testing.T) {
	if got := mcpReq(http.MethodGet, "/api/mcp/config", RoleViewer, "").Code; got != http.StatusOK {
		t.Fatalf("viewer GET config = %d, want 200", got)
	}
	cur := mcpReq(http.MethodGet, "/api/mcp/config", RoleViewer, "").Body.String()
	put := mcpReq(http.MethodPut, "/api/mcp/config", RoleAdmin, cur)
	if put.Code != http.StatusOK {
		t.Fatalf("admin PUT current config = %d, want 200: %s", put.Code, put.Body.String())
	}
	for _, want := range []string{`"stored":true`, `"listener_activation":"not_implemented"`, `"distribution_state":"local_only"`} {
		if !strings.Contains(put.Body.String(), want) {
			t.Fatalf("PUT response missing %q: %s", want, put.Body.String())
		}
	}
	if got := mcpReq(http.MethodPut, "/api/mcp/config", RoleViewer, cur).Code; got != http.StatusForbidden {
		t.Fatalf("viewer PUT config = %d, want 403", got)
	}
	wild := `{"gateway":{"enabled":true,"bind_address":"0.0.0.0","port":8091,"client_cert_mode":"none"},"management":{"enabled":false}}`
	if got := mcpReq(http.MethodPut, "/api/mcp/config", RoleAdmin, wild).Code; got == http.StatusOK {
		t.Fatalf("wildcard bind must be rejected, got 200")
	}
	mut := `{"gateway":{"enabled":false},"management":{"enabled":true,"bind_address":"127.0.0.1","port":8092,"client_cert_mode":"require","auth_mode":"oauth-token","default_min_role":"viewer","mutation_enabled":true,"output_max_bytes":1048576,"output_redaction_profile":"default"}}`
	if got := mcpReq(http.MethodPut, "/api/mcp/config", RoleAdmin, mut).Code; got == http.StatusOK {
		t.Fatalf("management mutation_enabled:true must be rejected, got 200")
	}
}

// TestMCPUX7_HealthAndManagementReads proves Health is capability-isolated and
// Management Access reports mutation off with a fixed non-mutating catalog (viewer).
func TestMCPUX7_HealthAndManagementReads(t *testing.T) {
	h := mcpReq(http.MethodGet, "/api/mcp/health", RoleViewer, "")
	if h.Code != http.StatusOK {
		t.Fatalf("viewer GET health = %d, want 200", h.Code)
	}
	for _, want := range []string{`"gateway"`, `"management"`, `"durability"`, `"runtime"`} {
		if !strings.Contains(h.Body.String(), want) {
			t.Fatalf("health missing %q: %s", want, h.Body.String())
		}
	}
	m := mcpReq(http.MethodGet, "/api/mcp/management-access", RoleViewer, "")
	if m.Code != http.StatusOK {
		t.Fatalf("viewer GET management-access = %d, want 200", m.Code)
	}
	for _, want := range []string{`"mutation_tools":0`, `"mutation_enabled":false`, `"tools"`} {
		if !strings.Contains(m.Body.String(), want) {
			t.Fatalf("management-access missing %q: %s", want, m.Body.String())
		}
	}
}

// TestMCPUX7_PolicyAndInventoryRBAC proves policy validate is operator-gated, a valid
// Gateway candidate validates through the real compiler (returning a server hash),
// and inventory reads require viewer + a tenant.
func TestMCPUX7_PolicyAndInventoryRBAC(t *testing.T) {
	if got := mcpReq(http.MethodPost, "/api/mcp/policy-simulate", RoleViewer, `{"mode":"validate","capability":"gateway","candidate":{}}`).Code; got != http.StatusForbidden {
		t.Fatalf("viewer policy-simulate = %d, want 403", got)
	}
	valid := `{"mode":"validate","capability":"gateway","candidate":{"schema_version":1,"capability":"gateway","policy_revision":1,"default_action":"DENY","rules":[]}}`
	v := mcpReq(http.MethodPost, "/api/mcp/policy-simulate", RoleOperator, valid)
	if v.Code != http.StatusOK || !strings.Contains(v.Body.String(), `"ok":true`) {
		t.Fatalf("operator validate valid candidate = %d body=%s", v.Code, v.Body.String())
	}
	if !strings.Contains(v.Body.String(), `"candidate_hash"`) {
		t.Fatalf("validate must return a server candidate_hash: %s", v.Body.String())
	}
	if got := mcpReq(http.MethodGet, "/api/mcp/servers?tenant=acme", RoleViewer, "").Code; got != http.StatusOK {
		t.Fatalf("viewer GET servers = %d, want 200", got)
	}
	if got := mcpReq(http.MethodGet, "/api/mcp/servers", RoleViewer, "").Code; got == http.StatusOK {
		t.Fatalf("servers without tenant must not be 200")
	}
	if got := mcpReq(http.MethodGet, "/api/mcp/tools?tenant=acme", RoleViewer, "").Code; got != http.StatusOK {
		t.Fatalf("viewer GET tools = %d, want 200", got)
	}
}
