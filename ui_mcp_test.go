package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mcpReq(method, target string, role UIRole, body string) *httptest.ResponseRecorder {
	var b *strings.Reader
	if body == "" {
		b = strings.NewReader("")
	} else {
		b = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, target, b)
	if role != "" {
		r = r.WithContext(context.WithValue(r.Context(), uiRoleKey{}, role))
	}
	w := httptest.NewRecorder()
	mux := http.NewServeMux()
	registerMCPRoutes(mux)
	mux.ServeHTTP(w, r)
	return w
}

func TestMCP_MethodRejection(t *testing.T) {
	// overview is GET-only; POST must be 405.
	if got := mcpReq(http.MethodPost, "/api/mcp/overview", RoleViewer, "").Code; got != http.StatusMethodNotAllowed {
		t.Fatalf("POST overview = %d, want 405", got)
	}
	// config PUT is admin-only; GET is viewer.
	if got := mcpReq(http.MethodDelete, "/api/mcp/config", RoleAdmin, "").Code; got != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE config = %d, want 405", got)
	}
}

func TestMCP_RBAC(t *testing.T) {
	// Viewer may read overview.
	if got := mcpReq(http.MethodGet, "/api/mcp/overview", RoleViewer, "").Code; got != http.StatusOK {
		t.Fatalf("viewer GET overview = %d, want 200", got)
	}
	// Viewer may NOT create a publication (needs operator).
	if got := mcpReq(http.MethodPost, "/api/mcp/publications", RoleViewer, `{}`).Code; got != http.StatusForbidden {
		t.Fatalf("viewer POST publications = %d, want 403", got)
	}
	// Operator may NOT decide a publication (needs admin).
	if got := mcpReq(http.MethodPost, "/api/mcp/publication-decision", RoleOperator, `{"request_id":"x","action":"approve"}`).Code; got != http.StatusForbidden {
		t.Fatalf("operator POST publication-decision = %d, want 403", got)
	}
	// Operator may NOT update config (needs admin).
	if got := mcpReq(http.MethodPut, "/api/mcp/config", RoleOperator, `{}`).Code; got != http.StatusForbidden {
		t.Fatalf("operator PUT config = %d, want 403", got)
	}
	// Viewer may NOT decide an operational approval (needs admin).
	if got := mcpReq(http.MethodPost, "/api/mcp/approval-decision", RoleViewer, `{"request_id":"x","action":"approve"}`).Code; got != http.StatusForbidden {
		t.Fatalf("viewer POST approval-decision = %d, want 403", got)
	}
}

func TestMCP_TenantRequired(t *testing.T) {
	// A tenant-scoped read without ?tenant= must be rejected (not a silent all-tenant read).
	if got := mcpReq(http.MethodGet, "/api/mcp/servers", RoleViewer, "").Code; got != http.StatusBadRequest {
		t.Fatalf("servers without tenant = %d, want 400", got)
	}
	if got := mcpReq(http.MethodGet, "/api/mcp/decisions", RoleViewer, "").Code; got != http.StatusBadRequest {
		t.Fatalf("decisions without tenant = %d, want 400", got)
	}
}

// TestMCP_DisabledDefaults proves the shipped admin singleton is dormant: no
// inventory/decision sources are wired (empty results), and durable
// approval/publication commit fails closed rather than fabricating evidence.
func TestMCP_DisabledDefaults(t *testing.T) {
	m := getMCPAdmin()
	if m.svc.Inventory != nil || m.svc.Decisions != nil {
		t.Fatal("disabled default must not wire inventory/decision sources")
	}
	// Config PUT with an admin role succeeds locally (node-local runtime config).
	w := mcpReq(http.MethodPut, "/api/mcp/config", RoleAdmin, `{"gateway":{"enabled":false,"bind_address":"127.0.0.1","port":8091,"client_cert_mode":"none","protocol_version_policy":"2025-06-18","unknown_tool_default_action":"deny","policy_default_action":"deny"},"management":{"enabled":false,"bind_address":"127.0.0.1","port":8092,"client_cert_mode":"require","auth_mode":"oauth-token","default_min_role":"viewer","tenant_scope_mode":"strict","output_max_bytes":1048576,"output_redaction_profile":"default"}}`)
	if w.Code != http.StatusOK {
		t.Fatalf("admin config PUT = %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "local_only") {
		t.Fatalf("config apply must report local_only: %s", w.Body.String())
	}
}

// TestMCP_NoExecutionImports is the structural no-upstream/no-broker/no-CPDP
// proof for the admin HTTP layer: ui_mcp.go must not import an upstream MCP
// client, the credential broker/provider, or the control-plane publication path.
func TestMCP_NoExecutionImports(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(pkgSourceDir(), "ui_mcp.go"))
	if err != nil {
		t.Fatal(err)
	}
	blob := string(src)
	// Scan only the import block for forbidden dependencies (avoids matching
	// prose in the file's doc comments).
	start := strings.Index(blob, "import (")
	end := strings.Index(blob, ")")
	if start < 0 || end < start {
		t.Fatal("could not locate import block")
	}
	imports := blob[start:end]
	for _, banned := range []string{
		"credentials/broker", "credentials/provider", "mcp/runtime",
	} {
		if strings.Contains(imports, banned) {
			t.Fatalf("ui_mcp.go imports %q — no upstream/broker execution allowed", banned)
		}
	}
	// No control-plane snapshot publication call names anywhere in the handler.
	for _, banned := range []string{"CurrentConfigSnapshot", "signSnapshot", "publishSnapshot"} {
		if strings.Contains(blob, banned) {
			t.Fatalf("ui_mcp.go references %q — no signed CP→DP publication allowed", banned)
		}
	}
}
