package adminapi

import (
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/management"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
)

func mgmtStack(t *testing.T) *management.Dispatcher {
	t.Helper()
	reg := &fakeReg{recs: nil}
	// Reuse the inventory fixtures.
	inv := invSvc()
	gw := policy.NewStore(policy.CapGateway)
	svc := &Service{
		Inventory: inv,
		Policy:    NewPolicyService(&fakePolicyStores{gw: gw}, policy.DefaultLimits(), DefaultLimits(), func() time.Time { return time.Unix(1, 0) }),
		Limits:    DefaultLimits(),
	}
	_ = reg
	be := NewManagementBackend(svc)
	return management.NewDispatcher(be, 1<<20, 1<<20)
}

func TestMgmtBackend_ServersListTenantScoped(t *testing.T) {
	d := mgmtStack(t)
	id := management.Identity{Tenant: "acme", Role: management.RoleViewer, Capability: "management",
		Scopes: map[string]bool{management.ScopeInventoryRead: true}}
	out, err := d.ToolsCall(id, "culvert_mcp_servers_list", nil)
	if err != nil {
		t.Fatalf("ToolsCall: %v", err)
	}
	blob := string(out)
	if !strings.Contains(blob, "s-acme-1") {
		t.Fatalf("acme should see its server: %s", blob)
	}
	if strings.Contains(blob, "s-globex-1") {
		t.Fatalf("cross-tenant server leaked through Management: %s", blob)
	}
}

func TestMgmtBackend_DraftScopeRequiredForValidate(t *testing.T) {
	d := mgmtStack(t)
	// Viewer with only inventory scope cannot validate (draft class).
	viewer := management.Identity{Tenant: "acme", Role: management.RoleOperator, Capability: "management",
		Scopes: map[string]bool{management.ScopeInventoryRead: true}}
	if _, err := d.ToolsCall(viewer, "culvert_mcp_policy_validate", []byte(`{"candidate":"e30="}`)); mcperr.ReasonOf(err) != mcperr.ReasonManagementToolUnauthorized {
		t.Fatalf("validate without draft scope must be unauthorized, got %v", err)
	}
}

func TestMgmtBackend_MutationToolUnknown(t *testing.T) {
	d := mgmtStack(t)
	admin := management.Identity{Tenant: "acme", Role: management.RoleAdmin, Capability: "management",
		Scopes: map[string]bool{management.ScopePolicyDraft: true, management.ScopeInventoryRead: true}}
	// A publish/mutation tool is not in the catalog -> unknown, never dispatched.
	if _, err := d.ToolsCall(admin, "culvert_mcp_policy_publish", nil); mcperr.ReasonOf(err) != mcperr.ReasonManagementToolUnknown {
		t.Fatalf("mutation tool must be unknown, got %v", err)
	}
}
