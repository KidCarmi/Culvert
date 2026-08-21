package management

import (
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// fakeBackend echoes a fixed payload and can be sized to test output bounds.
type fakeBackend struct {
	payload []byte
	calls   int
}

func (f *fakeBackend) Invoke(_ string, _ Identity, _ []byte) ([]byte, error) {
	f.calls++
	if f.payload == nil {
		return []byte(`{"ok":true}`), nil
	}
	return f.payload, nil
}

func mgmtID(role Role, scopes ...string) Identity {
	sm := map[string]bool{}
	for _, s := range scopes {
		sm[s] = true
	}
	return Identity{Tenant: "acme", Role: role, Scopes: sm, Capability: "management"}
}

// TestNoMutationTool proves the catalog contains ONLY read-only + draft classes
// and no mutation/publish/approve/config/credential/secret/exec tool names —
// the core "no mutation reachable" guarantee (MCP-MGMT-001/003).
func TestNoMutationTool(t *testing.T) {
	banned := []string{"publish", "approve", "reject", "activate", "mutate", "set", "update",
		"delete", "create", "rotate", "revoke", "issue", "config_put", "secret", "exec",
		"command", "shell", "export_raw", "log", "trace"}
	for _, s := range Catalog() {
		if s.Class != ClassReadOnly && s.Class != ClassDraft {
			t.Fatalf("tool %q has a non-read/draft class", s.Name)
		}
		for _, b := range banned {
			if strings.Contains(s.Name, b) {
				t.Fatalf("tool %q looks like a mutation/forbidden tool", s.Name)
			}
		}
	}
}

func TestToolsList_FilteredByAuthority(t *testing.T) {
	d := NewDispatcher(&fakeBackend{}, 1<<20, 1<<20)
	// A viewer with only inventory scope sees only inventory read-only tools.
	got := d.ToolsList(mgmtID(RoleViewer, ScopeInventoryRead))
	if len(got) == 0 {
		t.Fatal("viewer with inventory scope should see inventory tools")
	}
	for _, s := range got {
		if s.Scope != ScopeInventoryRead {
			t.Fatalf("unexpected tool leaked into list: %s", s.Name)
		}
	}
	// An identity with no scopes sees nothing.
	if n := len(d.ToolsList(mgmtID(RoleAdmin))); n != 0 {
		t.Fatalf("no-scope identity should see no tools, saw %d", n)
	}
}

func TestToolsCall_ReauthorizesIndependently(t *testing.T) {
	be := &fakeBackend{}
	d := NewDispatcher(be, 1<<20, 1<<20)
	// Viewer WITHOUT the draft scope cannot call a draft tool even though the
	// name is well-known (remembered/unauthorized tool gains no authority).
	_, err := d.ToolsCall(mgmtID(RoleOperator, ScopeInventoryRead), "culvert_mcp_policy_validate", nil)
	if mcperr.ReasonOf(err) != mcperr.ReasonManagementToolUnauthorized {
		t.Fatalf("want unauthorized, got %v", err)
	}
	if be.calls != 0 {
		t.Fatal("backend must not be invoked for an unauthorized call")
	}
	// With the right role+scope it succeeds.
	if _, err := d.ToolsCall(mgmtID(RoleOperator, ScopePolicyDraft), "culvert_mcp_policy_validate", nil); err != nil {
		t.Fatalf("authorized draft call failed: %v", err)
	}
}

func TestToolsCall_CrossCapabilityRejected(t *testing.T) {
	d := NewDispatcher(&fakeBackend{}, 1<<20, 1<<20)
	id := mgmtID(RoleAdmin, ScopeInventoryRead)
	id.Capability = "gateway" // a Gateway token must never call a Management tool
	if _, err := d.ToolsCall(id, "culvert_mcp_servers_list", nil); mcperr.ReasonOf(err) != mcperr.ReasonManagementToolUnauthorized {
		t.Fatalf("want unauthorized for cross-capability, got %v", err)
	}
}

func TestToolsCall_UnknownRejected(t *testing.T) {
	d := NewDispatcher(&fakeBackend{}, 1<<20, 1<<20)
	if _, err := d.ToolsCall(mgmtID(RoleAdmin, ScopeInventoryRead), "culvert_mcp_policy_publish", nil); mcperr.ReasonOf(err) != mcperr.ReasonManagementToolUnknown {
		t.Fatalf("a non-catalog (mutation) name must be unknown, got %v", err)
	}
}

func TestToolsCall_OutputBounded(t *testing.T) {
	be := &fakeBackend{payload: make([]byte, 2048)}
	d := NewDispatcher(be, 1<<20, 1024) // output cap below payload
	if _, err := d.ToolsCall(mgmtID(RoleViewer, ScopeInventoryRead), "culvert_mcp_overview", nil); mcperr.ReasonOf(err) != mcperr.ReasonManagementResultTooLarge {
		t.Fatalf("oversized result must fail closed, got %v", err)
	}
}

func TestToolsCall_InputBounded(t *testing.T) {
	d := NewDispatcher(&fakeBackend{}, 8, 1<<20)
	if _, err := d.ToolsCall(mgmtID(RoleOperator, ScopePolicyDraft), "culvert_mcp_policy_validate", make([]byte, 64)); mcperr.ReasonOf(err) != mcperr.ReasonAdminRangeExceeded {
		t.Fatalf("oversized input must fail closed, got %v", err)
	}
}
