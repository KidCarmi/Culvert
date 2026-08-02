// Package management implements the fixed, reviewed Management MCP tool catalog
// and its dispatch boundary (tools/list + tools/call) for PR-9. The catalog is
// READ-ONLY plus stateless draft/validate/simulate — there is NO mutation,
// activation, publication, credential, config-write, secret, log/trace-export,
// command-execution or arbitrary-access tool, and none can be added without a
// compile-time catalog change that the tests would reject (MCP-MGMT-001/003).
//
// Every call is independently re-authorized (a client gains no authority by
// remembering a tool a prior tools/list returned), tenant-scoped (MCP-MGMT-002),
// and its result is byte-bounded before a JSON-RPC response is built
// (MCP-MGMT-004). A Gateway-scoped token can never call a Management tool.
package management

import (
	"sort"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// Role is a Management authorization role. It mirrors the admin-UI role ladder
// but is enforced independently per tool.
type Role uint8

const (
	// RoleNone is the invalid zero value (fails closed).
	RoleNone Role = iota
	// RoleViewer may call read-only tools.
	RoleViewer
	// RoleOperator may additionally call draft/validate/simulate tools.
	RoleOperator
	// RoleAdmin may call everything a Management token is ever allowed to.
	RoleAdmin
)

func (r Role) atLeast(min Role) bool { return r != RoleNone && r >= min }

// Class classifies a Management tool. Only these two classes exist — there is no
// mutation class.
type Class uint8

const (
	// ClassReadOnly is a bounded, redacted read.
	ClassReadOnly Class = iota
	// ClassDraft is a stateless draft/validate/simulate that persists nothing.
	ClassDraft
)

// Management scope names (capability-local; NOT a generic "mcp" scope).
const (
	ScopeInventoryRead = "mgmt.inventory.read"
	ScopeDecisionRead  = "mgmt.decision.read"
	ScopePolicyRead    = "mgmt.policy.read"
	ScopePolicyDraft   = "mgmt.policy.draft"
	ScopeApprovalRead  = "mgmt.approval.read"
	ScopeHealthRead    = "mgmt.health.read"
)

// ToolSpec is one entry in the fixed Management catalog.
type ToolSpec struct {
	Name    string
	MinRole Role
	Scope   string
	Class   Class
}

// catalog is the FIXED reviewed Management tool set. Read-only + draft/validate/
// simulate only. Adding a mutation tool here would fail TestNoMutationTool.
var catalog = []ToolSpec{
	{"culvert_mcp_overview", RoleViewer, ScopeInventoryRead, ClassReadOnly},
	{"culvert_mcp_servers_list", RoleViewer, ScopeInventoryRead, ClassReadOnly},
	{"culvert_mcp_server_get", RoleViewer, ScopeInventoryRead, ClassReadOnly},
	{"culvert_mcp_tools_list", RoleViewer, ScopeInventoryRead, ClassReadOnly},
	{"culvert_mcp_tool_get", RoleViewer, ScopeInventoryRead, ClassReadOnly},
	{"culvert_mcp_decisions_search", RoleViewer, ScopeDecisionRead, ClassReadOnly},
	{"culvert_mcp_decision_explain", RoleViewer, ScopeDecisionRead, ClassReadOnly},
	{"culvert_mcp_policy_get", RoleViewer, ScopePolicyRead, ClassReadOnly},
	{"culvert_mcp_policy_validate", RoleOperator, ScopePolicyDraft, ClassDraft},
	{"culvert_mcp_policy_simulate", RoleOperator, ScopePolicyDraft, ClassDraft},
	{"culvert_mcp_policy_compare", RoleOperator, ScopePolicyDraft, ClassDraft},
	{"culvert_mcp_approvals_list", RoleViewer, ScopeApprovalRead, ClassReadOnly},
	{"culvert_mcp_approval_get", RoleViewer, ScopeApprovalRead, ClassReadOnly},
	{"culvert_mcp_health_get", RoleViewer, ScopeHealthRead, ClassReadOnly},
}

// specByName indexes the catalog for O(1) lookup.
var specByName = func() map[string]ToolSpec {
	m := make(map[string]ToolSpec, len(catalog))
	for _, s := range catalog {
		m[s.Name] = s
	}
	return m
}()

// Identity is the resolved Management caller context. Capability MUST be
// "management"; a Gateway token is rejected.
type Identity struct {
	Tenant     string
	Role       Role
	Scopes     map[string]bool
	Capability string
}

func (id Identity) authorized(spec ToolSpec) bool {
	if id.Capability != "management" {
		return false
	}
	if !id.Role.atLeast(spec.MinRole) {
		return false
	}
	return id.Scopes[spec.Scope]
}

// Backend produces the safe, already-redacted DTO bytes for a tool invocation.
// The adminapi adapter implements it; management never sees raw data. The
// backend must itself enforce tenant scoping from id.Tenant.
type Backend interface {
	Invoke(tool string, id Identity, input []byte) ([]byte, error)
}

// Dispatcher enforces the Management boundary around a Backend.
type Dispatcher struct {
	backend        Backend
	maxInputBytes  int
	maxOutputBytes int
}

// NewDispatcher builds a bounded Management dispatcher.
func NewDispatcher(backend Backend, maxInputBytes, maxOutputBytes int) *Dispatcher {
	return &Dispatcher{backend: backend, maxInputBytes: maxInputBytes, maxOutputBytes: maxOutputBytes}
}

// ToolsList returns only the tools id is authorized to see, sorted by name.
// A client cannot gain authority by remembering an omitted tool — tools/call
// re-authorizes independently.
func (d *Dispatcher) ToolsList(id Identity) []ToolSpec {
	out := make([]ToolSpec, 0, len(catalog))
	for _, s := range catalog {
		if id.authorized(s) {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ToolsCall independently authorizes and dispatches one tool invocation,
// bounding both input and output. An unknown or unauthorized tool fails closed;
// an oversized result fails closed (never truncated unsafely).
func (d *Dispatcher) ToolsCall(id Identity, name string, input []byte) ([]byte, error) {
	spec, ok := specByName[name]
	if !ok {
		return nil, mcperr.New(mcperr.ReasonManagementToolUnknown, "management.call", "unknown tool")
	}
	if !id.authorized(spec) {
		// Uniform: an unauthorized-but-existing tool is reported as unauthorized,
		// never leaking whether the name exists to a caller who cannot use it.
		return nil, mcperr.New(mcperr.ReasonManagementToolUnauthorized, "management.call", "not authorized for tool")
	}
	if len(input) > d.maxInputBytes {
		return nil, mcperr.New(mcperr.ReasonAdminRangeExceeded, "management.call", "input exceeds bound")
	}
	out, err := d.backend.Invoke(name, id, input)
	if err != nil {
		return nil, err
	}
	if len(out) > d.maxOutputBytes {
		return nil, mcperr.New(mcperr.ReasonManagementResultTooLarge, "management.call", "result exceeds output bound")
	}
	return out, nil
}

// Catalog returns a copy of the full fixed catalog (for tests and the GUI
// Management-access panel). It is not authorization — ToolsList/ToolsCall gate.
func Catalog() []ToolSpec {
	out := make([]ToolSpec, len(catalog))
	copy(out, catalog)
	return out
}
