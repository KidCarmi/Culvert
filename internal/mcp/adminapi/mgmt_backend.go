package adminapi

import (
	"encoding/json"

	"github.com/KidCarmi/Culvert/internal/mcp/management"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy/simulate"
)

// mgmtToolInput is the strict, bounded input shape a draft/validate/simulate
// Management tool accepts. Read-only tools ignore all but the addressing fields.
type mgmtToolInput struct {
	Capability string          `json:"capability,omitempty"`
	ServerID   string          `json:"server_id,omitempty"`
	ToolName   string          `json:"tool_name,omitempty"`
	EventID    string          `json:"event_id,omitempty"`
	Cursor     string          `json:"cursor,omitempty"`
	Limit      int             `json:"limit,omitempty"`
	Candidate  json.RawMessage `json:"candidate,omitempty"`
	Cases      []simulate.Case `json:"cases,omitempty"`
}

// ManagementBackend implements management.Backend over the adminapi Service. It
// is READ-ONLY plus draft/validate/simulate: every branch calls a read or a
// stateless policy evaluation and returns safe DTO bytes scoped to id.Tenant.
// There is no branch that publishes, approves, mutates config or materializes a
// credential — those tools are not in the catalog and cannot reach here.
type ManagementBackend struct {
	svc *Service
}

// NewManagementBackend adapts a Service as a management.Backend.
func NewManagementBackend(svc *Service) *ManagementBackend { return &ManagementBackend{svc: svc} }

// Invoke dispatches a fixed-catalog tool by name. Tenant scope comes from the
// resolved Management identity, never from tool arguments.
//
//nolint:gocyclo,cyclop // a flat dispatch table over the fixed read-only catalog
func (b *ManagementBackend) Invoke(tool string, id management.Identity, input []byte) ([]byte, error) {
	var in mgmtToolInput
	if len(input) > 0 {
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, mcperr.New(mcperr.ReasonManagementToolUnknown, "mgmt.backend", "malformed tool input")
		}
	}
	capNS := in.Capability
	if capNS == "" {
		capNS = "gateway"
	}
	tenant := id.Tenant
	switch tool {
	case "culvert_mcp_overview":
		return marshalSafe(map[string]any{"tenant": tenant, "distribution_state": "local_only"})
	case "culvert_mcp_health_get":
		if b.svc.Health == nil {
			return marshalSafe(map[string]any{})
		}
		return marshalSafe(b.svc.Health.Snapshot())
	case "culvert_mcp_servers_list":
		return b.readInventoryServers(tenant, in.Limit)
	case "culvert_mcp_server_get":
		return b.readInventoryServer(tenant, in.ServerID)
	case "culvert_mcp_tools_list":
		return b.readInventoryTools(tenant, in.ServerID, in.Limit)
	case "culvert_mcp_tool_get":
		return b.readInventoryTool(tenant, in.ServerID, in.ToolName)
	case "culvert_mcp_decisions_search":
		return b.readDecisions(capNS, tenant, in.Cursor, in.Limit)
	case "culvert_mcp_decision_explain":
		return b.readExplain(capNS, tenant, in.EventID)
	case "culvert_mcp_policy_get":
		return b.readPolicy(capNS)
	case "culvert_mcp_policy_validate":
		return marshalSafe(b.svc.Policy.Validate(capNS, in.Candidate))
	case "culvert_mcp_policy_simulate":
		res, err := b.svc.Policy.Simulate(capNS, in.Candidate, in.Cases)
		if err != nil {
			return nil, err
		}
		return marshalSafe(res)
	case "culvert_mcp_policy_compare":
		res, err := b.svc.Policy.Compare(capNS, in.Candidate, in.Cases)
		if err != nil {
			return nil, err
		}
		return marshalSafe(res)
	case "culvert_mcp_approvals_list":
		return b.readApprovals(tenant, in.Limit)
	case "culvert_mcp_approval_get":
		return b.readApproval(tenant, in.EventID)
	default:
		return nil, mcperr.New(mcperr.ReasonManagementToolUnknown, "mgmt.backend", "unknown tool")
	}
}

func (b *ManagementBackend) readInventoryServers(tenant string, limit int) ([]byte, error) {
	if b.svc.Inventory == nil {
		return marshalSafe([]ServerView{})
	}
	v, err := b.svc.Inventory.ListServers(tenant, limit)
	if err != nil {
		return nil, err
	}
	return marshalSafe(v)
}

func (b *ManagementBackend) readInventoryServer(tenant, serverID string) ([]byte, error) {
	if b.svc.Inventory == nil {
		return nil, mcperr.New(mcperr.ReasonAdminNotFound, "mgmt.backend", "not found")
	}
	v, err := b.svc.Inventory.GetServer(tenant, serverID)
	if err != nil {
		return nil, err
	}
	return marshalSafe(v)
}

func (b *ManagementBackend) readInventoryTools(tenant, serverID string, limit int) ([]byte, error) {
	if b.svc.Inventory == nil {
		return marshalSafe([]ToolView{})
	}
	v, err := b.svc.Inventory.ListTools(tenant, serverID, limit)
	if err != nil {
		return nil, err
	}
	return marshalSafe(v)
}

func (b *ManagementBackend) readInventoryTool(tenant, serverID, name string) ([]byte, error) {
	if b.svc.Inventory == nil {
		return nil, mcperr.New(mcperr.ReasonAdminNotFound, "mgmt.backend", "not found")
	}
	v, err := b.svc.Inventory.GetTool(tenant, serverID, name)
	if err != nil {
		return nil, err
	}
	return marshalSafe(v)
}

func (b *ManagementBackend) readDecisions(capability, tenant, cursor string, limit int) ([]byte, error) {
	if b.svc.Decisions == nil {
		return marshalSafe(SearchResult{})
	}
	v, err := b.svc.Decisions.Search(capability, tenant, cursor, limit, DecisionFilter{})
	if err != nil {
		return nil, err
	}
	return marshalSafe(v)
}

func (b *ManagementBackend) readExplain(capability, tenant, eventID string) ([]byte, error) {
	if b.svc.Decisions == nil {
		return nil, mcperr.New(mcperr.ReasonAdminNotFound, "mgmt.backend", "not found")
	}
	v, err := b.svc.Decisions.Explain(capability, tenant, eventID)
	if err != nil {
		return nil, err
	}
	return marshalSafe(v)
}

func (b *ManagementBackend) readPolicy(capability string) ([]byte, error) {
	if b.svc.Policy == nil {
		return marshalSafe(map[string]any{})
	}
	store, ok := b.svc.Policy.stores.Store(capability)
	if !ok {
		return nil, mcperr.New(mcperr.ReasonAdminNotFound, "mgmt.backend", "no policy store")
	}
	out := map[string]any{"capability": capability, "revision": uint64(store.CurrentRevision()), "distribution_state": "local_only"}
	if cur := store.Current(); cur != nil {
		out["hash"] = cur.Hash()
		out["rule_count"] = cur.RuleCount()
		out["default_action"] = cur.DefaultAction().String()
	}
	return marshalSafe(out)
}

func (b *ManagementBackend) readApprovals(tenant string, limit int) ([]byte, error) {
	if b.svc.Approvals == nil {
		return marshalSafe([]ApprovalView{})
	}
	if limit <= 0 || limit > b.svc.Limits.MaxPageSize() {
		limit = b.svc.Limits.MaxPageSize()
	}
	reqs := b.svc.Approvals.List(tenant, 0, limit)
	views := make([]ApprovalView, 0, len(reqs))
	for _, r := range reqs {
		views = append(views, approvalView(r))
	}
	return marshalSafe(views)
}

func (b *ManagementBackend) readApproval(tenant, id string) ([]byte, error) {
	if b.svc.Approvals == nil {
		return nil, mcperr.New(mcperr.ReasonApprovalNotFound, "mgmt.backend", "not found")
	}
	r, err := b.svc.Approvals.Get(approvalIDFromString(id), tenant)
	if err != nil {
		return nil, err
	}
	return marshalSafe(approvalView(r))
}

// marshalSafe marshals a safe DTO. A marshal error is reported as a bounded
// admin error, never the raw Go error.
func marshalSafe(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, mcperr.New(mcperr.ReasonAdminRequestInvalid, "mgmt.backend", "encode failed")
	}
	return b, nil
}
