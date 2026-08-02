package adminapi

import "github.com/KidCarmi/Culvert/internal/mcp/approval"

// ApprovalView is the safe, complete view of one approval or publication
// request. It carries the exact fields the MCP-POLICY-007 approval dialog must
// display — action, resource, server/tool, requester/agent/client, reason and
// rule, credential profile and power ceiling, policy/catalog revisions, durable
// event id, age and expiry — with NO credential material and NO raw body. The
// decisive condition and inspection state are cross-referenced by the dialog via
// the bound decision event (DecisionEventID -> decision explanation).
type ApprovalView struct {
	ID              string `json:"id"`
	Kind            string `json:"kind"`
	State           string `json:"state"`
	Tenant          string `json:"tenant"`
	Capability      string `json:"capability"`
	Requester       string `json:"requester"`
	Approver        string `json:"approver,omitempty"`
	Action          string `json:"action,omitempty"`
	Resource        string `json:"resource,omitempty"`
	ServerID        string `json:"server_id,omitempty"`
	ToolFingerprint string `json:"tool_fingerprint,omitempty"`
	OperationClass  string `json:"operation_class,omitempty"`
	RiskClass       string `json:"risk_class,omitempty"`

	CredentialProfileRef string `json:"credential_profile_ref,omitempty"`
	PowerCeiling         string `json:"power_ceiling,omitempty"`

	DecisionEventID  string `json:"decision_event_id,omitempty"`
	CandidateHash    string `json:"candidate_hash,omitempty"`
	BaseRevision     uint64 `json:"base_revision,omitempty"`
	ProposedRevision uint64 `json:"proposed_revision,omitempty"`
	PolicyRevision   uint64 `json:"policy_revision,omitempty"`
	CatalogRevision  uint64 `json:"catalog_revision,omitempty"`

	CreatedUnixNano int64  `json:"created_unix_nano"`
	ExpiryUnixNano  int64  `json:"expiry_unix_nano"`
	Reason          string `json:"reason,omitempty"`
}

// approvalView maps an approval.Request to its safe view.
func approvalView(r *approval.Request) ApprovalView {
	b := r.Binding()
	return ApprovalView{
		ID: string(r.ID()), Kind: r.Kind().String(), State: r.State().String(),
		Tenant: b.Tenant, Capability: b.Capability, Requester: string(r.Requester()),
		Approver: string(r.Approver()), Action: b.Action, Resource: b.Resource,
		ServerID: b.ServerID, ToolFingerprint: b.ToolFingerprint, OperationClass: b.OperationClass,
		RiskClass: b.RiskClass, CredentialProfileRef: b.CredentialProfile, PowerCeiling: b.PowerCeiling,
		DecisionEventID: b.DecisionEventID, CandidateHash: b.CandidateHash, BaseRevision: b.BaseRevision,
		ProposedRevision: b.ProposedRevision, PolicyRevision: b.Revisions.Policy, CatalogRevision: b.Revisions.Catalog,
		CreatedUnixNano: r.Created().UnixNano(), ExpiryUnixNano: r.Expiry().UnixNano(), Reason: r.Reason(),
	}
}

// approvalIDFromString wraps a raw id string as an approval.ID.
func approvalIDFromString(s string) approval.ID { return approval.ID(s) }
