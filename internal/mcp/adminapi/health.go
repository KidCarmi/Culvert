package adminapi

// DurabilityHealth is the safe per-capability PR-8 durability snapshot. It
// carries only bounded numeric/state fields — no tenant, subject, session, tool
// argument, URL or secret.
type DurabilityHealth struct {
	CriticalState        string `json:"critical_state"`
	DenialState          string `json:"denial_state"`
	Severity             string `json:"severity"`
	CritBytes            int64  `json:"crit_bytes"`
	CritQuota            int64  `json:"crit_quota"`
	OrdBytes             int64  `json:"ord_bytes"`
	OrdQuota             int64  `json:"ord_quota"`
	DenBytes             int64  `json:"den_bytes"`
	DenQuota             int64  `json:"den_quota"`
	CriticalReserveFree  int64  `json:"critical_reserve_free"`
	CommitFailures       uint64 `json:"commit_failures"`
	SyncFailures         uint64 `json:"sync_failures"`
	EncryptionFailures   uint64 `json:"encryption_failures"`
	DenialLoss           uint64 `json:"denial_loss"`
	CriticalDegradations uint64 `json:"critical_degradations"`
	RecoveryState        string `json:"recovery_state"`
	ExporterLag          uint64 `json:"exporter_lag"`
}

// RuntimeStateHealth is the safe per-capability listener/runtime snapshot.
type RuntimeStateHealth struct {
	State          string `json:"state"` // disabled|invalid|configured_not_started|starting|ready|degraded|draining|stopped
	ListenerReady  bool   `json:"listener_ready"`
	Draining       bool   `json:"draining"`
	ActiveSessions int    `json:"active_sessions"`
	AcceptedConns  uint64 `json:"accepted_conns"`
	RejectedConns  uint64 `json:"rejected_conns"`
	InFlight       int    `json:"in_flight"`
	// EnableRequested reports whether the operator explicitly asked to activate this
	// capability's listener (QUAL-1). It distinguishes "disabled by default" (false)
	// from "enable requested but configuration invalid" (true with State=="invalid").
	EnableRequested bool `json:"enable_requested"`
	// Reason is a bounded, secret-free classification when State is "invalid" (e.g.
	// "tls_material_unavailable", "no_trusted_keys"); never a raw error or path.
	Reason string `json:"reason,omitempty"`
	// Posture is "observe" when the listener is active in the QUAL-1 Observe posture.
	Posture string `json:"posture,omitempty"`
	// ExecutionEnabled reports whether upstream tool execution is composed. QUAL-1
	// ships NO executor, so a bound Gateway observe listener always reports false.
	ExecutionEnabled bool `json:"execution_enabled"`
}

// CapabilityHealth is the composed safe health of one MCP capability.
type CapabilityHealth struct {
	Capability          string             `json:"capability"`
	Runtime             RuntimeStateHealth `json:"runtime"`
	Durability          DurabilityHealth   `json:"durability"`
	Servers             int                `json:"servers"`
	QuarantinedTools    int                `json:"quarantined_tools"`
	DriftedTools        int                `json:"drifted_tools"`
	PolicyRevision      uint64             `json:"policy_revision"`
	PolicySnapshotHash  string             `json:"policy_snapshot_hash"`
	PendingApprovals    int                `json:"pending_approvals"`
	PendingPublications int                `json:"pending_publications"`
}

// ManagementAccessHealth is the safe Management-access surface state.
type ManagementAccessHealth struct {
	Enabled         bool   `json:"enabled"`
	EndpointBound   bool   `json:"endpoint_bound"`
	DefaultMinRole  string `json:"default_min_role"`
	OutputMaxBytes  int    `json:"output_max_bytes"`
	MutationEnabled bool   `json:"mutation_enabled"`
}

// HealthView is the complete safe MCP health snapshot. Gateway and Management
// are composed from SEPARATE sources so a degradation in one is never written
// into the other (capability isolation).
type HealthView struct {
	Gateway           CapabilityHealth       `json:"gateway"`
	Management        CapabilityHealth       `json:"management"`
	DistributionState string                 `json:"distribution_state"` // always local_only in PR-9
	ManagementAccess  ManagementAccessHealth `json:"management_access"`
}

// ApprovalCounts exposes bounded pending-projection counts per capability.
type ApprovalCounts interface {
	PendingCounts(capability string) (approvals, publications int)
}

// InventoryCounts exposes bounded per-capability inventory counts.
type InventoryCounts interface {
	Counts(capability string) (servers, quarantined, drifted int)
}

// HealthSources are the narrow, capability-keyed inputs the aggregator composes.
// Durability and Runtime are funcs so each capability is fetched independently
// (isolation) and tests can inject per-capability behavior.
type HealthSources struct {
	Durability func(capability string) DurabilityHealth
	Runtime    func(capability string) RuntimeStateHealth
	Policy     PolicyStores
	Approvals  ApprovalCounts
	Inventory  InventoryCounts
	Config     *ConfigStore
}

// HealthService composes the safe MCP health snapshot.
type HealthService struct {
	src HealthSources
	lim Limits
}

// NewHealthService builds a health aggregator.
func NewHealthService(src HealthSources, lim Limits) *HealthService {
	return &HealthService{src: src, lim: lim}
}

// Snapshot composes the current safe health view. Each capability is built from
// its own sources; the two are never mixed.
func (s *HealthService) Snapshot() HealthView {
	v := HealthView{
		Gateway:           s.capability("gateway"),
		Management:        s.capability("management"),
		DistributionState: "local_only",
	}
	if s.src.Config != nil {
		m := s.src.Config.Current().Management
		v.ManagementAccess = ManagementAccessHealth{
			Enabled: m.Enabled, EndpointBound: m.Enabled && m.BindAddress != "" && m.Port != 0,
			DefaultMinRole: m.DefaultMinRole, OutputMaxBytes: m.OutputMaxBytes, MutationEnabled: m.MutationEnabled,
		}
	}
	return v
}

func (s *HealthService) capability(capNS string) CapabilityHealth {
	c := CapabilityHealth{Capability: capNS}
	if s.src.Runtime != nil {
		c.Runtime = s.src.Runtime(capNS)
	}
	if s.src.Durability != nil {
		c.Durability = s.src.Durability(capNS)
	}
	if s.src.Policy != nil {
		if store, ok := s.src.Policy.Store(capNS); ok {
			c.PolicyRevision = uint64(store.CurrentRevision())
			if cur := store.Current(); cur != nil {
				c.PolicySnapshotHash = cur.Hash()
			}
		}
	}
	if s.src.Inventory != nil {
		c.Servers, c.QuarantinedTools, c.DriftedTools = s.src.Inventory.Counts(capNS)
	}
	if s.src.Approvals != nil {
		c.PendingApprovals, c.PendingPublications = s.src.Approvals.PendingCounts(capNS)
	}
	return c
}
