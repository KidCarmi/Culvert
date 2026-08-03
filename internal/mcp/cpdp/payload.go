package cpdp

import "github.com/KidCarmi/Culvert/internal/mcp/mcperr"

// Payload carries exactly ONE capability's reviewed state. Exactly one of the two
// pointers is non-nil, and it MUST match the envelope's signed capability. This
// makes cross-capability contamination a structural rejection: a Gateway snapshot
// can never carry (or activate) Management state and vice versa.
type Payload struct {
	Gateway    *GatewayPayload    `json:"gateway,omitempty"`
	Management *ManagementPayload `json:"management,omitempty"`
}

// GatewayListener is the reviewed Gateway listener/access configuration assigned
// to DP distribution. References/metadata only — never key material or a token.
type GatewayListener struct {
	Enabled                  bool     `json:"enabled"`
	BindAddress              string   `json:"bind_address"`
	Port                     int      `json:"port"`
	ProtocolVersionPolicy    string   `json:"protocol_version_policy"`
	OriginHostAllowlist      []string `json:"origin_host_allowlist"`
	TLSProfileRef            string   `json:"tls_profile_ref"`
	ClientCertMode           string   `json:"client_cert_mode"`
	UnknownToolDefaultAction string   `json:"unknown_tool_default_action"`
	PolicyDefaultAction      string   `json:"policy_default_action"`
	RateLimitRPS             int      `json:"rate_limit_rps"`
	RateLimitBurst           int      `json:"rate_limit_burst"`
}

// ServerRecord is a reviewed, SAFE registered-server record: endpoint + pinned
// identity + verification/enabled state. No credential material.
type ServerRecord struct {
	ID             string `json:"id"`
	Endpoint       string `json:"endpoint"`
	PinnedIdentity string `json:"pinned_identity"`
	Verified       bool   `json:"verified"`
	Enabled        bool   `json:"enabled"`
}

// ToolRecord is a reviewed tool-catalog entry with its fingerprint and
// drift/quarantine state.
type ToolRecord struct {
	Server      string `json:"server"`
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	DriftState  string `json:"drift_state"`
	Quarantined bool   `json:"quarantined"`
}

// InspectionProfileMeta is inspection-profile metadata (id + version). The profile
// bodies themselves are compiled from reviewed config on the DP.
type InspectionProfileMeta struct {
	ID      string `json:"id"`
	Version uint64 `json:"version"`
}

// CredentialProfileMeta is credential-profile METADATA ONLY: the profile id, its
// scope, and a provider REFERENCE (never a secret value or ciphertext). This is
// exactly what "credential_revision" tracks — profile shape, not secret material.
type CredentialProfileMeta struct {
	ProfileID   string `json:"profile_id"`
	Scope       string `json:"scope"`
	ProviderRef string `json:"provider_ref"`
	Version     uint64 `json:"version"`
}

// GatewayPayload is the reviewed state a Gateway DP needs. It never contains a
// credential value, a client token, or a signing private key.
type GatewayPayload struct {
	Listener           GatewayListener         `json:"listener"`
	Servers            []ServerRecord          `json:"servers"`
	Tools              []ToolRecord            `json:"tools"`
	PolicySource       string                  `json:"policy_source"` // strictly serializable PR-6 policy document
	InspectionProfiles []InspectionProfileMeta `json:"inspection_profiles"`
	CredentialProfiles []CredentialProfileMeta `json:"credential_profiles"`
}

// ManagementListener is the reviewed Management listener/access configuration.
type ManagementListener struct {
	Enabled               bool     `json:"enabled"`
	BindAddress           string   `json:"bind_address"`
	Port                  int      `json:"port"`
	ProtocolVersionPolicy string   `json:"protocol_version_policy"`
	OriginHostAllowlist   []string `json:"origin_host_allowlist"`
	TLSProfileRef         string   `json:"tls_profile_ref"`
	ClientCertMode        string   `json:"client_cert_mode"`
	AuthMode              string   `json:"auth_mode"`
	DefaultMinRole        string   `json:"default_min_role"`
	MutationEnabled       bool     `json:"mutation_enabled"` // MUST be false in V1
	TenantScopeMode       string   `json:"tenant_scope_mode"`
	OutputMaxBytes        int      `json:"output_max_bytes"`
	OutputRedaction       string   `json:"output_redaction"`
}

// ManagementPayload is the reviewed state a Management DP needs. It never contains
// a Gateway tool catalog, a Gateway credential profile, or a mutation capability.
type ManagementPayload struct {
	Listener                ManagementListener `json:"listener"`
	OperationCatalogVersion uint64             `json:"operation_catalog_version"`
	PolicyReadScope         string             `json:"policy_read_scope"`
}

// checkCapabilityIsolation verifies that a payload carries exactly the state of
// the declared capability and nothing belonging to the other one. A Gateway
// envelope with a non-nil Management payload (or vice versa), or an empty/both
// payload, fails closed.
func (p Payload) checkCapabilityIsolation(cap Capability) error {
	switch cap {
	case CapabilityGateway:
		if p.Gateway == nil {
			return mcperr.New(mcperr.ReasonSnapshotCapabilityMismatch, "cpdp.payload", "gateway payload missing")
		}
		if p.Management != nil {
			return mcperr.New(mcperr.ReasonSnapshotCapabilityMismatch, "cpdp.payload", "management payload on a gateway snapshot")
		}
	case CapabilityManagement:
		if p.Management == nil {
			return mcperr.New(mcperr.ReasonSnapshotCapabilityMismatch, "cpdp.payload", "management payload missing")
		}
		if p.Gateway != nil {
			return mcperr.New(mcperr.ReasonSnapshotCapabilityMismatch, "cpdp.payload", "gateway payload on a management snapshot")
		}
		// A Management snapshot MUST NOT enable mutation in V1.
		if p.Management.Listener.MutationEnabled {
			return mcperr.New(mcperr.ReasonSnapshotValidationFailed, "cpdp.payload", "management mutation is not permitted in V1")
		}
	default:
		return mcperr.New(mcperr.ReasonSnapshotCapabilityMismatch, "cpdp.payload", "unknown capability")
	}
	return nil
}
