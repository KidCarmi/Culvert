package cpdp

import (
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

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
	// Rollout is the OPTIONAL PR-11 signed rollout config (mode + scope + connector
	// mode). nil ⇒ no rollout change (an older/rolled-back CP that predates PR-11
	// never wipes a DP's rollout state). It rides the content hash + signature with
	// no extra plumbing and is validated + applied on the DP whole-or-nothing.
	Rollout *rollout.SignedConfig `json:"rollout,omitempty"`
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
	// Rollout is the OPTIONAL PR-11 signed rollout config for the Management
	// capability (mode + scope; Management never executes, so its mode gates only
	// listener presence + read behavior). nil ⇒ no rollout change.
	Rollout *rollout.SignedConfig `json:"rollout,omitempty"`
}

// checkCapabilityIsolation verifies that a payload carries exactly the state of
// the declared capability and nothing belonging to the other one. A Gateway
// envelope with a non-nil Management payload (or vice versa), or an empty/both
// payload, fails closed.
func (p Payload) checkCapabilityIsolation(capab Capability) error {
	switch capab {
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
	// The payload BLOCK is capability-correct; the embedded rollout config must be
	// too. rollout.SignedConfig carries its OWN Capability field, and every consumer
	// routes the commit by THAT field (rollout.State is capability-local), so a
	// config whose self-declared capability disagrees with the signed envelope would
	// steer a commit onto the OTHER capability's state — the exact cross-capability
	// contamination this isolation check exists to make structural. Enforce it HERE,
	// in the engine, so the invariant holds for every caller and, critically, for
	// every snapshot that reaches the durable store: a consumer reading recovered
	// state must not have to re-derive it (Applier.Recover deliberately re-runs only
	// signature/capability/min-version, not full payload validation).
	return p.checkRolloutCapability(capab)
}

// checkRolloutCapability verifies that an embedded rollout config's self-declared
// capability matches the envelope's signed capability. A nil rollout (no rollout
// change) is valid. Fails closed on any disagreement.
func (p Payload) checkRolloutCapability(capab Capability) error {
	var rc *rollout.SignedConfig
	switch capab {
	case CapabilityGateway:
		rc = p.Gateway.Rollout
	case CapabilityManagement:
		rc = p.Management.Rollout
	}
	if rc == nil {
		return nil // absence is not a change
	}
	want := rollout.CapabilityGateway
	if capab == CapabilityManagement {
		want = rollout.CapabilityManagement
	}
	if rc.Capability != want {
		return mcperr.New(mcperr.ReasonSnapshotCapabilityMismatch, "cpdp.payload",
			"rollout config capability does not match the snapshot capability")
	}
	return nil
}
