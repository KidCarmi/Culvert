package adminapi

import (
	"net"
	"strings"
	"sync"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// ListenerConfig is the PR-9-owned, node-local (RC-6) configuration for one MCP
// capability listener plus its access controls. It carries references and
// metadata only — never a private key, bearer token, client secret or raw
// credential. Distribution to other nodes is NOT implemented here (PR-10); a
// config read reports distribution_state=local_only.
type ListenerConfig struct {
	Enabled             bool     `json:"enabled"`
	BindAddress         string   `json:"bind_address"`
	Port                int      `json:"port"`
	ProtocolVersion     string   `json:"protocol_version_policy"`
	OriginHostAllowlist []string `json:"origin_host_allowlist"`
	// TLSProfileRef is a reference to a configured TLS profile, not key material.
	TLSProfileRef  string `json:"tls_profile_ref"`
	ClientCertMode string `json:"client_cert_mode"` // "none" | "request" | "require"
}

// GatewayConfig is the Gateway-capability listener/access configuration.
type GatewayConfig struct {
	ListenerConfig
	UnknownToolDefaultAction string `json:"unknown_tool_default_action"` // "deny" | "quarantine"
	PolicyDefaultAction      string `json:"policy_default_action"`       // "deny" (default-deny)
	RateLimitRPS             int    `json:"rate_limit_rps"`
	RateLimitBurst           int    `json:"rate_limit_burst"`
}

// ManagementConfig is the Management-capability listener/access configuration.
// Management runs CP-side only; its config is never DP-synced. In V1 mutation is
// unavailable: MutationEnabled MUST remain false (MCP-MGMT-001 / ADR-0024 D-13).
type ManagementConfig struct {
	ListenerConfig
	AuthMode        string `json:"auth_mode"`         // "oauth-token"
	DefaultMinRole  string `json:"default_min_role"`  // "viewer" | "operator" | "admin" (>= viewer)
	MutationEnabled bool   `json:"mutation_enabled"`  // MUST be false in V1
	TenantScopeMode string `json:"tenant_scope_mode"` // "strict" | "explicit-global"
	OutputMaxBytes  int    `json:"output_max_bytes"`  // MCP-MGMT-004 bound
	OutputRedaction string `json:"output_redaction_profile"`
	RateLimitRPS    int    `json:"rate_limit_rps"`
	RateLimitBurst  int    `json:"rate_limit_burst"`
}

// MCPConfig is the complete PR-9 MCP configuration: separate Gateway and
// Management settings whose runtime state is NOT shared (capability isolation).
type MCPConfig struct {
	Gateway    GatewayConfig    `json:"gateway"`
	Management ManagementConfig `json:"management"`
}

// DefaultMCPConfig returns the safe-default configuration: both capabilities
// disabled, no wildcard bind, TLS required, distinct ports, Management read-only
// and defaulting to at least viewer, with a bounded/redacted Management output.
func DefaultMCPConfig() MCPConfig {
	return MCPConfig{
		Gateway: GatewayConfig{
			ListenerConfig: ListenerConfig{
				Enabled: false, BindAddress: "127.0.0.1", Port: 8091,
				ProtocolVersion: "2025-06-18", ClientCertMode: "none",
			},
			UnknownToolDefaultAction: "deny",
			PolicyDefaultAction:      "deny",
			RateLimitRPS:             50,
			RateLimitBurst:           100,
		},
		Management: ManagementConfig{
			ListenerConfig: ListenerConfig{
				Enabled: false, BindAddress: "127.0.0.1", Port: 8092,
				ProtocolVersion: "2025-06-18", ClientCertMode: "require",
			},
			AuthMode:        "oauth-token",
			DefaultMinRole:  "viewer",
			MutationEnabled: false,
			TenantScopeMode: "strict",
			OutputMaxBytes:  1 << 20,
			OutputRedaction: "default",
			RateLimitRPS:    20,
			RateLimitBurst:  40,
		},
	}
}

// isWildcardBind reports whether addr is an unspecified/wildcard address that
// must never be a default bind.
func isWildcardBind(addr string) bool {
	a := strings.TrimSpace(addr)
	if a == "" || a == "*" || a == "0.0.0.0" || a == "::" || a == "[::]" {
		return true
	}
	if ip := net.ParseIP(a); ip != nil && ip.IsUnspecified() {
		return true
	}
	return false
}

func validPort(p int) bool { return p >= 1 && p <= 65535 }

// Validate enforces the PR-9 configuration invariants. A candidate config that
// fails validation is rejected with a classified error and the current running
// configuration is retained by the caller.
//
//nolint:gocyclo,cyclop,funlen // a flat table of independent listener invariants
func (c MCPConfig) Validate(maxOutputBytes int) error {
	// Per-listener structural checks (only when enabled — a disabled listener
	// keeps safe defaults but need not be fully configured).
	if c.Gateway.Enabled {
		if err := c.Gateway.ListenerConfig.validate("gateway"); err != nil {
			return err
		}
	}
	if c.Management.Enabled {
		if err := c.Management.ListenerConfig.validate("management"); err != nil {
			return err
		}
		if c.Management.MutationEnabled {
			return mcperr.New(mcperr.ReasonConfigInvalid, "mcpconfig", "management mutation is unavailable in V1")
		}
		switch c.Management.DefaultMinRole {
		case "viewer", "operator", "admin":
		default:
			return mcperr.New(mcperr.ReasonConfigInvalid, "mcpconfig", "management default_min_role must be viewer|operator|admin")
		}
		if c.Management.AuthMode != "oauth-token" {
			return mcperr.New(mcperr.ReasonConfigInvalid, "mcpconfig", "management auth_mode must be oauth-token")
		}
		if c.Management.OutputMaxBytes <= 0 || c.Management.OutputMaxBytes > maxOutputBytes {
			return mcperr.New(mcperr.ReasonConfigInvalid, "mcpconfig", "management output_max_bytes out of range")
		}
		if c.Management.OutputRedaction == "" {
			return mcperr.New(mcperr.ReasonConfigInvalid, "mcpconfig", "management output_redaction_profile required")
		}
	}
	// Non-overlap: Gateway and Management may not share a bind endpoint.
	if c.Gateway.Enabled && c.Management.Enabled {
		if c.Gateway.Port == c.Management.Port &&
			strings.EqualFold(c.Gateway.BindAddress, c.Management.BindAddress) {
			return mcperr.New(mcperr.ReasonConfigInvalid, "mcpconfig", "gateway and management must not share a bind endpoint")
		}
	}
	return nil
}

func (l ListenerConfig) validate(which string) error {
	if !validPort(l.Port) {
		return mcperr.New(mcperr.ReasonConfigInvalid, "mcpconfig", which+" port out of range")
	}
	if isWildcardBind(l.BindAddress) {
		return mcperr.New(mcperr.ReasonConfigInvalid, "mcpconfig", which+" wildcard bind is not permitted")
	}
	switch l.ClientCertMode {
	case "none", "request", "require":
	default:
		return mcperr.New(mcperr.ReasonConfigInvalid, "mcpconfig", which+" client_cert_mode invalid")
	}
	return nil
}

// ConfigStore holds the current MCP configuration behind an RWMutex. Reads are
// lock-free-ish (RLock); a Set validates the candidate and replaces atomically,
// retaining the previous configuration on any validation failure.
type ConfigStore struct {
	mu             sync.RWMutex
	cur            MCPConfig
	maxOutputBytes int
}

// NewConfigStore returns a store seeded with the safe defaults.
func NewConfigStore(maxOutputBytes int) *ConfigStore {
	return &ConfigStore{cur: DefaultMCPConfig(), maxOutputBytes: maxOutputBytes}
}

// Current returns a copy of the active configuration.
func (s *ConfigStore) Current() MCPConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cur
}

// Set validates cand and, only if valid, replaces the active configuration. On
// any validation failure the previous configuration is retained unchanged.
func (s *ConfigStore) Set(cand MCPConfig) error {
	if err := cand.Validate(s.maxOutputBytes); err != nil {
		return err
	}
	s.mu.Lock()
	s.cur = cand
	s.mu.Unlock()
	return nil
}
