package rollout

import "github.com/KidCarmi/Culvert/internal/mcp/mcperr"

// Connector-mode constants. V1 supports ONLY Model A (local-client). The other two
// are reserved, unimplemented, and ungated — every configuration surface and the
// snapshot validator must reject them (ON-PREM-CONNECTIVITY.md D-8/D-9).
const (
	// ConnectorLocalClient is Model A — the only supported V1 connectivity model
	// (managed internal AI client → LAN/VPN → Culvert MCP Gateway → approved remote
	// MCP server). No public ingress, no vendor connector.
	ConnectorLocalClient = "local-client"
	// ConnectorOutbound is Model B — a post-V1 roadmap slice. REJECTED in V1.
	ConnectorOutbound = "outbound-connector"
	// ConnectorDMZ is Model C — deferred, default-off. REJECTED in V1.
	ConnectorDMZ = "dmz-endpoint"
)

// ValidateConnectorMode accepts ONLY "local-client". An empty string is treated as
// the default local-client (safe). "outbound-connector" and "dmz-endpoint" — and
// any other value — are rejected with ReasonRolloutConnectorModeRejected. This is
// the single reusable enforcement point for every surface (API, YAML/env/flag,
// import, snapshot apply).
func ValidateConnectorMode(mode string) error {
	switch mode {
	case "", ConnectorLocalClient:
		return nil
	default:
		return mcperr.New(mcperr.ReasonRolloutConnectorModeRejected, "rollout.connector", "only local-client is supported in V1")
	}
}

// NormalizeConnectorMode returns the effective connector mode, defaulting an empty
// value to local-client. It assumes the value has already passed
// ValidateConnectorMode (callers validate before persisting).
func NormalizeConnectorMode(mode string) string {
	if mode == "" {
		return ConnectorLocalClient
	}
	return mode
}
