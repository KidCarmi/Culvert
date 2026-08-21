package main

// QUAL-1 — authoritative startup configuration for the dedicated MCP Gateway
// "Observe" listener. This file is the PURE resolver half of the startup slice
// (mirrors mtls_ocsp_startup_config.go / cluster_startup_config.go): it reads the
// loaded FileConfig, applies fail-closed defaults, and returns a plain value DTO.
// It performs NO I/O (no file read, no os.Getenv, no clock, no network) and never
// mutates its input, so it is deterministic and covered by
// startup_slice_contract_test.go. All side-effecting work (TLS material load, key
// parsing, authn/runtime construction) lives in the loader (mcp_observe_startup.go).

// mcpObserveStartupConfig is the resolved, side-effect-free view of the
// mcp.gateway.* configuration block. Enabled is false by default (the entire MCP
// subsystem is disabled unless the operator explicitly opts in).
type mcpObserveStartupConfig struct {
	Enabled         bool
	BindAddress     string
	Port            int
	ProtocolVersion string
	AllowedHosts    []string
	AllowedOrigins  []string
	RequireOrigin   bool
	ConnectorMode   string

	TLSCertFile    string
	TLSKeyFile     string
	ClientCAFile   string
	ClientCertMode string

	CanonicalResource string
	TrustedIssuers    []string
	AcceptedClientIDs []string
	RequiredScopes    []string
	AllowedScopes     []string
	SenderConstraint  string
	MinAssurance      string
	TrustedJWKSFile   string
	ResourceName      string

	// QualificationInventoryFile is the static, node-local qualification inventory
	// path (QUAL-2). Empty ⇒ no inventory (QUAL-1 empty-registry behavior).
	QualificationInventoryFile string

	// QualificationPolicyFile is the static, node-local Gateway policy source path
	// (QUAL-4). Empty ⇒ no policy composed (QUAL-3 behavior; decision telemetry stays
	// pending-policy). Present ⇒ the file is compiled + published as the node-local
	// active Observe evaluation snapshot; a present-but-invalid file fails activation
	// closed. The policy is EVALUATED for evidence only and never executes.
	QualificationPolicyFile string

	// Telemetry is the resolved QUAL-3 durable-telemetry block. Disabled ⇒ QUAL-2
	// behavior (no event manager). Pure value DTO; the side-effecting composition
	// (KEK, spool, exporter) lives in the loader.
	Telemetry mcpTelemetryStartupConfig
}

// mcpTelemetryStartupConfig is the resolved, side-effect-free view of the
// mcp.gateway.qualification_telemetry block (QUAL-3).
type mcpTelemetryStartupConfig struct {
	Enabled          bool
	NodeID           string
	DataDir          string
	KEKFile          string
	ExportType       string
	ExportDirectory  string
	ExportBatchSize  int
	ExportMaxRetries int
	ExportMaxBytes   int64
}

// Fail-closed defaults for the security-load-bearing knobs. A blank value in the
// config resolves to the STRONGEST posture, never the weakest:
//   - client certificates are REQUIRED (mutual TLS) unless explicitly relaxed;
//   - the token must be sender-constrained via mTLS unless explicitly relaxed;
//   - the subject must present HIGH assurance unless explicitly relaxed.
const (
	mcpDefaultClientCertMode   = "require"
	mcpDefaultSenderConstraint = "mtls"
	mcpDefaultMinAssurance     = "high"
)

// resolveMCPObserveStartupConfig resolves the mcp.gateway.* block into the DTO.
// Precedence is YAML value > fail-closed default (this block is YAML-only, matching
// the SecurityScan/LDAP/OIDC/mtls_ocsp precedent — no CLI-flag layer). It is pure:
// same FileConfig in ⇒ same DTO out, and fc is never mutated.
func resolveMCPObserveStartupConfig(fc *FileConfig) mcpObserveStartupConfig {
	if fc == nil {
		return mcpObserveStartupConfig{}
	}
	g := fc.MCP.Gateway
	return mcpObserveStartupConfig{
		Enabled:         g.Enabled,
		BindAddress:     g.BindAddress,
		Port:            g.Port,
		ProtocolVersion: g.ProtocolVersion,
		AllowedHosts:    copyStrings(g.AllowedHosts),
		AllowedOrigins:  copyStrings(g.AllowedOrigins),
		RequireOrigin:   g.RequireOrigin,
		ConnectorMode:   g.ConnectorMode,

		TLSCertFile:    g.TLSCertFile,
		TLSKeyFile:     g.TLSKeyFile,
		ClientCAFile:   g.ClientCAFile,
		ClientCertMode: firstStr(g.ClientCertMode, mcpDefaultClientCertMode),

		CanonicalResource: g.CanonicalResource,
		TrustedIssuers:    copyStrings(g.TrustedIssuers),
		AcceptedClientIDs: copyStrings(g.AcceptedClientIDs),
		RequiredScopes:    copyStrings(g.RequiredScopes),
		AllowedScopes:     copyStrings(g.AllowedScopes),
		SenderConstraint:  firstStr(g.SenderConstraint, mcpDefaultSenderConstraint),
		MinAssurance:      firstStr(g.MinAssurance, mcpDefaultMinAssurance),
		TrustedJWKSFile:   g.TrustedJWKSFile,
		ResourceName:      g.ResourceName,

		QualificationInventoryFile: g.QualificationInventoryFile,
		QualificationPolicyFile:    g.QualificationPolicyFile,

		Telemetry: mcpTelemetryStartupConfig{
			Enabled:          g.QualificationTelemetry.Enabled,
			NodeID:           g.QualificationTelemetry.NodeID,
			DataDir:          g.QualificationTelemetry.DataDir,
			KEKFile:          g.QualificationTelemetry.KEKFile,
			ExportType:       g.QualificationTelemetry.Export.Type,
			ExportDirectory:  g.QualificationTelemetry.Export.Directory,
			ExportBatchSize:  g.QualificationTelemetry.Export.BatchSize,
			ExportMaxRetries: g.QualificationTelemetry.Export.MaxRetries,
			ExportMaxBytes:   g.QualificationTelemetry.Export.MaxBytes,
		},
	}
}

// copyStrings returns a fresh copy of a string slice (nil-safe) so the DTO shares
// no backing array with the input FileConfig — keeping the resolver's no-mutation
// contract robust even if a later caller mutates the returned slice.
func copyStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}
