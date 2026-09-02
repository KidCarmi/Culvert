package main

// MCP live-tier PRODUCTION DEPENDENCY config resolution (§4 explicit opt-in, fail-closed).
//
// This file is the PURE resolution + validation half of the production live-tier
// dependency wiring. It reads NOTHING (the shim reads the environment and passes the
// values in) and constructs NOTHING (the builder in mcp_live_production_deps.go opens
// the KEK and composes the real collaborators). Keeping it pure means the startup-slice
// contract (startup_slice_contract_test.go) can pin it: same inputs → identical DTO, no
// hidden env/time/global reads.
//
// DISABLED BY DEFAULT. With CULVERT_MCP_LIVE_DEPS unset/false the resolver returns
// {Requested:false} and the builder composes NOTHING — a shipped build is byte-identical
// to "no live production dependencies", the live tier stays absent, and the executor is
// the Shadow/Observe path (or nil). This mirrors the CULVERT_MCP_SHADOW_READY doctrine:
// an env-only, startup-scoped, read-once opt-in with NO YAML/CLI/config_surfaces row (the
// same precedent as CULVERT_MCP_SHADOW_READY and CULVERT_MCP_DISTRIBUTION_TRUST_KEYS —
// node-local crypto/composition trust that never rides the config-export/rollback/CP→DP
// surfaces).
//
// PARTIAL CONFIG FAILS CLOSED. Opting in (CULVERT_MCP_LIVE_DEPS truthy) without supplying
// the required KEK file path is INVALID — validateMCPLiveProductionConfig returns an
// error and the builder fails closed to "not composed" rather than fabricating an
// ephemeral or insecure KEK. There is deliberately NO insecure fallback (§5): the KEK
// authority is the SAME file-provider doctrine telemetry already uses (secret.FileProvider
// + secret.ValidateProvider), so requiring an explicit operator-provisioned key file is a
// real production KEK source, not a deferred product decision.
//
// Opting in NEVER arms the live tier. Composition installs the guarded executor and stops
// (composeGatewayLiveTierInto records COMPOSED, never armed); arming is a separate,
// node-readiness-gated act (mcp_live_arming.go).

import (
	"errors"
	"path/filepath"
	"strings"
)

// mcpLiveDepsEnvVar is the explicit, operator-controlled master opt-in for composing the
// REAL production live-execution dependency graph on this node. Startup-scoped, read once.
// Default OFF.
const mcpLiveDepsEnvVar = "CULVERT_MCP_LIVE_DEPS"

// mcpLiveCredentialKEKEnvVar names the file path of the credential-broker KEK (the
// key-encryption key that seals credential material at rest). REQUIRED whenever
// mcpLiveDepsEnvVar is truthy; a missing path fails closed (no ephemeral/insecure
// fallback). Same file-provider doctrine as the telemetry KEK.
const mcpLiveCredentialKEKEnvVar = "CULVERT_MCP_LIVE_CREDENTIAL_KEK"

// errLiveDepsKEKMissing is the fail-closed reason for a partial opt-in: live deps
// requested but no KEK file supplied.
var errLiveDepsKEKMissing = errors.New("mcp live deps: enabled but no credential KEK file (CULVERT_MCP_LIVE_CREDENTIAL_KEK) supplied")

// mcpLiveProductionConfig is the resolved, pure DTO describing whether this node opts into
// the production live-tier dependency graph and where the credential KEK lives. It carries
// NO secret material — only a filesystem path the builder later validates and opens.
type mcpLiveProductionConfig struct {
	// Requested is true iff the operator explicitly opted in via CULVERT_MCP_LIVE_DEPS.
	Requested bool
	// KEKFile is the cleaned credential-broker KEK file path (empty when not requested).
	KEKFile string
}

// resolveMCPLiveProductionConfig is the pure resolver: it parses the master opt-in and
// cleans the KEK path. It performs NO validation-of-completeness (that is
// validateMCPLiveProductionConfig) and NO I/O. When not requested it returns a zero-value
// KEKFile so a disabled node carries no path at all.
func resolveMCPLiveProductionConfig(depsEnv, kekEnv string) mcpLiveProductionConfig {
	if !mcpEnvTruthy(depsEnv) {
		return mcpLiveProductionConfig{Requested: false}
	}
	kek := strings.TrimSpace(kekEnv)
	if kek != "" {
		kek = filepath.Clean(kek)
	}
	return mcpLiveProductionConfig{Requested: true, KEKFile: kek}
}

// validateMCPLiveProductionConfig is the pure fail-closed completeness check. A disabled
// config is always valid (nothing is composed). An enabled config MUST carry a KEK file
// path — a partial opt-in is rejected rather than silently degraded, mirroring
// validateTelemetryConfig.
func validateMCPLiveProductionConfig(cfg mcpLiveProductionConfig) error {
	if !cfg.Requested {
		return nil
	}
	if cfg.KEKFile == "" {
		return errLiveDepsKEKMissing
	}
	return nil
}

// mcpEnvTruthy reports whether an env value is one of the accepted truthy tokens. Same set
// as mcpShadowReadyEnabled, factored so the live-deps opt-in and the shadow opt-in cannot
// drift apart on what "on" means.
func mcpEnvTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes", "on":
		return true
	default:
		return false
	}
}
