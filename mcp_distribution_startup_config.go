package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"

	"github.com/KidCarmi/Culvert/internal/mcp/cpdp"
)

// envMCPDistributionTrustKeys names the operator-provisioned trust roots the DP
// verifies signed MCP CP→DP distribution envelopes against. It is a JSON array of
// PUBLIC ed25519 roots, in the SAME shape as CULVERT_RELEASE_CATALOG_TRUST_KEYS
// (the established env-only public-trust precedent):
//
//	[{"key_id":"mcp-2026","alg":"ed25519","public_key":"<base64-raw-32-byte-key>"}]
//
// PUBLIC material only — a private signing key is never provisioned to a DP. Unset
// or empty ⇒ MCP CP→DP distribution stays DISABLED (no applier is composed, the DP
// apply path is a no-op, and a received ConfigSnapshot is byte-identical to the
// pre-PR-10 SWG snapshot). A present-but-invalid value fails CLOSED to disabled
// (never composes an applier that would trust nothing or trust the wrong key). This
// mirrors the release-catalog trust-key precedent and carries the same recorded
// GUI-parity deferral: the trust material is env/file-provisioned crypto, surfaced
// READ-ONLY on GET /api/mcp/distribution, never a runtime-mutable panel toggle.
const envMCPDistributionTrustKeys = "CULVERT_MCP_DISTRIBUTION_TRUST_KEYS"

// mcpDistributionTrustKey is one operator trust root in the env JSON. It is the
// public-only projection of a cpdp.TrustRoot (base64 raw ed25519 public key).
type mcpDistributionTrustKey struct {
	KeyID     string `json:"key_id"`
	Alg       string `json:"alg"`
	PublicKey string `json:"public_key"`
}

// mcpDistributionStartupConfig is the resolved, node-local MCP distribution DP
// composition decision. Enabled is true ONLY when a valid, non-empty trust store
// was provisioned; every failure path resolves to Enabled=false with a bounded,
// secret-free Reason (fail-closed).
type mcpDistributionStartupConfig struct {
	Enabled     bool
	NodeID      string
	DataDir     string
	Trust       *cpdp.TrustStore
	TrustKeyIDs []string // bounded, non-secret (public key ids only) — for status
	Reason      string   // bounded classification: not_configured / invalid_* / ready
}

// resolveMCPDistributionStartupConfig is the PURE resolver for the DP distribution
// composition. It never reads the environment, the clock, or the filesystem — the
// shim packs those in — so it is deterministic and unit-testable. It fails CLOSED:
// any parse/decode/trust error resolves to a disabled config with a bounded reason,
// NEVER an enabled config with an empty or malformed trust store.
func resolveMCPDistributionStartupConfig(trustJSON, nodeID, dataDir string) mcpDistributionStartupConfig {
	off := func(reason string) mcpDistributionStartupConfig {
		return mcpDistributionStartupConfig{Enabled: false, NodeID: nodeID, DataDir: dataDir, Reason: reason}
	}
	if trustJSON == "" {
		return off("not_configured")
	}
	var raw []mcpDistributionTrustKey
	if err := json.Unmarshal([]byte(trustJSON), &raw); err != nil {
		return off("invalid_trust_json")
	}
	if len(raw) == 0 {
		return off("not_configured")
	}
	roots := make([]cpdp.TrustRoot, 0, len(raw))
	ids := make([]string, 0, len(raw))
	for i := range raw {
		k := raw[i]
		if k.Alg != cpdp.SigAlgEd25519 {
			return off("invalid_trust_alg")
		}
		pub, err := base64.StdEncoding.DecodeString(k.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return off("invalid_trust_key")
		}
		roots = append(roots, cpdp.TrustRoot{KeyID: k.KeyID, Alg: cpdp.SigAlgEd25519, Public: ed25519.PublicKey(pub)})
		ids = append(ids, k.KeyID)
	}
	trust, err := cpdp.NewTrustStore(roots)
	if err != nil {
		return off("invalid_trust_store")
	}
	if nodeID == "" {
		nodeID = "mcp-dp"
	}
	return mcpDistributionStartupConfig{
		Enabled: true, NodeID: nodeID, DataDir: dataDir, Trust: trust, TrustKeyIDs: ids, Reason: "ready",
	}
}
