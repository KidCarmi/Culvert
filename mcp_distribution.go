package main

import (
	"sync"
	"sync/atomic"

	"github.com/KidCarmi/Culvert/internal/mcp/cpdp"
	"github.com/KidCarmi/Culvert/internal/mcp/cpdp/apply"
)

// mcpDistribution holds the node-local MCP CP→DP signed-snapshot distribution
// state. It is DISABLED BY DEFAULT: with no MCP signer/trust configured, the CP
// capture returns nil envelopes (so a ConfigSnapshot is byte-identical to the
// pre-PR-10 SWG snapshot) and the DP apply path ignores any attached MCP envelope.
// The two capabilities are mechanically separate: a Gateway envelope never touches
// Management state and vice versa.
//
// This is the thin package-main seam only — all signing/validation/apply/rollback
// logic lives in internal/mcp/cpdp{,/apply,/publication}. No signing or validation
// logic is inlined here.
type mcpDistribution struct {
	enabled atomic.Bool

	mu sync.Mutex
	// CP side: the currently-published signed envelope per capability, captured into
	// each outbound ConfigSnapshot. nil ⇒ absent ⇒ no MCP change on the wire.
	cpGateway    *cpdp.Envelope
	cpManagement *cpdp.Envelope
	// DP side: the per-capability apply engines (nil when this node is not an MCP DP
	// or MCP distribution is disabled).
	dpGateway    *apply.Applier
	dpManagement *apply.Applier
}

// globalMCPDistribution is the process-wide, disabled-by-default distribution seam.
var globalMCPDistribution = &mcpDistribution{}

// mcpCapturedGateway returns the CP-published Gateway envelope to stamp onto an
// outbound ConfigSnapshot, or nil when MCP distribution is disabled/unpublished.
func mcpCapturedGateway() *cpdp.Envelope {
	d := globalMCPDistribution
	if !d.enabled.Load() {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cpGateway
}

// mcpCapturedManagement mirrors mcpCapturedGateway for the Management capability.
func mcpCapturedManagement() *cpdp.Envelope {
	d := globalMCPDistribution
	if !d.enabled.Load() {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cpManagement
}

// setCPPublished records a CP-published signed envelope for a capability so the
// next captured ConfigSnapshot carries it. Used by the publication coordinator's
// transport adapter.
func (d *mcpDistribution) setCPPublished(env *cpdp.Envelope) {
	if env == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	switch env.Manifest.Capability {
	case cpdp.CapabilityGateway:
		d.cpGateway = env
	case cpdp.CapabilityManagement:
		d.cpManagement = env
	}
}

// dpApplierFor returns the DP apply engine for a capability, or nil when this node
// is not an MCP DP for it (disabled).
func (d *mcpDistribution) dpApplierFor(capability cpdp.Capability) *apply.Applier {
	d.mu.Lock()
	defer d.mu.Unlock()
	switch capability {
	case cpdp.CapabilityGateway:
		return d.dpGateway
	case cpdp.CapabilityManagement:
		return d.dpManagement
	default:
		return nil
	}
}

// setDPApplier wires a capability's DP apply engine (test/startup wiring).
func (d *mcpDistribution) setDPApplier(capability cpdp.Capability, a *apply.Applier) {
	d.mu.Lock()
	defer d.mu.Unlock()
	switch capability {
	case cpdp.CapabilityGateway:
		d.dpGateway = a
	case cpdp.CapabilityManagement:
		d.dpManagement = a
	}
}

// mcpCapabilityStatus is the safe, read-only distribution status for one MCP
// capability (no secret, no signing key). Zeros/empties when nothing is published.
type mcpCapabilityStatus struct {
	CurrentHash       string `json:"current_hash"`
	PreviousHash      string `json:"previous_hash"`
	Epoch             int64  `json:"epoch"`
	ConfigRevision    uint64 `json:"config_revision"`
	PolicyRevision    uint64 `json:"policy_revision"`
	CatalogRevision   uint64 `json:"catalog_revision"`
	CredentialRev     uint64 `json:"credential_revision"`
	SigningKeyID      string `json:"signing_key_id"`
	MinimumDPVersion  uint32 `json:"minimum_dp_version"`
	RollbackAvailable bool   `json:"rollback_available"`
}

// mcpDistributionStatus reports the safe, operator-visible distribution status for
// both capabilities. When MCP distribution is disabled (the default) it truthfully
// reports local_only with empty per-capability status. It never exposes a private
// signing key, a raw signature, or a full raw snapshot.
func mcpDistributionStatus() map[string]any {
	d := globalMCPDistribution
	enabled := d.enabled.Load()
	d.mu.Lock()
	gw := capStatus(d.cpGateway)
	mg := capStatus(d.cpManagement)
	d.mu.Unlock()
	state := "local_only"
	if enabled && (d.cpGateway != nil || d.cpManagement != nil) {
		state = "pending_distribution"
	}
	return map[string]any{
		"enabled":            enabled,
		"distribution_state": state,
		"gateway":            gw,
		"management":         mg,
	}
}

func capStatus(env *cpdp.Envelope) mcpCapabilityStatus {
	if env == nil {
		return mcpCapabilityStatus{}
	}
	return mcpCapabilityStatus{
		CurrentHash:      env.ContentHash,
		Epoch:            env.Manifest.Epoch,
		ConfigRevision:   env.Manifest.Revisions.Config,
		PolicyRevision:   env.Manifest.Revisions.Policy,
		CatalogRevision:  env.Manifest.Revisions.Catalog,
		CredentialRev:    env.Manifest.Revisions.Credential,
		SigningKeyID:     env.KeyID,
		MinimumDPVersion: uint32(env.Manifest.MinDPVersion),
	}
}

// applySnapshotMCP applies the OPTIONAL signed MCP envelopes carried by a received
// ConfigSnapshot. Each capability is applied INDEPENDENTLY and WHOLE:
//
//   - a present (non-nil) envelope is handed to that capability's DP apply engine,
//     which verifies signature/epoch/version and either activates it atomically or
//     rejects it whole (keeping the DP's prior valid MCP snapshot);
//   - a nil envelope is a no-op — absence is NOT deletion, the DP keeps its local
//     MCP state (an older/rolled-back CP that predates MCP never wipes it);
//   - a failure to apply one capability NEVER affects the other, and NEVER corrupts
//     the SWG config apply (this runs after the SWG apply and only touches MCP
//     state).
//
// When MCP distribution is disabled (the default) the DP appliers are nil and the
// envelopes are ignored. This function READS both fields so the config-surface
// AppliesOnDP parity holds for the two MCP snapshot fields.
func applySnapshotMCP(snap ConfigSnapshot) {
	d := globalMCPDistribution
	if gw := snap.MCPGatewaySnapshot; gw != nil {
		if a := d.dpApplierFor(cpdp.CapabilityGateway); a != nil {
			if _, err := a.Apply(gw); err != nil {
				logger.Printf("MCP gateway snapshot rejected (SWG unaffected): %v", err)
			}
		}
	}
	if mg := snap.MCPManagementSnapshot; mg != nil {
		if a := d.dpApplierFor(cpdp.CapabilityManagement); a != nil {
			if _, err := a.Apply(mg); err != nil {
				logger.Printf("MCP management snapshot rejected (SWG unaffected): %v", err)
			}
		}
	}
}
