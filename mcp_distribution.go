package main

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/cpdp"
	"github.com/KidCarmi/Culvert/internal/mcp/cpdp/apply"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
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

	// composeReason is the bounded, secret-free classification of the DP composition
	// decision (not_configured / invalid_* / ready), surfaced READ-ONLY on the admin
	// distribution status. composeKeyIDs holds the PUBLIC trust-root key ids (no secret
	// material). Both are set once at startup by initMCPDistribution.
	composeReason string
	composeKeyIDs []string
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
	dpComposed := d.dpGateway != nil || d.dpManagement != nil
	reason := d.composeReason
	keyIDs := append([]string(nil), d.composeKeyIDs...)
	published := d.cpGateway != nil || d.cpManagement != nil
	d.mu.Unlock()
	state := "local_only"
	if enabled && published {
		state = "pending_distribution"
	}
	if reason == "" {
		reason = "not_configured"
	}
	return map[string]any{
		"enabled":            enabled,
		"distribution_state": state,
		"gateway":            gw,
		"management":         mg,
		// DP composition status (read-only; PUBLIC trust-root ids only, no secret).
		"dp_composed":       dpComposed,
		"dp_compose_reason": reason,
		"dp_trust_key_ids":  keyIDs,
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
			applyMCPCapabilityEnvelope(a, gw, cpdp.CapabilityGateway)
		}
	}
	if mg := snap.MCPManagementSnapshot; mg != nil {
		if a := d.dpApplierFor(cpdp.CapabilityManagement); a != nil {
			applyMCPCapabilityEnvelope(a, mg, cpdp.CapabilityManagement)
		}
	}
}

// applyMCPCapabilityEnvelope applies ONE capability's signed envelope as a single
// truthful transaction that couples the distribution activation with the node-local
// rollout commit (Codex P1-B). The invariant it enforces: an AckApplied is IMPOSSIBLE
// unless BOTH the distribution active state AND the local rollout state accepted the
// exact same rollout revision; a rollout rejected locally is NEVER reported to the CP
// as applied/converged, and no new-distribution/old-rollout split is ever left behind.
//
// Ordering (documented for the crash-boundary reasoning, §8):
//
//  1. Rollout precondition PRE-CHECK (pure, node-local): an executing target mode
//     (Shadow/Canary/Production) with the guarded-execution plane not composed, or a
//     capability-mismatched rollout config, is rejected WHOLE — BEFORE any distribution
//     activation — so the common Shadow fail-closed path never stages distribution
//     state (no persist, no window, no crash window, no AckApplied).
//  2. Distribution Apply: signature + epoch + revision + bounds are verified and, only
//     then, the candidate is durably persisted and atomically activated. The signature
//     is verified HERE, before any rollout config is trusted — there is no unsigned
//     local rollout shortcut.
//  3. Rollout COMMIT: the second durable half. Since the precondition was pre-checked,
//     the only failure reaching here is a rollout-state persistence failure.
//  4. COMPENSATE on rollout failure: revert the distribution activation to the prior
//     active snapshot and replace the pending Applied ack with a Rejected one, so no
//     AckApplied is delivered and no revision split remains. The rollout state has
//     already rolled itself back to the prior config (commitRolloutTransition is
//     atomic). A double persistence fault (compensating write also failing) is logged
//     and converged at the next restart by reconcileRolloutWithDistribution.
func applyMCPCapabilityEnvelope(a *apply.Applier, env *cpdp.Envelope, capb cpdp.Capability) {
	cfg := rolloutFromEnvelope(env)
	mgmt := capb == cpdp.CapabilityManagement
	// (1) Deterministic precondition pre-check, before distribution activation.
	if cfg != nil {
		if (cfg.Capability == rollout.CapabilityManagement) != mgmt {
			// Capability isolation: a Gateway envelope must never carry a Management
			// rollout (or vice versa). Reject WHOLE without staging distribution.
			_ = a.RejectAck(env, errRolloutPersistFailed)
			logger.Printf("MCP %s snapshot rejected: rollout capability mismatch (distribution not applied)", capb.String())
			return
		}
		if cfg.Mode.Executes() && !execDepsConfigured(mgmt) {
			_ = a.RejectAck(env, errShadowExecDepsNotConfigured)
			logger.Printf("MCP %s snapshot rejected: rollout %s requires execution dependencies (fail-closed; distribution not applied, no AckApplied)",
				capb.String(), cfg.Mode.String())
			return
		}
	}
	// (2) Distribution transaction: verify + persist + activate (Applied ack pending).
	if _, err := a.Apply(env); err != nil {
		logger.Printf("MCP %s snapshot rejected (SWG unaffected): %v", capb.String(), sanitizeLog(err.Error()))
		return
	}
	// The envelope carries no rollout change: distribution stands alone (absence is not
	// deletion — the local rollout state is kept).
	if cfg == nil {
		return
	}
	// (3) Rollout commit — the coupled second half.
	if err := getMCPRollout().commitRolloutTransition(cfg, "cp-snapshot", time.Now()); err != nil {
		// (4) Compensate: the rollout half was rejected AFTER the distribution half
		// activated. Revert distribution so the two never diverge and no AckApplied
		// stands for a rollout the node rejected.
		if _, aerr := a.AbortApplied(err); aerr != nil {
			logger.Printf("MCP %s CRITICAL: rollout commit failed AND distribution abort failed; restart reconciliation will converge: rollout=%v abort=%v",
				capb.String(), sanitizeLog(err.Error()), sanitizeLog(aerr.Error()))
			return
		}
		logger.Printf("MCP %s snapshot rejected: rollout commit failed, distribution reverted (no AckApplied): %v",
			capb.String(), sanitizeLog(err.Error()))
	}
}
