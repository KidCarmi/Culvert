package cpdp

import (
	"encoding/json"
	"strings"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// ValidateInput carries the context the whole-snapshot validator needs.
type ValidateInput struct {
	// ExpectCapability is the capability of the store the snapshot targets. The
	// envelope's signed capability must equal it.
	ExpectCapability Capability
	// DPVersion is the receiving DP's compatibility version.
	DPVersion CompatVersion
	// LastEpoch is the DP's last-seen trusted epoch, for a NON-mutating stale check
	// (the mutating ratchet is applied separately, only after validation passes).
	LastEpoch int64
	// Trust is the DP's trust store (public roots only).
	Trust *TrustStore
	// Limits is the validated bound set.
	Limits Limits
}

// Validate performs the complete whole-snapshot validation in the mandated order,
// rejecting the ENTIRE snapshot on any failure (no partial apply). It runs BEFORE
// any state mutation. The order is:
//
//	envelope bounds → schema → alg → key trust → content hash → signature
//	→ capability match → capability isolation → epoch stale check (non-mutating)
//	→ revision bounds → minimum DP version → per-section + aggregate bounds
//	→ payload consistency (safe config, references, no secret-bearing fields).
//
// It does NOT ratchet the epoch or mutate any state — a caller applies the
// mutating CommitObservedEpoch only after Validate returns nil.
func Validate(env *Envelope, in ValidateInput) error {
	if env == nil {
		return mcperr.New(mcperr.ReasonSnapshotMalformed, "cpdp.validate", "nil envelope")
	}
	// 1-6: cryptographic verification (schema, alg, key trust, hash, signature).
	if err := VerifySignature(env, in.Trust, in.Limits); err != nil {
		return err
	}
	// 7: capability match against the target store.
	if !in.ExpectCapability.Valid() {
		return mcperr.New(mcperr.ReasonSnapshotCapabilityMismatch, "cpdp.validate", "invalid target capability")
	}
	if env.Manifest.Capability != in.ExpectCapability {
		return mcperr.New(mcperr.ReasonSnapshotCapabilityMismatch, "cpdp.validate",
			"envelope capability does not match target store")
	}
	// 8: capability isolation (the payload carries only this capability's state).
	if err := env.Payload.checkCapabilityIsolation(env.Manifest.Capability); err != nil {
		return err
	}
	// 9: epoch stale check (NON-mutating). A stale/zombie epoch is rejected here so a
	// bad snapshot never reaches the ratchet.
	if err := (&EpochRatchet{last: in.LastEpoch}).CheckEpoch(env.Manifest.Epoch); err != nil {
		return err
	}
	// 10: revision bounds + internal consistency.
	if err := env.Manifest.Revisions.validate(); err != nil {
		return err
	}
	// 11: minimum DP version gate.
	if err := CheckMinVersion(env.Manifest.MinDPVersion, in.DPVersion); err != nil {
		return err
	}
	// 12: per-section and aggregate byte/entry bounds.
	if err := validateBounds(env, in.Limits); err != nil {
		return err
	}
	// 13: payload consistency, safe configuration, references, no secret-bearing.
	if err := validatePayloadConsistency(env, in.Limits); err != nil {
		return err
	}
	return nil
}

// validateBounds enforces the per-section entry caps and the aggregate byte
// bound. A section over its cap, or a total encoding over the aggregate/envelope
// bound, rejects the whole snapshot.
func validateBounds(env *Envelope, l Limits) error {
	raw, err := json.Marshal(env)
	if err != nil {
		return mcperr.Wrap(mcperr.ReasonSnapshotMalformed, "cpdp.validate", "marshal envelope", err)
	}
	if len(raw) > l.MaxEnvelopeBytes() {
		return mcperr.New(mcperr.ReasonSnapshotTooLarge, "cpdp.validate", "envelope exceeds byte bound")
	}
	if g := env.Payload.Gateway; g != nil {
		if len(g.Servers) > l.MaxRegistryServers() {
			return mcperr.New(mcperr.ReasonSnapshotTooLarge, "cpdp.validate", "too many servers")
		}
		if len(g.Tools) > l.MaxCatalogTools() {
			return mcperr.New(mcperr.ReasonSnapshotTooLarge, "cpdp.validate", "too many tools")
		}
		if len(g.CredentialProfiles) > l.MaxCredentialProfiles() {
			return mcperr.New(mcperr.ReasonSnapshotTooLarge, "cpdp.validate", "too many credential profiles")
		}
		if len(g.InspectionProfiles) > l.MaxInspectionProfiles() {
			return mcperr.New(mcperr.ReasonSnapshotTooLarge, "cpdp.validate", "too many inspection profiles")
		}
		if len(g.PolicySource) > l.MaxPayloadSectionBytes() {
			return mcperr.New(mcperr.ReasonSnapshotTooLarge, "cpdp.validate", "policy source exceeds section bound")
		}
	}
	return nil
}

// validatePayloadConsistency enforces payload-internal integrity: required
// references, safe configuration, and the no-secret-bearing invariant. It never
// mutates the envelope.
func validatePayloadConsistency(env *Envelope, l Limits) error {
	switch env.Manifest.Capability {
	case CapabilityGateway:
		return validateGatewayPayload(env.Payload.Gateway, l)
	case CapabilityManagement:
		return validateManagementPayload(env.Payload.Management)
	default:
		return mcperr.New(mcperr.ReasonSnapshotCapabilityMismatch, "cpdp.validate", "unknown capability")
	}
}

func validateGatewayPayload(g *GatewayPayload, l Limits) error {
	if g == nil {
		return mcperr.New(mcperr.ReasonSnapshotValidationFailed, "cpdp.validate", "nil gateway payload")
	}
	seenServer := make(map[string]bool, len(g.Servers))
	for i := range g.Servers {
		s := &g.Servers[i]
		if s.ID == "" || s.Endpoint == "" {
			return mcperr.New(mcperr.ReasonSnapshotValidationFailed, "cpdp.validate", "server record missing id or endpoint")
		}
		if seenServer[s.ID] {
			return mcperr.New(mcperr.ReasonSnapshotValidationFailed, "cpdp.validate", "duplicate server id")
		}
		seenServer[s.ID] = true
	}
	// Every tool must reference a registered server (catalog/registry consistency).
	for i := range g.Tools {
		t := &g.Tools[i]
		if t.Name == "" || t.Server == "" {
			return mcperr.New(mcperr.ReasonSnapshotValidationFailed, "cpdp.validate", "tool record missing name or server")
		}
		if !seenServer[t.Server] {
			return mcperr.New(mcperr.ReasonSnapshotValidationFailed, "cpdp.validate", "tool references an unregistered server")
		}
	}
	// Credential-profile metadata must be a REFERENCE, never a materialized secret.
	for i := range g.CredentialProfiles {
		c := &g.CredentialProfiles[i]
		if c.ProfileID == "" {
			return mcperr.New(mcperr.ReasonSnapshotValidationFailed, "cpdp.validate", "credential profile missing id")
		}
		if looksLikeSecret(c.ProviderRef) {
			return mcperr.New(mcperr.ReasonSnapshotValidationFailed, "cpdp.validate", "credential profile carries secret-bearing material")
		}
	}
	return nil
}

func validateManagementPayload(m *ManagementPayload) error {
	if m == nil {
		return mcperr.New(mcperr.ReasonSnapshotValidationFailed, "cpdp.validate", "nil management payload")
	}
	// Management mutation is never permitted in V1 (defence in depth with the
	// isolation check).
	if m.Listener.MutationEnabled {
		return mcperr.New(mcperr.ReasonSnapshotValidationFailed, "cpdp.validate", "management mutation not permitted in V1")
	}
	return nil
}

// looksLikeSecret is a conservative defensive check that a value that should be a
// REFERENCE is not an accidentally-embedded secret (e.g. the alerts at-rest
// ciphertext prefix). It never inspects a real secret — only guards a field that
// must not carry one.
func looksLikeSecret(s string) bool {
	return strings.HasPrefix(s, "enc:v1:") || strings.HasPrefix(s, "-----BEGIN")
}
