// Package apply implements the Data-Plane application and recovery path for signed
// MCP snapshots: it prepares immutable runtime objects OFF the active request
// path, runs bounded self-validation and dry policy samples using the EXACT PR-6
// compiler/evaluator, durably persists the validated candidate, ratchets the
// trusted epoch, atomically swaps the capability-local active pointer, retains the
// previous snapshot, and generates a hash-bound acknowledgement.
//
// It never mutates active state before all validation and persistence succeed,
// never holds the active-store lock while compiling, never materializes a
// credential, never performs an upstream or Control-Plane call, and never exposes
// a partially built object. It is decision-only: an applied snapshot activates
// decision state; the runtime still returns execution_state "not_implemented".
package apply

import (
	"github.com/KidCarmi/Culvert/internal/mcp/cpdp"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
)

// PreparedState is an immutable, fully-built runtime candidate for exactly one
// signed snapshot. It is constructed off the active path and only published by an
// atomic pointer swap after persistence succeeds — no request ever observes a
// half-built PreparedState.
type PreparedState struct {
	Capability  cpdp.Capability
	ContentHash string
	Revisions   cpdp.Revisions
	Epoch       int64

	// Gateway runtime objects (nil for a Management snapshot).
	Policy   *policy.Snapshot
	servers  map[string]cpdp.ServerRecord
	tools    map[string]cpdp.ToolRecord
	credMeta map[string]cpdp.CredentialProfileMeta
	inspMeta map[string]cpdp.InspectionProfileMeta

	// Management runtime objects (nil for a Gateway snapshot).
	mgmt *cpdp.ManagementPayload
}

// ServerCount / ToolCount expose bounded prepared-index sizes for health/tests.
func (p *PreparedState) ServerCount() int { return len(p.servers) }
func (p *PreparedState) ToolCount() int   { return len(p.tools) }

// Server returns a prepared server record by id (index lookup), off the active
// path.
func (p *PreparedState) Server(id string) (cpdp.ServerRecord, bool) {
	s, ok := p.servers[id]
	return s, ok
}

func policyCapability(c cpdp.Capability) (policy.Capability, bool) {
	switch c {
	case cpdp.CapabilityGateway:
		return policy.CapGateway, true
	case cpdp.CapabilityManagement:
		return policy.CapManagement, true
	default:
		return 0, false
	}
}

// Prepare builds the immutable runtime candidate for a validated envelope OFF the
// active path, using the EXACT PR-6 compiler, and runs the bounded dry checks. The
// caller MUST have already run cpdp.Validate on the envelope; Prepare performs the
// build + dry-sample step (5 + 6) and returns an error (leaving active state
// untouched) if any object fails to build or any dry check fails.
func Prepare(env *cpdp.Envelope) (*PreparedState, error) {
	if env == nil {
		return nil, mcperr.New(mcperr.ReasonSnapshotMalformed, "cpdp.apply.prepare", "nil envelope")
	}
	ps := &PreparedState{
		Capability:  env.Manifest.Capability,
		ContentHash: env.ContentHash,
		Revisions:   env.Manifest.Revisions,
		Epoch:       env.Manifest.Epoch,
	}
	switch env.Manifest.Capability {
	case cpdp.CapabilityGateway:
		if err := prepareGateway(ps, env.Payload.Gateway); err != nil {
			return nil, err
		}
	case cpdp.CapabilityManagement:
		if err := prepareManagement(ps, env.Payload.Management); err != nil {
			return nil, err
		}
	default:
		return nil, mcperr.New(mcperr.ReasonSnapshotCapabilityMismatch, "cpdp.apply.prepare", "unknown capability")
	}
	if err := ps.dryChecks(); err != nil {
		return nil, err
	}
	return ps, nil
}

func prepareGateway(ps *PreparedState, g *cpdp.GatewayPayload) error {
	if g == nil {
		return mcperr.New(mcperr.ReasonSnapshotValidationFailed, "cpdp.apply.prepare", "nil gateway payload")
	}
	// Compile the reviewed policy source with the EXACT PR-6 compiler. The compiler
	// enforces default-DENY, capability, and rule legality — a failure here is a
	// dry-validation failure and the candidate is rejected.
	snap, err := policy.Compile([]byte(g.PolicySource), policy.CreatedMeta{Author: "cpdp"}, policy.DefaultLimits())
	if err != nil {
		return mcperr.Wrap(mcperr.ReasonSnapshotValidationFailed, "cpdp.apply.prepare", "policy compile", err)
	}
	if snap.Capability() != policy.CapGateway {
		return mcperr.New(mcperr.ReasonSnapshotCapabilityMismatch, "cpdp.apply.prepare", "policy source is not a gateway policy")
	}
	ps.Policy = snap
	// Build immutable lookup indexes off the active path.
	ps.servers = make(map[string]cpdp.ServerRecord, len(g.Servers))
	for i := range g.Servers {
		ps.servers[g.Servers[i].ID] = g.Servers[i]
	}
	ps.tools = make(map[string]cpdp.ToolRecord, len(g.Tools))
	for i := range g.Tools {
		ps.tools[g.Tools[i].Server+"|"+g.Tools[i].Name] = g.Tools[i]
	}
	ps.credMeta = make(map[string]cpdp.CredentialProfileMeta, len(g.CredentialProfiles))
	for i := range g.CredentialProfiles {
		ps.credMeta[g.CredentialProfiles[i].ProfileID] = g.CredentialProfiles[i]
	}
	ps.inspMeta = make(map[string]cpdp.InspectionProfileMeta, len(g.InspectionProfiles))
	for i := range g.InspectionProfiles {
		ps.inspMeta[g.InspectionProfiles[i].ID] = g.InspectionProfiles[i]
	}
	return nil
}

func prepareManagement(ps *PreparedState, m *cpdp.ManagementPayload) error {
	if m == nil {
		return mcperr.New(mcperr.ReasonSnapshotValidationFailed, "cpdp.apply.prepare", "nil management payload")
	}
	if m.Listener.MutationEnabled {
		return mcperr.New(mcperr.ReasonSnapshotValidationFailed, "cpdp.apply.prepare", "management mutation not permitted in V1")
	}
	// A copy so the prepared state is immutable and unaliased from the envelope.
	cp := *m
	ps.mgmt = &cp
	return nil
}

// dryChecks runs the bounded self-validation and dry policy samples against the
// prepared runtime. Every check is deterministic and performs no network, CP, or
// broker activity.
func (p *PreparedState) dryChecks() error {
	switch p.Capability {
	case cpdp.CapabilityGateway:
		return p.dryChecksGateway()
	case cpdp.CapabilityManagement:
		return p.dryChecksManagement()
	default:
		return mcperr.New(mcperr.ReasonSnapshotCapabilityMismatch, "cpdp.apply.prepare", "unknown capability")
	}
}

func (p *PreparedState) dryChecksGateway() error {
	if p.Policy == nil {
		return mcperr.New(mcperr.ReasonSnapshotValidationFailed, "cpdp.apply.prepare", "no compiled policy")
	}
	// Default-deny: the compiler already enforces a DENY default; assert it here as
	// a belt-and-braces dry sample.
	if p.Policy.DefaultAction() != policy.ActionDeny {
		return mcperr.New(mcperr.ReasonSnapshotValidationFailed, "cpdp.apply.prepare", "policy does not default-deny")
	}
	// Dry evaluation: the pure PR-6 evaluator must run I/O-free and DETERMINISTICALLY
	// on an incomplete input, and fail closed (never allow-class). Two evaluations
	// must agree.
	eng := policy.NewEngine(policy.DefaultLimits())
	in := &policy.DecisionInput{Capability: policy.CapGateway}
	d1, _, _ := eng.Evaluate(p.Policy, in)
	d2, _, _ := eng.Evaluate(p.Policy, in)
	if d1.Action != d2.Action {
		return mcperr.New(mcperr.ReasonSnapshotValidationFailed, "cpdp.apply.prepare", "policy evaluation is non-deterministic")
	}
	if d1.IsAllowClass() {
		return mcperr.New(mcperr.ReasonSnapshotValidationFailed, "cpdp.apply.prepare", "policy allowed an incomplete input (fail-open)")
	}
	// Catalog/registry consistency: every prepared tool references a prepared server.
	for k, t := range p.tools {
		_ = k
		if _, ok := p.servers[t.Server]; !ok {
			return mcperr.New(mcperr.ReasonSnapshotValidationFailed, "cpdp.apply.prepare", "prepared tool references an unknown server")
		}
	}
	// No secret-bearing credential metadata slipped through.
	for _, c := range p.credMeta {
		if looksLikeSecret(c.ProviderRef) {
			return mcperr.New(mcperr.ReasonSnapshotValidationFailed, "cpdp.apply.prepare", "prepared credential metadata is secret-bearing")
		}
	}
	return nil
}

func (p *PreparedState) dryChecksManagement() error {
	if p.mgmt == nil {
		return mcperr.New(mcperr.ReasonSnapshotValidationFailed, "cpdp.apply.prepare", "no management state")
	}
	// Management mutation must remain unavailable.
	if p.mgmt.Listener.MutationEnabled {
		return mcperr.New(mcperr.ReasonSnapshotValidationFailed, "cpdp.apply.prepare", "management mutation available (forbidden)")
	}
	return nil
}

func looksLikeSecret(s string) bool {
	return len(s) >= 7 && (s[:7] == "enc:v1:") || (len(s) >= 11 && s[:11] == "-----BEGIN ")
}
