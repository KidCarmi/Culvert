package runtime

import (
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/identity"
	"github.com/KidCarmi/Culvert/internal/mcp/jsonrpc"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
)

// PolicyProvider supplies the current capability-local policy snapshot to a
// listener. It is READ-ONLY from the listener's perspective (an atomic snapshot
// load); the listener never mutates it. A nil return means no snapshot is published
// for that capability — the runtime then fails closed (never permissive).
type PolicyProvider interface {
	PolicySnapshot(capNS protocol.Capability) *policy.Snapshot
}

// newPolicyEngine builds this pipeline's own pure evaluator (no shared mutable state).
func newPolicyEngine() *policy.Engine { return policy.NewEngine(policy.DefaultLimits()) }

// policyErrorCode is the stable JSON-RPC error code for a policy rejection.
const policyErrorCode = -32050

// dispatchPolicy is the PR-6 decision-only path for a decision-point method
// (tools/list, tools/call). It builds the typed DecisionInput, evaluates the
// capability-local snapshot, records a sanitized policy observation, and maps the
// result to a deterministic response. It NEVER calls the credential broker, a
// provider, or an upstream MCP server, and NEVER fabricates execution success:
// even an ALLOW-class decision returns an execution-not-implemented result.
func (p *pipeline) dispatchPolicy(rb *recBuilder, req Request, msg jsonrpc.Message, ctx *identity.ResolvedContext, now time.Time) Outcome {
	snap := p.policy.PolicySnapshot(p.capability)
	if snap == nil {
		// Fail closed — never fall back to permissive observe mode.
		p.ctr.requestsRejected.Add(1)
		rb.rec.PolicyAction = policy.ActionDeny.String()
		rb.rec.PolicyReason = policy.ReasonSnapshotUnavailable.String()
		body := policyError(msg.ID, policy.ReasonSnapshotUnavailable, policy.ActionDeny, "")
		return p.finish(rb, Outcome{Status: 200, Disposition: DispRejected, Reason: mcperr.ReasonPolicySnapshotInvalid, ResponseBody: body})
	}
	in := p.buildPolicyInput(req, msg, ctx, snap.Revision(), now)
	d, _, _ := p.policyEngine.Evaluate(snap, &in)

	// Sanitized policy observation (safe metadata only).
	rb.rec.PolicyAction = d.Action.String()
	rb.rec.PolicyReason = string(d.Reason)
	rb.rec.MatchedRule = string(d.MatchedRule)
	rb.rec.PolicyRevision = uint64(d.PolicyRevision)

	if d.Action.IsAllowClass() {
		// Record the TRUE policy result, but do not execute: PR-6 has no upstream.
		p.ctr.observeOnly.Add(1)
		rb.rec.ExecutionState = "not_implemented"
		body := executionNotAvailable(msg.ID, d)
		return p.finish(rb, Outcome{Status: 200, Disposition: DispPolicyAllowed, Reason: mcperr.ReasonObserveOnly, ResponseBody: body})
	}
	// DENY / QUARANTINE / REQUIRE_* → deterministic typed JSON-RPC rejection.
	p.ctr.requestsRejected.Add(1)
	body := policyError(msg.ID, d.Reason, d.Action, d.MatchedRule)
	return p.finish(rb, Outcome{Status: 200, Disposition: DispRejected, Reason: mcperr.ReasonObserveOnly, ResponseBody: body})
}

// buildPolicyInput materializes the immutable decision tuple from the resolved
// identity, the live registry/catalog snapshots and the operation. All facts are
// read BEFORE evaluation (the evaluator itself does no I/O). It carries no raw
// arguments — only the tool name (an operand identity) and one-way fingerprints.
func (p *pipeline) buildPolicyInput(req Request, msg jsonrpc.Message, ctx *identity.ResolvedContext, polRev policy.Revision, now time.Time) policy.DecisionInput {
	capNS := policyCapability(p.capability)
	in := policy.DecisionInput{
		Capability:       capNS,
		PolicyRevision:   uint64(polRev),
		CatalogRevision:  catalogRevision(p.deps),
		RegistryRevision: registryRevision(p.deps),
		RuntimeRevision:  p.rev,
		EvalTime:         now,
		Principal:        policyPrincipal(ctx),
		Client:           policyClient(ctx, capNS),
		Session:          policy.Session{Fingerprint: digest(ctx.Fingerprint()), Assurance: policyAssurance(ctx.Assurance())},
	}
	if ag, ok := ctx.Agent(); ok {
		in.Agent = &policy.Agent{
			AgentID: ag.AgentID, Owner: ag.Owner.ID, Version: ag.Version,
			Managed: policyManaged(ag.Managed), Trust: policyTrust(ag.Trust),
		}
		in.Principal.SubjectID = firstNonEmpty(in.Principal.SubjectID, ag.AgentID)
	}
	op := policyOperation(p.capability, msg.Method, req.ServerID)
	if p.capability == protocol.Gateway {
		p.attachGatewayRefs(&in, req.ServerID, msg, &op)
	}
	in.Operation = op
	return in
}

// attachGatewayRefs fills the Gateway server + tool of the decision tuple from the
// live registry/catalog snapshots.
func (p *pipeline) attachGatewayRefs(in *policy.DecisionInput, serverID string, msg jsonrpc.Message, op *policy.Operation) {
	if p.deps.Registry != nil {
		if rec, ok := p.deps.Registry.Current().Get(registry.ServerID(serverID)); ok {
			in.Server = &policy.Server{
				ServerID: string(rec.ID), Owner: string(rec.OwnerScope),
				Enabled: rec.Enabled, Verification: policyVerification(rec.Verification),
			}
		}
	}
	if msg.Method != "tools/call" {
		return
	}
	name := toolNameFromParams(msg.Params)
	if name == "" {
		return
	}
	op.Operand = name
	tl := &policy.Tool{Name: name, ServerID: serverID}
	if p.deps.Catalog != nil {
		if rec, ok := p.deps.Catalog.Current().Get(catalog.ToolKey{Server: registry.ServerID(serverID), Name: name}); ok {
			sum := rec.Fingerprint.Sum()
			tl.FingerprintHash = hex.EncodeToString(sum[:])
			tl.Disposition, tl.Drift = policyDisposition(rec.Eligibility)
			tl.Destination = policyDestination(rec.Fingerprint.Destination)
			in.Tool = tl
			return
		}
	}
	// No catalog record ⇒ unknown tool (drives the hard quarantine override).
	tl.Disposition, tl.Drift = policy.DispQuarantined, policy.DriftUnknownTool
	in.Tool = tl
}

// --- translation helpers ---------------------------------------------------

func policyCapability(c protocol.Capability) policy.Capability {
	if c == protocol.Management {
		return policy.CapManagement
	}
	return policy.CapGateway
}

func policyPrincipal(ctx *identity.ResolvedContext) policy.Principal {
	p := policy.Principal{
		Tenant:    string(ctx.TenantID()),
		Assurance: policyAssurance(ctx.Assurance()),
		Issuer:    ctx.Issuer(),
	}
	sub := ctx.Subject()
	switch sub.Kind {
	case identity.SubjectHuman:
		p.Kind = policy.SubjectHuman
		if sub.Human != nil {
			p.SubjectID = sub.Human.Subject
			p.Groups = append([]string(nil), sub.Human.Groups...)
		}
	case identity.SubjectWorkload:
		p.Kind = policy.SubjectWorkload
		if sub.Workload != nil {
			p.SubjectID = sub.Workload.Service
		}
	}
	return p
}

func policyClient(ctx *identity.ResolvedContext, capNS policy.Capability) policy.Client {
	c := ctx.Client()
	return policy.Client{
		ClientID: c.ClientID, AppID: c.AppID, Tenant: string(c.Tenant),
		Trust: policyTrust(c.Trust), Capability: capNS,
	}
}

func policyOperation(c protocol.Capability, method, operand string) policy.Operation {
	op := policy.Operation{Method: method, Operand: operand}
	if c == protocol.Management {
		op.Namespace = policy.NamespaceManagementOperation
		op.DecisionPoint = "management_authorization"
	} else {
		op.Namespace = policy.NamespaceGatewayTool
		op.DecisionPoint = "policy_engine"
	}
	switch method {
	case "tools/list":
		op.Class = policy.OpDiscovery
		if c == protocol.Gateway {
			op.DecisionPoint = "tool_catalog_discovery"
		}
	default: // tools/call
		// Conservative default: a tool call is a write unless a later slice supplies a
		// finer class. Destructive is NEVER assumed.
		op.Class = policy.OpWrite
	}
	return op
}

func policyAssurance(a identity.AssuranceLevel) policy.Assurance {
	switch a {
	case identity.AssuranceLow:
		return policy.AssuranceLow
	case identity.AssuranceMedium:
		return policy.AssuranceMedium
	case identity.AssuranceHigh:
		return policy.AssuranceHigh
	default:
		return policy.AssuranceUnknown
	}
}

func policyTrust(t identity.TrustClass) policy.TrustClass {
	switch t {
	case identity.TrustUntrusted:
		return policy.TrustUntrusted
	case identity.TrustLow:
		return policy.TrustLow
	case identity.TrustHigh:
		return policy.TrustHigh
	default:
		return policy.TrustUnknown
	}
}

func policyManaged(m identity.ManagedState) policy.ManagedState {
	switch m {
	case identity.Managed:
		return policy.Managed
	case identity.Unmanaged:
		return policy.Unmanaged
	default:
		return policy.ManagedUnknown
	}
}

func policyVerification(v registry.Verification) policy.ServerVerification {
	if v == registry.VerifyIdentityMismatch {
		return policy.ServerIdentityMismatch
	}
	return policy.ServerVerified
}

func policyDisposition(e catalog.Eligibility) (policy.Disposition, policy.DriftClass) {
	switch e {
	case catalog.Quarantined:
		return policy.DispQuarantined, policy.DriftUnset // engine treats unset+quarantined as unknown tool
	case catalog.ReviewRequired:
		return policy.DispReviewRequired, policy.DriftSemanticDrift
	case catalog.PendingNarrowing:
		return policy.DispPendingNarrowing, policy.DriftSafeNarrowing
	case catalog.ServerDisabled:
		return policy.DispServerDisabled, policy.DriftIdentityChange
	default: // Usable
		return policy.DispUsable, policy.DriftNoMaterialChange
	}
}

func policyDestination(d catalog.DestinationClass) policy.Destination {
	switch d {
	case catalog.DestNone:
		return policy.DestinationNone
	case catalog.DestApproved:
		return policy.DestinationApproved
	case catalog.DestInternal:
		return policy.DestinationInternal
	case catalog.DestArbitrary:
		return policy.DestinationArbitrary
	default:
		return policy.DestinationUnknown
	}
}

func catalogRevision(d Deps) uint64 {
	// A decision input requires a POSITIVE catalog revision. A fresh, empty catalog
	// reports revision 0 (a valid state: no tools discovered yet), so clamp it to the
	// genesis revision 1 — otherwise every Gateway decision would fail structural
	// input validation before any real evaluation ran.
	if d.Catalog == nil {
		return 1
	}
	if r := d.Catalog.Current().Revision(); r > 0 {
		return r
	}
	return 1
}

func registryRevision(d Deps) uint64 {
	if d.Registry == nil {
		return 0
	}
	return d.Registry.Current().Revision()
}

func toolNameFromParams(params json.RawMessage) string {
	if len(params) == 0 {
		return ""
	}
	var b struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(params, &b); err != nil {
		return ""
	}
	return b.Name
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
