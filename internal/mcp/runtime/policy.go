package runtime

import (
	"context"
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
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
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
func (p *pipeline) dispatchPolicy(ctx context.Context, rb *recBuilder, req Request, msg jsonrpc.Message, ident *identity.ResolvedContext, now time.Time) Outcome {
	// Report the tool this request NAMES to the Canary reviewed-target sink FIRST, before
	// any decision this function makes can end the request — and that placement is the
	// whole point, twice over.
	//
	// A Canary scope pins the reviewed fingerprint in its tool selector, so a tool that
	// moves F1→F2 puts every later request OUT of scope; resolveEnforcing then routes them
	// to the shadow or record-only fallback, and the record-only branch returns without
	// ever reaching dispatchExecute, the executor, or the activation transaction. Worse,
	// the SAME F1→F2 change is what makes a new schema reject arguments the old one
	// accepted, so semantic inspection hard-fails those requests and dispatchPolicy exits
	// above the executor entirely (Codex P1, PR #1360, round 2). The snapshot-unavailable
	// and budget-expired returns are the same shape. Reporting from any point downstream
	// of one of those returns cannot see the one sequence the reviewed snapshot exists to
	// catch: the experiment's reviewed target has changed underneath it and the change is
	// exactly what hides the evidence.
	//
	// The identity is therefore derived from the request and the JSON-RPC message ALONE —
	// no policy snapshot, no catalog record, no inspection verdict — so nothing this
	// function can fail on is upstream of it.
	//
	// What is reported is an identity, not a verdict. The root compares the CURRENT
	// authoritative target against the activation's reviewed snapshot under the activation
	// lock, so a tool this activation was never reviewed for latches nothing, and a
	// rejected request drifts a Canary only when its reviewed target really has moved.
	p.observeCanaryReviewedTarget(req, msg)

	snap := p.policy.PolicySnapshot(p.capability)
	if snap == nil {
		// Fail closed — never fall back to permissive observe mode.
		p.ctr.requestsRejected.Add(1)
		rb.rec.PolicyAction = policy.ActionDeny.String()
		rb.rec.PolicyReason = policy.ReasonSnapshotUnavailable.String()
		body := policyError(msg.ID, policy.ReasonSnapshotUnavailable, policy.ActionDeny, "")
		return p.finish(rb, Outcome{Status: 200, Disposition: DispRejected, Reason: mcperr.ReasonPolicySnapshotInvalid, ResponseBody: body})
	}
	in := p.buildPolicyInput(req, msg, ident, snap.Revision(), now)

	// PR-7: semantic inspection runs BEFORE policy evaluation (Gateway tools/call
	// only). A hard security failure (schema invalid, SSRF/private destination,
	// DLP block, malformed args) blocks HERE — an ordinary ALLOW rule can never
	// override it, and schema-invalid arguments never reach policy as valid.
	insp := p.runInspection(ctx, req, msg, now)
	if insp.ran {
		recordInspection(rb, insp.result.Summary)
		applyInspectionToInput(&in, insp.result.Summary)
		if insp.result.HardFail {
			return p.rejectTyped(rb, msg, "BLOCKED_BY_INSPECTION", insp.result.HardReason)
		}
	}

	// The decision is made; the stages after it (durable commit, guarded
	// execution, upstream I/O) are the expensive ones. Re-check the budget so an
	// already-dead request never reaches them.
	if out, expired := p.checkBudget(ctx, rb); expired {
		return out
	}

	d, _, _ := p.policyEngine.Evaluate(snap, &in)

	// Sanitized policy observation (safe metadata only).
	rb.rec.PolicyAction = d.Action.String()
	rb.rec.PolicyReason = string(d.Reason)
	rb.rec.MatchedRule = string(d.MatchedRule)
	rb.rec.PolicyRevision = uint64(d.PolicyRevision)

	// PR-11 / Shadow activation: when a guarded executor is wired (Gateway only, armed
	// by rollout distribution or Shadow composition), hand it a NON-record-only
	// disposition — Shadow evaluate, Canary/Production execute, or a hard block — and it
	// owns the rollout-mode resolution + its own commit-before-side-effect. A RECORD-ONLY
	// disposition (Observe / Disabled / out-of-scope) deliberately KEEPS the inline
	// decision-only path below, which owns the canonical allow-class decision-event
	// commit and denial-lane routing — so composing an evaluator (e.g. a Shadow evaluator
	// on a shadow-ready node) never drops that Observe evidence for the traffic it does
	// not evaluate. When no executor is wired the branch is skipped entirely and the
	// decision-only path runs byte-identically.
	if p.executor != nil {
		ei := p.buildExecInput(req, msg, ident, in, d, insp, snap.Hash(), now)
		// Resolve the rollout disposition EXACTLY ONCE and carry it into execution, so
		// routing and execution never observe two snapshots of the mutable rollout state
		// (Codex P2, PR #1234). A record-only disposition keeps the inline Observe path;
		// everything else is handed to Execute with the same resolution.
		// Captured BEFORE the resolution, so it names the activation this request's scope
		// decision was actually made under. See Deps.CanaryGeneration.
		genAtResolve := p.deps.canaryGenerationAt(p.capability.String())
		res := p.executor.Resolve(ei)
		// Bind the request to the authorization envelope it resolved under. The hash comes
		// from the resolution itself — the same atomic scope snapshot that decided InScope —
		// so the request carries the envelope that actually authorized it rather than
		// whichever one happens to be installed later. The admission boundary requires the
		// two to still agree before it grants budget authority; see canaryAdmitScopeNotInForce.
		ei.ResolvedScopeHash = res.ScopeHash
		if res.Disposition != rollout.EffectRecordOnly {
			return p.dispatchExecute(ctx, rb, ei, res, genAtResolve)
		}
		// record-only disposition ⇒ the inline Observe evidence path. Honor an emergency kill
		// engaged AFTER Resolve before that path commits: the kill is a capability-wide
		// admission stop, so even a record-only request must not proceed under an active kill
		// (parity with Execute's entry re-check — the executing path is covered there; Codex P2,
		// PR #1234). Reading only the monotonic kill flag can only make the outcome more
		// restrictive, so it does not reopen the single-resolution TOCTOU.
		if p.executor.KillActive() {
			return p.rejectTyped(rb, msg, "BLOCKED_BY_EMERGENCY_KILL", mcperr.ReasonRolloutEmergencyActive)
		}
	}

	if d.Action.IsAllowClass() {
		// An ALLOW_WITH_REDACTION decision requires a REAL, re-validated redaction
		// transform (transformed hash) — otherwise it fails closed. No obligation, no
		// transform, residual secret, stale/missing profile ⇒ block, never a pretend
		// redaction.
		if d.Action == policy.ActionAllowWithRedaction && !p.satisfyRedaction(rb, insp, d) {
			return p.rejectTyped(rb, msg, "REDACTION_FAILED", mcperr.ReasonRedactionFailed)
		}
		// PR-8: DURABLY COMMIT the sanitized decision event BEFORE the (still
		// not-implemented) execution response. A CRITICAL operation whose event
		// cannot commit fails closed here — the receipt is evidence a FUTURE
		// execution stage may proceed, never an execution itself.
		if p.events != nil {
			if out, blocked := p.commitDecisionAllow(rb, &in, d, ident, insp, snap.Hash(), msg); blocked {
				return out
			}
		}
		// Record the TRUE policy result, but do not execute: PR-8 has no upstream.
		p.ctr.observeOnly.Add(1)
		rb.rec.ExecutionState = "not_implemented"
		body := executionNotAvailable(msg.ID, d)
		return p.finish(rb, Outcome{Status: 200, Disposition: DispPolicyAllowed, Reason: mcperr.ReasonObserveOnly, ResponseBody: body})
	}
	// DENY / QUARANTINE / REQUIRE_* → deterministic typed JSON-RPC rejection. PR-8:
	// route the authorization denial into the isolated denial lane (never blocks).
	if p.events != nil {
		p.routeDenial(ident, string(d.Reason))
	}
	p.ctr.requestsRejected.Add(1)
	body := policyError(msg.ID, d.Reason, d.Action, d.MatchedRule)
	return p.finish(rb, Outcome{Status: 200, Disposition: DispRejected, Reason: mcperr.ReasonObserveOnly, ResponseBody: body})
}

// buildPolicyInput materializes the immutable decision tuple from the resolved
// identity, the live registry/catalog snapshots and the operation. All facts are
// read BEFORE evaluation (the evaluator itself does no I/O). It carries no raw
// arguments — only the tool name (an operand identity) and one-way fingerprints.
// rejectTyped is the ONE shape every non-policy rejection in dispatchPolicy takes: count it, record
// the sanitized action and reason on the observation, and return the deterministic typed JSON-RPC
// error. Written once because the three sites that use it — inspection hard fail, emergency kill,
// failed redaction — must not drift apart in WHAT they record; a rejection that forgets its counter
// or its reason is a hole in the evidence, not a cosmetic difference.
//
// The snapshot-unavailable rejection deliberately does NOT use it: that one answers with a policy
// error carrying an action and a policy.Reason, a different contract with a different body.
func (p *pipeline) rejectTyped(rb *recBuilder, msg jsonrpc.Message, action string, reason mcperr.Reason) Outcome {
	p.ctr.requestsRejected.Add(1)
	rb.rec.PolicyAction = action
	rb.rec.PolicyReason = reason.Code()
	return p.finish(rb, Outcome{
		Status: 200, Disposition: DispRejected, Reason: reason,
		ResponseBody: inspectionError(msg.ID, reason),
	})
}

// observeCanaryReviewedTarget reports the tool this request NAMES to the Canary reviewed-target
// sink. It is called as the FIRST statement of dispatchPolicy, before any decision that function
// makes can end the request — see the comment at the call site for why that placement is the whole
// point, and canary_reviewed_target_test.go for the gates that hold it there.
func (p *pipeline) observeCanaryReviewedTarget(req Request, msg jsonrpc.Message) {
	serverID, toolName := p.canaryObservedTarget(req, msg)
	p.deps.noteCanaryTargetObserved(p.capability.String(), CanaryTargetObservation{
		// Read BEFORE any of dispatchPolicy's work, so it names an activation at least as old as
		// the one this request was decided under. The root refuses a superseded generation, so an
		// activation landing mid-request costs evidence, never a latch against the wrong reviewed
		// set.
		Generation: p.deps.canaryGenerationAt(p.capability.String()),
		ServerID:   serverID,
		ToolName:   toolName,
	})
}

// canaryObservedTarget names the tool this request is FOR, derived from the request and
// the JSON-RPC message ALONE. It deliberately reproduces the exact gate buildPolicyInput
// uses to populate in.Tool — Gateway capability, tools/call, a params name — so the
// identity reported to the Canary reviewed-target sink is the same one the executor path
// would have reported, only reachable before anything in dispatchPolicy can fail.
//
// It must NOT consult the catalog: a tool whose catalog record is absent still reaches
// buildPolicyInput as a named (quarantined) tool, and a reviewed target that has
// DISAPPEARED is precisely a target the activation can no longer be executing against.
// Any divergence between this gate and buildPolicyInput's is a silent hole, so the two
// are pinned against each other by test.
func (p *pipeline) canaryObservedTarget(req Request, msg jsonrpc.Message) (serverID, toolName string) {
	if p.capability != protocol.Gateway || msg.Method != "tools/call" {
		return "", ""
	}
	name := toolNameFromParams(msg.Params)
	if name == "" {
		return "", ""
	}
	return req.ServerID, name
}

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
		Session: policy.Session{
			Fingerprint:   digest(ctx.Fingerprint()),
			Assurance:     policyAssurance(ctx.Assurance()),
			SenderBinding: policySenderBinding(ctx.SenderConstraint()),
		},
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
			p.classifyReadFirstToolCall(op, serverID, name, in.Principal.Assurance)
			return
		}
	}
	// No catalog record ⇒ unknown tool (drives the hard quarantine override). It is NOT
	// classified: there is no current authoritative target to compare against a reviewed one,
	// so an unknown tool keeps the conservative OpWrite default. The root's classifier would
	// refuse it anyway (its own inventory read finds nothing), and both halves are pinned —
	// a tool Culvert cannot identify is the last thing that should be called read-only.
	tl.Disposition, tl.Drift = policy.DispQuarantined, policy.DriftUnknownTool
	in.Tool = tl
}

// classifyReadFirstToolCall is THE ONE PLACE a tools/call may be promoted from the
// conservative OpWrite default to OpRead, and it is deliberately the only place in this
// package that writes op.Class for a tool call.
//
// One classification, taken here, flows through in.Operation.Class into the decision tuple —
// which is what makes the policy engine, the Canary activation gate and the live side-effect
// gate see the SAME class by construction rather than by three agreeing implementations. A
// second classification anywhere downstream would reintroduce exactly the divergence that
// makes an operation-class disagreement dangerous: policy authorizing a write while the
// read-first gate admits a read, or the reverse.
//
// The promotion is ONE-DIRECTIONAL and affirmative-only. It never demotes (the default is
// already the conservative answer) and it never promotes on anything but an explicit reviewed
// read-only determination bound to this exact fingerprint. Every uncertainty — no classifier
// composed, no armed activation, no reviewed entry, a drifted fingerprint or identity, an
// unstated class — leaves OpWrite in place.
//
// Note what is NOT passed: no fingerprint, no catalog record, no annotation, no argument. The
// root resolves those from its own authoritative inventory. See Deps.CanaryOperationClass.
//
// # THE PROMOTION MAY MOVE A REQUEST BETWEEN RULES; IT MUST NOT MOVE IT OUT OF A HARD OVERRIDE
//
// The operation class is read by more than the read-first gate, and one of its readers is a
// FAIL-CLOSED hard override no rule can undo: MCP-ID-005, which denies a write/high-risk
// operation whose principal carries no assurance at all (policy/engine.go, subjectOverride).
// Because every tools/call was OpWrite before this seam existed, that override denied EVERY
// tool invocation from an unidentified principal, unconditionally. A promotion to OpRead takes
// the request out of writeOrHigher's band, so the override stops firing — and the promotion
// would then be the reason an identity control no longer applies.
//
// That is a different proposition from the one the review answered. A reviewer determined the
// TOOL does not mutate state; nobody determined that invoking it without knowing who is asking
// is acceptable, and a non-mutating tool still returns upstream data to its caller. So the
// promotion is DECLINED when the principal's assurance is unknown: the request keeps OpWrite,
// MCP-ID-005 denies it exactly as it did before this file gained a classifier, and nothing
// about a properly identified principal changes.
//
// It is the same shape as every other branch here — an uncertainty leaves OpWrite in place —
// and it is one-directional: declining to promote can only ever make a request MORE restricted.
// Rule matching is deliberately NOT protected this way: moving a reviewed read-only tool
// between ordinary rules is what the reviewed class is FOR. The line is the hard override.
func (p *pipeline) classifyReadFirstToolCall(op *policy.Operation, serverID, toolName string, assurance policy.Assurance) {
	if p.capability != protocol.Gateway {
		return
	}
	if assurance == policy.AssuranceUnknown {
		return // see the hard-override note above: never promote out of the MCP-ID-005 band
	}
	if p.deps.canaryReviewedReadFirst(p.capability.String(), serverID, toolName) {
		op.Class = policy.OpRead
	}
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
		// OVN-05: the VERIFIED proof-of-possession binding, carried as its own fact
		// rather than folded into Assurance. A rule that means "require a
		// sender-constrained token" can now say so directly.
		SenderBinding: policySenderBinding(ctx.SenderConstraint()),
		Issuer:        ctx.Issuer(),
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

// policySenderBinding maps the resolved (already VERIFIED) sender constraint to
// the policy vocabulary. Only a constraint authn actually verified reaches here —
// ConfirmNone means no proof-of-possession was established, never "not checked".
func policySenderBinding(sc identity.SenderConstraint) policy.SenderBinding {
	switch sc.Method {
	case identity.ConfirmDPoP:
		return policy.SenderBindingDPoP
	case identity.ConfirmMTLS:
		return policy.SenderBindingMTLS
	default:
		return policy.SenderBindingNone
	}
}
