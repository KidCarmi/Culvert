package runtime

import (
	"github.com/KidCarmi/Culvert/internal/mcp/events"
	evmodel "github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/events/spool"
	"github.com/KidCarmi/Culvert/internal/mcp/identity"
	"github.com/KidCarmi/Culvert/internal/mcp/inspection"
	"github.com/KidCarmi/Culvert/internal/mcp/jsonrpc"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
)

// EventProvider is the OPTIONAL PR-8 durable decision-event dependency (Deps.Events).
// When nil, the pipeline keeps the PR-7 decision-only path BYTE-IDENTICALLY: no
// event is constructed or committed and no denial is routed. When set, an
// ALLOW-class decision-point outcome DURABLY COMMITS a sanitized decision event
// BEFORE the (still not-implemented) execution response — a critical operation
// whose event cannot commit fails closed — and authentication/authorization
// denials are routed into the isolated denial lane. It NEVER causes an
// upstream/credential/broker call; execution_state stays "not_implemented".
type EventProvider interface {
	CommitDecision(f events.DecisionFacts) (spool.CommitReceipt, error)
	ObserveDenial(in events.DenialInput)
	WriteAllowedCritical(cap evmodel.Capability) bool
}

// durabilityErrorCode is the stable JSON-RPC error code for a fail-closed critical
// durability failure (the next slot after policy -32050 and inspection -32060).
const durabilityErrorCode = -32070

// eventCapability maps a protocol capability to the event-model capability.
func eventCapability(c protocol.Capability) evmodel.Capability {
	if c == protocol.Management {
		return evmodel.CapManagement
	}
	return evmodel.CapGateway
}

// operationClassToEvent maps a policy operation class to the event criticality and
// action class. A tool call is a write (critical) unless a finer class is known;
// discovery/read is ordinary. Destructive and Management mutation are critical.
func operationClassToEvent(c policy.OperationClass) (evmodel.Criticality, evmodel.ActionClass) {
	switch c {
	case policy.OpDestructive:
		return evmodel.CritCritical, evmodel.ActionClassDestructive
	case policy.OpWrite:
		return evmodel.CritCritical, evmodel.ActionClassWrite
	case policy.OpControl:
		return evmodel.CritCritical, evmodel.ActionClassManagementMutation
	default: // OpRead / OpDiscovery / OpUnset
		return evmodel.CritOrdinary, evmodel.ActionClassRead
	}
}

// commitDecisionAllow durably commits the decision event for an ALLOW-class
// decision-point outcome. It returns (out, true) when a CRITICAL commit failed and
// the operation must fail closed (the caller returns out); otherwise (_, false)
// and the caller proceeds to the not-implemented response. An ordinary commit
// failure applies the manager's low-risk loss policy and never blocks.
func (p *pipeline) commitDecisionAllow(rb *recBuilder, in *policy.DecisionInput, d policy.Decision, ctx *identity.ResolvedContext, insp inspectionRun, snapHash string, msg jsonrpc.Message) (Outcome, bool) {
	facts := p.decisionFacts(in, d, ctx, insp, snapHash)
	if _, err := p.events.CommitDecision(facts); err != nil {
		if facts.Criticality == evmodel.CritCritical {
			p.ctr.requestsRejected.Add(1)
			rb.rec.PolicyAction = "BLOCKED_BY_DURABILITY"
			rb.rec.PolicyReason = mcperr.ReasonOf(err).Code()
			rb.rec.ExecutionState = "" // no execution state on a fail-closed critical
			body := durabilityError(msg.ID, mcperr.ReasonOf(err))
			return p.finish(rb, Outcome{Status: 200, Disposition: DispRejected, Reason: mcperr.ReasonEventDurabilityDegraded, ResponseBody: body}), true
		}
		// Ordinary: recorded loss, operation proceeds to not-implemented.
	}
	return Outcome{}, false
}

// decisionFacts maps the live decision tuple, decision and sanitized inspection
// summary into the manager's safe DecisionFacts. It carries only safe ids, codes,
// revisions and hashes — never a raw argument, output, token or secret.
func (p *pipeline) decisionFacts(in *policy.DecisionInput, d policy.Decision, ctx *identity.ResolvedContext, insp inspectionRun, snapHash string) events.DecisionFacts {
	crit, aclass := operationClassToEvent(in.Operation.Class)
	f := events.DecisionFacts{
		Capability:  eventCapability(p.capability),
		Criticality: crit,
		ActionClass: aclass,
		Identity: evmodel.IdentityEvidence{
			Tenant:             string(ctx.TenantID()),
			PrincipalID:        in.Principal.SubjectID,
			PrincipalType:      subjectKindString(in.Principal.Kind),
			ClientID:           in.Client.ClientID,
			Assurance:          assuranceString(ctx.Assurance()),
			SessionCorrelation: ctx.TokenDigest(),
			Chain:              chainLinks(ctx),
		},
		Decision: evmodel.DecisionEvidence{
			Action: d.Action.String(), ReasonCode: string(d.Reason), MatchedRuleID: string(d.MatchedRule),
			Remediation: d.Remediation.String(), PolicyRevision: uint64(d.PolicyRevision),
			CatalogRevision: d.CatalogRevision, RegistryRevision: in.RegistryRevision,
			RuntimeRevision: in.RuntimeRevision, Obligations: d.ObligationIDs(),
			OperationClass: in.Operation.Class.String(), ExecutionState: "not_implemented",
			PolicySnapshotHash: snapHash,
		},
		SnapshotHash: snapHash,
	}
	if ag, ok := ctx.Agent(); ok {
		f.Identity.AgentID = ag.AgentID
	}
	if in.Server != nil {
		f.Identity.ServerID = in.Server.ServerID
	}
	if in.Tool != nil {
		f.Identity.ToolName = in.Tool.Name
		f.Identity.ToolFingerprint = in.Tool.FingerprintHash
	}
	if insp.ran {
		f.Inspection = inspectionEvidence(insp.result.Summary)
	}
	return f
}

// inspectionEvidence maps a sanitized inspection summary to the event evidence.
func inspectionEvidence(s inspection.Summary) evmodel.InspectionEvidence {
	ev := evmodel.InspectionEvidence{
		SchemaStatus:       s.SchemaStatus.String(),
		OutputSchemaStatus: s.OutputSchemaStatus.String(),
		MaxSeverity:        s.MaxSeverity.String(),
		DLPDisposition:     s.Disposition.String(),
		DestinationClass:   s.DestClass.String(),
		PinEvidenceHash:    s.PinnedHash,
		RedirectStatus:     s.RedirectStatus.String(),
		OriginalHash:       s.OriginalHash,
		TransformedHash:    s.TransformedHash,
		RedactionProfile:   s.RedactionProfile,
		RedactionRevision:  s.Revision,
	}
	for _, c := range s.Classes {
		ev.FindingClasses = append(ev.FindingClasses, c.String())
	}
	if s.InjectionSuspected {
		ev.InjectionLabels = append(ev.InjectionLabels, "possible_prompt_injection")
	}
	return ev
}

// routeDenial routes an authorization denial (a policy DENY, or an admission
// denial) into the isolated denial lane. Identity is included when it exists; the
// source is a stable listener-scoped bucket (the runtime does not carry the client
// address). It NEVER blocks and NEVER touches the critical track.
func (p *pipeline) routeDenial(ctx *identity.ResolvedContext, reason string) {
	if p.events == nil {
		return
	}
	in := events.DenialInput{
		Capability: eventCapability(p.capability),
		Listener:   p.listenerID,
		Source:     p.listenerID,
		Reason:     reason,
	}
	if ctx != nil {
		in.Tenant = string(ctx.TenantID())
		in.Principal = ctx.TokenDigest()
	}
	p.events.ObserveDenial(in)
}

// routeAuthDenial routes a pre-identity authentication/admission failure into the
// denial lane with NO tenant attribution (identity does not yet exist).
func (p *pipeline) routeAuthDenial(reason mcperr.Reason) {
	if p.events == nil {
		return
	}
	p.events.ObserveDenial(events.DenialInput{
		Capability: eventCapability(p.capability),
		Listener:   p.listenerID,
		Source:     p.listenerID,
		Reason:     reason.Code(),
	})
}

func subjectKindString(k policy.SubjectKind) string {
	switch k {
	case policy.SubjectHuman:
		return "human"
	case policy.SubjectWorkload:
		return "workload"
	default:
		return ""
	}
}

func assuranceString(a identity.AssuranceLevel) string {
	switch a {
	case identity.AssuranceLow:
		return "low"
	case identity.AssuranceMedium:
		return "medium"
	case identity.AssuranceHigh:
		return "high"
	default:
		return ""
	}
}

func chainLinks(ctx *identity.ResolvedContext) []evmodel.ChainLink {
	links := ctx.Chain()
	if len(links) == 0 {
		return nil
	}
	out := make([]evmodel.ChainLink, 0, len(links))
	for _, l := range links {
		out = append(out, evmodel.ChainLink{Kind: l.Kind.String(), ID: l.ID})
	}
	return out
}
