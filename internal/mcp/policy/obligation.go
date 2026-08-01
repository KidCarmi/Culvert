package policy

import "github.com/KidCarmi/Culvert/internal/mcp/mcperr"

// LoggingClass is the mandated logging/telemetry class for a decision.
type LoggingClass uint8

const (
	// LogUnset — zero value.
	LogUnset LoggingClass = iota
	// LogStandard — standard request logging.
	LogStandard
	// LogFull — full request logging.
	LogFull
	// LogAudit — audit-grade logging (retained).
	LogAudit
)

// String returns the logging-class label.
func (l LoggingClass) String() string {
	switch l {
	case LogStandard:
		return "standard"
	case LogFull:
		return "full"
	case LogAudit:
		return "audit"
	default:
		return "unset"
	}
}

// ObservationLevel is the mandated decision-observation detail level.
type ObservationLevel uint8

const (
	// ObsUnset — zero value (defaults to summary at emit time).
	ObsUnset ObservationLevel = iota
	// ObsSummary — summary observation.
	ObsSummary
	// ObsDetailed — detailed observation.
	ObsDetailed
)

// String returns the observation-level label.
func (o ObservationLevel) String() string {
	switch o {
	case ObsSummary:
		return "summary"
	case ObsDetailed:
		return "detailed"
	default:
		return "unset"
	}
}

// SessionGrant is the ALLOW_FOR_SESSION obligation payload.
type SessionGrant struct {
	SessionBound   bool // the grant is bound to a specific session id
	TTLSeconds     int  // > 0
	MaxCalls       int  // > 0
	RevokeRequired bool // the grant must be revocable
}

// RedactionReq is the ALLOW_WITH_REDACTION obligation payload.
type RedactionReq struct {
	ProfileRef              string // opaque redaction-profile reference (non-empty)
	TransformedHashRequired bool   // the transformed content must be hash-attested (PR-7)
}

// Obligations is the typed, immutable obligation set attached to a rule/decision.
// Optional action-specific parts are pointers; a nil pointer means "not present".
// Nothing here is a secret or a raw token — credential profile / rate-limit /
// redaction references are opaque identifiers only.
type Obligations struct {
	Logging           LoggingClass
	Observation       ObservationLevel
	RateLimitProfile  string        // opaque rate-limit profile reference (optional)
	Destination       Destination   // bounded destination scope (optional; 0 = unset)
	CredentialProfile string        // Gateway credential-profile id (opaque; ALLOW-class Gateway only)
	OnceCall          bool          // ALLOW_ONCE: exactly one call permitted
	Session           *SessionGrant // ALLOW_FOR_SESSION payload
	Redaction         *RedactionReq // ALLOW_WITH_REDACTION payload
	Confirmation      bool          // REQUIRE_CONFIRMATION: confirmation is required
	Approval          bool          // REQUIRE_APPROVAL: approval is required
	TicketRequired    bool          // an external ticket/reference is required
}

// clone returns a deep copy so the compiled rule owns private obligation state that
// caller mutation after construction cannot alter.
func (o Obligations) clone() Obligations {
	c := o
	if o.Session != nil {
		s := *o.Session
		c.Session = &s
	}
	if o.Redaction != nil {
		r := *o.Redaction
		c.Redaction = &r
	}
	return c
}

// IDs returns the bounded, safe obligation identifiers for a runtime decision /
// observe record — never a secret, only opaque references and typed labels. The
// order is stable.
func (o Obligations) IDs() []string {
	var out []string
	if o.Logging != LogUnset {
		out = append(out, "log:"+o.Logging.String())
	}
	if o.Observation != ObsUnset {
		out = append(out, "obs:"+o.Observation.String())
	}
	if o.RateLimitProfile != "" {
		out = append(out, "rate:"+o.RateLimitProfile)
	}
	if o.Destination != DestinationUnknown {
		out = append(out, "dest:"+o.Destination.String())
	}
	if o.CredentialProfile != "" {
		out = append(out, "cred:"+o.CredentialProfile)
	}
	if o.OnceCall {
		out = append(out, "once")
	}
	if o.Session != nil {
		out = append(out, "session")
	}
	if o.Redaction != nil {
		out = append(out, "redact:"+o.Redaction.ProfileRef)
	}
	if o.Confirmation {
		out = append(out, "confirm")
	}
	if o.Approval {
		out = append(out, "approval")
	}
	if o.TicketRequired {
		out = append(out, "ticket")
	}
	return out
}

func obligationErr(detail string) error {
	return mcperr.New(mcperr.ReasonPolicyObligationInvalid, "policy.obligation", detail)
}

// validateFor enforces the per-action obligation matrix at snapshot compile time.
// destructive marks a destructive-operation rule (which requires stronger
// obligations for an ALLOW-class action). cap is the rule's capability namespace
// (a Management rule may never select a Gateway credential profile).
func (o Obligations) validateFor(a Action, cap Capability, destructive bool) error {
	if err := o.validateShape(); err != nil {
		return err
	}
	// A credential profile may only ride an ALLOW-class Gateway decision.
	if o.CredentialProfile != "" {
		if !a.IsAllowClass() {
			return obligationErr("credential profile is not permitted on a non-ALLOW-class action")
		}
		if cap != CapGateway {
			return obligationErr("only a Gateway rule may select a credential profile")
		}
	}
	switch a {
	case ActionDeny, ActionQuarantine:
		if o.CredentialProfile != "" {
			return obligationErr("credential profile is forbidden on DENY/QUARANTINE")
		}
	case ActionAllow:
		if o.Approval {
			return obligationErr("a plain ALLOW may not carry an approval obligation")
		}
	case ActionAllowOnce:
		if !o.OnceCall {
			return obligationErr("ALLOW_ONCE requires the one-call obligation")
		}
	case ActionAllowForSession:
		if o.Session == nil {
			return obligationErr("ALLOW_FOR_SESSION requires a session grant")
		}
	case ActionAllowWithRedaction:
		if o.Redaction == nil || o.Redaction.ProfileRef == "" {
			return obligationErr("ALLOW_WITH_REDACTION requires a redaction-profile reference")
		}
	case ActionMonitor:
		if o.Logging == LogUnset {
			return obligationErr("MONITOR requires a logging/telemetry obligation")
		}
	case ActionRequireApproval:
		if !o.Approval {
			return obligationErr("REQUIRE_APPROVAL requires the approval obligation")
		}
	case ActionRequireConfirmation:
		if !o.Confirmation {
			return obligationErr("REQUIRE_CONFIRMATION requires the confirmation obligation")
		}
	}
	// A destructive operation reaching an ALLOW-class action needs strong obligations:
	// it must be bounded (one-call or session) and audited.
	if destructive && a.IsAllowClass() {
		if !o.OnceCall && o.Session == nil {
			return obligationErr("a destructive ALLOW-class rule must bound execution (one-call or session)")
		}
		if o.Logging != LogAudit {
			return obligationErr("a destructive ALLOW-class rule must mandate audit logging")
		}
	}
	return nil
}

// validateShape rejects internally inconsistent obligation payloads (zero/negative
// bounds), independent of the action.
func (o Obligations) validateShape() error {
	if o.Session != nil {
		if o.Session.TTLSeconds <= 0 || o.Session.MaxCalls <= 0 {
			return obligationErr("session grant requires positive TTL and max-calls")
		}
	}
	if o.Redaction != nil && o.Redaction.ProfileRef == "" {
		return obligationErr("redaction obligation requires a profile reference")
	}
	return nil
}
