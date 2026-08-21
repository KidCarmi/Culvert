package policy

// EventClass is the deterministic event classification of a decision (it maps to
// the EVENT-MODEL category/criticality in a later slice). It is derived purely
// from the action + whether a hard override fired.
type EventClass uint8

const (
	// EventError — an invalid input / unavailable snapshot (fail closed).
	EventError EventClass = iota
	// EventAllow — an ALLOW-class permit.
	EventAllow
	// EventDeny — an explicit or default deny.
	EventDeny
	// EventQuarantine — a quarantine (unknown tool / privilege expansion).
	EventQuarantine
	// EventApprovalRequired — approval pending.
	EventApprovalRequired
	// EventConfirmationRequired — confirmation pending.
	EventConfirmationRequired
	// EventMonitor — a monitored (non-blocking) intent.
	EventMonitor
)

// String returns the event-class label.
func (e EventClass) String() string {
	switch e {
	case EventAllow:
		return "allow"
	case EventDeny:
		return "deny"
	case EventQuarantine:
		return "quarantine"
	case EventApprovalRequired:
		return "approval_required"
	case EventConfirmationRequired:
		return "confirmation_required"
	case EventMonitor:
		return "monitor"
	default:
		return "error"
	}
}

// eventClassFor derives the deterministic event classification of an action.
func eventClassFor(a Action) EventClass {
	switch a {
	case ActionAllow, ActionAllowOnce, ActionAllowForSession, ActionAllowWithRedaction:
		return EventAllow
	case ActionMonitor:
		return EventMonitor
	case ActionQuarantine:
		return EventQuarantine
	case ActionRequireApproval:
		return EventApprovalRequired
	case ActionRequireConfirmation:
		return EventConfirmationRequired
	default: // ActionDeny, ActionInvalid
		return EventDeny
	}
}

// Decision is the RUNTIME-SAFE result of an evaluation. It is bounded and carries
// only safe metadata — no raw arguments, tokens, secrets or the full policy
// document — so it is safe for observe records and wire-level error mapping. Every
// decision carries a reason code and the policy+catalog revision context.
type Decision struct {
	Action          Action
	Effect          Effect
	Reason          ReasonCode
	Remediation     Remediation
	MatchedRule     RuleID // "" when no rule matched (hard override / default deny)
	Capability      Capability
	PolicyRevision  Revision
	CatalogRevision uint64
	EventClass      EventClass
	Obligations     Obligations
	HardOverride    bool // a hard security override produced this decision
}

// ObligationIDs returns the bounded, safe obligation identifiers of the decision.
func (d Decision) ObligationIDs() []string { return d.Obligations.IDs() }

// IsAllowClass reports whether the decision permits (metadata only in PR-6).
func (d Decision) IsAllowClass() bool { return d.Action.IsAllowClass() }

// TraceKind is the kind of an explain-trace entry.
type TraceKind uint8

const (
	// TraceHardOverride — a hard security override was evaluated.
	TraceHardOverride TraceKind = iota
	// TraceRuleConsidered — an ordinary rule was considered.
	TraceRuleConsidered
	// TraceWinner — the winning rule.
	TraceWinner
	// TraceDefaultDeny — the terminal default-deny.
	TraceDefaultDeny
	// TraceInputInvalid — the input failed structural validation.
	TraceInputInvalid
)

// String returns the trace-kind label.
func (k TraceKind) String() string {
	switch k {
	case TraceHardOverride:
		return "hard_override"
	case TraceRuleConsidered:
		return "rule_considered"
	case TraceWinner:
		return "winner"
	case TraceDefaultDeny:
		return "default_deny"
	case TraceInputInvalid:
		return "input_invalid"
	default:
		return "unknown"
	}
}

// TraceEntry is one bounded, sanitized step of the internal explain trace. It
// identifies fields and condition ids but never exposes raw bearer tokens, DPoP
// proofs, credential material, complete tool arguments, secrets, private cert
// material or unbounded tenant-controlled strings — only opaque ids, enum labels
// and stable condition ids ("field|op").
type TraceEntry struct {
	Kind        TraceKind
	RuleID      RuleID
	ConditionID string // stable "field|op" of the decisive condition (or "")
	Matched     bool
	Label       string // fixed, developer-authored label (never hostile input)
}

// ExplainTrace is the internal, deterministic decision explanation the simulator
// and (later) Management MCP consume. It is bounded and sanitized.
type ExplainTrace struct {
	Entries         []TraceEntry
	Winner          RuleID     // "" for hard override / default deny
	Decisive        string     // decisive condition id or override/default label
	Final           ReasonCode // the final reason code
	Action          Action
	Capability      Capability
	PolicyRevision  Revision
	CatalogRevision uint64
}
