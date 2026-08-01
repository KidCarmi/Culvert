package policy

// RuleID is an opaque, stable rule identifier. It is never a display name — the
// engine stamps it onto a matched decision and the explain trace.
type RuleID string

// Revision is a monotonically increasing policy-snapshot revision.
type Revision uint64

// Rule is one compiled, immutable policy rule. Its condition closures are pure
// functions over the input; the rule owns private copies of all mutable data
// (conditions slice + obligation payloads), so a caller cannot mutate it after
// compilation. Fields are unexported and read through accessors.
type Rule struct {
	id               RuleID
	priority         int
	enabled          bool
	conditions       []compiledCond
	action           Action
	reason           ReasonCode
	remediation      Remediation
	obligations      Obligations
	owner            string
	expiryUnix       int64 // 0 = no expiry
	allowDestructive bool
	// rawKey is the canonical, order-independent serialization of this rule, used to
	// build the deterministic snapshot hash. It is never exposed.
	rawKey string
}

// ID returns the rule's opaque id.
func (r *Rule) ID() RuleID { return r.id }

// Priority returns the rule's unique integer priority (lower = evaluated first).
func (r *Rule) Priority() int { return r.priority }

// Enabled reports whether the rule participates in evaluation.
func (r *Rule) Enabled() bool { return r.enabled }

// Action returns the rule's decision action.
func (r *Rule) Action() Action { return r.action }

// Reason returns the rule's stable reason code.
func (r *Rule) Reason() ReasonCode { return r.reason }

// Remediation returns the rule's remediation code.
func (r *Rule) Remediation() Remediation { return r.remediation }

// Obligations returns the rule's obligation set.
func (r *Rule) Obligations() Obligations { return r.obligations }

// AllowsDestructive reports whether the rule is explicitly authorized to permit a
// destructive operation (with the destructive obligation contract).
func (r *Rule) AllowsDestructive() bool { return r.allowDestructive }

// matches reports whether every condition (AND semantics) matches the input, and
// returns the id of the FIRST condition that did not match (for the explain trace),
// or "" when all matched. An expired rule (relative to the input's EvalTime) never
// matches. A rule with no conditions matches every input of its namespace.
func (r *Rule) matches(in *DecisionInput) (bool, string) {
	if r.expiryUnix != 0 && in.EvalTime.Unix() >= r.expiryUnix {
		return false, "expiry"
	}
	for _, c := range r.conditions {
		if !c.match(in) {
			return false, c.id
		}
	}
	return true, ""
}
