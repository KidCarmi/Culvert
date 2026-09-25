package policy

import (
	"sort"
	"strings"
)

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
func (r *Rule) matches(in *DecisionInput) (matched bool, failCond string) {
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

// ConditionFields returns the POLICY FIELD each of this rule's conditions reads, in
// declaration order, deduplicated, sorted. A rule with no conditions returns nil — it
// matches every input of its namespace and therefore reads nothing.
//
// The values are drawn from the CLOSED field vocabulary in fields.go ("tool.name",
// "principal.tenant", …); a compiled condition cannot name anything else, because compile
// rejects an unknown field. No operator-supplied VALUE is exposed — only which field was
// consulted.
//
// It exists for the Canary activation permit (see Snapshot.Rule): a preflight verdict over
// one constructed tuple generalises to every request the scope admits ONLY IF the winning
// rule read nothing the activation does not bind. The caller compares this set against the
// fields it bound authoritatively and refuses the permit on any field outside it, so a rule
// conditioned on a request-variable field (session assurance, client id, inspection
// evidence) can never be certified as an executable permit.
//
// The stable condition id is "field|op" (see compiledCond), so the field is the segment
// before the first "|". That format is part of the package's explain-trace contract — the
// same ids appear in TraceEntry.ConditionID, and the permit caller parses them there too.
func (r *Rule) ConditionFields() []string {
	if len(r.conditions) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(r.conditions))
	out := make([]string, 0, len(r.conditions))
	for _, c := range r.conditions {
		f := ConditionField(c.id)
		if f == "" {
			continue
		}
		if _, dup := seen[f]; dup {
			continue
		}
		seen[f] = struct{}{}
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// ConditionField extracts the policy field from a stable condition id ("field|op"), as it
// appears on a compiled condition and on TraceEntry.ConditionID. It returns "" for an id
// that carries no field — the trace uses a few fixed non-field labels ("expiry", "",
// override labels), and a caller must not mistake one of those for a bound field.
//
// It is exported so the Canary activation permit reads the SAME id format from the trace
// and from Rule.ConditionFields through one parser, rather than two that could drift.
func ConditionField(conditionID string) string {
	i := strings.IndexByte(conditionID, '|')
	if i <= 0 {
		return ""
	}
	return conditionID[:i]
}
