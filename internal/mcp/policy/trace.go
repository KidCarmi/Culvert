package policy

// traceBuilder accumulates a bounded, sanitized explain trace during evaluation.
// It never records raw input values — only stable condition ids ("field|op"),
// rule ids and fixed developer-authored labels. Once the entry cap is reached it
// stops appending (deterministic truncation) so a hostile snapshot cannot grow the
// trace without bound.
type traceBuilder struct {
	limit     int
	entries   []TraceEntry
	truncated bool
}

func newTraceBuilder(limit int) *traceBuilder {
	if limit < 1 {
		limit = 1
	}
	return &traceBuilder{limit: limit}
}

func (tb *traceBuilder) add(kind TraceKind, ruleID RuleID, condID string, matched bool, label string) {
	if len(tb.entries) >= tb.limit {
		tb.truncated = true
		return
	}
	tb.entries = append(tb.entries, TraceEntry{
		Kind: kind, RuleID: ruleID, ConditionID: condID, Matched: matched, Label: label,
	})
}

// finish assembles a trace whose winner is none (default-deny / snapshot cases).
func (tb *traceBuilder) finish(d Decision, decisive string) ExplainTrace {
	return tb.assemble(d, "", decisive)
}

// finishOverride assembles a trace for a hard override (decisive = the last entry's
// condition id).
func (tb *traceBuilder) finishOverride(d Decision) ExplainTrace {
	return tb.assemble(d, "", tb.lastCondition())
}

// finishWinner assembles a trace whose winning rule is winner.
func (tb *traceBuilder) finishWinner(d Decision, winner RuleID) ExplainTrace {
	return tb.assemble(d, winner, string(winner))
}

func (tb *traceBuilder) assemble(d Decision, winner RuleID, decisive string) ExplainTrace {
	return ExplainTrace{
		Entries:         tb.entries,
		Winner:          winner,
		Decisive:        decisive,
		Final:           d.Reason,
		Action:          d.Action,
		Capability:      d.Capability,
		PolicyRevision:  d.PolicyRevision,
		CatalogRevision: d.CatalogRevision,
	}
}

func (tb *traceBuilder) lastCondition() string {
	if len(tb.entries) == 0 {
		return ""
	}
	return tb.entries[len(tb.entries)-1].ConditionID
}
