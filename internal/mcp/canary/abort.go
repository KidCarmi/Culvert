package canary

// AbortScope classifies the BLAST RADIUS of a Canary safety trip: does a condition fail a
// single request closed, or does it force the whole Canary to stop (auto-demote to
// Shadow/Observe, or engage the kill switch)? Conflating the two is the mistake this
// taxonomy prevents — a per-request refusal must NOT tear down the Canary, and a
// Canary-integrity breach must NOT be swallowed as one request's fail-closed.
type AbortScope uint8

const (
	// AbortScopeUnset is the invalid zero value (fails closed to the stronger action).
	AbortScopeUnset AbortScope = iota
	// AbortRequest — fail THIS request closed; the Canary continues. The normal enforcement
	// outcome for an in-scope request that a control refuses (policy deny, stale decision,
	// credential-not-ready, inspection block, kill engaged for this request).
	AbortRequest
	// AbortCanary — STOP the whole Canary: no new executions are admitted, the mode
	// auto-demotes to Shadow (or Observe) and/or the kill switch engages. Reserved for
	// conditions that mean the Canary's SAFETY PREMISE no longer holds.
	AbortCanary
)

// String returns a stable label.
func (s AbortScope) String() string {
	switch s {
	case AbortRequest:
		return "request"
	case AbortCanary:
		return "canary"
	default:
		return "unset"
	}
}

// AbortCondition names a Canary safety trip and the blast radius it forces. The list is the
// architectural taxonomy (§16): the runtime maps a detected condition to one of these and
// acts on Scope. It is data, not a live detector — wiring the detectors is a live-execution
// activation concern; this phase pins the classification so a future detector cannot
// silently choose the weaker action.
type AbortCondition struct {
	Code  string     `json:"code"`
	Scope AbortScope `json:"scope"`
	// WhyCanaryWide documents, for the AbortCanary rows, why a single occurrence is a
	// whole-Canary breach rather than a per-request fault.
	WhyCanaryWide string `json:"why_canary_wide,omitempty"`
}

// AbortConditions is the fixed first-Canary abort taxonomy. The AbortCanary rows are the
// ones whose SINGLE occurrence proves the Canary's premise is violated — an out-of-scope
// execution, a scope escape, a fingerprint/identity rug-pull, evidence loss, or a
// credential-safety failure — because each means the controlled experiment is no longer
// controlled. The AbortRequest rows are ordinary per-request fail-closed outcomes that a
// healthy Canary produces and survives.
func AbortConditions() []AbortCondition {
	return []AbortCondition{
		// ── whole-Canary breaches: a single occurrence stops the Canary ───────────────
		{Code: "out_of_scope_execution", Scope: AbortCanary,
			WhyCanaryWide: "a real side effect outside the enumerated scope means scoping is not actually enforced"},
		{Code: "scope_escape", Scope: AbortCanary,
			WhyCanaryWide: "an execution reached a server/tool/principal the scope excludes — containment is broken"},
		{Code: "tool_fingerprint_drift", Scope: AbortCanary,
			WhyCanaryWide: "the executed tool no longer matches the reviewed+approved fingerprint (rug-pull)"},
		{Code: "server_identity_drift", Scope: AbortCanary,
			WhyCanaryWide: "the upstream server's pinned identity changed — the approved trust anchor is gone"},
		{Code: "outcome_evidence_loss", Scope: AbortCanary,
			WhyCanaryWide: "a real side effect occurred without a durable record — the Canary is no longer reconstructable"},
		{Code: "credential_safety_failure", Scope: AbortCanary,
			WhyCanaryWide: "a credential passthrough / non-zeroized material / auth-in-logs event breaks the credential contract"},
		{Code: "budget_exhausted", Scope: AbortCanary,
			WhyCanaryWide: "the machine-enforced blast-radius budget (total/window) is spent — the experiment is over"},
		{Code: "elevated_error_rate", Scope: AbortCanary,
			WhyCanaryWide: "sustained upstream/enforcement error rate over threshold — the target is unhealthy"},
		{Code: "latency_pathology", Scope: AbortCanary,
			WhyCanaryWide: "sustained latency pathology — the Canary is degrading the data path"},
		{Code: "unexpected_upstream_response", Scope: AbortCanary,
			WhyCanaryWide: "an upstream response that response-inspection could not classify safely — fail the Canary, not just the request"},
		{Code: "independent_witness_mismatch", Scope: AbortCanary,
			WhyCanaryWide: "authoritative reconciliation contradicts Culvert's own record of what physically happened — " +
				"a duplicated attempt, a reservation reused, or a binding that does not match the intent. The experiment's " +
				"central claim is that it can account for every physical effect; a contradiction retires that claim"},
		{Code: "window_expired", Scope: AbortCanary,
			WhyCanaryWide: "the time-boxed activation window elapsed. It is an automatic STOP rather than a fault: a first " +
				"Canary is authorized for a bounded interval, and authority must end when the interval does — with or " +
				"without traffic to notice it"},

		// ── per-request fail-closed: the Canary continues ─────────────────────────────
		{Code: "policy_deny", Scope: AbortRequest},
		{Code: "stale_decision", Scope: AbortRequest},
		{Code: "credential_not_ready", Scope: AbortRequest},
		{Code: "response_inspection_block", Scope: AbortRequest},
		{Code: "emergency_kill_for_request", Scope: AbortRequest},
		{Code: "allowance_consumed", Scope: AbortRequest},
	}
}
