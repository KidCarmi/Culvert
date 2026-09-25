package canary

import (
	"reflect"
	"slices"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/policy"
)

// ---------------------------------------------------------------------------
// BLOCKER #14 — the pure half. These gates cover EvaluateExactPermit alone: given the real
// engine's outputs, is this an executable permit?
//
// The engine-driven half (does the exact tuple actually resolve this way against a real
// compiled snapshot) lives in the root package, where the authoritative inventory is.
// ---------------------------------------------------------------------------

// okPermit is the all-satisfied baseline: a plain ALLOW won on bound fields alone.
func okPermit() PermitInput {
	return PermitInput{
		TupleBuilt: true,
		Decision: policy.Decision{
			Action: policy.ActionAllow, Capability: policy.CapGateway,
			MatchedRule: "ALLOW_READ_T", HardOverride: false,
			Obligations: policy.Obligations{Logging: policy.LogStandard, Observation: policy.ObsSummary},
		},
		Trace: policy.ExplainTrace{
			Winner: "ALLOW_READ_T",
			Entries: []policy.TraceEntry{
				{Kind: policy.TraceRuleConsidered, RuleID: "DENY_OTHER", ConditionID: "tool.name|exact"},
				{Kind: policy.TraceWinner, RuleID: "ALLOW_READ_T"},
			},
		},
		WinnerResolved:        true,
		WinnerConditionFields: []string{"tool.name", "principal.tenant"},
		OperationClass:        policy.OpRead,
	}
}

// TestPermit_BaselineIsPermitted is the POSITIVE CONTROL for every negative gate below. A
// verdict function that answered "not a permit" to everything would satisfy all of them while
// making the First Canary permanently un-runnable, which is a worse outcome than the defect.
func TestPermit_BaselineIsPermitted(t *testing.T) {
	if got := EvaluateExactPermit(okPermit()); got != PermitOK {
		t.Fatalf("the all-satisfied baseline must be a permit, got %q", got)
	}
}

// TestPermit_RejectionMatrix drives every refusal reason from the baseline by changing exactly
// ONE thing, so no case can pass for another case's reason.
func TestPermit_RejectionMatrix(t *testing.T) {
	cases := []struct {
		name string
		want PermitReason
		mut  func(*PermitInput)
	}{
		{"tuple could not be built", PermitTupleUnavailable, func(p *PermitInput) { p.TupleBuilt = false }},
		{"engine errored", PermitEvaluationFailed, func(p *PermitInput) { p.EvalErr = true }},
		{"management capability", PermitCapabilityMismatch, func(p *PermitInput) {
			p.Decision.Capability = policy.CapManagement
		}},
		{"hard override fired", PermitHardOverride, func(p *PermitInput) { p.Decision.HardOverride = true }},
		{"default deny (no rule matched)", PermitNoMatchedRule, func(p *PermitInput) {
			p.Decision.MatchedRule, p.Decision.Action = "", policy.ActionDeny
		}},
		{"explicit DENY", PermitActionNotPlainAllow, func(p *PermitInput) { p.Decision.Action = policy.ActionDeny }},
		{"QUARANTINE", PermitActionNotPlainAllow, func(p *PermitInput) { p.Decision.Action = policy.ActionQuarantine }},
		{"REQUIRE_APPROVAL", PermitActionNotPlainAllow, func(p *PermitInput) {
			p.Decision.Action = policy.ActionRequireApproval
		}},
		{"REQUIRE_CONFIRMATION", PermitActionNotPlainAllow, func(p *PermitInput) {
			p.Decision.Action = policy.ActionRequireConfirmation
		}},
		{"MONITOR", PermitActionNotPlainAllow, func(p *PermitInput) { p.Decision.Action = policy.ActionMonitor }},
		{"ALLOW_ONCE", PermitActionNotPlainAllow, func(p *PermitInput) { p.Decision.Action = policy.ActionAllowOnce }},
		{"ALLOW_FOR_SESSION", PermitActionNotPlainAllow, func(p *PermitInput) {
			p.Decision.Action = policy.ActionAllowForSession
		}},
		{"ALLOW_WITH_REDACTION", PermitActionNotPlainAllow, func(p *PermitInput) {
			p.Decision.Action = policy.ActionAllowWithRedaction
		}},
		{"write class", PermitOperationClassNotReadFirst, func(p *PermitInput) { p.OperationClass = policy.OpWrite }},
		{"destructive class", PermitOperationClassNotReadFirst, func(p *PermitInput) {
			p.OperationClass = policy.OpDestructive
		}},
		{"control class", PermitOperationClassNotReadFirst, func(p *PermitInput) { p.OperationClass = policy.OpControl }},
		{"unset class", PermitOperationClassNotReadFirst, func(p *PermitInput) { p.OperationClass = policy.OpUnset }},
		{"credential obligation", PermitObligationNotSatisfiable, func(p *PermitInput) {
			p.Decision.Obligations.CredentialProfile = "prof-1"
		}},
		{"rate-limit obligation", PermitObligationNotSatisfiable, func(p *PermitInput) {
			p.Decision.Obligations.RateLimitProfile = "rl-1"
		}},
		{"destination obligation", PermitObligationNotSatisfiable, func(p *PermitInput) {
			p.Decision.Obligations.Destination = policy.DestinationApproved
		}},
		{"ticket obligation", PermitObligationNotSatisfiable, func(p *PermitInput) {
			p.Decision.Obligations.TicketRequired = true
		}},
		{"once-call obligation", PermitObligationNotSatisfiable, func(p *PermitInput) {
			p.Decision.Obligations.OnceCall = true
		}},
		{"session obligation", PermitObligationNotSatisfiable, func(p *PermitInput) {
			p.Decision.Obligations.Session = &policy.SessionGrant{SessionBound: true, TTLSeconds: 1, MaxCalls: 1, RevokeRequired: true}
		}},
		{"redaction obligation", PermitObligationNotSatisfiable, func(p *PermitInput) {
			p.Decision.Obligations.Redaction = &policy.RedactionReq{ProfileRef: "r", TransformedHashRequired: true}
		}},
		{"confirmation obligation", PermitObligationNotSatisfiable, func(p *PermitInput) {
			p.Decision.Obligations.Confirmation = true
		}},
		{"approval obligation", PermitObligationNotSatisfiable, func(p *PermitInput) {
			p.Decision.Obligations.Approval = true
		}},
		{"winner read an unbound field", PermitVerdictNotInvariant, func(p *PermitInput) {
			p.WinnerConditionFields = []string{"tool.name", "session.assurance"}
		}},
		{"winner not found in the snapshot", PermitVerdictNotInvariant, func(p *PermitInput) {
			p.WinnerResolved = false
		}},
		{"a rejected rule turned on an unbound field", PermitVerdictNotInvariant, func(p *PermitInput) {
			p.Trace.Entries[0].ConditionID = "client.id|exact"
		}},
		{"a rejected rule turned on expiry", PermitVerdictNotInvariant, func(p *PermitInput) {
			p.Trace.Entries[0].ConditionID = "expiry"
		}},
		{"the trace was truncated", PermitVerdictNotInvariant, func(p *PermitInput) { p.Trace.Truncated = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := okPermit()
			tc.mut(&p)
			if got := EvaluateExactPermit(p); got != tc.want {
				t.Fatalf("want %q, got %q", tc.want, got)
			}
		})
	}
}

// TestPermit_EveryReasonIsReachable proves the vocabulary is not carrying a dead entry: every
// reason AllPermitReasons advertises is produced by some case in the matrix above.
func TestPermit_EveryReasonIsReachable(t *testing.T) {
	seen := map[PermitReason]bool{}
	muts := []func(*PermitInput){
		func(p *PermitInput) { p.TupleBuilt = false },
		func(p *PermitInput) { p.EvalErr = true },
		func(p *PermitInput) { p.Decision.Capability = policy.CapManagement },
		func(p *PermitInput) { p.Decision.HardOverride = true },
		func(p *PermitInput) { p.Decision.MatchedRule = "" },
		func(p *PermitInput) { p.Decision.Action = policy.ActionMonitor },
		func(p *PermitInput) { p.OperationClass = policy.OpWrite },
		func(p *PermitInput) { p.Decision.Obligations.TicketRequired = true },
		func(p *PermitInput) { p.WinnerConditionFields = []string{"client.id"} },
	}
	for _, m := range muts {
		p := okPermit()
		m(&p)
		seen[EvaluateExactPermit(p)] = true
	}
	for _, r := range AllPermitReasons() {
		if !seen[r] {
			t.Errorf("AllPermitReasons advertises %q but no case produces it (orphaned reason)", r)
		}
	}
	if len(seen) != len(AllPermitReasons()) {
		t.Fatalf("produced %d distinct reasons for %d advertised", len(seen), len(AllPermitReasons()))
	}
}

// TestPermit_EveryObligationFieldIsClassified is the ANTI-DRIFT wall for §6. It derives the
// field list from policy.Obligations by REFLECTION and requires every field to be declared
// either satisfiable or refused. A new obligation added to the engine therefore fails the build
// until somebody decides whether this node can satisfy it — an unknown obligation is never
// silently treated as satisfied.
func TestPermit_EveryObligationFieldIsClassified(t *testing.T) {
	sat, ref := PermitSatisfiableObligationFields(), PermitRefusedObligationFields()
	classified := map[string]int{}
	for _, f := range sat {
		classified[f]++
	}
	for _, f := range ref {
		classified[f]++
	}
	ot := reflect.TypeOf(policy.Obligations{})
	for i := 0; i < ot.NumField(); i++ {
		name := ot.Field(i).Name
		switch classified[name] {
		case 1: // exactly one classification
		case 0:
			t.Errorf("policy.Obligations.%s is UNCLASSIFIED: add it to PermitSatisfiableObligationFields "+
				"(with the runtime capability that guarantees it) or PermitRefusedObligationFields, and "+
				"handle it in permitObligationsSatisfiable. An unknown obligation must never be treated "+
				"as satisfied.", name)
		default:
			t.Errorf("policy.Obligations.%s is classified %d times — it must be satisfiable OR refused, not both", name, classified[name])
		}
	}
	for f := range classified {
		if _, ok := ot.FieldByName(f); !ok {
			t.Errorf("%q is classified but is not a field of policy.Obligations — a rename left this list stale", f)
		}
	}
	if len(sat)+len(ref) != ot.NumField() {
		t.Fatalf("classified %d fields but policy.Obligations has %d", len(sat)+len(ref), ot.NumField())
	}
}

// TestPermit_EveryRefusedObligationActuallyRefuses is the behavioural half of the wall above.
// The lists could be complete and the switch could still have dropped a case; this drives each
// refused field to a non-zero value and requires the verdict to change.
func TestPermit_EveryRefusedObligationActuallyRefuses(t *testing.T) {
	setters := map[string]func(*policy.Obligations){
		"Approval":          func(o *policy.Obligations) { o.Approval = true },
		"Confirmation":      func(o *policy.Obligations) { o.Confirmation = true },
		"CredentialProfile": func(o *policy.Obligations) { o.CredentialProfile = "p" },
		"Destination":       func(o *policy.Obligations) { o.Destination = policy.DestinationApproved },
		"OnceCall":          func(o *policy.Obligations) { o.OnceCall = true },
		"RateLimitProfile":  func(o *policy.Obligations) { o.RateLimitProfile = "r" },
		"Redaction": func(o *policy.Obligations) {
			o.Redaction = &policy.RedactionReq{ProfileRef: "r", TransformedHashRequired: true}
		},
		"Session": func(o *policy.Obligations) {
			o.Session = &policy.SessionGrant{SessionBound: true, TTLSeconds: 1, MaxCalls: 1, RevokeRequired: true}
		},
		"TicketRequired": func(o *policy.Obligations) { o.TicketRequired = true },
	}
	for _, f := range PermitRefusedObligationFields() {
		set, ok := setters[f]
		if !ok {
			t.Fatalf("no setter for refused obligation %q — this gate cannot prove it refuses", f)
		}
		p := okPermit()
		set(&p.Decision.Obligations)
		if got := EvaluateExactPermit(p); got != PermitObligationNotSatisfiable {
			t.Errorf("obligation %q is declared refused but the verdict was %q", f, got)
		}
	}
}

// TestPermit_SatisfiableObligationsDoNotRefuse is the control for the gate above: the two
// obligations declared satisfiable must NOT refuse, at every value they can take. Without it,
// "refuse everything" would pass the refusal gate.
func TestPermit_SatisfiableObligationsDoNotRefuse(t *testing.T) {
	for _, lg := range []policy.LoggingClass{policy.LogUnset, policy.LogStandard, policy.LogFull, policy.LogAudit} {
		for _, ob := range []policy.ObservationLevel{policy.ObsUnset, policy.ObsSummary, policy.ObsDetailed} {
			p := okPermit()
			p.Decision.Obligations = policy.Obligations{Logging: lg, Observation: ob}
			if got := EvaluateExactPermit(p); got != PermitOK {
				t.Fatalf("logging=%v observation=%v must remain a permit, got %q", lg, ob, got)
			}
		}
	}
}

// TestPermit_BoundFieldsAreAllRealPolicyFields keeps the bound set honest: every entry must be a
// field the policy engine actually recognises. A typo would silently make a field "unbound",
// which fails closed — but it would also make the set a lie, and the next reader would trust it.
func TestPermit_BoundFieldsAreAllRealPolicyFields(t *testing.T) {
	for _, f := range PermitBoundFields() {
		if !policy.FieldIsKnown(f) {
			t.Errorf("PermitBoundFields lists %q, which the policy engine does not recognise", f)
		}
	}
	if !slices.IsSorted(PermitBoundFields()) {
		t.Error("PermitBoundFields must stay sorted so a reviewer can diff it")
	}
}

// TestPermit_RequestVariableFieldsAreNotBound is the SECURITY half of the bound set. These are
// the fields a real request carries and a preflight must invent; binding any of them would turn
// the permit back into a statement about one imagined request. Listed explicitly rather than
// derived, because "not in the bound list" is the assertion and a derivation would be circular.
func TestPermit_RequestVariableFieldsAreNotBound(t *testing.T) {
	mustBeUnbound := []string{
		"principal.kind", "principal.issuer", "principal.groups", "principal.assurance",
		"principal.sender_binding", "principal.sender_bound",
		"agent.id", "agent.owner", "agent.version", "agent.managed", "agent.trust",
		"client.id", "client.app", "client.trust",
		"session.assurance", "session.sender_binding", "session.prior_confirmation",
		"session.prior_approval", "session.prior_grant",
		"inspection.dlp_available", "inspection.redaction_available", "inspection.dest_inspect_available",
		"inspection.secret_scan_available", "inspection.secret_found", "inspection.pii_found",
		"inspection.injection_suspected", "inspection.schema_invalid",
		"resource.type", "resource.id", "resource.tenant",
		"destination.class", "destination.environment", "destination.approved_breadth",
		"credential.profile", "credential.kind", "credential.power_ceiling",
		"tool.risk", "tool.credential_power", "tool.reversibility",
		"time",
	}
	for _, f := range mustBeUnbound {
		if PermitFieldIsBound(f) {
			t.Errorf("SECURITY: %q is request-variable but is listed as BOUND. A rule reading it would "+
				"be certified against a value this preflight invented rather than one the activation "+
				"controls.", f)
		}
		if !policy.FieldIsKnown(f) {
			t.Errorf("%q is asserted unbound but the engine does not recognise it — this entry proves nothing", f)
		}
	}
}
