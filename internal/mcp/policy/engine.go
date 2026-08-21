package policy

import "github.com/KidCarmi/Culvert/internal/mcp/mcperr"

// Engine evaluates immutable decision inputs against immutable snapshots. It holds
// no mutable state, performs NO I/O, and never calls time.Now — the evaluation
// timestamp is the input's explicit EvalTime. The SAME Engine.Evaluate is used by
// the runtime AND the simulator (there is no second evaluator).
type Engine struct {
	lim Limits
}

// NewEngine returns an engine bounded by lim.
func NewEngine(lim Limits) *Engine { return &Engine{lim: lim} }

// Evaluate produces a runtime-safe Decision and an internal ExplainTrace for one
// input against one snapshot. It is a pure function of (snap, in). It returns a
// non-nil error ONLY for a structurally invalid input or an unavailable snapshot —
// a case that must be distinguished from a valid tuple that no rule matched. In
// every case the returned Decision is fail-closed (a DENY/QUARANTINE), so a caller
// that ignores the error still cannot permit.
//
// Evaluation order (hard overrides dominate ANY user rule; first-match laundering
// is impossible because overrides run first):
//
//  1. snapshot available + capability match
//  2. structural input validity
//  3. cross-tenant resource reference → DENY MCP.AUTH.TENANT_MISMATCH
//  4. missing/ambiguous identity on write/high-risk → DENY MCP.AUTH.IDENTITY_AMBIGUOUS (MCP-ID-005)
//  5. Management mutation/activation → DENY  MCP.MANAGEMENT.MUTATION_NOT_APPROVED
//  6. Gateway cross-tenant server    → DENY  MCP.AUTH.TENANT_MISMATCH (QUAL-5 tenant isolation)
//  7. server identity changed       → DENY  MCP.SERVER.IDENTITY_CHANGED
//  8. server disabled               → DENY  MCP.SERVER.DISABLED
//  9. unknown tool                  → QUARANTINE MCP.TOOL.UNKNOWN
//  10. privilege expansion           → QUARANTINE MCP.TOOL.PRIVILEGE_EXPANSION
//  11. ordered first-match over enabled rules (+ destructive contract)
//  12. default deny                 → DENY  MCP.POLICY.NO_MATCH_DEFAULT_DENY
func (e *Engine) Evaluate(snap *Snapshot, in *DecisionInput) (Decision, ExplainTrace, error) {
	tb := newTraceBuilder(e.lim.MaxTraceEntries())
	if in == nil {
		// A nil tuple is a caller/programming error, not a policy no-match: fail closed
		// with a typed invalid-input error and never dereference it.
		d := hard(ActionDeny, ReasonInvalidInput, RemediationNotPermitted, &DecisionInput{}, nil)
		tb.add(TraceInputInvalid, "", "", false, "nil decision input")
		return d, tb.finishOverride(d), inputErr("nil decision input")
	}
	if snap == nil {
		d := failClosed(ActionDeny, ReasonSnapshotUnavailable, RemediationWaitForPolicyPublication, in, 0)
		return d, tb.finish(d, ""), mcperr.New(mcperr.ReasonPolicySnapshotInvalid, "policy.evaluate", "no policy snapshot")
	}
	if in.Capability != snap.capability {
		d := hard(ActionDeny, ReasonCapabilityMismatch, RemediationNotPermitted, in, snap)
		tb.add(TraceHardOverride, "", "capability", false, "input/snapshot capability mismatch")
		return d, tb.finishOverride(d), mcperr.New(mcperr.ReasonPolicyNamespaceMismatch, "policy.evaluate", "input capability does not match the snapshot")
	}
	if err := in.Validate(e.lim); err != nil {
		d := hard(ActionDeny, ReasonInvalidInput, RemediationNotPermitted, in, snap)
		tb.add(TraceInputInvalid, "", "", false, "decision tuple failed structural validation")
		return d, tb.finishOverride(d), err
	}
	if d, ok := e.hardOverride(snap, in, tb); ok {
		return d, tb.finishOverride(d), nil
	}
	return e.matchRules(snap, in, tb)
}

// hardOverride evaluates the hard security overrides in precedence order (subject-
// level first, then server/tool). It returns (decision, true) when one fires, else
// (_, false). Splitting the two bands keeps each helper simple and the precedence
// explicit — subject/tenant/Management overrides dominate server/tool ones.
func (e *Engine) hardOverride(snap *Snapshot, in *DecisionInput, tb *traceBuilder) (Decision, bool) {
	if d, ok := e.subjectOverride(snap, in, tb); ok {
		return d, true
	}
	return e.serverToolOverride(snap, in, tb)
}

// subjectOverride evaluates the tenant/identity/Management-mutation overrides.
func (e *Engine) subjectOverride(snap *Snapshot, in *DecisionInput, tb *traceBuilder) (Decision, bool) {
	// 3. Cross-tenant resource reference.
	if in.Resource != nil && in.Resource.Tenant != "" && in.Resource.Tenant != in.Principal.Tenant {
		tb.add(TraceHardOverride, "", "resource.tenant", false, "cross-tenant resource reference")
		return hard(ActionDeny, ReasonTenantMismatch, RemediationUseCorrectResource, in, snap), true
	}
	// 4. Missing/ambiguous identity on a write/high-risk operation (MCP-ID-005).
	if writeOrHigher(in.Operation.Class) && in.Principal.Assurance == AssuranceUnknown {
		tb.add(TraceHardOverride, "", "principal.assurance", false, "ambiguous identity on a write/high-risk operation")
		return hard(ActionDeny, ReasonIdentityAmbiguous, RemediationIncreaseAssurance, in, snap), true
	}
	// 5. Management mutation/activation (V1 boundary): no ordinary rule overrides this.
	if in.Capability == CapManagement && isMutationClass(in.Operation.Class) {
		tb.add(TraceHardOverride, "", "operation.class", false, "Management mutation/activation is not permitted in V1")
		return hard(ActionDeny, ReasonManagementMutationNotApproved, RemediationNotPermitted, in, snap), true
	}
	return Decision{}, false
}

// serverToolOverride evaluates the Gateway server + tool fail-closed overrides.
func (e *Engine) serverToolOverride(snap *Snapshot, in *DecisionInput, tb *traceBuilder) (Decision, bool) {
	// 6. Gateway tenant isolation (QUAL-5): the authenticated tenant MUST own the
	// addressed server. The binding is EXACT — the authenticated tenant string must
	// equal the registry OwnerScope byte-for-byte; no prefix/substring/case-fold/
	// wildcard/global tenant. An empty OwnerScope fails CLOSED: an unscoped server is
	// NEVER treated as "owned by every tenant". This is the FIRST server-level
	// override, so it dominates every server/tool signal below AND every user rule —
	// a cross-tenant request can never be laundered into an ALLOW and never learns the
	// foreign server's verification or enabled state (no foreign-tenant leak). The
	// principal tenant is guaranteed non-empty here (structural validation ran first),
	// so only an empty/mismatched server owner can trip this. Management inputs carry
	// no Server, so this is Gateway-only by construction.
	if in.Server != nil {
		if in.Server.Owner == "" || in.Server.Owner != in.Principal.Tenant {
			tb.add(TraceHardOverride, "", "server.owner", false, "authenticated tenant does not own the addressed server")
			return hard(ActionDeny, ReasonTenantMismatch, RemediationUseCorrectResource, in, snap), true
		}
		// 7/8. Server-level fail-closed (Gateway), evaluated only AFTER tenant isolation
		// so a cross-tenant request never reaches these server-state checks.
		if in.Server.Verification == ServerIdentityMismatch || in.Tool != nil && in.Tool.Drift == DriftIdentityChange {
			tb.add(TraceHardOverride, "", "server.verification", false, "server identity changed")
			return hard(ActionDeny, ReasonServerIdentityChanged, RemediationVerifyServerIdentity, in, snap), true
		}
		if !in.Server.Enabled {
			tb.add(TraceHardOverride, "", "server.enabled", false, "server is disabled")
			return hard(ActionDeny, ReasonServerDisabled, RemediationVerifyServerIdentity, in, snap), true
		}
	}
	// 9/10. Tool-level quarantine overrides. A quarantined disposition is an
	// authoritative catalog signal and quarantines INDEPENDENT of drift — it is not
	// shadowed by the input validator's drift requirement, so a catalog-quarantined
	// tool (which carries an unresolved drift class) still fails closed here.
	if in.Tool != nil {
		switch {
		case in.Tool.Drift == DriftUnknownTool || in.Tool.Disposition == DispQuarantined:
			tb.add(TraceHardOverride, "", "tool.drift", false, "unknown or quarantined tool")
			return hard(ActionQuarantine, ReasonToolUnknown, RemediationReviewToolDrift, in, snap), true
		case in.Tool.Drift == DriftPrivilegeExpansion:
			tb.add(TraceHardOverride, "", "tool.drift", false, "privilege expansion")
			return hard(ActionQuarantine, ReasonToolPrivilegeExpansion, RemediationReviewToolDrift, in, snap), true
		}
	}
	return Decision{}, false
}

// matchRules performs the ordered first-match over enabled rules, applies the
// destructive-operation contract, and falls through to default-deny.
func (e *Engine) matchRules(snap *Snapshot, in *DecisionInput, tb *traceBuilder) (Decision, ExplainTrace, error) {
	destructive := in.Operation.Class == OpDestructive
	for _, r := range snap.rules {
		if !r.enabled {
			continue
		}
		ok, failCond := r.matches(in)
		if !ok {
			tb.add(TraceRuleConsidered, r.id, failCond, false, "condition did not match")
			continue
		}
		// Destructive contract: an ALLOW-class rule may permit a destructive op ONLY
		// when explicitly authorized (bounded + audited, enforced at compile). An
		// ordinary ALLOW-class rule that happens to match a destructive op is
		// downgraded to REQUIRE_APPROVAL — never a silent allow, never MONITOR.
		if destructive && r.action.IsAllowClass() && !r.allowDestructive {
			tb.add(TraceWinner, r.id, "", true, "matched but not authorized for a destructive operation")
			d := decisionFromReason(ActionRequireApproval, ReasonApprovalRequired, RemediationRequestApproval, in, snap, r.id, Obligations{Approval: true})
			return d, tb.finishWinner(d, r.id), nil
		}
		tb.add(TraceWinner, r.id, "", true, "all conditions matched")
		d := decisionFromRule(r, in, snap)
		return d, tb.finishWinner(d, r.id), nil
	}
	tb.add(TraceDefaultDeny, "", "", false, "no enabled rule matched")
	d := failClosed(ActionDeny, ReasonNoMatchDefaultDeny, RemediationContactPolicyOwner, in, snap.revision)
	d.Capability, d.CatalogRevision = in.Capability, in.CatalogRevision
	return d, tb.finish(d, "default_deny"), nil
}

// writeOrHigher reports whether the class is write/destructive/control (the
// "write/high-risk" band for MCP-ID-005).
func writeOrHigher(c OperationClass) bool {
	return c == OpWrite || c == OpDestructive || c == OpControl
}

// isMutationClass reports whether a Management operation class represents
// activation/publication/mutation/state-affecting administration (forbidden in V1).
func isMutationClass(c OperationClass) bool {
	return c == OpWrite || c == OpDestructive || c == OpControl
}

// --- decision constructors -------------------------------------------------

func decisionFromRule(r *Rule, in *DecisionInput, snap *Snapshot) Decision {
	return Decision{
		Action:          r.action,
		Effect:          r.action.Effect(),
		Reason:          r.reason,
		Remediation:     r.remediation,
		MatchedRule:     r.id,
		Capability:      in.Capability,
		PolicyRevision:  snap.revision,
		CatalogRevision: in.CatalogRevision,
		EventClass:      eventClassFor(r.action),
		Obligations:     r.obligations.clone(),
	}
}

func decisionFromReason(a Action, reason ReasonCode, rem Remediation, in *DecisionInput, snap *Snapshot, rule RuleID, obl Obligations) Decision {
	return Decision{
		Action:          a,
		Effect:          a.Effect(),
		Reason:          reason,
		Remediation:     rem,
		MatchedRule:     rule,
		Capability:      in.Capability,
		PolicyRevision:  snap.revision,
		CatalogRevision: in.CatalogRevision,
		EventClass:      eventClassFor(a),
		Obligations:     obl,
	}
}

// hard builds a hard-override decision (no matched rule).
func hard(a Action, reason ReasonCode, rem Remediation, in *DecisionInput, snap *Snapshot) Decision {
	rev := Revision(0)
	if snap != nil {
		rev = snap.revision
	}
	return Decision{
		Action: a, Effect: a.Effect(), Reason: reason, Remediation: rem,
		Capability: in.Capability, PolicyRevision: rev, CatalogRevision: in.CatalogRevision,
		EventClass: eventClassFor(a), HardOverride: true,
	}
}

// failClosed builds a fail-closed decision when there may be no usable snapshot.
func failClosed(a Action, reason ReasonCode, rem Remediation, in *DecisionInput, rev Revision) Decision {
	return Decision{
		Action: a, Effect: a.Effect(), Reason: reason, Remediation: rem,
		Capability: in.Capability, PolicyRevision: rev, CatalogRevision: in.CatalogRevision,
		EventClass: eventClassFor(a), HardOverride: reason != ReasonNoMatchDefaultDeny,
	}
}
