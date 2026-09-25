package canary

// Reason is a stable, bounded classification code for a single UNMET Canary
// prerequisite. It is a fixed vocabulary (never interpolated with runtime data —
// tenant/host/secret/error text never appears in a reason) so the readiness surface is
// safe to expose read-only and machine-consumable by an operator gate.
type Reason string

// The complete Canary readiness vocabulary (§2). Each corresponds to exactly ONE fact in
// Facts; a missing fact yields exactly one of these. Ordering here is the canonical
// evaluation order used by Evaluate.
const (
	// ReasonShadowExitNotPassed — the full 13-criterion Shadow Exit Review has not passed
	// for this build/scope. Canary may not even be architected-active without it.
	ReasonShadowExitNotPassed Reason = "shadow_exit_review_not_passed"
	// ReasonScopeNotBounded — the requested Canary scope is not explicit, enumerable and
	// bounded (empty, percentage-only, wildcard, or over a cap). See ValidateScope.
	ReasonScopeNotBounded Reason = "canary_scope_not_bounded"
	// ReasonScopeNotReadFirst — the requested Canary scope admits an operation class beyond
	// read/discovery (write/destructive/control), which the first Canary forbids.
	ReasonScopeNotReadFirst Reason = "canary_scope_not_read_first"
	// ReasonScopeNotExactFirstCanary — the requested Canary scope is a valid, bounded,
	// read-first Canary scope but is NOT the ONE exact first experiment: exactly one tenant,
	// one server, one fully-pinned tool on that server, and one explicitly named principal,
	// with every other selector class empty. The broader bounds ValidateScope enforces belong
	// to the Canary ARCHITECTURE (which a later graduation phase may use); the FIRST Canary is
	// narrower, and this row is what makes a wider signed scope unable to activate at all.
	// See ValidateFirstCanaryScope.
	ReasonScopeNotExactFirstCanary Reason = "canary_scope_not_exact_first_canary"
	// ReasonLiveExecutorAbsent — the live-execution plane (executor) is not composed. This
	// is the shipped-default blocker: liveExecDepsConfigured is false and the execution
	// posture wall pins that no live executor exists.
	ReasonLiveExecutorAbsent Reason = "live_executor_absent"
	// ReasonUpstreamCallerAbsent — no authoritative bounded UpstreamCaller is present.
	ReasonUpstreamCallerAbsent Reason = "upstream_caller_absent"
	// ReasonCredentialPathNotReady — the credential execution path (broker Plan→gate→
	// Materialize→zeroize) is not ready when the scope's tools require a credential profile.
	ReasonCredentialPathNotReady Reason = "credential_path_not_ready" // #nosec G101 -- a reason code, not a credential
	// ReasonDurableEventsDegraded — the durable decision/outcome event plane is unavailable
	// or degraded (evidence-before-side-effect cannot be guaranteed).
	ReasonDurableEventsDegraded Reason = "durable_events_degraded"
	// ReasonResponseInspectionNotReady — the response inspection/DLP plane is not composed.
	ReasonResponseInspectionNotReady Reason = "response_inspection_not_ready"
	// ReasonRegistryUnhealthy — the server registry is unavailable.
	ReasonRegistryUnhealthy Reason = "registry_unhealthy"
	// ReasonCatalogUnhealthy — the tool catalog is unavailable.
	ReasonCatalogUnhealthy Reason = "catalog_unhealthy"
	// ReasonPolicyUnhealthy — the policy engine / snapshot is unavailable.
	ReasonPolicyUnhealthy Reason = "policy_unhealthy"
	// ReasonEmergencyKillActive — the emergency kill switch is engaged for the capability.
	ReasonEmergencyKillActive Reason = "emergency_kill_active"
	// ReasonKillBoundaryGuardAbsent — the final kill-generation boundary guard
	// (PREREQ-MCP-KILL-1) is not asserted present by the live composition.
	ReasonKillBoundaryGuardAbsent Reason = "kill_boundary_guard_absent"
	// ReasonToolFreshnessGuardAbsent — the final tool-freshness (drift) boundary guard is
	// not asserted present by the live composition.
	ReasonToolFreshnessGuardAbsent Reason = "tool_freshness_guard_absent"
	// ReasonLiveApprovalInvalid — no valid live_execution ToolApproval satisfies the scope
	// (see trust.go SatisfiesLiveExecution). A shadow_evaluation approval NEVER qualifies.
	ReasonLiveApprovalInvalid Reason = "live_execution_approval_invalid"
	// ReasonServerNotUsable — the target server is disabled or its identity does not match.
	ReasonServerNotUsable Reason = "server_not_usable"
	// ReasonToolFingerprintStale — the target tool's current observed fingerprint does not
	// match the approved fingerprint (a rug-pull; fail closed).
	ReasonToolFingerprintStale Reason = "tool_fingerprint_stale"
	// ReasonToolNotCatalogUsable — the exact scoped tool is not catalog.Usable at the exact
	// fingerprint and fingerprint FORMAT the activation binds (blocker #13).
	//
	// This is a statement about ONE governed target, never about catalog health: a reachable,
	// perfectly healthy catalog whose record for this tool is Quarantined leaves this row unmet
	// while ReasonCatalogUnhealthy stays satisfied. The two are separate rows precisely because
	// they fail for opposite reasons and point at opposite remedies.
	//
	// It exists because usability is enforced by the POLICY ENGINE, not by this preflight:
	// a quarantined tool is hard-overridden to ActionQuarantine before any operator ALLOW rule
	// is consulted (policy/engine.go). Without this row a node could hold a valid live approval,
	// a valid reviewed target, an exact scope and a read-first class, report Ready:true, and then
	// have every request die at that hard override — the activation would be reporting readiness
	// for an experiment that cannot execute a single call.
	//
	// The only way to satisfy it is the existing governed shadow_evaluation promotion lifecycle
	// (an exact, four-eyes, fingerprint-bound approval → catalog.Promote). A live_execution
	// approval NEVER satisfies it: live trust is orthogonal to catalog usability (§15), and that
	// separation is the reason this is its own fact rather than a clause on LiveApprovalValid.
	ReasonToolNotCatalogUsable Reason = "tool_not_catalog_usable"
	// ReasonExactPolicyNotExecutable — the EXACT First-Canary request does not resolve, through
	// the real shared policy engine, to a decision that can actually execute (blocker #14).
	//
	// It is deliberately SEPARATE from ReasonPolicyUnhealthy, and the two fail for opposite
	// reasons: PolicyHealthy is `mcpPolicy.composed()` — a snapshot EXISTS — and a perfectly
	// healthy snapshot in which no rule matches the exact tuple satisfies it while leaving every
	// request answered by default deny. A snapshot existing is not an authorization.
	//
	// MET requires all of: no hard override; a rule actually matched; that rule's action is a
	// PLAIN policy.ActionAllow (never merely Action.IsAllowClass() — see
	// FirstCanaryRequiresPlainAllow); the evaluated operation class is read-first; every
	// obligation on the matched rule is satisfiable on this node; and the verdict is INVARIANT
	// over every policy field the activation does not bind (PermitBoundFields), so it is a
	// statement about the experiment rather than about one imagined request.
	//
	// Enforcement does not move: the policy engine still decides every real request. This row
	// only stops the next FULL ACTIVATION PREFLIGHT admitting an experiment whose every call
	// would be refused. NOT the node's own readiness surface — factActivation, so EvaluateNode
	// skips it and node status can still report Ready.
	ReasonExactPolicyNotExecutable Reason = "exact_policy_not_executable"
	// ReasonCredentialPathRequired — the exact First-Canary request is not provably
	// CREDENTIAL-FREE: at least one authoritative layer says this tool needs a credential
	// (blocker #9, first disjunct).
	//
	// It is deliberately SEPARATE from ReasonCredentialPathNotReady, and they are near
	// opposites. That row is NODE-level and asks whether this node COULD do credentials at all
	// (the broker Plan→gate→Materialize path is composed). This row is ACTIVATION-level and
	// asks whether this EXPERIMENT needs one — which the First Canary forbids outright, because
	// no production credential Provider adapter exists yet.
	//
	// It is also not implied by ReasonExactPolicyNotExecutable. The permit refuses a matched
	// rule carrying a CredentialProfile OBLIGATION, which is the only credential statement any
	// enforcement path reads; the authoritative registry server record and the reviewed
	// fingerprint are two further statements no enforcement path consults. Policy saying "no
	// credential" while the server record requires one is precisely the state in which
	// execution takes the no-broker branch and reaches a credential-required upstream with NO
	// Authorization header. See EvaluateCredentialFree.
	ReasonCredentialPathRequired Reason = "credential_path_required" // #nosec G101 -- a reason code, not a credential
	// ReasonRollbackPathUnhealthy — the deterministic Canary→Shadow/Observe rollback path is
	// not healthy (an emergency demotion could not be performed). Driven by the executable
	// persist/restore rehearsal — rollback MECHANICS evidence.
	ReasonRollbackPathUnhealthy Reason = "rollback_path_unhealthy"
	// ReasonRollbackCoordinatorRehearsalPending — the AUTHORITATIVE rollback path (a rehearsal
	// routed through the real commitRolloutTransitionAt coordinator, proving parity with its Shadow
	// preflight, emergency-kill, revision, durability, and rollback guards) has NOT been rehearsed.
	// The executable persist/restore drill (RollbackPathHealthy) proves rollback MECHANICS only — not
	// that the authoritative coordinator would actually PERMIT the demotion — so it is not sufficient
	// on its own. This is a SEPARATE, machine-visible HARD prerequisite
	// (CANARY-ROLLBACK-COORDINATOR-REHEARSAL) that is OPEN in this build and keeps Canary readiness
	// false so no transition can become READY merely because the mechanics rehearsal passed. It closes
	// only when a follow-up implements the coordinator-routed rehearsal (owner decision: not in this PR).
	ReasonRollbackCoordinatorRehearsalPending Reason = "rollback_coordinator_rehearsal_pending"
	// ReasonBudgetNotConfigured — no valid machine-enforced blast-radius budget is set (see
	// ValidateBudget). The first Canary may never run without hard execution ceilings.
	ReasonBudgetNotConfigured Reason = "canary_budget_not_configured"
	// ReasonCapabilityNotGateway — Canary execution is Gateway-only; Management never
	// crosses the upstream side-effect boundary.
	ReasonCapabilityNotGateway Reason = "capability_not_gateway"
)

// Facts is the complete set of individually-observable prerequisites the caller supplies
// from live state. Every field is a positive assertion ("this prerequisite HOLDS"); the
// zero value is therefore the fully fail-closed state (nothing ready), which is the
// shipped default. Evaluate maps each false field to its named Reason — there is NO
// aggregate boolean and no field that can substitute for another.
//
// The boundary-guard facts (KillBoundaryGuardPresent, ToolFreshnessGuardPresent) are
// asserted by the FUTURE live composition after it wires the guarded executor whose
// boundary invariants are independently pinned by internal/mcp/execution's boundary tests
// (PREREQ-MCP-KILL-1). They are false today because no live executor is composed.
type Facts struct {
	CapabilityGateway bool // the capability under evaluation is Gateway (not Management)

	ShadowExitReviewPassed bool

	ScopeBounded   bool // ValidateScope returned no error
	ScopeReadFirst bool // the scope admits only read/discovery operation classes
	// ScopeExactFirstCanary — ValidateFirstCanaryScope returned no reason: the SIGNED
	// activation scope is the one exact reviewed experiment. It is a SEPARATE fact from
	// ScopeBounded, never a substitute: a scope can be bounded (≤ the architecture's caps)
	// and still authorize two tools or two principals, which the first experiment forbids.
	ScopeExactFirstCanary bool

	LiveExecutorComposed      bool // liveExecDepsConfigured(gateway) — the live tier is armed
	UpstreamCallerPresent     bool // an authoritative bounded UpstreamCaller is wired
	CredentialPathReady       bool // broker Plan→gate→Materialize path ready (or no credential needed)
	DurableEventsHealthy      bool
	ResponseInspectionReady   bool
	RegistryHealthy           bool
	CatalogHealthy            bool
	PolicyHealthy             bool
	EmergencyKillClear        bool // the kill switch is NOT engaged
	KillBoundaryGuardPresent  bool
	ToolFreshnessGuardPresent bool

	LiveApprovalValid      bool // a valid live_execution approval satisfies the scope
	ServerUsable           bool
	ToolFingerprintCurrent bool
	// ToolCatalogUsable — every tool the scope admits is currently catalog.Usable at the exact
	// fingerprint+format being bound, reached through the governed promotion lifecycle. It is
	// LIVE governance state, deliberately re-observed at each evaluation and never copied into
	// the activation's immutable reviewed snapshot: a revoked or expired promotion must be able
	// to make the next FULL ACTIVATION PREFLIGHT refuse (Evaluate -> Ready:false), which a frozen
	// copy could not express. NOT "un-ready" on the NODE surface — this is a factActivation row,
	// so EvaluateNode excludes it and mcpCanaryStatus can never report it.
	// See ReasonToolNotCatalogUsable.
	ToolCatalogUsable bool
	// ExactPolicyPermit — the EXACT First-Canary decision tuple, evaluated by the REAL shared
	// policy engine against the CURRENT snapshot, is a plain executable ALLOW with satisfiable
	// obligations and a verdict invariant over every unbound field. Like ToolCatalogUsable it is
	// LIVE governance state, re-observed at each evaluation and never copied into the
	// activation's immutable reviewed snapshot: a policy change that removes the permit must be
	// able to make the next FULL ACTIVATION PREFLIGHT refuse (Evaluate -> Ready:false), which a
	// frozen copy could not express. NOT "un-ready" on the NODE surface — factActivation again.
	// See ReasonExactPolicyNotExecutable and EvaluateExactPermit.
	ExactPolicyPermit bool
	// FirstCanaryCredentialFree — every authoritative credential statement for the exact
	// First-Canary request is empty, so the execution path can perform no credential planning,
	// no materialization, no provider access and can send no Authorization header. Like
	// ExactPolicyPermit it is LIVE state, re-observed at each evaluation and never copied into
	// the activation's immutable reviewed snapshot: a credential profile ADDED to the server
	// after activation must be able to make the next FULL ACTIVATION PREFLIGHT refuse
	// (Evaluate -> Ready:false), which a frozen copy could not express. NOT "un-ready" on the
	// NODE surface — factActivation again, so the drift is caught at the next transition or
	// restart and NOT on a status read (§25d).
	// See ReasonCredentialPathRequired and EvaluateCredentialFree.
	FirstCanaryCredentialFree bool
	RollbackPathHealthy       bool // the persist/restore rollback MECHANICS were executably rehearsed
	// RollbackCoordinatorRehearsed — the AUTHORITATIVE rollback path was rehearsed through the real
	// commitRolloutTransitionAt coordinator. It is a SEPARATE hard prerequisite from RollbackPathHealthy
	// (which is mechanics-only) and is FALSE in this build (CANARY-ROLLBACK-COORDINATOR-REHEARSAL open),
	// so a rehearsed-mechanics node is still not ready. See ReasonRollbackCoordinatorRehearsalPending.
	RollbackCoordinatorRehearsed bool

	BudgetConfigured bool // ValidateBudget returned no error
}

// Readiness is the structured Canary readiness verdict. Ready is true IFF Unmet is empty.
// Unmet is the canonical-ordered, de-duplicated list of every missing prerequisite — an
// operator (or an activation preflight) reads it to know EXACTLY what must still become
// true, never a bare boolean.
type Readiness struct {
	Ready bool     `json:"ready"`
	Unmet []Reason `json:"unmet"`
}

// factScope distinguishes a NODE-level prerequisite — a property of the node/build that holds
// independently of any specific requested Canary — from an ACTIVATION-level one, which is only
// meaningful once an operator supplies a concrete scope, live approval, and budget. The
// scope-independent node-readiness dry run (EvaluateNode) evaluates only the node-level facts;
// the full activation preflight (Evaluate) checks both (Codex P2, PR #1249).
type factScope uint8

const (
	factNode       factScope = iota // holds/observed from node+build state alone
	factActivation                  // depends on the operator-supplied scope/approval/budget
)

// readinessCheck is one ordered prerequisite: its positive-assertion accessor, the Reason it
// emits when unmet, and whether it is a node- or activation-level fact.
type readinessCheck struct {
	ok     func(Facts) bool
	reason Reason
	scope  factScope
}

// readinessChecks is the canonical-ordered prerequisite table (matches the Reason declaration
// order) and the SINGLE source of truth for both Evaluate and EvaluateNode. The ten
// activation-level rows are exactly the facts a caller resolves from a requested scope/
// approval/budget/target; every other row is node-level.
var readinessChecks = []readinessCheck{
	{func(f Facts) bool { return f.ShadowExitReviewPassed }, ReasonShadowExitNotPassed, factNode},
	{func(f Facts) bool { return f.ScopeBounded }, ReasonScopeNotBounded, factActivation},
	{func(f Facts) bool { return f.ScopeReadFirst }, ReasonScopeNotReadFirst, factActivation},
	{func(f Facts) bool { return f.ScopeExactFirstCanary }, ReasonScopeNotExactFirstCanary, factActivation},
	{func(f Facts) bool { return f.LiveExecutorComposed }, ReasonLiveExecutorAbsent, factNode},
	{func(f Facts) bool { return f.UpstreamCallerPresent }, ReasonUpstreamCallerAbsent, factNode},
	{func(f Facts) bool { return f.CredentialPathReady }, ReasonCredentialPathNotReady, factNode},
	{func(f Facts) bool { return f.DurableEventsHealthy }, ReasonDurableEventsDegraded, factNode},
	{func(f Facts) bool { return f.ResponseInspectionReady }, ReasonResponseInspectionNotReady, factNode},
	{func(f Facts) bool { return f.RegistryHealthy }, ReasonRegistryUnhealthy, factNode},
	{func(f Facts) bool { return f.CatalogHealthy }, ReasonCatalogUnhealthy, factNode},
	{func(f Facts) bool { return f.PolicyHealthy }, ReasonPolicyUnhealthy, factNode},
	{func(f Facts) bool { return f.EmergencyKillClear }, ReasonEmergencyKillActive, factNode},
	{func(f Facts) bool { return f.KillBoundaryGuardPresent }, ReasonKillBoundaryGuardAbsent, factNode},
	{func(f Facts) bool { return f.ToolFreshnessGuardPresent }, ReasonToolFreshnessGuardAbsent, factNode},
	{func(f Facts) bool { return f.LiveApprovalValid }, ReasonLiveApprovalInvalid, factActivation},
	{func(f Facts) bool { return f.ServerUsable }, ReasonServerNotUsable, factActivation},
	{func(f Facts) bool { return f.ToolFingerprintCurrent }, ReasonToolFingerprintStale, factActivation},
	{func(f Facts) bool { return f.ToolCatalogUsable }, ReasonToolNotCatalogUsable, factActivation},
	{func(f Facts) bool { return f.ExactPolicyPermit }, ReasonExactPolicyNotExecutable, factActivation},
	{func(f Facts) bool { return f.FirstCanaryCredentialFree }, ReasonCredentialPathRequired, factActivation},
	{func(f Facts) bool { return f.RollbackPathHealthy }, ReasonRollbackPathUnhealthy, factNode},
	{func(f Facts) bool { return f.RollbackCoordinatorRehearsed }, ReasonRollbackCoordinatorRehearsalPending, factNode},
	{func(f Facts) bool { return f.BudgetConfigured }, ReasonBudgetNotConfigured, factActivation},
}

// Evaluate returns the FULL Canary readiness verdict for the supplied facts — every
// prerequisite, node- and activation-level alike. It is a pure function: same facts ⇒
// identical verdict, no side effects, no I/O. A false fact adds its named Reason in canonical
// order; Ready is true only when every prerequisite holds.
//
// The capability gate is evaluated first and, when the capability is not Gateway, is the
// SOLE reason (a Management "Canary" is a category error — it never executes upstream — so
// enumerating the other unmet live facts for it would be misleading).
func Evaluate(f Facts) Readiness { return evaluate(f, false) }

// EvaluateNode returns the SCOPE-INDEPENDENT node readiness verdict: it evaluates only the
// node-level prerequisites and NEVER reports an activation-input fact (scope bounded,
// read-first, exact first-Canary scope, live approval, server usability, tool fingerprint,
// exact scoped tool catalog-usable, exact policy permit, budget) as unmet. This is the operator dry-run surface
// consumed before any scope is chosen — a node that has satisfied every node-level
// prerequisite reports node_ready true even though no activation input has been supplied yet,
// instead of being permanently not-ready because the ten activation facts default false
// (Codex P2, PR #1249). The count and membership live in readinessChecks (the factActivation
// rows); this comment restates them and TestEvaluateNode_ExcludesActivationInputs derives them
// from that table, so a new row cannot leave this list quietly stale. The complete verdict is Evaluate, driven by the
// activation preflight once a scope/approval/budget exist.
func EvaluateNode(f Facts) Readiness { return evaluate(f, true) }

func evaluate(f Facts, nodeOnly bool) Readiness {
	if !f.CapabilityGateway {
		return Readiness{Ready: false, Unmet: []Reason{ReasonCapabilityNotGateway}}
	}
	var unmet []Reason
	for i := range readinessChecks {
		c := readinessChecks[i]
		if nodeOnly && c.scope == factActivation {
			continue
		}
		if !c.ok(f) {
			unmet = append(unmet, c.reason)
		}
	}
	return Readiness{Ready: len(unmet) == 0, Unmet: unmet}
}

// AllReasons returns the complete Canary readiness vocabulary in canonical order. It exists
// so a test can prove Facts↔Reason parity (every reason reachable, none orphaned) and so
// the admin surface can advertise the full prerequisite list even when everything is unmet.
func AllReasons() []Reason {
	return []Reason{
		ReasonShadowExitNotPassed,
		ReasonScopeNotBounded,
		ReasonScopeNotReadFirst,
		ReasonScopeNotExactFirstCanary,
		ReasonLiveExecutorAbsent,
		ReasonUpstreamCallerAbsent,
		ReasonCredentialPathNotReady,
		ReasonDurableEventsDegraded,
		ReasonResponseInspectionNotReady,
		ReasonRegistryUnhealthy,
		ReasonCatalogUnhealthy,
		ReasonPolicyUnhealthy,
		ReasonEmergencyKillActive,
		ReasonKillBoundaryGuardAbsent,
		ReasonToolFreshnessGuardAbsent,
		ReasonLiveApprovalInvalid,
		ReasonServerNotUsable,
		ReasonToolFingerprintStale,
		ReasonToolNotCatalogUsable,
		ReasonExactPolicyNotExecutable,
		ReasonCredentialPathRequired,
		ReasonRollbackPathUnhealthy,
		ReasonRollbackCoordinatorRehearsalPending,
		ReasonBudgetNotConfigured,
		ReasonCapabilityNotGateway,
	}
}
