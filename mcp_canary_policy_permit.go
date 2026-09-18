package main

import (
	"strings"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	mcpruntime "github.com/KidCarmi/Culvert/internal/mcp/runtime"
	"github.com/KidCarmi/Culvert/internal/mcp/tooltrust"
)

// mcp_canary_policy_permit.go — blocker #14. The EXACT First-Canary request must resolve,
// through the REAL shared policy engine, to a decision that can actually execute.
//
// THE DEFECT. The readiness table's only policy row was PolicyHealthy, which is
// `mcpPolicy.composed()`: a snapshot EXISTS. Nothing asked what the exact request RESOLVES to.
// A node could hold an exact scope, a reviewed read-first target, a four-eyes live approval, a
// catalog-usable tool (blocker #13) and a valid budget, report Ready:true — and then have every
// request answered by default deny, because no enabled rule matched the tuple at all. Blocker
// #13 stopped the request dying at the catalog hard override; it says nothing about whether an
// operator rule then ALLOWs it. That is this row.
//
// WHAT IS RESOLVED HERE, AND WHAT IS NOT. This file resolves the tuple and runs the engine. It
// decides NOTHING: the verdict is canary.EvaluateExactPermit, a pure function in the readiness
// engine, and enforcement stays exactly where it was — the policy engine decides every real
// request, unchanged. This row only stops a node reporting Ready for an experiment whose every
// call would be refused.
//
// NO SECOND EVALUATOR. The tuple is built by mcpruntime.ExactPermitTuple, which shares
// GatewayServerRef / GatewayToolRef with the live request path and routes the operation class
// through the one classification site; it is evaluated by mcpruntime.EvaluateExactPermitTuple,
// which builds the engine with the same newPolicyEngine and the same Limits the pipeline uses.
// There is no rule matching, no action interpretation and no obligation semantics in this file.
//
// PROOF, NOT SAMPLE. A preflight has no request, so the tuple has to CHOOSE values for the
// fields a real request would carry. canary.EvaluateExactPermit therefore additionally requires
// the verdict to be INVARIANT over every field the activation does not bind: the winning rule
// must read only bound fields, and every rule rejected before it must have been rejected on one.
// Otherwise the permit would be a statement about one imagined request.

// canaryExactPolicyPermit resolves the blocker-#14 activation fact for a requested scope and the
// CANDIDATE reviewed targets the activation would bind: does the exact First-Canary request
// resolve to a plain, executable, invariant ALLOW?
//
// It is a pure READ. It promotes nothing, arms nothing, publishes nothing and mutates no store;
// the only state it touches is the tool-trust reconcile that the coherent capture performs, which
// is one-directional (it withdraws lapsed trust and re-affirms exact-match active trust, and can
// never make a tool usable the governed lifecycle had not already promoted — see
// canaryScopedToolsCatalogUsable).
//
// Fail-closed at every step: no policy snapshot, no coherent inventory capture, a scope that is
// not the exact one-of-everything shape, a missing registry or catalog record, a tuple that
// cannot be built, or an engine error all yield false with a bounded reason.
func canaryExactPolicyPermit(scope rollout.ScopeSpec, reviewed []canary.ReviewedTarget, now time.Time) (bool, canary.PermitReason) {
	f := canaryExactRequestFacts(scope, reviewed, now)
	return f.Permit, f.PermitReason
}

// exactRequestFacts carries both activation facts the exact First-Canary request decides, each
// with its own bounded refusal reason. They are returned together because they are two questions
// about ONE request and must be answered from ONE observation of node state.
type exactRequestFacts struct {
	// Permit — blocker #14. The exact tuple resolves to a plain, executable, invariant ALLOW.
	Permit       bool
	PermitReason canary.PermitReason
	// CredentialFree — blocker #9, first disjunct. Every authoritative credential layer for that
	// same request is empty, so no credential planning, materialization, provider access or
	// Authorization header can arise from it.
	CredentialFree       bool
	CredentialFreeReason canary.CredentialFreeReason
}

// canaryExactRequestFacts resolves BOTH exact-request activation facts from ONE coherent capture.
//
// THE SHARED CAPTURE IS THE POINT, not a micro-optimisation. Resolving them separately would take
// two reconcile+snapshot pairs, and between them the registry and catalog publish independently —
// so the permit could be decided against an inventory in which the tool needs no credential while
// the credential fact is decided against one in which it does, or the reverse. Each verdict would
// be individually true and their conjunction would describe no state that ever existed. One
// capture makes the pair a statement about a single observed inventory.
//
// It is a pure READ with the same properties as canaryExactPolicyPermit: it promotes nothing, arms
// nothing, publishes nothing, and fails closed on every step it cannot establish.
func canaryExactRequestFacts(scope rollout.ScopeSpec, reviewed []canary.ReviewedTarget, now time.Time) exactRequestFacts {
	pi, cf := buildExactPermitInput(scope, reviewed, now)
	pr := canary.EvaluateExactPermit(pi)
	cr := canary.EvaluateCredentialFree(cf)
	return exactRequestFacts{
		Permit: pr == canary.PermitOK, PermitReason: pr,
		CredentialFree: cr == canary.CredFreeOK, CredentialFreeReason: cr,
	}
}

// buildExactPermitInput gathers everything canary.EvaluateExactPermit needs for the exact
// First-Canary request. Split from the caller so the resolution reads top-to-bottom and the
// verdict stays a single call to the pure engine.
func buildExactPermitInput(scope rollout.ScopeSpec, reviewed []canary.ReviewedTarget, now time.Time) (canary.PermitInput, canary.CredentialFreeInput) {
	unavailable := canary.PermitInput{TupleBuilt: false}
	noCredFacts := canary.CredentialFreeInput{Resolved: false}
	// EXACTLY ONE of each. The permit speaks about ONE request; a scope admitting two tenants or
	// two tools has no single exact request to speak about. This is not a re-implementation of
	// blocker #5's gate (canary.ValidateFirstCanaryScope, its own readiness row) — it is this
	// resolver refusing to pick one element out of an ambiguous scope and call it "the" request.
	if len(scope.Tenants) != 1 || len(scope.Tools) != 1 || len(scope.Principals) != 1 {
		return unavailable, noCredFacts
	}
	tenant, principal, st := scope.Tenants[0], scope.Principals[0], scope.Tools[0]
	snap := mcpGatewayPolicySnapshot()
	if snap == nil {
		return unavailable, noCredFacts
	}
	// ONE COHERENT CAPTURE of the registry and the catalog, reconciled first — the same seam
	// and the same reasoning as the blocker-#13 row: reconcile-then-read across two lock
	// acquisitions can observe a durably-revoked store with the tool still catalog.Usable, so
	// the reconcile and BOTH snapshots happen under one hold. Every fact below comes from these
	// two values and nothing re-reads the inventory.
	cat, servers, ok := mcpToolTrustReconcileSnapshotFor()
	if !ok {
		return unavailable, noCredFacts
	}
	rec, recOK := cat.Get(catalog.ToolKey{Server: registry.ServerID(st.Server), Name: st.Name})
	srv, srvOK := servers.Get(registry.ServerID(st.Server))
	if !recOK || !srvOK {
		return unavailable, noCredFacts
	}
	// The reviewed determination is asked against the CANDIDATE set the activation would bind,
	// not the active one: at preflight time nothing is armed, which is the question being
	// decided. The comparison is canary.ReviewedTargetSet's own — the same four-eyes
	// ReviewedTarget comparison the runtime's classifier uses — so the preflight can never
	// classify anything the runtime would not.
	readFirst := candidateReviewedReadFirst(reviewed, exactPermitCurrentTarget(srv, rec, st.Name))
	in, built := mcpruntime.ExactPermitTuple(mcpruntime.ExactPermitTupleInput{
		PolicyRevision:    uint64(snap.Revision()),
		CatalogRevision:   rec.Revision,
		RegistryRevision:  srv.Revision,
		EvalTime:          now,
		Tenant:            tenant,
		SubjectID:         principal,
		ServerRec:         srv,
		ToolRec:           rec,
		ToolName:          st.Name,
		ReviewedReadFirst: readFirst,
	})
	if !built {
		return unavailable, noCredFacts
	}
	dec, trace, err := mcpruntime.EvaluateExactPermitTuple(snap, in)
	pi := canary.PermitInput{
		TupleBuilt:     true,
		EvalErr:        err != nil,
		Decision:       dec,
		Trace:          trace,
		OperationClass: in.Operation.Class,
	}
	// The winner's own condition fields, read from the SAME snapshot the decision came from. A
	// decision naming a rule that snapshot does not contain leaves WinnerResolved false, which
	// the pure verdict treats as an unknown dependency — never as "no dependency".
	if dec.MatchedRule != "" {
		if rule := snap.Rule(dec.MatchedRule); rule != nil {
			pi.WinnerResolved, pi.WinnerConditionFields = true, rule.ConditionFields()
		}
	}
	// Blocker #9. The three authoritative credential statements, taken from the SAME decision and
	// the SAME two snapshots the permit was decided on, so the two facts can never disagree about
	// which state they describe. Resolved is true because all three were read from authoritative
	// state — NOT because they turned out empty; every early return above leaves it false.
	//
	// An engine error still yields Resolved:true and an EMPTY policy statement, which is correct
	// and not a hole: the permit row refuses that tuple outright (PermitEvaluationFailed), so a
	// credential-free verdict on it can never contribute to a Ready node. Reporting the inventory
	// truth here keeps the operator surface honest about which layer objected.
	cf := canary.CredentialFreeInput{
		Resolved:                 true,
		PolicyCredentialProfile:  dec.Obligations.CredentialProfile,
		ServerCredentialProfile:  string(srv.CredentialProfile),
		CatalogCredentialProfile: string(rec.Fingerprint.CredentialProfile),
	}
	return pi, cf
}

// exactPermitCurrentTarget projects the CURRENT authoritative target for the exact tool from the
// two captured snapshots, in the shape canary.ReviewedTargetSet compares against.
//
// It takes the already-captured records rather than calling mcpCurrentAuthoritativeTarget,
// which would re-read the live inventory and put this decision back across two reads — the
// defect the blocker-#13 resolver shipped once already. The identity comes from the CATALOG
// RECORD so it is atomic with the fingerprint taken from that same record, exactly as
// mcpToolTrust.loadTarget does; the registry's own pin is compared against it by the
// blocker-#13 row, which is a separate readiness fact and not re-derived here.
func exactPermitCurrentTarget(srv registry.ServerRecord, rec catalog.ToolRecord, toolName string) canary.ReviewedTarget {
	sum := rec.Fingerprint.Sum()
	return canary.ReviewedTarget{
		Tenant:            string(srv.OwnerScope),
		ServerID:          string(srv.ID),
		ToolName:          toolName,
		Fingerprint:       tooltrust.FingerprintDigest(sum),
		FingerprintFormat: rec.Fingerprint.FormatVersion,
		ServerIdentity:    string(rec.Fingerprint.Identity),
	}
}

// candidateReviewedReadFirst adapts the CANDIDATE reviewed targets to the runtime's
// ReviewedReadFirstFn seam, for the one exact target this preflight is resolving.
//
// It returns nil — which never promotes, leaving the conservative OpWrite default — when the
// candidate set cannot be canonicalized. That is the same refusal the activation itself makes:
// canary.CanonicalizeReviewedTargets rejects an empty, duplicated, disagreeing or unclassified
// set, and an activation carrying one does not arm. A preflight must not be more permissive than
// the activation it is gating, so an un-canonicalizable set yields no read-first class and the
// permit is refused as not read-first.
//
// The seam's (capability, serverID, toolName) arguments are checked against the exact target
// this resolver captured, so a call for any OTHER tool answers false rather than reusing this
// target's determination.
func candidateReviewedReadFirst(reviewed []canary.ReviewedTarget, cur canary.ReviewedTarget) mcpruntime.ReviewedReadFirstFn {
	set, rr := canary.CanonicalizeReviewedTargets(reviewed)
	if rr != canary.ReviewedOK {
		return nil
	}
	return func(capability, serverID, toolName string) bool {
		if capability != rollout.CapabilityGateway.String() {
			return false
		}
		if serverID != cur.ServerID || toolName != cur.ToolName {
			return false
		}
		return set.ReviewedReadFirst(cur)
	}
}

// mcpGatewayPolicySnapshot returns the CURRENT published Gateway policy snapshot, or nil when
// none is published.
//
// It reads the store the runtime evaluator reads — the holder's live Gateway store pointer —
// rather than the holder's cached metadata, so the snapshot this permit is evaluated against is
// the same object a request would be evaluated against. Reading the cached revision and then
// fetching a snapshot separately would be two reads of state that can move between them.
func mcpGatewayPolicySnapshot() *policy.Snapshot {
	st, ok := mcpPolicy.storeFor(strings.ToLower(rollout.CapabilityGateway.String()))
	if !ok || st == nil {
		return nil
	}
	return st.Current()
}

// canaryExactPolicyPermitStatus renders the read-only operator view of this row: the bounded
// permit vocabulary and the closed set of policy fields an activation binds. Values only — no
// tenant, rule id, rule body, principal or host ever appears.
//
// The bound-field list is surfaced because it is the one part of this row an operator cannot
// infer: a rule that looks correct can still fail the permit for reading a field the activation
// does not bind, and without the list that refusal is unexplainable from outside.
func canaryExactPolicyPermitStatus() map[string]any {
	all := canary.AllPermitReasons()
	reasons := make([]string, 0, len(all))
	for _, r := range all {
		reasons = append(reasons, string(r))
	}
	return map[string]any{
		"unmet_readiness_reason":  string(canary.ReasonExactPolicyNotExecutable),
		"required_action":         canary.FirstCanaryRequiresPlainAllow,
		"refusal_reasons":         reasons,
		"bound_policy_fields":     canary.PermitBoundFields(),
		"satisfiable_obligations": canary.PermitSatisfiableObligationFields(),
		"refused_obligations":     canary.PermitRefusedObligationFields(),
		"evaluated_by":            "shared_policy_engine",
	}
}
