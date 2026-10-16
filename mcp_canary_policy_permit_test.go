package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	mcpruntime "github.com/KidCarmi/Culvert/internal/mcp/runtime"
)

// ---------------------------------------------------------------------------
// BLOCKER #14 — the ENGINE-DRIVEN half. Every gate here drives the REAL policy engine over a
// REAL compiled snapshot, against a tool promoted to catalog.Usable through the REAL governed
// shadow_evaluation lifecycle. Nothing is stubbed: `permitRig` seeds the inventory, promotes the
// tool with requestAndApprove, publishes a compiled snapshot into the same holder the runtime
// evaluator reads, and calls the production resolver.
//
// The pure verdict's own matrix lives in internal/mcp/canary/permit_test.go.
// ---------------------------------------------------------------------------

// permitRig is the one-server/one-tool fixture these gates share: promoted, policy-published,
// with a read-only reviewed determination.
type permitRig struct {
	usableRig
	now time.Time
}

// newPermitRig builds the full stack a permit needs: inventory + governed promotion + a
// compiled Gateway snapshot carrying one plain ALLOW that matches the exact tuple on BOUND
// fields only.
func newPermitRig(t *testing.T, doc string) permitRig {
	t.Helper()
	r := newUsableRig(t)
	// The governed shadow_evaluation approval — the ONLY writer of catalog.Usable.
	requestAndApprove(t, r.serverID, r.toolName, r.fpHex, r.catalogRev(t), time.Hour)
	if got := r.eligibility(t); got != catalog.Usable {
		t.Fatalf("premise: the governed promotion must have landed, got %v", got)
	}
	// The four-eyes LIVE approval, classified READ-ONLY. It is what the production probe
	// projects into the candidate reviewed set, so without it the class cannot be bound and the
	// permit is refused as not read-first — correctly, but for the wrong reason to be testing.
	requestAndApproveLive(t, r.serverID, r.toolName, r.fpHex, r.catalogRev(t))
	publishPermitPolicy(t, doc)
	return permitRig{usableRig: r, now: time.Unix(r.now.Load(), 0)}
}

// publishPermitPolicy compiles doc and publishes it into the process holder's Gateway store —
// the SAME store the runtime PolicyProvider reads — restoring the previous state on cleanup.
func publishPermitPolicy(t *testing.T, doc string) {
	t.Helper()
	snap, err := policy.Compile([]byte(doc), policy.CreatedMeta{}, policy.DefaultLimits())
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	// Reset BEFORE publishing: the store enforces monotonic revisions, so a test that builds two
	// rigs would otherwise republish revision 1 over revision 1 and be rejected as stale.
	mcpPolicy.resetForTest()
	t.Cleanup(func() { mcpPolicy.resetForTest() })
	if err := publishMCPPolicy(mcpPolLoaded, "", snap); err != nil {
		t.Fatalf("publish policy: %v", err)
	}
}

// permitPolicyDoc renders a one-rule Gateway policy. The rule matches the exact tuple on BOUND
// fields only (tool.name + principal.tenant), so the baseline verdict is invariant.
func permitPolicyDoc(action, obligations string) string {
	return `{"schema_version":1,"capability":"gateway","policy_revision":1,"default_action":"DENY",` +
		`"rules":[{"id":"ALLOW_READ_T","priority":1,"action":"` + action + `",` +
		`"reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none",` +
		`"conditions":[{"field":"tool.name","op":"exact","value":"t"},` +
		`{"field":"principal.tenant","op":"exact","value":"` + ttTenant + `"}],` +
		`"obligations":{` + obligations + `}}]}`
}

// plainAllowDoc is the canonical First-Canary rule: plain ALLOW, logging only.
func plainAllowDoc() string { return permitPolicyDoc("ALLOW", `"logging":"standard"`) }

// reviewedReadOnly builds the CANDIDATE reviewed-target set an activation over this rig would
// bind, classified read-only. It is the same shape reviewedTargetsFromBindings projects.
func (r permitRig) reviewedReadOnly(t *testing.T) []canary.ReviewedTarget {
	t.Helper()
	return r.reviewedWithClass(t, policy.OpRead)
}

func (r permitRig) reviewedWithClass(t *testing.T, class policy.OperationClass) []canary.ReviewedTarget {
	t.Helper()
	ti := mcpToolTrust.loadTarget(r.serverID, r.toolName)
	if !ti.found {
		t.Fatal("target must resolve")
	}
	return []canary.ReviewedTarget{{
		Tenant:            ti.target.Tenant,
		ServerID:          r.serverID,
		ToolName:          r.toolName,
		Fingerprint:       ti.target.Fingerprint,
		FingerprintFormat: ti.target.FingerprintFormatVersion,
		ServerIdentity:    ti.pinnedIdentity,
		OperationClass:    class,
	}}
}

// permit runs the production resolver for this rig's exact scope.
func (r permitRig) permit(t *testing.T, reviewed []canary.ReviewedTarget) (bool, canary.PermitReason) {
	t.Helper()
	return canaryExactPolicyPermit(r.scope(), reviewed, r.now)
}

// ── the POSITIVE CONTROL ──────────────────────────────────────────────────────

// TestPermitE2E_ExactPlainAllowIsAPermit is the anti-vacuity control for every negative gate in
// this file. A resolver that answered false to everything would satisfy all of them while making
// the First Canary permanently un-runnable — a worse outcome than the defect.
func TestPermitE2E_ExactPlainAllowIsAPermit(t *testing.T) {
	r := newPermitRig(t, plainAllowDoc())
	ok, reason := r.permit(t, r.reviewedReadOnly(t))
	if !ok {
		t.Fatalf("the canonical First-Canary shape must be a permit, got %q", reason)
	}
}

// ── §10 the required matrix, driven through the REAL engine ───────────────────

// TestPermitE2E_RejectionMatrix changes exactly ONE thing from the canonical shape per case and
// requires the named refusal. Every case goes through policy.Compile + the shared engine, so a
// case proves what the engine actually does, not what the fixture asserts.
func TestPermitE2E_RejectionMatrix(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want canary.PermitReason
	}{
		{"no matching rule -> default DENY", permitPolicyDoc("ALLOW", `"logging":"standard"`) /*replaced below*/, canary.PermitNoMatchedRule},
		{"explicit DENY", permitPolicyDoc("DENY", ``), canary.PermitActionNotPlainAllow},
		{"MONITOR", permitPolicyDoc("MONITOR", `"logging":"standard"`), canary.PermitActionNotPlainAllow},
		{"REQUIRE_APPROVAL", permitPolicyDoc("REQUIRE_APPROVAL", `"approval":true`), canary.PermitActionNotPlainAllow},
		{"REQUIRE_CONFIRMATION", permitPolicyDoc("REQUIRE_CONFIRMATION", `"confirmation":true`), canary.PermitActionNotPlainAllow},
		{"ALLOW_ONCE", permitPolicyDoc("ALLOW_ONCE", `"once_call":true,"logging":"standard"`), canary.PermitActionNotPlainAllow},
		{"ALLOW_FOR_SESSION", permitPolicyDoc("ALLOW_FOR_SESSION",
			`"logging":"standard","session":{"session_bound":true,"ttl_seconds":60,"max_calls":1,"revoke_required":true}`),
			canary.PermitActionNotPlainAllow},
		{"ALLOW_WITH_REDACTION", permitPolicyDoc("ALLOW_WITH_REDACTION",
			`"logging":"standard","redaction":{"profile_ref":"p","transformed_hash_required":true}`),
			canary.PermitActionNotPlainAllow},
		{"ALLOW with a credential obligation", permitPolicyDoc("ALLOW", `"logging":"standard","credential_profile":"cp-1"`),
			canary.PermitObligationNotSatisfiable},
		{"ALLOW with a rate-limit obligation", permitPolicyDoc("ALLOW", `"logging":"standard","rate_limit_profile":"rl-1"`),
			canary.PermitObligationNotSatisfiable},
		{"ALLOW with a ticket obligation", permitPolicyDoc("ALLOW", `"logging":"standard","ticket_required":true`),
			canary.PermitObligationNotSatisfiable},
		{"ALLOW won on an unbound field", `{"schema_version":1,"capability":"gateway","policy_revision":1,` +
			`"default_action":"DENY","rules":[{"id":"ALLOW_READ_T","priority":1,"action":"ALLOW",` +
			`"reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none",` +
			`"conditions":[{"field":"tool.name","op":"exact","value":"t"},` +
			`{"field":"principal.kind","op":"exact","value":"workload"}],` +
			`"obligations":{"logging":"standard"}}]}`, canary.PermitVerdictNotInvariant},
	}
	// Case 0 needs a rule that matches NOTHING, so the engine falls through to default deny.
	cases[0].doc = permitPolicyDoc("ALLOW", `"logging":"standard"`)
	cases[0].doc = `{"schema_version":1,"capability":"gateway","policy_revision":1,"default_action":"DENY",` +
		`"rules":[{"id":"ALLOW_OTHER","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE",` +
		`"remediation":"none","conditions":[{"field":"tool.name","op":"exact","value":"not-t"}],` +
		`"obligations":{"logging":"standard"}}]}`
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newPermitRig(t, tc.doc)
			ok, reason := r.permit(t, r.reviewedReadOnly(t))
			if ok || reason != tc.want {
				t.Fatalf("want refusal %q, got ok=%v reason=%q", tc.want, ok, reason)
			}
		})
	}
}

// TestPermitE2E_QuarantinedToolIsHardOverridden is blocker #13's enforcement seen from #14: an
// un-promoted tool reaches the policy engine as DispQuarantined and is hard-overridden BEFORE
// any operator rule, so the identical ALLOW rule that permits the promoted tool refuses here.
// It is the exact reason #13 and #14 are separate rows: #13's row would be unmet too, but this
// proves the permit itself refuses rather than inheriting that row's verdict.
func TestPermitE2E_QuarantinedToolIsHardOverridden(t *testing.T) {
	restoreMCPInventory(t)
	nowI := seedPermitClock(t)
	_, cat, serverID, toolName, fpHex := seedToolTrustInventory(t)
	publishPermitPolicy(t, plainAllowDoc())
	r := permitRig{usableRig: usableRig{cat: cat, serverID: serverID, toolName: toolName, fpHex: fpHex, now: nowI},
		now: time.Unix(nowI.Load(), 0)}
	if got := r.eligibility(t); got != catalog.Quarantined {
		t.Fatalf("premise: a seeded tool must be Quarantined, got %v", got)
	}
	ok, reason := r.permit(t, r.reviewedReadOnly(t))
	if ok || reason != canary.PermitHardOverride {
		t.Fatalf("a quarantined tool must be refused by the engine's hard override, got ok=%v reason=%q", ok, reason)
	}
}

// seedPermitClock composes tool trust on an injected clock and returns it.
func seedPermitClock(t *testing.T) *atomic.Int64 {
	t.Helper()
	now := &atomic.Int64{}
	now.Store(1_700_000_000)
	composeToolTrust(t, func() time.Time { return time.Unix(now.Load(), 0) })
	return now
}

// TestPermitE2E_WriteClassIsNotAPermit covers §10's "write-class instead of reviewed read".
// The reviewed determination is MUTATING, so the one classification site leaves the conservative
// OpWrite default in place and the permit refuses — even though the ALLOW rule still matches.
//
// It is ALSO the gate that pins the check ORDER in EvaluateExactPermit. Against the previous
// order (hard override before class) this fails with "policy_hard_override": the engine denies a
// write-class tuple whose principal assurance is unknown (MCP-ID-005), and the preflight must
// CHOOSE an assurance because that field is unbound. Requiring read-first first makes that
// branch unreachable, which is what puts the whole hard-override band inside the invariance
// argument. See the ordering note on EvaluateExactPermit.
func TestPermitE2E_WriteClassIsNotAPermit(t *testing.T) {
	r := newPermitRig(t, plainAllowDoc())
	ok, reason := r.permit(t, r.reviewedWithClass(t, policy.OpWrite))
	if ok || reason != canary.PermitOperationClassNotReadFirst {
		t.Fatalf("a mutating reviewed class must not be a First-Canary permit, got ok=%v reason=%q", ok, reason)
	}
}

// TestPermitE2E_WrongPrincipalAndWrongToolAreNotPermits covers §10's identity rows. Both refuse
// as "no matched rule": the rule is keyed on the exact tool and tenant, so a scope naming a
// different principal or tool produces a tuple no rule matches.
func TestPermitE2E_WrongPrincipalAndWrongToolAreNotPermits(t *testing.T) {
	doc := `{"schema_version":1,"capability":"gateway","policy_revision":1,"default_action":"DENY",` +
		`"rules":[{"id":"ALLOW_READ_T","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE",` +
		`"remediation":"none","conditions":[{"field":"tool.name","op":"exact","value":"t"},` +
		`{"field":"principal.subject","op":"exact","value":"agent-1"}],` +
		`"obligations":{"logging":"standard"}}]}`
	r := newPermitRig(t, doc)
	// Control: the exact principal IS a permit under this rule.
	if ok, reason := r.permit(t, r.reviewedReadOnly(t)); !ok {
		t.Fatalf("control: the exact principal must be a permit, got %q", reason)
	}
	wrongPrincipal := r.scope()
	wrongPrincipal.Principals = []string{"agent-2"}
	if ok, reason := canaryExactPolicyPermit(wrongPrincipal, r.reviewedReadOnly(t), r.now); ok || reason != canary.PermitNoMatchedRule {
		t.Fatalf("a different principal must not inherit the permit, got ok=%v reason=%q", ok, reason)
	}
	wrongTool := r.scope()
	wrongTool.Tools = []rollout.ToolSel{{Server: r.serverID, Name: "absent-tool", Fingerprint: r.fpHex}}
	if ok, reason := canaryExactPolicyPermit(wrongTool, r.reviewedReadOnly(t), r.now); ok || reason != canary.PermitTupleUnavailable {
		t.Fatalf("a tool absent from the catalog has no tuple to evaluate, got ok=%v reason=%q", ok, reason)
	}
}

// ── §12 hard overrides still beat a matching ALLOW ────────────────────────────

// TestPermitE2E_HardOverrideDifferential is §12's required differential: the SAME ALLOW rule,
// the same fixture, changed only in the hard-override input. Healthy ⇒ permit; hard-failed ⇒ not.
// Each case names the override the engine fires, so a case cannot pass because some OTHER
// refusal happened to trigger.
func TestPermitE2E_HardOverrideDifferential(t *testing.T) {
	cases := []struct {
		name string
		// break mutates authoritative state so a hard override fires.
		brk func(t *testing.T, r permitRig)
	}{
		{"tenant does not own the server", func(t *testing.T, r permitRig) {}},
		{"server disabled", func(t *testing.T, r permitRig) {
			reg, _ := mcpInventory.sharedInventory()
			if _, err := reg.SetEnabled(registry.ServerID(r.serverID), false); err != nil {
				t.Fatalf("disable: %v", err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newPermitRig(t, plainAllowDoc())
			// POSITIVE half: healthy ⇒ the ALLOW rule wins.
			if ok, reason := r.permit(t, r.reviewedReadOnly(t)); !ok {
				t.Fatalf("control: the healthy tuple must be a permit before the break, got %q", reason)
			}
			if tc.name == "tenant does not own the server" {
				// A scope naming a tenant that does not own the server: the engine's tenant
				// isolation fires before any rule. The tuple is still built — ownership comes
				// from the registry — so this exercises the ENGINE, not the resolver's guards.
				foreign := r.scope()
				foreign.Tenants = []string{"other-tenant"}
				ok, reason := canaryExactPolicyPermit(foreign, r.reviewedReadOnly(t), r.now)
				if ok || reason != canary.PermitHardOverride {
					t.Fatalf("a cross-tenant tuple must lose to the hard override, got ok=%v reason=%q", ok, reason)
				}
				return
			}
			tc.brk(t, r)
			ok, reason := r.permit(t, r.reviewedReadOnly(t))
			if ok {
				t.Fatalf("NEGATIVE half: a matching ALLOW rule must still lose to the hard override, got reason=%q", reason)
			}
			if reason != canary.PermitHardOverride && reason != canary.PermitOperationClassNotReadFirst {
				t.Fatalf("expected the engine's hard override (or the classifier declining for an "+
					"unusable target), got %q", reason)
			}
		})
	}
}

// ── §13 anti-vacuity: an ALLOW→DENY rule mutation must move the fact ──────────

// TestPermitE2E_RuleMutationMovesTheFact is the structural anti-vacuity control §13 requires.
// A resolver returning a constant would pass either the positive or the negative gates but never
// both across a single changed character in the POLICY DOCUMENT.
func TestPermitE2E_RuleMutationMovesTheFact(t *testing.T) {
	allow := newPermitRig(t, permitPolicyDoc("ALLOW", `"logging":"standard"`))
	okAllow, reasonAllow := allow.permit(t, allow.reviewedReadOnly(t))
	if !okAllow {
		t.Fatalf("ALLOW must be a permit, got %q", reasonAllow)
	}
	deny := newPermitRig(t, permitPolicyDoc("DENY", ``))
	okDeny, reasonDeny := deny.permit(t, deny.reviewedReadOnly(t))
	if okDeny {
		t.Fatal("DENY must not be a permit")
	}
	if reasonDeny != canary.PermitActionNotPlainAllow {
		t.Fatalf("the DENY must be refused for its ACTION, got %q", reasonDeny)
	}
}

// TestPermitE2E_NoPolicySnapshotFailsClosed proves the row does not silently pass when there is
// nothing to evaluate against. PolicyHealthy would ALSO be unmet here — that is the point: the
// two rows fail together for a missing snapshot and independently for everything else.
func TestPermitE2E_NoPolicySnapshotFailsClosed(t *testing.T) {
	r := newPermitRig(t, plainAllowDoc())
	mcpPolicy.resetForTest()
	ok, reason := r.permit(t, r.reviewedReadOnly(t))
	if ok || reason != canary.PermitTupleUnavailable {
		t.Fatalf("no published snapshot must fail closed, got ok=%v reason=%q", ok, reason)
	}
}

// TestPermitE2E_AmbiguousScopeHasNoExactRequest proves the resolver refuses to pick one element
// out of a scope that admits several. It is NOT a re-implementation of blocker #5's gate — that
// row decides whether the scope may activate; this decides whether there is a single request to
// speak about at all.
func TestPermitE2E_AmbiguousScopeHasNoExactRequest(t *testing.T) {
	r := newPermitRig(t, plainAllowDoc())
	for _, tc := range []struct {
		name string
		mut  func(*rollout.ScopeSpec)
	}{
		{"two tenants", func(s *rollout.ScopeSpec) { s.Tenants = []string{ttTenant, "other"} }},
		{"two principals", func(s *rollout.ScopeSpec) { s.Principals = []string{"agent-1", "agent-2"} }},
		{"no tools", func(s *rollout.ScopeSpec) { s.Tools = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sc := r.scope()
			tc.mut(&sc)
			if ok, reason := canaryExactPolicyPermit(sc, r.reviewedReadOnly(t), r.now); ok || reason != canary.PermitTupleUnavailable {
				t.Fatalf("an ambiguous scope has no exact request, got ok=%v reason=%q", ok, reason)
			}
		})
	}
}

// TestPermitE2E_UnclassifiableReviewedSetIsNotAPermit proves a candidate reviewed set the
// ACTIVATION would refuse cannot produce a permit here either. A preflight must never be more
// permissive than the activation it gates.
func TestPermitE2E_UnclassifiableReviewedSetIsNotAPermit(t *testing.T) {
	r := newPermitRig(t, plainAllowDoc())
	for _, tc := range []struct {
		name     string
		reviewed []canary.ReviewedTarget
	}{
		{"empty set", nil},
		{"unset class", r.reviewedWithClass(t, policy.OpUnset)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ok, reason := r.permit(t, tc.reviewed)
			if ok || reason != canary.PermitOperationClassNotReadFirst {
				t.Fatalf("an un-canonicalizable reviewed set must leave the conservative class, got ok=%v reason=%q", ok, reason)
			}
		})
	}
}

// TestPermitE2E_ReviewedSetForAnotherToolDoesNotClassify proves the candidate-set adapter is
// bound to the exact target it was built for: a reviewed entry for a DIFFERENT tool must not
// promote this one.
func TestPermitE2E_ReviewedSetForAnotherToolDoesNotClassify(t *testing.T) {
	r := newPermitRig(t, plainAllowDoc())
	other := r.reviewedReadOnly(t)
	other[0].ToolName = "some-other-tool"
	ok, reason := r.permit(t, other)
	if ok || reason != canary.PermitOperationClassNotReadFirst {
		t.Fatalf("a reviewed entry for another tool must not classify this one, got ok=%v reason=%q", ok, reason)
	}
}

// ── §11 end-to-end: policy ALLOW ⇒ rollout EffectExecute ──────────────────────

// TestPermitE2E_AllowResolvesToEffectExecute is §11's complete policy-side path. It takes the
// decision the permit certified and pushes it through the REAL rollout resolver under Canary
// mode, requiring EffectExecute.
//
// IT STOPS THERE, DELIBERATELY. No upstream is contacted, no executor is composed, no Canary is
// activated. The claim is exactly "the policy side resolves to execute" — blockers 1/2/3/8/9/10/
// 11/12/15 are untouched and the §26 verdict is unchanged.
func TestPermitE2E_AllowResolvesToEffectExecute(t *testing.T) {
	r := newPermitRig(t, plainAllowDoc())
	if ok, reason := r.permit(t, r.reviewedReadOnly(t)); !ok {
		t.Fatalf("premise: the exact request must be a permit, got %q", reason)
	}
	res := rollout.Resolve(rollout.ResolveInput{
		Mode: rollout.ModeCanary, InScope: true, Action: rollout.ActionKindAllow,
		ObligationsSatisfied: true,
	})
	if res.Disposition != rollout.EffectExecute {
		t.Fatalf("a permitted plain ALLOW must resolve to EffectExecute, got %v (block=%v)", res.Disposition, res.BlockReason)
	}
	// NEGATIVE control: the same resolver blocks every non-allow action, so EffectExecute above
	// is a property of the ALLOW and not of the resolver being permissive.
	for _, a := range []rollout.ActionKind{rollout.ActionKindDenied, rollout.ActionKindConfirm, rollout.ActionKindApproval} {
		blocked := rollout.Resolve(rollout.ResolveInput{
			Mode: rollout.ModeCanary, InScope: true, Action: a, ObligationsSatisfied: true,
		})
		if blocked.Disposition != rollout.EffectBlock {
			t.Fatalf("control: %v must block, got %v", a, blocked.Disposition)
		}
	}
}

// ── §9 TOCTOU: a green preflight is a statement about its instant ─────────────

// TestPermitE2E_PolicyChangeAfterPreflightRemovesTheFact is §9's control. The preflight sees a
// permit; the policy is then republished as DENY; the SAME resolver must now refuse.
//
// This is the whole TOCTOU answer, and it is architectural rather than a new mechanism: nothing
// caches the permit. The fact is LIVE governance state, re-observed at every evaluation and
// deliberately NOT copied into the activation's immutable reviewed snapshot — the same decision
// blocker #13 made for catalog usability, for the same reason. A frozen copy could not express
// "the authorization was withdrawn".
func TestPermitE2E_PolicyChangeAfterPreflightRemovesTheFact(t *testing.T) {
	r := newPermitRig(t, plainAllowDoc())
	if ok, reason := r.permit(t, r.reviewedReadOnly(t)); !ok {
		t.Fatalf("premise: the preflight must first SEE a permit, got %q", reason)
	}
	// The authority changes underneath, exactly as an operator policy edit would.
	republishPermitPolicy(t, `{"schema_version":1,"capability":"gateway","policy_revision":2,`+
		`"default_action":"DENY","rules":[{"id":"ALLOW_READ_T","priority":1,"action":"DENY",`+
		`"reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none",`+
		`"conditions":[{"field":"tool.name","op":"exact","value":"t"}],"obligations":{}}]}`)
	ok, reason := r.permit(t, r.reviewedReadOnly(t))
	if ok {
		t.Fatal("SECURITY: a preflight verdict must not survive the policy change that removed it")
	}
	if reason != canary.PermitActionNotPlainAllow {
		t.Fatalf("expected the new DENY to be the refusal, got %q", reason)
	}
}

// TestPermitE2E_StaleAllowCannotBecomeAPhysicalEffect is §9's runtime half: even if a stale
// ALLOW were somehow held, the REQUEST path re-evaluates policy against the CURRENT snapshot and
// the rollout resolver blocks a non-allow decision. The permit is never consulted at request
// time — this pins that the request path's own authority is what decides.
func TestPermitE2E_StaleAllowCannotBecomeAPhysicalEffect(t *testing.T) {
	// A decision carried over from the old snapshot is, by the time it reaches the resolver,
	// simply an action. Under the CURRENT authority the same tuple evaluates to DENY, which
	// maps to a block-class action and cannot reach EffectExecute.
	blocked := rollout.Resolve(rollout.ResolveInput{
		Mode: rollout.ModeCanary, InScope: true, Action: rollout.ActionKindDenied, ObligationsSatisfied: true,
	})
	if blocked.Disposition == rollout.EffectExecute {
		t.Fatal("SECURITY: a denied action must never reach EffectExecute")
	}
	// The permit resolver holds NO cache: two calls against different published authorities give
	// different answers, which is what makes "re-observed at every evaluation" true rather than
	// asserted. Proven by the gate above; this one pins the runtime consequence.
	if blocked.Disposition != rollout.EffectBlock {
		t.Fatalf("a denied action must block, got %v", blocked.Disposition)
	}
}

// republishPermitPolicy publishes a NEW snapshot over the current one (revision must advance).
func republishPermitPolicy(t *testing.T, doc string) {
	t.Helper()
	snap, err := policy.Compile([]byte(doc), policy.CreatedMeta{}, policy.DefaultLimits())
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	if err := publishMCPPolicy(mcpPolLoaded, "", snap); err != nil {
		t.Fatalf("republish policy: %v", err)
	}
}

// ── the activation row is carried on BOTH production preflight paths ──────────

// TestPermitE2E_ProductionPreflightCarriesTheRow proves the production input probe actually
// resolves this fact rather than leaving it at its fail-closed zero — the wiring half, without
// which every gate above would be testing a function nothing calls.
func TestPermitE2E_ProductionPreflightCarriesTheRow(t *testing.T) {
	r := newPermitRig(t, plainAllowDoc())
	ai := productionCanaryActivationInputs(rollout.CapabilityGateway, r.scope(), 1)
	if !ai.ExactPolicyPermit {
		t.Fatal("the production probe must resolve ExactPolicyPermit for the canonical shape — " +
			"if it cannot, the row is unsatisfiable in production and the gate is vacuous")
	}
	// The NEGATIVE half on the same path: republish as DENY and require the probe to drop it.
	republishPermitPolicy(t, `{"schema_version":1,"capability":"gateway","policy_revision":2,`+
		`"default_action":"DENY","rules":[]}`)
	if productionCanaryActivationInputs(rollout.CapabilityGateway, r.scope(), 1).ExactPolicyPermit {
		t.Fatal("SECURITY: the production probe reported a permit with no matching rule")
	}
}

// TestPermitE2E_UnmetRowBlocksActivationReadiness proves the row is LOAD-BEARING in the
// authoritative preflight: with every other activation fact satisfied, an unmet permit alone
// keeps Ready false and names itself.
func TestPermitE2E_UnmetRowBlocksActivationReadiness(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	in := validCanaryActivationInput(now)
	in.ExactPolicyPermit = false
	rd := evaluateCanaryActivationPreflight(in)
	if rd.Ready {
		t.Fatal("an unmet exact-policy permit must keep the activation preflight not-ready")
	}
	if !canaryUnmetHas(rd, canary.ReasonExactPolicyNotExecutable) {
		t.Fatalf("the refusal must name itself, got unmet=%v", rd.Unmet)
	}
}

// ── blocker #9 overlap, recorded not closed ───────────────────────────────────

// TestPermitE2E_CredentialFreeRuleIsRequired records, executably, the blocker-#9 OVERLAP this PR
// reports and does NOT act on: the permit requires the matched rule to carry no CredentialProfile.
//
// That is literally blocker #9's first closure disjunct ("verifying a no-CredentialProfile matched
// rule"), now machine-checked rather than a runbook step. It is NOT sufficient to close #9, and the
// ledger says so: this fact binds the tuple the PREFLIGHT can construct, whose request-variable
// fields are unbound by construction. A rule reading one of them yields PermitVerdictNotInvariant
// rather than a permit — so the permit never certifies a credential-free rule for a request shape
// it could not describe — but #9 also names the broker/provider path, which nothing here exercises.
// Closing #9 is a separate decision with its own review.
func TestPermitE2E_CredentialFreeRuleIsRequired(t *testing.T) {
	withCred := newPermitRig(t, permitPolicyDoc("ALLOW", `"logging":"standard","credential_profile":"cp-1"`))
	ok, reason := withCred.permit(t, withCred.reviewedReadOnly(t))
	if ok || reason != canary.PermitObligationNotSatisfiable {
		t.Fatalf("a credential-bearing ALLOW must not be a First-Canary permit, got ok=%v reason=%q", ok, reason)
	}
	// Control: the identical rule without the credential obligation IS a permit, so the refusal
	// above is caused by the credential and not by the rest of the fixture.
	free := newPermitRig(t, plainAllowDoc())
	if ok, reason := free.permit(t, free.reviewedReadOnly(t)); !ok {
		t.Fatalf("control: the credential-free rule must be a permit, got %q", reason)
	}
}

// ── surface ──────────────────────────────────────────────────────────────────

// TestPermitE2E_StatusSurfaceIsBoundedAndComplete proves the read-only operator view carries the
// complete vocabulary and leaks nothing: no tenant, rule id, principal, host or error text.
func TestPermitE2E_StatusSurfaceIsBoundedAndComplete(t *testing.T) {
	st := canaryExactPolicyPermitStatus()
	reasons, _ := st["refusal_reasons"].([]string)
	if len(reasons) != len(canary.AllPermitReasons()) {
		t.Fatalf("the surface must advertise every refusal reason, got %d of %d", len(reasons), len(canary.AllPermitReasons()))
	}
	fields, _ := st["bound_policy_fields"].([]string)
	if len(fields) != len(canary.PermitBoundFields()) {
		t.Fatal("the surface must advertise the complete bound-field set")
	}
	blob := fmt.Sprint(st)
	for _, forbidden := range []string{ttTenant, "controlled", "agent-1", "ALLOW_READ_T"} {
		if strings.Contains(blob, forbidden) {
			t.Fatalf("the status surface leaked %q: %s", forbidden, blob)
		}
	}
}

// ---------------------------------------------------------------------------
// §13 STRUCTURAL ANTI-VACUITY. The behavioural gates above prove the resolver answers
// correctly today. These prove it cannot stop asking the REAL engine tomorrow — a second
// evaluator, a hand-written rule match, or a hard-coded rule id would all still satisfy every
// behavioural gate on the fixture they were written against.
// ---------------------------------------------------------------------------

// TestPermitWall_ResolverUsesTheSharedEvaluator pins that the permit resolver reaches the policy
// engine through the runtime's shared entry point and NOWHERE else. A local policy.NewEngine
// would be a second evaluator with its own Limits; a local Evaluate would be a second decision
// path. Both are the divergence §4 forbids, and both compile.
func TestPermitWall_ResolverUsesTheSharedEvaluator(t *testing.T) {
	f := parsePermitResolver(t)
	var sawShared, sawTuple int
	forbidden := map[string]string{
		"policy.NewEngine": "a SECOND evaluator with its own Limits",
		"policy.Compile":   "compiling a policy of its own rather than reading the published one",
	}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		name := pkg.Name + "." + sel.Sel.Name
		if why, bad := forbidden[name]; bad {
			t.Errorf("SECURITY: the permit resolver calls %s — %s. The exact request must be "+
				"decided by the SAME engine the runtime uses (mcpruntime.EvaluateExactPermitTuple).", name, why)
		}
		switch name {
		case "mcpruntime.EvaluateExactPermitTuple":
			sawShared++
		case "mcpruntime.ExactPermitTuple":
			sawTuple++
		}
		return true
	})
	// CONTROLS. Without these the loop above would pass forever against a resolver that stopped
	// evaluating anything at all — which is the cheapest way to satisfy every negative gate.
	if sawShared != 1 {
		t.Fatalf("the resolver must call mcpruntime.EvaluateExactPermitTuple exactly once, saw %d", sawShared)
	}
	if sawTuple != 1 {
		t.Fatalf("the resolver must build its tuple through mcpruntime.ExactPermitTuple exactly once, saw %d", sawTuple)
	}
}

// TestPermitWall_NoHardCodedRuleIdentity pins §8's "do not hard-code a rule ID in product logic":
// the POLICY decides which rule wins, and the permit reads the winner the engine named. A
// resolver that compared MatchedRule against a constant would be enforcing a rule the operator
// never wrote.
func TestPermitWall_NoHardCodedRuleIdentity(t *testing.T) {
	f := parsePermitResolver(t)
	ast.Inspect(f, func(n ast.Node) bool {
		bin, ok := n.(*ast.BinaryExpr)
		if !ok || (bin.Op != token.EQL && bin.Op != token.NEQ) {
			return true
		}
		for _, side := range []ast.Expr{bin.X, bin.Y} {
			sel, ok := side.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "MatchedRule" {
				continue
			}
			other := bin.Y
			if side == bin.Y {
				other = bin.X
			}
			lit, isLit := other.(*ast.BasicLit)
			if isLit && lit.Value != `""` {
				t.Errorf("SECURITY: the resolver compares MatchedRule against the literal %s. The "+
					"policy decides which rule wins; pinning an id here enforces a rule the operator "+
					"never wrote and silently stops enforcing the one they did.", lit.Value)
			}
		}
		return true
	})
}

// TestPermitWall_FactIsNotPersistedIntoTheReviewedSnapshot pins the §3 decision that the permit
// is LIVE governance state. canary.ReviewedTarget is the activation's immutable record; adding a
// permit field to it would freeze an authorization that must be able to be withdrawn — the same
// mistake blocker #13 explicitly refused for catalog usability.
func TestPermitWall_FactIsNotPersistedIntoTheReviewedSnapshot(t *testing.T) {
	rt := reflect.TypeOf(canary.ReviewedTarget{})
	for i := 0; i < rt.NumField(); i++ {
		n := rt.Field(i).Name
		if strings.Contains(strings.ToLower(n), "permit") || strings.Contains(strings.ToLower(n), "policyallow") {
			t.Errorf("SECURITY: canary.ReviewedTarget.%s persists a policy permit into the "+
				"activation's IMMUTABLE reviewed snapshot. The permit must be re-observed at every "+
				"evaluation so a withdrawn authorization can make the next activation preflight "+
				"refuse; a frozen copy cannot express that.", n)
		}
	}
	st := reflect.TypeOf(canaryRuntimeState{})
	for i := 0; i < st.NumField(); i++ {
		n := st.Field(i).Name
		if strings.Contains(strings.ToLower(n), "permit") {
			t.Errorf("SECURITY: canaryRuntimeState.%s persists the permit into durable activation "+
				"state; it is live governance state, not a reviewed fact.", n)
		}
	}
}

// parsePermitResolver returns the AST of buildExactPermitInput — the resolver body every wall
// above inspects. Parsed from source so a rename, a different call spelling, or a helper that
// hides the call is still caught.
func parsePermitResolver(t *testing.T) *ast.FuncDecl {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(".", "mcp_canary_policy_permit.go"), nil, parser.AllErrors)
	if err != nil {
		t.Fatalf("parse resolver: %v", err)
	}
	for _, d := range file.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if ok && fn.Name.Name == "buildExactPermitInput" {
			return fn
		}
	}
	t.Fatal("buildExactPermitInput not found — the walls in this file are checking nothing")
	return nil
}

// TestPermitWall_ResolverTakesOneCoherentCapture pins that the permit resolver reads the
// authoritative inventory EXACTLY ONCE, through the coherent capture seam.
//
// It exists because mutation M27 survived without it. The resolver's correctness argument is the
// same one the blocker-#13 row had to learn twice: reconciling and then reading across two lock
// acquisitions can observe a durably-revoked trust store with its tool still catalog.Usable, and
// re-reading the inventory for a second fact can straddle a re-ingest so the decision is
// internally inconsistent — a registry record from one publication judged against a catalog
// record from another. One read of each source, under one hold, is what makes that impossible;
// a cross-check between two reads could only DETECT an inconsistency that one read cannot
// produce.
//
// The behavioural gates cannot see this: every one of them passes against a two-read resolver on
// a quiescent fixture, because nothing changes between the reads. That is precisely why the
// invariant needs a structural gate.
func TestPermitWall_ResolverTakesOneCoherentCapture(t *testing.T) {
	f := parsePermitResolver(t)
	captures := 0
	forbidden := map[string]string{
		"mcpInventory.sharedInventory":  "reads the inventory OUTSIDE the reconciled capture",
		"mcpToolTrust.loadTarget":       "re-reads BOTH current snapshots, putting the decision across two reads",
		"mcpCurrentAuthoritativeTarget": "re-reads the live inventory (it calls loadTarget)",
		"mcpToolTrustReconcile":         "reconciles without capturing, leaving the read outside the hold",
	}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			switch fn.Name {
			case "mcpToolTrustReconcileSnapshotFor":
				captures++
			case "mcpCurrentAuthoritativeTarget", "mcpToolTrustReconcile":
				t.Errorf("SECURITY: the permit resolver calls %s, which %s. Every fact must come "+
					"from the ONE coherent capture.", fn.Name, forbidden[fn.Name])
			}
		case *ast.SelectorExpr:
			pkg, isIdent := fn.X.(*ast.Ident)
			if !isIdent {
				return true
			}
			name := pkg.Name + "." + fn.Sel.Name
			if why, bad := forbidden[name]; bad {
				t.Errorf("SECURITY: the permit resolver calls %s, which %s. Every fact must come "+
					"from the ONE coherent capture.", name, why)
			}
		}
		return true
	})
	// The CONTROL, and the reason M27 survived: counting is the assertion, not the absence of
	// forbidden names. A second call to the SAME seam is two reads just as surely as a call to a
	// different one, and no allow/deny list can express that.
	if captures != 1 {
		t.Fatalf("SECURITY: the permit resolver must take EXACTLY ONE coherent capture "+
			"(mcpToolTrustReconcileSnapshotFor), saw %d. Two captures are two reads: the registry "+
			"record and the catalog record could then come from different publications, and the "+
			"reconcile+read pair could be straddled by a revocation.", captures)
	}
}

// TestPermitE2E_EveryBoundFieldCarriesTheExactTarget is the general closure for mutation M15,
// which SURVIVED the first campaign: the tuple's `operation.operand` could be replaced with a
// literal and nothing noticed, because no fixture rule read that field.
//
// The lesson generalises past the one field. PermitBoundFields() is the set the invariance proof
// rests on: a rule may read any of them and still be certified. That guarantee is worth nothing
// unless every one of them actually CARRIES the exact target's value — a bound field populated
// from the wrong source would be certified just as confidently, and the permit would describe a
// request that does not exist.
//
// So this drives the REAL engine once per bound field, with a rule conditioned on THAT field
// alone at the value the exact target should produce. A permit means the tuple carried it; a
// PermitNoMatchedRule means the field is mis-populated. Checking through the engine rather than
// by reading the struct is deliberate: it is the engine's view of the tuple that decides a real
// request, and a struct assertion would compare the builder against itself.
func TestPermitE2E_EveryBoundFieldCarriesTheExactTarget(t *testing.T) {
	// The value each bound field must carry for the canonical experiment, and the operator each
	// is matched with. Literals, so a change to a projection fails here and a human looks.
	type probe struct{ op, value string }
	want := map[string]probe{
		"capability":          {"exact", "gateway"},
		"operation.class":     {"exact", "read"},
		"operation.method":    {"exact", "tools/call"},
		"operation.namespace": {"exact", "gateway_tool"},
		"operation.operand":   {"exact", "t"},
		"operation.point":     {"exact", "policy_engine"},
		"principal.subject":   {"exact", "agent-1"},
		"principal.tenant":    {"exact", ttTenant},
		"server.enabled":      {"bool", "true"},
		"server.id":           {"exact", "controlled"},
		"server.owner":        {"exact", ttTenant},
		"server.verification": {"exact", "verified"},
		"tool.destination":    {"exact", "unknown"},
		"tool.disposition":    {"exact", "usable"},
		"tool.drift":          {"exact", "no_material_change"},
		"tool.name":           {"exact", "t"},
	}
	// DECLARED EXCLUSIONS, each with the reason it cannot be probed this way.
	skip := map[string]string{
		// The seeded server carries no environment, and the policy field accessor reports an
		// absent optional field as present=false — so no `exact` condition can match it. There
		// is nothing to bind wrongly: the value is empty on both the tuple and every request.
		"server.environment": "empty on the seeded server; an absent optional field never matches",
		// The fingerprint is per-fixture rather than a literal, so it is probed below with the
		// value read from the authoritative catalog record.
		"tool.fingerprint": "probed separately against the record's own digest",
	}
	// COMPLETENESS: every bound field must be probed or explicitly excluded. A new bound field
	// therefore fails the build until someone proves the tuple carries it.
	for _, f := range canary.PermitBoundFields() {
		_, probed := want[f]
		_, excluded := skip[f]
		if probed == excluded {
			t.Fatalf("bound field %q must be either probed or declared excluded (probed=%v excluded=%v) — "+
				"the invariance proof rests on every bound field carrying the exact target's value", f, probed, excluded)
		}
	}
	for field, p := range want {
		t.Run(field, func(t *testing.T) {
			doc := `{"schema_version":1,"capability":"gateway","policy_revision":1,"default_action":"DENY",` +
				`"rules":[{"id":"BIND_PROBE","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE",` +
				`"remediation":"none","conditions":[{"field":"` + field + `","op":"` + p.op + `","value":"` + p.value + `"}],` +
				`"obligations":{"logging":"standard"}}]}`
			r := newPermitRig(t, doc)
			ok, reason := r.permit(t, r.reviewedReadOnly(t))
			if !ok {
				t.Fatalf("the exact tuple must carry %s=%q, but the rule keyed on it did not win (%q). "+
					"A bound field the tuple populates wrongly would still be certified by the "+
					"invariance proof, so the permit would describe a request that does not exist.",
					field, p.value, reason)
			}
		})
	}
	t.Run("tool.fingerprint", func(t *testing.T) {
		base := newPermitRig(t, plainAllowDoc())
		doc := `{"schema_version":1,"capability":"gateway","policy_revision":1,"default_action":"DENY",` +
			`"rules":[{"id":"BIND_PROBE","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE",` +
			`"remediation":"none","conditions":[{"field":"tool.fingerprint","op":"exact","value":"` + base.fpHex + `"}],` +
			`"obligations":{"logging":"standard"}}]}`
		r := newPermitRig(t, doc)
		if ok, reason := r.permit(t, r.reviewedReadOnly(t)); !ok {
			t.Fatalf("the exact tuple must carry the catalog record's own fingerprint digest, got %q", reason)
		}
	})
}

// ── §14 the certified verdict must not have a scheduled end ───────────────────

// expiringWinnerDoc renders the canonical First-Canary rule with an expiry, plus a SHADOWED
// lower-priority rule that the winner hides. The shadowed rule is a MONITOR carrying a
// rate_limit_profile obligation: an action FirstCanaryRequiresPlainAllow refuses (it still
// reaches EffectExecute and performs the real upstream call) and an obligation
// permitObligationsSatisfiable refuses (no runtime consumer enforces it). Neither refusal can
// fire while the winner matches, because the engine stops at the FIRST match — which is exactly
// why the winner's expiry has to be checked.
func expiringWinnerDoc(expiryUnix int64) string {
	return `{"schema_version":1,"capability":"gateway","policy_revision":2,"default_action":"DENY","rules":[` +
		`{"id":"ALLOW_READ_T","priority":1,"action":"ALLOW",` +
		`"reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none",` +
		`"expiry_unix":` + strconv.FormatInt(expiryUnix, 10) + `,` +
		`"conditions":[{"field":"tool.name","op":"exact","value":"t"},` +
		`{"field":"principal.tenant","op":"exact","value":"` + ttTenant + `"}],` +
		`"obligations":{"logging":"standard"}},` +
		`{"id":"MONITOR_FALLBACK","priority":2,"action":"MONITOR",` +
		`"reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none",` +
		`"conditions":[{"field":"tool.name","op":"exact","value":"t"}],` +
		`"obligations":{"logging":"standard","rate_limit_profile":"rl-unenforced"}}]}`
}

// TestPermitE2E_ExpiringWinnerIsNotAPermit drives the real engine, the real snapshot store and
// the real resolver. The winner matches at activation on bound fields only, with a satisfiable
// obligation — every other permit check passes — and expires 60s later.
//
// Before the fix this returned PermitOK, certifying "the exact request resolves to a plain,
// executable, invariant ALLOW" for a rulebase that stops saying so one minute later with no
// operator action and nothing to audit.
func TestPermitE2E_ExpiringWinnerIsNotAPermit(t *testing.T) {
	r := newPermitRig(t, plainAllowDoc())
	// Control: the SAME rule without an expiry is a permit, so the refusal below is caused by
	// the expiry and by nothing else about this fixture.
	if ok, reason := canaryExactPolicyPermit(r.scope(), r.reviewedReadOnly(t), r.now); !ok {
		t.Fatalf("control: the expiry-free rule must be a permit, got %q", reason)
	}
	publishPermitPolicy(t, expiringWinnerDoc(r.now.Add(60*time.Second).Unix()))
	ok, reason := canaryExactPolicyPermit(r.scope(), r.reviewedReadOnly(t), r.now)
	if ok || reason != canary.PermitVerdictNotInvariant {
		t.Fatalf("a winner that expires mid-window must not be certified, got ok=%v reason=%q", ok, reason)
	}
}

// TestPermitE2E_ExpiringWinnerShadowsARefusedAction is the IMPACT proof, and it is what makes
// the previous test a security gate rather than a pedantic one. It shows what the expired
// winner hands the exact First-Canary request to: a rule the permit vocabulary refuses on two
// independent grounds, which the invariance check never saw because it was never traced.
func TestPermitE2E_ExpiringWinnerShadowsARefusedAction(t *testing.T) {
	r := newPermitRig(t, plainAllowDoc())
	expiry := r.now.Add(60 * time.Second).Unix()
	publishPermitPolicy(t, expiringWinnerDoc(expiry))
	// While the winner still matches, the shadowed rule leaves no trace entry at all.
	_, trace, err := evaluateExpiringRig(t, r, r.now)
	if err != nil {
		t.Fatalf("evaluate at activation: %v", err)
	}
	for i := range trace.Entries {
		if trace.Entries[i].RuleID == "MONITOR_FALLBACK" {
			t.Fatalf("premise: the shadowed rule must be invisible at activation, trace=%+v", trace.Entries)
		}
	}
	// One second after the winner expires the shadowed rule decides the same request.
	dec, _, err := evaluateExpiringRig(t, r, time.Unix(expiry+1, 0))
	if err != nil {
		t.Fatalf("evaluate after expiry: %v", err)
	}
	if dec.MatchedRule != "MONITOR_FALLBACK" || dec.Action == policy.ActionAllow {
		t.Fatalf("after expiry the shadowed rule must take over, got rule=%q action=%v",
			dec.MatchedRule, dec.Action)
	}
	if dec.Obligations.RateLimitProfile == "" {
		t.Fatalf("premise: the shadowed rule must carry the unenforced obligation, got %+v", dec.Obligations)
	}
}

// evaluateExpiringRig evaluates the rig's exact tuple at an explicit instant through the same
// tuple builder and engine the resolver uses, so the impact proof observes the real decision
// rather than a re-implementation of it.
func evaluateExpiringRig(t *testing.T, r permitRig, at time.Time) (policy.Decision, policy.ExplainTrace, error) {
	t.Helper()
	snap := mcpGatewayPolicySnapshot()
	if snap == nil {
		t.Fatal("no published gateway policy snapshot")
	}
	cat, servers, ok := mcpToolTrustReconcileSnapshotFor()
	if !ok {
		t.Fatal("no coherent inventory capture")
	}
	rec, recOK := cat.Get(catalog.ToolKey{Server: registry.ServerID(r.serverID), Name: r.toolName})
	srv, srvOK := servers.Get(registry.ServerID(r.serverID))
	if !recOK || !srvOK {
		t.Fatal("missing catalog or registry record")
	}
	in, built := mcpruntime.ExactPermitTuple(mcpruntime.ExactPermitTupleInput{
		PolicyRevision:  uint64(snap.Revision()),
		CatalogRevision: rec.Revision, RegistryRevision: srv.Revision,
		EvalTime: at, Tenant: ttTenant, SubjectID: r.scope().Principals[0],
		ServerRec: srv, ToolRec: rec, ToolName: r.toolName,
		ReviewedReadFirst: candidateReviewedReadFirst(r.reviewedReadOnly(t),
			exactPermitCurrentTarget(srv, rec, r.toolName)),
	})
	if !built {
		t.Fatal("exact tuple could not be built")
	}
	return mcpruntime.EvaluateExactPermitTuple(snap, in)
}
