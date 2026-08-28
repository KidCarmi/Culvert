package rollout

import (
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

func testLimits(t *testing.T) Limits {
	t.Helper()
	return DefaultLimits()
}

// ── Mode + transition ──────────────────────────────────────────────────────

func TestModeParseAndRank(t *testing.T) {
	for _, m := range []Mode{ModeDisabled, ModeObserve, ModeShadow, ModeCanary, ModeProduction} {
		got, err := ParseMode(m.String())
		if err != nil || got != m {
			t.Fatalf("ParseMode(%q) = %v, %v", m.String(), got, err)
		}
	}
	if _, err := ParseMode("bogus"); err == nil {
		t.Fatal("ParseMode(bogus) should fail")
	}
	if ModeDisabled.Rank() != 0 || ModeProduction.Rank() != 4 {
		t.Fatal("unexpected ranks")
	}
	// Shadow requires the guarded-execution plane composed (to EVALUATE), Observe never
	// does. This is not "performs upstream execution" — see FullyEnforces.
	if ModeObserve.RequiresExecutionPlane() || !ModeShadow.RequiresExecutionPlane() {
		t.Fatal("RequiresExecutionPlane wrong")
	}
	if ModeShadow.FullyEnforces() || !ModeCanary.FullyEnforces() {
		t.Fatal("FullyEnforces wrong")
	}
	// RequiresLiveExecution is the STRICT subset that excludes Shadow: after Layer B,
	// Shadow composes the evaluation plane but performs NO real upstream side effect, so
	// it must NOT require live-execution readiness. Only Canary/Production do. This is the
	// predicate the readiness split relies on — Shadow gating on it would re-introduce the
	// coupling this phase removes.
	if ModeShadow.RequiresLiveExecution() {
		t.Fatal("Shadow must not require live execution (Layer B: no upstream side effect)")
	}
	if ModeObserve.RequiresLiveExecution() || ModeDisabled.RequiresLiveExecution() {
		t.Fatal("Observe/Disabled must not require live execution")
	}
	if !ModeCanary.RequiresLiveExecution() || !ModeProduction.RequiresLiveExecution() {
		t.Fatal("Canary/Production must require live execution")
	}
}

func TestPromotionOneStageOnly(t *testing.T) {
	ok := [][2]Mode{{ModeDisabled, ModeObserve}, {ModeObserve, ModeShadow}, {ModeShadow, ModeCanary}}
	for _, p := range ok {
		k, err := CheckTransition(TransitionInput{Capability: CapabilityGateway, From: p[0], To: p[1]})
		if err != nil || k != TransitionPromotion {
			t.Fatalf("promotion %v→%v: kind=%v err=%v", p[0], p[1], k, err)
		}
	}
	skips := [][2]Mode{{ModeDisabled, ModeShadow}, {ModeObserve, ModeCanary}, {ModeShadow, ModeProduction}}
	for _, p := range skips {
		if _, err := CheckTransition(TransitionInput{Capability: CapabilityGateway, From: p[0], To: p[1]}); err == nil {
			t.Fatalf("skip promotion %v→%v should be rejected", p[0], p[1])
		}
	}
}

func TestDemotionMultiStage(t *testing.T) {
	for _, p := range [][2]Mode{{ModeProduction, ModeDisabled}, {ModeCanary, ModeObserve}, {ModeShadow, ModeDisabled}} {
		k, err := CheckTransition(TransitionInput{Capability: CapabilityGateway, From: p[0], To: p[1]})
		if err != nil || k != TransitionDemotion {
			t.Fatalf("demotion %v→%v: kind=%v err=%v", p[0], p[1], k, err)
		}
	}
}

func TestNoOpTransitionRejected(t *testing.T) {
	if _, err := CheckTransition(TransitionInput{Capability: CapabilityGateway, From: ModeShadow, To: ModeShadow}); err == nil {
		t.Fatal("no-op transition should be rejected")
	}
}

type testVerifier struct {
	accept  bool
	gotBind QualificationBinding
}

func (v *testVerifier) VerifyProductionQualification(b QualificationBinding) error {
	v.gotBind = b
	if v.accept {
		return nil
	}
	return mcperr.New(mcperr.ReasonRolloutQualificationInvalid, "test", "rejected")
}

func TestProductionLockedWithoutVerifier(t *testing.T) {
	_, err := CheckTransition(TransitionInput{Capability: CapabilityGateway, From: ModeCanary, To: ModeProduction})
	if mcperr.ReasonOf(err) != mcperr.ReasonRolloutProductionLocked {
		t.Fatalf("expected production locked, got %v", err)
	}
}

func TestProductionRejectedByVerifier(t *testing.T) {
	v := &testVerifier{accept: false}
	b := QualificationBinding{Capability: CapabilityGateway, FromMode: ModeCanary, ToMode: ModeProduction, TargetScopeHash: "h", SnapshotHash: "s"}
	_, err := CheckTransition(TransitionInput{Capability: CapabilityGateway, From: ModeCanary, To: ModeProduction, Qualification: v, Binding: b})
	if mcperr.ReasonOf(err) != mcperr.ReasonRolloutQualificationInvalid {
		t.Fatalf("expected qualification invalid, got %v", err)
	}
}

func TestProductionAcceptedOnlyViaVerifier(t *testing.T) {
	v := &testVerifier{accept: true}
	b := QualificationBinding{Capability: CapabilityGateway, FromMode: ModeCanary, ToMode: ModeProduction, TargetScopeHash: "h", SnapshotHash: "s"}
	k, err := CheckTransition(TransitionInput{Capability: CapabilityGateway, From: ModeCanary, To: ModeProduction, Qualification: v, Binding: b})
	if err != nil || k != TransitionPromotion {
		t.Fatalf("production via verifier: kind=%v err=%v", k, err)
	}
	if v.gotBind.SnapshotHash != "s" {
		t.Fatal("verifier did not receive the binding")
	}
}

func TestProductionBindingMustMatch(t *testing.T) {
	v := &testVerifier{accept: true}
	// Binding for a different capability must be rejected before the verifier is trusted.
	b := QualificationBinding{Capability: CapabilityManagement, FromMode: ModeCanary, ToMode: ModeProduction, TargetScopeHash: "h", SnapshotHash: "s"}
	_, err := CheckTransition(TransitionInput{Capability: CapabilityGateway, From: ModeCanary, To: ModeProduction, Qualification: v, Binding: b})
	if mcperr.ReasonOf(err) != mcperr.ReasonRolloutQualificationInvalid {
		t.Fatalf("mismatched binding should fail, got %v", err)
	}
}

// ── Scope ──────────────────────────────────────────────────────────────────

func gwSubject() Subject {
	return Subject{Capability: CapabilityGateway, Tenant: "t1", ServerID: "s1", ToolName: "read_file", ToolFingerprint: "fp1", PrincipalID: "p1", Operation: RiskRead}
}

func TestEmptyScopeMatchesNothing(t *testing.T) {
	sc := EmptyScope(CapabilityGateway)
	if !sc.MatchesNothing() {
		t.Fatal("empty scope should match nothing")
	}
	if sc.Contains(gwSubject()) {
		t.Fatal("empty scope must not contain any subject (no wildcard all)")
	}
}

func TestScopeDimensionMatch(t *testing.T) {
	sc, err := Compile(ScopeSpec{Capability: CapabilityGateway, Tenants: []string{"t1"}, Servers: []string{"s1"}}, 1, testLimits(t))
	if err != nil {
		t.Fatal(err)
	}
	if !sc.Contains(gwSubject()) {
		t.Fatal("subject should match")
	}
	other := gwSubject()
	other.Tenant = "t2"
	if sc.Contains(other) {
		t.Fatal("tenant t2 must not match (AND across dimensions)")
	}
}

func TestScopeExclusionNarrows(t *testing.T) {
	sc, err := Compile(ScopeSpec{Capability: CapabilityGateway, Tenants: []string{"t1"}, ExcludePrincipals: []string{"p1"}}, 1, testLimits(t))
	if err != nil {
		t.Fatal(err)
	}
	if sc.Contains(gwSubject()) {
		t.Fatal("excluded principal must not match")
	}
	ok := gwSubject()
	ok.PrincipalID = "p2"
	if !sc.Contains(ok) {
		t.Fatal("non-excluded principal should match")
	}
}

func TestScopeCapabilityIsolation(t *testing.T) {
	sc, _ := Compile(ScopeSpec{Capability: CapabilityGateway, Tenants: []string{"t1"}}, 1, testLimits(t))
	mgmt := gwSubject()
	mgmt.Capability = CapabilityManagement
	if sc.Contains(mgmt) {
		t.Fatal("gateway scope must never match a management subject")
	}
}

func TestScopeHighRiskGate(t *testing.T) {
	_, err := Compile(ScopeSpec{Capability: CapabilityGateway, Servers: []string{"s1"}, Operations: []RiskClass{RiskWrite}}, 1, testLimits(t))
	if mcperr.ReasonOf(err) != mcperr.ReasonRolloutScopeInvalid {
		t.Fatalf("write op without high-risk scope should fail, got %v", err)
	}
	if _, err := Compile(ScopeSpec{Capability: CapabilityGateway, Servers: []string{"s1"}, Operations: []RiskClass{RiskWrite}, HighRisk: true}, 1, testLimits(t)); err != nil {
		t.Fatalf("write op with high-risk scope should compile: %v", err)
	}
}

func TestScopeDefaultReadOnly(t *testing.T) {
	sc, _ := Compile(ScopeSpec{Capability: CapabilityGateway, Servers: []string{"s1"}}, 1, testLimits(t))
	w := gwSubject()
	w.Operation = RiskWrite
	if sc.Contains(w) {
		t.Fatal("a default (non-high-risk) scope must not admit a write op")
	}
}

func TestPercentageBucketStable(t *testing.T) {
	// Same (salt,key) must produce the same bucket every call (restart stability).
	for i := 0; i < 100; i++ {
		first := StableBucket("salt-A", "user-42")
		second := StableBucket("salt-A", "user-42")
		if first != second {
			t.Fatal("bucket not deterministic")
		}
	}
	// A different salt (a new revision) re-buckets; must still be deterministic.
	if StableBucket("salt-A", "user-42") == StableBucket("salt-B", "user-42") {
		// Not guaranteed different, but the point is determinism; re-check stability.
		_ = 0
	}
	sc, err := Compile(ScopeSpec{Capability: CapabilityGateway, Servers: []string{"s1"}, Percent: 50, BucketSalt: "salt-A"}, 1, testLimits(t))
	if err != nil {
		t.Fatal(err)
	}
	subj := gwSubject()
	first := sc.Contains(subj)
	for i := 0; i < 50; i++ {
		if sc.Contains(subj) != first {
			t.Fatal("percentage membership not stable across calls")
		}
	}
}

func TestPercentageRequiresSalt(t *testing.T) {
	_, err := Compile(ScopeSpec{Capability: CapabilityGateway, Servers: []string{"s1"}, Percent: 10}, 1, testLimits(t))
	if mcperr.ReasonOf(err) != mcperr.ReasonRolloutScopeInvalid {
		t.Fatalf("percentage without salt should fail, got %v", err)
	}
}

func TestScopeEnumerable(t *testing.T) {
	pure, _ := Compile(ScopeSpec{Capability: CapabilityGateway, Percent: 1, BucketSalt: "s"}, 1, testLimits(t))
	if pure.Enumerable() {
		t.Fatal("a pure-percentage scope must not be enumerable")
	}
	enum, _ := Compile(ScopeSpec{Capability: CapabilityGateway, Servers: []string{"s1"}}, 1, testLimits(t))
	if !enum.Enumerable() {
		t.Fatal("a dimensioned scope must be enumerable")
	}
}

func TestScopeHashDeterministic(t *testing.T) {
	a, _ := Compile(ScopeSpec{Capability: CapabilityGateway, Servers: []string{"s1", "s2"}, Tenants: []string{"t1"}}, 3, testLimits(t))
	b, _ := Compile(ScopeSpec{Capability: CapabilityGateway, Tenants: []string{"t1"}, Servers: []string{"s2", "s1"}}, 3, testLimits(t))
	if a.Hash() != b.Hash() {
		t.Fatal("scope hash must be order-independent")
	}
	c, _ := Compile(ScopeSpec{Capability: CapabilityGateway, Servers: []string{"s1"}}, 3, testLimits(t))
	if a.Hash() == c.Hash() {
		t.Fatal("different scopes must hash differently")
	}
}

func TestSelectorSchemaFailClosed(t *testing.T) {
	if SupportsSelectorSchema(selectorSchema + 1) {
		t.Fatal("a higher selector schema must not be supported (fail closed)")
	}
}

// ── Mode resolution semantics ──────────────────────────────────────────────

func TestResolveDisabledObserveRecordOnly(t *testing.T) {
	for _, m := range []Mode{ModeDisabled, ModeObserve} {
		r := Resolve(ResolveInput{Mode: m, InScope: true, Action: ActionKindAllow})
		if r.Disposition != EffectRecordOnly || r.Executed {
			t.Fatalf("%v must be record-only, got %v", m, r.Disposition)
		}
	}
}

func TestResolveShadowEvaluatesAndRecordsOverride(t *testing.T) {
	// A non-hard DENY in shadow scope is a would-execute-and-record: a NON-executing
	// shadow evaluation (EffectShadowEvaluate, Executed=false), override set. Shadow
	// evaluates the would-be outcome; it never crosses the side-effect boundary
	// (SH-INV-1).
	r := Resolve(ResolveInput{Mode: ModeShadow, InScope: true, Action: ActionKindDenied})
	if r.Disposition != EffectShadowEvaluate {
		t.Fatalf("shadow in-scope should shadow-evaluate, got %v", r.Disposition)
	}
	if r.Executed {
		t.Fatal("shadow must NOT be marked executed — it evaluates, it does not execute")
	}
	if r.EvaluatedAction != ActionKindDenied {
		t.Fatal("evaluated action must be preserved as DENY")
	}
	if !r.ShadowOverride {
		t.Fatal("shadow override must be set when policy would have blocked")
	}
}

// TestResolveShadowHardFailureEvaluates pins the truthful non-enforcing Shadow
// semantics: an in-scope hard failure is NOT downgraded to an EffectBlock (which would
// be indistinguishable from real enforcement) — it is routed to the non-executing
// EffectShadowEvaluate disposition so the evaluator can record WOULD_FAIL_HARD_CONTROL /
// WOULD_FAIL_INSPECTION. `Executed` stays false and the classified hard reason is
// preserved for the evaluator's evidence. Shadow predicts; it never executes and never
// enforces.
func TestResolveShadowHardFailureEvaluates(t *testing.T) {
	r := Resolve(ResolveInput{Mode: ModeShadow, InScope: true, Action: ActionKindAllow, HardFailure: true, HardReason: mcperr.ReasonSSRFBlocked})
	if r.Disposition != EffectShadowEvaluate || r.Executed {
		t.Fatalf("hard failure in shadow must route to a non-executing evaluation, got disposition=%v executed=%v", r.Disposition, r.Executed)
	}
	if r.Disposition == EffectExecute {
		t.Fatal("shadow must NEVER emit EffectExecute")
	}
	if r.HardFailure != true {
		t.Fatal("hard-failure flag must be preserved for evidence")
	}
	if r.BlockReason != mcperr.ReasonSSRFBlocked {
		t.Fatal("classified hard reason must be preserved for the evaluator")
	}
}

func TestResolveShadowOutOfScopeRecordOnly(t *testing.T) {
	r := Resolve(ResolveInput{Mode: ModeShadow, InScope: false, Action: ActionKindAllow})
	if r.Disposition != EffectRecordOnly || r.Executed {
		t.Fatal("shadow out-of-scope must be record-only (observe behavior)")
	}
}

func TestResolveCanaryEnforces(t *testing.T) {
	// DENY blocks.
	if r := Resolve(ResolveInput{Mode: ModeCanary, InScope: true, Action: ActionKindDenied}); r.Disposition != EffectBlock {
		t.Fatal("canary must block DENY")
	}
	// ALLOW with obligations satisfied executes.
	if r := Resolve(ResolveInput{Mode: ModeCanary, InScope: true, Action: ActionKindAllow, ObligationsSatisfied: true}); r.Disposition != EffectExecute {
		t.Fatal("canary must execute a satisfied ALLOW")
	}
	// ALLOW_ONCE without a satisfied allowance blocks.
	if r := Resolve(ResolveInput{Mode: ModeCanary, InScope: true, Action: ActionKindAllowOnce, ObligationsSatisfied: false}); r.Disposition != EffectBlock {
		t.Fatal("canary must block an unsatisfied ALLOW_ONCE")
	}
	// REQUIRE_APPROVAL blocks with the approval-required reason.
	r := Resolve(ResolveInput{Mode: ModeCanary, InScope: true, Action: ActionKindApproval})
	if r.Disposition != EffectBlock || r.BlockReason != mcperr.ReasonApprovalRequired {
		t.Fatalf("canary approval-required must block, got %v/%v", r.Disposition, r.BlockReason)
	}
}

func TestResolveCanaryOutOfScopeShadowFallback(t *testing.T) {
	// Out of canary scope, but in shadow scope, retains shadow behavior: a NON-executing
	// shadow evaluation (never the enforcing execute path).
	r := Resolve(ResolveInput{Mode: ModeCanary, InScope: false, ShadowEnabled: true, ShadowInScope: true, Action: ActionKindDenied})
	if r.Disposition != EffectShadowEvaluate || r.Executed {
		t.Fatalf("canary out-of-scope with shadow fallback should shadow-evaluate (not execute), got %v", r.Disposition)
	}
	// Out of both scopes → observe behavior.
	r2 := Resolve(ResolveInput{Mode: ModeCanary, InScope: false, ShadowEnabled: false, Action: ActionKindAllow})
	if r2.Disposition != EffectRecordOnly {
		t.Fatal("canary out-of-scope with no shadow should be record-only")
	}
}

// ── State machine ──────────────────────────────────────────────────────────

func TestStateSetConfigAndResolve(t *testing.T) {
	st := NewState(CapabilityGateway, testLimits(t))
	if st.CurrentMode() != ModeDisabled {
		t.Fatal("initial mode must be Disabled")
	}
	cfg := SignedConfig{SelectorSchema: selectorSchema, Capability: CapabilityGateway, Mode: ModeShadow, ScopeRevision: 1,
		Scope: ScopeSpec{Capability: CapabilityGateway, Servers: []string{"s1"}}, ConnectorMode: ConnectorLocalClient}
	if err := st.SetConfig(cfg, "admin@test", 1000); err != nil {
		t.Fatal(err)
	}
	if st.CurrentMode() != ModeShadow {
		t.Fatal("mode should be Shadow after SetConfig")
	}
	res := st.ResolveFor(gwSubject(), ActionKindDenied, false, mcperr.ReasonNone, false)
	if res.Disposition != EffectShadowEvaluate || res.Executed {
		t.Fatal("in-scope shadow should shadow-evaluate (not execute)")
	}
	if len(st.History()) != 1 {
		t.Fatal("a mode change should be recorded in history")
	}
}

func TestStateKillSwitch(t *testing.T) {
	st := NewState(CapabilityGateway, testLimits(t))
	if st.Killed() {
		t.Fatal("not killed initially")
	}
	st.EngageKillSwitch("oncall", 1)
	if !st.Killed() {
		t.Fatal("kill switch should engage")
	}
	st.ClearKillSwitch()
	if st.Killed() {
		t.Fatal("kill switch should clear")
	}
}

func TestStatePersistRoundTrip(t *testing.T) {
	st := NewState(CapabilityGateway, testLimits(t))
	cfg := SignedConfig{SelectorSchema: selectorSchema, Capability: CapabilityGateway, Mode: ModeShadow, ScopeRevision: 1,
		Scope: ScopeSpec{Capability: CapabilityGateway, Servers: []string{"s1"}}, ConnectorMode: ConnectorLocalClient}
	if err := st.SetConfig(cfg, "admin", 1); err != nil {
		t.Fatal(err)
	}
	st.EngageKillSwitch("oncall", 2)
	p := st.ToPersist()

	restored := NewState(CapabilityGateway, testLimits(t))
	if err := restored.LoadPersist(p); err != nil {
		t.Fatal(err)
	}
	if restored.CurrentMode() != ModeShadow {
		t.Fatal("mode must survive restart")
	}
	if !restored.Killed() {
		t.Fatal("kill switch must survive restart (restart-persistent)")
	}
}

// ── Connector mode ─────────────────────────────────────────────────────────

func TestConnectorModeValidation(t *testing.T) {
	if err := ValidateConnectorMode(ConnectorLocalClient); err != nil {
		t.Fatal("local-client must be accepted")
	}
	if err := ValidateConnectorMode(""); err != nil {
		t.Fatal("empty (default local-client) must be accepted")
	}
	for _, bad := range []string{ConnectorOutbound, ConnectorDMZ, "public-listener", "bridge"} {
		if err := ValidateConnectorMode(bad); mcperr.ReasonOf(err) != mcperr.ReasonRolloutConnectorModeRejected {
			t.Fatalf("connector mode %q must be rejected", bad)
		}
	}
}

func TestSignedConfigRejectsConnector(t *testing.T) {
	cfg := SignedConfig{SelectorSchema: selectorSchema, Capability: CapabilityGateway, Mode: ModeObserve,
		Scope: ScopeSpec{Capability: CapabilityGateway}, ConnectorMode: ConnectorOutbound}
	if mcperr.ReasonOf(cfg.Validate(CapabilityGateway, testLimits(t))) != mcperr.ReasonRolloutConnectorModeRejected {
		t.Fatal("signed config must reject outbound-connector")
	}
}

func TestSignedConfigCanaryRequiresEnumerable(t *testing.T) {
	cfg := SignedConfig{SelectorSchema: selectorSchema, Capability: CapabilityGateway, Mode: ModeCanary,
		Scope: ScopeSpec{Capability: CapabilityGateway, Percent: 1, BucketSalt: "s"}, ConnectorMode: ConnectorLocalClient}
	if mcperr.ReasonOf(cfg.Validate(CapabilityGateway, testLimits(t))) != mcperr.ReasonRolloutScopeInvalid {
		t.Fatal("canary must require an enumerable scope")
	}
}

// TestShadowNeverResolvesToExecute is §15 mutation #1: an in-scope Shadow request must
// NEVER resolve to EffectExecute, for ANY policy action and with or without a hard
// failure — Shadow evaluates, it never crosses the side-effect boundary. Mutation:
// making resolveShadow return EffectExecute for the allow case fails this exhaustively.
func TestShadowNeverResolvesToExecute(t *testing.T) {
	actions := []ActionKind{
		ActionKindDenied, ActionKindAllow, ActionKindConfirm, ActionKindApproval,
		ActionKindAllowOnce, ActionKindAllowSession, ActionKindRedaction,
	}
	for _, inScope := range []bool{true, false} {
		for _, hard := range []bool{true, false} {
			for _, a := range actions {
				r := Resolve(ResolveInput{
					Mode: ModeShadow, InScope: inScope, Action: a,
					HardFailure: hard, ObligationsSatisfied: true,
				})
				if r.Disposition == EffectExecute {
					t.Fatalf("SECURITY: Shadow resolved to EffectExecute (inScope=%v hard=%v action=%v)", inScope, hard, a)
				}
				if r.Executed {
					t.Fatalf("SECURITY: Shadow marked Executed (inScope=%v hard=%v action=%v)", inScope, hard, a)
				}
				// In-scope Shadow is always the non-executing evaluate disposition;
				// out-of-scope is Observe (record-only). Never execute, never block.
				want := EffectShadowEvaluate
				if !inScope {
					want = EffectRecordOnly
				}
				if r.Disposition != want {
					t.Fatalf("Shadow disposition = %v, want %v (inScope=%v hard=%v action=%v)", r.Disposition, want, inScope, hard, a)
				}
			}
		}
	}
}

// TestEmptyScopeMatchesNoSubject is §15 mutation #6: a missing/empty scope must match
// NOTHING (never "all subjects"). Combined with the Shadow-requires-enumerable
// validation, this makes "missing scope shadows everything" impossible in both
// directions — the config is rejected AND, defensively, an empty scope contains nothing.
func TestEmptyScopeMatchesNoSubject(t *testing.T) {
	empty := EmptyScope(CapabilityGateway)
	if !empty.MatchesNothing() {
		t.Fatal("an empty scope must report MatchesNothing")
	}
	subjects := []Subject{
		{Capability: CapabilityGateway, PrincipalID: "p1", ServerID: "s1", Operation: RiskRead},
		{Capability: CapabilityGateway, Tenant: "t1", Operation: RiskRead},
		{Capability: CapabilityGateway, ClientID: "c1", AgentID: "a1", Operation: RiskWrite},
	}
	for _, s := range subjects {
		if empty.Contains(s) {
			t.Fatalf("SECURITY: an empty scope must not contain any subject, matched %+v", s)
		}
	}
}

// TestSignedConfigShadowRequiresEnumerable pins the "no scope = no Shadow" contract
// (SHADOW-ACTIVATION.md §5). An EMPTY Shadow scope and a PERCENTAGE-ONLY Shadow scope
// must both be rejected fail-closed at validation, so a mis-scoped Shadow activation can
// never look accepted while shadowing nothing (or, via a later widening, everything).
//
// Mutation coverage: reverting the Validate change so ModeShadow is not in the
// enumerable-required set makes the empty-scope case pass validation (would_execute a
// fleet-wide shadow by omission) and fails this test.
func TestSignedConfigShadowRequiresEnumerable(t *testing.T) {
	// Empty scope (no inclusion selectors, no percentage) — the classic "missing scope".
	empty := SignedConfig{SelectorSchema: selectorSchema, Capability: CapabilityGateway, Mode: ModeShadow,
		Scope: ScopeSpec{Capability: CapabilityGateway}, ConnectorMode: ConnectorLocalClient}
	if mcperr.ReasonOf(empty.Validate(CapabilityGateway, testLimits(t))) != mcperr.ReasonRolloutScopeInvalid {
		t.Fatal("SECURITY: an empty-scope Shadow config must be rejected (no scope = no Shadow)")
	}
	// Percentage-only scope — "1% of everything" is not an enumerable bounded target.
	pct := SignedConfig{SelectorSchema: selectorSchema, Capability: CapabilityGateway, Mode: ModeShadow,
		Scope: ScopeSpec{Capability: CapabilityGateway, Percent: 1, BucketSalt: "s"}, ConnectorMode: ConnectorLocalClient}
	if mcperr.ReasonOf(pct.Validate(CapabilityGateway, testLimits(t))) != mcperr.ReasonRolloutScopeInvalid {
		t.Fatal("SECURITY: a percentage-only Shadow config must be rejected (not an enumerable bounded target)")
	}
	// A tightly bounded Shadow scope (one server) is valid — the first-activation shape.
	ok := SignedConfig{SelectorSchema: selectorSchema, Capability: CapabilityGateway, Mode: ModeShadow, ScopeRevision: 1,
		Scope: ScopeSpec{Capability: CapabilityGateway, Servers: []string{"controlled-test-server"}}, ConnectorMode: ConnectorLocalClient}
	if err := ok.Validate(CapabilityGateway, testLimits(t)); err != nil {
		t.Fatalf("a bounded single-server Shadow scope must validate: %v", err)
	}
}

// ── Evidence (injected clock) ──────────────────────────────────────────────

func TestEvidenceWindowsInjectedClock(t *testing.T) {
	e := newEvidenceSummary()
	start := time.Unix(1_000_000, 0)
	e.BeginWindow(ModeShadow, start.Unix(), OriginSynthetic)
	if e.Origin != OriginSynthetic {
		t.Fatal("origin must be labeled synthetic in tests")
	}
	// 13 days: shadow window not yet met.
	if met, _ := e.PromotionEvidenceMet(ModeShadow, ModeCanary, start.Add(13*24*time.Hour)); met {
		t.Fatal("13 days must not satisfy the 14-day shadow window")
	}
	// 15 days + rollback rehearsed: met.
	e.RollbackRehearsed = true
	if met, why := e.PromotionEvidenceMet(ModeShadow, ModeCanary, start.Add(15*24*time.Hour)); !met {
		t.Fatalf("15 days + rehearsal should satisfy shadow→canary: %s", why)
	}
	// Open defects always block.
	e.OpenCriticalHighDefects = 1
	if met, _ := e.PromotionEvidenceMet(ModeShadow, ModeCanary, start.Add(30*24*time.Hour)); met {
		t.Fatal("open critical/high defects must block promotion")
	}
}

// TestAdmitsToolForEvaluation pins the principal-agnostic tool-in-scope check that the
// Shadow usable-tool preflight uses (Codex P1, PR #1234): a scope targets a tool for a
// tools/call evaluation when it admits the write risk class and the tool's server/tool
// selectors, independent of the calling identity. A read-only scope, an excluded server,
// or an off-scope server/tool must NOT be admitted.
func TestAdmitsToolForEvaluation(t *testing.T) {
	lim := DefaultLimits()
	mk := func(spec ScopeSpec) Scope {
		sc, err := Compile(spec, 1, lim)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		return sc
	}

	// Server-scoped, write-admitting scope: the in-scope tool is targeted.
	write := mk(ScopeSpec{Capability: CapabilityGateway, Servers: []string{"s1"}, Operations: []RiskClass{RiskWrite}, HighRisk: true})
	if !write.AdmitsToolForEvaluation("s1", "t", "fp") {
		t.Fatal("a write-admitting scope over server s1 must target s1's tool")
	}
	// Identity is not part of the check: no principal was configured, yet the tool is targeted.
	if !write.AdmitsToolForEvaluation("s1", "other-tool", "fp2") {
		t.Fatal("the tool match must be principal-agnostic and cover any tool on the in-scope server")
	}
	// A server NOT in the scope is not targeted.
	if write.AdmitsToolForEvaluation("s2", "t", "fp") {
		t.Fatal("a tool on an out-of-scope server must not be targeted")
	}

	// Read-only scope: no tools/call (write class) is ever targeted.
	readOnly := mk(ScopeSpec{Capability: CapabilityGateway, Servers: []string{"s1"}, Operations: []RiskClass{RiskRead}})
	if readOnly.AdmitsToolForEvaluation("s1", "t", "fp") {
		t.Fatal("a read-only scope must not target a write-class tools/call tool")
	}

	// Explicit server exclusion wins.
	excl := mk(ScopeSpec{Capability: CapabilityGateway, Servers: []string{"s1"}, ExcludeServers: []string{"s1"}, Operations: []RiskClass{RiskWrite}, HighRisk: true})
	if excl.AdmitsToolForEvaluation("s1", "t", "fp") {
		t.Fatal("an excluded server must not be targeted")
	}

	// The empty (matches-nothing) scope targets no tool.
	if EmptyScope(CapabilityGateway).AdmitsToolForEvaluation("s1", "t", "fp") {
		t.Fatal("the empty scope must target no tool")
	}

	// A tool-selector scope targets only the named tool.
	toolSel := mk(ScopeSpec{Capability: CapabilityGateway, Servers: []string{"s1"}, Tools: []ToolSel{{Server: "s1", Name: "t", Fingerprint: "fp"}}, Operations: []RiskClass{RiskWrite}, HighRisk: true})
	if !toolSel.AdmitsToolForEvaluation("s1", "t", "fp") {
		t.Fatal("the named tool must be targeted")
	}
	if toolSel.AdmitsToolForEvaluation("s1", "t", "different-fp") {
		t.Fatal("a tool selector must not target a different fingerprint")
	}

	// The fingerprint dimension is honored (Codex P1, PR #1234): a scope pinned to a specific
	// fingerprint must NOT be satisfied by a Usable tool on the same admitted server whose
	// fingerprint it does not admit — otherwise the usable-tool gate would pass for a scope
	// Contains could never admit.
	fpScope := mk(ScopeSpec{Capability: CapabilityGateway, Servers: []string{"s1"}, ToolFingerprints: []string{"pinned-fp"}, Operations: []RiskClass{RiskWrite}, HighRisk: true})
	if !fpScope.AdmitsToolForEvaluation("s1", "t", "pinned-fp") {
		t.Fatal("the pinned fingerprint must be targeted")
	}
	if fpScope.AdmitsToolForEvaluation("s1", "other", "unpinned-fp") {
		t.Fatal("a tool whose fingerprint the scope does not admit must NOT be targeted — even on an in-scope server")
	}

	// A self-contradicting identity dimension admits NO request (Contains rejects all), so a
	// Usable tool on an in-scope server must NOT be treated as reachable (Codex P2, PR #1234).
	principalContradiction := mk(ScopeSpec{Capability: CapabilityGateway, Servers: []string{"s1"}, Principals: []string{"p"}, ExcludePrincipals: []string{"p"}, Operations: []RiskClass{RiskWrite}, HighRisk: true})
	if principalContradiction.AdmitsToolForEvaluation("s1", "t", "fp") {
		t.Fatal("a scope whose only principal is also excluded admits no request — its usable tool must not be reachable")
	}
	tenantContradiction := mk(ScopeSpec{Capability: CapabilityGateway, Servers: []string{"s1"}, Tenants: []string{"acme"}, ExcludeTenants: []string{"acme"}, Operations: []RiskClass{RiskWrite}, HighRisk: true})
	if tenantContradiction.AdmitsToolForEvaluation("s1", "t", "fp") {
		t.Fatal("a scope whose only tenant is also excluded admits no request — its usable tool must not be reachable")
	}
	// A partial exclusion (one of two included principals excluded) still admits the other, so
	// the tool remains reachable — the contradiction check must not over-reject.
	partial := mk(ScopeSpec{Capability: CapabilityGateway, Servers: []string{"s1"}, Principals: []string{"p", "q"}, ExcludePrincipals: []string{"p"}, Operations: []RiskClass{RiskWrite}, HighRisk: true})
	if !partial.AdmitsToolForEvaluation("s1", "t", "fp") {
		t.Fatal("a scope that still admits principal q must keep its usable tool reachable")
	}
}
