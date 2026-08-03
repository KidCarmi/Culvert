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
	if ModeObserve.Executes() || !ModeShadow.Executes() {
		t.Fatal("Executes wrong")
	}
	if ModeShadow.FullyEnforces() || !ModeCanary.FullyEnforces() {
		t.Fatal("FullyEnforces wrong")
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
		if StableBucket("salt-A", "user-42") != StableBucket("salt-A", "user-42") {
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

func TestResolveShadowExecutesAndRecordsOverride(t *testing.T) {
	// A non-hard DENY in shadow scope is allow-and-record (executes, override set).
	r := Resolve(ResolveInput{Mode: ModeShadow, InScope: true, Action: ActionKindDenied})
	if r.Disposition != EffectExecute || !r.Executed {
		t.Fatalf("shadow in-scope should execute, got %v", r.Disposition)
	}
	if r.EvaluatedAction != ActionKindDenied {
		t.Fatal("evaluated action must be preserved as DENY")
	}
	if !r.ShadowOverride {
		t.Fatal("shadow override must be set when policy would have blocked")
	}
}

func TestResolveShadowHardFailureBlocks(t *testing.T) {
	r := Resolve(ResolveInput{Mode: ModeShadow, InScope: true, Action: ActionKindAllow, HardFailure: true, HardReason: mcperr.ReasonSSRFBlocked})
	if r.Disposition != EffectBlock || r.Executed {
		t.Fatal("hard failure must block even in shadow")
	}
	if r.BlockReason != mcperr.ReasonSSRFBlocked {
		t.Fatal("block reason must be preserved")
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
	// Out of canary scope, but in shadow scope, retains shadow behavior (executes).
	r := Resolve(ResolveInput{Mode: ModeCanary, InScope: false, ShadowEnabled: true, ShadowInScope: true, Action: ActionKindDenied})
	if r.Disposition != EffectExecute {
		t.Fatalf("canary out-of-scope with shadow fallback should execute (shadow), got %v", r.Disposition)
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
	if res.Disposition != EffectExecute {
		t.Fatal("in-scope shadow should execute")
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
