package canary

import (
	"reflect"
	"testing"
)

// allTrueFacts returns a Facts with every prerequisite satisfied — the ONLY input that
// yields Ready. Tests flip one field at a time to prove each is independently load-bearing.
func allTrueFacts() Facts {
	return Facts{
		CapabilityGateway:         true,
		ShadowExitReviewPassed:    true,
		ScopeBounded:              true,
		ScopeReadFirst:            true,
		LiveExecutorComposed:      true,
		UpstreamCallerPresent:     true,
		CredentialPathReady:       true,
		DurableEventsHealthy:      true,
		ResponseInspectionReady:   true,
		RegistryHealthy:           true,
		CatalogHealthy:            true,
		PolicyHealthy:             true,
		EmergencyKillClear:        true,
		KillBoundaryGuardPresent:  true,
		ToolFreshnessGuardPresent: true,
		LiveApprovalValid:         true,
		ServerUsable:              true,
		ToolFingerprintCurrent:    true,
		RollbackPathHealthy:       true,
		BudgetConfigured:          true,
	}
}

func TestEvaluate_AllFactsTrueIsReady(t *testing.T) {
	got := Evaluate(allTrueFacts())
	if !got.Ready || len(got.Unmet) != 0 {
		t.Fatalf("all-true facts must be Ready with no unmet reasons, got ready=%v unmet=%v", got.Ready, got.Unmet)
	}
}

// TestEvaluate_ZeroFactsIsDormantDefault proves the shipped-default posture: the zero Facts
// value (nothing composed) is NOT ready, and — most importantly — live_executor_absent is
// among the reasons. This is the fact that keeps Canary dormant in production.
func TestEvaluate_ZeroFactsIsDormantDefault(t *testing.T) {
	got := Evaluate(Facts{}) // capability not gateway → single reason
	if got.Ready {
		t.Fatal("zero Facts must never be ready")
	}
	if len(got.Unmet) != 1 || got.Unmet[0] != ReasonCapabilityNotGateway {
		t.Fatalf("zero Facts (no capability) must fail with exactly capability_not_gateway, got %v", got.Unmet)
	}
	// With the capability set but nothing else, every other prerequisite must be unmet and
	// live_executor_absent must be present.
	got = Evaluate(Facts{CapabilityGateway: true})
	if got.Ready {
		t.Fatal("gateway-only Facts must never be ready")
	}
	if !containsReason(got.Unmet, ReasonLiveExecutorAbsent) {
		t.Fatalf("the dormant default must report live_executor_absent, got %v", got.Unmet)
	}
}

// TestEvaluate_EachFactIsIndependentlyLoadBearing flips exactly one prerequisite false from
// the all-true baseline and asserts the verdict flips to not-ready with EXACTLY that fact's
// reason. This is the non-vacuity proof: no fact is dead, none substitutes for another.
func TestEvaluate_EachFactIsIndependentlyLoadBearing(t *testing.T) {
	cases := []struct {
		field  string
		reason Reason
	}{
		{"ShadowExitReviewPassed", ReasonShadowExitNotPassed},
		{"ScopeBounded", ReasonScopeNotBounded},
		{"ScopeReadFirst", ReasonScopeNotReadFirst},
		{"LiveExecutorComposed", ReasonLiveExecutorAbsent},
		{"UpstreamCallerPresent", ReasonUpstreamCallerAbsent},
		{"CredentialPathReady", ReasonCredentialPathNotReady},
		{"DurableEventsHealthy", ReasonDurableEventsDegraded},
		{"ResponseInspectionReady", ReasonResponseInspectionNotReady},
		{"RegistryHealthy", ReasonRegistryUnhealthy},
		{"CatalogHealthy", ReasonCatalogUnhealthy},
		{"PolicyHealthy", ReasonPolicyUnhealthy},
		{"EmergencyKillClear", ReasonEmergencyKillActive},
		{"KillBoundaryGuardPresent", ReasonKillBoundaryGuardAbsent},
		{"ToolFreshnessGuardPresent", ReasonToolFreshnessGuardAbsent},
		{"LiveApprovalValid", ReasonLiveApprovalInvalid},
		{"ServerUsable", ReasonServerNotUsable},
		{"ToolFingerprintCurrent", ReasonToolFingerprintStale},
		{"RollbackPathHealthy", ReasonRollbackPathUnhealthy},
		{"BudgetConfigured", ReasonBudgetNotConfigured},
	}
	// Guard: the number of flip cases must equal the number of bool prerequisite fields
	// (minus CapabilityGateway, which is the short-circuit). If a field is added without a
	// case, this fails — the parity that stops a silently-unchecked prerequisite.
	boolFields := countBoolFields(reflect.TypeOf(Facts{})) - 1 // exclude CapabilityGateway
	if len(cases) != boolFields {
		t.Fatalf("Facts has %d prerequisite bools but only %d flip cases — a prerequisite is unchecked", boolFields, len(cases))
	}
	for _, tc := range cases {
		f := allTrueFacts()
		setBoolField(t, &f, tc.field, false)
		got := Evaluate(f)
		if got.Ready {
			t.Fatalf("flipping %s false must make the verdict not-ready", tc.field)
		}
		if len(got.Unmet) != 1 || got.Unmet[0] != tc.reason {
			t.Fatalf("flipping %s false must yield exactly [%s], got %v", tc.field, tc.reason, got.Unmet)
		}
	}
}

// TestEvaluate_ReasonVocabularyParity proves AllReasons is exactly the set Evaluate can
// emit — no reason is orphaned (declared but unreachable) and none is emitted without being
// advertised. It drives every reachable reason via a single-fact flip plus the capability
// short-circuit.
func TestEvaluate_ReasonVocabularyParity(t *testing.T) {
	reachable := map[Reason]bool{}
	// capability short-circuit
	for _, r := range Evaluate(Facts{}).Unmet {
		reachable[r] = true
	}
	// every single-fact flip
	fieldReason := map[string]Reason{
		"ShadowExitReviewPassed": ReasonShadowExitNotPassed, "ScopeBounded": ReasonScopeNotBounded,
		"ScopeReadFirst": ReasonScopeNotReadFirst, "LiveExecutorComposed": ReasonLiveExecutorAbsent,
		"UpstreamCallerPresent": ReasonUpstreamCallerAbsent, "CredentialPathReady": ReasonCredentialPathNotReady,
		"DurableEventsHealthy": ReasonDurableEventsDegraded, "ResponseInspectionReady": ReasonResponseInspectionNotReady,
		"RegistryHealthy": ReasonRegistryUnhealthy, "CatalogHealthy": ReasonCatalogUnhealthy,
		"PolicyHealthy": ReasonPolicyUnhealthy, "EmergencyKillClear": ReasonEmergencyKillActive,
		"KillBoundaryGuardPresent": ReasonKillBoundaryGuardAbsent, "ToolFreshnessGuardPresent": ReasonToolFreshnessGuardAbsent,
		"LiveApprovalValid": ReasonLiveApprovalInvalid, "ServerUsable": ReasonServerNotUsable,
		"ToolFingerprintCurrent": ReasonToolFingerprintStale, "RollbackPathHealthy": ReasonRollbackPathUnhealthy,
		"BudgetConfigured": ReasonBudgetNotConfigured,
	}
	for field := range fieldReason {
		f := allTrueFacts()
		setBoolField(t, &f, field, false)
		for _, r := range Evaluate(f).Unmet {
			reachable[r] = true
		}
	}
	all := AllReasons()
	if len(all) != len(reachable) {
		t.Fatalf("AllReasons has %d entries but %d are reachable — vocabulary drift", len(all), len(reachable))
	}
	for _, r := range all {
		if !reachable[r] {
			t.Errorf("AllReasons advertises %q but Evaluate never emits it (orphaned reason)", r)
		}
	}
}

// TestEvaluateNode_ExcludesActivationInputs is the Codex P2 regression: the scope-independent
// node dry run must never report an activation-input fact (scope/approval/budget/server/
// fingerprint) as unmet, so node_ready reflects NODE deficiencies alone. With every node fact
// satisfied but every activation fact false, EvaluateNode must be Ready with an empty Unmet
// set, while the full Evaluate reports exactly the six activation reasons.
func TestEvaluateNode_ExcludesActivationInputs(t *testing.T) {
	activationReasons := map[Reason]bool{
		ReasonScopeNotBounded: true, ReasonScopeNotReadFirst: true, ReasonLiveApprovalInvalid: true,
		ReasonServerNotUsable: true, ReasonToolFingerprintStale: true, ReasonBudgetNotConfigured: true,
	}
	// Node facts all true; the six activation facts all false.
	f := allTrueFacts()
	f.ScopeBounded, f.ScopeReadFirst, f.LiveApprovalValid = false, false, false
	f.ServerUsable, f.ToolFingerprintCurrent, f.BudgetConfigured = false, false, false

	node := EvaluateNode(f)
	if !node.Ready || len(node.Unmet) != 0 {
		t.Fatalf("node readiness must be Ready when every NODE fact holds regardless of activation inputs, got ready=%v unmet=%v", node.Ready, node.Unmet)
	}
	// The full verdict must surface exactly the six activation reasons (nothing node-level).
	full := Evaluate(f)
	if full.Ready {
		t.Fatal("full readiness must not be ready with activation inputs unmet")
	}
	if len(full.Unmet) != len(activationReasons) {
		t.Fatalf("full Evaluate must report exactly the %d activation reasons, got %v", len(activationReasons), full.Unmet)
	}
	for _, r := range full.Unmet {
		if !activationReasons[r] {
			t.Errorf("full Evaluate reported %q, which is not an activation-input reason", r)
		}
	}
}

// TestEvaluateNode_StillReportsNodeDeficiencies proves EvaluateNode is not vacuous: a false
// NODE fact (the dormant-default live tier) is still reported, and the capability short-circuit
// is preserved.
func TestEvaluateNode_StillReportsNodeDeficiencies(t *testing.T) {
	if r := EvaluateNode(Facts{}); r.Ready || len(r.Unmet) != 1 || r.Unmet[0] != ReasonCapabilityNotGateway {
		t.Fatalf("EvaluateNode must keep the capability short-circuit, got %v", r.Unmet)
	}
	node := EvaluateNode(Facts{CapabilityGateway: true})
	if node.Ready {
		t.Fatal("a gateway node with nothing composed must not be node-ready")
	}
	if !containsReason(node.Unmet, ReasonLiveExecutorAbsent) {
		t.Fatalf("node readiness must still report live_executor_absent, got %v", node.Unmet)
	}
	// It must NOT report any activation-input reason even though those facts are false.
	for _, r := range []Reason{ReasonScopeNotBounded, ReasonLiveApprovalInvalid, ReasonBudgetNotConfigured} {
		if containsReason(node.Unmet, r) {
			t.Errorf("node readiness must not report activation reason %q", r)
		}
	}
}

// --- reflection helpers ---

func countBoolFields(t reflect.Type) int {
	n := 0
	for i := 0; i < t.NumField(); i++ {
		if t.Field(i).Type.Kind() == reflect.Bool {
			n++
		}
	}
	return n
}

func setBoolField(t *testing.T, f *Facts, name string, v bool) {
	t.Helper()
	rv := reflect.ValueOf(f).Elem().FieldByName(name)
	if !rv.IsValid() || rv.Kind() != reflect.Bool {
		t.Fatalf("Facts has no bool field %q", name)
	}
	rv.SetBool(v)
}

func containsReason(rs []Reason, want Reason) bool {
	for _, r := range rs {
		if r == want {
			return true
		}
	}
	return false
}
