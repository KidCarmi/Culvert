package canary

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"testing"
)

// allTrueFacts returns a Facts with every prerequisite satisfied — the ONLY input that
// yields Ready. Tests flip one field at a time to prove each is independently load-bearing.
func allTrueFacts() Facts {
	return Facts{
		CapabilityGateway:            true,
		ShadowExitReviewPassed:       true,
		ScopeBounded:                 true,
		ScopeReadFirst:               true,
		ScopeExactFirstCanary:        true,
		LiveExecutorComposed:         true,
		UpstreamCallerPresent:        true,
		CredentialPathReady:          true,
		DurableEventsHealthy:         true,
		ResponseInspectionReady:      true,
		RegistryHealthy:              true,
		CatalogHealthy:               true,
		PolicyHealthy:                true,
		EmergencyKillClear:           true,
		KillBoundaryGuardPresent:     true,
		ToolFreshnessGuardPresent:    true,
		LiveApprovalValid:            true,
		ServerUsable:                 true,
		ToolFingerprintCurrent:       true,
		ToolCatalogUsable:            true,
		RollbackPathHealthy:          true,
		RollbackCoordinatorRehearsed: true,
		BudgetConfigured:             true,
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
		{"ScopeExactFirstCanary", ReasonScopeNotExactFirstCanary},
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
		{"ToolCatalogUsable", ReasonToolNotCatalogUsable},
		{"RollbackPathHealthy", ReasonRollbackPathUnhealthy},
		{"RollbackCoordinatorRehearsed", ReasonRollbackCoordinatorRehearsalPending},
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
		"ScopeReadFirst": ReasonScopeNotReadFirst, "ScopeExactFirstCanary": ReasonScopeNotExactFirstCanary,
		"LiveExecutorComposed":  ReasonLiveExecutorAbsent,
		"UpstreamCallerPresent": ReasonUpstreamCallerAbsent, "CredentialPathReady": ReasonCredentialPathNotReady,
		"DurableEventsHealthy": ReasonDurableEventsDegraded, "ResponseInspectionReady": ReasonResponseInspectionNotReady,
		"RegistryHealthy": ReasonRegistryUnhealthy, "CatalogHealthy": ReasonCatalogUnhealthy,
		"PolicyHealthy": ReasonPolicyUnhealthy, "EmergencyKillClear": ReasonEmergencyKillActive,
		"KillBoundaryGuardPresent": ReasonKillBoundaryGuardAbsent, "ToolFreshnessGuardPresent": ReasonToolFreshnessGuardAbsent,
		"LiveApprovalValid": ReasonLiveApprovalInvalid, "ServerUsable": ReasonServerNotUsable,
		"ToolFingerprintCurrent": ReasonToolFingerprintStale, "ToolCatalogUsable": ReasonToolNotCatalogUsable,
		"RollbackPathHealthy":          ReasonRollbackPathUnhealthy,
		"RollbackCoordinatorRehearsed": ReasonRollbackCoordinatorRehearsalPending,
		"BudgetConfigured":             ReasonBudgetNotConfigured,
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
// node dry run must never report an activation-input fact (scope/read-first/exact-first-Canary/
// approval/server/fingerprint/catalog-usability/budget) as unmet, so node_ready reflects NODE
// deficiencies alone. With every node fact satisfied but every activation fact false,
// EvaluateNode must be Ready with an empty Unmet set, while the full Evaluate reports exactly
// the eight activation reasons.
//
// The expected set and the constructed Facts are both checked AGAINST readinessChecks rather
// than trusted as hand-written enumeration (Codex P2, PR #1378). Without those two derived
// assertions this test is self-referential: a newly added factActivation row that allTrueFacts
// initializes true, and that neither the map nor the explicit false assignments below mention,
// leaves Evaluate reporting the same count as the stale map and the test passes while proving
// nothing about the new row. That is not a hypothetical -- CANARY-READINESS-MATRIX.md drifted
// to an undercount by exactly this route and stayed wrong across two reviews.
func TestEvaluateNode_ExcludesActivationInputs(t *testing.T) {
	activationReasons := map[Reason]bool{
		ReasonScopeNotBounded: true, ReasonScopeNotReadFirst: true, ReasonScopeNotExactFirstCanary: true,
		ReasonLiveApprovalInvalid: true, ReasonServerNotUsable: true, ReasonToolFingerprintStale: true,
		ReasonToolNotCatalogUsable: true, ReasonBudgetNotConfigured: true,
	}

	// DERIVED CHECK 1 -- membership. The hand-written map above must equal the factActivation
	// rows of readinessChecks exactly, so adding a row without listing it here fails the build
	// rather than silently shrinking what this test covers.
	fromTable := map[Reason]bool{}
	for i := range readinessChecks {
		if readinessChecks[i].scope == factActivation {
			fromTable[readinessChecks[i].reason] = true
		}
	}
	if len(fromTable) != len(activationReasons) {
		t.Fatalf("activationReasons lists %d reasons but readinessChecks marks %d rows factActivation: %v vs %v",
			len(activationReasons), len(fromTable), activationReasons, fromTable)
	}
	for r := range fromTable {
		if !activationReasons[r] {
			t.Fatalf("readinessChecks marks %q factActivation but activationReasons omits it -- add it here and to the explicit false assignments below", r)
		}
	}

	// Node facts all true; the eight activation facts all false.
	f := allTrueFacts()
	f.ScopeBounded, f.ScopeReadFirst, f.ScopeExactFirstCanary = false, false, false
	f.LiveApprovalValid, f.ServerUsable = false, false
	f.ToolFingerprintCurrent, f.BudgetConfigured = false, false
	f.ToolCatalogUsable = false

	// DERIVED CHECK 2 -- the fixture matches its own description. Asked directly, every
	// factActivation accessor must answer false and every factNode accessor true. Check 1 alone
	// does not get here: a row can be listed in the map and still left true in the Facts above,
	// which would drop it out of Unmet and make the count assertion pass for the wrong reason.
	for i := range readinessChecks {
		c := readinessChecks[i]
		if got, want := c.ok(f), c.scope == factNode; got != want {
			t.Fatalf("fixture is wrong for %q (scope=%d): accessor returned %v, want %v -- node facts must be true and activation facts false", c.reason, c.scope, got, want)
		}
	}

	node := EvaluateNode(f)
	if !node.Ready || len(node.Unmet) != 0 {
		t.Fatalf("node readiness must be Ready when every NODE fact holds regardless of activation inputs, got ready=%v unmet=%v", node.Ready, node.Unmet)
	}
	// The full verdict must surface exactly the eight activation reasons (nothing node-level).
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

// ── every unmet prerequisite is reported TOGETHER, not one at a time ─────────
//
// Codex P2 round 12. The single-field flips above prove each accessor in ISOLATION: they
// start from allTrueFacts() and turn exactly one fact off, so every OTHER fact is true in
// every case they run. That makes them blind to an accessor that consults another fact —
// `return f.ToolCatalogUsable || !f.LiveExecutorComposed` passes the whole package, because
// the disjunct is false in every fixture those tests build. On the SHIPPED node the live
// executor is absent, so that accessor would report the tool catalog-usable no matter what
// the catalog says, and Unmet would silently stop listing a missing prerequisite.
//
// Verified: the mutation above was applied and `go test ./internal/mcp/canary/` returned ok.
//
// This gate is the opposite fixture — every prerequisite FALSE — and it is DERIVED: the
// expected reason set is read off readinessChecks, so a new row is covered the moment it
// exists. Every accessor in the table is a plain positive field read, so all-false must
// yield all-unmet exactly; an accessor that consults a second fact breaks that, whichever
// direction it leans.
func TestEvaluate_EveryUnmetFactIsReportedTogether(t *testing.T) {
	// Capability holds so evaluate() reaches the table; every prerequisite is false.
	got := Evaluate(Facts{CapabilityGateway: true})

	want := map[Reason]bool{}
	for _, c := range readinessChecks {
		want[c.reason] = true
	}
	if len(want) == 0 {
		t.Fatal("gate is vacuous: readinessChecks is empty")
	}

	have := map[Reason]bool{}
	for _, r := range got.Unmet {
		have[r] = true
	}
	for r := range want {
		if !have[r] {
			t.Errorf("SECURITY: with EVERY prerequisite false, %s is missing from Unmet — its "+
				"accessor is satisfied by something other than its own fact, so on a node where "+
				"that other fact happens to hold the prerequisite stops being reported", r)
		}
	}
	for r := range have {
		if !want[r] {
			t.Errorf("Unmet reports %s, which is not a row in readinessChecks", r)
		}
	}
	if got.Ready {
		t.Fatal("CONTROL: a node with every prerequisite false must not be Ready")
	}
}

// ── every accessor reads exactly ONE fact: its own ───────────────────────────
//
// Codex P2 round 13, and it lands on an assumption I stated in the gate above without
// asserting it. TestEvaluate_EveryUnmetFactIsReportedTogether is only sound if every
// accessor is a plain positive field read — otherwise all-false is just a third VERTEX,
// and an accessor can be made to agree at all-true, every single-false, AND all-false
// while disagreeing in between. Measured: replacing the catalog accessor with
//
//	f.ToolCatalogUsable || (!f.LiveExecutorComposed && !f.UpstreamCallerPresent && f.PolicyHealthy)
//
// passes the entire internal/mcp/canary package (ok, 0.018s), and on a partially composed
// node with healthy policy it suppresses ReasonToolNotCatalogUsable even though the catalog
// fact is false — a missing prerequisite silently dropped from Unmet on exactly the kind of
// node a Canary would first meet.
//
// Vertex coverage cannot close this: 2^23 combinations is not enumerable and any hand-picked
// subset is another proxy. So the SHAPE is asserted directly — each accessor body must be a
// single `return f.<Field>` — which makes the property true by construction rather than
// sampled, and makes the all-false gate's assumption load-bearing text instead of a hope.
func TestReadinessChecks_EveryAccessorReadsOnlyItsOwnFact(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "readiness.go", nil, 0)
	if err != nil {
		t.Fatalf("parse readiness.go: %v", err)
	}
	var table *ast.CompositeLit
	ast.Inspect(file, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok || len(vs.Names) != 1 || vs.Names[0].Name != "readinessChecks" {
			return true
		}
		if len(vs.Values) == 1 {
			table, _ = vs.Values[0].(*ast.CompositeLit)
		}
		return false
	})
	if table == nil {
		t.Fatal("gate is vacuous: readinessChecks table literal not found")
	}
	if len(table.Elts) != len(readinessChecks) {
		t.Fatalf("gate is vacuous: found %d literal rows for %d table entries",
			len(table.Elts), len(readinessChecks))
	}

	for i, el := range table.Elts {
		lit, ok := el.(*ast.CompositeLit)
		if !ok || len(lit.Elts) == 0 {
			t.Errorf("row %d is not a composite literal", i)
			continue
		}
		fn, ok := lit.Elts[0].(*ast.FuncLit)
		if !ok {
			t.Errorf("row %d's accessor is not a function literal — it may be a named function "+
				"or a wrapper, and this gate cannot see what it reads", i)
			continue
		}
		if field := soleFactFieldRead(fn); field == "" {
			t.Errorf("SECURITY: row %d (%s) is not a plain `return f.<Field>`. An accessor that "+
				"consults more than its own fact can agree with every fixture this package builds "+
				"and still suppress its reason on a node in between — which is a missing "+
				"prerequisite silently dropped from Unmet",
				i, readinessChecks[i].reason)
		}
	}
}

// soleFactFieldRead returns the field name when the body is exactly `return f.<Field>`, else "".
func soleFactFieldRead(fn *ast.FuncLit) string {
	if fn.Body == nil || len(fn.Body.List) != 1 {
		return ""
	}
	ret, ok := fn.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return ""
	}
	sel, ok := ret.Results[0].(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	if id, ok := sel.X.(*ast.Ident); !ok || id.Name != "f" {
		return ""
	}
	return sel.Sel.Name
}
