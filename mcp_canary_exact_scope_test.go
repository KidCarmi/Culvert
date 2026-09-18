package main

import (
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// ---------------------------------------------------------------------------
// EXACT FIRST-CANARY SCOPE — ACTIVATION-PREFLIGHT ENFORCEMENT (blocker #5)
//
// canary.ValidateFirstCanaryScope decides the shape; these gates prove the
// decision is made in the ONE place that can stop a Canary from going live at
// all — the authoritative activation preflight — and not deferred to a runtime
// side-effect gate, which would only fire after a Canary had already activated.
//
// The PRIMARY closure proof is TestExactScope_WiderScopeCannotBeReadyEvenWithEverythingElseSatisfied:
// with EVERY other prerequisite true, a signed scope authorizing two principals,
// two tools, two servers or two tenants still yields Ready:false. The runtime
// denial check at the bottom is defense-in-depth and is deliberately NOT the
// closure argument.
// ---------------------------------------------------------------------------

// exactCanaryActivationInput is validCanaryActivationInput — whose scope is already the ONE
// exact reviewed experiment (one tenant, one server, one fully-pinned tool, one principal).
// Reusing it keeps the exact-scope gates anchored to the same fixture the rest of the
// activation preflight suite uses, so a drift in that fixture cannot make these gates vacuous.
func exactCanaryActivationInput(now time.Time) CanaryActivationInput {
	return validCanaryActivationInput(now)
}

// TestExactScope_CanonicalExperimentSatisfiesTheActivationRow is the anti-vacuity control at
// the preflight layer: the ONE reviewed experiment must SATISFY
// canary_scope_not_exact_first_canary. Without this every gate below would also pass an
// implementation that rejects every scope, which would make the first Canary unreachable
// rather than exact.
func TestExactScope_CanonicalExperimentSatisfiesTheActivationRow(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	in := exactCanaryActivationInput(now)
	if r := canary.ValidateFirstCanaryScope(in.Scope, in.ScopeRev); r != canary.FirstCanaryScopeOK {
		t.Fatalf("the activation fixture's scope must BE the one exact experiment, got %q", r)
	}
	rd := evaluateCanaryActivationPreflight(in)
	if canaryUnmetHas(rd, canary.ReasonScopeNotExactFirstCanary) {
		t.Fatalf("the exact experiment must satisfy %s, got unmet=%v", canary.ReasonScopeNotExactFirstCanary, rd.Unmet)
	}
	// It must remain not-ready for the shipped reasons (live tier unarmed) — the exact-scope
	// row is an ADDITIONAL prerequisite, never one that can make a Canary ready.
	if rd.Ready {
		t.Fatal("SECURITY: no activation input may make Canary ready while the live tier is unarmed")
	}
}

// widerThanReviewedScopes enumerates the ways a signed scope can authorize more than the one
// reviewed experiment. Each is the canonical fixture with exactly ONE widening applied, so a
// rejection is attributable to that widening alone.
func widerThanReviewedScopes(base rollout.ScopeSpec) []struct {
	name  string
	scope rollout.ScopeSpec
} {
	fp := base.Tools[0].Fingerprint
	srv := base.Servers[0]
	mk := func(f func(*rollout.ScopeSpec)) rollout.ScopeSpec {
		s := base
		s.Tenants = append([]string(nil), base.Tenants...)
		s.Servers = append([]string(nil), base.Servers...)
		s.Tools = append([]rollout.ToolSel(nil), base.Tools...)
		s.Principals = append([]string(nil), base.Principals...)
		s.Operations = append([]rollout.RiskClass(nil), base.Operations...)
		f(&s)
		return s
	}
	return []struct {
		name  string
		scope rollout.ScopeSpec
	}{
		{"two_principals", mk(func(s *rollout.ScopeSpec) { s.Principals = append(s.Principals, "synthetic-2") })},
		{"two_tools", mk(func(s *rollout.ScopeSpec) {
			s.Tools = append(s.Tools, rollout.ToolSel{Server: srv, Name: "echo2", Fingerprint: fp})
		})},
		{"two_servers", mk(func(s *rollout.ScopeSpec) { s.Servers = append(s.Servers, "srv-canary-2") })},
		{"two_tenants", mk(func(s *rollout.ScopeSpec) { s.Tenants = append(s.Tenants, "t2") })},
		{"principal_plus_client", mk(func(s *rollout.ScopeSpec) { s.Clients = []string{"c1"} })},
		{"principal_plus_agent", mk(func(s *rollout.ScopeSpec) { s.Agents = []string{"a1"} })},
		{"principal_plus_group", mk(func(s *rollout.ScopeSpec) { s.Groups = []string{"g1"} })},
		{"client_only_identity", mk(func(s *rollout.ScopeSpec) { s.Principals = nil; s.Clients = []string{"c1"} })},
		{"agent_only_identity", mk(func(s *rollout.ScopeSpec) { s.Principals = nil; s.Agents = []string{"a1"} })},
		{"group_only_identity", mk(func(s *rollout.ScopeSpec) { s.Principals = nil; s.Groups = []string{"g1"} })},
		{"no_principal", mk(func(s *rollout.ScopeSpec) { s.Principals = nil })},
		{"duplicate_principal", mk(func(s *rollout.ScopeSpec) { s.Principals = []string{s.Principals[0], s.Principals[0]} })},
		{"duplicate_tool", mk(func(s *rollout.ScopeSpec) { s.Tools = []rollout.ToolSel{s.Tools[0], s.Tools[0]} })},
		{"duplicate_server", mk(func(s *rollout.ScopeSpec) { s.Servers = []string{srv, srv} })},
		{"duplicate_tenant", mk(func(s *rollout.ScopeSpec) { s.Tenants = []string{s.Tenants[0], s.Tenants[0]} })},
		{"bare_fingerprint_dimension", mk(func(s *rollout.ScopeSpec) { s.ToolFingerprints = []string{fp} })},
		{"environment_dimension", mk(func(s *rollout.ScopeSpec) { s.Environments = []string{"prod"} })},
		{"percentage", mk(func(s *rollout.ScopeSpec) { s.Percent = 50; s.BucketSalt = "salt" })},
		{"wildcard_identifier", mk(func(s *rollout.ScopeSpec) { s.Principals = []string{"*"} })},
		{"exclusion_carve_out", mk(func(s *rollout.ScopeSpec) { s.ExcludePrincipals = []string{"nobody"} })},
	}
}

// TestExactScope_WiderScopeCannotBeReadyEvenWithEverythingElseSatisfied is the PRIMARY
// blocker-#5 closure proof (§10/§12). Every other Canary prerequisite — node and activation
// alike — is asserted TRUE, so nothing else can be the cause. A signed scope that authorizes
// more than the one reviewed experiment must STILL leave the verdict not-ready, with the
// exact-scope row as the sole unmet reason.
//
// This is what "the broader scope cannot activate at all" means mechanically: the readiness
// verdict is the gate every live-execution transition consults, so Ready:false here IS
// activation being impossible.
func TestExactScope_WiderScopeCannotBeReadyEvenWithEverythingElseSatisfied(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	in := exactCanaryActivationInput(now)

	// Every prerequisite satisfied. This is deliberately unreachable in the shipped build (the
	// live tier is never armed); it is constructed here precisely so the exact-scope row is the
	// ONLY thing that can hold the verdict back.
	allTrue := canary.Facts{
		CapabilityGateway: true, ShadowExitReviewPassed: true,
		ScopeBounded: true, ScopeReadFirst: true, ScopeExactFirstCanary: true,
		LiveExecutorComposed: true, UpstreamCallerPresent: true, CredentialPathReady: true,
		DurableEventsHealthy: true, ResponseInspectionReady: true, RegistryHealthy: true,
		CatalogHealthy: true, PolicyHealthy: true, EmergencyKillClear: true,
		KillBoundaryGuardPresent: true, ToolFreshnessGuardPresent: true,
		LiveApprovalValid: true, ServerUsable: true, ToolFingerprintCurrent: true,
		ToolCatalogUsable:   true,
		RollbackPathHealthy: true, RollbackCoordinatorRehearsed: true, BudgetConfigured: true,
	}
	// Positive control: with the EXACT scope and everything else true, the verdict IS ready.
	// Without this the test could not distinguish "the exact-scope gate blocked it" from
	// "something else always blocks it".
	if rd := evaluateActivationOnFacts(allTrue, in); !rd.Ready {
		t.Fatalf("positive control: the exact experiment with every prerequisite satisfied must be Ready, got unmet=%v", rd.Unmet)
	}

	for _, tc := range widerThanReviewedScopes(in.Scope) {
		t.Run(tc.name, func(t *testing.T) {
			wider := in
			wider.Scope = tc.scope
			rd := evaluateActivationOnFacts(allTrue, wider)
			if rd.Ready {
				t.Fatalf("SECURITY: a signed scope wider than the one reviewed experiment (%s) returned Ready:true — "+
					"the First Canary is not exact", tc.name)
			}
			if !canaryUnmetHas(rd, canary.ReasonScopeNotExactFirstCanary) {
				t.Fatalf("%s must be refused by %s (got unmet=%v) — it must fail for the EXACT-SCOPE reason, "+
					"not because another prerequisite happened to be false", tc.name, canary.ReasonScopeNotExactFirstCanary, rd.Unmet)
			}
		})
	}
}

// TestExactScope_IsNotSatisfiedByTheBoundedScopeRow proves the two scope rows are independent
// facts, not one fact spelled twice. A scope inside the Canary ARCHITECTURE's caps (two tools,
// two principals) satisfies canary_scope_not_bounded and must still fail the exact row — which
// is the whole reason blocker #5 existed: the machine gate was checking the wrong, wider
// question.
func TestExactScope_IsNotSatisfiedByTheBoundedScopeRow(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	base := exactCanaryActivationInput(now)
	for _, tc := range []struct {
		name  string
		apply func(*rollout.ScopeSpec)
	}{
		{"two_tools_within_architecture_cap", func(s *rollout.ScopeSpec) {
			s.Tools = append(append([]rollout.ToolSel(nil), s.Tools...),
				rollout.ToolSel{Server: s.Servers[0], Name: "echo2", Fingerprint: s.Tools[0].Fingerprint})
		}},
		{"two_principals_within_architecture_cap", func(s *rollout.ScopeSpec) {
			s.Principals = []string{s.Principals[0], "synthetic-2"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := exactCanaryActivationInput(now)
			scope := base.Scope
			scope.Tools = append([]rollout.ToolSel(nil), base.Scope.Tools...)
			scope.Principals = append([]string(nil), base.Scope.Principals...)
			tc.apply(&scope)
			in.Scope = scope
			// The BASE contract accepts it — that is the gap blocker #5 names.
			if r := canary.ValidateScope(scope, in.ScopeRev); r != canary.ScopeOK {
				t.Fatalf("precondition: the architecture's bounded-scope contract must ACCEPT %s (got %q) — "+
					"otherwise this test is not exercising the gap", tc.name, r)
			}
			rd := evaluateCanaryActivationPreflight(in)
			if canaryUnmetHas(rd, canary.ReasonScopeNotBounded) {
				t.Fatalf("precondition: %s must satisfy the bounded-scope row, got unmet=%v", tc.name, rd.Unmet)
			}
			if !canaryUnmetHas(rd, canary.ReasonScopeNotExactFirstCanary) {
				t.Fatalf("SECURITY: %s satisfies the bounded-scope row and must still fail the EXACT row; unmet=%v", tc.name, rd.Unmet)
			}
		})
	}
}

// TestExactScope_EnforcedInTheAuthoritativePreflightNotOnlyAtRuntime is the structural gate for
// §4. It pins three facts about WHERE the decision is made:
//
//  1. canary.ValidateFirstCanaryScope is called in the root package exactly once, inside
//     evaluateActivationOnFacts — the single shared body of the activation preflight.
//  2. Its argument is in.Scope — the SIGNED activation scope carried by CanaryActivationInput,
//     never a request-derived, telemetry-derived, or operator-convention value.
//  3. BOTH preflight entry points (the plain one used by the restart reconcile and the _Locked
//     one used by the serialized commit gate) route through that shared body, so neither caller
//     can reach a live mode without the exact-scope verdict.
//
// A timing-free structural gate is used deliberately: it fails identically on any machine,
// under -race, at any load, and it catches the mutation "evaluate the exact shape somewhere
// later" that a behavioural test on one caller would miss.
func TestExactScope_EnforcedInTheAuthoritativePreflightNotOnlyAtRuntime(t *testing.T) {
	fset := token.NewFileSet()
	calls, routesThrough := scanExactScopeEnforcement(t, fset)

	if len(calls) != 1 {
		t.Fatalf("canary.ValidateFirstCanaryScope must be called EXACTLY once in the root package "+
			"(the authoritative activation preflight), found %d: %+v", len(calls), calls)
	}
	c := calls[0]
	if c.fn != "evaluateActivationOnFacts" {
		t.Fatalf("the exact-scope verdict must be decided in evaluateActivationOnFacts (the shared activation "+
			"preflight body), found it in %s (%s). Deciding it anywhere else — a runtime side-effect gate, an "+
			"admin handler — means a wider Canary could already have gone live.", c.fn, c.file)
	}
	if c.arg != "in.Scope" {
		t.Fatalf("the exact-scope verdict must be taken on the SIGNED activation scope (in.Scope), got %q. "+
			"A request-derived, telemetry-derived or operator-narrowed scope is never proof of exactness: if the "+
			"signed scope could authorize two identities, the First Canary is not exact even if only one request arrives.", c.arg)
	}
	for _, entry := range []string{"evaluateCanaryActivationPreflight", "evaluateCanaryActivationPreflightLocked"} {
		if !routesThrough[entry] {
			t.Errorf("%s must route through evaluateActivationOnFacts, or its callers reach a live mode "+
				"without the exact-scope verdict", entry)
		}
	}
}

// TestExactScope_EveryActivationInputCarriesTheSignedScope closes the other half of §3. The wall
// above pins that the verdict is taken on in.Scope; this pins what in.Scope IS. Every
// CanaryActivationInput built in non-test root code must set Scope from the SIGNED rollout config —
// cfg.Scope on the serialized commit gate, restored.Scope on the restart reconcile — never from a
// request, a tool approval, a catalog observation, or anything narrowed by what was actually
// called. Without this, an implementation could satisfy the call-site wall perfectly while handing
// it a scope assembled from runtime telemetry.
func TestExactScope_EveryActivationInputCarriesTheSignedScope(t *testing.T) {
	// The signed-config expressions a Canary activation may be built from. Both name a
	// rollout.Config value: cfg is the config being committed, restored is the durable config being
	// reconciled at startup. Adding a spelling here is a deliberate act a reviewer sees.
	signed := map[string]bool{"cfg.Scope": true, "restored.Scope": true}

	fset := token.NewFileSet()
	dir := pkgSourceDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	found := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		for _, got := range activationInputScopeExprs(fset, f, &found) {
			if signed[got] {
				continue
			}
			t.Errorf("%s: CanaryActivationInput.Scope = %q — a Canary activation's scope must come "+
				"from the SIGNED rollout config (%v). A request-derived or observation-derived scope is "+
				"never proof of exactness: if the signed scope could authorize two identities, the First "+
				"Canary is not exact however few requests arrive.", name, got, signedSpellings(signed))
		}
	}
	if found == 0 {
		t.Fatal("no CanaryActivationInput literal found in non-test root code — this wall proves nothing; " +
			"the activation path moved and the gate must follow it")
	}
}

// activationInputScopeExprs returns the source spelling of the Scope field of every
// CanaryActivationInput composite literal in f, incrementing *found once per literal (including
// one that omits Scope, so an omitted field cannot make the wall look satisfied).
func activationInputScopeExprs(fset *token.FileSet, f *ast.File, found *int) []string {
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		cl, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		id, ok := cl.Type.(*ast.Ident)
		if !ok || id.Name != "CanaryActivationInput" {
			return true
		}
		*found++
		for _, elt := range cl.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Scope" {
				out = append(out, exprText(fset, kv.Value))
			}
		}
		return true
	})
	return out
}

func signedSpellings(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// exactScopeCall is one observed canary.ValidateFirstCanaryScope call site.
type exactScopeCall struct{ file, fn, arg string }

// scanExactScopeEnforcement walks every non-test root source file and returns the
// canary.ValidateFirstCanaryScope call sites plus the set of activation-preflight entry points
// that route through the shared evaluateActivationOnFacts body.
func scanExactScopeEnforcement(t *testing.T, fset *token.FileSet) (calls []exactScopeCall, routesThrough map[string]bool) {
	t.Helper()
	// Anchored to pkgSourceDir(), never the CWD: a concurrent os.Chdir in another test would
	// otherwise make this wall read the wrong directory and pass vacuously (static_read_wall_test.go).
	dir := pkgSourceDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	routesThrough = map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			calls = append(calls, exactScopeCallsIn(fset, name, fd)...)
			if isActivationPreflightEntry(fd.Name.Name) && callsIdent(fd.Body, "evaluateActivationOnFacts") {
				routesThrough[fd.Name.Name] = true
			}
		}
	}
	return calls, routesThrough
}

// exactScopeCallsIn returns the canary.ValidateFirstCanaryScope call sites inside fd, recording the
// spelling of the first argument so the wall can assert it is the SIGNED scope.
func exactScopeCallsIn(fset *token.FileSet, file string, fd *ast.FuncDecl) []exactScopeCall {
	var out []exactScopeCall
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		ce, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := ce.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "canary" || sel.Sel.Name != "ValidateFirstCanaryScope" {
			return true
		}
		arg := "<none>"
		if len(ce.Args) > 0 {
			arg = exprText(fset, ce.Args[0])
		}
		out = append(out, exactScopeCall{file: file, fn: fd.Name.Name, arg: arg})
		return true
	})
	return out
}

func isActivationPreflightEntry(name string) bool {
	return name == "evaluateCanaryActivationPreflight" || name == "evaluateCanaryActivationPreflightLocked"
}

// callsIdent reports whether body contains a direct call to the named package-level function.
func callsIdent(body *ast.BlockStmt, name string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		ce, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := ce.Fun.(*ast.Ident); ok && id.Name == name {
			found = true
		}
		return true
	})
	return found
}

// exprText renders an expression back to source so the wall can assert the exact argument
// spelling (in.Scope) rather than merely that "some argument" was passed.
func exprText(fset *token.FileSet, e ast.Expr) string {
	var sb strings.Builder
	if err := printer.Fprint(&sb, fset, e); err != nil {
		return "<unprintable>"
	}
	return sb.String()
}

// TestExactScope_ReadinessRowIsActivationLevelAndFailClosed pins that the new prerequisite is
// wired like every other activation fact: fail-closed by default (a node fact table never
// asserts it), invisible to the scope-independent node dry run, and reported by the full
// verdict.
func TestExactScope_ReadinessRowIsActivationLevelAndFailClosed(t *testing.T) {
	// The node fact table must NEVER assert the exact-scope fact: it is meaningful only once a
	// signed scope exists, and a node-level true would let a scopeless node advertise exactness.
	nf := canaryNodeFacts(rollout.CapabilityGateway)
	if nf.ScopeExactFirstCanary {
		t.Fatal("SECURITY: the node fact table must never assert ScopeExactFirstCanary — there is no scope to judge")
	}
	// The node dry run must not report it (it is not a node deficiency).
	node := evaluateCanaryNodeReadiness(rollout.CapabilityGateway)
	for _, r := range node.Unmet {
		if r == canary.ReasonScopeNotExactFirstCanary {
			t.Fatal("the scope-independent node dry run must not report the exact-scope row")
		}
	}
	// The full verdict on an empty activation input must report it.
	full := evaluateCanaryActivationPreflight(CanaryActivationInput{Capability: rollout.CapabilityGateway})
	if full.Ready {
		t.Fatal("an empty activation input must never be ready")
	}
	if !canaryUnmetHas(full, canary.ReasonScopeNotExactFirstCanary) {
		t.Fatalf("an empty (zero) scope must fail the exact-scope row, got unmet=%v", full.Unmet)
	}
	// And the reason is part of the advertised vocabulary.
	found := false
	for _, r := range canary.AllReasons() {
		if r == canary.ReasonScopeNotExactFirstCanary {
			found = true
		}
	}
	if !found {
		t.Fatal("canary.AllReasons must advertise the exact-scope row so an operator sees the prerequisite")
	}
}

// TestExactScope_StatusSurfaceAdvertisesTheExactShape proves the contract is observable without
// SSH: the read-only Canary status carries the exact shape separately from the architecture's
// bounds, so an operator can see that a scope inside the bounds may still be far wider than the
// one reviewed experiment.
func TestExactScope_StatusSurfaceAdvertisesTheExactShape(t *testing.T) {
	st := mcpCanaryStatus()
	exact, ok := st["first_canary_exact_scope"].(map[string]any)
	if !ok {
		t.Fatal("mcpCanaryStatus must advertise first_canary_exact_scope")
	}
	for _, k := range []string{"tenants", "servers", "tools", "principals"} {
		if v, _ := exact[k].(int); v != 1 {
			t.Errorf("first_canary_exact_scope[%q] = %v, want 1", k, exact[k])
		}
	}
	for _, k := range []string{"clients", "agents", "groups", "environments", "bare_tool_fingerprints", "exclusions", "percent"} {
		if v, _ := exact[k].(int); v != 0 {
			t.Errorf("first_canary_exact_scope[%q] = %v, want 0", k, exact[k])
		}
	}
	if v, _ := exact["identity_counted_by"].(string); v != "principals_only" {
		t.Errorf("identity_counted_by = %v, want principals_only (an aggregate across identity classes is the hazard)", exact["identity_counted_by"])
	}
	if v, _ := exact["validated_from"].(string); v != "signed_activation_scope" {
		t.Errorf("validated_from = %v, want signed_activation_scope", exact["validated_from"])
	}
	if v, _ := exact["unmet_readiness_reason"].(string); v != string(canary.ReasonScopeNotExactFirstCanary) {
		t.Errorf("unmet_readiness_reason = %v, want %v", exact["unmet_readiness_reason"], canary.ReasonScopeNotExactFirstCanary)
	}
	reasons, _ := exact["rejection_reasons"].([]string)
	if len(reasons) != len(canary.AllFirstCanaryScopeReasons()) {
		t.Errorf("rejection_reasons must advertise the full exact-scope vocabulary (%d), got %d",
			len(canary.AllFirstCanaryScopeReasons()), len(reasons))
	}
	// The architecture's bounds must still be surfaced SEPARATELY and must NOT have been
	// silently redefined to 1 — that would be the forbidden global tightening (§1).
	bounds, ok := st["first_canary_bounds"].(map[string]any)
	if !ok {
		t.Fatal("first_canary_bounds must remain a separate view of the architecture caps")
	}
	if v, _ := bounds["max_tools"].(int); v < 2 {
		t.Errorf("first_canary_bounds[max_tools] = %v: exactness must not be implemented by redefining the architecture cap", bounds["max_tools"])
	}
}

// TestExactScope_RuntimeStillDeniesOutOfScopeIdentities is the DEFENSE-IN-DEPTH check (§10),
// explicitly NOT the blocker-closure proof. Once the one exact scope is what activated, a
// request naming a different principal, server or tool is still rejected by the runtime scope
// matcher. The closure argument remains that a broader scope cannot activate at all.
func TestExactScope_RuntimeStillDeniesOutOfScopeIdentities(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	spec := exactCanaryActivationInput(now).Scope
	sc, err := rollout.Compile(spec, 1, rollout.DefaultLimits())
	if err != nil {
		t.Fatalf("compile the exact scope: %v", err)
	}
	inScope := rollout.Subject{
		Capability: rollout.CapabilityGateway,
		Tenant:     spec.Tenants[0], ServerID: spec.Servers[0],
		ToolName: spec.Tools[0].Name, ToolFingerprint: spec.Tools[0].Fingerprint,
		PrincipalID: spec.Principals[0], Operation: rollout.RiskRead,
	}
	if !sc.Contains(inScope) {
		t.Fatal("positive control: the one reviewed subject must be in scope, else the denials below prove nothing")
	}
	for _, tc := range []struct {
		name string
		mut  func(*rollout.Subject)
	}{
		{"other_principal_P2", func(s *rollout.Subject) { s.PrincipalID = "synthetic-2" }},
		{"other_server_S2", func(s *rollout.Subject) { s.ServerID = "srv-canary-2" }},
		{"other_tool_Tool2", func(s *rollout.Subject) { s.ToolName = "echo2" }},
		{"other_tenant_T2", func(s *rollout.Subject) { s.Tenant = "t2" }},
		{"other_fingerprint", func(s *rollout.Subject) { s.ToolFingerprint = "deadbeef" }},
		{"empty_principal", func(s *rollout.Subject) { s.PrincipalID = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			subj := inScope
			tc.mut(&subj)
			if sc.Contains(subj) {
				t.Fatalf("runtime defense-in-depth: %s must NOT be admitted by the one exact scope", tc.name)
			}
		})
	}
}

// TestExactScope_EmptyDimensionsLeaveAttributesUnconstrainedButPinTheIdentity pins the one place
// the exact shape deliberately does not narrow, so it reads as a decision rather than an oversight.
// An EMPTY inclusion dimension matches anything in rollout's matcher, so the reviewed scope admits
// principal P1 arriving through ANY client, agent or group. That does not widen the identity axis:
// every admitted request must still carry PrincipalID == P1, which is exactly what "one named
// principal" bounds. Requiring "exactly one client" instead is the aggregate-counting error the
// exact gate exists to prevent — it would treat a client as an identity peer of a principal.
func TestExactScope_EmptyDimensionsLeaveAttributesUnconstrainedButPinTheIdentity(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	spec := exactCanaryActivationInput(now).Scope
	if len(spec.Clients) != 0 || len(spec.Agents) != 0 || len(spec.Groups) != 0 {
		t.Fatal("precondition: the exact shape leaves the non-principal identity dimensions empty")
	}
	sc, err := rollout.Compile(spec, 1, rollout.DefaultLimits())
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	base := rollout.Subject{
		Capability: rollout.CapabilityGateway,
		Tenant:     spec.Tenants[0], ServerID: spec.Servers[0],
		ToolName: spec.Tools[0].Name, ToolFingerprint: spec.Tools[0].Fingerprint,
		PrincipalID: spec.Principals[0], Operation: rollout.RiskRead,
	}
	// Any client/agent/group is admitted — the attributes are unconstrained.
	for _, mut := range []func(*rollout.Subject){
		func(s *rollout.Subject) { s.ClientID = "any-client" },
		func(s *rollout.Subject) { s.AgentID = "any-agent" },
		func(s *rollout.Subject) { s.Groups = []string{"any-group"} },
	} {
		subj := base
		mut(&subj)
		if !sc.Contains(subj) {
			t.Fatal("an empty non-principal dimension must match anything — if this changes, the exact " +
				"shape's meaning changed and the header note must be rewritten")
		}
	}
	// But the PRINCIPAL is pinned: changing it alone is refused no matter what the other
	// attributes say. That is the bound "one named principal" actually provides.
	for _, mut := range []func(*rollout.Subject){
		func(s *rollout.Subject) { s.PrincipalID = "someone-else" },
		func(s *rollout.Subject) { s.PrincipalID = "someone-else"; s.ClientID = "any-client" },
		func(s *rollout.Subject) { s.PrincipalID = "someone-else"; s.Groups = []string{"any-group"} },
	} {
		subj := base
		mut(&subj)
		if sc.Contains(subj) {
			t.Fatal("SECURITY: a principal other than the one reviewed must never be admitted, whatever " +
				"client, agent or group the request carries")
		}
	}
}
