package main

// SEC-DIAG-ROSTER-1 governance walls, AST-based.
//
// The operator contract (GET /api/diagnostics, GET /api/health/explain) is
// viewer-readable, but some of its rows are derived from admin-only roster
// state. Two things must therefore hold, and each is checked here from the
// PRIMITIVE rather than from the file that happened to be edited (CHAOS-70's
// recorded lesson):
//
//  1. Every serialization of an OperatorContract onto a response goes
//     through writeOperatorContract, the one helper that role-redacts. A
//     textual "the handler mentions redactContractForRole" check is not
//     enough (Codex P2, PR #1601): a renderer could compute the redacted
//     value and send the full one.
//  2. Every function REACHABLE from buildOperatorContract that reads a roster
//     primitive is classified — in any root-package production file, not just
//     diagnostics.go (Codex P2, PR #1601: the repo's *_health.go pattern would
//     otherwise be invisible).
//
// Both analyses are pure functions over a set of parsed sources, so the
// negative controls below can inject a fixture or a mutated handler in memory
// and prove the wall fails, without touching the tree.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// contractSources is the root package's production source, by file name.
type contractSources map[string][]byte

func loadContractSources(t *testing.T) contractSources {
	t.Helper()
	root := pkgSourceDir()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	srcs := contractSources{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(root, name)) // #nosec G304 -- in-repo package source
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		srcs[name] = b
	}
	return srcs
}

// clone returns a copy that a negative control may mutate freely.
func (s contractSources) clone() contractSources {
	out := make(contractSources, len(s))
	for k, v := range s {
		out[k] = v
	}
	return out
}

// replaceOnce rewrites file's source, failing the test unless old occurs once.
func (s contractSources) replaceOnce(t *testing.T, file, old, repl string) {
	t.Helper()
	src := string(s[file])
	if n := strings.Count(src, old); n != 1 {
		t.Fatalf("fixture: %q occurs %d times in %s, want exactly 1", old, n, file)
	}
	s[file] = []byte(strings.Replace(src, old, repl, 1))
}

// contractFunc is one top-level function or method declaration.
type contractFunc struct {
	File string
	Key  string // "name" for a function, "Recv.name" for a method
	Decl *ast.FuncDecl
}

type contractIndex struct {
	funcs   []*contractFunc
	byName  map[string][]*contractFunc // top-level functions by name
	methods map[string][]*contractFunc // methods by method name
}

func parseContractSources(t *testing.T, srcs contractSources) *contractIndex {
	t.Helper()
	fset := token.NewFileSet()
	idx := &contractIndex{byName: map[string][]*contractFunc{}, methods: map[string][]*contractFunc{}}
	names := make([]string, 0, len(srcs))
	for n := range srcs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		f, err := parser.ParseFile(fset, name, srcs[name], parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			cf := &contractFunc{File: name, Key: fd.Name.Name, Decl: fd}
			if fd.Recv != nil && len(fd.Recv.List) == 1 {
				cf.Key = contractRecvTypeName(fd.Recv.List[0].Type) + "." + fd.Name.Name
				idx.methods[fd.Name.Name] = append(idx.methods[fd.Name.Name], cf)
			} else {
				idx.byName[fd.Name.Name] = append(idx.byName[fd.Name.Name], cf)
			}
			idx.funcs = append(idx.funcs, cf)
		}
	}
	return idx
}

func contractRecvTypeName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.StarExpr:
		return contractRecvTypeName(x.X)
	case *ast.Ident:
		return x.Name
	case *ast.IndexExpr:
		return contractRecvTypeName(x.X)
	}
	return "?"
}

func isCallTo(e ast.Expr, name string) (*ast.CallExpr, bool) {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return nil, false
	}
	id, ok := call.Fun.(*ast.Ident)
	return call, ok && id.Name == name
}

// ─── wall 1: the only serializer ─────────────────────────────────────────────

const operatorContractWriter = "writeOperatorContract"

// contractRenderExceptions are functions that obtain an OperatorContract
// without writeOperatorContract, with the reason.
var contractRenderExceptions = map[string]string{
	// The support-bundle collector is a different trust boundary, not the live
	// viewer-facing API: it writes through in.Redactor.Classify under the
	// struct's redact:"internal" tags and a declared MaxClass of ClassInternal,
	// and a bundle is admin-created, admin-approved and capture-level gated
	// before anyone can download it. If that lifecycle ever widens to a lower
	// role, this exception is wrong.
	"diagnosticsCollector.Collect": "support-bundle redactor + admin-approved lifecycle",
}

// contractRenderViolations reports every way production code could put an
// OperatorContract on a response other than through writeOperatorContract.
func contractRenderViolations(idx *contractIndex) (violations []string, writerCalls int) {
	// The writer itself is NOT exempt: its whole body is validated by
	// writerViolations, so a second write, a conditional write, or any other
	// use of the unredacted value inside it fails the wall (Codex P2, #1545).
	writerSeen := false
	for _, fn := range idx.funcs {
		if fn.Key == operatorContractWriter {
			writerSeen = true
			violations = append(violations, writerViolations(fn)...)
			continue
		}
		if _, ok := contractRenderExceptions[fn.Key]; ok {
			continue
		}
		v, n := contractRenderViolationsIn(fn)
		violations = append(violations, v...)
		writerCalls += n
	}
	if !writerSeen {
		violations = append(violations, operatorContractWriter+": missing")
	}
	return violations, writerCalls
}

// writerViolations validates writeOperatorContract's COMPLETE body:
//   - exactly one write to the response of any kind (jsonOK, json.Marshal /
//     MarshalIndent, any .Encode / .Write / .WriteString, fmt.Fprint*);
//   - that write is an unconditional top-level statement of the form
//     jsonOK(w, redactContractForRole(full, <role>.HasRole(RoleAdmin)));
//   - the contract parameter is referenced exactly once — as that call's
//     first argument — so the unredacted value cannot be used anywhere else.
func writerViolations(fn *contractFunc) []string {
	where := fn.File + ": " + operatorContractWriter
	var out []string
	if writes := responseWritesIn(fn.Decl.Body); len(writes) != 1 {
		out = append(out, fmt.Sprintf("%s performs %d response writes, want exactly 1", where, len(writes)))
	}
	param := contractParamName(fn.Decl)
	if param == "" {
		return append(out, where+" has no OperatorContract parameter")
	}
	if !hasTopLevelRedactedWrite(fn.Decl.Body, param) {
		out = append(out, where+" does not unconditionally serialize "+
			"jsonOK(w, redactContractForRole("+param+", <role>.HasRole(RoleAdmin)))")
	}
	if n := identUses(fn.Decl.Body, param); n != 1 {
		out = append(out, fmt.Sprintf("%s references the unredacted %q %d times, want exactly 1 "+
			"(as redactContractForRole's argument)", where, param, n))
	}
	return out
}

// responseWritesIn collects every call in body that writes a response or
// serializes a value.
func responseWritesIn(body *ast.BlockStmt) []*ast.CallExpr {
	var writes []*ast.CallExpr
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && (isSerializerCall(call) || isRawWriteCall(call)) {
			writes = append(writes, call)
		}
		return true
	})
	return writes
}

// isRawWriteCall matches .Write / .WriteString on anything and fmt.Fprint*.
func isRawWriteCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	switch sel.Sel.Name {
	case "Write", "WriteString":
		return true
	case "Fprint", "Fprintf", "Fprintln":
		pkg, ok := sel.X.(*ast.Ident)
		return ok && pkg.Name == "fmt"
	}
	return false
}

// hasTopLevelRedactedWrite reports whether body has, as a direct statement,
// jsonOK(w, redactContractForRole(param, <x>.HasRole(RoleAdmin))).
func hasTopLevelRedactedWrite(body *ast.BlockStmt, param string) bool {
	for _, st := range body.List {
		es, ok := st.(*ast.ExprStmt)
		if !ok {
			continue
		}
		if call, ok := isCallTo(es.X, "jsonOK"); ok && len(call.Args) == 2 && isAdminGatedRedaction(call.Args[1], param) {
			return true
		}
	}
	return false
}

func isAdminGatedRedaction(e ast.Expr, param string) bool {
	red, ok := isCallTo(e, "redactContractForRole")
	if !ok || len(red.Args) != 2 {
		return false
	}
	if id, ok := red.Args[0].(*ast.Ident); !ok || id.Name != param {
		return false
	}
	gate, ok := red.Args[1].(*ast.CallExpr)
	if !ok || len(gate.Args) != 1 {
		return false
	}
	sel, ok := gate.Fun.(*ast.SelectorExpr)
	arg, ok2 := gate.Args[0].(*ast.Ident)
	return ok && ok2 && sel.Sel.Name == "HasRole" && arg.Name == "RoleAdmin"
}

// contractParamName is the name of fd's OperatorContract parameter, or "".
func contractParamName(fd *ast.FuncDecl) string {
	if fd.Type.Params == nil {
		return ""
	}
	for _, p := range fd.Type.Params.List {
		if isOperatorContractType(p.Type) && len(p.Names) == 1 {
			return p.Names[0].Name
		}
	}
	return ""
}

// identUses counts references to name in body.
func identUses(body *ast.BlockStmt, name string) int {
	n := 0
	ast.Inspect(body, func(node ast.Node) bool {
		if id, ok := node.(*ast.Ident); ok && id.Name == name {
			n++
		}
		return true
	})
	return n
}

func contractRenderViolationsIn(fn *contractFunc) (violations []string, writerCalls int) {
	typed := contractTypedIdents(fn.Decl)
	where := fn.File + ": " + fn.Key
	// Arguments of writeOperatorContract calls are the one place a
	// buildOperatorContract() call may appear.
	allowedBuild := map[*ast.CallExpr]bool{}
	ast.Inspect(fn.Decl.Body, func(n ast.Node) bool {
		if call, ok := isCallTo(asExpr(n), operatorContractWriter); ok {
			writerCalls++
			for _, a := range call.Args {
				if b, ok := isCallTo(a, "buildOperatorContract"); ok {
					allowedBuild[b] = true
				}
			}
		}
		return true
	})
	ast.Inspect(fn.Decl.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if _, ok := isCallTo(call, "buildOperatorContract"); ok && !allowedBuild[call] {
			violations = append(violations, where+" obtains buildOperatorContract() other than as a direct "+
				"argument of "+operatorContractWriter)
		}
		if _, ok := isCallTo(call, "redactContractForRole"); ok {
			violations = append(violations, where+" calls redactContractForRole directly; only "+
				operatorContractWriter+" may redact, so the redacted value is the one serialized")
		}
		if isSerializerCall(call) {
			for _, a := range call.Args {
				if isContractValued(a, typed) {
					violations = append(violations, where+" serializes an OperatorContract outside "+
						operatorContractWriter)
				}
			}
		}
		return true
	})
	return violations, writerCalls
}

func asExpr(n ast.Node) ast.Expr {
	e, _ := n.(ast.Expr)
	return e
}

// isSerializerCall matches jsonOK(...), json.Marshal/MarshalIndent(...) and
// any .Encode(...) (a json.Encoder, however it was obtained).
func isSerializerCall(call *ast.CallExpr) bool {
	switch f := call.Fun.(type) {
	case *ast.Ident:
		return f.Name == "jsonOK"
	case *ast.SelectorExpr:
		switch f.Sel.Name {
		case "Encode":
			return true
		case "Marshal", "MarshalIndent":
			pkg, ok := f.X.(*ast.Ident)
			return ok && pkg.Name == "json"
		}
	}
	return false
}

// isContractValued reports whether e evaluates to an OperatorContract: a
// producer call, a composite literal, or an identifier declared as one.
func isContractValued(e ast.Expr, typed map[string]bool) bool {
	switch x := e.(type) {
	case *ast.ParenExpr:
		return isContractValued(x.X, typed)
	case *ast.UnaryExpr:
		return isContractValued(x.X, typed)
	case *ast.StarExpr:
		return isContractValued(x.X, typed)
	case *ast.Ident:
		return typed[x.Name]
	case *ast.CompositeLit:
		id, ok := x.Type.(*ast.Ident)
		return ok && id.Name == "OperatorContract"
	case *ast.CallExpr:
		_, b := isCallTo(x, "buildOperatorContract")
		_, r := isCallTo(x, "redactContractForRole")
		return b || r
	}
	return false
}

// contractTypedIdents collects the names declared in fd as an OperatorContract:
// parameters of that type, `var` specs, and `:=`/`=` assignments from a
// contract-valued expression.
func contractTypedIdents(fd *ast.FuncDecl) map[string]bool {
	typed := map[string]bool{}
	markContractParams(fd.Type.Params, typed)
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.ValueSpec:
			markContractValueSpec(x, typed)
		case *ast.AssignStmt:
			markContractAssign(x, typed)
		}
		return true
	})
	return typed
}

// isOperatorContractType matches OperatorContract and *OperatorContract.
func isOperatorContractType(e ast.Expr) bool {
	if s, ok := e.(*ast.StarExpr); ok {
		e = s.X
	}
	id, ok := e.(*ast.Ident)
	return ok && id.Name == "OperatorContract"
}

func markContractParams(params *ast.FieldList, typed map[string]bool) {
	if params == nil {
		return
	}
	for _, p := range params.List {
		if !isOperatorContractType(p.Type) {
			continue
		}
		for _, n := range p.Names {
			typed[n.Name] = true
		}
	}
}

func markContractValueSpec(spec *ast.ValueSpec, typed map[string]bool) {
	declared := spec.Type != nil && isOperatorContractType(spec.Type)
	for i, name := range spec.Names {
		if declared || (i < len(spec.Values) && isContractValued(spec.Values[i], typed)) {
			typed[name.Name] = true
		}
	}
}

func markContractAssign(as *ast.AssignStmt, typed map[string]bool) {
	for i, lhs := range as.Lhs {
		id, ok := lhs.(*ast.Ident)
		if ok && i < len(as.Rhs) && isContractValued(as.Rhs[i], typed) {
			typed[id.Name] = true
		}
	}
}

// TestWall_EveryOperatorContractRendererIsClassified: writeOperatorContract
// is the only serializer, structurally. Replaces the textual wall that
// checked only that a handler MENTIONED redactContractForRole.
func TestWall_EveryOperatorContractRendererIsClassified(t *testing.T) {
	violations, writerCalls := contractRenderViolations(parseContractSources(t, loadContractSources(t)))
	for _, v := range violations {
		t.Error(v)
	}
	// Not vacuous: both known viewer-facing renderers route through the
	// helper. Deleting or renaming one drops the count and fails here.
	if writerCalls < 2 {
		t.Errorf("found %d %s call(s), want at least 2 (apiDiagnostics + apiHealthExplain)",
			writerCalls, operatorContractWriter)
	}
}

// TestWall_OperatorContractRenderer_NegativeControls proves the wall fails on
// the shapes it exists to stop, using in-memory mutations of the real tree.
func TestWall_OperatorContractRenderer_NegativeControls(t *testing.T) {
	base := loadContractSources(t)

	// (a) Codex's P2 shape: redact, then send the FULL value.
	bypass := base.clone()
	bypass.replaceOnce(t, "ui_support.go", "writeOperatorContract(w, r, buildOperatorContract())",
		"full := buildOperatorContract()\n\t_ = redactContractForRole(full, uiRole(r).HasRole(RoleAdmin))\n\tjsonOK(w, full)")
	if v, _ := contractRenderViolations(parseContractSources(t, bypass)); len(v) == 0 {
		t.Error("a handler that redacts and then serializes the full contract passed the wall")
	}

	// (b) A new renderer in an unrelated file using a json.Encoder.
	extra := base.clone()
	extra["zz_fixture_contract_leak.go"] = []byte("package main\n\nimport (\n\t\"encoding/json\"\n\t\"net/http\"\n)\n\n" +
		"func apiFixtureContractLeak(w http.ResponseWriter, _ *http.Request) {\n" +
		"\tc := buildOperatorContract()\n\t_ = json.NewEncoder(w).Encode(c)\n}\n")
	if v, _ := contractRenderViolations(parseContractSources(t, extra)); len(v) == 0 {
		t.Error("a new renderer encoding buildOperatorContract() directly passed the wall")
	}

	// (c) The helper itself loses its admin gate.
	widened := base.clone()
	widened.replaceOnce(t, "diagnostics.go", "jsonOK(w, redactContractForRole(full, uiRole(r).HasRole(RoleAdmin)))",
		"jsonOK(w, redactContractForRole(full, uiRole(r).HasRole(RoleViewer)))")
	if v, _ := contractRenderViolations(parseContractSources(t, widened)); len(v) == 0 {
		t.Error("a writeOperatorContract gated on RoleViewer passed the wall")
	}

	// (d)–(f) The writer's body is validated in full, not just searched for
	// one compliant call (Codex P2, PR #1545).
	const redacted = "jsonOK(w, redactContractForRole(full, uiRole(r).HasRole(RoleAdmin)))"
	for name, repl := range map[string]string{
		"extra write of full after the redacted write": redacted + "\n\tjsonOK(w, full)",
		"conditional write of full":                    "if r.URL.Query().Get(\"raw\") != \"\" {\n\t\tjsonOK(w, full)\n\t}\n\t" + redacted,
		"writes full directly":                         "jsonOK(w, full)",
		"raw write of a marshalled full":               redacted + "\n\tb, _ := json.Marshal(full)\n\t_, _ = w.Write(b)",
	} {
		mutated := base.clone()
		mutated.replaceOnce(t, "diagnostics.go", redacted, repl)
		if v, _ := contractRenderViolations(parseContractSources(t, mutated)); len(v) == 0 {
			t.Errorf("writer mutation %q passed the wall", name)
		}
	}
}

// ─── wall 2: roster-derived rows anywhere in the package ─────────────────────

// rosterAccessorMethods are the Config reads whose result is admin-only roster
// state. rosterCounterVars are the CHAOS-70 durability counters
// (roster_persist_durability.go): refused admin changes, degraded login-path
// writes (a consumed backup code or TOTP replay counter that may not survive
// a restart) and non-durable mutations are admin-only under the PR #1545
// policy table.
var (
	rosterAccessorMethods = []string{"ListUIUsers", "UserHasTOTP", "GetUser", "hasLocalAdministrator", "rosterPersistTarget"}
	rosterCounterVars     = []string{"rosterPersistRefused", "rosterPersistBestEffort", "rosterNotDurable"}
)

// rosterRowExceptions are the reachable functions allowed to read a roster
// primitive, with the reason. Anything else reachable from
// buildOperatorContract that reads one fails the wall.
var rosterRowExceptions = map[string]string{
	"checkOversizeConfiguredUsernames": "the admin_username_length row; redacted in redactContractForRole",
	"collectAdminUsernames":            "feeds admin_username_length; redacted in redactContractForRole",
	"hasCredentialCapableProvider": "reads cfg.GetUser() only as a BOOLEAN existence probe; renders no " +
		"name, role, count or second-factor posture",
	"readRosterDurabilityFacts": "the CHAOS-70 counters, local-admin probe and roster-target load outcome behind admin_roster_durability; " +
		"redactContractForRole replaces that row with rosterDurabilityFacts.viewerRow below admin " +
		"(gated by diagnostics_roster_durability_test.go)",
}

// contractReachable returns every function reachable from
// buildOperatorContract. Over-approximates on purpose: a referenced
// identifier naming a top-level function, and a selector naming any method
// declared in the package, are both treated as edges, so a check passed by
// value or called through any receiver is still followed.
func contractReachable(idx *contractIndex) map[*contractFunc]bool {
	seen := map[*contractFunc]bool{}
	queue := append([]*contractFunc(nil), idx.byName["buildOperatorContract"]...)
	for len(queue) > 0 {
		fn := queue[0]
		queue = queue[1:]
		if seen[fn] {
			continue
		}
		seen[fn] = true
		ast.Inspect(fn.Decl.Body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				queue = append(queue, idx.methods[x.Sel.Name]...)
			case *ast.Ident:
				queue = append(queue, idx.byName[x.Name]...)
			}
			return true
		})
	}
	return seen
}

// rosterPrimitiveIn returns the first roster primitive fn reads, or "".
func rosterPrimitiveIn(fn *contractFunc) string {
	found := ""
	ast.Inspect(fn.Decl.Body, func(n ast.Node) bool {
		if found != "" {
			return false
		}
		switch x := n.(type) {
		case *ast.CallExpr:
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
				for _, m := range rosterAccessorMethods {
					if sel.Sel.Name == m {
						found = m + "()"
					}
				}
			}
		case *ast.Ident:
			for _, v := range rosterCounterVars {
				if x.Name == v {
					found = v
				}
			}
		}
		return true
	})
	return found
}

// rosterRowViolations reports reachable, unclassified roster readers, plus
// how many classified ones were seen (for the not-vacuous check).
func rosterRowViolations(idx *contractIndex) (violations []string, classifiedSeen int) {
	for fn := range contractReachable(idx) {
		prim := rosterPrimitiveIn(fn)
		if prim == "" {
			continue
		}
		if _, ok := rosterRowExceptions[fn.Key]; ok {
			classifiedSeen++
			continue
		}
		violations = append(violations, fn.File+": "+fn.Key+" reads "+prim+" and is reachable from "+
			"buildOperatorContract, so its row rides the viewer-readable operator contract. Redact it in "+
			"redactContractForRole (with a gate beside TestApiDiagnostics_UsernameRowDetailIsAdminOnly) and "+
			"classify it in rosterRowExceptions, or record there why its detail is safe below admin")
	}
	sort.Strings(violations)
	return violations, classifiedSeen
}

// TestWall_RosterDerivedDiagnosticsAreEnumerated scans EVERY root-package
// production file, classifying only roster reads that can contribute a row
// to the operator contract.
func TestWall_RosterDerivedDiagnosticsAreEnumerated(t *testing.T) {
	idx := parseContractSources(t, loadContractSources(t))
	violations, classifiedSeen := rosterRowViolations(idx)
	for _, v := range violations {
		t.Error(v)
	}
	if classifiedSeen == 0 {
		t.Fatal("not-vacuous check: no classified roster reader is reachable from buildOperatorContract — " +
			"the primitive names or the reachability walk changed and this wall is scanning for nothing")
	}
	// Precision control: the admin-only users API reads the roster but is not
	// part of the contract, so it must not be reachable.
	for fn := range contractReachable(idx) {
		if fn.Key == "apiAuthUsers" {
			t.Error("apiAuthUsers is reachable from buildOperatorContract; the walk is no longer meaningful")
		}
	}
}

// TestWall_RosterDerivedDiagnostics_NegativeControl puts a roster-derived row
// in a NEW *_health.go file and wires it into buildOperatorContract, in
// memory. The old diagnostics.go-only wall could not see this.
func TestWall_RosterDerivedDiagnostics_NegativeControl(t *testing.T) {
	srcs := loadContractSources(t).clone()
	srcs["zz_fixture_roster_health.go"] = []byte("package main\n\nimport \"fmt\"\n\n" +
		"func checkFixtureRosterHealth() OperatorContractCheck {\n" +
		"\treturn OperatorContractCheck{Code: \"fixture_roster\", Status: diagWarn,\n" +
		"\t\tMessage: fmt.Sprintf(\"%d admin accounts\", len(cfg.ListUIUsers()))}\n}\n")
	srcs.replaceOnce(t, "diagnostics.go", "\t\tcheckStorage(),\n", "\t\tcheckStorage(),\n\t\tcheckFixtureRosterHealth(),\n")

	violations, _ := rosterRowViolations(parseContractSources(t, srcs))
	found := false
	for _, v := range violations {
		if strings.Contains(v, "zz_fixture_roster_health.go: checkFixtureRosterHealth") {
			found = true
		}
	}
	if !found {
		t.Errorf("a roster-derived row in a new *_health.go file passed the wall; violations=%q", violations)
	}
}

// ─── wall 3: roster-row producers only feed the contract ─────────────────────

// rosterRowProducers are the functions that BUILD a roster-derived row (or its
// inputs). Their output is redacted only because it travels inside the
// OperatorContract through writeOperatorContract, so a production caller
// outside the contract path — say, a new handler that serializes
// []OperatorContractCheck{checkOversizeConfiguredUsernames()} — would bypass
// redactContractForRole entirely (CodeRabbit, PR #1545). Boolean probes such
// as hasCredentialCapableProvider are deliberately NOT producers: they render
// no roster value and have legitimate callers on the proxy path.
var rosterRowProducers = map[string]bool{
	"checkOversizeConfiguredUsernames": true,
	"collectAdminUsernames":            true,
	"checkAdminRosterDurability":       true,
	"readRosterDurabilityFacts":        true,
}

// rosterProducerCallerExceptions are callers outside the contract walk that
// may reference a producer, with the reason.
var rosterProducerCallerExceptions = map[string]string{
	// The redactor re-derives admin_roster_durability's VIEWER row from the
	// facts below admin; it runs only inside writeOperatorContract.
	"redactContractForRole": "renders the viewer twin inside writeOperatorContract",
}

// contractReachableKeys is contractReachable keyed by function key.
func contractReachableKeys(idx *contractIndex) map[string]bool {
	keys := map[string]bool{}
	for fn := range contractReachable(idx) {
		keys[fn.Key] = true
	}
	return keys
}

// rosterProducerViolations reports production functions that reference a
// roster-row producer without being reachable from buildOperatorContract.
func rosterProducerViolations(idx *contractIndex) []string {
	reachable := contractReachableKeys(idx)
	var violations []string
	for _, fn := range idx.funcs {
		if reachable[fn.Key] || rosterRowProducers[fn.Key] {
			continue
		}
		if _, ok := rosterProducerCallerExceptions[fn.Key]; ok {
			continue
		}
		violations = append(violations, producerUsesIn(fn)...)
	}
	sort.Strings(violations)
	return violations
}

func producerUsesIn(fn *contractFunc) []string {
	var out []string
	ast.Inspect(fn.Decl.Body, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && rosterRowProducers[id.Name] {
			out = append(out, fn.File+": "+fn.Key+" uses roster-row producer "+id.Name+
				" outside the operator-contract path, so its output bypasses redactContractForRole")
		}
		return true
	})
	return out
}

// TestWall_RosterRowProducersOnlyReachedViaContract pins that roster-derived
// rows reach a response only inside the redacted contract.
func TestWall_RosterRowProducersOnlyReachedViaContract(t *testing.T) {
	idx := parseContractSources(t, loadContractSources(t))
	for _, v := range rosterProducerViolations(idx) {
		t.Error(v)
	}
	// Not vacuous: every producer must exist and be reachable.
	reachable := contractReachableKeys(idx)
	for p := range rosterRowProducers {
		if !reachable[p] {
			t.Errorf("roster-row producer %s is not reachable from buildOperatorContract — renamed or "+
				"removed without updating rosterRowProducers", p)
		}
	}

	// Negative control: a new handler serializing a producer's row directly.
	srcs := loadContractSources(t).clone()
	srcs["zz_fixture_roster_rows.go"] = []byte("package main\n\nimport \"net/http\"\n\n" +
		"func apiFixtureRosterRows(w http.ResponseWriter, _ *http.Request) {\n" +
		"\tjsonOK(w, []OperatorContractCheck{checkOversizeConfiguredUsernames()})\n}\n")
	found := false
	for _, v := range rosterProducerViolations(parseContractSources(t, srcs)) {
		if strings.Contains(v, "apiFixtureRosterRows") {
			found = true
		}
	}
	if !found {
		t.Error("a handler serializing checkOversizeConfiguredUsernames() directly passed the wall")
	}
}
