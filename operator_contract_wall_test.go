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
	writerOK := false
	for _, fn := range idx.funcs {
		if fn.Key == operatorContractWriter {
			writerOK = writerRedactsForAdmin(fn.Decl)
			continue
		}
		if _, ok := contractRenderExceptions[fn.Key]; ok {
			continue
		}
		v, n := contractRenderViolationsIn(fn)
		violations = append(violations, v...)
		writerCalls += n
	}
	if !writerOK {
		violations = append(violations, operatorContractWriter+": missing, or does not serialize "+
			"jsonOK(w, redactContractForRole(full, <role>.HasRole(RoleAdmin)))")
	}
	return violations, writerCalls
}

// writerRedactsForAdmin checks the helper's own body structurally.
func writerRedactsForAdmin(fd *ast.FuncDecl) bool {
	found := false
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); !ok || id.Name != "jsonOK" {
			return true
		}
		red, ok := isCallTo(call.Args[1], "redactContractForRole")
		if !ok || len(red.Args) != 2 {
			return true
		}
		gate, ok := red.Args[1].(*ast.CallExpr)
		if !ok || len(gate.Args) != 1 {
			return true
		}
		sel, ok := gate.Fun.(*ast.SelectorExpr)
		arg, ok2 := gate.Args[0].(*ast.Ident)
		if ok && ok2 && sel.Sel.Name == "HasRole" && arg.Name == "RoleAdmin" {
			found = true
		}
		return true
	})
	return found
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

// contractTypedIdents collects the names declared in fd as an OperatorContract.
func contractTypedIdents(fd *ast.FuncDecl) map[string]bool {
	typed := map[string]bool{}
	isContractType := func(e ast.Expr) bool {
		if s, ok := e.(*ast.StarExpr); ok {
			e = s.X
		}
		id, ok := e.(*ast.Ident)
		return ok && id.Name == "OperatorContract"
	}
	if fd.Type.Params != nil {
		for _, p := range fd.Type.Params.List {
			if isContractType(p.Type) {
				for _, n := range p.Names {
					typed[n.Name] = true
				}
			}
		}
	}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.ValueSpec:
			for i, name := range x.Names {
				if (x.Type != nil && isContractType(x.Type)) || (i < len(x.Values) && isContractValued(x.Values[i], typed)) {
					typed[name.Name] = true
				}
			}
		case *ast.AssignStmt:
			for i, lhs := range x.Lhs {
				id, ok := lhs.(*ast.Ident)
				if ok && i < len(x.Rhs) && isContractValued(x.Rhs[i], typed) {
					typed[id.Name] = true
				}
			}
		}
		return true
	})
	return typed
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
}

// ─── wall 2: roster-derived rows anywhere in the package ─────────────────────

// rosterAccessorMethods are the Config reads whose result is admin-only roster
// state. rosterCounterVars are the CHAOS-70 durability counters
// (roster_persist_durability.go): refused admin changes, degraded login-path
// writes (a consumed backup code or TOTP replay counter that may not survive
// a restart) and non-durable mutations are admin-only under the PR #1545
// policy table.
var (
	rosterAccessorMethods = []string{"ListUIUsers", "UserHasTOTP", "GetUser", "hasLocalAdministrator"}
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
	"readRosterDurabilityFacts": "the CHAOS-70 counters and local-admin probe behind admin_roster_durability; " +
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
