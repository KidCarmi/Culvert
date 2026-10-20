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
//     jsonOK(w, redactContractForRole(full, uiRole(r).HasRole(RoleAdmin))),
//     where r is the writer's own *http.Request parameter — the gate's
//     receiver is the REQUEST's role, never a constant such as
//     RoleAdmin.HasRole(RoleAdmin) or any other expression (Codex P2, #1545);
//   - the request parameter is never reassigned, so uiRole(r) reads the role
//     the auth middleware put on the incoming request;
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
	req := requestParamName(fn.Decl)
	if req == "" {
		return append(out, where+" has no *http.Request parameter to take the caller's role from")
	}
	if !hasTopLevelRedactedWrite(fn.Decl.Body, param, req) {
		out = append(out, where+" does not unconditionally serialize "+
			"jsonOK(w, redactContractForRole("+param+", uiRole("+req+").HasRole(RoleAdmin)))")
	}
	if identAssigned(fn.Decl.Body, req) {
		out = append(out, fmt.Sprintf("%s reassigns the request %q, so uiRole(%s) may not be the "+
			"caller's role", where, req, req))
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
// jsonOK(w, redactContractForRole(param, uiRole(req).HasRole(RoleAdmin))).
func hasTopLevelRedactedWrite(body *ast.BlockStmt, param, req string) bool {
	for _, st := range body.List {
		es, ok := st.(*ast.ExprStmt)
		if !ok {
			continue
		}
		if call, ok := isCallTo(es.X, "jsonOK"); ok && len(call.Args) == 2 && isAdminGatedRedaction(call.Args[1], param, req) {
			return true
		}
	}
	return false
}

func isAdminGatedRedaction(e ast.Expr, param, req string) bool {
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
	if !ok || !ok2 || sel.Sel.Name != "HasRole" || arg.Name != "RoleAdmin" {
		return false
	}
	// The receiver must be exactly uiRole(req): the role the auth middleware
	// resolved for THIS request. A constant receiver (RoleAdmin.HasRole(...))
	// or any other expression would un-redact for every caller.
	recv, ok := isCallTo(sel.X, "uiRole")
	if !ok || len(recv.Args) != 1 {
		return false
	}
	reqArg, ok := recv.Args[0].(*ast.Ident)
	return ok && reqArg.Name == req
}

// requestParamName is the name of fd's *http.Request parameter, or "".
func requestParamName(fd *ast.FuncDecl) string {
	if fd.Type.Params == nil {
		return ""
	}
	for _, p := range fd.Type.Params.List {
		star, ok := p.Type.(*ast.StarExpr)
		if !ok || len(p.Names) != 1 {
			continue
		}
		sel, ok := star.X.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Request" {
			continue
		}
		if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "http" {
			return p.Names[0].Name
		}
	}
	return ""
}

// identAssigned reports whether body assigns to name (=, :=, op=) anywhere.
func identAssigned(body *ast.BlockStmt, name string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, lhs := range as.Lhs {
			if id, ok := lhs.(*ast.Ident); ok && id.Name == name {
				found = true
			}
		}
		return !found
	})
	return found
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
		// Codex P2, #1545: the gate's receiver must be the REQUEST's role.
		"constant admin receiver":            "jsonOK(w, redactContractForRole(full, RoleAdmin.HasRole(RoleAdmin)))",
		"receiver not the request role":      "jsonOK(w, redactContractForRole(full, UIRole(\"admin\").HasRole(RoleAdmin)))",
		"role taken from another request":    "jsonOK(w, redactContractForRole(full, uiRole(new(http.Request)).HasRole(RoleAdmin)))",
		"request reassigned before the gate": "r = r.WithContext(context.WithValue(r.Context(), uiRoleKey{}, RoleAdmin))\n\t" + redacted,
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
	rosterAccessorMethods = []string{"ListUIUsers", "UserHasTOTP", "GetUser", "hasLocalAdministrator", "rosterPersistTarget", "rosterWriteEvidence"}
	rosterCounterVars     = []string{"rosterPersistRefused", "rosterPersistBestEffort", "rosterNotDurable"}
)

// rosterKind is how a classified roster reader's result may travel.
type rosterKind int

const (
	// rosterRedactedRow builds an operator-contract row from roster state. Its
	// Code constant must be classified in redactContractForRole, and any other
	// function that consumes the row is itself a roster consumer.
	rosterRedactedRow rosterKind = iota + 1
	// rosterInput returns roster data (not a row) to a row builder. Every
	// caller is a roster consumer and must be classified in turn.
	rosterInput
	// rosterProbe reads the roster but returns only a fact reviewed as safe
	// below admin, so its callers are NOT roster consumers.
	rosterProbe
)

type rosterClass struct {
	Kind   rosterKind
	Code   string // rosterRedactedRow only: the code constant redactContractForRole must reference
	Reason string
}

// rosterRowExceptions classifies every function reachable from
// buildOperatorContract that reads a roster primitive OR consumes (calls or
// references) another roster reader whose kind is not rosterProbe. Anything
// else reachable that does either fails the wall (Codex P2, PR #1545: a new
// check calling collectAdminUsernames() and rendering len(inv.names) used to
// pass every wall without being redacted). buildOperatorContract itself is the
// aggregation root: its result is redacted by writeOperatorContract (wall 1).
var rosterRowExceptions = map[string]rosterClass{
	"checkOversizeConfiguredUsernames": {Kind: rosterRedactedRow, Code: "adminUsernameLengthCode",
		Reason: "the admin_username_length row"},
	"collectAdminUsernames": {Kind: rosterInput,
		Reason: "the inventory checkOversizeConfiguredUsernames renders; every consumer is classified"},
	"hasCredentialCapableProvider": {Kind: rosterProbe, Reason: "reads cfg.GetUser() only as a BOOLEAN " +
		"existence probe; renders no name, role, count or second-factor posture"},
	"checkAdminRosterDurability": {Kind: rosterRedactedRow, Code: "adminRosterDurabilityCode",
		Reason: "the admin_roster_durability row; redactContractForRole replaces it with " +
			"rosterDurabilityFacts.viewerRow below admin (gated by diagnostics_roster_durability_test.go)"},
	"readRosterDurabilityFacts": {Kind: rosterInput, Reason: "the CHAOS-70 counters, local-admin probe and " +
		"roster-target load outcome behind admin_roster_durability"},
}

const (
	rosterContractRoot = "buildOperatorContract"
	rosterRedactor     = "redactContractForRole"
)

// contractReachable returns every function reachable from
// buildOperatorContract. Over-approximates on purpose: a referenced
// identifier naming a top-level function, and a selector naming any method
// declared in the package, are both treated as edges, so a check passed by
// value or called through any receiver is still followed.
func contractReachable(idx *contractIndex) map[*contractFunc]bool {
	seen := map[*contractFunc]bool{}
	queue := append([]*contractFunc(nil), idx.byName[rosterContractRoot]...)
	for len(queue) > 0 {
		fn := queue[0]
		queue = queue[1:]
		if seen[fn] {
			continue
		}
		seen[fn] = true
		queue = append(queue, contractRefs(idx, fn)...)
	}
	return seen
}

// contractRefs is fn's over-approximated callee set (see contractReachable).
func contractRefs(idx *contractIndex, fn *contractFunc) []*contractFunc {
	var refs []*contractFunc
	ast.Inspect(fn.Decl.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			refs = append(refs, idx.methods[x.Sel.Name]...)
		case *ast.Ident:
			refs = append(refs, idx.byName[x.Name]...)
		}
		return true
	})
	return refs
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

// rosterTaint maps every reachable function that touches roster state to how
// it does: it reads a primitive directly, or — transitively, to a fixpoint —
// it references a reachable function that does, unless that callee is a
// classified rosterProbe. Iteration follows idx.funcs so messages are stable.
func rosterTaint(idx *contractIndex, reachable map[*contractFunc]bool) map[*contractFunc]string {
	taint := map[*contractFunc]string{}
	refs := map[*contractFunc][]*contractFunc{}
	for _, fn := range idx.funcs {
		if !reachable[fn] {
			continue
		}
		refs[fn] = contractRefs(idx, fn)
		if p := rosterPrimitiveIn(fn); p != "" {
			taint[fn] = "reads " + p
		}
	}
	for changed := true; changed; {
		changed = false
		for _, fn := range idx.funcs {
			if _, done := taint[fn]; done || !reachable[fn] {
				continue
			}
			for _, callee := range refs[fn] {
				if _, tainted := taint[callee]; !tainted || rosterRowExceptions[callee.Key].Kind == rosterProbe {
					continue
				}
				taint[fn] = "consumes roster reader " + callee.Key
				changed = true
				break
			}
		}
	}
	return taint
}

// rosterRowViolations reports reachable roster readers and consumers that are
// not classified, classified rows that redactContractForRole does not handle,
// and stale classifications; plus how many classified readers were seen (for
// the not-vacuous check).
func rosterRowViolations(idx *contractIndex) (violations []string, classifiedSeen int) {
	reachable := contractReachable(idx)
	taint := rosterTaint(idx, reachable)
	var redactor *contractFunc
	if rs := idx.byName[rosterRedactor]; len(rs) == 1 {
		redactor = rs[0]
	} else {
		violations = append(violations, fmt.Sprintf("%s: found %d declarations, want exactly 1", rosterRedactor, len(rs)))
	}
	seenKeys := map[string]bool{}
	for _, fn := range idx.funcs {
		how, tainted := taint[fn]
		if !reachable[fn] || fn.Key == rosterContractRoot {
			continue
		}
		class, classified := rosterRowExceptions[fn.Key]
		if classified {
			seenKeys[fn.Key] = true
		}
		switch {
		case !tainted && classified:
			violations = append(violations, fn.File+": "+fn.Key+" is classified in rosterRowExceptions but "+
				"neither reads nor consumes roster state; remove the stale entry")
		case !tainted:
		case !classified:
			violations = append(violations, fn.File+": "+fn.Key+" "+how+" and is reachable from "+
				"buildOperatorContract, so its row rides the viewer-readable operator contract. Redact it in "+
				"redactContractForRole (with a gate beside TestApiDiagnostics_UsernameRowDetailIsAdminOnly) and "+
				"classify it in rosterRowExceptions, or record there why its detail is safe below admin")
		default:
			classifiedSeen++
			violations = append(violations, rosterClassViolations(idx, fn, class, redactor)...)
		}
	}
	for key := range rosterRowExceptions {
		if !seenKeys[key] {
			violations = append(violations, key+" is classified in rosterRowExceptions but is not reachable "+
				"from buildOperatorContract; remove or rename the stale entry")
		}
	}
	sort.Strings(violations)
	return violations, classifiedSeen
}

// returnedRowCodes collects the Code of every row fn can return (Codex P2
// 4319946930 on PR #1601): each return statement's value is followed — a
// composite OperatorContractCheck literal's Code, a call into another
// function or method that returns one (recursively), or a local variable
// through every assignment to it and every assignment to its Code field.
// Anything it cannot resolve to a code identifier is reported in unknown, so
// the check fails closed.
func returnedRowCodes(idx *contractIndex, fn *contractFunc, seen map[*contractFunc]bool) (codes, unknown []string) {
	if seen[fn] {
		return nil, nil
	}
	seen[fn] = true
	add := func(c, u []string) {
		codes, unknown = append(codes, c...), append(unknown, u...)
	}
	inspectOwnBody(fn.Decl.Body, func(n ast.Node) {
		if ret, ok := n.(*ast.ReturnStmt); ok {
			for _, res := range ret.Results {
				add(rowExprCodes(idx, fn, res, seen))
			}
		}
	})
	return codes, unknown
}

// inspectOwnBody visits body without descending into function literals,
// whose returns are not fn's.
func inspectOwnBody(body ast.Node, visit func(ast.Node)) {
	ast.Inspect(body, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		if n != nil {
			visit(n)
		}
		return true
	})
}

// rowExprCodes resolves the codes a row-valued expression in fn can carry.
func rowExprCodes(idx *contractIndex, fn *contractFunc, e ast.Expr, seen map[*contractFunc]bool) (codes, unknown []string) {
	switch x := e.(type) {
	case *ast.ParenExpr:
		return rowExprCodes(idx, fn, x.X, seen)
	case *ast.CompositeLit:
		for _, el := range x.Elts {
			if kv, ok := el.(*ast.KeyValueExpr); ok {
				if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Code" {
					return codeIdent(kv.Value)
				}
			}
		}
		return nil, []string{"a row literal without a Code"}
	case *ast.CallExpr:
		callees := rowReturningCallees(idx, x)
		if len(callees) == 0 {
			return nil, []string{"a row from an unresolved call"}
		}
		for _, callee := range callees {
			c, u := returnedRowCodes(idx, callee, seen)
			codes, unknown = append(codes, c...), append(unknown, u...)
		}
		return codes, unknown
	case *ast.Ident:
		return localRowCodes(idx, fn, x.Name, seen)
	}
	return nil, []string{"a row from an expression the wall cannot follow"}
}

// codeIdent is the code a Code field is set to: a named constant, or unknown.
func codeIdent(e ast.Expr) (codes, unknown []string) {
	if id, ok := e.(*ast.Ident); ok {
		return []string{id.Name}, nil
	}
	return nil, []string{"a Code that is not a named constant"}
}

// rowReturningCallees resolves a call to the package functions or methods it
// may name that return an OperatorContractCheck.
func rowReturningCallees(idx *contractIndex, call *ast.CallExpr) []*contractFunc {
	var cands []*contractFunc
	switch f := call.Fun.(type) {
	case *ast.Ident:
		cands = idx.byName[f.Name]
	case *ast.SelectorExpr:
		cands = idx.methods[f.Sel.Name]
	}
	var out []*contractFunc
	for _, c := range cands {
		if r := c.Decl.Type.Results; r != nil && len(r.List) == 1 {
			if id, ok := r.List[0].Type.(*ast.Ident); ok && id.Name == "OperatorContractCheck" {
				out = append(out, c)
			}
		}
	}
	return out
}

// localRowCodes follows a local row variable through every assignment to it
// and every assignment to its Code field in fn.
func localRowCodes(idx *contractIndex, fn *contractFunc, name string, seen map[*contractFunc]bool) (codes, unknown []string) {
	assigned := false
	inspectOwnBody(fn.Decl.Body, func(n ast.Node) {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != len(as.Rhs) {
			return
		}
		for i, lhs := range as.Lhs {
			switch l := lhs.(type) {
			case *ast.Ident:
				if l.Name == name {
					assigned = true
					c, u := rowExprCodes(idx, fn, as.Rhs[i], seen)
					codes, unknown = append(codes, c...), append(unknown, u...)
				}
			case *ast.SelectorExpr:
				if id, ok := l.X.(*ast.Ident); ok && id.Name == name && l.Sel.Name == "Code" {
					c, u := codeIdent(as.Rhs[i])
					codes, unknown = append(codes, c...), append(unknown, u...)
				}
			}
		}
	})
	if !assigned {
		unknown = append(unknown, "the row variable "+name+", which the wall cannot trace")
	}
	return codes, unknown
}

// rosterClassViolations checks that a classified reader's entry is coherent:
// a reason is recorded and a redacted row is actually classified by the
// redactor under the code the row renders (in its own body or in a function
// it reaches, such as rosterDurabilityFacts.adminRow).
func rosterClassViolations(idx *contractIndex, fn *contractFunc, class rosterClass, redactor *contractFunc) []string {
	where := fn.File + ": " + fn.Key
	var out []string
	if strings.TrimSpace(class.Reason) == "" {
		out = append(out, where+" is classified in rosterRowExceptions without a reason")
	}
	switch class.Kind {
	case rosterRedactedRow:
		codes, unknown := returnedRowCodes(idx, fn, map[*contractFunc]bool{})
		if class.Code == "" || len(codes) == 0 {
			out = append(out, fmt.Sprintf("%s is classified as a redacted row under %q but does not render "+
				"that code", where, class.Code))
		}
		for _, c := range codes {
			if c != class.Code {
				out = append(out, fmt.Sprintf("%s is classified as a redacted row under %q but can return a "+
					"row coded %s, which the redactor does not handle as this row", where, class.Code, c))
			}
		}
		for _, u := range unknown {
			out = append(out, fmt.Sprintf("%s is classified as a redacted row under %q but returns %s",
				where, class.Code, u))
		}
		if redactor != nil && (class.Code == "" || identUses(redactor.Decl.Body, class.Code) == 0) {
			out = append(out, fmt.Sprintf("%s is classified as a redacted row under %q but %s does not "+
				"classify that code, so the row reaches viewers unredacted", where, class.Code, rosterRedactor))
		}
	case rosterInput, rosterProbe:
	default:
		out = append(out, where+" has an unknown rosterRowExceptions kind")
	}
	return out
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

// rosterViolationFor reports whether violations name want.
func rosterViolationFor(violations []string, want string) bool {
	for _, v := range violations {
		if strings.Contains(v, want) {
			return true
		}
	}
	return false
}

// TestWall_RosterConsumers_NegativeControls proves the wall follows roster
// state through its classified producers (Codex P2, PR #1545): a reachable
// consumer of collectAdminUsernames or of the redacted row is not exempt just
// because the function it calls is classified, and a classified row is
// accepted only while redactContractForRole actually handles its code.
func TestWall_RosterConsumers_NegativeControls(t *testing.T) {
	base := loadContractSources(t)
	wire := func(srcs contractSources, check string) {
		srcs.replaceOnce(t, "diagnostics.go", "\t\tcheckStorage(),\n", "\t\tcheckStorage(),\n\t\t"+check+"(),\n")
	}
	const hdr = "package main\n\nimport \"fmt\"\n\n"
	for name, tc := range map[string]struct{ src, check, want string }{
		"renders a count from collectAdminUsernames": {
			src: hdr + "func checkFixtureRosterCount() OperatorContractCheck {\n" +
				"\tinv := collectAdminUsernames()\n" +
				"\treturn OperatorContractCheck{Code: \"fixture_roster_count\", Status: diagWarn,\n" +
				"\t\tMessage: fmt.Sprintf(\"%d admin accounts\", len(inv.names))}\n}\n",
			check: "checkFixtureRosterCount", want: "checkFixtureRosterCount consumes roster reader collectAdminUsernames",
		},
		"re-codes the redacted row": {
			src: hdr + "func checkFixtureRecodedRow() OperatorContractCheck {\n" +
				"\tc := checkOversizeConfiguredUsernames()\n\tc.Code = \"fixture_recoded\"\n" +
				"\treturn OperatorContractCheck{Code: c.Code, Status: c.Status, Message: fmt.Sprint(c.Message)}\n}\n",
			check: "checkFixtureRecodedRow", want: "checkFixtureRecodedRow consumes roster reader checkOversizeConfiguredUsernames",
		},
		"consumes through an unclassified helper": {
			src: hdr + "func fixtureRosterSize() int { return len(collectAdminUsernames().names) }\n\n" +
				"func checkFixtureViaHelper() OperatorContractCheck {\n" +
				"\treturn OperatorContractCheck{Code: \"fixture_via_helper\", Status: diagWarn,\n" +
				"\t\tMessage: fmt.Sprintf(\"%d\", fixtureRosterSize())}\n}\n",
			check: "checkFixtureViaHelper", want: "checkFixtureViaHelper consumes roster reader fixtureRosterSize",
		},
	} {
		srcs := base.clone()
		srcs["zz_fixture_roster_consumer.go"] = []byte(tc.src)
		wire(srcs, tc.check)
		if v, _ := rosterRowViolations(parseContractSources(t, srcs)); !rosterViolationFor(v, tc.want) {
			t.Errorf("%s: passed the wall; want a violation containing %q, got %q", name, tc.want, v)
		}
	}

	// Codex P2 4319946930 on #1601: a branch of a classified row returns a row
	// under another code. A reachable helper still references the classified
	// code, so "the code is referenced somewhere" is not enough.
	for name, inject := range map[string]string{
		"returns an unclassified literal": "\tcase f.refused > 1000000:\n" +
			"\t\treturn OperatorContractCheck{Code: \"fixture_unclassified\", Status: diagWarn}\n",
		"re-codes the row":    "\tcase f.refused > 1000000:\n\t\trow.Code = fixtureOtherCode\n",
		"returns another row": "\tcase f.refused > 1000000:\n\t\treturn checkStorage()\n",
	} {
		recoded := base.clone()
		recoded.replaceOnce(t, "diagnostics.go", "\tcase f.refused == 0 && f.degraded == 0:\n",
			inject+"\tcase f.refused == 0 && f.degraded == 0:\n")
		v, _ := rosterRowViolations(parseContractSources(t, recoded))
		if !rosterViolationFor(v, "checkAdminRosterDurability is classified as a redacted row") {
			t.Errorf("an adminRow branch that %s passed the wall; violations=%q", name, v)
		}
	}

	// The redactor stops classifying the row's code: the classification alone
	// must not keep the wall green.
	unredacted := base.clone()
	unredacted.replaceOnce(t, "diagnostics.go", "\t\tcase adminUsernameLengthCode:\n",
		"\t\tcase \"fixture_other_code\":\n")
	if v, _ := rosterRowViolations(parseContractSources(t, unredacted)); !rosterViolationFor(v,
		"checkOversizeConfiguredUsernames is classified as a redacted row") {
		t.Errorf("a classified row that redactContractForRole no longer handles passed the wall; violations=%q", v)
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
//
// The set is DERIVED from rosterRowExceptions (every redacted row and roster
// input), so classifying a new roster consumer for wall 2 also confines it
// here.
var rosterRowProducers = rosterProducerKeys()

func rosterProducerKeys() map[string]bool {
	keys := map[string]bool{}
	for k, c := range rosterRowExceptions {
		if c.Kind == rosterRedactedRow || c.Kind == rosterInput {
			keys[k] = true
		}
	}
	return keys
}

// rosterProducerUse is the ONE producer use a caller outside the contract
// walk is allowed: the exact call `<producer>().<method>()`, with no
// arguments, matched on the AST.
type rosterProducerUse struct {
	producer, method, reason string
}

// rosterProducerCallerExceptions are callers outside the contract walk that
// may make exactly one kind of producer use. Every OTHER roster-row producer
// use inside them is still a violation (Codex P2 4317365515 on PR #1601): the
// redactor is excepted for re-deriving the viewer row, not as a whole.
var rosterProducerCallerExceptions = map[string]rosterProducerUse{
	// The redactor re-derives admin_roster_durability's VIEWER row from the
	// facts below admin; it runs only inside writeOperatorContract.
	"redactContractForRole": {producer: "readRosterDurabilityFacts", method: "viewerRow",
		reason: "renders the viewer twin inside writeOperatorContract"},
}

// allowedProducerIdents returns the producer identifiers in body that form
// the exact allowed use `<producer>().<method>()`.
func allowedProducerIdents(body ast.Node, use rosterProducerUse) map[*ast.Ident]bool {
	allowed := map[*ast.Ident]bool{}
	if use.producer == "" {
		return allowed
	}
	ast.Inspect(body, func(n ast.Node) bool {
		outer, ok := n.(*ast.CallExpr)
		if !ok || len(outer.Args) != 0 {
			return true
		}
		sel, ok := outer.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != use.method {
			return true
		}
		inner, ok := sel.X.(*ast.CallExpr)
		if !ok || len(inner.Args) != 0 {
			return true
		}
		if id, ok := inner.Fun.(*ast.Ident); ok && id.Name == use.producer {
			allowed[id] = true
		}
		return true
	})
	return allowed
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
		violations = append(violations, producerUsesIn(fn, rosterProducerCallerExceptions[fn.Key])...)
	}
	sort.Strings(violations)
	return violations
}

// producerUsesIn reports fn's roster-row producer uses, except the one exact
// use its exception (if any) allows.
func producerUsesIn(fn *contractFunc, use rosterProducerUse) []string {
	allowed := allowedProducerIdents(fn.Decl.Body, use)
	var out []string
	ast.Inspect(fn.Decl.Body, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && rosterRowProducers[id.Name] && !allowed[id] {
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

// TestWall_RedactorExceptionIsTheExactViewerRowCall (Codex P2 4317365515 on
// PR #1601): the redactor's exception covers only
// `readRosterDurabilityFacts().viewerRow()`. The exact use is present (the
// exception is not stale), and any other roster-row producer use inside the
// redactor — copying another row's Message, or reading the facts any other
// way — fails the wall. A whole-function exception fails the negative
// controls.
func TestWall_RedactorExceptionIsTheExactViewerRowCall(t *testing.T) {
	base := loadContractSources(t)
	idx := parseContractSources(t, base)
	for key, use := range rosterProducerCallerExceptions {
		var fn *contractFunc
		for _, f := range idx.funcs {
			if f.Key == key {
				fn = f
			}
		}
		if fn == nil {
			t.Errorf("exception %s names no function", key)
			continue
		}
		if len(allowedProducerIdents(fn.Decl.Body, use)) == 0 {
			t.Errorf("exception %s: the allowed use %s().%s() is not in it — stale exception", key, use.producer, use.method)
		}
	}

	const anchor = "\t\t\tchecks[i].Message = diagnosticsRedactedUsernameMessage\n"
	for name, inject := range map[string]string{
		"copies another roster row's Message": "\t\t\tchecks[i].Message = checkOversizeConfiguredUsernames().Message\n",
		"reads the facts another way":         "\t\t\tchecks[i].Message = fmt.Sprint(readRosterDurabilityFacts().refused)\n",
		"keeps the facts for later":           "\t\t\tfacts := readRosterDurabilityFacts\n\t\t\t_ = facts\n",
		// The right producer through the wrong method: the ADMIN row below admin.
		"renders the admin row": "\t\t\tchecks[i] = readRosterDurabilityFacts().adminRow()\n",
		// The right method on another producer (shape only: the wall reads the AST).
		"uses another producer's viewerRow": "\t\t\tchecks[i] = checkAdminRosterDurability().viewerRow()\n",
	} {
		srcs := base.clone()
		srcs.replaceOnce(t, "diagnostics.go", anchor, inject)
		found := false
		for _, v := range rosterProducerViolations(parseContractSources(t, srcs)) {
			if strings.Contains(v, "redactContractForRole uses roster-row producer") {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: a redactor that %s passed the wall", name, name)
		}
	}
}
