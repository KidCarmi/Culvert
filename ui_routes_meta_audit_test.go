package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

// ── Phase C1.5: metadata-vs-handler validation (REPORT-ONLY) ──────────────
//
// AST-driven cross-check between uiRoutes metadata and what each handler
// actually does. C1.5 is a SAFETY SIGNAL, not a compiler of behavior:
//
//   • Detects only STABLE, DIRECT patterns:
//       - direct requireRole(w, r, RoleX) calls in the handler body
//       - direct auditEvent / auditEventDiff calls
//       - direct http.MethodX literals (case-on-method, gate-before-handle)
//   • Does NOT trace control flow into helper functions, closures, or
//     dynamically-dispatched methods. Such cases surface as "unknown".
//   • Mismatches FAIL the test. Unknowns are logged via t.Logf so they
//     are visible in CI output without blocking the run — they are
//     follow-up tasks, not regressions.
//   • Zero production code changes; this file is _test.go only.
//
// Three tests cover the metadata fields C2 will eventually enforce:
//   TestC15_MinRole_MetadataMatchesHandler
//   TestC15_Mutating_MetadataMatchesHandler
//   TestC15_AuditExpected_MetadataMatchesHandler

// ── Per-method analysis types (Phase C1.5 evolution) ──────────────────────
//
// MethodAny ("*") is defined in ui_routes_meta.go — used both by the
// metadata schema (for routes whose handler delegates routing) and by
// this scanner (as the catch-all bucket for calls not pinned to a
// specific method).

// methodBehavior captures the per-method AST findings for one handler:
// which roles its requireRole calls accept inside that method's case
// block (or guard region), and whether any auditEvent call appears in
// the same scope.
type methodBehavior struct {
	rolesSeen  []UIRole // every role argument seen for requireRole in this method's scope
	callsAudit bool     // any direct auditEvent / auditEventDiff in this scope
}

// minRole returns the lowest-priority role observed for this method,
// or "" if no requireRole call was attributed to this method.
func (b *methodBehavior) minRole() UIRole {
	var lowest UIRole
	for _, r := range b.rolesSeen {
		if lowest == "" || rolePriorityOf(r) < rolePriorityOf(lowest) {
			lowest = r
		}
	}
	return lowest
}

// ── AST scanner ───────────────────────────────────────────────────────────

// methodClassification summarises which HTTP methods appear as
// http.MethodX literals in a handler's body.
type methodClassification int

const (
	methodsUnknown  methodClassification = iota // no http.MethodX literals seen
	methodsReadOnly                             // only GET/HEAD/OPTIONS literals
	methodsMutating                             // at least one of POST/PUT/DELETE literal
)

// minRoleClassification summarises the lowest role any direct
// requireRole call in the handler body permits.
type minRoleClassification struct {
	confident bool     // true ⇔ at least one requireRole call was found
	minRole   UIRole   // lowest role seen across all requireRole calls
	rolesSeen []UIRole // every role argument observed (for diagnostics)
}

// handlerBehavior aggregates all C1.5 signals for one handler.
//
// Two views coexist:
//
//   - Aggregate view (rawMethods, methods, minRole, callsAudit) — used by
//     the original three TestC15_* tests; treats the handler as a whole.
//   - Per-method view (byMethod) — populated by the upgraded scanner
//     with conservative method-context tracking. Each entry maps an
//     HTTP method (or MethodAny) to the requireRole / auditEvent calls
//     attributed to that method's scope.
type handlerBehavior struct {
	file       string
	line       int
	rawMethods map[string]bool // aggregate: presence of http.MethodX literal anywhere
	methods    methodClassification
	minRole    minRoleClassification
	callsAudit bool // aggregate: any direct auditEvent or auditEventDiff call

	// byMethod is the per-method attribution. Keys are upper-case HTTP
	// methods ("GET", "POST", ...) or MethodAny ("*") for calls the
	// scanner could not confidently pin to a specific method.
	byMethod map[string]*methodBehavior
}

// recordRole adds a requireRole observation under the given method scope.
func (h *handlerBehavior) recordRole(method string, role UIRole) {
	if h.byMethod == nil {
		h.byMethod = map[string]*methodBehavior{}
	}
	mb := h.byMethod[method]
	if mb == nil {
		mb = &methodBehavior{}
		h.byMethod[method] = mb
	}
	mb.rolesSeen = append(mb.rolesSeen, role)
}

// recordAudit marks that an auditEvent call was attributed to method.
func (h *handlerBehavior) recordAudit(method string) {
	if h.byMethod == nil {
		h.byMethod = map[string]*methodBehavior{}
	}
	mb := h.byMethod[method]
	if mb == nil {
		mb = &methodBehavior{}
		h.byMethod[method] = mb
	}
	mb.callsAudit = true
}

var (
	c15ScannerOnce sync.Once
	c15Handlers    map[string]*handlerBehavior
	c15ScannerErr  error
)

// scanHandlers parses every non-test .go file in the working directory,
// indexes top-level function declarations by name, and computes their
// handlerBehavior. Result is memoised across the three C1.5 tests.
func scanHandlers(t *testing.T) map[string]*handlerBehavior {
	t.Helper()
	c15ScannerOnce.Do(func() {
		c15Handlers, c15ScannerErr = doScanHandlers()
	})
	if c15ScannerErr != nil {
		t.Fatalf("scanHandlers: %v", c15ScannerErr)
	}
	return c15Handlers
}

func doScanHandlers() (map[string]*handlerBehavior, error) {
	fset := token.NewFileSet()
	out := make(map[string]*handlerBehavior, 256)

	// Absolute package source dir — NOT CWD — so a concurrent test's os.Chdir
	// cannot make this AST scan enumerate a different directory (the CWD-race flake).
	dir := pkgSourceDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", name, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil { // skip method declarations
				continue
			}
			beh := analyzeHandler(fn)
			beh.file = name
			beh.line = fset.Position(fn.Pos()).Line
			out[fn.Name.Name] = beh
		}
	}
	return out, nil
}

// analyzeHandler walks the body of fn and records all C1.5 signals.
// Conservative: only direct calls / literals are detected.
//
// Two passes are performed:
//
//  1. ast.Inspect over the whole body — populates the aggregate fields
//     (rawMethods, minRole.rolesSeen, callsAudit). These match the
//     pre-evolution behavior used by the original TestC15_* tests.
//  2. walkBodyPerMethod — sequential top-level pass that attributes
//     each requireRole / auditEvent call to a specific HTTP method
//     when the method context is OBVIOUS (case in switch r.Method;
//     gate-before-handle if-guard returning on wrong method). All
//     other calls are attributed to MethodAny.
func analyzeHandler(fn *ast.FuncDecl) *handlerBehavior {
	beh := &handlerBehavior{rawMethods: map[string]bool{}}
	if fn.Body == nil {
		return beh
	}
	// Pass 2: sequential per-method attribution.
	walkBodyPerMethod(fn.Body, MethodAny, beh)

	// Pass 1: original aggregate scan (kept for the existing tests).
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			// http.MethodX literal
			if pkg, ok := x.X.(*ast.Ident); ok && pkg.Name == "http" {
				if strings.HasPrefix(x.Sel.Name, "Method") && len(x.Sel.Name) > len("Method") {
					m := strings.ToUpper(strings.TrimPrefix(x.Sel.Name, "Method"))
					beh.rawMethods[m] = true
				}
			}
		case *ast.CallExpr:
			id, ok := x.Fun.(*ast.Ident)
			if !ok {
				return true
			}
			switch id.Name {
			case "auditEvent", "auditEventDiff", "auditEventDiffID":
				beh.callsAudit = true
			case "requireRole":
				if role := extractRequireRoleArg(x); role != "" {
					beh.minRole.rolesSeen = append(beh.minRole.rolesSeen, role)
					if !beh.minRole.confident || rolePriorityOf(role) < rolePriorityOf(beh.minRole.minRole) {
						beh.minRole.minRole = role
					}
					beh.minRole.confident = true
				}
			}
		}
		return true
	})

	// Method classification.
	hasMutating := beh.rawMethods["POST"] || beh.rawMethods["PUT"] || beh.rawMethods["DELETE"] || beh.rawMethods["PATCH"]
	hasReadOnly := beh.rawMethods["GET"] || beh.rawMethods["HEAD"] || beh.rawMethods["OPTIONS"]
	switch {
	case hasMutating:
		beh.methods = methodsMutating
	case hasReadOnly:
		beh.methods = methodsReadOnly
	default:
		beh.methods = methodsUnknown
	}
	return beh
}

// identToRole maps a UIRole identifier (as it appears in source) to its value.
func identToRole(name string) UIRole {
	switch name {
	case "RoleAdmin":
		return RoleAdmin
	case "RoleOperator":
		return RoleOperator
	case "RoleViewer":
		return RoleViewer
	case "RolePublic":
		return RolePublic
	}
	return ""
}

// rolePriorityOf returns the comparison priority used to identify the
// lowest role seen. Mirrors store.go's rolePriority but is local to
// avoid binding C1.5 logic to internal enforcement state.
func rolePriorityOf(r UIRole) int {
	switch r {
	case RoleAdmin:
		return 3
	case RoleOperator:
		return 2
	case RoleViewer:
		return 1
	case RolePublic:
		return 0
	}
	return -1
}

// ── Test helpers ──────────────────────────────────────────────────────────

func sortedJoin(lines []string) string {
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// ── Test 1: per-method MinRole parity ─────────────────────────────────────

// TestC15_MinRole_MetadataMatchesHandler reports cases where the per-
// method MinRole declared in uiRoutes contradicts what the AST scanner
// observed for that method.
//
// Failure modes:
//
//   - Public route whose handler nonetheless has any direct requireRole
//     call attributed to the declared method — fails.
//   - Non-public, specific-method entry where metadata MinRole differs
//     from the AST's lowest role for that method — fails.
//   - MethodAny entry where metadata MinRole differs from the AST's
//     aggregate lowest role across all attributed methods — fails.
//   - Non-public method with NO AST signal — logged UNKNOWN (handler
//     may delegate to a helper that gates).
func TestC15_MinRole_MetadataMatchesHandler(t *testing.T) {
	handlers := scanHandlers(t)
	var mismatches, unknowns []string

	for _, r := range uiRoutes {
		beh, ok := handlers[r.Handler]
		if !ok {
			unknowns = append(unknowns, fmt.Sprintf(
				"  %s (path=%q): handler not found at top level (closure / method / generated?)",
				r.Handler, r.Path))
			continue
		}
		for _, m := range r.Methods {
			label := r.Handler + " " + m.Method
			astRole, astHas := astMinRoleFor(beh, m.Method)

			if r.Public {
				if astHas {
					mismatches = append(mismatches, fmt.Sprintf(
						"  %s (path=%q, file=%s:%d): metadata Public=true but handler has requireRole call attributed to %s (rolesSeen=%v)",
						label, r.Path, beh.file, beh.line, m.Method, rolesForMethod(beh, m.Method)))
				}
				continue
			}
			if !astHas {
				unknowns = append(unknowns, fmt.Sprintf(
					"  %s (path=%q, file=%s:%d): metadata MinRole=%s, but no requireRole call attributed to %s (delegated?)",
					label, r.Path, beh.file, beh.line, m.MinRole, m.Method))
				continue
			}
			if astRole != m.MinRole {
				mismatches = append(mismatches, fmt.Sprintf(
					"  %s (path=%q, file=%s:%d): metadata MinRole=%s, handler lowest requireRole=%s (rolesSeen=%v)",
					label, r.Path, beh.file, beh.line, m.MinRole, astRole, rolesForMethod(beh, m.Method)))
			}
		}
	}

	if len(unknowns) > 0 {
		t.Logf("C1.5 MinRole — %d UNKNOWN (informational, not failing):\n%s", len(unknowns), sortedJoin(unknowns))
	}
	if len(mismatches) > 0 {
		t.Errorf("C1.5 MinRole — %d MISMATCHES:\n%s", len(mismatches), sortedJoin(mismatches))
	}
}

// ── Test 2: per-method Mutating parity ────────────────────────────────────

// TestC15_Mutating_MetadataMatchesHandler reports cases where the
// per-method Mutating flag is inconsistent with the HTTP method's
// conventional safety (POST/PUT/DELETE/PATCH are mutating; GET/HEAD/
// OPTIONS are not). MethodAny entries are not method-checked here
// (their Mutating is doctrine-driven, not derivable).
func TestC15_Mutating_MetadataMatchesHandler(t *testing.T) {
	var mismatches []string
	for _, r := range uiRoutes {
		for _, m := range r.Methods {
			if m.Method == MethodAny {
				continue
			}
			expected := isMutatingMethod(m.Method)
			if m.Mutating != expected {
				mismatches = append(mismatches, fmt.Sprintf(
					"  %s %s (path=%q): metadata Mutating=%v, conventional Mutating=%v",
					r.Handler, m.Method, r.Path, m.Mutating, expected))
			}
		}
	}
	if len(mismatches) > 0 {
		t.Errorf("C1.5 Mutating — %d MISMATCHES:\n%s", len(mismatches), sortedJoin(mismatches))
	}
}

// ── Test 3: per-method AuditExpected parity ───────────────────────────────

// TestC15_AuditExpected_MetadataMatchesHandler reports cases where the
// per-method AuditExpected flag contradicts whether the handler body
// directly invokes auditEvent / auditEventDiff for that method.
//
// Asymmetric on purpose:
//
//   - AuditExpected=true but no direct audit call — UNKNOWN (handler may
//     delegate to a helper that audits). Logged, not failed.
//   - AuditExpected=false but handler calls audit directly — fails (the
//     metadata is hiding an audit event the handler emits).
func TestC15_AuditExpected_MetadataMatchesHandler(t *testing.T) {
	handlers := scanHandlers(t)
	var mismatches, unknowns []string

	for _, r := range uiRoutes {
		beh, ok := handlers[r.Handler]
		if !ok {
			continue
		}
		for _, m := range r.Methods {
			astAudits := astAuditsFor(beh, m.Method)
			if m.AuditExpected && !astAudits {
				unknowns = append(unknowns, fmt.Sprintf(
					"  %s %s (path=%q, file=%s:%d): metadata AuditExpected=true but no direct auditEvent call attributed to %s (may delegate)",
					r.Handler, m.Method, r.Path, beh.file, beh.line, m.Method))
			}
			if !m.AuditExpected && astAudits {
				mismatches = append(mismatches, fmt.Sprintf(
					"  %s %s (path=%q, file=%s:%d): metadata AuditExpected=false but handler calls auditEvent for %s",
					r.Handler, m.Method, r.Path, beh.file, beh.line, m.Method))
			}
		}
	}

	if len(unknowns) > 0 {
		t.Logf("C1.5 AuditExpected — %d UNKNOWN (informational):\n%s", len(unknowns), sortedJoin(unknowns))
	}
	if len(mismatches) > 0 {
		t.Errorf("C1.5 AuditExpected — %d MISMATCHES:\n%s", len(mismatches), sortedJoin(mismatches))
	}
}

// ── Per-method test helpers ───────────────────────────────────────────────

// astMinRoleFor returns the lowest role the AST attributed to the given
// metadata method. For specific methods, looks up beh.byMethod[method].
// For MethodAny, aggregates across every entry in beh.byMethod (the
// metadata says "any method" so any AST observation counts).
func astMinRoleFor(beh *handlerBehavior, method string) (UIRole, bool) {
	if method == MethodAny {
		var lowest UIRole
		seen := false
		for _, mb := range beh.byMethod {
			if r := mb.minRole(); r != "" {
				seen = true
				if lowest == "" || rolePriorityOf(r) < rolePriorityOf(lowest) {
					lowest = r
				}
			}
		}
		return lowest, seen
	}
	mb := beh.byMethod[method]
	if mb == nil {
		return "", false
	}
	r := mb.minRole()
	return r, r != ""
}

// rolesForMethod returns the unique roles AST saw under the given
// method scope (or aggregated across all methods for MethodAny).
func rolesForMethod(beh *handlerBehavior, method string) []UIRole {
	if method == MethodAny {
		var all []UIRole
		for _, mb := range beh.byMethod {
			all = append(all, mb.rolesSeen...)
		}
		return uniqRoles(all)
	}
	if mb := beh.byMethod[method]; mb != nil {
		return uniqRoles(mb.rolesSeen)
	}
	return nil
}

// astAuditsFor returns true when the AST attributed an auditEvent call
// to the metadata method's scope.
func astAuditsFor(beh *handlerBehavior, method string) bool {
	if method == MethodAny {
		for _, mb := range beh.byMethod {
			if mb.callsAudit {
				return true
			}
		}
		return false
	}
	if mb := beh.byMethod[method]; mb != nil {
		return mb.callsAudit
	}
	return false
}

// isMutatingMethod returns true for HTTP methods that conventionally
// change state. Mirrors securityMiddleware's isMutating expression.
func isMutatingMethod(method string) bool {
	switch method {
	case "POST", "PUT", "DELETE", "PATCH":
		return true
	}
	return false
}

// sortedKeys returns the sorted keys of a string-keyed map.
func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ── Conservative per-method context walker ────────────────────────────────
//
// walkBodyPerMethod walks the top-level statements of a function body
// sequentially, maintaining an "active method" that defaults to
// MethodAny. The active method is narrowed only for stable, obvious
// patterns:
//
//   • switch r.Method { case http.MethodX: ... } — calls inside that
//     case body are attributed to X. Default case inherits the active
//     method from outside the switch.
//   • if r.Method != http.MethodX { ...return... } at the top level —
//     all subsequent top-level statements are attributed to X (the
//     gate-before-handle pattern). The if body is NOT scanned (it only
//     runs on the rejected path).
//
// Anything else falls under MethodAny. The walker is intentionally
// conservative; it does not attempt to follow control flow into nested
// blocks, helper-function calls, or complex conditionals.

func walkBodyPerMethod(body *ast.BlockStmt, active string, beh *handlerBehavior) {
	if body == nil {
		return
	}
	for _, stmt := range body.List {
		switch s := stmt.(type) {
		case *ast.IfStmt:
			if guarded, ok := classifyMethodReturnGuard(s); ok {
				// "if r.Method != http.MethodX { return }" — narrow active method.
				active = guarded
				continue
			}
			// Generic if — recurse with current active method.
			collectMethodCalls(s, active, beh)

		case *ast.SwitchStmt:
			if isSwitchOnRequestMethod(s) {
				for _, c := range s.Body.List {
					cc, ok := c.(*ast.CaseClause)
					if !ok {
						continue
					}
					methods := extractMethodsFromCase(cc)
					if len(methods) == 0 {
						// default case — inherits the outer active method.
						for _, st := range cc.Body {
							collectMethodCalls(st, active, beh)
						}
						continue
					}
					for _, m := range methods {
						for _, st := range cc.Body {
							collectMethodCalls(st, m, beh)
						}
					}
				}
				continue
			}
			// Generic switch — recurse with current active method.
			collectMethodCalls(s, active, beh)

		default:
			collectMethodCalls(s, active, beh)
		}
	}
}

// collectMethodCalls walks every requireRole / auditEvent call inside
// node and attributes each to method.
func collectMethodCalls(node ast.Node, method string, beh *handlerBehavior) {
	ast.Inspect(node, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		id, ok := call.Fun.(*ast.Ident)
		if !ok {
			return true
		}
		switch id.Name {
		case "auditEvent", "auditEventDiff", "auditEventDiffID":
			beh.recordAudit(method)
		case "requireRole":
			if role := extractRequireRoleArg(call); role != "" {
				beh.recordRole(method, role)
			}
		}
		return true
	})
}

// extractRequireRoleArg returns the UIRole value from a requireRole(w, r, X)
// call, or "" if the third argument is not in a recognised form.
//
// Two forms are recognised:
//   - Named constant: requireRole(w, r, RoleAdmin) — *ast.Ident
//   - String literal: requireRole(w, r, "admin")  — *ast.BasicLit (STRING)
//
// The string-literal form is used in update.go / update_cluster.go and
// would otherwise be invisible to AST detection.
func extractRequireRoleArg(call *ast.CallExpr) UIRole {
	if len(call.Args) < 3 {
		return ""
	}
	switch a := call.Args[2].(type) {
	case *ast.Ident:
		return identToRole(a.Name)
	case *ast.BasicLit:
		if a.Kind != token.STRING {
			return ""
		}
		// Strip surrounding quotes from the literal.
		s := a.Value
		if len(s) >= 2 && (s[0] == '"' || s[0] == '`') {
			s = s[1 : len(s)-1]
		}
		switch s {
		case "admin":
			return RoleAdmin
		case "operator":
			return RoleOperator
		case "viewer":
			return RoleViewer
		case "public":
			return RolePublic
		}
	}
	return ""
}

// classifyMethodReturnGuard recognises `if r.Method != http.MethodX { ...; return }`
// at top level. Returns (X, true) on match, ("", false) otherwise.
// Conservative: requires a bare != comparison, no else clause, and a
// return statement somewhere in the body.
func classifyMethodReturnGuard(s *ast.IfStmt) (string, bool) {
	if s.Else != nil || s.Init != nil {
		return "", false
	}
	bin, ok := s.Cond.(*ast.BinaryExpr)
	if !ok || bin.Op != token.NEQ {
		return "", false
	}
	method := extractMethodLiteral(bin.X)
	if method == "" {
		method = extractMethodLiteral(bin.Y)
	}
	if method == "" {
		return "", false
	}
	if !exprIsRequestMethod(bin.X) && !exprIsRequestMethod(bin.Y) {
		return "", false
	}
	// Body must contain at least one return statement.
	bodyHasReturn := false
	for _, stmt := range s.Body.List {
		if _, ok := stmt.(*ast.ReturnStmt); ok {
			bodyHasReturn = true
			break
		}
	}
	if !bodyHasReturn {
		return "", false
	}
	return method, true
}

// extractMethodLiteral returns "POST" / "GET" / etc. when expr is a
// http.MethodX selector, or "" otherwise.
func extractMethodLiteral(expr ast.Expr) string {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "http" {
		return ""
	}
	if !strings.HasPrefix(sel.Sel.Name, "Method") || sel.Sel.Name == "Method" {
		return ""
	}
	return strings.ToUpper(strings.TrimPrefix(sel.Sel.Name, "Method"))
}

// exprIsRequestMethod returns true when expr looks like a `.Method`
// field access (e.g. `r.Method`). Receiver name is not validated.
func exprIsRequestMethod(expr ast.Expr) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	return sel.Sel.Name == "Method"
}

// isSwitchOnRequestMethod returns true when s is `switch r.Method { ... }`.
func isSwitchOnRequestMethod(s *ast.SwitchStmt) bool {
	return s.Tag != nil && exprIsRequestMethod(s.Tag)
}

// extractMethodsFromCase returns each "POST"/"GET"/... method
// constant in a `case http.MethodX [, http.MethodY]:` clause. Empty
// for the default case.
func extractMethodsFromCase(cc *ast.CaseClause) []string {
	out := make([]string, 0, len(cc.List))
	for _, expr := range cc.List {
		if m := extractMethodLiteral(expr); m != "" {
			out = append(out, m)
		}
	}
	return out
}

// ── Per-method dump (review aid for schema migration) ─────────────────────

// TestC15_Dump_PerMethodFindings prints, for every handler referenced by
// uiRoutes, the per-method AST findings produced by the upgraded
// scanner. The output is the source-of-truth input for migrating
// uiRoutes from single-MinRole to per-method shape.
//
// This test always passes; it is a reporting tool, not a regression
// gate. Run with -v:
//
//	go test -count=1 -v -run TestC15_Dump_PerMethodFindings ./...
func TestC15_Dump_PerMethodFindings(t *testing.T) {
	handlers := scanHandlers(t)

	// Stable iteration: walk uiRoutes in definition order, dedup by handler.
	seen := make(map[string]bool, len(uiRoutes))
	type row struct {
		handler string
		path    string
		file    string
		line    int
		methods []string // formatted per-method lines
	}
	var rows []row

	methodOrder := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", MethodAny}

	for _, r := range uiRoutes {
		if seen[r.Handler] {
			continue
		}
		seen[r.Handler] = true

		beh, ok := handlers[r.Handler]
		if !ok {
			rows = append(rows, row{
				handler: r.Handler,
				path:    r.Path,
				methods: []string{"  HANDLER NOT FOUND (closure / method / generated)"},
			})
			continue
		}

		var lines []string
		for _, m := range methodOrder {
			mb, ok := beh.byMethod[m]
			if !ok {
				continue
			}
			roles := uniqRoles(mb.rolesSeen)
			minRoleStr := string(mb.minRole())
			if minRoleStr == "" {
				minRoleStr = "(none)"
			}
			audit := "no"
			if mb.callsAudit {
				audit = "yes"
			}
			lines = append(lines, fmt.Sprintf(
				"  %-7s minRole=%-10s audit=%-3s rolesSeen=%v",
				m, minRoleStr, audit, roles))
		}
		// If byMethod is empty entirely (handler has no requireRole/audit calls),
		// note that explicitly.
		if len(lines) == 0 {
			lines = []string{"  (no requireRole or auditEvent calls anywhere — likely public, delegated, or routing-only)"}
		}

		// Also include the aggregate http.MethodX literal set for context.
		methodLits := sortedKeys(beh.rawMethods)
		if len(methodLits) == 0 {
			lines = append(lines, "  http.MethodX literals seen: (none)")
		} else {
			lines = append(lines, fmt.Sprintf("  http.MethodX literals seen: %v", methodLits))
		}

		rows = append(rows, row{
			handler: r.Handler,
			path:    r.Path,
			file:    beh.file,
			line:    beh.line,
			methods: lines,
		})
	}

	// Stable output: alphabetical by handler.
	sort.Slice(rows, func(i, j int) bool { return rows[i].handler < rows[j].handler })

	var sb strings.Builder
	fmt.Fprintf(&sb, "\n──── C1.5 Per-Method AST Dump (%d unique handlers) ────\n", len(rows))
	for _, r := range rows {
		loc := ""
		if r.file != "" {
			loc = fmt.Sprintf(" %s:%d", r.file, r.line)
		}
		fmt.Fprintf(&sb, "\n%s (path=%q)%s\n", r.handler, r.path, loc)
		for _, l := range r.methods {
			fmt.Fprintln(&sb, l)
		}
	}
	t.Log(sb.String())
}

// uniqRoles returns the unique roles in slice (preserving sort order).
func uniqRoles(roles []UIRole) []UIRole {
	seen := map[UIRole]bool{}
	var out []UIRole
	for _, r := range roles {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return rolePriorityOf(out[i]) < rolePriorityOf(out[j]) })
	return out
}
