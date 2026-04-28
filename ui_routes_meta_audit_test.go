package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
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

// handlerBehavior aggregates all three C1.5 signals for one handler.
type handlerBehavior struct {
	file       string
	line       int
	rawMethods map[string]bool // "GET", "POST", ... presence of http.MethodX literal
	methods    methodClassification
	minRole    minRoleClassification
	callsAudit bool // any direct auditEvent or auditEventDiff call
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

	entries, err := os.ReadDir(".")
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
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
func analyzeHandler(fn *ast.FuncDecl) *handlerBehavior {
	beh := &handlerBehavior{rawMethods: map[string]bool{}}
	if fn.Body == nil {
		return beh
	}
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
			case "auditEvent", "auditEventDiff":
				beh.callsAudit = true
			case "requireRole":
				if len(x.Args) >= 3 {
					if rid, ok := x.Args[2].(*ast.Ident); ok {
						if role := identToRole(rid.Name); role != "" {
							beh.minRole.rolesSeen = append(beh.minRole.rolesSeen, role)
							if !beh.minRole.confident || rolePriorityOf(role) < rolePriorityOf(beh.minRole.minRole) {
								beh.minRole.minRole = role
							}
							beh.minRole.confident = true
						}
					}
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

// ── Test 1: MinRole parity ────────────────────────────────────────────────

// TestC15_MinRole_MetadataMatchesHandler reports cases where the
// MinRole declared in uiRoutes does not match the lowest role any
// direct requireRole call in the handler permits.
//
// Failure modes:
//
//   - Public route whose handler nonetheless calls requireRole — fails.
//   - Non-public route whose handler has no direct requireRole call —
//     logged as UNKNOWN (handler may delegate to a helper that gates).
//   - Non-public route where metadata MinRole differs from the lowest
//     requireRole role in the handler body — fails.
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
		if r.Public {
			if beh.minRole.confident {
				mismatches = append(mismatches, fmt.Sprintf(
					"  %s (path=%q, file=%s:%d): metadata Public=true but handler calls requireRole(%v)",
					r.Handler, r.Path, beh.file, beh.line, beh.minRole.rolesSeen))
			}
			continue
		}
		if !beh.minRole.confident {
			unknowns = append(unknowns, fmt.Sprintf(
				"  %s (path=%q, file=%s:%d): non-public route but no direct requireRole call (may delegate to a helper) — metadata MinRole=%s",
				r.Handler, r.Path, beh.file, beh.line, r.MinRole))
			continue
		}
		if beh.minRole.minRole != r.MinRole {
			mismatches = append(mismatches, fmt.Sprintf(
				"  %s (path=%q, file=%s:%d): metadata MinRole=%s, handler lowest requireRole=%s (rolesSeen=%v)",
				r.Handler, r.Path, beh.file, beh.line, r.MinRole, beh.minRole.minRole, beh.minRole.rolesSeen))
		}
	}

	if len(unknowns) > 0 {
		t.Logf("C1.5 MinRole — %d UNKNOWN (informational, not failing):\n%s", len(unknowns), sortedJoin(unknowns))
	}
	if len(mismatches) > 0 {
		t.Errorf("C1.5 MinRole — %d MISMATCHES:\n%s", len(mismatches), sortedJoin(mismatches))
	}
}

// ── Test 2: Mutating parity ───────────────────────────────────────────────

// TestC15_Mutating_MetadataMatchesHandler reports cases where the
// Mutating flag in uiRoutes contradicts the http.MethodX literals
// observed in the handler body.
//
// Failure modes:
//
//   - Mutating=true but handler references no POST/PUT/DELETE/PATCH literal
//     and DOES reference at least one read-only method literal — fails.
//   - Mutating=false but handler references at least one
//     POST/PUT/DELETE/PATCH literal — fails.
//   - Handler references no http.MethodX literal at all — UNKNOWN (handler
//     may not gate on method, or may delegate). Logged.
func TestC15_Mutating_MetadataMatchesHandler(t *testing.T) {
	handlers := scanHandlers(t)
	var mismatches, unknowns []string

	for _, r := range uiRoutes {
		beh, ok := handlers[r.Handler]
		if !ok {
			continue // already covered as UNKNOWN by the MinRole test
		}
		switch beh.methods {
		case methodsUnknown:
			unknowns = append(unknowns, fmt.Sprintf(
				"  %s (path=%q, file=%s:%d): no http.MethodX literal in body — metadata Mutating=%v",
				r.Handler, r.Path, beh.file, beh.line, r.Mutating))
		case methodsMutating:
			if !r.Mutating {
				mismatches = append(mismatches, fmt.Sprintf(
					"  %s (path=%q, file=%s:%d): metadata Mutating=false, handler references mutating method(s): %v",
					r.Handler, r.Path, beh.file, beh.line, sortedKeys(beh.rawMethods)))
			}
		case methodsReadOnly:
			if r.Mutating {
				mismatches = append(mismatches, fmt.Sprintf(
					"  %s (path=%q, file=%s:%d): metadata Mutating=true, handler references only read-only method(s): %v",
					r.Handler, r.Path, beh.file, beh.line, sortedKeys(beh.rawMethods)))
			}
		}
	}

	if len(unknowns) > 0 {
		t.Logf("C1.5 Mutating — %d UNKNOWN (informational):\n%s", len(unknowns), sortedJoin(unknowns))
	}
	if len(mismatches) > 0 {
		t.Errorf("C1.5 Mutating — %d MISMATCHES:\n%s", len(mismatches), sortedJoin(mismatches))
	}
}

// ── Test 3: AuditExpected parity ──────────────────────────────────────────

// TestC15_AuditExpected_MetadataMatchesHandler reports cases where the
// AuditExpected flag in uiRoutes contradicts whether the handler body
// directly invokes auditEvent or auditEventDiff.
//
// Failure modes:
//
//   - AuditExpected=true but handler has no direct audit call — UNKNOWN
//     (handler may delegate to a helper that audits). Logged, not failed.
//   - AuditExpected=false but handler does call audit directly — fails
//     (the metadata is hiding an audit event the handler genuinely emits).
//
// Asymmetric on purpose: false negatives ("we said true but it's a
// helper that audits") are common and acceptable in C1.5 shadow mode;
// false positives ("we said false but it audits anyway") are noise the
// metadata should reflect.
func TestC15_AuditExpected_MetadataMatchesHandler(t *testing.T) {
	handlers := scanHandlers(t)
	var mismatches, unknowns []string

	for _, r := range uiRoutes {
		beh, ok := handlers[r.Handler]
		if !ok {
			continue
		}
		if r.AuditExpected && !beh.callsAudit {
			unknowns = append(unknowns, fmt.Sprintf(
				"  %s (path=%q, file=%s:%d): metadata AuditExpected=true but no direct auditEvent call (may delegate)",
				r.Handler, r.Path, beh.file, beh.line))
		}
		if !r.AuditExpected && beh.callsAudit {
			mismatches = append(mismatches, fmt.Sprintf(
				"  %s (path=%q, file=%s:%d): metadata AuditExpected=false but handler directly calls auditEvent",
				r.Handler, r.Path, beh.file, beh.line))
		}
	}

	if len(unknowns) > 0 {
		t.Logf("C1.5 AuditExpected — %d UNKNOWN (informational):\n%s", len(unknowns), sortedJoin(unknowns))
	}
	if len(mismatches) > 0 {
		t.Errorf("C1.5 AuditExpected — %d MISMATCHES:\n%s", len(mismatches), sortedJoin(mismatches))
	}
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
