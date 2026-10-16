package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── SEC-ADMISSION-OWNER-1, round 3 ──────────────────────────────────────────
//
// The owner walls in admission_owner_wall_test.go resolve the limiter's
// binding at two syntactic hops: DataPlaneClient.Run must pass the
// package-level `rl`, and rateLimitGossipLoop must keep the parameter it was
// handed. Both reason INSIDE those functions.
//
// That leaves the package handle itself unguarded. `Run` captures the pointer
// value when it starts the gossip loop, while the request path reads the
// global on every request — so a reassignment anywhere else in production
// (`rl = newRateLimiter()` in a startup or reconfiguration helper) splits the
// owner after the fact: requests enforce with the new limiter, gossip keeps
// feeding the old one, the live budget is discarded, and the enforcing limiter
// is never armed. That is the same silent per-node degradation the other walls
// exist to prevent, reached from outside their scope.
//
// Reproduced before writing this: adding such a function to admission.go left
// every TestAdmissionOwner_ test passing (Codex P2, PR #1584).
//
// ADR-0038's boundary map already states the invariant — "No production
// reassignment of rl" — so this gate enforces a rule the design recorded and
// nothing checked. The package-level `var rl = newRateLimiter()` DECLARATION
// in admission.go is the one permitted write; tests may still rebind the
// handle through their own helpers, so only non-test files are scanned.
//
// It lives in its own file rather than beside the other walls so that it
// merges cleanly alongside concurrent edits to them.

// pkgSourcePath anchors a package source filename to the package source
// directory, so a parse resolves the same file whatever the process working
// directory is. pkgSourceDir() is itself anchored via runtime.Caller.
func pkgSourcePath(filename string) string {
	return filepath.Join(pkgSourceDir(), filename)
}

// localShadow is one declaration of the handle's name that shadows the package
// handle: pos is where it becomes visible, [lo, hi) is the scope it is visible in.
type localShadow struct {
	pos, lo, hi token.Pos
}

// scopeExtent reports the extent of the scope a node opens, if it opens one.
func scopeExtent(n ast.Node) (lo, hi token.Pos, opens bool) {
	switch v := n.(type) {
	case *ast.BlockStmt:
		return v.Lbrace, v.Rbrace, true
	case *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt,
		*ast.TypeSwitchStmt, *ast.CaseClause, *ast.CommClause, *ast.FuncLit:
		return n.Pos(), n.End(), true
	}
	return 0, 0, false
}

// handleScan is the per-function result of resolving one name: every local
// declaration that shadows the package handle, and every `=` write to the name.
type handleScan struct {
	shadows []localShadow
	writes  []token.Pos
}

// signatureShadows returns the shadow a receiver, parameter or named result
// named name casts over the whole body.
func signatureShadows(fn *ast.FuncDecl, name string) []localShadow {
	var out []localShadow
	for _, fl := range []*ast.FieldList{fn.Recv, fn.Type.Params, fn.Type.Results} {
		if fl == nil {
			continue
		}
		for _, f := range fl.List {
			for _, id := range f.Names {
				if id.Name == name {
					out = append(out, localShadow{pos: fn.Body.Lbrace, lo: fn.Body.Lbrace, hi: fn.Body.Rbrace})
				}
			}
		}
	}
	return out
}

// enclosingScope walks the ancestor stack outward from at and returns the
// extent of the nearest scope-opening node, defaulting to the function body.
func enclosingScope(stack []ast.Node, at int, body *ast.BlockStmt) (lo, hi token.Pos) {
	for i := at; i >= 0; i-- {
		if l, h, opens := scopeExtent(stack[i]); opens {
			return l, h
		}
	}
	return body.Lbrace, body.Rbrace
}

// assignNode records a `:=` shadow or an `=` write to name from one assignment.
func (sc *handleScan) assignNode(v *ast.AssignStmt, name string, scope func() (token.Pos, token.Pos)) {
	for _, lhs := range v.Lhs {
		id, ok := lhs.(*ast.Ident)
		if !ok || id.Name != name {
			continue
		}
		switch v.Tok {
		case token.DEFINE:
			lo, hi := scope()
			sc.shadows = append(sc.shadows, localShadow{pos: id.Pos(), lo: lo, hi: hi})
		case token.ASSIGN:
			sc.writes = append(sc.writes, id.Pos())
		}
	}
}

// varNode records a `var name …` shadow.
func (sc *handleScan) varNode(v *ast.GenDecl, name string, scope func() (token.Pos, token.Pos)) {
	if v.Tok != token.VAR {
		return
	}
	for _, spec := range v.Specs {
		vs, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for _, id := range vs.Names {
			if id.Name == name {
				lo, hi := scope()
				sc.shadows = append(sc.shadows, localShadow{pos: id.Pos(), lo: lo, hi: hi})
			}
		}
	}
}

// rangeNode records a `for name := range …` shadow, scoped to the range stmt.
func (sc *handleScan) rangeNode(v *ast.RangeStmt, name string) {
	if v.Tok != token.DEFINE {
		return
	}
	for _, k := range []ast.Expr{v.Key, v.Value} {
		if id, ok := k.(*ast.Ident); ok && id.Name == name {
			sc.shadows = append(sc.shadows, localShadow{pos: id.Pos(), lo: v.Pos(), hi: v.End()})
		}
	}
}

// scanFuncForHandle collects the shadows and writes of name within fn.
func scanFuncForHandle(fn *ast.FuncDecl, name string) handleScan {
	sc := handleScan{shadows: signatureShadows(fn, name)}
	var stack []ast.Node
	ast.Inspect(fn, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		stack = append(stack, n)
		scope := func() (token.Pos, token.Pos) {
			return enclosingScope(stack, len(stack)-2, fn.Body)
		}
		switch v := n.(type) {
		case *ast.AssignStmt:
			sc.assignNode(v, name, scope)
		case *ast.GenDecl:
			sc.varNode(v, name, scope)
		case *ast.RangeStmt:
			sc.rangeNode(v, name)
		}
		return true
	})
	return sc
}

// shadowedAt reports whether a declaration of the handle's name is visible at
// pos: in an enclosing scope, and lexically before it.
func shadowedAt(shadows []localShadow, pos token.Pos) bool {
	for _, sh := range shadows {
		if sh.pos <= pos && pos >= sh.lo && pos < sh.hi {
			return true
		}
	}
	return false
}

// assignsPackageHandle reports the functions in file that assign to the
// PACKAGE-LEVEL name.
//
// Shadowing is resolved PER ASSIGNMENT, not per function. An earlier version
// computed one `local` flag over the whole body and skipped the function when
// it was set, so a helper that both wrote the global AND separately declared an
// unrelated inner local of the same name —
//
//	rl = newRateLimiter()                     // the regression
//	if b { rl := newRateLimiter(); _ = rl }    // unrelated shadow
//
// — was skipped entirely, and the wall accepted the exact split-owner
// regression it exists to prevent (Codex P2 on fad9ca6). An assignment is a
// write to the global unless a declaration of that name is visible AT THAT
// ASSIGNMENT: in an enclosing scope, and lexically before it.
func assignsPackageHandle(file *ast.File, name string) []string {
	var out []string
	for _, d := range file.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		sc := scanFuncForHandle(fn, name)
		for _, w := range sc.writes {
			if !shadowedAt(sc.shadows, w) {
				out = append(out, fn.Name.Name)
				break
			}
		}
	}
	return out
}

// Nothing in production may reassign the admission composition handle.
func TestAdmissionOwner_Wall_NoProductionReassignmentOfTheOwner(t *testing.T) {
	// Both the enumeration AND the parse are anchored to the package source dir,
	// never to the process CWD: a concurrent test's os.Chdir would otherwise make
	// this scan read another directory (TestTestFileReadsAreCWDIndependent is the
	// wall for that class). Anchoring only the ReadDir would satisfy that wall's
	// literal check while leaving the parse exposed to the same race.
	dir := pkgSourceDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	scanned := 0
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, filepath.Join(dir, n), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", n, err)
		}
		scanned++
		for _, fn := range assignsPackageHandle(f, "rl") {
			t.Errorf("%s: %s reassigns the package-level admission handle `rl`. "+
				"DataPlaneClient.Run captured the previous pointer for the gossip loop, so after this "+
				"the request path enforces with one limiter while gossip feeds another — the split owner "+
				"is silent (an un-armed limiter is never reported stale) and the live budget is discarded. "+
				"ADR-0038 records this as 'No production reassignment of rl' (SEC-ADMISSION-OWNER-1)", n, fn)
		}
	}
	// Not-vacuous: the scan must actually have read the package.
	if scanned < 10 {
		t.Fatalf("only %d non-test files scanned; this gate's selector has gone stale", scanned)
	}

	// CONTROLS: the same predicate must REJECT the shapes this gate exists to
	// catch, and must ACCEPT the declaration and a local of the same name.
	for name, tc := range map[string]struct {
		src  string
		want bool
	}{
		"reassignment in a helper":  {"package main\nfunc reconfigure() { rl = newRateLimiter() }", true},
		"reassignment in a branch":  {"package main\nfunc reconfigure(b bool) { if b { rl = newRateLimiter() } }", true},
		"package declaration only":  {"package main\nvar rl = newRateLimiter()", false},
		"local of the same name":    {"package main\nfunc h() { rl := newRateLimiter(); rl = newRateLimiter(); _ = rl }", false},
		"unrelated global assigned": {"package main\nfunc h() { other = newRateLimiter() }", false},

		// Codex P2 on fad9ca6: a global write PLUS an unrelated inner shadow.
		// The pre-fix predicate set one per-function `local` flag and skipped
		// the whole function, so it reported nothing for this input — the wall
		// accepted the very regression it exists to prevent.
		"global write beside an inner shadow": {
			"package main\nfunc h(b bool) { rl = newRateLimiter(); if b { rl := newRateLimiter(); _ = rl } }", true},
		"inner shadow written, global untouched": {
			"package main\nfunc h(b bool) { if b { rl := newRateLimiter(); rl = newRateLimiter(); _ = rl } }", false},
		"write before the local is in scope": {
			"package main\nfunc h() { rl = newRateLimiter(); rl := newRateLimiter(); _ = rl }", true},
		"var-declared local shadows": {
			"package main\nfunc h() { var rl *RateLimiter; rl = newRateLimiter(); _ = rl }", false},
		"parameter shadows": {
			"package main\nfunc h(rl *RateLimiter) { rl = newRateLimiter() }", false},
		"closure writes the global": {
			"package main\nfunc h() { go func() { rl = newRateLimiter() }() }", true},
	} {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "control.go", tc.src, 0)
		if err != nil {
			t.Fatalf("parse %s control: %v", name, err)
		}
		if got := len(assignsPackageHandle(f, "rl")) > 0; got != tc.want {
			t.Errorf("control %q: flagged=%v, want %v — this gate is matching the wrong thing", name, got, tc.want)
		}
	}
}
