//go:build linux

package main

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"testing"
)

func swapVTMode(t *testing.T, get func(int) (int, error), set func(int, int) error) {
	t.Helper()
	oldGet, oldSet := vtGetMode, vtSetMode
	vtGetMode, vtSetMode = get, set
	t.Cleanup(func() { vtGetMode, vtSetMode = oldGet, oldSet })
}

// A VT left in graphics mode (the plymouth device-wait exit) is put back in
// text mode on the descriptor the console was handed.
func TestEnsureTextMode_RestoresGraphicsMode(t *testing.T) {
	var gotFD, gotMode = -1, -1
	swapVTMode(t, func(int) (int, error) { return 1 /* KD_GRAPHICS */, nil },
		func(fd, mode int) error { gotFD, gotMode = fd, mode; return nil })
	changed, err := ensureTextMode(7)
	if err != nil || !changed || gotFD != 7 || gotMode != kdText {
		t.Fatalf("changed=%v err=%v fd=%d mode=%d", changed, err, gotFD, gotMode)
	}
}

// Text mode is left alone: no write, so no repaint flicker on a healthy boot.
func TestEnsureTextMode_TextModeIsUntouched(t *testing.T) {
	swapVTMode(t, func(int) (int, error) { return kdText, nil },
		func(int, int) error { t.Fatal("KDSETMODE issued on a VT already in text mode"); return nil })
	if changed, err := ensureTextMode(0); err != nil || changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
}

func TestEnsureTextMode_ReportsFailures(t *testing.T) {
	boom := errors.New("boom")
	swapVTMode(t, func(int) (int, error) { return 0, boom }, func(int, int) error { t.Fatal("set after a failed get"); return nil })
	if changed, err := ensureTextMode(0); !errors.Is(err, boom) || changed {
		t.Fatalf("get failure: changed=%v err=%v", changed, err)
	}
	swapVTMode(t, func(int) (int, error) { return 1, nil }, func(int, int) error { return boom })
	if changed, err := ensureTextMode(0); !errors.Is(err, boom) || changed {
		t.Fatalf("set failure: changed=%v err=%v", changed, err)
	}
}

// The real ioctls on a descriptor that is not a VT fail without side effects.
func TestEnsureTextMode_NonVTIsAnError(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if changed, err := ensureTextMode(int(r.Fd())); err == nil || changed {
		t.Fatalf("pipe accepted as a VT: changed=%v err=%v", changed, err)
	}
}

// runTerminal repairs the VT in login mode (tty1) before every menu frame,
// after the terminal boundary check; never in admin mode, whose terminal is an
// SSH pty or another user's VT. The call must be a direct statement on fd 0:
// one hidden in a closure, a nested branch or on another descriptor fails.
func TestRunTerminal_RepairsTextModeBeforeEveryMenuFrame(t *testing.T) {
	validate, loopBody := runTerminalShape(t)
	if validate < 0 || loopBody == nil || len(loopBody.List) < 2 {
		t.Fatal("want validateTerminal before the menu loop")
	}
	guard, ok := loopBody.List[0].(*ast.IfStmt)
	if !ok || guard.Init != nil || guard.Else != nil {
		t.Fatal("the menu loop must open with `if !admin { ensureTextMode(0) }`")
	}
	if u, ok := guard.Cond.(*ast.UnaryExpr); !ok || u.Op != token.NOT || !identNamed(u.X, "admin") {
		t.Fatal("the text-mode repair must be gated on !admin")
	}
	if !hasDirectRepair(guard.Body) {
		t.Fatal("ensureTextMode(0) must be a direct statement in the !admin branch")
	}
	if !isCallTo(firstCall(loopBody.List[1]), "menu") {
		t.Fatal("the repair must come immediately before the menu frame")
	}
}

// runTerminalShape returns the index of the validateTerminal check in
// runTerminal (-1 if absent) and the body of the first loop after it.
func runTerminalShape(t *testing.T) (validate int, loopBody *ast.BlockStmt) {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "terminal_linux.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	validate = -1
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "runTerminal" {
			continue
		}
		for i, stmt := range fn.Body.List {
			if s, ok := stmt.(*ast.IfStmt); ok && validate < 0 && isCallTo(firstCall(s.Init), "validateTerminal") {
				validate = i
			}
			if s, ok := stmt.(*ast.ForStmt); ok && validate >= 0 && loopBody == nil {
				loopBody = s.Body
			}
		}
	}
	return validate, loopBody
}

// hasDirectRepair reports a top-level `ensureTextMode(0)` statement.
func hasDirectRepair(body *ast.BlockStmt) bool {
	for _, stmt := range body.List {
		call := firstCall(stmt)
		if es, ok := stmt.(*ast.ExprStmt); ok {
			call = es.X
		}
		c, ok := call.(*ast.CallExpr)
		if !ok || !isCallTo(c, "ensureTextMode") || len(c.Args) != 1 {
			continue
		}
		if lit, ok := c.Args[0].(*ast.BasicLit); ok && lit.Kind == token.INT && lit.Value == "0" {
			return true
		}
	}
	return false
}

func identNamed(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}

func isCallTo(e ast.Expr, name string) bool {
	c, ok := e.(*ast.CallExpr)
	return ok && identNamed(c.Fun, name)
}

func firstCall(stmt ast.Stmt) ast.Expr {
	if a, ok := stmt.(*ast.AssignStmt); ok && len(a.Rhs) == 1 {
		return a.Rhs[0]
	}
	return nil
}
