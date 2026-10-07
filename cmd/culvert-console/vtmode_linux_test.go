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

// The request numbers are linux/kd.h's; a typo would silently do nothing.
func TestEnsureTextMode_KernelConstants(t *testing.T) {
	if kdSetMode != 0x4B3A || kdGetMode != 0x4B3B || kdText != 0 {
		t.Fatal("console-mode ioctl constants drifted from linux/kd.h")
	}
}

// runTerminal repairs the VT in login mode (tty1), after the terminal
// boundary check and before the first menu frame; never in admin mode, whose
// terminal is an SSH pty or another user's VT.
func TestRunTerminal_RepairsTextModeBeforeTheMenu(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "terminal_linux.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var body *ast.BlockStmt
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "runTerminal" {
			body = fn.Body
		}
	}
	if body == nil {
		t.Fatal("runTerminal not found")
	}
	validate, repair, loop := -1, -1, -1
	for i, stmt := range body.List {
		switch s := stmt.(type) {
		case *ast.IfStmt:
			if init, ok := s.Init.(*ast.AssignStmt); ok && callsNamed(init, "validateTerminal") {
				validate = i
			}
			if u, ok := s.Cond.(*ast.UnaryExpr); ok && u.Op == token.NOT && identNamed(u.X, "admin") && callsNamed(s.Body, "ensureTextMode") {
				repair = i
			}
		case *ast.ForStmt:
			if loop < 0 {
				loop = i
			}
		}
	}
	if validate < 0 || repair < 0 || loop < 0 || validate >= repair || repair >= loop {
		t.Fatalf("want validateTerminal < if !admin { ensureTextMode } < menu loop, got %d %d %d", validate, repair, loop)
	}
}

func identNamed(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}

func callsNamed(n ast.Node, name string) bool {
	found := false
	ast.Inspect(n, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok && identNamed(c.Fun, name) {
			found = true
		}
		return !found
	})
	return found
}
