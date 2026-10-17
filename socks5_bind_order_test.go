package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// The bind loop must publish the server (adopt) before it records the bind
// (noteSOCKS5Bound): the record feeds /healthz "ready", the binds counter and
// listener_up, and a reader acting on it must find Addr() non-nil. The
// reverse order was an intermittent failure of
// TestChaos66_ListenerRebindsOnceThePortIsFree on the determinism gate; a
// scheduling window cannot be forced from a test, so the ORDER is pinned.
func TestSOCKS5Bind_PublishesBeforeRecordingTheBind(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "socks5_bind.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var adoptPos, notePos token.Pos
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fn := call.Fun.(type) {
		case *ast.SelectorExpr:
			if fn.Sel.Name == "adopt" && adoptPos == token.NoPos {
				adoptPos = call.Pos()
			}
		case *ast.Ident:
			if fn.Name == "noteSOCKS5Bound" && notePos == token.NoPos {
				notePos = call.Pos()
			}
		}
		return true
	})
	if adoptPos == token.NoPos || notePos == token.NoPos {
		t.Fatalf("selector matched nothing (adopt=%v noteSOCKS5Bound=%v); the gate would be vacuous", adoptPos, notePos)
	}
	if adoptPos > notePos {
		t.Fatalf("noteSOCKS5Bound (%s) runs before adopt (%s): surfaces report a bound listener whose address is still nil",
			fset.Position(notePos), fset.Position(adoptPos))
	}
}
