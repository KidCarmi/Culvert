package catdb

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strings"
	"testing"
)

// guardCalls are the CommunityDB methods that arm containment (and, for access,
// the degraded refusal). A closure passed directly to one of them is GUARDED.
var guardCalls = map[string]bool{"access": true, "contain": true}

// guardedOnlyHelpers may touch c.db outside a guard closure because they are
// reachable ONLY from inside one. The wall checks that claim: every call to
// them must sit inside a guard closure or inside another helper on this list.
var guardedOnlyHelpers = map[string]string{
	"walk":     "the domain walk; called only from Lookup's access closure",
	"getExact": "one point read; called only from walk",
}

// noBadgerAccess are exported methods that must never touch badger at all.
// Each carries the reason it needs no guard.
var noBadgerAccess = map[string]string{
	"LookupFaults":             "reads three atomics; must stay answerable on a dead store",
	"SetBulkWriteFaultForTest": "test seam; assigns the writeFault func field, never touches badger",
}

// communityDBMethods parses the package's non-test sources and returns every
// method declared on *CommunityDB, plus the receiver identifier each one uses.
func communityDBMethods(t *testing.T) map[string]*ast.FuncDecl {
	t.Helper()
	ents, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*ast.FuncDecl{}
	fset := token.NewFileSet()
	for _, e := range ents {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || len(fn.Recv.List) != 1 || fn.Body == nil {
				continue
			}
			star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
			if !ok {
				continue
			}
			if id, ok := star.X.(*ast.Ident); ok && id.Name == "CommunityDB" {
				out[fn.Name.Name] = fn
			}
		}
	}
	return out
}

func recvName(fn *ast.FuncDecl) string {
	if names := fn.Recv.List[0].Names; len(names) == 1 {
		return names[0].Name
	}
	return ""
}

// inGuardClosure reports whether the innermost-first ancestor stack contains a
// function literal passed directly as an argument to recv.access / recv.contain.
func inGuardClosure(stack []ast.Node, recv string) bool {
	for i := len(stack) - 1; i > 0; i-- {
		lit, ok := stack[i].(*ast.FuncLit)
		if !ok {
			continue
		}
		call, ok := stack[i-1].(*ast.CallExpr)
		if !ok {
			continue
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !guardCalls[sel.Sel.Name] {
			continue
		}
		if id, ok := sel.X.(*ast.Ident); !ok || id.Name != recv {
			continue
		}
		for _, arg := range call.Args {
			if arg == lit {
				return true
			}
		}
	}
	return false
}

// inspectWithStack walks n, calling visit with each node and its ancestors.
func inspectWithStack(n ast.Node, visit func(node ast.Node, stack []ast.Node)) {
	var stack []ast.Node
	ast.Inspect(n, func(node ast.Node) bool {
		if node == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		visit(node, stack)
		stack = append(stack, node)
		return true
	})
}

// recvSelector reports whether node is recv.<field> and returns field.
func recvSelector(node ast.Node, recv string) (string, bool) {
	sel, ok := node.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok || id.Name != recv {
		return "", false
	}
	return sel.Sel.Name, true
}

// TestCommunityDB_EveryBadgerAccessIsGuarded is the CHAOS-74 wall. Containment
// that guards one method leaks through the others: Stats and BulkWrite
// reached a latched, damaged store and SIGBUS'd. Any reference to c.db must sit
// inside a closure passed to access/contain, or in a helper that is itself
// reachable only from inside one, and every exported method must either arm
// the guard or be on the reasoned noBadgerAccess list. A new method that
// touches badger any other way fails here.
func TestCommunityDB_EveryBadgerAccessIsGuarded(t *testing.T) {
	methods := communityDBMethods(t)
	if len(methods) == 0 {
		t.Fatal("found no CommunityDB methods; the wall is not looking at the right sources")
	}
	usesGuard := map[string]bool{}
	touchesDB := map[string]bool{}
	for name, fn := range methods {
		usesGuard[name], touchesDB[name] = scanMethod(t, name, fn)
	}
	for name := range guardedOnlyHelpers {
		if methods[name] == nil {
			t.Errorf("guardedOnlyHelpers lists %s, which no longer exists; prune the list", name)
		}
	}
	checkExportedClassification(t, usesGuard, touchesDB)
}

// scanMethod reports whether the method arms a guard and whether it touches
// c.db, flagging any c.db reference or guarded-only helper call that is not
// inside an access/contain closure.
func scanMethod(t *testing.T, name string, fn *ast.FuncDecl) (usesGuard, touchesDB bool) {
	t.Helper()
	recv := recvName(fn)
	if recv == "" {
		return false, false
	}
	_, isHelper := guardedOnlyHelpers[name]
	inspectWithStack(fn.Body, func(node ast.Node, stack []ast.Node) {
		field, ok := recvSelector(node, recv)
		if !ok {
			return
		}
		guarded := isHelper || inGuardClosure(stack, recv)
		switch {
		case field == "db":
			touchesDB = true
			if !guarded {
				t.Errorf("%s touches c.db outside an access/contain closure", name)
			}
		case guardCalls[field]:
			usesGuard = true
		case guardedOnlyHelpers[field] != "" && !guarded:
			t.Errorf("%s calls guarded-only helper %s outside an access/contain closure", name, field)
		}
	})
	return usesGuard, touchesDB
}

// checkExportedClassification requires every exported method to arm the
// guard, or to be on noBadgerAccess and provably not reach badger.
func checkExportedClassification(t *testing.T, usesGuard, touchesDB map[string]bool) {
	t.Helper()
	typ := reflect.TypeOf(&CommunityDB{})
	for i := 0; i < typ.NumMethod(); i++ {
		name := typ.Method(i).Name
		_, exempt := noBadgerAccess[name]
		switch {
		case exempt && (touchesDB[name] || usesGuard[name]):
			t.Errorf("%s is on noBadgerAccess but reaches badger; route it through access instead", name)
		case !exempt && !usesGuard[name]:
			t.Errorf("exported method %s neither goes through access/contain nor is on the reasoned noBadgerAccess list", name)
		}
	}
}

// TestCommunityDB_DegradedStoreNeverReachesBadger mirrors the reproduction
// (latch, then Stats / BulkWrite) without a real SIGBUS. The store has NO
// badger handle at all, so any method that touches badger after the latch
// would nil-dereference, and that is a plain panic ContainFault re-raises.
// Passing means each data method refused on the latch alone.
func TestCommunityDB_DegradedStoreNeverReachesBadger(t *testing.T) {
	c := &CommunityDB{}
	if !c.noteMemFault() {
		t.Fatal("first fault must latch")
	}
	if got := c.Stats(); got != 0 {
		t.Errorf("Stats on a degraded store = %d, want 0", got)
	}
	if err := c.BulkWrite(map[string]string{"evil.example": "Malware"}); !errors.Is(err, ErrDegraded) {
		t.Errorf("BulkWrite on a degraded store = %v, want ErrDegraded", err)
	}
	if cat, ok := c.Lookup("evil.example"); ok || cat != "" {
		t.Errorf("Lookup on a degraded store = (%q, %v)", cat, ok)
	}
	if _, mem, degraded := c.LookupFaults(); mem != 1 || !degraded {
		t.Errorf("refusals were counted as new faults or un-latched: mem=%d degraded=%v", mem, degraded)
	}
}
