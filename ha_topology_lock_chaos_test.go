package main

// ha_topology_lock_chaos_test.go — CHAOS-71: no snapshot publish runs under
// HAState.mu, and lease renewal never waits on publication (Codex P1
// 4301857115 on #1556).

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/halease"
)

// TestChaos71_SlowTopologyPublishDoesNotCostTheLease: an HA enable whose CP
// address republish takes longer than the lease TTL (a large permitted
// snapshot marshal, here a seam) must not cost the fence. The keepalive
// starts before the publish and renews while it runs, so the lease is still
// held, still renewed, and the node has not self-fenced when the publish
// returns. Under h.mu the keepalive could not start (or take h.mu to record a
// renewal) until the publish ended, by which time the lease had expired.
func TestChaos71_SlowTopologyPublishDoesNotCostTheLease(t *testing.T) {
	const (
		myAddr = "10.0.0.2:50051"
		peer   = "10.0.0.9:50051"
		ttl    = 3 * time.Second // the supported minimum TTL
	)
	h := cpAddrTopologyFixture(t)
	f := halease.NewFake(ttl)
	h.SetLeaseProvider(f, "cp-a")
	cpAddrActiveCP(t, myAddr)

	var slowed atomic.Int32
	prev := cpAddrMergeBeforeCommit
	cpAddrMergeBeforeCommit = func() {
		if slowed.Add(1) == 1 {
			time.Sleep(ttl + 700*time.Millisecond) // longer than the TTL, let alone the trusted window
		}
	}
	t.Cleanup(func() { cpAddrMergeBeforeCommit = prev })

	if _, err := h.EnableAsLeader(peer, false); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if slowed.Load() == 0 {
		t.Fatal("precondition: the topology republish never reached the slow commit")
	}
	cpAssertStillFenced(t, h, f)
	if got := globalConfigStore.Get().CPAddresses; !slicesEqual(got, []string{peer, myAddr}) {
		t.Errorf("published CP address list = %v, want %v", got, []string{peer, myAddr})
	}
	// And it keeps holding: one more keepalive round after the publish.
	time.Sleep(ttl / 2)
	cpAssertStillFenced(t, h, f)
}

// cpAssertStillFenced: this node still leads under a live, renewed lease.
func cpAssertStillFenced(t *testing.T, h *HAState, f *halease.Fake) {
	t.Helper()
	if st := h.Status(); st.Role != "leader" || h.CurrentEpoch() == 0 {
		t.Fatalf("role=%q epoch=%d — the node self-fenced while its address list was being published", st.Role, h.CurrentEpoch())
	}
	st, err := f.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.Holder != "cp-a" || st.ValidFor <= 0 {
		t.Fatalf("lease holder=%q valid_for=%s — the lease was not renewed during the publish", st.Holder, st.ValidFor)
	}
}

// cpPublishPrimitives are the snapshot marshal and commit primitives every
// publish goes through (commitPublish validates with
// validateSnapshotForPublish, then commitLocked).
var cpPublishPrimitives = map[string]bool{
	"commitPublish": true, "validateSnapshotForPublish": true, "commitLocked": true,
}

// TestChaos71_Wall_NoSnapshotPublishUnderTheHALock: no code path that holds
// HAState.mu can reach a snapshot marshal or commit — not a *Locked HAState
// method (called with h.mu held), and not a call made inside an h.mu (or
// globalHA.mu) critical section. The by-name call graph is conservative, and
// it follows package-level function seams (`var x = func(...) {...}`) into
// their bodies, so a publish behind a seam is still seen.
func TestChaos71_Wall_NoSnapshotPublishUnderTheHALock(t *testing.T) {
	funcs := cpFuncsWithSeams(t)
	lockedMethods, regions := 0, 0
	for name, decls := range funcs {
		for _, fn := range decls {
			recv := cpHAStateReceiver(fn)
			if recv != "" && strings.HasSuffix(name, "Locked") {
				lockedMethods++
				if path, bad := cpReaches(funcs, name, cpPublishPrimitives, 10); bad {
					t.Errorf("%s runs with HAState.mu held and reaches %s — a snapshot publish under the HA lock blocks lease renewal",
						name, strings.Join(path, " → "))
				}
			}
			n, offenders := cpScanHALockedCalls(fn.Body, recv)
			regions += n
			for _, callee := range offenders {
				if path, bad := cpReaches(funcs, callee, cpPublishPrimitives, 10); bad || cpPublishPrimitives[callee] {
					t.Errorf("%s calls %s while holding HAState.mu, reaching %s — publish after releasing the lock",
						name, callee, strings.Join(path, " → "))
				}
			}
		}
	}
	if lockedMethods < 3 || regions < 20 {
		t.Fatalf("the wall saw %d *Locked HAState methods and %d HA lock regions — its selectors have gone stale", lockedMethods, regions)
	}
}

// cpFuncsWithSeams is cpParseFuncsAndGateHolders' by-name function map plus a
// synthetic declaration for every package-level variable initialised with a
// function literal (the test seams production code calls through).
func cpFuncsWithSeams(t *testing.T) map[string][]*ast.FuncDecl {
	t.Helper()
	funcs, _ := cpParseFuncsAndGateHolders(t)
	dir := pkgSourceDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	seams := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		for _, fd := range cpSeamDecls(f) {
			seams++
			funcs[fd.Name.Name] = append(funcs[fd.Name.Name], fd)
		}
	}
	if seams == 0 {
		t.Fatal("no package-level function seams found — the wall's seam scan has gone stale")
	}
	return funcs
}

// cpSeamDecls returns a synthetic declaration for each package-level
// variable in f initialised with a function literal.
func cpSeamDecls(f *ast.File) []*ast.FuncDecl {
	var out []*ast.FuncDecl
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, sp := range gd.Specs {
			vs, ok := sp.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, v := range vs.Values {
				if lit, ok := v.(*ast.FuncLit); ok && i < len(vs.Names) {
					out = append(out, &ast.FuncDecl{Name: vs.Names[i], Type: lit.Type, Body: lit.Body})
				}
			}
		}
	}
	return out
}

// cpHAStateReceiver returns fn's receiver name when it is a *HAState method.
func cpHAStateReceiver(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) != 1 || len(fn.Recv.List[0].Names) != 1 {
		return ""
	}
	star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
	if !ok {
		return ""
	}
	if id, ok := star.X.(*ast.Ident); !ok || id.Name != "HAState" {
		return ""
	}
	return fn.Recv.List[0].Names[0].Name
}

// cpScanHALockedCalls walks body's statements in order, modelling whether an
// HAState mutex (recv.mu or globalHA.mu) is held, and returns how many
// acquisitions it saw plus the callee names called while held. A deferred
// unlock keeps it held to the end; an unlock inside a branch that leaves the
// function (`if ... { h.mu.Unlock(); return }`) releases only that branch;
// closures and go statements run later and are skipped.
func cpScanHALockedCalls(body *ast.BlockStmt, recv string) (locks int, callees []string) {
	if body == nil {
		return 0, nil
	}
	w := &cpHALockWalker{recv: recv}
	w.stmts(body.List, false)
	return w.locks, w.callees
}

type cpHALockWalker struct {
	recv    string
	locks   int
	callees []string
}

// stmts walks a statement list starting in state held and returns the state
// after it, and whether the list always leaves the function.
func (w *cpHALockWalker) stmts(list []ast.Stmt, held bool) (after bool, leaves bool) {
	for _, st := range list {
		if held, leaves = w.stmt(st, held); leaves {
			return held, true
		}
	}
	return held, false
}

func (w *cpHALockWalker) stmt(st ast.Stmt, held bool) (after bool, leaves bool) {
	switch st := st.(type) {
	case *ast.ExprStmt:
		if call, ok := st.X.(*ast.CallExpr); ok {
			if op, ok := cpHALockOp(call, w.recv); ok {
				if op == "Lock" || op == "RLock" {
					w.locks++
					return true, false
				}
				return false, false
			}
		}
	case *ast.DeferStmt:
		if _, ok := cpHALockOp(st.Call, w.recv); ok {
			return held, false
		}
		return held, false // a deferred call runs at return; not scanned as held code
	case *ast.GoStmt:
		return held, false
	case *ast.ReturnStmt:
		w.calls(st, held)
		return held, true
	case *ast.BlockStmt:
		return w.stmts(st.List, held)
	case *ast.IfStmt:
		return w.ifStmt(st, held)
	case *ast.ForStmt:
		w.calls(st.Init, held)
		w.calls(st.Cond, held)
		w.stmts(st.Body.List, held)
		return held, false
	case *ast.RangeStmt:
		w.calls(st.X, held)
		w.stmts(st.Body.List, held)
		return held, false
	case *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt:
		w.clauses(st, held)
		return held, false
	}
	w.calls(st, held)
	return held, false
}

func (w *cpHALockWalker) ifStmt(st *ast.IfStmt, held bool) (after, leaves bool) {
	if st.Init != nil {
		held, _ = w.stmt(st.Init, held)
	}
	w.calls(st.Cond, held)
	bodyHeld, bodyLeaves := w.stmts(st.Body.List, held)
	elseHeld, elseLeaves := held, false
	if st.Else != nil {
		elseHeld, elseLeaves = w.stmt(st.Else, held)
	}
	switch {
	case bodyLeaves && elseLeaves:
		return held, true
	case bodyLeaves:
		return elseHeld, false
	case elseLeaves:
		return bodyHeld, false
	}
	return bodyHeld || elseHeld, false // conservative: held if either path holds it
}

func (w *cpHALockWalker) clauses(n ast.Node, held bool) {
	ast.Inspect(n, func(x ast.Node) bool {
		switch c := x.(type) {
		case *ast.CaseClause:
			w.calls(c.List, held)
			w.stmts(c.Body, held)
			return false
		case *ast.CommClause:
			w.stmts(c.Body, held)
			return false
		}
		return true
	})
}

// calls records every call in n (closures excluded) when held.
func (w *cpHALockWalker) calls(n any, held bool) {
	if !held || n == nil {
		return
	}
	var nodes []ast.Node
	switch v := n.(type) {
	case []ast.Expr:
		for _, e := range v {
			nodes = append(nodes, e)
		}
	case ast.Node:
		if v == nil {
			return
		}
		nodes = append(nodes, v)
	}
	for _, node := range nodes {
		ast.Inspect(node, func(x ast.Node) bool {
			switch c := x.(type) {
			case *ast.FuncLit:
				return false
			case *ast.CallExpr:
				switch f := c.Fun.(type) {
				case *ast.Ident:
					w.callees = append(w.callees, f.Name)
				case *ast.SelectorExpr:
					w.callees = append(w.callees, f.Sel.Name)
				}
			}
			return true
		})
	}
}

// cpHALockOp reports the mutex method a call invokes on recv.mu or
// globalHA.mu, if any.
func cpHALockOp(call *ast.CallExpr, recv string) (string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	mu, ok := sel.X.(*ast.SelectorExpr)
	if !ok || mu.Sel.Name != "mu" {
		return "", false
	}
	id, ok := mu.X.(*ast.Ident)
	if !ok || (id.Name != "globalHA" && (recv == "" || id.Name != recv)) {
		return "", false
	}
	switch sel.Sel.Name {
	case "Lock", "RLock", "Unlock", "RUnlock":
		return sel.Sel.Name, true
	}
	return "", false
}
