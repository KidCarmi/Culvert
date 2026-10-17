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

// cpScanHALockedCalls walks body in source order, modelling whether an
// HAState mutex (recv.mu or globalHA.mu) is held, and returns how many
// acquisitions it saw plus the callee names called while held. A deferred
// unlock keeps it held to the end; closures run later and are skipped.
func cpScanHALockedCalls(body *ast.BlockStmt, recv string) (locks int, callees []string) {
	if body == nil {
		return 0, nil
	}
	held := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.DeferStmt:
			if _, ok := cpHALockOp(n.Call, recv); ok {
				return false
			}
		case *ast.CallExpr:
			if op, ok := cpHALockOp(n, recv); ok {
				if op == "Lock" || op == "RLock" {
					held = true
					locks++
				} else {
					held = false
				}
				return true
			}
			if held {
				switch f := n.Fun.(type) {
				case *ast.Ident:
					callees = append(callees, f.Name)
				case *ast.SelectorExpr:
					callees = append(callees, f.Sel.Name)
				}
			}
		}
		return true
	})
	return locks, callees
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
