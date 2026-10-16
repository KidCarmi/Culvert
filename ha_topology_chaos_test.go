package main

// ha_topology_chaos_test.go — CHAOS-71: the published CP address list follows
// EVERY HA transition (Codex P1 4295317903 on #1556), by construction.

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// cpUseTopologySource points the CP address derivation (and the republish
// hook) at h for the test's duration.
func cpUseTopologySource(t *testing.T, h *HAState) {
	t.Helper()
	prev := haTopologyOverride.Load()
	haTopologyOverride.Store(h)
	t.Cleanup(func() { haTopologyOverride.Store(prev) })
}

// TestChaos71_HATransitionsRepublishTheCPAddressList drives a real HAState
// through every topology transition — enable, standby entry, promote,
// self-fence, resume — plus the Codex path (a persisted leader whose delayed
// bind published BEFORE onActivated resumed HA), and after EACH asserts the
// published CP address list equals what buildCPAddressList derives. No caller
// republishes; the single topology writer does.
func TestChaos71_HATransitionsRepublishTheCPAddressList(t *testing.T) {
	tempHADir(t)
	_ = cpIsolateActivation(t)
	cpChaosSetup(t)
	const (
		peer   = "10.0.0.9:50051"
		myAddr = "10.0.0.2:50051"
	)

	h := &HAState{}
	cpUseTopologySource(t, h)
	t.Cleanup(h.Stop)

	// An active Control Plane: the store's list is owned, and the first
	// publish happened with HA still off (the recovered-leader boot order).
	globalConfigStore.setCPAddressSource(buildCPAddressList)
	if err := globalConfigStore.Update(CurrentConfigSnapshot()); err != nil {
		t.Fatalf("seed publish: %v", err)
	}
	s := &cpListenerSupervisor{cfg: cpListenerConfig{addr: myAddr}, stopping: make(chan struct{})}
	if outcome, _, err := s.commitActivation(); outcome != cpCommitted || err != nil {
		t.Fatalf("activation: outcome=%d err=%v", outcome, err)
	}

	check := func(step string, want []string) {
		t.Helper()
		got := globalConfigStore.Get().CPAddresses
		if derived := buildCPAddressList(); !slicesEqual(got, derived) {
			t.Errorf("%s: published CP address list %v != derived %v — the transition did not republish", step, got, derived)
		}
		if !slicesEqual(got, want) {
			t.Errorf("%s: published CP address list = %v, want %v", step, got, want)
		}
	}
	check("before HA", nil)

	// 1. Resume as a persisted leader AFTER the bind (the Codex path).
	h.ResumeAsLeader(&haConfig{Enabled: true, Role: "leader", PeerAddr: peer, Token: "tok"})
	check("resume after a delayed bind", []string{peer, myAddr})

	// 2. Self-fence: role changes, the list is re-derived (standby still lists).
	h.selfFence("test: listener dark")
	check("self-fence", []string{peer, myAddr})

	// 3. Enter standby against a different leader address.
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the sync loop exits immediately
	const newLeader = "10.0.0.7:50051"
	h.StartAsStandby(ctx, newLeader, "tok", myAddr, "", "", "", false, func() error { return nil })
	check("standby entry", []string{newLeader, myAddr})

	// 4. Promote.
	if err := h.PromoteManually(); err != nil {
		t.Fatalf("promote: %v", err)
	}
	check("promote", []string{newLeader, myAddr})

	// 5. Enable HA anew with yet another peer.
	const enablePeer = "10.0.0.5:50051"
	if _, err := h.EnableAsLeader(enablePeer, false); err != nil {
		t.Fatalf("enable: %v", err)
	}
	check("enable", []string{enablePeer, myAddr})
}

// TestChaos71_Wall_HATopologyHasOneWriter: outside setTopologyLocked no
// production file assigns an HAState's role or peerAddr, so no transition can
// change what the CP address list derives from without republishing it.
func TestChaos71_Wall_HATopologyHasOneWriter(t *testing.T) {
	dir := pkgSourceDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	inSetter := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			// Inside an *HAState method any x.role / x.peerAddr write counts;
			// elsewhere (no type information) a write through globalHA does.
			method := fn.Recv != nil && cpIsHAStateReceiver(fn.Recv)
			for _, lhs := range cpHATopologyWrites(fn, method) {
				if fn.Name.Name == "setTopologyLocked" {
					inSetter++
					continue
				}
				t.Errorf("%s: %s assigns HAState.%s directly — go through setTopologyLocked so the CP address list is republished",
					fset.Position(lhs.Pos()), fn.Name.Name, lhs.Sel.Name)
			}
		}
	}
	if inSetter < 2 {
		t.Fatalf("the wall found %d writes in setTopologyLocked — its selector has gone stale", inSetter)
	}
}

// cpHATopologyWrites returns every assignment target in fn whose selector is
// role or peerAddr — on any receiver when anyReceiver, else on globalHA only.
func cpHATopologyWrites(fn *ast.FuncDecl, anyReceiver bool) []*ast.SelectorExpr {
	var out []*ast.SelectorExpr
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, lhs := range as.Lhs {
			sel, ok := lhs.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "role" && sel.Sel.Name != "peerAddr") {
				continue
			}
			if id, isIdent := sel.X.(*ast.Ident); anyReceiver || (isIdent && id.Name == "globalHA") {
				out = append(out, sel)
			}
		}
		return true
	})
	return out
}

// cpIsHAStateReceiver reports whether a method receiver is *HAState.
func cpIsHAStateReceiver(recv *ast.FieldList) bool {
	if len(recv.List) != 1 {
		return false
	}
	star, ok := recv.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	id, ok := star.X.(*ast.Ident)
	return ok && id.Name == "HAState"
}
