package main

// cp_addr_owner_gen_chaos_test.go — CHAOS-71: every address-list commit is
// bound to the ownership generation it built from (Codex P2 4302952407 on
// #1556, the third finding in the withdrawal/ownership area). A source
// captured before a withdrawal committed and released ownership re-added the
// dead Control Plane at a higher version, and nothing removed it.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

const (
	ownGenDead  = "10.0.0.2:50051" // the Control Plane whose supervisor exits terminally
	ownGenOther = "10.0.0.9:50051"
	ownGenNew   = "10.0.0.5:50051"
)

// ownGenSource is a source whose list the test changes, like the live
// topology buildCPAddressList reads.
type ownGenSource struct {
	mu    sync.Mutex
	addrs []string
}

func (o *ownGenSource) set(addrs ...string) {
	o.mu.Lock()
	o.addrs = addrs
	o.mu.Unlock()
}

func (o *ownGenSource) build() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.addrs...)
}

// ownGenStore is an owned, published store whose committed list names
// ownGenDead, built from src.
func ownGenStore(t *testing.T) (*ConfigStore, *ownGenSource) {
	t.Helper()
	_ = cpIsolateActivation(t)
	_, _ = cpAddrPublishHarness(t)
	s := globalConfigStore
	src := &ownGenSource{}
	src.set(ownGenOther, ownGenDead)
	s.setCPAddressSource(src.build)
	if err := s.Update(ConfigSnapshot{}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if got := s.Get().CPAddresses; !slicesEqual(got, []string{ownGenOther, ownGenDead}) {
		t.Fatalf("precondition: committed list = %v", got)
	}
	return s, src
}

// ownGenInCommitWindow runs fn once, inside the first address publish's
// window between validation and commit. fn may publish itself: the flag is
// set before it runs, so its own publish passes the window untouched.
func ownGenInCommitWindow(t *testing.T, fn func()) {
	t.Helper()
	var fired atomic.Bool
	prev := cpAddrMergeBeforeCommit
	cpAddrMergeBeforeCommit = func() {
		if fired.CompareAndSwap(false, true) {
			fn()
		}
	}
	t.Cleanup(func() { cpAddrMergeBeforeCommit = prev })
}

func ownGenWantList(t *testing.T, s *ConfigStore, want []string, why string) {
	t.Helper()
	if got := s.Get().CPAddresses; !slicesEqual(got, want) {
		t.Errorf("committed list = %v, want %v: %s", got, want, why)
	}
}

// TestChaos71_StaleSourceNeverCommitsAfterAWithdrawal is the finding's exact
// sequence: a publish captures source A, then a terminal exit withdraws the
// dead Control Plane, commits the removal and releases ownership, then the
// stale publish runs. The dead address must not reappear.
func TestChaos71_StaleSourceNeverCommitsAfterAWithdrawal(t *testing.T) {
	s, _ := ownGenStore(t)
	stale := s.currentCPAddrOwner() // a full-publish reconcile or a retry captured A

	if _, err := s.withdrawCPAddress(ownGenDead); err != nil {
		t.Fatalf("withdrawal: %v", err)
	}
	if s.releaseCPAddressSourceAfterWithdrawal(ownGenDead) {
		t.Fatal("ownership kept after the withdrawal committed")
	}
	v := s.Version()

	if _, err := s.publishOwnedCPAddressesAs("config_publish", stale, nil); err != nil {
		t.Fatalf("stale publish: %v", err)
	}
	ownGenWantList(t, s, []string{ownGenOther}, "a source captured before the withdrawal re-added the dead Control Plane")
	if s.Version() != v {
		t.Errorf("version %d → %d: the stale publish committed", v, s.Version())
	}
	if s.currentCPAddrOwner().owned() {
		t.Error("the stale publish left the list owned")
	}
	if st := s.cpAddrPublishSnapshot(); st.pending {
		t.Errorf("released ownership but the stale publish latched pending: %+v", st)
	}
}

// TestChaos71_FullPublishReconcileStopsWhenAWithdrawalLandsBeforeItCommits
// drives the same race through the real full-publish path: Update's reconcile
// has built and validated A's list (now carrying a new peer) when the
// terminal exit's withdrawal commits and releases ownership.
func TestChaos71_FullPublishReconcileStopsWhenAWithdrawalLandsBeforeItCommits(t *testing.T) {
	s, src := ownGenStore(t)
	src.set(ownGenOther, ownGenDead, ownGenNew) // the reconcile has a change to commit
	ownGenInCommitWindow(t, func() {
		if _, err := s.withdrawCPAddress(ownGenDead); err != nil {
			t.Errorf("withdrawal: %v", err)
		}
	})

	if err := s.Update(ConfigSnapshot{}); err != nil {
		t.Fatalf("full publish: %v", err)
	}
	ownGenWantList(t, s, []string{ownGenOther, ownGenNew}, "the reconcile committed its pre-withdrawal source over the withdrawal")
	if s.currentCPAddrOwner().owned() {
		t.Error("ownership was not released after the withdrawal committed")
	}
}

// TestChaos71_SupersededOwnerRebuildsFromTheNewOwner: a new owner installed
// while a publish bound to the old one is in its commit window (no commit in
// between, so only the generation can tell) makes that publish rebuild from
// the NEW owner's source — never commit the old owner's list, whichever
// builder its caller chose for the old owner.
func TestChaos71_SupersededOwnerRebuildsFromTheNewOwner(t *testing.T) {
	s, _ := ownGenStore(t)
	next := &ownGenSource{}
	next.set(ownGenOther, ownGenNew)
	ownGenInCommitWindow(t, func() { s.setCPAddressSource(next.build) })

	stale := func() []string { return []string{ownGenOther, ownGenDead, "10.0.0.7:50051"} }
	if _, err := s.publishOwnedCPAddresses(haTransitionPromote, stale); err != nil {
		t.Fatalf("publish: %v", err)
	}
	ownGenWantList(t, s, []string{ownGenOther, ownGenNew}, "a publish bound to the superseded owner committed its list")
}

// TestChaos71_Wall_AddressSourceReadsCarryTheOwnerGeneration: the owner is
// written in ONE place (setCPAddrOwnerLocked, which bumps the generation),
// cpAddrSource is read in ONE place (cpAddrOwnerLocked, which pairs it with
// the generation), the source leaves a cpAddrOwner only through its methods,
// and the one address-kind commit plan (updateCPAddressesBound) checks the
// generation it was bound to — as does the commit's base check under s.mu.
func TestChaos71_Wall_AddressSourceReadsCarryTheOwnerGeneration(t *testing.T) {
	scan := ownGenScan(t)
	wantOnly := func(what string, got map[string]int, allowed ...string) {
		t.Helper()
		ok := map[string]bool{}
		for _, a := range allowed {
			ok[a] = true
			if got[a] == 0 {
				t.Errorf("%s: none found in %s — the wall's selector has gone stale", what, a)
			}
		}
		for owner := range got {
			if !ok[owner] {
				t.Errorf("%s in %s — only %v may: every source read used for a commit must carry the ownership generation", what, owner, allowed)
			}
		}
	}
	wantOnly("an owner write (cpAddrSource/cpAddrWithdrawal/cpAddrOwnerGen)", scan.ownerWrites, "setCPAddrOwnerLocked")
	wantOnly("a read of cpAddrSource", scan.sourceReads, "cpAddrOwnerLocked", "setCPAddrOwnerLocked")
	wantOnly("a read of cpAddrOwner.src", scan.ownerSrcReads, "owned", "builder", "without")
	wantOnly("an address-kind publish plan", scan.addressPlans, "updateCPAddressesBound")
	if scan.genChecks["updateCPAddressesBound"] == 0 {
		t.Error("updateCPAddressesBound no longer compares the view's ownerGen with the owner it was bound to")
	}
	if scan.genChecks["committedIsLocked"] == 0 {
		t.Error("committedIsLocked no longer compares the ownership generation under s.mu")
	}
}

type ownGenScanResult struct {
	ownerWrites, sourceReads, ownerSrcReads, addressPlans, genChecks map[string]int
}

func ownGenScan(t *testing.T) ownGenScanResult {
	t.Helper()
	dir := pkgSourceDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	r := ownGenScanResult{map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}}
	ownerFields := map[string]bool{"cpAddrSource": true, "cpAddrWithdrawal": true, "cpAddrOwnerGen": true}
	fset := token.NewFileSet()
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
			owner := cpTopLevelName(decl)
			ast.Inspect(decl, func(n ast.Node) bool {
				ownGenScanNode(r, ownerFields, owner, n)
				return true
			})
		}
	}
	return r
}

func ownGenScanNode(r ownGenScanResult, ownerFields map[string]bool, owner string, n ast.Node) {
	written := func(x ast.Expr) {
		if sel, ok := x.(*ast.SelectorExpr); ok && ownerFields[sel.Sel.Name] {
			r.ownerWrites[owner]++
		}
	}
	switch n := n.(type) {
	case *ast.AssignStmt:
		for _, lhs := range n.Lhs {
			written(lhs)
		}
	case *ast.IncDecStmt:
		written(n.X)
	case *ast.SelectorExpr:
		switch n.Sel.Name {
		case "cpAddrSource":
			r.sourceReads[owner]++
		case "src":
			r.ownerSrcReads[owner]++
		case "ownerGen", "cpAddrOwnerGen":
			r.genChecks[owner]++
		}
	case *ast.CompositeLit:
		if id, ok := n.Type.(*ast.Ident); ok && id.Name == "publishPlan" {
			for _, el := range n.Elts {
				if kv, ok := el.(*ast.KeyValueExpr); ok {
					if v, ok := kv.Value.(*ast.Ident); ok && v.Name == "publishAddresses" {
						r.addressPlans[owner]++
					}
				}
			}
		}
	}
}
