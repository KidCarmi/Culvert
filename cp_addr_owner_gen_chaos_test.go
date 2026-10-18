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

// ── A full publish never decides the CP address list (Codex P2 4307107242) ──

// ownGenHATopology makes the HA state derive [ownGenOther, ownGenDead] — the
// list a full publish would resurrect if it ever derived CPAddresses itself.
func ownGenHATopology(t *testing.T) {
	t.Helper()
	h := &HAState{}
	h.mu.Lock()
	h.role, h.peerAddr = "leader", ownGenOther
	h.mu.Unlock()
	cpUseTopologySource(t, h)
	clusterRoleMu.Lock()
	prev := clusterRole.grpcAddr
	clusterRole.grpcAddr = ownGenDead
	clusterRoleMu.Unlock()
	t.Cleanup(func() {
		clusterRoleMu.Lock()
		clusterRole.grpcAddr = prev
		clusterRoleMu.Unlock()
	})
	if got := buildCPAddressList(); !slicesEqual(got, []string{ownGenOther, ownGenDead}) {
		t.Fatalf("precondition: the HA state derives %v, want it to name the dead Control Plane", got)
	}
}

// ownGenWithdrawAndRelease is the terminal exit: withdraw ownGenDead, commit
// the removal, release ownership.
func ownGenWithdrawAndRelease(t *testing.T, s *ConfigStore) {
	t.Helper()
	if _, err := s.withdrawCPAddress(ownGenDead); err != nil {
		t.Errorf("withdrawal: %v", err)
	}
	if s.releaseCPAddressSourceAfterWithdrawal(ownGenDead) {
		t.Error("ownership kept after the withdrawal committed")
	}
}

// TestChaos71_FullPublishAfterAReleaseKeepsTheWithdrawnAddressOut — (a): a
// terminal exit withdrew the dead Control Plane, committed the removal and
// released ownership. An ordinary full publish afterwards — the real
// publishCurrentConfigSnapshot, and Update of a snapshot carrying the
// HA-derived list — must not re-add it: nothing would own or retry its
// removal.
func TestChaos71_FullPublishAfterAReleaseKeepsTheWithdrawnAddressOut(t *testing.T) {
	s, _ := ownGenStore(t)
	ownGenHATopology(t)
	ownGenWithdrawAndRelease(t, s)
	ownGenWantList(t, s, []string{ownGenOther}, "precondition: the withdrawal")

	if got := CurrentConfigSnapshot().CPAddresses; !slicesEqual(got, []string{ownGenOther}) {
		t.Errorf("CurrentConfigSnapshot derived CPAddresses %v, want the committed %v", got, []string{ownGenOther})
	}
	if err := publishCurrentConfigSnapshot(); err != nil {
		t.Fatalf("full publish: %v", err)
	}
	ownGenWantList(t, s, []string{ownGenOther}, "publishCurrentConfigSnapshot re-added the withdrawn Control Plane")
	if err := s.Update(ConfigSnapshot{CPAddresses: buildCPAddressList()}); err != nil {
		t.Fatalf("full publish of an HA-derived list: %v", err)
	}
	ownGenWantList(t, s, []string{ownGenOther}, "a full publish committed its own (HA-derived) list")
	if s.currentCPAddrOwner().owned() {
		t.Error("a full publish re-established ownership")
	}
}

// TestChaos71_FullPublishCapturedBeforeTheWithdrawalKeepsItOut — (b): the
// full publish captured its snapshot (naming the dead Control Plane) BEFORE
// the terminal exit; the withdrawal commits and releases ownership inside its
// validate→commit window, so its CAS retries. The retry must carry the
// post-withdrawal committed list, not the captured one.
func TestChaos71_FullPublishCapturedBeforeTheWithdrawalKeepsItOut(t *testing.T) {
	s, _ := ownGenStore(t)
	ownGenHATopology(t)
	captured := ConfigSnapshot{BlockedHosts: []string{"captured.example"}, CPAddresses: buildCPAddressList()}
	var windows atomic.Int32
	prev := configPublishBeforeCommit
	configPublishBeforeCommit = func() {
		if windows.Add(1) == 1 {
			ownGenWithdrawAndRelease(t, s)
		}
	}
	t.Cleanup(func() { configPublishBeforeCommit = prev })

	if err := s.Update(captured); err != nil {
		t.Fatalf("full publish: %v", err)
	}
	if windows.Load() < 2 {
		t.Fatalf("the full publish did not retry its CAS after the withdrawal (%d window(s))", windows.Load())
	}
	ownGenWantList(t, s, []string{ownGenOther}, "the retried full publish re-added the withdrawn Control Plane")
	if !cpListNames(s.Get().BlockedHosts, "captured.example") {
		t.Error("the full publish's own content was not committed")
	}
}

// TestChaos71_OwnedFullPublishCarriesTheOwnersList — (c), the owned control:
// while the list is owned, a full publish carries the owner's list (its own
// captured list is ignored) and the reconcile applies the owner's change.
func TestChaos71_OwnedFullPublishCarriesTheOwnersList(t *testing.T) {
	s, src := ownGenStore(t)
	src.set(ownGenOther, ownGenNew)
	if err := s.Update(ConfigSnapshot{CPAddresses: []string{"bogus:1"}}); err != nil {
		t.Fatalf("full publish: %v", err)
	}
	ownGenWantList(t, s, []string{ownGenOther, ownGenNew}, "an owned full publish did not end on the owner's list")
	if !s.currentCPAddrOwner().owned() {
		t.Error("ownership lost")
	}
}

// TestChaos71_Wall_CPAddressesHaveOneWriter: CPAddresses in a committed
// snapshot are written only by the address-kind plan (updateCPAddressesBound)
// or carried forward from the committed snapshot (X.snap.CPAddresses inside a
// plan, or committedCPAddresses in the builder). Every full-kind plan carries
// the committed list UNCONDITIONALLY, as a top-level statement of its build.
// The HA-state derivation (buildCPAddressList) reaches only the owned path.
func TestChaos71_Wall_CPAddressesHaveOneWriter(t *testing.T) {
	fullPlans := 0
	for _, f := range ownGenParse(t) {
		for _, decl := range f.Decls {
			owner := cpTopLevelName(decl)
			ast.Inspect(decl, func(n ast.Node) bool {
				v, full := ownGenAddressWrite(owner, n)
				if v != "" {
					t.Error(v)
				}
				if full {
					fullPlans++
				}
				return true
			})
		}
	}
	if fullPlans == 0 {
		t.Error("no full-kind publish plan found — the wall's selector has gone stale")
	}
}

// ownGenAddressWrite judges one node for the one-writer wall: a violation
// message (or ""), and whether n is a full-kind publish plan.
func ownGenAddressWrite(owner string, n ast.Node) (violation string, fullPlan bool) {
	switch x := n.(type) {
	case *ast.AssignStmt:
		for i, lhs := range x.Lhs {
			sel, ok := lhs.(*ast.SelectorExpr)
			if ok && sel.Sel.Name == "CPAddresses" && i < len(x.Rhs) &&
				owner != "updateCPAddressesBound" && !ownGenCarriesForward(x.Rhs[i]) {
				return owner + " writes CPAddresses from something other than the committed snapshot — only the address-kind plan decides the list", false
			}
		}
	case *ast.KeyValueExpr:
		if k, ok := x.Key.(*ast.Ident); ok && k.Name == "CPAddresses" && !ownGenCarriesForward(x.Value) {
			return owner + " builds a snapshot literal with its own CPAddresses", false
		}
	case *ast.CompositeLit:
		if build := ownGenFullPlanBuild(x); build != nil {
			if !ownGenTopLevelCarry(build) {
				return owner + ": a full-kind publish plan does not carry the committed CPAddresses unconditionally", true
			}
			return "", true
		}
	case *ast.Ident:
		if x.Name == "buildCPAddressList" && !ownGenDerivationOwners[owner] {
			return owner + " uses buildCPAddressList — the HA-state derivation may reach only the owned address publish", false
		}
	}
	return "", false
}

// ownGenDerivationOwners hand buildCPAddressList to the owned path only.
var ownGenDerivationOwners = map[string]bool{
	"buildCPAddressList": true, "cpPublishCPAddresses": true, "republishTopology": true, "activateControlPlane": true,
}

func ownGenParse(t *testing.T) []*ast.File {
	t.Helper()
	dir := pkgSourceDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		files = append(files, f)
	}
	return files
}

// ownGenCarriesForward: e is the committed list — X.snap.CPAddresses, or a
// committedCPAddresses() call.
func ownGenCarriesForward(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.SelectorExpr:
		inner, ok := x.X.(*ast.SelectorExpr)
		return x.Sel.Name == "CPAddresses" && ok && inner.Sel.Name == "snap"
	case *ast.CallExpr:
		if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
			return sel.Sel.Name == "committedCPAddresses"
		}
	}
	return false
}

// ownGenFullPlanBuild is the build function of a publishPlan literal of kind
// publishFull, or nil.
func ownGenFullPlanBuild(lit *ast.CompositeLit) *ast.FuncLit {
	if id, ok := lit.Type.(*ast.Ident); !ok || id.Name != "publishPlan" {
		return nil
	}
	var full bool
	var build *ast.FuncLit
	for _, el := range lit.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		switch leaseIdentName(kv.Key) {
		case "kind":
			full = leaseIdentName(kv.Value) == "publishFull"
		case "build":
			build, _ = kv.Value.(*ast.FuncLit)
		}
	}
	if !full {
		return nil
	}
	if build == nil {
		return &ast.FuncLit{Body: &ast.BlockStmt{}} // a full plan with no literal build: reported
	}
	return build
}

// ownGenTopLevelCarry: build's body has, as a top-level statement, an
// assignment of the committed list to CPAddresses.
func ownGenTopLevelCarry(build *ast.FuncLit) bool {
	for _, st := range build.Body.List {
		as, ok := st.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			continue
		}
		if sel, ok := as.Lhs[0].(*ast.SelectorExpr); ok && sel.Sel.Name == "CPAddresses" && ownGenCarriesForward(as.Rhs[0]) {
			return true
		}
	}
	return false
}
