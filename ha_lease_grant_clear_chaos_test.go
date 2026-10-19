package main

// ha_lease_grant_clear_chaos_test.go — Codex P1 4306890528 on #1556: "Clear
// the lease epoch when a guarded resume aborts".
//
// A guarded boot resume acquired fencing epoch E, its post-acquisition
// revalidation found ha_config.json removed or disabled, and the return left
// leaseEpoch/fenceEpoch = E with no HA role and no keepalive. The retry then
// decided "no HA" and cleared the intent gate, so leader-gated RPCs and
// issuance were allowed while CurrentEpoch() advertised the abandoned E on
// every heartbeat and enrollment — Data Planes ratcheted to an epoch no
// committed snapshot carries.
//
// The class: every exit after a lease Acquire on the resume, enable, promote
// and recovery paths either installs the grant (role plus keepalive) or clears
// its local state through clearLeaseGrantLocked, under h.mu. No lease is
// released — ADR-0005 has no Release; the grant runs out its TTL.

import (
	"context"
	"errors"
	"go/ast"
	"go/token"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/halease"
)

// cpHookedLease runs afterAcquire right after every Acquire, outside HAState.mu
// (the window between a grant and its caller's install decision).
type cpHookedLease struct {
	*halease.Fake
	afterAcquire func()
}

func (l *cpHookedLease) Acquire(ctx context.Context, id string) (bool, halease.Status, error) {
	granted, st, err := l.Fake.Acquire(ctx, id)
	if l.afterAcquire != nil {
		l.afterAcquire()
	}
	return granted, st, err
}

// assertNoLocalGrant: no epoch advertised (CurrentEpoch and the lock-free
// publish stamp), no write authority, no keepalive — while the backend still
// holds the unkept grant (no Release).
func assertNoLocalGrant(t *testing.T, h *HAState, fake *halease.Fake, why string) {
	t.Helper()
	if e := h.CurrentEpoch(); e != 0 {
		t.Errorf("%s: CurrentEpoch() = %d, want 0 — the abandoned grant is still advertised", why, e)
	}
	if e := h.PublishedFenceEpoch(); e != 0 {
		t.Errorf("%s: PublishedFenceEpoch() = %d, want 0", why, e)
	}
	if h.WriteAllowed() {
		t.Errorf("%s: write authority on an uninstalled grant", why)
	}
	h.mu.RLock()
	keepalive := h.leaseStopCh != nil
	h.mu.RUnlock()
	if keepalive {
		t.Errorf("%s: a keepalive is renewing an uninstalled grant", why)
	}
	if fake != nil {
		if st, _ := fake.Read(context.Background()); st.Holder != "cp-a" || st.Epoch == 0 {
			t.Errorf("%s: backend lease = %+v, want the unkept grant still held by cp-a (no Release)", why, st)
		}
	}
}

// TestChaos71_RevalidationAbortAfterTheGrantClearsTheEpoch is the finding, on
// the real boot callback: the config is removed or disabled inside the
// acquisition window. The node advertises no epoch, has no write authority and
// issues nothing while gated; once the retry decides "no HA", issuance is the
// standalone kind with epoch 0, and a config publish carries the same stamp as
// before the resume.
func TestChaos71_RevalidationAbortAfterTheGrantClearsTheEpoch(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T)
	}{
		{"config_removed", func(t *testing.T) {
			if err := os.Remove(haConfigPath()); err != nil {
				t.Error(err)
			}
		}},
		{"config_disabled", func(t *testing.T) {
			if err := saveHAConfig(&haConfig{Enabled: false}); err != nil {
				t.Error(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tempHADir(t)
			t.Cleanup(swapGlobalHA(t))
			cpLeaderConfig(t)
			fake := halease.NewFake(time.Minute)
			globalHA.SetLeaseProvider(fake, "cp-a")
			t.Cleanup(globalHA.Stop)
			store := &ConfigStore{}
			if err := store.Update(cpCommitSnapshot(1)); err != nil {
				t.Fatal(err)
			}
			stampBefore := store.Get().Epoch

			prev := haResumeAfterAcquire
			haResumeAfterAcquire = func() { tc.mutate(t) }
			t.Cleanup(func() { haResumeAfterAcquire = prev })

			if resumeLeadershipAttempt() {
				t.Fatal("precondition: the aborted resume decided the intent")
			}
			if st := globalHA.Status(); st.Role != "" {
				t.Fatalf("role after the aborted resume = %q, want none", st.Role)
			}
			assertNoLocalGrant(t, globalHA, fake, "after the revalidation abort")
			if ok, _ := haIssuanceAllowed(); ok {
				t.Error("issuance allowed while the intent is still undecided")
			}

			haResumeAfterAcquire = prev
			if !resumeLeadershipAttempt() { // the retry: no HA config, decided
				t.Fatal("the retry did not decide a removed/disabled config")
			}
			if st := globalHA.Status(); st.Enabled {
				t.Fatalf("HA still enabled after the retry decided no HA: %+v", st)
			}
			assertNoLocalGrant(t, globalHA, fake, "after the retry decided no HA")
			if err := store.Update(cpCommitSnapshot(2)); err != nil {
				t.Fatal(err)
			}
			if got := store.Get().Epoch; got != stampBefore {
				t.Errorf("config publish stamp = %d after the aborted resume, want the unchanged %d", got, stampBefore)
			}
		})
	}
}

// TestChaos71_ClaimedResumeAfterTheGrantClearsTheEpoch: the under-lock aborts
// — shutdown right after the grant (guarded and unguarded resume), and a live
// HA transition (a standby join) claiming the node in the window.
func TestChaos71_ClaimedResumeAfterTheGrantClearsTheEpoch(t *testing.T) {
	for _, tc := range []struct {
		name    string
		guarded bool
		claim   func(h *HAState)
	}{
		{"shutdown_guarded", true, func(h *HAState) { h.BeginShutdown() }},
		{"shutdown_unguarded", false, func(h *HAState) { h.BeginShutdown() }},
		{"standby_join_claims", true, func(h *HAState) {
			h.mu.Lock()
			h.role = "standby"
			h.mu.Unlock()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tempHADir(t)
			cfg := cpLeaderConfig(t)
			fake := halease.NewFake(time.Minute)
			h := &HAState{}
			h.SetLeaseProvider(fake, "cp-a")
			t.Cleanup(h.Stop)
			prev := haResumeAfterAcquire
			haResumeAfterAcquire = func() { tc.claim(h) }
			t.Cleanup(func() { haResumeAfterAcquire = prev })

			if tc.guarded {
				if h.ResumeAsLeaderIfUnclaimed(cfg, func() bool { return true }) {
					t.Fatal("the claimed resume applied")
				}
			} else {
				h.ResumeAsLeader(cfg)
			}
			if st := h.Status(); st.Role == "leader" {
				t.Fatal("the claimed resume took the leader role")
			}
			assertNoLocalGrant(t, h, fake, tc.name)
		})
	}
}

// TestChaos71_FailedPromotionAfterTheGrantClearsTheEpoch: onPromote fails or
// panics after the promotion's grant. The node stays a standby that advertises
// no epoch.
func TestChaos71_FailedPromotionAfterTheGrantClearsTheEpoch(t *testing.T) {
	for _, tc := range []struct {
		name      string
		onPromote func() error
	}{
		{"onPromote_error", func() error { return errors.New("bind refused") }},
		{"onPromote_panic", func() error { panic("contained") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := panicStandby(t)
			fake := halease.NewFake(time.Minute)
			h.SetLeaseProvider(fake, "cp-a")
			h.mu.Lock()
			h.pc = promoteContext{set: true, onPromote: tc.onPromote}
			h.mu.Unlock()

			h.promote("test")
			if st := h.Status(); st.Role != "standby" {
				t.Fatalf("role after the failed promotion = %q, want standby", st.Role)
			}
			assertNoLocalGrant(t, h, fake, tc.name)
		})
	}
}

// TestChaos71_RecoveryGrantWithoutTheLeaderRoleClearsTheEpoch: the recovery
// loop's grant lands after the leader role went away (or shutdown began). It
// installs nothing and re-persists no leader config.
func TestChaos71_RecoveryGrantWithoutTheLeaderRoleClearsTheEpoch(t *testing.T) {
	for _, tc := range []struct {
		name string
		lose func(h *HAState)
	}{
		{"role_gone", func(h *HAState) {
			h.mu.Lock()
			h.role = ""
			h.mu.Unlock()
		}},
		{"shutdown", func(h *HAState) { h.BeginShutdown() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tempHADir(t)
			fake := halease.NewFake(time.Minute)
			h := &HAState{}
			lease := &cpHookedLease{Fake: fake}
			lease.afterAcquire = func() { tc.lose(h) }
			h.SetLeaseProvider(lease, "cp-a")
			h.mu.Lock()
			h.role = "leader"
			h.mu.Unlock()
			t.Cleanup(h.Stop)

			var lastLog time.Time
			suppressed := 0
			if !h.leaseRecoveryAttempt(time.Now(), &lastLog, &suppressed) {
				t.Fatal("precondition: the granted round did not end the loop")
			}
			assertNoLocalGrant(t, h, fake, tc.name)
			if _, err := loadHAConfig(); err == nil {
				t.Error("the uninstalled recovery grant re-persisted an HA config")
			}
		})
	}
}

// ── The wall ────────────────────────────────────────────────────────────────

// leaseAcquireHelpers take a grant and hand it to their caller; they install
// nothing themselves, so the wall checks their callers.
var leaseAcquireHelpers = map[string]bool{
	"acquireLeaseAttempt": true, "acquireLeaseForLeadership": true,
	"acquireLeaseForResume": true, "resumeAcquireRound": true,
}

// leaseGrantTakers is every production function that takes a grant through a
// helper and must install or clear it. A new one must be added here, after its
// exits are reviewed.
var leaseGrantTakers = []string{"EnableAsLeader", "leaseRecoveryAttempt", "promote", "resumeAsLeader"}

// leaseGrantClear is the single clear for an uninstalled grant; leaseGrantInstall
// is the install's last step (the keepalive).
const (
	leaseGrantClear   = "clearLeaseGrantLocked"
	leaseGrantInstall = "startLeaseKeepalive"
)

// leaseGrantExits reports, for one grant-taking function, every exit after its
// acquisition that neither installs (a dominating startLeaseKeepalive) nor
// reaches clearLeaseGrantLocked, and is not a denied branch (inside an if or
// case whose condition negates the grant, or tests the acquisition's error).
func leaseGrantExits(funcs map[string][]*ast.FuncDecl, fn *ast.FuncDecl) (bad []string, sawAcquire bool) {
	acq, grantVar, errVar := leaseAcquireSite(fn)
	if acq == nil {
		return nil, false
	}
	marks := func(calls []string) bool {
		for _, c := range calls {
			if c == leaseGrantClear || c == leaseGrantInstall {
				return true
			}
			if _, ok := cpReaches(funcs, c, map[string]bool{leaseGrantClear: true}, 6); ok {
				return true
			}
		}
		return false
	}
	check := func(path []ast.Node, what string) {
		calls, denied := leaseDominating(path, acq, grantVar, errVar)
		if !denied && !marks(calls) {
			bad = append(bad, what)
		}
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		if r, ok := n.(*ast.ReturnStmt); ok && r.Pos() > acq.Pos() {
			check(leasePathTo(fn.Body, r), "the return at body offset "+strconv.Itoa(int(r.Pos()-fn.Body.Pos())))
		}
		return true
	})
	if n := len(fn.Body.List); n > 0 {
		if _, ok := fn.Body.List[n-1].(*ast.ReturnStmt); !ok {
			check([]ast.Node{fn.Body, &ast.EmptyStmt{Semicolon: fn.Body.Rbrace}}, "the implicit return at the end")
		}
	}
	return bad, true
}

// leaseAcquireSite is the first call to an acquisition helper in fn, with the
// identifiers its grant bool and its error are assigned to (if any).
func leaseAcquireSite(fn *ast.FuncDecl) (acq *ast.CallExpr, grantVar, errVar string) {
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if acq != nil {
			return false
		}
		if as, ok := n.(*ast.AssignStmt); ok {
			if c := leaseAcquireCall(as.Rhs); c != nil {
				acq = c
				grantVar, errVar = leaseIdentName(as.Lhs[0]), ""
				if len(as.Lhs) == 3 {
					errVar = leaseIdentName(as.Lhs[2])
				}
				return false
			}
		}
		if c, ok := n.(*ast.CallExpr); ok && leaseAcquireHelpers[leaseSelName(c)] {
			acq = c
			return false
		}
		return true
	})
	return acq, grantVar, errVar
}

// leaseAcquireCall is the acquisition helper call that is the whole
// right-hand side of an assignment, or nil.
func leaseAcquireCall(rhs []ast.Expr) *ast.CallExpr {
	if len(rhs) != 1 {
		return nil
	}
	if c, ok := rhs[0].(*ast.CallExpr); ok && leaseAcquireHelpers[leaseSelName(c)] {
		return c
	}
	return nil
}

func leaseIdentName(e ast.Expr) string {
	if id, ok := e.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

func leaseSelName(c *ast.CallExpr) string {
	switch f := c.Fun.(type) {
	case *ast.SelectorExpr:
		return f.Sel.Name
	case *ast.Ident:
		return f.Name
	}
	return ""
}

// leasePathTo is the chain of nodes from root down to target.
func leasePathTo(root ast.Node, target ast.Node) []ast.Node {
	var path []ast.Node
	var walk func(n ast.Node) bool
	walk = func(n ast.Node) bool {
		if n == nil || n.Pos() > target.Pos() || n.End() < target.End() {
			return false
		}
		path = append(path, n)
		if n == target {
			return true
		}
		found := false
		ast.Inspect(n, func(c ast.Node) bool {
			if found || c == nil || c == n {
				return !found
			}
			if walk(c) {
				found = true
			}
			return false
		})
		if !found {
			path = path[:len(path)-1]
		}
		return found
	}
	walk(root)
	return path
}

// leaseDom collects the calls that run on every path from the acquisition to
// one exit, and whether that exit is on a branch where no grant was taken.
type leaseDom struct {
	acq              *ast.CallExpr
	grantVar, errVar string
	calls            []string
	denied           bool
}

// add records every call in n (not inside a function literal: it does not run
// here).
func (d *leaseDom) add(n ast.Node) {
	if n == nil {
		return
	}
	ast.Inspect(n, func(c ast.Node) bool {
		if _, ok := c.(*ast.FuncLit); ok {
			return false
		}
		if call, ok := c.(*ast.CallExpr); ok {
			d.calls = append(d.calls, leaseSelName(call))
		}
		return true
	})
}

// addStmt: a preceding simple statement runs on the way to the exit; of a
// preceding if, only its init and condition do.
func (d *leaseDom) addStmt(st ast.Stmt) {
	switch x := st.(type) {
	case *ast.ExprStmt, *ast.AssignStmt, *ast.DeclStmt, *ast.IncDecStmt, *ast.SendStmt:
		d.add(x)
	case *ast.IfStmt:
		d.add(x.Init)
		d.add(x.Cond)
	}
}

// deniedCond: e holds only when no grant was taken — it negates the
// acquisition or its grant bool, or tests its error.
func (d *leaseDom) deniedCond(e ast.Expr) bool {
	hit := false
	ast.Inspect(e, func(c ast.Node) bool {
		switch x := c.(type) {
		case *ast.UnaryExpr:
			hit = hit || (x.Op == token.NOT && (x.X == d.acq || (d.grantVar != "" && leaseIdentName(x.X) == d.grantVar)))
		case *ast.BinaryExpr:
			hit = hit || (x.Op == token.NEQ && d.errVar != "" && leaseIdentName(x.X) == d.errVar && leaseIdentName(x.Y) == "nil")
		}
		return !hit
	})
	return hit
}

// visit accounts for one enclosing node n of the exit, whose child on the way
// to the exit is child.
func (d *leaseDom) visit(n, child ast.Node) {
	switch s := n.(type) {
	case *ast.BlockStmt:
		for _, st := range s.List {
			if st.Pos() >= child.Pos() {
				break
			}
			if st.End() >= d.acq.Pos() {
				d.addStmt(st)
			}
		}
	case *ast.CaseClause:
		for _, e := range s.List {
			d.add(e)
			d.denied = d.denied || d.deniedCond(e)
		}
		for _, st := range s.Body {
			if st.Pos() >= child.Pos() {
				break
			}
			d.addStmt(st)
		}
	case *ast.IfStmt:
		d.add(s.Init)
		d.add(s.Cond)
		d.denied = d.denied || (child == s.Body && d.deniedCond(s.Cond))
	case *ast.SwitchStmt:
		d.add(s.Init)
		d.add(s.Tag)
	}
}

// leaseDominating collects the calls that run on every path from the
// acquisition to the exit at the end of path: whole simple statements that
// precede it in an enclosing block (from the acquisition on), and the init and
// condition of every enclosing if / switch / case. denied reports a branch
// that runs only when no grant was taken.
func leaseDominating(path []ast.Node, acq *ast.CallExpr, grantVar, errVar string) (calls []string, denied bool) {
	d := &leaseDom{acq: acq, grantVar: grantVar, errVar: errVar}
	for i := 0; i+1 < len(path); i++ {
		d.visit(path[i], path[i+1])
	}
	return d.calls, d.denied
}

// TestChaos71_Wall_EveryLeaseGrantIsInstalledOrCleared: every function that
// takes a fencing grant (calls an acquisition helper) leaves it, on every exit
// after the acquisition, either installed (startLeaseKeepalive dominates the
// exit) or cleared (the exit is dominated by a call reaching
// clearLeaseGrantLocked), unless the exit is a branch on which no grant was
// taken. The lease Acquire itself is called only by acquireLeaseAttempt.
func TestChaos71_Wall_EveryLeaseGrantIsInstalledOrCleared(t *testing.T) {
	funcs, _ := cpParseFuncsAndGateHolders(t)
	var takers []string
	for name, decls := range funcs {
		for _, fn := range decls {
			for _, c := range cpCallees(fn) {
				if c == "Acquire" && name != "acquireLeaseAttempt" && !leaseCallsConnLimiter(fn) {
					t.Errorf("%s calls a lease Acquire directly — acquire through acquireLeaseAttempt", name)
				}
			}
			if leaseAcquireHelpers[name] {
				continue
			}
			bad, took := leaseGrantExits(funcs, fn)
			if !took {
				continue
			}
			takers = append(takers, name)
			for _, b := range bad {
				t.Errorf("%s: %s neither installs nor clears the fencing grant it took (clearLeaseGrantLocked)", name, b)
			}
		}
	}
	sort.Strings(takers)
	if strings.Join(takers, ",") != strings.Join(leaseGrantTakers, ",") {
		t.Errorf("grant-taking functions = %v, want %v — review a new taker's exits and list it", takers, leaseGrantTakers)
	}
}

// leaseCallsConnLimiter: the only other production Acquire is the
// connection limiter's.
func leaseCallsConnLimiter(fn *ast.FuncDecl) bool {
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "Acquire" {
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == "connLimiter" {
				found = true
			}
		}
		return !found
	})
	return found
}
