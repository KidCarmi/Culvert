package main

// ha_alert_lock_chaos_test.go — CHAOS-71: no alert is dispatched, or queued
// for the startup flush, while HAState.mu is held (CodeRabbit 4315714615 on
// #1645). fireAlert runs globalAlertStore.Dispatch synchronously: it takes the
// store's dedup mutex and can run an O(n) expiry scan, so a page sent under
// h.mu can delay lease renewal and every HA status reader. An HA producer
// records its episode and builds the page under h.mu, and dispatches it only
// after the caller releases the lock (haDeferredPage).

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// cpAlertDispatchPrimitives are the synchronous alert sinks: the dispatch
// itself (fireAlert → AlertStore.Dispatch, the internal/alerts sink Fire, the
// startup flush's startupAlertFire) and the startup-queue enqueue
// (deferStartupAlert, deferStartupAlertWhile).
var cpAlertDispatchPrimitives = map[string]bool{
	"fireAlert": true, "startupAlertFire": true, "Dispatch": true, "Fire": true,
	"deferStartupAlert": true, "deferStartupAlertWhile": true,
}

// TestChaos71_Wall_NoAlertDispatchUnderTheHALock: no code path that holds
// HAState.mu reaches an alert dispatch or the startup-alert enqueue — not a
// *Locked HAState method (called with h.mu held), and not a call made inside
// an h.mu (or globalHA.mu) critical section. The by-name call graph is
// conservative and follows package-level function seams. A `go` statement
// dispatches on another goroutine, after the lock is released, so it is not a
// synchronous dispatch under the lock and is not followed.
func TestChaos71_Wall_NoAlertDispatchUnderTheHALock(t *testing.T) {
	funcs := cpFuncsWithSeams(t)
	offenders, lockedMethods, regions := cpAlertDispatchUnderHALock(funcs)
	for _, o := range offenders {
		t.Errorf("%s — dispatch the page after releasing HAState.mu (haDeferredPage)", o)
	}
	if lockedMethods < 3 || regions < 20 {
		t.Fatalf("the wall saw %d *Locked HAState methods and %d HA lock regions — its selectors have gone stale", lockedMethods, regions)
	}
	// The producers the wall exists for are still seen: each records its
	// episode under h.mu and pages afterwards.
	for _, name := range []string{"noteEpochRefusedLocked", "commitGrant", "exposeGrantLocked", "noteIntentUnreadable"} {
		if len(funcs[name]) == 0 {
			t.Errorf("%s is gone — re-point the wall at the HA page producers", name)
		}
	}
}

// TestChaos71_Wall_AlertUnderTheHALockWallCatchesAnInjectedDispatch — the
// negative control. Declarations injected in memory (the real source is not
// touched): a *Locked method that fires directly, an h.mu region that reaches
// the startup enqueue through a helper, a deferred-unlock region that
// dispatches, and a seam that dispatches. Each must be flagged. A page
// dispatched after the unlock, and one handed to a goroutine, must not be.
func TestChaos71_Wall_AlertUnderTheHALockWallCatchesAnInjectedDispatch(t *testing.T) {
	const src = `package main
func (h *HAState) cpInjectedPageLocked() { fireAlert("x", AlertPayload{}) }
func (h *HAState) cpInjectedRegion() {
	h.mu.Lock()
	h.cpInjectedHelper()
	h.mu.Unlock()
}
func (h *HAState) cpInjectedHelper() { deferStartupAlertWhile("x", AlertPayload{}, nil) }
func (h *HAState) cpInjectedDeferredUnlock() {
	h.mu.Lock()
	defer h.mu.Unlock()
	globalAlertStore.Dispatch("x", AlertPayload{})
}
var cpInjectedSeam = func() { startupAlertFire("x", AlertPayload{}) }
func (h *HAState) cpInjectedSeamCaller() {
	h.mu.Lock()
	cpInjectedSeam()
	h.mu.Unlock()
}
func (h *HAState) cpInjectedAfterUnlock() {
	h.mu.Lock()
	h.mu.Unlock()
	fireAlert("x", AlertPayload{})
}
func (h *HAState) cpInjectedGoLocked() { go fireAlert("x", AlertPayload{}) }
`
	f, err := parser.ParseFile(token.NewFileSet(), "injected.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	funcs := cpFuncsWithSeams(t)
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			funcs[fn.Name.Name] = append(funcs[fn.Name.Name], fn)
		}
	}
	for _, fd := range cpSeamDecls(f) {
		funcs[fd.Name.Name] = append(funcs[fd.Name.Name], fd)
	}
	offenders, _, _ := cpAlertDispatchUnderHALock(funcs)
	flagged := func(name string) bool {
		for _, o := range offenders {
			if strings.HasPrefix(o, name+" ") {
				return true
			}
		}
		return false
	}
	for _, want := range []string{"cpInjectedPageLocked", "cpInjectedRegion", "cpInjectedDeferredUnlock", "cpInjectedSeamCaller"} {
		if !flagged(want) {
			t.Errorf("the wall missed the injected dispatch under the HA lock in %s (offenders: %v)", want, offenders)
		}
	}
	for _, clean := range []string{"cpInjectedAfterUnlock", "cpInjectedGoLocked"} {
		if flagged(clean) {
			t.Errorf("the wall flagged %s, which dispatches off the HA lock (offenders: %v)", clean, offenders)
		}
	}
}

// cpAlertDispatchUnderHALock returns one line per path from HAState.mu to an
// alert primitive, plus how many *Locked HAState methods and lock regions it
// scanned.
func cpAlertDispatchUnderHALock(funcs map[string][]*ast.FuncDecl) (offenders []string, lockedMethods, regions int) {
	names := make([]string, 0, len(funcs))
	for name := range funcs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, fn := range funcs[name] {
			recv := cpHAStateReceiver(fn)
			if recv != "" && strings.HasSuffix(name, "Locked") {
				lockedMethods++
				if path, bad := cpReachesSync(funcs, name, cpAlertDispatchPrimitives, 10); bad {
					offenders = append(offenders, name+" runs with HAState.mu held and reaches "+strings.Join(path, " → "))
				}
			}
			n, callees := cpScanHALockedCalls(fn.Body, recv)
			regions += n
			for _, callee := range callees {
				if cpAlertDispatchPrimitives[callee] {
					offenders = append(offenders, name+" calls "+callee+" while holding HAState.mu")
					continue
				}
				if cpGenericMethodNames[callee] {
					continue
				}
				if path, bad := cpReachesSync(funcs, callee, cpAlertDispatchPrimitives, 10); bad {
					offenders = append(offenders, name+" calls "+callee+" while holding HAState.mu, reaching "+strings.Join(path, " → "))
				}
			}
		}
	}
	return offenders, lockedMethods, regions
}

// cpReachesSync is cpReaches over the synchronous call graph: a call made by
// a `go` statement runs on another goroutine and is not followed.
func cpReachesSync(funcs map[string][]*ast.FuncDecl, start string, forbidden map[string]bool, depth int) ([]string, bool) {
	type node struct {
		name string
		path []string
	}
	seen := map[string]bool{start: true}
	queue := []node{{start, []string{start}}}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if len(cur.path) > depth {
			continue
		}
		for _, decl := range funcs[cur.name] {
			for _, callee := range cpSyncCallees(decl) {
				if forbidden[callee] {
					return append(append([]string(nil), cur.path...), callee), true
				}
				if !seen[callee] {
					seen[callee] = true
					queue = append(queue, node{callee, append(append([]string(nil), cur.path...), callee)})
				}
			}
		}
	}
	return nil, false
}

// cpGenericMethodNames are method names the by-name graph does not follow:
// the sync/atomic, mutex, io and context methods every lock region calls. By
// name alone they would alias unrelated package-main methods (a state
// loader's Load, a store's Add), and the wall would report paths no
// execution takes. No alert primitive is in the list, so Dispatch and Fire
// are still matched.
var cpGenericMethodNames = map[string]bool{
	"Load": true, "Store": true, "Add": true, "Swap": true, "CompareAndSwap": true,
	"Lock": true, "Unlock": true, "RLock": true, "RUnlock": true, "TryLock": true,
	"Read": true, "Write": true, "Close": true, "Done": true, "Err": true, "Wait": true,
	"String": true, "Error": true,
}

// cpSyncCallees is cpCallees without the calls `go` statements start, and
// without generic method names (cpGenericMethodNames).
func cpSyncCallees(fn *ast.FuncDecl) []string {
	var out []string
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch c := n.(type) {
		case *ast.GoStmt:
			return false
		case *ast.CallExpr:
			switch f := c.Fun.(type) {
			case *ast.Ident:
				out = append(out, f.Name)
			case *ast.SelectorExpr:
				if !cpGenericMethodNames[f.Sel.Name] {
					out = append(out, f.Sel.Name)
				}
			}
		}
		return true
	})
	return out
}

// cpAssertHALockFree proves h.mu is not held by the caller of the seam it is
// called from: a TryLock that succeeds at least once within the bound. A
// caller holding h.mu would hold it for the whole call, so every attempt
// would fail; another goroutine's brief hold (the keepalive) only delays it.
func cpAssertHALockFree(h *HAState) bool {
	deadline := time.Now().Add(2 * time.Second)
	for {
		if h.mu.TryLock() {
			h.mu.Unlock()
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(time.Millisecond)
	}
}

// cpLockCheckedPages captures config_snapshot_rejected pages from fireAlert
// and from the startup flush, and counts every one dispatched while h.mu was
// held.
func cpLockCheckedPages(t *testing.T, h *HAState) (pages func() int, underLock *atomic.Int32) {
	t.Helper()
	var mu sync.Mutex
	n := 0
	underLock = &atomic.Int32{}
	record := func(event string, p AlertPayload) {
		if event != "config_snapshot_rejected" || p.Source != "ha" {
			return
		}
		if !cpAssertHALockFree(h) {
			underLock.Add(1)
		}
		mu.Lock()
		n++
		mu.Unlock()
	}
	prevFire, prevStartup := fireAlert, startupAlertFire
	fireAlert, startupAlertFire = record, record
	t.Cleanup(func() { fireAlert, startupAlertFire = prevFire, prevStartup })
	return func() int { mu.Lock(); defer mu.Unlock(); return n }, underLock
}

// TestChaos71_EpochRefusalPagesOncePerEpisodeOffTheHALock: an epoch refusal
// pages exactly once per episode, and the page is dispatched with h.mu
// released — on the commit's refusal (enable), on the exposure's refusal (a
// promote whose activation's first publish did not commit), on a second
// refusal in the same episode (a recovery round: no second page), and on the
// boot path, where it is queued and delivered once at the startup flush.
func TestChaos71_EpochRefusalPagesOncePerEpisodeOffTheHALock(t *testing.T) {
	const (
		myAddr = "10.0.0.2:50051"
		peer   = "10.0.0.9:50051"
	)
	assert := func(t *testing.T, pages func() int, underLock *atomic.Int32, want int) {
		t.Helper()
		if n := pages(); n != want {
			t.Errorf("the epoch refusal paged %d time(s), want %d", n, want)
		}
		if n := underLock.Load(); n != 0 {
			t.Errorf("%d epoch-refusal page(s) were dispatched while HAState.mu was held", n)
		}
	}
	t.Run("commit_refusal", func(t *testing.T) {
		h, f, _ := cpEpochHarness(t, myAddr)
		pages, underLock := cpLockCheckedPages(t, h)
		cpRejectEpochStamp(t, cpNextGrantEpoch(t, f))
		if _, err := h.EnableAsLeader(peer, false); err == nil {
			t.Fatal("enable succeeded although its epoch could not be committed")
		}
		assert(t, pages, underLock, 1)
	})
	t.Run("same_episode_pages_once", func(t *testing.T) {
		h, f, _ := cpEpochHarness(t, myAddr)
		pages, underLock := cpLockCheckedPages(t, h)
		cpReadOnlyLeader(t, h, f) // the resume refusal opens the episode
		f.ExpireForTest()
		cpRejectEpochStamp(t, cpNextGrantEpoch(t, f))
		if cpRecoveryRound(h) {
			t.Fatal("the recovery round reported done although its epoch could not be committed")
		}
		assert(t, pages, underLock, 1)
	})
	t.Run("exposure_refusal", func(t *testing.T) {
		// A promote with nothing published: the preflight passes, then the
		// config grows and the activation's first publish is rejected, so the
		// exposure finds no committed snapshot carrying the epoch.
		h, _, _ := cpUnpublishedEpochHarness(t, nil)
		pages, underLock := cpLockCheckedPages(t, h)
		prev := snapshotWireBudget
		t.Cleanup(func() { snapshotWireBudget = prev })
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		h.StartAsStandby(ctx, "10.0.0.7:50051", "tok", myAddr, "", "", "", false, func() error {
			globalConfigStore.setCPAddressSource(buildCPAddressList)
			snapshotWireBudget = 16
			_ = globalConfigStore.Update(CurrentConfigSnapshot())
			return nil
		})
		if err := h.PromoteManually(); err == nil {
			t.Fatal("promote succeeded although no committed snapshot carries its epoch")
		}
		assert(t, pages, underLock, 1)
	})
	t.Run("boot_queue_delivers_once_at_the_flush", func(t *testing.T) {
		h, f, _ := cpEpochHarness(t, myAddr)
		cpStartupAlertsLoaded(t, false) // boot: the webhooks are not loaded yet
		pages, underLock := cpLockCheckedPages(t, h)
		cpRejectEpochStamp(t, cpNextGrantEpoch(t, f))
		h.ResumeAsLeader(&haConfig{Enabled: true, Role: "leader", PeerAddr: peer, Token: "tok"})
		if n := pages(); n != 0 {
			t.Fatalf("%d page(s) fired before the webhooks loaded", n)
		}
		flushStartupAlerts() // the episode is still open: delivered
		assert(t, pages, underLock, 1)
	})
	t.Run("boot_queue_drops_a_closed_episode", func(t *testing.T) {
		h, f, _ := cpEpochHarness(t, myAddr)
		cpStartupAlertsLoaded(t, false)
		pages, underLock := cpLockCheckedPages(t, h)
		cpRejectEpochStamp(t, cpNextGrantEpoch(t, f))
		h.ResumeAsLeader(&haConfig{Enabled: true, Role: "leader", PeerAddr: peer, Token: "tok"})
		h.mu.Lock()
		h.epochRefused = false // a later install ended the episode before the flush
		h.mu.Unlock()
		flushStartupAlerts()
		assert(t, pages, underLock, 0)
	})
}
