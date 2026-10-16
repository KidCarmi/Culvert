package main

// cdr_breaker_serialized_test.go — the CDR breaker's coupled state
// (state, openedAt, half-open generation, newest-reservation stamp, probe
// budget) changes in ONE critical section per transition, and only the
// sanitize RPC path may reserve a probe (PR #1611 review, three Codex P1s on
// 155a936):
//
//  1. A failed probe's cleanup ran after the state had flipped to open; a
//     concurrent Reserve re-armed half-open in between and the cleanup then
//     zeroed its generation — state half-open with no generation, and every
//     later reserver spun.
//  2. A stale re-arm published its generation before its stamp and budget, so
//     a second contender re-armed again and both were admitted past a
//     one-probe budget.
//  3. GET /api/cdr/config reached Pick() through cdrActiveClient() and
//     reserved the sole half-open probe for a status read, so proxy traffic
//     saw no instance and (fail-open by default) forwarded unsanitized.
//
// The interleaving tests pause a goroutine INSIDE a transition through the
// breaker's injected clock (the only call a transition makes out of its own
// code), prove the breaker's mutex is held at that point, release it, and
// check the outcome. No test sleeps.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/KidCarmi/Sluice/proto/sluicev1"
)

// pausingClock is a test clock whose NEXT read, once armed, blocks the
// reading goroutine until resume is called. Because every transition reads
// the clock while holding the breaker's mutex, a paused reader is a
// goroutine frozen mid-transition.
type pausingClock struct {
	cur     atomic.Int64
	armed   atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func newPausingClock(b *cdrCircuitBreaker) *pausingClock {
	c := &pausingClock{}
	c.cur.Store(time.Now().UnixNano())
	b.setNowFn(c.now)
	return c
}

func (c *pausingClock) now() time.Time {
	if c.armed.CompareAndSwap(true, false) {
		close(c.entered)
		<-c.release
	}
	return time.Unix(0, c.cur.Load())
}

func (c *pausingClock) advance(d time.Duration) { c.cur.Add(int64(d)) }

// pauseNext arms the clock; the returned function waits until a goroutine is
// frozen in it.
func (c *pausingClock) pauseNext() (waitEntered func()) {
	c.entered = make(chan struct{})
	c.release = make(chan struct{})
	c.armed.Store(true)
	return func() { <-c.entered }
}

func (c *pausingClock) resume() { close(c.release) }

// assertHeldMidTransition proves the frozen goroutine is inside the breaker's
// critical section: nobody else can be part-way through a transition with it.
func assertHeldMidTransition(t *testing.T, b *cdrCircuitBreaker, what string) {
	t.Helper()
	if b.mu.TryLock() {
		b.mu.Unlock()
		t.Fatalf("%s runs outside the breaker mutex — a concurrent transition can "+
			"interleave with it", what)
	}
}

// breakerInvariantViolation checks the coupled-state invariants under the
// lock and describes the first one broken, or returns "".
func breakerInvariantViolation(b *cdrCircuitBreaker) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	state, gen, tried := b.state.Load(), b.halfOpenGen.Load(), b.halfOpenTried.Load()
	switch {
	case state == cbStateHalfOpen && gen == 0:
		return "state half-open with generation 0 — every reserver would spin"
	case tried < 0 || tried > b.cfg.HalfOpenProbes:
		return fmt.Sprintf("probe budget %d outside [0, %d]", tried, b.cfg.HalfOpenProbes)
	case state != cbStateHalfOpen && tried != 0:
		return fmt.Sprintf("%d probe slots held while %s", tried, breakerStateName(state))
	}
	return ""
}

func assertBreakerInvariants(t *testing.T, b *cdrCircuitBreaker, when string) {
	t.Helper()
	if v := breakerInvariantViolation(b); v != "" {
		t.Fatalf("%s: %s", when, v)
	}
}

// halfOpenWithProbe returns a breaker in half-open with its single probe
// reserved, driven by a pausing clock.
func halfOpenWithProbe(t *testing.T) (*cdrCircuitBreaker, *pausingClock, cdrProbeReservation) {
	t.Helper()
	b := newCDRCircuitBreaker(cdrBreakerConfig{})
	clk := newPausingClock(b)
	tripOpen(t, b)
	clk.advance(b.cfg.ResetTimeout + time.Second)
	ok, r := b.Reserve()
	if !ok || b.State() != cbStateHalfOpen || r.gen == 0 {
		t.Fatalf("setup: Reserve = (%v, gen %d) in %s, want the half-open probe",
			ok, r.gen, breakerStateName(b.State()))
	}
	return b, clk, r
}

// TestCDRBreaker_FailedProbeCleanupIsAtomicWithReopen is scenario 1. The
// probe fails; while its OnFailure is frozen mid-transition, a Reserve is
// issued whose clock is already past ResetTimeout from the OLD openedAt —
// exactly the reader that used to re-arm half-open in the gap. It must wait
// for the transition, see the fresh reset timer, be denied, and leave no
// half-open-without-generation state behind.
func TestCDRBreaker_FailedProbeCleanupIsAtomicWithReopen(t *testing.T) {
	b, clk, _ := halfOpenWithProbe(t)
	clk.advance(b.cfg.ResetTimeout + time.Second) // past ResetTimeout from the old openedAt

	waitEntered := clk.pauseNext()
	failed := make(chan struct{})
	go func() { b.OnFailure(); close(failed) }()
	waitEntered()
	assertHeldMidTransition(t, b, "the failed-probe transition")

	type result struct {
		ok bool
		r  cdrProbeReservation
	}
	reserved := make(chan result, 1)
	go func() { ok, r := b.Reserve(); reserved <- result{ok, r} }()
	clk.resume()
	<-failed
	got := <-reserved

	if got.ok {
		t.Fatalf("REGRESSION: a Reserve racing the failed probe was admitted (gen %d) — it "+
			"re-armed half-open against the stale openedAt", got.r.gen)
	}
	if b.State() != cbStateOpen {
		t.Fatalf("state %s after a failed probe, want open", breakerStateName(b.State()))
	}
	assertBreakerInvariants(t, b, "after the failed probe")

	// The next legitimate recovery still works and terminates.
	clk.advance(b.cfg.ResetTimeout + time.Second)
	if ok, r := b.Reserve(); !ok || r.gen == 0 {
		t.Fatalf("recovery Reserve = (%v, gen %d), want a fresh half-open probe", ok, r.gen)
	}
	if ok, _ := b.Reserve(); ok {
		t.Fatal("a second probe was admitted past the one-probe budget")
	}
	assertBreakerInvariants(t, b, "after recovery")
}

// TestCDRBreaker_StaleReArmAdmitsExactlyOne is scenario 2. The probe is
// abandoned past HalfOpenProbeTimeout; the first contender is frozen inside
// its re-arm while a burst of others queue. Exactly one may be admitted.
func TestCDRBreaker_StaleReArmAdmitsExactlyOne(t *testing.T) {
	b, clk, _ := halfOpenWithProbe(t) // the probe is never reported: abandoned
	clk.advance(b.cfg.HalfOpenProbeTimeout + time.Second)

	waitEntered := clk.pauseNext()
	var admitted atomic.Int32
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if ok, _ := b.Reserve(); ok {
			admitted.Add(1)
		}
	}()
	waitEntered()
	assertHeldMidTransition(t, b, "the stale re-arm")

	const burst = 16
	for i := 0; i < burst; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, _ := b.Reserve(); ok {
				admitted.Add(1)
			}
		}()
	}
	clk.resume()
	wg.Wait()

	if n := admitted.Load(); n != 1 {
		t.Fatalf("REGRESSION: %d contenders admitted by one stale re-arm, want exactly 1 — "+
			"a recovering Sluice gets a burst instead of a probe", n)
	}
	if n := b.staleProbes.Load(); n != 1 {
		t.Fatalf("staleProbes = %d, want 1 re-arm", n)
	}
	assertBreakerInvariants(t, b, "after the burst")
}

// TestCDRConfigGet_DoesNotConsumeTheProbe is scenario 3, plus every other
// status/UI/diagnostic selector: none may reserve the half-open probe, and
// the sanitize path must still find it afterwards.
func TestCDRConfigGet_DoesNotConsumeTheProbe(t *testing.T) {
	resetCDRCountersAndCache(t)
	freshPolicyStore(t)
	c, stop := startFakeSluice(t, &fakeSluice{result: &pb.SanitizeResult{Status: pb.Status_CLEAN}})
	t.Cleanup(stop)
	withActiveCDRClient(t, c, CDRConfig{Enabled: true})
	pc := cdrPool.List()[0]
	b := pc.Breaker
	clk := newPausingClock(b)
	tripOpen(t, b)
	clk.advance(b.cfg.ResetTimeout + time.Second)

	rec := httptest.NewRecorder()
	apiCDRConfigGet(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/cdr/config", http.NoBody))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"clientActive":true`) {
		t.Fatalf("GET /api/cdr/config = %d %s, want 200 with clientActive=true",
			rec.Code, rec.Body.String())
	}
	assertProbeUntouched(t, b, "GET /api/cdr/config")
	// The other non-sanitize selectors.
	if cdrActiveClient() == nil || cdrPool.Pick() == nil {
		t.Fatal("status selectors report no instance past ResetTimeout")
	}
	_ = cdrPickOtherClient("not-" + pc.Name)
	_ = cdrPickClientNotHolding("no-such-fingerprint")

	assertProbeUntouched(t, b, "the status/diagnostic selectors")
	out := safeCDRSanitize(t.Context(), sampleReq("example.com"), []byte("doc-after-status"),
		"application/pdf", sampleID, cdrActiveConfig())
	if out.Status != "CLEAN" || b.State() != cbStateClosed {
		t.Fatalf("the document after the status reads got %q and left the breaker %s, "+
			"want CLEAN and closed", out.Status, breakerStateName(b.State()))
	}
}

// assertProbeUntouched requires that a read left an open breaker open with no
// probe slot held.
func assertProbeUntouched(t *testing.T, b *cdrCircuitBreaker, what string) {
	t.Helper()
	if b.State() != cbStateOpen || b.halfOpenTried.Load() != 0 {
		t.Fatalf("REGRESSION: %s moved the breaker to %s with %d probe slot(s) held — "+
			"the probe the next document needs was spent on a read",
			what, breakerStateName(b.State()), b.halfOpenTried.Load())
	}
}

// stressLedger counts, per half-open generation, the holders a stress worker
// has been admitted and not yet retired, and records any generation that ever
// held more than the budget.
type stressLedger struct {
	budget     int
	mu         sync.Mutex
	live       map[int64]int
	overBudget atomic.Int64
}

func (l *stressLedger) admit(gen int64) {
	if gen == 0 {
		return // closed-state admission: no budget involved
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.live[gen]++
	if l.live[gen] > l.budget {
		l.overBudget.Add(1)
	}
}

// retire runs BEFORE the breaker frees the slot, so the ledger can never
// count a holder the breaker has already replaced.
func (l *stressLedger) retire(gen int64) {
	if gen == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.live[gen]--
}

// invariantChecker re-checks the coupled invariants under the breaker lock
// until stop is closed, keeping the first violation.
type invariantChecker struct {
	checks    atomic.Int64
	violation atomic.Value
	done      chan struct{}
}

func startInvariantChecker(b *cdrCircuitBreaker, stop <-chan struct{}) *invariantChecker {
	c := &invariantChecker{done: make(chan struct{})}
	go func() {
		defer close(c.done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if v := breakerInvariantViolation(b); v != "" {
				c.violation.CompareAndSwap(nil, v)
			}
			c.checks.Add(1)
		}
	}()
	return c
}

// stressSteps are the clock advances a worker cycles through; mixed so the
// reset timer, the stale-probe timeout and fresh reservations all interleave.
var stressSteps = []time.Duration{0, time.Millisecond, 3 * time.Millisecond, 7 * time.Millisecond}

// runStressWorker is one worker: reserve, then release, succeed, fail or
// abandon (never report — only the stale reclaim recovers that slot).
func runStressWorker(b *cdrCircuitBreaker, clock *atomic.Int64, ledger *stressLedger, g, iters int) {
	for i := 0; i < iters; i++ {
		clock.Add(int64(stressSteps[(g+i)%len(stressSteps)]))
		ok, r := b.Reserve()
		if !ok {
			_ = b.Available()
			continue
		}
		ledger.admit(r.gen)
		switch (g*31 + i*17) % 5 {
		case 0:
			ledger.retire(r.gen)
			b.Release(r)
		case 1:
			ledger.retire(r.gen)
			b.OnSuccess()
			b.Release(r) // the deferred-release shape: must be a no-op now
		case 2, 3:
			ledger.retire(r.gen)
			b.OnFailure()
			b.Release(r)
		case 4:
			// Abandoned.
		}
	}
}

// TestCDRBreaker_ConcurrentTransitionsKeepInvariants is the -race stress gate:
// concurrent Reserve, Release, OnSuccess, OnFailure, abandonment (which drives
// the stale reclaim) and Available over a shared advancing clock. A checker
// asserts the coupled invariants under the lock throughout, and per budget
// generation no more holders are ever live than the budget allows. The test
// terminating at all is the no-spin assertion.
func TestCDRBreaker_ConcurrentTransitionsKeepInvariants(t *testing.T) {
	const budget = 2
	b := newCDRCircuitBreaker(cdrBreakerConfig{
		FailureThreshold:     2,
		ResetTimeout:         10 * time.Millisecond,
		HalfOpenProbes:       budget,
		HalfOpenProbeTimeout: 40 * time.Millisecond,
	})
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	b.setNowFn(func() time.Time { return time.Unix(0, clock.Load()) })
	ledger := &stressLedger{budget: budget, live: map[int64]int{}}

	stop := make(chan struct{})
	checker := startInvariantChecker(b, stop)

	const workers, iters = 8, 3000
	var wg sync.WaitGroup
	for g := 0; g < workers; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			runStressWorker(b, &clock, ledger, g, iters)
		}(g)
	}
	finished := make(chan struct{})
	go func() { wg.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(60 * time.Second):
		t.Fatal("REGRESSION: workers did not finish — a reserver is spinning")
	}
	close(stop)
	<-checker.done

	if v := checker.violation.Load(); v != nil {
		t.Fatalf("REGRESSION: invariant broken under concurrent transitions: %v", v)
	}
	if n := ledger.overBudget.Load(); n != 0 {
		t.Fatalf("REGRESSION: %d admissions exceeded the %d-probe budget of their generation", n, budget)
	}
	if checker.checks.Load() == 0 {
		t.Fatal("the invariant checker never ran; the test proves nothing")
	}
	if b.staleProbes.Load() == 0 {
		t.Fatal("no stale reclaim happened; the abandonment arm was not exercised")
	}
	assertBreakerInvariants(t, b, "after stress")
}

// TestCDRBreaker_ReservingCallsOnlyOnTheSanitizePath is the AST wall: a
// half-open probe may be reserved only by the caller that issues the
// sanitize RPC and therefore records or releases it. Any other production
// reservation — a status handler, a UI liveness check, a diagnostic — strands
// the probe the next document needs.
//
// It pins, across every non-test .go file in package main:
//   - no `<x>.Breaker.Allow` / `<x>.Breaker.Reserve` anywhere (callers go
//     through the pool);
//   - the reserving method expression `(*cdrCircuitBreaker).Reserve` only in
//     cdrClientPool.PickReserved;
//   - `.PickReserved` only in cdrPickPooledReserved;
//   - `cdrPickPooledReserved` only in the two Sanitize RPC callers
//     (safeCDRSanitize, apiCDRTest) — TestCDRRPC_EverySanitizeCallOwnsAReservation
//     pins the converse, that every Sanitize call reserves;
//   - any other `.Reserve` in a cdr*.go file only in Allow (the breaker's
//     own test-only wrapper) — so a pool selector cannot quietly reserve
//     through a closure.
func TestCDRBreaker_ReservingCallsOnlyOnTheSanitizePath(t *testing.T) {
	allowed := map[string]map[string]bool{ // selector/ident -> enclosing funcs
		"Reserve(method-expr)":  {"PickReserved": true},
		"PickReserved":          {"cdrPickPooledReserved": true},
		"cdrPickPooledReserved": {"safeCDRSanitize": true, "apiCDRTest": true},
		"Reserve(cdr)":          {"Allow": true},
	}
	entries, err := os.ReadDir(pkgSourceDir())
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	seen := map[string]int{}
	for _, ent := range entries {
		name := ent.Name()
		if ent.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(pkgSourceDir(), name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				key := reservingUse(n, strings.HasPrefix(name, "cdr"))
				if key == "" {
					return true
				}
				seen[key]++
				if !allowed[key][fn.Name.Name] {
					t.Errorf("%s: %s in %s — only the sanitize RPC path may reserve a "+
						"half-open probe; status/UI/diagnostic callers must use Available()/Pick()",
						fset.Position(n.Pos()), key, fn.Name.Name)
				}
				return true
			})
		}
	}
	for key := range allowed {
		if seen[key] == 0 {
			t.Errorf("the wall found no %s at all — it has gone vacuous (renamed?)", key)
		}
	}
}

// reservingUse classifies n as one of the reserving uses the wall tracks, or
// "" when it is none. `Breaker.Allow` / `Breaker.Reserve` are reported under
// a key no function is allowed.
func reservingUse(n ast.Node, cdrFile bool) string {
	switch x := n.(type) {
	case *ast.SelectorExpr:
		switch x.Sel.Name {
		case "Allow", "Reserve":
			if inner, ok := x.X.(*ast.SelectorExpr); ok && inner.Sel.Name == "Breaker" {
				return "Breaker." + x.Sel.Name
			}
			if x.Sel.Name == "Reserve" && isBreakerTypeExpr(x.X) {
				return "Reserve(method-expr)"
			}
			if x.Sel.Name == "Reserve" && cdrFile {
				return "Reserve(cdr)"
			}
		case "PickReserved":
			return "PickReserved"
		}
	case *ast.Ident:
		if x.Name == "cdrPickPooledReserved" {
			return "cdrPickPooledReserved"
		}
	}
	return ""
}

// isBreakerTypeExpr matches `(*cdrCircuitBreaker)`.
func isBreakerTypeExpr(e ast.Expr) bool {
	if p, ok := e.(*ast.ParenExpr); ok {
		e = p.X
	}
	star, ok := e.(*ast.StarExpr)
	if !ok {
		return false
	}
	id, ok := star.X.(*ast.Ident)
	return ok && id.Name == "cdrCircuitBreaker"
}
