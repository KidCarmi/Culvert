package ssrf

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// gatedResolver answers every lookup with answer/err once the test closes
// gate, or ends when the lookup's context does. It counts lookups and records
// the cause each cancelled lookup observed.
type gatedResolver struct {
	gate    chan struct{}
	exited  chan error // one send per lookup: nil on answer, cause on cancel
	lookups atomic.Int64
	answer  []string
	err     error
}

func newGatedResolver(t *testing.T, answer []string, err error) *gatedResolver {
	t.Helper()
	g := &gatedResolver{gate: make(chan struct{}), exited: make(chan error, 4096), answer: answer, err: err}
	restore := SetLookupHostForTest(g.lookup)
	t.Cleanup(func() {
		select {
		case <-g.gate:
		default:
			close(g.gate)
		}
		restore()
	})
	return g
}

func (g *gatedResolver) lookup(ctx context.Context, _ string) ([]string, error) {
	g.lookups.Add(1)
	select {
	case <-g.gate:
		g.exited <- nil
		return g.answer, g.err
	case <-ctx.Done():
		g.exited <- context.Cause(ctx)
		return nil, ctx.Err()
	}
}

// waitFor polls cond until it holds; a regression fails instead of hanging.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func startHerd(ctx context.Context, n int, hostport string, budget time.Duration) <-chan error {
	out := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() { out <- PrivateHostBudget(ctx, hostport, budget) }()
	}
	return out
}

// The defect: every concurrent miss for one host issued its own lookup.
func TestPrivateHost_ConcurrentMissesShareOneLookup(t *testing.T) {
	const n = 64
	g := newGatedResolver(t, []string{"93.184.216.34"}, nil)
	res := startHerd(context.Background(), n, "herd.example.test:443", 10*time.Second)
	waitFor(t, "every caller to join one flight", func() bool { return flights.waitersFor("herd.example.test") == n })
	close(g.gate)
	for i := 0; i < n; i++ {
		if err := <-res; err != nil {
			t.Fatalf("public host refused: %v", err)
		}
	}
	if got := g.lookups.Load(); got != 1 {
		t.Fatalf("%d concurrent misses issued %d lookups, want 1", n, got)
	}
	if priv, found := dnsCache.Lookup("herd.example.test"); !found || priv {
		t.Fatalf("verdict not cached as public: private=%v found=%v", priv, found)
	}
	if got := flights.inFlight(); got != 0 {
		t.Fatalf("%d flights still registered after completion", got)
	}
}

// A shared private verdict refuses every waiter as an SSRF block.
func TestPrivateHost_SharedPrivateVerdictBlocksEveryWaiter(t *testing.T) {
	const n = 8
	g := newGatedResolver(t, []string{"93.184.216.34", "169.254.169.254"}, nil)
	res := startHerd(context.Background(), n, "meta.example.test:80", 10*time.Second)
	waitFor(t, "every caller to join", func() bool { return flights.waitersFor("meta.example.test") == n })
	close(g.gate)
	for i := 0; i < n; i++ {
		err := <-res
		if !errors.Is(err, ErrBlocked) || !strings.Contains(err.Error(), "169.254.169.254") {
			t.Fatalf("want ErrBlocked naming the private address, got %v", err)
		}
	}
	if priv, found := dnsCache.Lookup("meta.example.test"); !found || !priv {
		t.Fatalf("private verdict not cached: private=%v found=%v", priv, found)
	}
}

// A shared resolution failure fails every waiter closed, as a plain error, and
// is still never cached.
func TestPrivateHost_SharedFailureIsNotCached(t *testing.T) {
	const n = 8
	g := newGatedResolver(t, nil, errors.New("no such host"))
	res := startHerd(context.Background(), n, "nx.example.test:443", 10*time.Second)
	waitFor(t, "every caller to join", func() bool { return flights.waitersFor("nx.example.test") == n })
	close(g.gate)
	for i := 0; i < n; i++ {
		err := <-res
		if err == nil || errors.Is(err, ErrBlocked) || errors.Is(err, ErrLookupBudget) {
			t.Fatalf("resolution failure must fail closed as a plain error, got %v", err)
		}
	}
	if _, found := dnsCache.Lookup("nx.example.test"); found {
		t.Fatal("a failed lookup must never be cached")
	}
	if err := PrivateHostBudget(context.Background(), "nx.example.test:443", time.Second); err == nil {
		t.Fatal("second check must fail closed too")
	}
	if got := g.lookups.Load(); got != 2 {
		t.Fatalf("lookups = %d, want 2 (failure not cached, so the next check re-resolves)", got)
	}
}

// One caller hanging up must not fail, or cancel the lookup for, the others.
func TestPrivateHost_OneWaiterLeavingDoesNotCancelTheOthers(t *testing.T) {
	g := newGatedResolver(t, []string{"93.184.216.34"}, nil)
	quitter, cancel := context.WithCancel(context.Background())
	defer cancel()
	q := startHerd(quitter, 1, "shared.example.test:443", time.Hour)
	waitFor(t, "first caller to join", func() bool { return flights.waitersFor("shared.example.test") == 1 })
	stay := startHerd(context.Background(), 1, "shared.example.test:443", time.Hour)
	waitFor(t, "second caller to join", func() bool { return flights.waitersFor("shared.example.test") == 2 })

	cancel()
	if err := <-q; !errors.Is(err, context.Canceled) || errors.Is(err, ErrLookupBudget) || errors.Is(err, ErrBlocked) {
		t.Fatalf("leaver must get its own cancellation, got %v", err)
	}
	close(g.gate)
	if err := <-stay; err != nil {
		t.Fatalf("remaining waiter failed after another left: %v", err)
	}
	if c := <-g.exited; c != nil {
		t.Fatalf("shared lookup was cancelled (cause %v) while a waiter remained", c)
	}
}

// Each waiter keeps its own budget: a short-budget caller times out with
// ErrLookupBudget while an unbounded one keeps waiting for the answer.
func TestPrivateHost_BudgetIsPerWaiter(t *testing.T) {
	g := newGatedResolver(t, []string{"93.184.216.34"}, nil)
	patient := make(chan error, 1)
	go func() { patient <- PrivateHostContext(context.Background(), "budget.example.test:443") }()
	waitFor(t, "patient caller to join", func() bool { return flights.waitersFor("budget.example.test") == 1 })

	err := PrivateHostBudget(context.Background(), "budget.example.test:443", 20*time.Millisecond)
	if !errors.Is(err, ErrLookupBudget) || errors.Is(err, ErrBlocked) {
		t.Fatalf("short-budget waiter: want ErrLookupBudget, got %v", err)
	}
	select {
	case err := <-patient:
		t.Fatalf("unbounded waiter returned early: %v", err)
	default:
	}
	close(g.gate)
	if err := <-patient; err != nil {
		t.Fatalf("unbounded waiter: %v", err)
	}
}

// When the last waiter leaves, the lookup is cancelled with that waiter's
// cause and unregistered, so the next caller starts a fresh lookup rather than
// joining a dead one.
func TestPrivateHost_LastWaiterLeavingCancelsTheLookup(t *testing.T) {
	g := newGatedResolver(t, []string{"93.184.216.34"}, nil)
	err := PrivateHostBudget(context.Background(), "abandon.example.test:443", 20*time.Millisecond)
	if !errors.Is(err, ErrLookupBudget) {
		t.Fatalf("want ErrLookupBudget, got %v", err)
	}
	select {
	case c := <-g.exited:
		if !errors.Is(c, ErrLookupBudget) {
			t.Fatalf("abandoned lookup cancelled with cause %v, want ErrLookupBudget", c)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("abandoned lookup was never cancelled")
	}
	if got := flights.inFlight(); got != 0 {
		t.Fatalf("abandoned flight still registered (%d)", got)
	}
	if _, found := dnsCache.Lookup("abandon.example.test"); found {
		t.Fatal("abandoned lookup must not be cached")
	}
	close(g.gate)
	if err := PrivateHostBudget(context.Background(), "abandon.example.test:443", time.Second); err != nil {
		t.Fatalf("fresh check after abandonment: %v", err)
	}
	if got := g.lookups.Load(); got != 2 {
		t.Fatalf("lookups = %d, want 2 (the abandoned flight must not be reused)", got)
	}
}

// A context that has already ended never starts a lookup.
func TestPrivateHost_EndedContextStartsNoLookup(t *testing.T) {
	g := newGatedResolver(t, []string{"93.184.216.34"}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := PrivateHostContext(ctx, "dead.example.test:443"); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if got := g.lookups.Load(); got != 0 {
		t.Fatalf("an ended context issued %d lookups", got)
	}
}

// CacheReset (the resolver / guard-table swap seam) orphans in-progress
// flights: their verdict must not reach the cache, and new callers must not
// join them.
func TestPrivateHost_CacheResetOrphansInFlightLookups(t *testing.T) {
	g := newGatedResolver(t, []string{"10.0.0.1"}, nil)
	old := startHerd(context.Background(), 1, "swap.example.test:443", time.Hour)
	waitFor(t, "caller to join", func() bool { return flights.waitersFor("swap.example.test") == 1 })
	CacheReset()
	if got := flights.inFlight(); got != 0 {
		t.Fatalf("flight survived CacheReset (%d registered)", got)
	}
	close(g.gate)
	if err := <-old; !errors.Is(err, ErrBlocked) {
		t.Fatalf("orphaned flight must still answer its own waiter: %v", err)
	}
	if _, found := dnsCache.Lookup("swap.example.test"); found {
		t.Fatal("an orphaned flight wrote its verdict into the reset cache")
	}
}

// A burst of distinct cold hosts must not leave the in-flight map's bucket
// array retained once it drains.
func TestPrivateHost_FlightMapReallocatedAfterBurst(t *testing.T) {
	const n = flightMapShrinkAt + 64
	g := newGatedResolver(t, []string{"93.184.216.34"}, nil)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = PrivateHostContext(context.Background(), fmt.Sprintf("burst-%d.example.test:443", i))
		}()
	}
	waitFor(t, "every distinct host to be in flight", func() bool { return flights.inFlight() == n })
	close(g.gate)
	wg.Wait()
	flights.mu.Lock()
	peak, size := flights.peak, len(flights.m)
	flights.mu.Unlock()
	if size != 0 || peak != 0 {
		t.Fatalf("after drain: len=%d peak=%d, want a freshly allocated empty map", size, peak)
	}
}

// A panicking resolver must fail every waiter closed, not crash the process
// from the shared lookup's goroutine, and must not be cached.
func TestPrivateHost_PanickingLookupFailsClosed(t *testing.T) {
	restore := SetLookupHostForTest(func(context.Context, string) ([]string, error) { panic("resolver bug") })
	t.Cleanup(restore)
	err := PrivateHostContext(context.Background(), "panic.example.test:443")
	if !errors.Is(err, errLookupPanicked) || errors.Is(err, ErrBlocked) {
		t.Fatalf("want a plain fail-closed errLookupPanicked, got %v", err)
	}
	if _, found := dnsCache.Lookup("panic.example.test"); found {
		t.Fatal("a panicked lookup must never be cached")
	}
	if got := flights.inFlight(); got != 0 {
		t.Fatalf("panicked flight still registered (%d)", got)
	}
}
