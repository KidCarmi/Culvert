package ssrf

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// wedgedResolver models a resolver that never answers: it returns only when
// the context it was handed ends, and reports why. release is the test's
// escape hatch, so a regression (a context that never ends) fails the test
// instead of hanging the package.
type wedgedResolver struct {
	entered chan struct{}
	exited  chan struct{} // one send per lookup, after cause is recorded
	release chan struct{}
	cause   atomic.Pointer[error]
	hadDL   atomic.Bool
}

func newWedgedResolver(t *testing.T) *wedgedResolver {
	t.Helper()
	w := &wedgedResolver{entered: make(chan struct{}, 8), exited: make(chan struct{}, 8), release: make(chan struct{})}
	restore := SetLookupHostForTest(w.lookup)
	t.Cleanup(func() {
		close(w.release)
		restore()
	})
	return w
}

func (w *wedgedResolver) lookup(ctx context.Context, _ string) ([]string, error) {
	_, has := ctx.Deadline()
	w.hadDL.Store(has)
	w.entered <- struct{}{}
	defer func() { w.exited <- struct{}{} }()
	select {
	case <-ctx.Done():
		c := context.Cause(ctx)
		w.cause.Store(&c)
		return nil, ctx.Err()
	case <-w.release:
		return nil, errors.New("released by test: the lookup context never ended")
	}
}

func (w *wedgedResolver) observedCause() error {
	if p := w.cause.Load(); p != nil {
		return *p
	}
	return nil
}

// The defect: the tunnel paths ran the guard with no bound, so a resolver that
// stopped answering held the calling goroutine for the OS resolver budget. The
// budget must end the lookup, identify itself as the reason, stay distinct
// from an SSRF verdict, and leave nothing in the cache.
func TestPrivateHostBudget_EndsWedgedLookup(t *testing.T) {
	w := newWedgedResolver(t)

	err := PrivateHostBudget(context.Background(), "wedged.example.test:443", 20*time.Millisecond)
	if err == nil {
		t.Fatal("a lookup that never completed must fail closed, got nil")
	}
	if !errors.Is(err, ErrLookupBudget) {
		t.Fatalf("error must wrap ErrLookupBudget, got %v", err)
	}
	if errors.Is(err, ErrBlocked) {
		t.Fatalf("a resolver timeout is not an SSRF verdict; must not wrap ErrBlocked: %v", err)
	}
	// The shared lookup runs on its own goroutine (miss-path single-flight):
	// its context is cancelled before the guard returns, but the resolver
	// observes that asynchronously, so wait for it to exit before asserting.
	select {
	case <-w.exited:
	case <-time.After(5 * time.Second):
		t.Fatal("the abandoned lookup was never cancelled")
	}
	if got := w.observedCause(); !errors.Is(got, ErrLookupBudget) {
		t.Fatalf("resolver's context ended with cause %v, want ErrLookupBudget", got)
	}
	if _, found := dnsCache.Lookup("wedged.example.test"); found {
		t.Fatal("a failed lookup must never be cached")
	}
}

// The caller's own context still wins, and is not misreported as the budget.
func TestPrivateHostBudget_CallerCancelIsNotTheBudget(t *testing.T) {
	w := newWedgedResolver(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- PrivateHostBudget(ctx, "abandoned.example.test:443", time.Hour) }()
	<-w.entered
	cancel()
	err := <-done
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want the caller's cancellation, got %v", err)
	}
	if errors.Is(err, ErrLookupBudget) || errors.Is(err, ErrBlocked) {
		t.Fatalf("caller cancellation misreported: %v", err)
	}
}

// Verdicts and caching are exactly PrivateHostContext's.
func TestPrivateHostBudget_VerdictsAndCacheUnchanged(t *testing.T) {
	var calls atomic.Int64
	restore := SetLookupHostForTest(func(_ context.Context, host string) ([]string, error) {
		calls.Add(1)
		switch host {
		case "public.example.test":
			return []string{"93.184.216.34"}, nil
		case "mixed.example.test":
			return []string{"93.184.216.34", "10.0.0.7"}, nil
		}
		return nil, errors.New("no such host")
	})
	t.Cleanup(restore)

	for i := 0; i < 2; i++ {
		if err := PrivateHostBudget(context.Background(), "public.example.test:443", time.Second); err != nil {
			t.Fatalf("public host refused: %v", err)
		}
		if err := PrivateHostBudget(context.Background(), "mixed.example.test:443", time.Second); !errors.Is(err, ErrBlocked) {
			t.Fatalf("host with a private address must be ErrBlocked, got %v", err)
		}
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("resolved %d times, want 2 (second round served from the cache)", got)
	}
	for i := 0; i < 2; i++ {
		err := PrivateHostBudget(context.Background(), "nxdomain.example.test:443", time.Second)
		if err == nil || errors.Is(err, ErrBlocked) || errors.Is(err, ErrLookupBudget) {
			t.Fatalf("resolution failure must fail closed as a plain error, got %v", err)
		}
	}
	if got := calls.Load(); got != 4 {
		t.Fatalf("resolved %d times, want 4 (failures are never cached)", got)
	}
}

// The bound must cost the per-request hot path nothing: the timer exists only
// on a miss, so a cached verdict allocates exactly what PrivateHostContext does.
func TestPrivateHostBudget_CacheHitPaysNothingForTheBound(t *testing.T) {
	CacheStore("hot.example.test", false)
	t.Cleanup(func() { CacheDelete("hot.example.test") })
	ctx := context.Background()
	base := testing.AllocsPerRun(200, func() { _ = PrivateHostContext(ctx, "hot.example.test:443") })
	got := testing.AllocsPerRun(200, func() { _ = PrivateHostBudget(ctx, "hot.example.test:443", 10*time.Second) })
	if got != base {
		t.Fatalf("cache hit allocs: budget=%v, unbounded=%v; the bound must be free on a hit", got, base)
	}
}

// PrivateHost / PrivateHostContext keep their contract: no deadline is added.
func TestPrivateHostContext_AddsNoDeadline(t *testing.T) {
	w := newWedgedResolver(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- PrivateHostContext(ctx, "legacy.example.test:443") }()
	<-w.entered
	if w.hadDL.Load() {
		t.Fatal("PrivateHostContext must not impose a deadline of its own")
	}
	cancel()
	<-done
}
