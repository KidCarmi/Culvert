package upstream

import (
	"context"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ── CircuitBreaker ───────────────────────────────────────────────────────────

func TestCircuitBreaker_StartsClosedAndAllows(t *testing.T) {
	cb := newCircuitBreaker(3, 10*time.Second)
	if !cb.Allow() {
		t.Fatal("new circuit breaker should allow requests")
	}
	if cb.State() != "closed" {
		t.Fatalf("state = %q, want closed", cb.State())
	}
}

func TestCircuitBreaker_OpensAfterThreshold(t *testing.T) {
	cb := newCircuitBreaker(3, 10*time.Second)
	cb.RecordFailure()
	cb.RecordFailure()
	if !cb.Allow() {
		t.Fatal("should still allow before threshold")
	}
	cb.RecordFailure() // 3rd failure → threshold reached
	if cb.Allow() {
		t.Fatal("should NOT allow after threshold failures")
	}
	if cb.State() != "open" {
		t.Fatalf("state = %q, want open", cb.State())
	}
}

func TestCircuitBreaker_SuccessResetsToClose(t *testing.T) {
	cb := newCircuitBreaker(2, 10*time.Second)
	cb.RecordFailure()
	cb.RecordFailure() // opens
	if cb.State() != "open" {
		t.Fatal("expected open")
	}
	cb.RecordSuccess()
	if cb.State() != "closed" {
		t.Fatalf("state = %q, want closed after success", cb.State())
	}
	if !cb.Allow() {
		t.Fatal("should allow after reset")
	}
}

func TestCircuitBreaker_TransitionsToHalfOpen(t *testing.T) {
	cb := newCircuitBreaker(1, 10*time.Millisecond)
	cb.RecordFailure() // opens immediately (threshold=1)
	if cb.State() != "open" {
		t.Fatal("expected open")
	}
	time.Sleep(20 * time.Millisecond) // wait past timeout
	if !cb.Allow() {
		t.Fatal("should allow (half-open probe) after timeout")
	}
	if cb.State() != "half-open" {
		t.Fatalf("state = %q, want half-open", cb.State())
	}
}

func TestCircuitBreaker_DefaultThresholdAndTimeout(t *testing.T) {
	cb := newCircuitBreaker(0, 0) // defaults
	if cb.threshold != 5 {
		t.Fatalf("threshold = %d, want 5", cb.threshold)
	}
	if cb.timeout != 60*time.Second {
		t.Fatalf("timeout = %v, want 60s", cb.timeout)
	}
}

// Ensure concurrency safety of circuit breaker under load.
func TestCircuitBreaker_ConcurrentAccess(t *testing.T) {
	t.Parallel()
	cb := newCircuitBreaker(100, time.Minute)
	var wg atomic.Int64
	done := make(chan struct{})
	for i := 0; i < 50; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				cb.Allow()
				cb.RecordFailure()
				cb.RecordSuccess()
				_ = cb.State()
			}
			if wg.Add(1) == 50 {
				close(done)
			}
		}()
	}
	<-done
}

// ── Pool ─────────────────────────────────────────────────────────────────────

func TestPool_Configure(t *testing.T) {
	pool := &Pool{}
	pool.Configure([]Entry{
		{URL: "http://proxy1.test:3128"},
		{URL: "http://proxy2.test:3128"},
	}, 3, 30*time.Second)
	if !pool.Enabled() {
		t.Fatal("pool should be enabled after Configure")
	}
	list := pool.List()
	if len(list) != 2 {
		t.Fatalf("list length = %d, want 2", len(list))
	}
	for _, s := range list {
		if !s.Healthy {
			t.Fatalf("proxy %s should start healthy", s.URL)
		}
		if s.Circuit != "closed" {
			t.Fatalf("circuit = %q, want closed", s.Circuit)
		}
	}
}

func TestPool_EmptyReturnsNil(t *testing.T) {
	pool := &Pool{}
	if pool.Enabled() {
		t.Fatal("empty pool should not be enabled")
	}
	if pool.Next() != nil {
		t.Fatal("Next on empty pool should return nil")
	}
}

func TestPool_NextRoundRobin(t *testing.T) {
	pool := &Pool{}
	pool.Configure([]Entry{
		{URL: "http://a.test:3128"},
		{URL: "http://b.test:3128"},
	}, 5, time.Minute)

	// Collect 4 picks.
	seen := map[string]int{}
	for i := 0; i < 4; i++ {
		up := pool.Next()
		if up == nil {
			t.Fatal("Next returned nil")
		}
		seen[up.URL.Host]++
	}
	if seen["a.test:3128"] == 0 || seen["b.test:3128"] == 0 {
		t.Fatalf("expected round-robin across both proxies, got %v", seen)
	}
}

func TestPool_SkipsUnhealthy(t *testing.T) {
	pool := &Pool{}
	pool.Configure([]Entry{
		{URL: "http://bad.test:3128"},
		{URL: "http://good.test:3128"},
	}, 5, time.Minute)

	// Mark first as unhealthy.
	pool.mu.RLock()
	pool.proxies[0].Healthy.Store(false)
	pool.mu.RUnlock()

	for i := 0; i < 5; i++ {
		up := pool.Next()
		if up == nil {
			t.Fatal("Next returned nil")
		}
		if up.URL.Host != "good.test:3128" {
			t.Fatalf("expected good proxy, got %s", up.URL.Host)
		}
	}
}

func TestPool_AllDownReturnsNil(t *testing.T) {
	pool := &Pool{}
	pool.Configure([]Entry{
		{URL: "http://a.test:3128"},
	}, 5, time.Minute)
	pool.mu.RLock()
	pool.proxies[0].Healthy.Store(false)
	pool.mu.RUnlock()

	if pool.Next() != nil {
		t.Fatal("should return nil when all unhealthy")
	}
}

func TestPool_ProxyFunc(t *testing.T) {
	pool := &Pool{}
	pool.Configure([]Entry{
		{URL: "http://parent.test:8080"},
	}, 5, time.Minute)
	pf := pool.ProxyFunc()
	u, err := pf(nil)
	if err != nil {
		t.Fatalf("ProxyFunc error: %v", err)
	}
	if u == nil || u.Host != "parent.test:8080" {
		t.Fatalf("expected parent.test:8080, got %v", u)
	}

	// When all down, returns nil (direct).
	pool.mu.RLock()
	pool.proxies[0].Healthy.Store(false)
	pool.mu.RUnlock()
	u, err = pf(nil)
	if err != nil {
		t.Fatalf("ProxyFunc error: %v", err)
	}
	if u != nil {
		t.Fatalf("expected nil (direct), got %v", u)
	}
}

func TestPool_InvalidURL(t *testing.T) {
	pool := &Pool{}
	pool.Configure([]Entry{
		{URL: "://bad"},
	}, 5, time.Minute)
	if pool.Enabled() {
		t.Fatal("invalid URL should not create a proxy")
	}
}

func TestPool_ConfigureReplacesExisting(t *testing.T) {
	pool := &Pool{}
	pool.Configure([]Entry{{URL: "http://a.test:3128"}}, 5, time.Minute)
	if len(pool.List()) != 1 {
		t.Fatal("expected 1 proxy")
	}
	pool.Configure([]Entry{
		{URL: "http://b.test:3128"},
		{URL: "http://c.test:3128"},
	}, 5, time.Minute)
	if len(pool.List()) != 2 {
		t.Fatal("expected 2 proxies after reconfigure")
	}
}

// Verify that ProxyFunc falls back on circuit-breaker open.
func TestPool_CBOpenFallback(t *testing.T) {
	pool := &Pool{}
	pool.Configure([]Entry{{URL: "http://cb.test:3128"}}, 1, time.Minute)
	pool.mu.RLock()
	pool.proxies[0].CB.RecordFailure() // threshold=1 → open
	pool.mu.RUnlock()
	if pool.Next() != nil {
		t.Fatal("should return nil when circuit is open")
	}

	pf := pool.ProxyFunc()
	u, _ := pf(nil)
	if u != nil {
		t.Fatal("ProxyFunc should return nil (direct) when CB open")
	}
	_ = url.URL{}
}

// Ensure pool concurrent access doesn't panic.
func TestPool_ConcurrentNext(t *testing.T) {
	t.Parallel()
	pool := &Pool{}
	pool.Configure([]Entry{
		{URL: "http://a.test:3128"},
		{URL: "http://b.test:3128"},
	}, 5, time.Minute)

	done := make(chan struct{})
	var wg atomic.Int64
	for i := 0; i < 20; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				_ = pool.Next()
				_ = pool.List()
			}
			if wg.Add(1) == 20 {
				close(done)
			}
		}()
	}
	<-done
}

// ── Persistence / CB-parameter contracts (moved from admin_settings_upstream_test.go) ──

func TestPool_SetProxiesPreservesCBParams(t *testing.T) {
	pool := &Pool{}
	pool.Configure([]Entry{{URL: "http://seed.test:3128"}}, 7, 90*time.Second)

	pool.SetProxies([]Entry{{URL: "http://replaced.test:3128"}})

	pool.mu.RLock()
	defer pool.mu.RUnlock()
	if len(pool.proxies) != 1 {
		t.Fatalf("proxies = %d, want 1", len(pool.proxies))
	}
	cb := pool.proxies[0].CB
	if cb.threshold != 7 {
		t.Errorf("threshold = %d, want 7 (SetProxies must keep Configure's CB params)", cb.threshold)
	}
	if cb.timeout != 90*time.Second {
		t.Errorf("timeout = %v, want 90s (SetProxies must keep Configure's CB params)", cb.timeout)
	}
}

func TestPool_SetProxiesOnZeroPoolUsesCBDefaults(t *testing.T) {
	// A pool that was never Configure'd (or Configure'd with zero params —
	// YAML with no circuit_breaker section) must fall back to the
	// newCircuitBreaker defaults, matching the API handler's old behavior.
	pool := &Pool{}
	pool.SetProxies([]Entry{{URL: "http://gui-added.test:3128"}})

	pool.mu.RLock()
	defer pool.mu.RUnlock()
	if len(pool.proxies) != 1 {
		t.Fatalf("proxies = %d, want 1", len(pool.proxies))
	}
	cb := pool.proxies[0].CB
	if cb.threshold != 5 || cb.timeout != 60*time.Second {
		t.Errorf("CB params = %d/%v, want defaults 5/60s", cb.threshold, cb.timeout)
	}
}

func TestPool_EntriesReturnsRawCredentialedURL(t *testing.T) {
	const raw = "http://user:sekret-cred@parent.test:3128" // #nosec G101 -- fake userinfo in a reserved .test URL; fixture verifies raw credential round-trip (List() redacts)
	pool := &Pool{}
	pool.Configure([]Entry{{URL: raw}}, 5, time.Minute)

	entries := pool.Entries()
	if len(entries) != 1 || entries[0].URL != raw {
		t.Fatalf("Entries() = %+v, want raw URL %q (persistence must round-trip credentials)", entries, raw)
	}
	list := pool.List()
	if len(list) != 1 {
		t.Fatalf("List() = %d entries, want 1", len(list))
	}
	if strings.Contains(list[0].URL, "sekret-cred") {
		t.Errorf("List() leaked the credential: %q (must stay redacted)", list[0].URL)
	}
}

func TestPool_SkipsHostlessURL(t *testing.T) {
	pool := &Pool{}
	pool.SetProxies([]Entry{
		{URL: "parent1.corp.com:3128"}, // no scheme — parses opaque, undialable
		{URL: ""},
		{URL: "http://ok.test:3128"},
	})
	entries := pool.Entries()
	if len(entries) != 1 || entries[0].URL != "http://ok.test:3128" {
		t.Fatalf("Entries() = %+v, want only the valid scheme://host URL", entries)
	}
	if got := len(pool.List()); got != 1 {
		t.Fatalf("List() = %d proxies, want 1", got)
	}
}

func TestPool_CBParamsAccessor(t *testing.T) {
	pool := &Pool{}
	pool.Configure(nil, 9, 45*time.Second)
	th, to := pool.CBParams()
	if th != 9 || to != 45*time.Second {
		t.Fatalf("CBParams() = %d/%v, want 9/45s", th, to)
	}
}

// ── Config / Status types ────────────────────────────────────────────────────

func TestFormatSummary(t *testing.T) {
	entries := []Entry{
		{URL: "http://a.test:3128"},
		{URL: "http://b.test:3128"},
	}
	s := FormatSummary(entries)
	if s == "" {
		t.Fatal("summary should not be empty")
	}
	if FormatSummary(nil) != "direct" {
		t.Fatal("empty entries should summarize as direct")
	}
}

func TestStatus_Fields(t *testing.T) {
	s := Status{
		URL:     "http://x.test",
		Healthy: true,
		Circuit: "closed",
	}
	if s.URL == "" || !s.Healthy || s.Circuit != "closed" {
		t.Fatal("Status fields should be set correctly")
	}
}

func TestConfig_Struct(t *testing.T) {
	cfg := Config{
		Proxies:        []Entry{{URL: "http://p.test"}},
		HealthInterval: "30s",
	}
	if len(cfg.Proxies) != 1 {
		t.Fatal("expected 1 proxy entry")
	}
}

// ── RunHealthCheckLoop (P1.3 / S4.UpstreamHealth) ────────────────────────────
//
// The shutdown invariant under test is:
//
//	"the upstream health-check goroutine cannot remain detached after
//	 lifecycle cancellation."
//
// Each test wraps RunHealthCheckLoop in a goroutine guarded by a `done`
// channel that is closed only after the function returns. Receiving from
// `done` proves the function returned, which means the deferred ticker.Stop
// ran. The tests treat `done` as the black-box exit signal — they do not
// assert directly on ticker state.
//
// We use a fresh, empty *Pool so HealthCheck (if it ever fires) is a no-op:
// the proxies slice is empty, so the per-iteration HTTP probe loop runs zero
// times and never touches the network.

func TestRunHealthCheckLoop_ExitsOnContextCancel(t *testing.T) {
	pool := &Pool{}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		RunHealthCheckLoop(ctx, pool, 10*time.Millisecond)
	}()

	cancel()

	select {
	case <-done:
		// Pass — loop returned.
	case <-time.After(time.Second):
		t.Fatal("RunHealthCheckLoop did not exit within 1s of context cancellation; goroutine is detached")
	}
}

func TestRunHealthCheckLoop_PreCancelledCtx_ExitsImmediately(t *testing.T) {
	pool := &Pool{}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		RunHealthCheckLoop(ctx, pool, time.Hour) // long interval — ticks must NOT be required
	}()

	select {
	case <-done:
		// Pass.
	case <-time.After(200 * time.Millisecond):
		t.Fatal("RunHealthCheckLoop did not exit promptly when ctx was already cancelled; the loop is waiting on the ticker instead of ctx.Done()")
	}
}

func TestRunHealthCheckLoop_InvalidInputsReturn(t *testing.T) {
	cases := []struct {
		name     string
		pool     *Pool
		interval time.Duration
	}{
		{"nil pool, positive interval", nil, time.Second},
		{"non-nil pool, zero interval", &Pool{}, 0},
		{"non-nil pool, negative interval", &Pool{}, -1 * time.Second},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			done := make(chan struct{})
			go func() {
				defer close(done)
				// Background ctx — the function must NOT need cancellation to
				// exit; the early-return guard is what's under test.
				RunHealthCheckLoop(context.Background(), tc.pool, tc.interval)
			}()

			select {
			case <-done:
				// Pass — guard fired.
			case <-time.After(200 * time.Millisecond):
				t.Fatalf("RunHealthCheckLoop(%s) did not return promptly; the defensive guard is missing or wedged", tc.name)
			}
		})
	}
}
