package main

import (
	"net/url"
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

// ── UpstreamPool ─────────────────────────────────────────────────────────────

func TestUpstreamPool_Configure(t *testing.T) {
	pool := &UpstreamPool{}
	pool.Configure([]UpstreamEntry{
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

func TestUpstreamPool_EmptyReturnsNil(t *testing.T) {
	pool := &UpstreamPool{}
	if pool.Enabled() {
		t.Fatal("empty pool should not be enabled")
	}
	if pool.Next() != nil {
		t.Fatal("Next on empty pool should return nil")
	}
}

func TestUpstreamPool_NextRoundRobin(t *testing.T) {
	pool := &UpstreamPool{}
	pool.Configure([]UpstreamEntry{
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

func TestUpstreamPool_SkipsUnhealthy(t *testing.T) {
	pool := &UpstreamPool{}
	pool.Configure([]UpstreamEntry{
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

func TestUpstreamPool_AllDownReturnsNil(t *testing.T) {
	pool := &UpstreamPool{}
	pool.Configure([]UpstreamEntry{
		{URL: "http://a.test:3128"},
	}, 5, time.Minute)
	pool.mu.RLock()
	pool.proxies[0].Healthy.Store(false)
	pool.mu.RUnlock()

	if pool.Next() != nil {
		t.Fatal("should return nil when all unhealthy")
	}
}

func TestUpstreamPool_ProxyFunc(t *testing.T) {
	pool := &UpstreamPool{}
	pool.Configure([]UpstreamEntry{
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

func TestUpstreamPool_InvalidURL(t *testing.T) {
	pool := &UpstreamPool{}
	pool.Configure([]UpstreamEntry{
		{URL: "://bad"},
	}, 5, time.Minute)
	if pool.Enabled() {
		t.Fatal("invalid URL should not create a proxy")
	}
}

func TestFormatUpstreamSummary(t *testing.T) {
	entries := []UpstreamEntry{
		{URL: "http://a.test:3128"},
		{URL: "http://b.test:3128"},
	}
	s := formatUpstreamSummary(entries)
	if s == "" {
		t.Fatal("summary should not be empty")
	}
}

// ── UpstreamStatus ───────────────────────────────────────────────────────────

func TestUpstreamStatus_Fields(t *testing.T) {
	s := UpstreamStatus{
		URL:     "http://x.test",
		Healthy: true,
		Circuit: "closed",
	}
	if s.URL == "" || !s.Healthy || s.Circuit != "closed" {
		t.Fatal("UpstreamStatus fields should be set correctly")
	}
}

// ── UpstreamConfig ───────────────────────────────────────────────────────────

func TestUpstreamConfig_Struct(t *testing.T) {
	cfg := UpstreamConfig{
		Proxies:        []UpstreamEntry{{URL: "http://p.test"}},
		HealthInterval: "30s",
	}
	if len(cfg.Proxies) != 1 {
		t.Fatal("expected 1 proxy entry")
	}
}

// Ensure concurrency safety of circuit breaker under load.
func TestCircuitBreaker_ConcurrentAccess(t *testing.T) {
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

// Ensure pool concurrent access doesn't panic.
func TestUpstreamPool_ConcurrentNext(t *testing.T) {
	pool := &UpstreamPool{}
	pool.Configure([]UpstreamEntry{
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

// ── applyUpstreamProxy ──────────────────────────────────────────────────────

func TestApplyUpstreamProxy_SetsTransportProxy(t *testing.T) {
	origProxy := upstreamTransport.Proxy
	defer func() { upstreamTransport.Proxy = origProxy }()

	pool := &UpstreamPool{}
	pool.Configure([]UpstreamEntry{{URL: "http://test.proxy:8080"}}, 5, time.Minute)

	// Save/restore global pool.
	origPool := *upstreamPool
	*upstreamPool = *pool
	defer func() { *upstreamPool = origPool }()

	applyUpstreamProxy()

	if upstreamTransport.Proxy == nil {
		t.Fatal("expected transport Proxy to be set")
	}

	u, err := upstreamTransport.Proxy(nil)
	if err != nil {
		t.Fatalf("Proxy func error: %v", err)
	}
	if u == nil {
		t.Fatal("expected proxy URL, got nil")
	}
	if u.Host != "test.proxy:8080" {
		t.Fatalf("proxy host = %s, want test.proxy:8080", u.Host)
	}
}

func TestUpstreamPool_ConfigureReplacesExisting(t *testing.T) {
	pool := &UpstreamPool{}
	pool.Configure([]UpstreamEntry{{URL: "http://a.test:3128"}}, 5, time.Minute)
	if len(pool.List()) != 1 {
		t.Fatal("expected 1 proxy")
	}
	pool.Configure([]UpstreamEntry{
		{URL: "http://b.test:3128"},
		{URL: "http://c.test:3128"},
	}, 5, time.Minute)
	if len(pool.List()) != 2 {
		t.Fatal("expected 2 proxies after reconfigure")
	}
}

// Verify that ProxyFunc falls back on circuit-breaker open.
func TestUpstreamPool_CBOpenFallback(t *testing.T) {
	pool := &UpstreamPool{}
	pool.Configure([]UpstreamEntry{{URL: "http://cb.test:3128"}}, 1, time.Minute)
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
