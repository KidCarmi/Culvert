package main

// Tests + benchmarks for the resolveHost host→IP TTL cache (perf: repeated
// blocking DNS on the policy hot path and the per-request destination-country
// tracker; see hostIPCache in geoip.go).
//
// All tests stub lookupHostFn (the DNS seam) so nothing here performs real
// resolution: results are deterministic and the resolver-invocation count is
// observable. Tests share the process-wide resolvedHostCache, so each uses
// distinct hostnames and resets the cache around itself.

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// stubResolver replaces lookupHostFn with a counting stub returning addrs/err,
// and returns (counter, restore). Callers must defer restore().
func stubResolver(addrs []string, err error) (*atomic.Int64, func()) {
	var calls atomic.Int64
	orig := lookupHostFn
	lookupHostFn = func(host string) ([]string, error) {
		calls.Add(1)
		return addrs, err
	}
	origCache := resolvedHostCache.entries
	resolvedHostCache.mu.Lock()
	resolvedHostCache.entries = map[string]hostIPEntry{}
	resolvedHostCache.mu.Unlock()
	return &calls, func() {
		lookupHostFn = orig
		resolvedHostCache.mu.Lock()
		resolvedHostCache.entries = origCache
		resolvedHostCache.mu.Unlock()
	}
}

func TestResolveHost_CachesResolution(t *testing.T) {
	calls, restore := stubResolver([]string{"203.0.113.10"}, nil)
	defer restore()

	first := resolveHost("cache-hit.test.invalid")
	second := resolveHost("cache-hit.test.invalid")
	if first == nil || !first.Equal(net.ParseIP("203.0.113.10")) {
		t.Fatalf("first resolveHost = %v, want 203.0.113.10", first)
	}
	if second == nil || !second.Equal(first) {
		t.Fatalf("second resolveHost = %v, want cached %v", second, first)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("resolver invoked %d times for two calls, want 1 (cache miss only)", n)
	}
}

func TestResolveHost_NegativeCache(t *testing.T) {
	calls, restore := stubResolver(nil, errors.New("NXDOMAIN"))
	defer restore()

	if ip := resolveHost("neg-cache.test.invalid"); ip != nil {
		t.Fatalf("failed resolution returned %v, want nil", ip)
	}
	if ip := resolveHost("neg-cache.test.invalid"); ip != nil {
		t.Fatalf("second call returned %v, want nil", ip)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("resolver invoked %d times, want 1 — failures must be negative-cached", n)
	}
}

func TestResolveHost_TTLExpiry(t *testing.T) {
	calls, restore := stubResolver([]string{"203.0.113.20"}, nil)
	defer restore()

	_ = resolveHost("ttl-expiry.test.invalid")
	// Force the entry stale instead of sleeping.
	resolvedHostCache.mu.Lock()
	e := resolvedHostCache.entries["ttl-expiry.test.invalid"]
	e.expiry = time.Now().Add(-time.Second)
	resolvedHostCache.entries["ttl-expiry.test.invalid"] = e
	resolvedHostCache.mu.Unlock()

	if ip := resolveHost("ttl-expiry.test.invalid"); ip == nil {
		t.Fatal("post-expiry resolveHost returned nil, want re-resolved IP")
	}
	if n := calls.Load(); n != 2 {
		t.Fatalf("resolver invoked %d times, want 2 (initial + post-expiry re-resolve)", n)
	}
}

func TestResolveHost_IPLiteralBypassesCacheAndResolver(t *testing.T) {
	calls, restore := stubResolver([]string{"203.0.113.30"}, nil)
	defer restore()

	if ip := resolveHost("198.51.100.7"); ip == nil || !ip.Equal(net.ParseIP("198.51.100.7")) {
		t.Fatalf("public IP literal = %v, want 198.51.100.7", ip)
	}
	if ip := resolveHost("10.1.2.3"); ip != nil {
		t.Fatalf("private IP literal = %v, want nil (SSRF posture)", ip)
	}
	if n := calls.Load(); n != 0 {
		t.Fatalf("resolver invoked %d times for IP literals, want 0", n)
	}
	resolvedHostCache.mu.RLock()
	size := len(resolvedHostCache.entries)
	resolvedHostCache.mu.RUnlock()
	if size != 0 {
		t.Fatalf("cache holds %d entries after IP-literal calls, want 0", size)
	}
}

func TestResolveHost_PortStrippedBeforeCacheKey(t *testing.T) {
	calls, restore := stubResolver([]string{"203.0.113.40"}, nil)
	defer restore()

	_ = resolveHost("port-strip.test.invalid:443")
	_ = resolveHost("port-strip.test.invalid")
	if n := calls.Load(); n != 1 {
		t.Fatalf("resolver invoked %d times, want 1 — host:port and bare host must share a cache entry", n)
	}
}

func TestResolveHost_PrivateOnlyAnswersNegativeCached(t *testing.T) {
	calls, restore := stubResolver([]string{"192.168.1.5", "10.0.0.9"}, nil)
	defer restore()

	if ip := resolveHost("private-only.test.invalid"); ip != nil {
		t.Fatalf("private-only resolution = %v, want nil (SSRF posture)", ip)
	}
	_ = resolveHost("private-only.test.invalid")
	if n := calls.Load(); n != 1 {
		t.Fatalf("resolver invoked %d times, want 1 — private-only results must be cached", n)
	}
}

func TestResolveHost_CacheBoundEviction(t *testing.T) {
	_, restore := stubResolver([]string{"203.0.113.50"}, nil)
	defer restore()
	origMax := hostIPCacheMaxEntries
	hostIPCacheMaxEntries = 20
	defer func() { hostIPCacheMaxEntries = origMax }()

	for i := 0; i < 3*hostIPCacheMaxEntries; i++ {
		_ = resolveHost(fmt.Sprintf("bound-%d.test.invalid", i))
	}
	resolvedHostCache.mu.RLock()
	size := len(resolvedHostCache.entries)
	resolvedHostCache.mu.RUnlock()
	if size > hostIPCacheMaxEntries {
		t.Fatalf("cache grew to %d entries, cap is %d — the bound is the memory-DoS guard", size, hostIPCacheMaxEntries)
	}
}

func TestResolveHost_ConcurrentAccess(t *testing.T) {
	_, restore := stubResolver([]string{"203.0.113.60"}, nil)
	defer restore()

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				// Mix of shared hits and per-goroutine misses; exercises the
				// RLock fast path and the insert path under -race.
				_ = resolveHost("concurrent-shared.test.invalid")
				_ = resolveHost(fmt.Sprintf("concurrent-%d-%d.test.invalid", g, i%25))
			}
		}(g)
	}
	wg.Wait()
}

// ─── Benchmarks ───────────────────────────────────────────────────────────────
//
// Run:
//   go test -run '^$' -bench 'BenchmarkResolveHost' -benchmem .
//
// The stub resolver returns instantly, so the *structural* before/after shows
// as resolver calls/op + allocs/op; in production every avoided call is a real
// getaddrinfo/DNS round-trip (µs when OS-cached, ms otherwise — Go's resolver
// itself does not cache), previously paid per country-scoped rule per request
// on the policy path and once more per allowed request by the tracker.

// BenchmarkResolveHost_Uncached measures the pre-cache behavior: every call
// pays a resolver invocation (the cache is defeated by expiring each entry).
func BenchmarkResolveHost_Uncached(b *testing.B) {
	_, restore := stubResolver([]string{"203.0.113.70"}, nil)
	defer restore()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = resolveHost("bench-uncached.test.invalid")
		resolvedHostCache.mu.Lock()
		delete(resolvedHostCache.entries, "bench-uncached.test.invalid")
		resolvedHostCache.mu.Unlock()
	}
}

// BenchmarkResolveHost_Cached measures the steady-state hot path: a warm
// cache entry, zero resolver invocations.
func BenchmarkResolveHost_Cached(b *testing.B) {
	calls, restore := stubResolver([]string{"203.0.113.71"}, nil)
	defer restore()
	_ = resolveHost("bench-cached.test.invalid") // warm
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if ip := resolveHost("bench-cached.test.invalid"); ip == nil {
			b.Fatal("unexpected nil on warm cache")
		}
	}
	b.StopTimer()
	if n := calls.Load(); n != 1 {
		b.Fatalf("resolver invoked %d times, want 1 (warm-up only)", n)
	}
}

// BenchmarkResolveHost_CachedParallel exercises the shared RWMutex read path
// under parallelism — the shape the proxy actually runs (many concurrent
// request goroutines hitting a warm entry).
func BenchmarkResolveHost_CachedParallel(b *testing.B) {
	_, restore := stubResolver([]string{"203.0.113.72"}, nil)
	defer restore()
	_ = resolveHost("bench-parallel.test.invalid") // warm
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if ip := resolveHost("bench-parallel.test.invalid"); ip == nil {
				b.Fatal("unexpected nil on warm cache")
			}
		}
	})
}
