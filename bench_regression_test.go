//go:build benchgate

package main

// Deterministic benchmark-regression gate (CI quality program — PR-3).
//
// Pairs with the benchstat artifact the weekly workflow produces. benchstat
// reports ns/op deltas vs the PR-2 baseline (informational — ns/op is
// hardware-sensitive and not a reliable cross-runner gate). THIS test is the
// hard gate, keyed on ALLOCATIONS PER OP, which are deterministic and
// hardware-independent: a change that adds an allocation to the per-request
// policy hot path fails here regardless of runner speed.
//
// Baseline (PR-2, testdata/bench/policy-baseline.txt): policy Evaluate allocates
// ~2 allocs/rule on the no-match full scan, and scrubForwardedHeaders ~13
// allocs/op. The bounds below add modest headroom; a per-rule allocation
// regression (→ ~3 allocs/rule) blows past them.
//
//   go test -tags benchgate -run 'TestBenchGate_' -v .

import (
	"net/http"
	"testing"
)

// TestBenchGate_PolicyEvalAllocs locks in the O(1)-allocation policy hot path.
// Before the host-normalize-once + precomputed-normFQDN optimization, Evaluate
// allocated ~2/rule (2000 allocs/op at 1000 rules); it is now a small CONSTANT
// regardless of rule count. The bound is therefore a constant, not a function of
// rule count — any reintroduction of per-rule allocation fails this gate.
func TestBenchGate_PolicyEvalAllocs(t *testing.T) {
	// Post-optimization: 2 allocs/op (the per-request host normalization + the
	// per-request client-IP parse feeding the precomputed-CIDR fast path),
	// independent of rule count. Headroom of a few absorbs runtime noise while
	// still catching an O(rules) regression immediately.
	const maxAllocs int64 = 4
	for _, rules := range []int{10, 100, 1000, 10000} {
		ps := buildPolicyStore(rules)
		res := testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = ps.Evaluate("203.0.113.7", "", "unauth", "target.example.com", nil)
			}
		})
		allocs := res.AllocsPerOp()
		t.Logf("Evaluate rules=%d: %d allocs/op (bound %d), %d ns/op", rules, allocs, maxAllocs, res.NsPerOp())
		if allocs > maxAllocs {
			t.Errorf("REGRESSION: Evaluate rules=%d allocates %d/op, exceeds constant bound %d — "+
				"per-rule allocation has returned to the policy hot path (host/pattern re-normalization?). "+
				"See docs/ci/proxy-quality-architecture.md §8a.", rules, allocs, maxAllocs)
		}
	}
}

// TestBenchGate_UpstreamInspectTLSConfigAllocs locks in the shared-root-pool
// contract on the SSL-inspect upstream leg. Before the optimization every
// inspected CONNECT tunnel called x509.SystemCertPool(), which clones the
// cached system pool per call — 162 allocs/op and ~26.7 KB/op measured with a
// standard Linux ca-certificates bundle. With upstreamVerifyRoots the steady
// state is the single tls.Config allocation; any reintroduction of a per-tunnel
// pool clone blows through the constant bound immediately.
func TestBenchGate_UpstreamInspectTLSConfigAllocs(t *testing.T) {
	const maxAllocs int64 = 4 // steady state 1 (the tls.Config); pre-fix 162
	// Warm the once-loaded pool so the measurement is steady state, not the
	// first-call pool load.
	if cfg := upstreamInspectTLSConfig("warm.example.com", false); cfg.RootCAs == nil {
		t.Fatal("nil RootCAs on the verifying path")
	}
	res := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			cfg := upstreamInspectTLSConfig("origin.example.com", false)
			if cfg.RootCAs == nil {
				b.Fatal("nil RootCAs on the verifying path")
			}
		}
	})
	allocs := res.AllocsPerOp()
	t.Logf("upstreamInspectTLSConfig: %d allocs/op (bound %d), %d ns/op", allocs, maxAllocs, res.NsPerOp())
	if allocs > maxAllocs {
		t.Errorf("REGRESSION: upstreamInspectTLSConfig allocates %d/op, exceeds bound %d — "+
			"a per-tunnel system-cert-pool clone (x509.SystemCertPool per call) has returned to the SSL-inspect hot path", allocs, maxAllocs)
	}
}

// TestBenchGate_PolicyEvalCIDRAllocs locks in the O(1)-allocation scan over
// source-scoped (CIDR) rulesets. Before the srcIPNet precompute, every rule
// with a CIDR SourceIP re-ran net.ParseCIDR + net.ParseIP per request (~4
// allocs/rule — 4002 allocs/op measured at 1000 rules); it is now a Contains()
// on the precomputed *net.IPNet with the client IP parsed once per Evaluate.
// The bound is a constant, not a function of rule count — any reintroduction
// of per-rule parsing fails this gate.
func TestBenchGate_PolicyEvalCIDRAllocs(t *testing.T) {
	const maxAllocs int64 = 4 // steady state 2 (host normalization + client-IP parse)
	for _, rules := range []int{10, 100, 1000} {
		ps := buildCIDRPolicyStore(rules)
		res := testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = ps.Evaluate("203.0.113.7", "", "unauth", "target.example.com", nil)
			}
		})
		allocs := res.AllocsPerOp()
		t.Logf("Evaluate CIDR rules=%d: %d allocs/op (bound %d), %d ns/op", rules, allocs, maxAllocs, res.NsPerOp())
		if allocs > maxAllocs {
			t.Errorf("REGRESSION: Evaluate CIDR rules=%d allocates %d/op, exceeds constant bound %d — "+
				"per-rule CIDR/client-IP parsing has returned to the policy hot path (srcIPNet precompute bypassed?)",
				rules, allocs, maxAllocs)
		}
	}
}

// TestBenchGate_ResolveHostCached locks in the host→IP TTL cache on the GeoIP
// resolution seam. Before the cache, resolveHost ran a BLOCKING net.LookupHost
// on every call — reached per country-scoped rule per request from the policy
// hot path (geo.LookupCached) and once more per allowed request from the
// destination-country tracker. The gate pins BOTH contracts: the resolver is
// invoked at most once for a warm host (the regression that matters — DNS
// round-trips returning to the hot path), and the warm path stays within a
// small constant allocation bound.
func TestBenchGate_ResolveHostCached(t *testing.T) {
	origFn := lookupHostFn
	var resolverCalls int64
	lookupHostFn = func(host string) ([]string, error) {
		resolverCalls++
		return []string{"203.0.113.99"}, nil
	}
	defer func() { lookupHostFn = origFn }()

	const host = "benchgate-resolve.test.invalid"
	// Evict any entry left by a prior run in the same process (the cache TTL is
	// minutes, far longer than a test run) so the warm-up below always misses
	// and the resolver-call assertion is deterministic under -count>1.
	resolvedHostCache.mu.Lock()
	delete(resolvedHostCache.entries, host)
	resolvedHostCache.mu.Unlock()
	if ip := resolveHost(host); ip == nil {
		t.Fatal("warm-up resolveHost returned nil")
	}
	const maxAllocs int64 = 4 // steady state ~2 (SplitHostPort AddrError on a bare host)
	res := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if ip := resolveHost(host); ip == nil {
				b.Fatal("nil on warm cache")
			}
		}
	})
	allocs := res.AllocsPerOp()
	t.Logf("resolveHost warm: %d allocs/op (bound %d), %d ns/op, resolver calls=%d", allocs, maxAllocs, res.NsPerOp(), resolverCalls)
	if resolverCalls != 1 {
		t.Errorf("REGRESSION: resolver invoked %d times for a warm host, want 1 — "+
			"per-call blocking DNS has returned to the GeoIP resolution seam (hostIPCache bypassed?)", resolverCalls)
	}
	if allocs > maxAllocs {
		t.Errorf("REGRESSION: warm resolveHost allocates %d/op, exceeds bound %d", allocs, maxAllocs)
	}
}

// TestBenchGate_AuthCapabilityProbeAllocs locks in the allocation-free IdP
// capability probes on the per-request auth hot path. resolveRequestAuth
// evaluates credCapable + ssoCapable on EVERY proxied request; before the
// HasEnabledProviders/HasEnabledOIDC probes, an IdP-only SSO deployment paid
// a deep clone of every IdP profile (idpRegistry.All(), ~5 allocs/profile)
// plus an EnabledProviders slice build per request just to answer the two
// booleans (~9 allocs/op measured at 4 profiles). The probes are read-only
// scans under RLock — the bound is ZERO, independent of profile count.
func TestBenchGate_AuthCapabilityProbeAllocs(t *testing.T) {
	const maxAllocs int64 = 0
	for _, profiles := range []int{1, 4, 16} {
		reg := buildProbeRegistry(profiles, true, true)
		res := testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = reg.HasEnabledProviders()
				_ = reg.HasEnabledOIDC()
			}
		})
		allocs := res.AllocsPerOp()
		t.Logf("capability probes profiles=%d: %d allocs/op (bound %d), %d ns/op", profiles, allocs, maxAllocs, res.NsPerOp())
		if allocs > maxAllocs {
			t.Errorf("REGRESSION: IdP capability probes allocate %d/op at %d profiles, exceed bound %d — "+
				"per-request profile cloning/slice building has returned to the auth hot path "+
				"(All()/EnabledProviders() in a boolean probe?)", allocs, profiles, maxAllocs)
		}
	}
}

// TestBenchGate_ScrubAllocs guards the per-request header-scrub hot path.
func TestBenchGate_ScrubAllocs(t *testing.T) {
	const maxAllocs = 16 // baseline 13
	res := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			r, _ := http.NewRequest(http.MethodGet, "http://target.example.com/", nil)
			r.Header.Set("X-Forwarded-For", "10.0.0.1, 203.0.113.9, 192.168.1.1")
			r.Header.Set("X-Real-IP", "10.1.2.3")
			r.Header.Set("X-User-Identity", "spoofed@evil.example")
			scrubForwardedHeaders(r)
		}
	})
	allocs := res.AllocsPerOp()
	t.Logf("scrubForwardedHeaders: %d allocs/op (bound %d)", allocs, maxAllocs)
	if allocs > maxAllocs {
		t.Errorf("REGRESSION: scrubForwardedHeaders allocates %d/op, exceeds bound %d (baseline ~13)", allocs, maxAllocs)
	}
}
