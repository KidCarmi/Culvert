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
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/sslbypass"
	"github.com/KidCarmi/Culvert/internal/ssrf"
	"github.com/KidCarmi/Culvert/internal/urlcat"
)

// TestBenchGate_PolicyEvalAllocs locks in the O(1)-allocation policy hot path.
// Before the host-normalize-once + precomputed-normFQDN optimization, Evaluate
// allocated ~2/rule (2000 allocs/op at 1000 rules); it is now a small CONSTANT
// regardless of rule count. The bound is therefore a constant, not a function of
// rule count — any reintroduction of per-rule allocation fails this gate.
func TestBenchGate_PolicyEvalAllocs(t *testing.T) {
	// Measured: 0 allocs/op, independent of rule count. This was 2/op (the
	// per-request host normalization + the per-request client-IP parse feeding
	// the precomputed-CIDR fast path) until the hostutil already-canonical fast
	// path removed the normalization pair — NormalizeHostStrict no longer calls
	// idna.ToASCII or net.ParseIP for an ordinary ASCII hostname, so Evaluate is
	// now allocation-free end to end.
	//
	// The bound stays at 4 rather than tightening to the measured 0: its job is to
	// catch an O(rules) regression, and leaving headroom keeps the gate immune to
	// escape-analysis differences across Go releases and architectures (the
	// client-IP parse can legitimately return to 1 alloc). The exact per-shape
	// allocation contract for normalization is pinned where it belongs, in
	// internal/hostutil's TestNormalizeHostStrict_AllocRegression.
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

// TestBenchGate_AuthResolveAllocs locks in the snapshot-based Stage-1 auth
// resolver (resolveAuthOutcomeSnapshot). Before it, resolveAuthOutcome ran
// resolveAuthOutcomeFrom over policyStore.List() on EVERY un-credentialed
// request — a full per-request rulebase deep clone plus a second copy and a
// re-sort (~1 MB/op and ~478 µs/op measured at 1000 rules). The gate pins two
// contracts: (a) a rulebase with no auth rules resolves with ZERO allocations
// at any size, and (b) with a fixed auth-rule tranche the allocation count is a
// constant independent of access-rule count (the per-auth-rule CIDR parse is
// inherent and bounded by the tranche size, never by the rulebase).
func TestBenchGate_AuthResolveAllocs(t *testing.T) {
	ctx := benchNoCredCtx()
	// (a) access-only rulebases: the scan exits every rule at the type check and
	// the lazy scratch never computes — 0 allocs measured; headroom of 2.
	const maxAllocsAccessOnly = 2
	for _, rules := range []int{10, 100, 1000, 10000} {
		ps := buildAuthResolveStore(rules)
		res := testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = resolveAuthOutcomeSnapshot(ps.evaluationSnapshot(), ctx)
			}
		})
		allocs := res.AllocsPerOp()
		t.Logf("resolveAuthOutcomeSnapshot access-only rules=%d: %d allocs/op (bound %d), %d ns/op",
			rules, allocs, maxAllocsAccessOnly, res.NsPerOp())
		if allocs > maxAllocsAccessOnly {
			t.Errorf("REGRESSION: auth resolve over %d access-only rules allocates %d/op, exceeds bound %d — "+
				"per-request rulebase cloning (List()) or per-rule derivation has returned to the no-credentials path",
				rules, allocs, maxAllocsAccessOnly)
		}
	}
	// (b) fixed 8-auth-rule tranche across growing access rulebases. This was 33
	// allocs/op (8 rules × 4 for net.ParseCIDR + one client-IP parse) until the
	// subject-CIDR precompute (precomputeSubjectNets, run by sortLocked) moved
	// the parse to publication time; the scan now allocates ONLY the single
	// per-request client-IP parse — measured 1 alloc/op, constant in BOTH access
	// and auth rule count. The bound keeps a little headroom but is far below
	// the per-rule shape: 8 auth rules re-parsing their CIDRs would land at ~33
	// and fail here immediately.
	const maxAllocsWithAuth = 4
	for _, rules := range []int{10, 1000, 10000} {
		ps := buildAuthResolveStore(rules, benchAuthRules(8)...)
		res := testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = resolveAuthOutcomeSnapshot(ps.evaluationSnapshot(), ctx)
			}
		})
		allocs := res.AllocsPerOp()
		t.Logf("resolveAuthOutcomeSnapshot access=%d auth=8: %d allocs/op (bound %d), %d ns/op",
			rules, allocs, maxAllocsWithAuth, res.NsPerOp())
		if allocs > maxAllocsWithAuth {
			t.Errorf("REGRESSION: auth resolve over %d access + 8 auth rules allocates %d/op, exceeds constant bound %d — "+
				"allocation is scaling with rulebase size again (List() clone, per-rule host normalization, or per-rule IP parse), "+
				"or the subject-CIDR precompute (precomputeSubjectNets) is no longer reaching the resolver",
				rules, allocs, maxAllocsWithAuth)
		}
	}
}

// TestBenchGate_AuthScheduleTZAllocs locks the Stage-1 schedule gate onto the
// process-wide timezone cache. time.LoadLocation is NOT cached by the stdlib —
// it re-reads and re-parses the tzdata file on every call (~8.6 µs and ~8.6 KB
// per call measured on CI hardware). authScheduleParseable runs per scheduled
// auth rule per request, so calling it directly put a disk read and 8.6 KB of
// garbage on the proxy hot path for every scheduled rule of every request.
// Stage-2 fixed the identical bug; this pins the Stage-1 half.
//
// The gate is allocation-keyed (hardware-independent): the cached resolution is
// 0 allocs/op, the uncached one is 13.
func TestBenchGate_AuthScheduleTZAllocs(t *testing.T) {
	const maxAllocs = 2 // measured 0; uncached time.LoadLocation is 13
	sched := &PolicySchedule{
		Timezone:  "America/New_York",
		Days:      []string{"Mon", "Tue", "Wed", "Thu", "Fri"},
		TimeStart: "09:00",
		TimeEnd:   "17:00",
	}
	// Warm the cache once so the benchmark measures the steady state (the first
	// resolution legitimately reads tzdata; every later one must not).
	if !authScheduleParseable(sched) {
		t.Fatalf("fixture timezone %q did not resolve", sched.Timezone)
	}
	res := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = authScheduleParseable(sched)
		}
	})
	allocs := res.AllocsPerOp()
	t.Logf("authScheduleParseable tz=%s: %d allocs/op (bound %d), %d ns/op",
		sched.Timezone, allocs, maxAllocs, res.NsPerOp())
	if allocs > maxAllocs {
		t.Errorf("REGRESSION: authScheduleParseable allocates %d/op, exceeds bound %d — "+
			"the Stage-1 schedule gate is calling time.LoadLocation directly again instead of "+
			"resolving through scheduleLocationResolved, putting a tzdata disk read on the request path",
			allocs, maxAllocs)
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
	lookupHostFn = func(_ context.Context, host string) ([]string, error) {
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
				// ADR-0027 capability probes — the successors actually consumed
				// by resolveRequestAuth's ssoCapable/credCapable; same zero bound.
				_ = reg.HasEnabledInteractiveProvider()
				_ = reg.HasEnabledCredentialProvider()
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

// TestBenchGate_GeoTrackDispatchDisabledAllocs locks in the goroutine-free,
// allocation-free destination-country dispatch when no GeoIP DB is loaded —
// the default deployment. Before the maybeTrackDestinationCountry gate,
// handleRequest ran `go trackDestinationCountry(host)` per allowed request:
// a heap-allocated closure wrapper (Go 1.17+ `go f(arg)` lowering), a
// goroutine spawn/schedule round, and two semaphore channel ops, all to
// discover geoip.Enabled() == false inside geo.LookupFull. The gated path is
// a single RLock probe; the bound is ZERO — any reintroduction of the
// pre-gate spawn (or an allocating probe) fails this gate.
func TestBenchGate_GeoTrackDispatchDisabledAllocs(t *testing.T) {
	if geoTrackEnabledFn() {
		t.Fatal("GeoIP DB unexpectedly loaded; the disabled-path gate requires no DB (no .mmdb fixture exists in the tree)")
	}
	const maxAllocs int64 = 0
	res := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			maybeTrackDestinationCountry("target.example.com")
		}
	})
	allocs := res.AllocsPerOp()
	t.Logf("maybeTrackDestinationCountry disabled: %d allocs/op (bound %d), %d ns/op", allocs, maxAllocs, res.NsPerOp())
	if allocs > maxAllocs {
		t.Errorf("REGRESSION: disabled geo-track dispatch allocates %d/op, exceeds bound %d — "+
			"a per-request tracker spawn has returned to handleRequest for non-GeoIP deployments "+
			"(geoip.Enabled() probe hoisted out of maybeTrackDestinationCountry?)", allocs, maxAllocs)
	}
}

// TestBenchGate_SSLBypassMatchesAllocs locks in the O(1)-allocation SSL-bypass
// scan on the per-CONNECT decision path (resolveSSLDecision → sslBypass.Matches,
// consulted for every CONNECT whose matched rule says inspect). Before the
// pattern.norm precompute, every glob pattern re-ran hostutil.NormalizeHost on
// BOTH the static pattern and the already-normalized host via MatchFQDN — ~4
// allocs/pattern (82 allocs/op measured at 20 patterns); it is now a
// MatchFQDNNorm over the compile-time-normalized pattern, so the steady state
// is the single per-call host normalization, independent of pattern count —
// the same contract TestBenchGate_PolicyEvalAllocs pins for rule FQDNs. Any
// reintroduction of per-pattern normalization fails this gate.
func TestBenchGate_SSLBypassMatchesAllocs(t *testing.T) {
	const maxAllocs int64 = 4 // steady state 2 (the per-call host normalization)
	for _, patterns := range []int{5, 20, 50} {
		pats := make([]string, patterns)
		for i := range pats {
			pats[i] = fmt.Sprintf("*.bypass-%d.example.com", i)
		}
		m := &sslbypass.Matcher{}
		if err := m.Set(pats); err != nil {
			t.Fatal(err)
		}
		res := testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if m.Matches("www.no-match.example.net") {
					b.Fatal("unexpected match")
				}
			}
		})
		allocs := res.AllocsPerOp()
		t.Logf("Matches patterns=%d: %d allocs/op (bound %d), %d ns/op", patterns, allocs, maxAllocs, res.NsPerOp())
		if allocs > maxAllocs {
			t.Errorf("REGRESSION: sslbypass.Matches patterns=%d allocates %d/op, exceeds constant bound %d — "+
				"per-pattern host/pattern re-normalization has returned to the CONNECT decision path "+
				"(pattern.norm precompute bypassed / MatchFQDN instead of MatchFQDNNorm?)", patterns, allocs, maxAllocs)
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

// TestBenchGate_ForwardedForFilterAllocs locks in the allocation-free
// X-Forwarded-For filter. The scrub runs on every plain-HTTP request, every
// WebSocket upgrade, and every decrypted inner exchange of an SSL-inspected
// tunnel, so per-hop allocation here is allocation on essentially all proxied
// traffic. The bound above cannot catch it: it includes http.NewRequest, whose
// ~10 allocations swamp the filter's own.
//
// The pre-change filter ran strings.Split + net.ParseIP + net.IP.String() +
// strings.Join, i.e. roughly two allocations per hop plus the join — 6 allocs and
// 208 B/op on an ordinary three-hop public chain, 12 allocs and 560 B on a deep
// one. It now parses into a netip.Addr value, renders through a stack buffer, and
// returns the input verbatim when the header is already in sanitized form (the
// load-balancer case), so the ALL-PUBLIC shapes are allocation-free end to end.
//
// Allocations are the gate, not ns/op: they are deterministic and hardware-
// independent. Any reintroduction of net.ParseIP, an intermediate []string, or an
// unconditional rebuild fails here regardless of runner speed.
func TestBenchGate_ForwardedForFilterAllocs(t *testing.T) {
	cases := []struct {
		name string
		xff  string
		// wantChanged is the shape being pinned, not just a sanity check: it is
		// what separates "recognised as already-sanitized" from "rewritten", and
		// the two have different allocation contracts.
		wantChanged bool
		maxAllocs   int64
	}{
		// Already-sanitized chains: the filter must recognise the fixed point and
		// return the input, allocating nothing at any chain length.
		{"single public hop", "203.0.113.9", false, 0},
		{"public chain", "203.0.113.9, 198.51.100.4, 192.0.2.33", false, 0},
		{"deep public chain", "203.0.113.1, 203.0.113.2, 203.0.113.3, 203.0.113.4, " +
			"203.0.113.5, 203.0.113.6, 203.0.113.7, 203.0.113.8", false, 0},
		// Every hop dropped: the value is rewritten, but to nothing, so the empty
		// builder never allocates either.
		{"all private", "10.0.0.1, 192.168.1.1, 172.16.0.1", true, 0},
		// Shapes that genuinely rewrite: exactly ONE allocation, the returned
		// string. Never one per hop.
		{"mixed chain", "10.0.0.1, 203.0.113.9, 192.168.1.1", true, 1},
		{"non-canonical spacing", "203.0.113.9,198.51.100.4,192.0.2.33", true, 1},
		{"ipv6 mixed chain", "2001:db8::1, fe80::1, 2001:db8::2", true, 1},
		{"deep mixed chain", "203.0.113.1, 10.0.0.1, 203.0.113.2, 10.0.0.2, 203.0.113.3, " +
			"10.0.0.3, 203.0.113.4, 10.0.0.4", true, 1},
		// Pathological chain whose rendered value outgrows the stack scratch. This
		// is the ONLY shape allowed to allocate for the buffer itself, and the
		// point of the case is that the cost stays a small CONSTANT — the buffer
		// doubles, it does not allocate per hop.
		{"over-scratch chain", overScratchChain(30), false, 2},
	}
	for _, tc := range cases {
		// Assert the fixture's shape OUTSIDE the benchmark. A b.Fatalf inside
		// testing.Benchmark makes it return a ZERO BenchmarkResult, whose
		// AllocsPerOp is 0 — which would sail through the bound below and turn a
		// broken fixture into a silently passing gate.
		if _, changed := sanitizeForwardedFor(tc.xff); changed != tc.wantChanged {
			t.Errorf("fixture %q: changed = %v, want %v — the already-sanitized fast path no longer "+
				"classifies this shape as expected, so the allocation bound below is measuring the wrong branch",
				tc.name, changed, tc.wantChanged)
			continue
		}
		res := testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _ = sanitizeForwardedFor(tc.xff)
			}
		})
		if res.N == 0 {
			t.Errorf("fixture %q: benchmark did not run (zero result) — the measurement below is meaningless", tc.name)
			continue
		}
		allocs := res.AllocsPerOp()
		t.Logf("sanitizeForwardedFor %s: %d allocs/op (bound %d), %d ns/op, changed=%v",
			tc.name, allocs, tc.maxAllocs, res.NsPerOp(), tc.wantChanged)
		if allocs > tc.maxAllocs {
			t.Errorf("REGRESSION: sanitizeForwardedFor %q allocates %d/op, exceeds bound %d — "+
				"per-hop allocation has returned to the forwarded-header scrub (net.ParseIP instead of "+
				"netip.ParseAddr, an intermediate []string + strings.Join, addr.String() per hop, or the "+
				"already-sanitized fast path bypassed). See proxy.go sanitizeForwardedFor.", tc.name, allocs, tc.maxAllocs)
		}
	}
}

// TestBenchGate_PrivateAddrClassifierAllocs pins the guard table that the filter
// above calls once per hop. It is a linear scan, and a PUBLIC address — the
// common case — matches nothing and so always pays the full scan of its family.
// The bound is ZERO: the netip entry point exists precisely so classification
// costs no allocation, and PrivateIP (the net.IP façade the other eight SSRF
// call sites use) must stay allocation-free through it too.
func TestBenchGate_PrivateAddrClassifierAllocs(t *testing.T) {
	const maxAllocs int64 = 0
	for _, s := range []string{"203.0.113.9", "10.0.0.1", "2001:db8::1", "fe80::1"} {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatal(err)
		}
		ip := net.ParseIP(s)
		res := testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = ssrf.PrivateAddr(addr)
				_ = isPrivateIP(ip)
			}
		})
		allocs := res.AllocsPerOp()
		t.Logf("PrivateAddr+isPrivateIP %s: %d allocs/op (bound %d), %d ns/op", s, allocs, maxAllocs, res.NsPerOp())
		if allocs > maxAllocs {
			t.Errorf("REGRESSION: private-address classification of %s allocates %d/op, exceeds bound %d — "+
				"the guard table is materialising a net.IP (or otherwise allocating) per check, on a path "+
				"reached once per X-Forwarded-For hop per request. See internal/ssrf PrivateAddr.", s, allocs, maxAllocs)
		}
	}
}

// TestBenchGate_TracingIDAllocs guards the per-request tracing-ID generators.
// setupRequestTracing runs both on essentially every proxied request (the
// request ID and traceparent are generated whenever the client sent none —
// the norm for direct client traffic). generateTraceparent previously paid
// fmt.Sprintf + two hex.EncodeToString (5 allocs/op, 144 B); the in-place
// hex.Encode rewrite is 1 alloc (the returned string), and generateRequestID
// has always been 1. The bound gives one alloc of headroom while still
// catching any fmt/strings re-introduction immediately.
func TestBenchGate_TracingIDAllocs(t *testing.T) {
	const maxAllocs int64 = 2 // steady state 1 each; pre-fix traceparent was 5
	for name, fn := range map[string]func() string{
		"generateRequestID":   generateRequestID,
		"generateTraceparent": generateTraceparent,
	} {
		res := testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if fn() == "" {
					b.Fatal("empty tracing ID")
				}
			}
		})
		allocs := res.AllocsPerOp()
		t.Logf("%s: %d allocs/op (bound %d), %d ns/op", name, allocs, maxAllocs, res.NsPerOp())
		if allocs > maxAllocs {
			t.Errorf("REGRESSION: %s allocates %d/op, exceeds bound %d — "+
				"per-request tracing-ID generation has regained fmt/hex-string overhead "+
				"(this runs on every proxied request via setupRequestTracing)", name, allocs, maxAllocs)
		}
	}
}

// TestBenchGate_PolicyEvalScheduledAllocs locks in the O(1)-allocation scan
// over scheduled rulesets. Before the minutes-of-day comparison, every rule
// with a time-of-day window ran fmt.Sprintf("%02d:%02d", ...) per request
// (1 alloc/rule — 1002 allocs/op measured at 1000 rules, ~35% of the scan's
// wall time), and each scheduled rule paid its own time.Now() inside the scan.
// The scan now reads the clock once (lazily) and compares integer minutes; the
// bound is a constant, not a function of rule count — any reintroduction of
// per-rule formatting fails this gate.
func TestBenchGate_PolicyEvalScheduledAllocs(t *testing.T) {
	const maxAllocs int64 = 4 // steady state 2 (host normalization + client-IP parse)
	for _, rules := range []int{10, 100, 1000} {
		ps := buildScheduledPolicyStore(rules)
		res := testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = ps.Evaluate("203.0.113.7", "", "unauth", "target.example.com", nil)
			}
		})
		allocs := res.AllocsPerOp()
		t.Logf("Evaluate scheduled rules=%d: %d allocs/op (bound %d), %d ns/op", rules, allocs, maxAllocs, res.NsPerOp())
		if allocs > maxAllocs {
			t.Errorf("REGRESSION: Evaluate scheduled rules=%d allocates %d/op, exceeds constant bound %d — "+
				"per-rule time formatting has returned to the schedule check on the policy hot path "+
				"(fmt.Sprintf in matchSchedule / parseClockMinutes fallback engaged on well-formed bounds?)",
				rules, allocs, maxAllocs)
		}
	}
}

// TestBenchGate_BlockPathAlertAllocs locks in the per-request alert-producer
// gate. Before it, every blocked request ran `go fireAlert(...)` unconditionally:
// a goroutine spawn, a heap-escaped payload, an RFC3339 timestamp format, a
// dedup-key concat and a round trip through the single process-wide dedup mutex
// — all to deliver an alert to nobody, because the default posture is no
// webhooks configured. Measured cost was 752-3106 ns/op at 2-3 allocs/op against
// an allow-path baseline of ~113 ns/op at 0 allocs/op, i.e. a blocked request
// cost 5-20x an allowed one.
//
// That is the wrong way round for a gateway: block volume peaks exactly when a
// scanning or beaconing flood is in progress, so the ungated producer degraded
// the proxy hardest under attack. recordStats now consults HasSubscriber first
// (the same contract storage_health.go uses), and the block path is allocation-
// free again.
//
// Allocations are the gate, not ns/op: they are deterministic and hardware-
// independent, so this bound holds across runners. A single alloc/op here means
// the goroutine spawn (or the payload build feeding it) has returned to the
// unsubscribed block path.
func TestBenchGate_BlockPathAlertAllocs(t *testing.T) {
	const maxAllocs int64 = 0 // steady state 0; pre-fix 2-3

	orig := globalAlertStore
	defer func() { globalAlertStore = orig }()
	as := &AlertStore{}
	as.Init("") // no webhooks — the default posture
	globalAlertStore = as

	for _, status := range []string{"POLICY_BLOCK", "POLICY_DROP", "THREAT_BLOCKED", "SCAN_BLOCKED", "DPI_BLOCKED"} {
		res := testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				recordStats("203.0.113.7", "target.example.com", status, "deny-rule", "block")
			}
		})
		allocs := res.AllocsPerOp()
		t.Logf("recordStats %s (no subscriber): %d allocs/op (bound %d), %d ns/op", status, allocs, maxAllocs, res.NsPerOp())
		if allocs > maxAllocs {
			t.Errorf("REGRESSION: recordStats %s allocates %d/op with NO webhook subscribed, exceeds bound %d — "+
				"the HasSubscriber gate has been bypassed and every blocked request is spawning an alert "+
				"goroutine again. See store.go recordStats.", status, allocs, maxAllocs)
		}
	}
}

// TestBenchGate_DNSFailureAlertAllocs is the same contract for the second
// per-request producer. fireDNSFailureAlert is reached from all four dial sites
// (plain HTTP, CONNECT bypass, CONNECT inspect, WebSocket); its rate is set by
// the environment, not the operator, so a resolver brownout would otherwise turn
// every request into a goroutine spawn plus an err.Error() format.
func TestBenchGate_DNSFailureAlertAllocs(t *testing.T) {
	const maxAllocs int64 = 0 // steady state 0; the err.Error() format alone was 1

	orig := globalAlertStore
	defer func() { globalAlertStore = orig }()
	as := &AlertStore{}
	as.Init("")
	globalAlertStore = as

	err := errTestDNS{}
	res := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			fireDNSFailureAlert("dns-fail.example.com", err)
		}
	})
	allocs := res.AllocsPerOp()
	t.Logf("fireDNSFailureAlert (no subscriber): %d allocs/op (bound %d), %d ns/op", allocs, maxAllocs, res.NsPerOp())
	if allocs > maxAllocs {
		t.Errorf("REGRESSION: fireDNSFailureAlert allocates %d/op with NO webhook subscribed, exceeds bound %d — "+
			"the HasSubscriber gate has been bypassed; a DNS brownout will now spawn a goroutine per request. "+
			"See alerts.go fireDNSFailureAlert.", allocs, maxAllocs)
	}
}

// TestBenchGate_RequestLogEntryAllocs locks in the allocation-free per-request
// request-log record. persistLogEntry is the chokepoint every logged request
// flows through — HTTP, CONNECT, WebSocket, SOCKS5, TUNNEL_CLOSED accounting
// rows and SSL-inspected inner requests — so an allocation here is an
// allocation on 100% of logged traffic.
//
// The only allocation it ever had was time.Now().Format("15:04:05"), a
// one-second-resolution render re-derived per request. It is now memoised per
// wall-clock second (store_logclock.go), which took the record build from
// 277 ns/1 alloc to 150 ns/0 allocs serially. This gate fails if a per-request
// format, an fmt.Sprintf, or any other allocating field build returns to the
// path.
func TestBenchGate_RequestLogEntryAllocs(t *testing.T) {
	const maxAllocs int64 = 0 // steady state 0; the clock render alone was 1

	if logger == nil {
		logger = log.New(io.Discard, "", log.LstdFlags)
	}
	res := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			persistLogEntry("203.0.113.7", "GET", "benchgate.example.com", "OK",
				"allow-corp-saas", "Allow", "alice@corp.example", 0, 0, 0, "", "", AuthLogFields{})
		}
	})
	allocs := res.AllocsPerOp()
	t.Logf("persistLogEntry: %d allocs/op (bound %d), %d ns/op", allocs, maxAllocs, res.NsPerOp())
	if allocs > maxAllocs {
		t.Errorf("REGRESSION: persistLogEntry allocates %d/op, exceeds bound %d — "+
			"per-request allocation has returned to the request-log chokepoint "+
			"(a re-introduced time.Format, or an allocating field build). "+
			"See store.go persistLogEntry and store_logclock.go.", allocs, maxAllocs)
	}
}

// overScratchChain builds a canonical all-public X-Forwarded-For value with n
// hops, used to probe the filter past its stack scratch. 30 IPv4 hops render to
// ~380 bytes, comfortably beyond the 256-byte buffer.
func overScratchChain(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "203.0.%d.%d", i/256, i%256)
	}
	return b.String()
}

// TestBenchGate_CategoryLookupConstantInTaxonomySize locks in the
// SIZE-INDEPENDENCE contract on host→category resolution.
//
// catStore.LookupHost sits on the request path: lookupHostCategory (policy.go)
// calls it, and categoryGroupMatchesHostRule (categorygroup.go) calls THAT once
// per proxied request for every enabled access rule carrying a
// DestCategoryGroup. It used to be a nested scan over every host pattern of
// every category, so the cost was O(taxonomy) per rule per request — measured
// ~24 us on the SHIPPED default taxonomy (657 patterns) and ~252 us at 5657, or
// ~497 us of pure CPU per request for a 20-rule category posture. It is now a
// bounded probe per host label (internal/urlcat lookupIn).
//
// This gate is keyed on the RATIO between two taxonomy sizes measured on the
// SAME machine in the same run, not on absolute ns/op — that is what keeps it
// hardware-independent, the same property the alloc-keyed gates above rely on.
// A return to the linear scan shows up as a ~10x ratio and fails immediately;
// the indexed lookup's ratio is ~1, with the remaining slack being map/cache
// effects from the larger index.
//
// Allocation cannot gate this one: the old scan was already 0 allocs/op (the
// "."+pattern concatenation is stack-allocated because it never escapes
// strings.HasSuffix). The regression this guards is pure CPU.
func TestBenchGate_CategoryLookupConstantInTaxonomySize(t *testing.T) {
	// Ratio bound. Measured ~1.05x indexed (76 ns at 657 patterns, 80 ns at
	// 6570); the linear scan measured ~10x (24 us → 250 us). 4 leaves generous
	// room for a noisy shared runner while staying far below the failure mode.
	const maxRatio = 4.0

	// A host in NO category: the clean-traffic case, and the worst case for the
	// old scan since a miss cannot short-circuit.
	const probe = "uncategorized.example.invalid"

	measure := func(patterns int) (int64, int) {
		entries := urlcat.DefaultEntries()
		base := 0
		for _, e := range entries {
			base += len(e.Hosts)
		}
		if patterns > base {
			hosts := make([]string, 0, patterns-base)
			for i := 0; i < patterns-base; i++ {
				hosts = append(hosts, fmt.Sprintf("pad-%d.corp.invalid", i))
			}
			entries = append(entries, &urlcat.Entry{Name: "Padding", Hosts: hosts})
			base = patterns
		}
		s := urlcat.New(entries)
		if _, _, ok := s.LookupHost(probe); ok {
			t.Fatalf("patterns=%d: probe host matched — the benchmark is not measuring the miss path", base)
		}
		// Two rounds, keep the faster: damps a scheduler hiccup on a shared
		// runner without weakening the bound.
		best := int64(0)
		for round := 0; round < 2; round++ {
			ns := testing.Benchmark(func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					_, _, _ = s.LookupHost(probe)
				}
			}).NsPerOp()
			if best == 0 || ns < best {
				best = ns
			}
		}
		return best, base
	}

	smallNs, smallN := measure(0)     // the shipped default taxonomy
	largeNs, largeN := measure(10000) // a deployment that grew its own categories

	ratio := float64(largeNs) / float64(smallNs)
	t.Logf("LookupHost: %d ns/op at %d patterns, %d ns/op at %d patterns — ratio %.2fx (bound %.1fx)",
		smallNs, smallN, largeNs, largeN, ratio, maxRatio)
	if ratio > maxRatio {
		t.Errorf("REGRESSION: LookupHost cost grew %.2fx when the taxonomy grew %.1fx, exceeding the %.1fx bound — "+
			"host→category resolution is scaling with taxonomy size again instead of with the host's label count. "+
			"That cost is paid inside the request goroutine, once per category-group rule, on every proxied request. "+
			"See internal/urlcat lookupIn and the hostIndex/adminHostIndex construction in rebuildIndex.",
			ratio, float64(largeN)/float64(smallN), maxRatio)
	}
}
