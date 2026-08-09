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
	"fmt"
	"io"
	"log"
	"net/http"
	"testing"

	"github.com/KidCarmi/Culvert/internal/sslbypass"
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
