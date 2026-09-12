package main

// CHAOS-60 — the GeoIP resolution chain under a slow / unavailable resolver.
//
// Two defects, both reproduced against the pre-fix tree before this file was
// written:
//
//	GEO-1  geo.LookupCached — the accessor the per-request policy path uses,
//	       documented at its call site as "cache-only to avoid blocking the
//	       request goroutine" and recorded in the chaos register (row WK-3) as
//	       "never blocks on DB/DNS" — performed an UNCANCELLABLE net.LookupHost
//	       on a host→IP cache miss, inside the request goroutine, with no
//	       deadline, no bound and no single-flight.
//
//	GEO-2  The IP→country cache that the same path reads was, on the request
//	       path, populated by exactly one thing: trackDestinationCountry, a
//	       best-effort dashboard sampler that runs only on the ALLOW branch and
//	       drops its work when its 256-slot pool is full. Country-scoped policy
//	       ENFORCEMENT therefore depended on a telemetry goroutine having won a
//	       semaphore slot on an earlier request.
//
// Every test here stubs the resolver and the internal/geoip engine seams, so
// nothing performs real DNS and no MaxMind fixture is needed. Tests share the
// process-wide caches and counters, so each resets what it touches.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ── harness ────────────────────────────────────────────────────────────────

// geoTestEngine replaces the internal/geoip seams with an in-memory stand-in
// and returns it. warmed counts LookupByIP calls (the cache-populating call
// the warmer makes); the country map is what LookupCachedByIP answers from.
type geoTestEngine struct {
	mu      sync.Mutex
	country map[string]string
	warmed  atomic.Int64
}

func newGeoTestEngine(t *testing.T) *geoTestEngine {
	t.Helper()
	e := &geoTestEngine{country: map[string]string{}}

	origEnabled, origLookup, origCached := geoEnabledFn, geoLookupIPFn, geoLookupCachedIPFn
	origHook := geoWarmHook
	origLogger := logger
	if logger == nil {
		logger = log.New(os.Stderr, "[test] ", 0)
	}

	geoEnabledFn = func() bool { return true }
	geoLookupIPFn = func(ip net.IP) (string, string) {
		e.warmed.Add(1)
		// Mirror the real engine: a successful lookup caches its answer, so a
		// later LookupCachedByIP hits.
		e.mu.Lock()
		defer e.mu.Unlock()
		code := "XX"
		e.country[ip.String()] = code
		return code, "Testland"
	}
	geoLookupCachedIPFn = func(ip net.IP) (string, bool) {
		e.mu.Lock()
		defer e.mu.Unlock()
		c, ok := e.country[ip.String()]
		return c, ok
	}

	resetGeoResolveHealthForTest()
	t.Cleanup(func() {
		// Warm goroutines outlive the test body, and the saturation state and
		// counters they touch are process-global. Drain before restoring, or a
		// leaked warm clears the next test's saturation state and makes an
		// order-dependent flake out of a deterministic gate.
		deadline := time.Now().Add(5 * time.Second)
		for geoWarm.inflight.Load() > 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		geoEnabledFn, geoLookupIPFn, geoLookupCachedIPFn = origEnabled, origLookup, origCached
		geoWarmHook = origHook
		logger = origLogger
		resetGeoResolveHealthForTest()
		drainGeoWarmSem()
	})
	return e
}

// drainGeoWarmSem empties the warm semaphore so a test that deliberately
// saturated it cannot leak that state into the next one.
func drainGeoWarmSem() {
	for {
		select {
		case <-geoWarmSem:
		default:
			return
		}
	}
}

// awaitWarm waits for one warm-hook signal. It is BOUNDED so that a build in
// which LookupCached never arms a warm at all fails this gate with a message
// instead of hanging until the package timeout.
func awaitWarm(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("no warm was armed within 5s: %s", what)
	}
}

// waitFor polls cond until it holds or the deadline passes.
func waitForGeo(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", d, what)
}

// ── GEO-1: the request path must not block on DNS ──────────────────────────

// TestChaos60_LookupCachedNeverBlocksOnDNS is the primary defect gate. The
// resolver is stubbed to take far longer than any request budget; the policy
// path's accessor must still answer immediately, fail-closed.
func TestChaos60_LookupCachedNeverBlocksOnDNS(t *testing.T) {
	newGeoTestEngine(t)
	const resolverDelay = 2 * time.Second
	_, restore := stubResolver([]string{"203.0.113.7"}, nil)
	defer restore()
	orig := lookupHostFn
	lookupHostFn = func(ctx context.Context, host string) ([]string, error) {
		time.Sleep(resolverDelay)
		return orig(ctx, host)
	}

	start := time.Now()
	code, ok := geo.LookupCached("blocked-resolver.test.invalid")
	elapsed := time.Since(start)

	if ok || code != "" {
		t.Fatalf("LookupCached on an uncached host = (%q, %v), want (\"\", false) — fail closed", code, ok)
	}
	// A generous bound: the point is "did not wait for the resolver", not a
	// latency SLO. Anything at or above the resolver delay means the request
	// goroutine took the DNS round trip.
	if elapsed >= resolverDelay/2 {
		t.Fatalf("LookupCached blocked for %s against a %s resolver — the per-request policy path must never wait on DNS", elapsed, resolverDelay)
	}
}

// TestChaos60_PreFixShapeBlocksOnDNS is a permanent DEFECT PROOF. It rebuilds
// the pre-fix body of LookupCached inline and shows it blocks, so the gate
// above can never quietly start proving less than it claims — if a future
// change makes the resolver stub cheap, or makes resolveHost non-blocking by
// accident, this test fails and says so.
func TestChaos60_PreFixShapeBlocksOnDNS(t *testing.T) {
	newGeoTestEngine(t)
	const resolverDelay = 300 * time.Millisecond
	_, restore := stubResolver([]string{"203.0.113.8"}, nil)
	defer restore()
	orig := lookupHostFn
	lookupHostFn = func(ctx context.Context, host string) ([]string, error) {
		time.Sleep(resolverDelay)
		return orig(ctx, host)
	}

	// The pre-fix body, verbatim in shape: Enabled → resolveHost (blocking) →
	// cache-only country probe.
	preFixLookupCached := func(host string) (string, bool) {
		if !geoEnabledFn() {
			return "", false
		}
		ip := resolveHost(host)
		if ip == nil {
			return "", false
		}
		return geoLookupCachedIPFn(ip)
	}

	start := time.Now()
	_, _ = preFixLookupCached("prefix-shape.test.invalid")
	elapsed := time.Since(start)

	if elapsed < resolverDelay {
		t.Fatalf("the pre-fix shape returned in %s against a %s resolver — this proof no longer reproduces the defect it exists to pin", elapsed, resolverDelay)
	}
}

// TestChaos60_ConcurrentMissesResolveOnce pins the single-flight. Pre-fix,
// concurrent misses for one host each fired their own resolution, so a
// reconnect storm against a single host multiplied 1:1 into DNS queries aimed
// at a resolver that is, by hypothesis, already failing.
func TestChaos60_ConcurrentMissesResolveOnce(t *testing.T) {
	calls, restore := stubResolver([]string{"203.0.113.9"}, nil)
	defer restore()
	orig := lookupHostFn
	lookupHostFn = func(ctx context.Context, host string) ([]string, error) {
		// Wide enough that every caller is inside the miss window.
		time.Sleep(100 * time.Millisecond)
		return orig(ctx, host)
	}

	const callers = 50
	var wg sync.WaitGroup
	results := make([]net.IP, callers)
	start := make(chan struct{})
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results[i] = resolveHost("stampede.test.invalid")
		}()
	}
	close(start)
	wg.Wait()

	if n := calls.Load(); n != 1 {
		t.Fatalf("%d concurrent misses caused %d resolver invocations, want 1 — misses must be single-flighted", callers, n)
	}
	want := net.ParseIP("203.0.113.9")
	for i, got := range results {
		if got == nil || !got.Equal(want) {
			t.Fatalf("caller %d got %v, want %v — a follower must receive the leader's answer", i, got, want)
		}
	}
}

// ── GEO-2: enforcement must not depend on the dashboard sampler ────────────

// TestChaos60_WarmConvergesWithoutTheDashboardSampler is the GEO-2 gate. The
// destination-country tracker is not involved at all here: a miss on the
// policy path must arm its own warm, and the NEXT evaluation must match.
func TestChaos60_WarmConvergesWithoutTheDashboardSampler(t *testing.T) {
	eng := newGeoTestEngine(t)
	_, restore := stubResolver([]string{"203.0.113.11"}, nil)
	defer restore()

	done := make(chan struct{}, 4)
	geoWarmHook = func() { done <- struct{}{} }

	// First evaluation: nothing cached, fail closed, warm armed.
	if code, ok := geo.LookupCached("converge.test.invalid"); ok || code != "" {
		t.Fatalf("first LookupCached = (%q, %v), want (\"\", false)", code, ok)
	}
	awaitWarm(t, done, "a policy-path miss must arm its own warm rather than waiting for the dashboard sampler")

	// Second evaluation: both caches are now warm, so the country-scoped rule
	// can decide. Pre-fix this only happened if the dashboard sampler had run.
	waitForGeo(t, 2*time.Second, "the warmed country to become visible", func() bool {
		code, ok := geo.LookupCached("converge.test.invalid")
		return ok && code == "XX"
	})

	if n := eng.warmed.Load(); n == 0 {
		t.Fatal("the warm never populated the IP→country cache — enforcement would still depend on trackDestinationCountry")
	}
}

// TestChaos60_WarmFiresWhenOnlyTheCountryHalfIsMissing covers the other miss
// shape: the host→IP entry is live but the IP has never been geolocated. Left
// unwarmed, that host is permanently undecidable on the policy path whenever
// the dashboard sampler is saturated.
func TestChaos60_WarmFiresWhenOnlyTheCountryHalfIsMissing(t *testing.T) {
	eng := newGeoTestEngine(t)
	_, restore := stubResolver([]string{"203.0.113.12"}, nil)
	defer restore()

	// Seed the host half only.
	resolvedHostCache.put("half-warm.test.invalid", net.ParseIP("203.0.113.12"))

	done := make(chan struct{}, 4)
	geoWarmHook = func() { done <- struct{}{} }

	if code, ok := geo.LookupCached("half-warm.test.invalid"); ok || code != "" {
		t.Fatalf("LookupCached with an ungeolocated IP = (%q, %v), want (\"\", false)", code, ok)
	}
	awaitWarm(t, done, "a country-half miss must arm a warm")

	if n := eng.warmed.Load(); n != 1 {
		t.Fatalf("country-half miss caused %d warms, want 1", n)
	}
	waitForGeo(t, 2*time.Second, "the country half to warm", func() bool {
		code, ok := geo.LookupCached("half-warm.test.invalid")
		return ok && code == "XX"
	})
}

// TestChaos60_NegativeCachedHostDoesNotWarm pins the other direction: a host
// that RESOLVED to nothing usable (NXDOMAIN, resolver down, private-only) is
// already negative-cached, and its TTL — not a warm per request — governs when
// it is retried. Warming here would put the blocking resolution back on the
// request path's critical rate, one goroutine per request.
func TestChaos60_NegativeCachedHostDoesNotWarm(t *testing.T) {
	eng := newGeoTestEngine(t)
	_, restore := stubResolver(nil, errors.New("NXDOMAIN"))
	defer restore()

	resolvedHostCache.put("dead-host.test.invalid", nil)

	spawned := make(chan struct{}, 8)
	geoWarmHook = func() { spawned <- struct{}{} }

	for range 25 {
		if code, ok := geo.LookupCached("dead-host.test.invalid"); ok || code != "" {
			t.Fatalf("negative-cached host = (%q, %v), want (\"\", false)", code, ok)
		}
	}

	select {
	case <-spawned:
		t.Fatal("a negative-cached host armed a warm — the negative TTL, not the request rate, must govern the retry")
	case <-time.After(100 * time.Millisecond):
	}
	if n := eng.warmed.Load(); n != 0 {
		t.Fatalf("negative-cached host caused %d engine lookups, want 0", n)
	}
	if got := geoResolveState().Started; got != 0 {
		t.Fatalf("warm started counter = %d, want 0", got)
	}
}

// ── bounds, saturation, and the counters that make it visible ──────────────

// TestChaos60_WarmIsBoundedAndDropsWhenSaturated pins the drop-on-full bound.
// A queue here would convert a resolver outage into unbounded memory; the
// bound is what keeps a blackholed resolver from costing one goroutine (and
// one resolver FD) per request.
func TestChaos60_WarmIsBoundedAndDropsWhenSaturated(t *testing.T) {
	newGeoTestEngine(t)
	_, restore := stubResolver([]string{"203.0.113.13"}, nil)
	defer restore()

	// A private pool: another test's in-flight warm must not be able to free a
	// slot underneath this one (the shared-global variant of this test was
	// order-dependent and passed or failed on goroutine timing).
	defer swapGeoWarmSemForTest(1)()
	geoWarmSem <- struct{}{}

	done := make(chan struct{}, 8)
	geoWarmHook = func() { done <- struct{}{} }

	before := geoResolveState()
	geo.LookupCached("saturated.test.invalid")
	awaitWarm(t, done, "the drop path runs the hook synchronously")

	after := geoResolveState()
	if after.Dropped != before.Dropped+1 {
		t.Fatalf("dropped counter %d → %d, want +1 — a refused warm must be counted", before.Dropped, after.Dropped)
	}
	if after.Started != before.Started {
		t.Fatalf("started counter moved (%d → %d) while the pool was full — a dropped warm must not be counted as started", before.Started, after.Started)
	}
	if !after.Saturated {
		t.Fatal("saturation gauge stayed 0 while warms were being dropped")
	}
}

// TestChaos60_WarmSkipsAHostAlreadyBeingResolved pins the second half of the
// single-flight: a warm for a host whose resolution is already in flight must
// not consume a slot to do nothing.
func TestChaos60_WarmSkipsAHostAlreadyBeingResolved(t *testing.T) {
	newGeoTestEngine(t)
	_, restore := stubResolver([]string{"203.0.113.14"}, nil)
	defer restore()

	// Claim the single-flight slot the way a leader would, and hold it.
	call, leader := resolvedHostCache.joinFlight("inflight.test.invalid")
	if !leader {
		t.Fatalf("test setup: joinFlight returned leader=%v, want leader", leader)
	}
	defer resolvedHostCache.finishFlight("inflight.test.invalid", call, nil)

	spawned := make(chan struct{}, 8)
	geoWarmHook = func() { spawned <- struct{}{} }

	before := geoResolveState()
	for range 20 {
		warmGeoHost("inflight.test.invalid")
	}
	after := geoResolveState()

	if after.Started != before.Started || after.Dropped != before.Dropped {
		t.Fatalf("warms for an in-flight host were spawned or dropped (started %d→%d, dropped %d→%d) — they must be skipped",
			before.Started, after.Started, before.Dropped, after.Dropped)
	}
	select {
	case <-spawned:
		t.Fatal("a warm goroutine was spawned for a host already being resolved")
	case <-time.After(50 * time.Millisecond):
	}
}

// TestChaos60_UnresolvedCountryEvaluationIsCounted pins the security-relevant
// signal. A country-scoped rule that does not match because the country is
// unknown is a rule that did not enforce, and this counter is the operator's
// only way to see it.
func TestChaos60_UnresolvedCountryEvaluationIsCounted(t *testing.T) {
	newGeoTestEngine(t)
	_, restore := stubResolver([]string{"203.0.113.15"}, nil)
	defer restore()
	geoWarmHook = func() {}

	rule := &PolicyRule{DestCountry: []string{"XX"}}
	var sc hostCatScratch

	before := geoResolveState().Unresolved
	if matchDestNorm(rule, "uncounted.test.invalid", "uncounted.test.invalid", &sc) {
		t.Fatal("a country rule matched on an unknown country — the geo check must fail closed")
	}
	after := geoResolveState().Unresolved

	if after != before+1 {
		t.Fatalf("unresolved counter %d → %d, want +1", before, after)
	}
}

// TestChaos60_SaturationRecoversOnEvidenceNotTime pins the recovery
// discipline shared with storage_health.go and socks5_health.go: the degraded
// state clears when a warm actually gets a slot, never because time passed.
func TestChaos60_SaturationRecoversOnEvidenceNotTime(t *testing.T) {
	newGeoTestEngine(t)
	_, restore := stubResolver([]string{"203.0.113.16"}, nil)
	defer restore()

	defer swapGeoWarmSemForTest(1)()
	geoWarmSem <- struct{}{}

	done := make(chan struct{}, 8)
	geoWarmHook = func() { done <- struct{}{} }

	warmGeoHost("sat-recover.test.invalid")
	awaitWarm(t, done, "the refused warm")
	if !geoResolveState().Saturated {
		t.Fatal("saturation not recorded")
	}

	// Time alone must not clear it.
	time.Sleep(20 * time.Millisecond)
	if !geoResolveState().Saturated {
		t.Fatal("saturation cleared on elapsed time — recovery must be on observed evidence only")
	}

	<-geoWarmSem // free the slot: a warm can now make real progress
	warmGeoHost("sat-recover-2.test.invalid")
	awaitWarm(t, done, "the warm that got a slot")
	waitForGeo(t, time.Second, "saturation to clear after a warm got a slot", func() bool {
		return !geoResolveState().Saturated
	})
}

// ── controls ───────────────────────────────────────────────────────────────

// TestChaos60_ControlWarmerActuallyResolves is the control for the gates
// above. A warmer that spawned a goroutine and did nothing would satisfy every
// "does not block" and "is bounded" assertion while leaving country rules
// permanently unenforceable — strictly worse than the defect. This proves the
// warm performs the resolution it exists to perform.
func TestChaos60_ControlWarmerActuallyResolves(t *testing.T) {
	eng := newGeoTestEngine(t)
	calls, restore := stubResolver([]string{"203.0.113.17"}, nil)
	defer restore()

	done := make(chan struct{}, 4)
	geoWarmHook = func() { done <- struct{}{} }

	warmGeoHost("control-resolve.test.invalid")
	awaitWarm(t, done, "the control warm")

	if n := calls.Load(); n != 1 {
		t.Fatalf("warm caused %d resolver invocations, want 1", n)
	}
	if n := eng.warmed.Load(); n != 1 {
		t.Fatalf("warm caused %d engine lookups, want 1", n)
	}
	if ip, ok := resolvedHostCache.get("control-resolve.test.invalid"); !ok || ip == nil {
		t.Fatalf("warm did not populate the host cache (ip=%v ok=%v)", ip, ok)
	}
}

// TestChaos60_ControlDisabledGeoIPDoesNothing pins the default posture: with
// no GeoIP database loaded — the shipped default — the policy path performs no
// resolution, spawns no goroutine and touches no counter.
func TestChaos60_ControlDisabledGeoIPDoesNothing(t *testing.T) {
	newGeoTestEngine(t)
	geoEnabledFn = func() bool { return false }
	calls, restore := stubResolver([]string{"203.0.113.18"}, nil)
	defer restore()
	geoWarmHook = func() { t.Error("a warm was spawned with GeoIP disabled") }

	if code, ok := geo.LookupCached("disabled.test.invalid"); ok || code != "" {
		t.Fatalf("LookupCached with GeoIP disabled = (%q, %v), want (\"\", false)", code, ok)
	}
	if n := calls.Load(); n != 0 {
		t.Fatalf("resolver invoked %d times with GeoIP disabled, want 0", n)
	}
	if st := geoResolveState(); st.Started != 0 || st.Dropped != 0 {
		t.Fatalf("warm counters moved with GeoIP disabled: %+v", st)
	}
}

// ── metrics surface ────────────────────────────────────────────────────────

// TestChaos60_MetricsAppearOnlyWhenGeoIPIsLoaded pins both halves of the
// exposition rule. The absent-when-unloaded half is the load-bearing one: a
// flat `culvert_geo_warm_saturated 0` on a node that has no GeoIP database is
// indistinguishable from a node whose geo rules have stopped enforcing, and
// every paging rule on these series is `> 0` (the socks5 / cluster_ca
// precedent).
func TestChaos60_MetricsAppearOnlyWhenGeoIPIsLoaded(t *testing.T) {
	series := []string{
		"culvert_geo_warm_total",
		"culvert_geo_warm_dropped_total",
		"culvert_geo_warm_failed_total",
		"culvert_geo_warm_saturated",
		"culvert_geo_warm_inflight",
		"culvert_geo_policy_unresolved_total",
	}

	newGeoTestEngine(t)
	body := renderMetrics(t)
	for _, name := range series {
		if !strings.Contains(body, name) {
			t.Errorf("/metrics is missing %s on a node with a GeoIP database loaded", name)
		}
	}

	geoEnabledFn = func() bool { return false }
	body = renderMetrics(t)
	for _, name := range series {
		if strings.Contains(body, name) {
			t.Errorf("/metrics exports %s on a node with no GeoIP database — a flat 0 there is indistinguishable from geo rules having stopped enforcing", name)
		}
	}
}

// TestChaos60_APanickingLeaderStillPublishes pins the single-flight's most
// dangerous failure mode. The leader owns the slot; if it can return without
// publishing, every current follower blocks forever AND the slot stays
// occupied, so every later caller for that hostname becomes a permanently
// blocked follower too — one panic would take out that host for the life of
// the process. The panic must still propagate; it must simply not strand
// anyone on the way out.
func TestChaos60_APanickingLeaderStillPublishes(t *testing.T) {
	_, restore := stubResolver(nil, nil)
	defer restore()

	const host = "panicking-leader.test.invalid"
	release := make(chan struct{})
	var first atomic.Bool
	lookupHostFn = func(context.Context, string) ([]string, error) {
		if first.CompareAndSwap(false, true) {
			<-release // hold the slot until the follower is committed
			panic("resolver seam blew up")
		}
		return []string{"203.0.113.30"}, nil
	}

	leaderDone := make(chan struct{})
	go func() {
		defer close(leaderDone)
		defer func() { _ = recover() }() // the caller's own guard
		resolveHost(host)
	}()

	// Let a follower attach to the leader's call.
	followerDone := make(chan net.IP, 1)
	waitForGeo(t, 2*time.Second, "the leader to claim the single-flight slot", func() bool {
		return resolvedHostCache.resolving(host)
	})
	go func() { followerDone <- resolveHost(host) }()
	time.Sleep(20 * time.Millisecond)

	close(release)

	select {
	case <-leaderDone:
	case <-time.After(2 * time.Second):
		t.Fatal("the leader goroutine never returned")
	}
	select {
	case ip := <-followerDone:
		if ip != nil {
			t.Fatalf("follower got %v from a panicking leader, want nil — fail closed", ip)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the follower was stranded by a leader that returned without publishing")
	}

	// And the slot must be free, so the hostname is not poisoned for the rest
	// of the process lifetime.
	if resolvedHostCache.resolving(host) {
		t.Fatal("the single-flight slot was never released — every later caller for this host would block forever")
	}
}

// TestChaos60_OneHotHostCannotMonopolizeTheWarmPool pins the per-host
// reservation. Raised by Codex against the first version of this fix (P1).
//
// The warmer's "is this host already being resolved?" check was a PRE-check:
// the single-flight claim was only registered later, by the goroutine, inside
// resolveHost. Concurrent policy evaluations for one uncached hostname — the
// reconnect-storm shape this whole change exists to survive — therefore ALL
// passed the check, ALL consumed a semaphore slot, and all but one parked as
// followers holding those slots for the resolver's full delay. One popular
// destination could drain the entire pool, so warms for unrelated hosts were
// dropped and THEIR country rules stayed unresolved: the exact degradation
// this PR fixes, re-entered through its own fix.
//
// The reservation must therefore be taken BEFORE a slot is consumed.
//
// This is a MANY-TRIAL gate, deliberately, and for the reason
// TestChaos54_StopIsPromptDuringAcceptBackoff is one: whether the leader's
// goroutine happens to register its claim before the other callers reach the
// pre-check is a scheduling coin flip, so a single trial passes a broken
// build most of the time. The invariant asserted in each trial is exact —
// one host, at most one slot — and only the number of trials is statistical.
func TestChaos60_OneHotHostCannotMonopolizeTheWarmPool(t *testing.T) {
	newGeoTestEngine(t)
	_, restore := stubResolver([]string{"203.0.113.40"}, nil)
	defer restore()

	const (
		pool    = 8
		callers = pool * 4
		trials  = 60
	)
	defer swapGeoWarmSemForTest(pool)()

	for trial := range trials {
		host := fmt.Sprintf("hot-host-%d.test.invalid", trial)

		release := make(chan struct{})
		var releaseOnce sync.Once
		lookupHostFn = func(context.Context, string) ([]string, error) {
			<-release // hold the slot the way a slow resolver would
			return []string{"203.0.113.40"}, nil
		}

		// All callers arrive at warmGeoHost together — the storm shape.
		start := make(chan struct{})
		var wg sync.WaitGroup
		for range callers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				warmGeoHost(host)
			}()
		}
		close(start)
		wg.Wait()

		held := len(geoWarmSem)
		releaseOnce.Do(func() { close(release) })
		waitForGeo(t, 5*time.Second, "the trial's warms to drain", func() bool {
			return geoResolveState().InFlight == 0
		})

		// Exactly one warm may be in flight for one host, however many callers
		// asked. More than one held slot means unrelated destinations would
		// have their warms dropped and their country rules left unresolved.
		if held > 1 {
			t.Fatalf("trial %d: %d concurrent warms for ONE host held %d/%d pool slots, want at most 1 — one hot destination must not be able to drain the pool",
				trial, callers, held, pool)
		}
		resetGeoResolveHealthForTest()
	}
}

// TestCheckGeoResolution_OperatorContractRow pins the `geo_resolution`
// diagnostics row: before it existed, a country-scoped rule that silently
// stopped matching (a saturated warm pool, or unresolved evaluations
// outnumbering completed warms) was visible only on the raw /metrics text
// endpoint or in the process log — nowhere in GET /api/diagnostics or the
// admin GUI. This is the same evidence, admin-visible without a curl.
func TestCheckGeoResolution_OperatorContractRow(t *testing.T) {
	resetGeoResolveHealthForTest()
	t.Cleanup(resetGeoResolveHealthForTest)

	if c := checkGeoResolution(); c.Code != "geo_resolution" || c.Status != diagOK {
		t.Fatalf("idle state: got %+v, want ok/geo_resolution", c)
	}

	geoWarm.started.Add(10)
	geoWarm.unresolved.Add(1)
	if c := checkGeoResolution(); c.Status != diagOK {
		t.Fatalf("low unresolved rate: got %+v, want ok", c)
	}
	resetGeoResolveHealthForTest()

	geoWarm.started.Add(2)
	geoWarm.unresolved.Add(5)
	if c := checkGeoResolution(); c.Status != diagWarn || c.OperatorAction == "" {
		t.Fatalf("unresolved evaluations outnumbering warms: got %+v, want warn with an operator action", c)
	}
	resetGeoResolveHealthForTest()

	geoWarm.mu.Lock()
	geoWarm.saturated = true
	geoWarm.mu.Unlock()
	if c := checkGeoResolution(); c.Status != diagWarn || c.OperatorAction == "" {
		t.Fatalf("saturated pool: got %+v, want warn with an operator action", c)
	}
}
