package main

// dns_resolve_chaos_test.go — CHAOS-57 gates.
//
// Three DEFECT gates (D1–D3) were each verified FAILING against the pre-fix
// tree: with `net.LookupHost` behind the seam and no single-flight, no
// deadline, no pool bound and no stale serving, D1 hung for the wedged
// resolver's full budget, D2 observed 200 resolver invocations for 200
// concurrent requests to ONE host, and D3 observed geo resolution go dark the
// moment a warm entry expired.
//
// The rest pin the new behaviour, plus two CONTROLS. Controls matter here for
// the reason they mattered in CHAOS-56: a resolver that simply stopped
// resolving would pass every defect gate while being far worse than the defect,
// so the suite has to prove the mechanism still RESOLVES (C1) and still tells
// the truth about failures (C2).

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// blockingResolver installs a seam that blocks until release is closed, then
// returns err. Returns the invocation counter.
func blockingResolver(t *testing.T, release <-chan struct{}, addrs []string, err error) *atomic.Int64 {
	t.Helper()
	var calls atomic.Int64
	orig := lookupHostFn
	lookupHostFn = func(ctx context.Context, host string) ([]string, error) {
		calls.Add(1)
		select {
		case <-release:
			return addrs, err
		case <-ctx.Done():
			return nil, &net.DNSError{Err: "i/o timeout", Name: host, IsTimeout: true}
		}
	}
	resolvedHostCache.mu.Lock()
	origEntries := resolvedHostCache.entries
	resolvedHostCache.entries = map[string]hostIPEntry{}
	resolvedHostCache.inflight = map[string]*hostIPFlight{}
	resolvedHostCache.mu.Unlock()
	resetDNSResolveHealthForTest()
	t.Cleanup(func() {
		drainInflightResolutions()
		lookupHostFn = orig
		resolvedHostCache.mu.Lock()
		resolvedHostCache.entries = origEntries
		resolvedHostCache.inflight = map[string]*hostIPFlight{}
		resolvedHostCache.mu.Unlock()
		resetDNSResolveHealthForTest()
	})
	return &calls
}

// ─── D1: the resolution is bounded in TIME ───────────────────────────────────

// TestChaos57_WedgedResolverDoesNotBlockTheRequestPathForever pins the
// deadline. Pre-fix this call sat in net.LookupHost for the OS budget
// (resolv.conf ships timeout:5 attempts:2 per nameserver) on the REQUEST
// goroutine, holding a client connection and a per-IP connection-limiter slot.
func TestChaos57_WedgedResolverDoesNotBlockTheRequestPathForever(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	blockingResolver(t, release, nil, nil)

	done := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		_ = resolveHost("wedged.chaos57.invalid")
		done <- time.Since(start)
	}()

	select {
	case elapsed := <-done:
		// Generous ceiling: the contract is "bounded by dnsResolveTimeout", and
		// a shared CI runner can add scheduling slop. Pre-fix this never
		// returned at all until the resolver did.
		if elapsed > dnsResolveTimeout*3 {
			t.Fatalf("resolveHost took %s against a wedged resolver, want ≈%s", elapsed, dnsResolveTimeout)
		}
	case <-time.After(dnsResolveTimeout * 5):
		t.Fatal("resolveHost never returned against a wedged resolver — the resolution deadline is gone")
	}
}

// TestChaos57_TimeoutIsCountedAndClassified: a deadline overrun must be
// visible. Pre-fix nothing on this path counted, logged or alerted a failure.
func TestChaos57_TimeoutIsCountedAndClassified(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	blockingResolver(t, release, nil, nil)

	_ = resolveHost("timeout-counted.chaos57.invalid")

	snap := dnsResolveState()
	if snap.Failures == 0 {
		t.Fatal("a resolution that overran its deadline was charged to no counter")
	}
	if snap.Timeouts == 0 {
		t.Fatalf("timeout not classified: %+v", snap)
	}
	if snap.LastReason != "timeout" {
		t.Fatalf("LastReason = %q, want \"timeout\"", snap.LastReason)
	}
}

// ─── D2: the resolution is SINGLE-FLIGHTED ───────────────────────────────────

// TestChaos57_ConcurrentMissesForOneHostResolveOnce pins the single-flight.
//
// Pre-fix: 200 concurrent misses for one host produced 200 resolver
// invocations — one blocked goroutine per request AND one query per request
// aimed at a resolver that, in the failure case this matters for, is already
// failing.
func TestChaos57_ConcurrentMissesForOneHostResolveOnce(t *testing.T) {
	release := make(chan struct{})
	calls := blockingResolver(t, release, []string{"203.0.113.57"}, nil)

	const goroutines = 200
	var wg sync.WaitGroup
	started := make(chan struct{}, goroutines)
	results := make([]net.IP, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			started <- struct{}{}
			results[i] = resolveHost("herd.chaos57.invalid")
		}(i)
	}
	for i := 0; i < goroutines; i++ {
		<-started
	}
	// Give every goroutine a chance to reach the flight before the leader
	// completes, so the count below is a real measurement of the herd.
	time.Sleep(150 * time.Millisecond)
	inflightCalls := calls.Load()
	close(release)
	wg.Wait()

	if inflightCalls != 1 {
		t.Fatalf("resolver invoked %d times for %d concurrent misses of ONE host, want 1 — the single-flight is gone and a resolver brownout amplifies by request rate", inflightCalls, goroutines)
	}
	want := net.ParseIP("203.0.113.57")
	for i, got := range results {
		if got == nil || !got.Equal(want) {
			t.Fatalf("follower %d got %v, want the leader's answer %v — followers must inherit the result, not a nil", i, got, want)
		}
	}
}

// TestChaos57_FollowersAreReleasedWhenTheLeaderSheds: a leader that sheds must
// still finish its flight. If it did not, every follower would block forever on
// a flight nobody completes — a bounded resolver fault converted into a
// permanent request-plane hang that no upstream recover() can undo.
func TestChaos57_FollowersAreReleasedWhenTheLeaderSheds(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	blockingResolver(t, release, nil, nil)
	restore := shrinkResolverPool(t, 0)
	defer restore()

	done := make(chan struct{})
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); _ = resolveHost("shed-followers.chaos57.invalid") }()
		}
		wg.Wait()
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("followers blocked forever behind a leader that shed — finishFlight is not reached on every leader exit path")
	}
}

// ─── D3: an expired-but-usable answer is SERVED, not discarded ───────────────

// TestChaos57_ResolverOutageDoesNotTakeGeoRulesDark is the security half.
//
// A DestCountry rule that does not match is SKIPPED and evaluation continues to
// lower-priority rules, so an unknown country silently stops a "block sanctioned
// countries" rule from enforcing while a broad allow rule beneath it takes over.
// Pre-fix, the first cache expiry during a resolver outage did exactly that for
// every host at once.
func TestChaos57_ResolverOutageDoesNotTakeGeoRulesDark(t *testing.T) {
	calls, restore := stubResolver([]string{"203.0.113.58"}, nil)
	defer restore()

	warm := resolveHost("outage.chaos57.invalid")
	if warm == nil {
		t.Fatal("warm-up resolution failed")
	}
	waitForResolverCalls(t, calls, 1)

	// The resolver dies, and the entry expires underneath it. Drain first: the
	// warm-up may still have a flight outstanding, and swapping the seam over a
	// live reader is a -race failure, not a product bug.
	drainInflightResolutions()
	origFn := lookupHostFn
	lookupHostFn = func(_ context.Context, _ string) ([]string, error) {
		return nil, &net.DNSError{Err: "server misbehaving", Name: "outage.chaos57.invalid"}
	}
	defer func() {
		drainInflightResolutions()
		lookupHostFn = origFn
	}()
	expireEntry("outage.chaos57.invalid", time.Second)

	got := resolveHost("outage.chaos57.invalid")
	if got == nil || !got.Equal(warm) {
		t.Fatalf("resolveHost = %v during a resolver outage, want the last known address %v — geo-scoped rules go dark otherwise", got, warm)
	}
}

// TestChaos57_FailedRefreshDoesNotDestroyTheStaleAnswer proves the background
// refresh cannot make an outage worse than it already is.
//
// The background refresh must not be able to make things worse. A failed
// refresh writes a NEGATIVE result, and a negative entry is served as FRESH for
// the negative TTL — so without the guard in hostIPCache.put the refresh
// introduced by this change would itself take geo dark for exactly the window
// the stale answer existed to cover.
func TestChaos57_FailedRefreshDoesNotDestroyTheStaleAnswer(t *testing.T) {
	calls, restore := stubResolver([]string{"203.0.113.59"}, nil)
	defer restore()

	warm := resolveHost("refresh-fail.chaos57.invalid")
	if warm == nil {
		t.Fatal("warm-up resolution failed")
	}
	waitForResolverCalls(t, calls, 1)
	drainInflightResolutions()

	origFn := lookupHostFn
	lookupHostFn = func(_ context.Context, _ string) ([]string, error) {
		return nil, &net.DNSError{Err: "server misbehaving", Name: "refresh-fail.chaos57.invalid"}
	}
	defer func() {
		drainInflightResolutions()
		lookupHostFn = origFn
	}()

	expireEntry("refresh-fail.chaos57.invalid", time.Second)
	if got := resolveHost("refresh-fail.chaos57.invalid"); got == nil {
		t.Fatal("first stale serve returned nil")
	}
	// Let the failing refresh land.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if dnsResolveState().Failures > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if dnsResolveState().Failures == 0 {
		t.Fatal("the background refresh never ran")
	}

	// The stale positive must survive the failed refresh.
	if got := resolveHost("refresh-fail.chaos57.invalid"); got == nil || !got.Equal(warm) {
		t.Fatalf("after a failed refresh resolveHost = %v, want the preserved stale address %v — a failed refresh must never overwrite a still-servable answer", got, warm)
	}
}

// TestChaos57_StaleServesDoNotStackRefreshes pins at most ONE refresh per host,
// however many requests are served stale behind it.
//
// At most ONE refresh per host may be in flight, however many requests are
// served stale behind it. During a resolver outage the stale window is not a
// rare edge — it is every request for every host in the working set, for the
// length of the outage — so a per-request refresh would put a resolution
// attempt and an exclusive cache-lock acquisition on the policy path precisely
// when the gateway is already degraded.
func TestChaos57_StaleServesDoNotStackRefreshes(t *testing.T) {
	// The refresh is held OPEN for the whole burst, which is the case that
	// matters: a completed refresh makes the entry fresh again, so only a
	// resolver that is NOT answering keeps every request in the stale window —
	// exactly the outage this mechanism exists for.
	release := make(chan struct{})
	warm := make(chan struct{})
	calls := blockingResolver(t, release, []string{"203.0.113.66"}, nil)

	close(warm)
	go func() { <-warm; time.Sleep(20 * time.Millisecond); close(release) }()
	if resolveHost("stale-stack.chaos57.invalid") == nil {
		t.Fatal("warm-up failed")
	}
	drainInflightResolutions()
	if n := calls.Load(); n != 1 {
		t.Fatalf("warm-up used %d resolver calls, want 1", n)
	}

	// Now wedge the resolver for the rest of the test and expire the entry.
	wedge := make(chan struct{})
	defer close(wedge)
	origFn := lookupHostFn
	lookupHostFn = func(ctx context.Context, host string) ([]string, error) {
		calls.Add(1)
		select {
		case <-wedge:
			return nil, &net.DNSError{Err: "server misbehaving", Name: host}
		case <-ctx.Done():
			return nil, &net.DNSError{Err: "i/o timeout", Name: host, IsTimeout: true}
		}
	}
	defer func() {
		drainInflightResolutions()
		lookupHostFn = origFn
	}()
	expireEntry("stale-stack.chaos57.invalid", time.Second)

	// A burst of stale serves. The first becomes the refresh leader; every
	// other one must ride behind it and be served immediately.
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ip := resolveHost("stale-stack.chaos57.invalid"); ip == nil {
				t.Error("a stale serve returned nil while a refresh was in flight")
			}
		}()
	}
	wg.Wait()

	// Exactly one refresh, not one per request.
	if n := calls.Load(); n != 2 {
		t.Fatalf("100 stale serves against a wedged resolver used %d resolver calls, want 2 (warm-up + ONE refresh) — refreshes are stacking per request", n)
	}
	if snap := dnsResolveState(); snap.StaleServed != 100 {
		t.Fatalf("StaleServed=%d, want 100 — every stale serve must be counted", snap.StaleServed)
	}
}

// ─── The resolver pool is BOUNDED ────────────────────────────────────────────

// driveResolverDegraded records a run of failures that SPANS the degradation
// threshold. The threshold is a duration measured from the first failure of the
// run to the latest one, so a burst of failures all stamped after the threshold
// is not degradation — that distinction is the point of the mechanism and it
// has to be reproduced faithfully here.
func driveResolverDegraded() {
	start := time.Now()
	noteDNSResolveFailure("timeout", start)
	for i := 1; i <= 4; i++ {
		noteDNSResolveFailure("timeout", start.Add(dnsResolveDegradedAfter+time.Duration(i)*time.Second))
	}
}

// shrinkResolverPool replaces the process-wide resolver pool with one of size n.
func shrinkResolverPool(t *testing.T, n int) (restore func()) {
	t.Helper()
	orig := dnsResolveSem
	dnsResolveSem = make(chan struct{}, n)
	return func() {
		drainInflightResolutions()
		dnsResolveSem = orig
	}
}

// TestChaos57_DistinctHostFloodIsShedNotQueued proves a herd spread across many
// hosts is shed rather than queued.
//
// Single-flight collapses a herd on ONE host and does nothing about a herd
// across MANY hosts — and the hostname is attacker-controlled, so a scanning
// client during a resolver brownout would otherwise create one blocked
// goroutine per distinct host, each holding a request, a connection and a
// connection-limiter slot.
func TestChaos57_DistinctHostFloodIsShedNotQueued(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	blockingResolver(t, release, nil, nil)
	restore := shrinkResolverPool(t, 2)
	defer restore()

	const flood = 100
	done := make(chan struct{})
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		for i := 0; i < flood; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_ = resolveHost(floodHost(i))
			}(i)
		}
		wg.Wait()
	}()

	select {
	case <-done:
	case <-time.After(dnsResolveTimeout * 4):
		t.Fatal("a distinct-host flood was queued rather than shed — the resolver pool bound is gone")
	}

	snap := dnsResolveState()
	if snap.Shed == 0 {
		t.Fatalf("no resolution was shed under a %d-host flood against a 2-slot pool: %+v", flood, snap)
	}
}

func floodHost(i int) string {
	return "flood-" + strings.Repeat("x", i%3) + itoaSmall(i) + ".chaos57.invalid"
}

func itoaSmall(i int) string {
	if i == 0 {
		return "0"
	}
	var b [8]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}

// TestChaos57_ShedResultIsNotCached: saturation is a fact about THIS node's
// load, not about the host. Caching it would let a transient overload suppress
// resolution of a legitimate destination for a full negative TTL.
func TestChaos57_ShedResultIsNotCached(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	blockingResolver(t, release, nil, nil)
	restore := shrinkResolverPool(t, 0)
	defer restore()

	if ip := resolveHost("shed-nocache.chaos57.invalid"); ip != nil {
		t.Fatalf("shed resolution returned %v, want nil", ip)
	}
	resolvedHostCache.mu.RLock()
	_, cached := resolvedHostCache.entries["shed-nocache.chaos57.invalid"]
	resolvedHostCache.mu.RUnlock()
	if cached {
		t.Fatal("a shed resolution was written to the cache — a transient overload must not suppress a legitimate destination for a TTL")
	}
}

// ─── Observability contracts ─────────────────────────────────────────────────

// TestChaos57_NXDOMAINNeverDrivesDegradation keeps an authoritative "no such
// host" out of the degradation run.
//
// An authoritative "this name does not exist" is a resolver working perfectly,
// and a gateway sees a steady stream of them from typos and malware beaconing to
// sinkholed C2. Counting them toward degradation would page on healthy traffic
// — and, because the hostname is client-chosen, would let any client fabricate
// the page on demand.
func TestChaos57_NXDOMAINNeverDrivesDegradation(t *testing.T) {
	resetDNSResolveHealthForTest()
	defer resetDNSResolveHealthForTest()

	now := time.Now()
	for i := 0; i < 1000; i++ {
		noteDNSResolveFailure("nxdomain", now.Add(time.Duration(i)*time.Second))
	}
	snap := dnsResolveState()
	if snap.Failing || snap.Degraded {
		t.Fatalf("1000 NXDOMAIN answers over %s produced Failing=%v Degraded=%v — client-chosen hostnames must not be able to fabricate a page",
			dnsResolveDegradedAfter, snap.Failing, snap.Degraded)
	}
	if snap.Failures != 1000 {
		t.Fatalf("NXDOMAIN answers must still be COUNTED: Failures=%d, want 1000", snap.Failures)
	}
}

// TestChaos57_DegradationIsADurationAndAlertsOnce pins the threshold as a
// DURATION and the page as fire-once per episode.
func TestChaos57_DegradationIsADurationAndAlertsOnce(t *testing.T) {
	resetDNSResolveHealthForTest()
	defer resetDNSResolveHealthForTest()

	var alerts int64
	origAlert := fireDNSResolveAlert
	fireDNSResolveAlert = func(string) { atomic.AddInt64(&alerts, 1) }
	defer func() { fireDNSResolveAlert = origAlert }()

	start := time.Now()
	// A short burst must NOT page: the threshold is a duration, not a count.
	for i := 0; i < 500; i++ {
		noteDNSResolveFailure("timeout", start.Add(time.Duration(i)*time.Millisecond))
	}
	if got := atomic.LoadInt64(&alerts); got != 0 {
		t.Fatalf("a 500-failure burst inside %s paged %d times, want 0", dnsResolveDegradedAfter, got)
	}
	if dnsResolveState().Degraded {
		t.Fatal("degraded before the duration threshold")
	}

	// Sustained past the threshold pages exactly once.
	for i := 0; i < 10; i++ {
		noteDNSResolveFailure("timeout", start.Add(dnsResolveDegradedAfter+time.Duration(i)*time.Second))
	}
	if got := atomic.LoadInt64(&alerts); got != 1 {
		t.Fatalf("sustained failure paged %d times, want exactly 1 (fire-once latch per episode)", got)
	}
	if !dnsResolveState().Degraded {
		t.Fatal("not degraded after sustained failure past the threshold")
	}
}

// TestChaos57_RecoveryIsOnObservedEvidence requires an observed successful
// resolution to clear the degraded state.
//
// Elapsed time never clears the degraded state. A gateway whose resolution
// failures stop because traffic stopped has not recovered, and reporting that
// as recovery is the mistake ca_health.go and storage_health.go both name.
func TestChaos57_RecoveryIsOnObservedEvidence(t *testing.T) {
	resetDNSResolveHealthForTest()
	defer resetDNSResolveHealthForTest()

	driveResolverDegraded()
	if !dnsResolveState().Degraded {
		t.Fatal("setup: not degraded")
	}
	// No amount of not-looking clears it.
	if snap := dnsResolveState(); !snap.Degraded {
		t.Fatal("degraded state cleared without evidence")
	}
	noteDNSResolveOK()
	snap := dnsResolveState()
	if snap.Degraded || snap.Failing || snap.Consecutive != 0 {
		t.Fatalf("an observed successful resolution did not clear the episode: %+v", snap)
	}
	// History survives recovery.
	if snap.Failures != 5 {
		t.Fatalf("Failures=%d after recovery, want the cumulative 5 — a history of transient outages must stay visible", snap.Failures)
	}
}

// TestChaos57_PrivateOnlyAnswerIsNotAResolverFault treats an answer carrying only
// private addresses as a HEALTHY resolver.
//
// On a split-horizon estate this is the common case. The resolver ANSWERED, so
// it must clear a failure episode exactly like a public answer does — otherwise
// an internal-DNS deployment reports a permanently broken resolver.
func TestChaos57_PrivateOnlyAnswerIsNotAResolverFault(t *testing.T) {
	resetDNSResolveHealthForTest()
	defer resetDNSResolveHealthForTest()

	driveResolverDegraded()
	if !dnsResolveState().Degraded {
		t.Fatal("setup: not degraded")
	}
	noteDNSNoPublicAnswer()
	if snap := dnsResolveState(); snap.Degraded || snap.Failing {
		t.Fatalf("a private-only ANSWER left the resolver reported as degraded: %+v", snap)
	}
}

// TestChaos57_AlertDetailIsBounded pins the dedup-key contract on BOTH
// dns_failure producers.
//
// Store.Dispatch dedups on `event + ":" + Detail`. A *net.DNSError's text
// embeds the QUERIED HOSTNAME, which is client-chosen, so a raw err.Error()
// gives every failure a distinct key the 30 s window cannot suppress — the
// fan-out then lands in the 500-entry retry queue and evicts real threat
// alerts (WK-12/RS-5).
func TestChaos57_AlertDetailIsBounded(t *testing.T) {
	seen := map[string]struct{}{}
	for i := 0; i < 200; i++ {
		err := &net.DNSError{
			Err:  "no such host",
			Name: "attacker-chosen-" + itoaSmall(i) + ".example.invalid",
			// A real resolver error also carries the server address.
			Server:     "10.0.0." + itoaSmall(i%250),
			IsNotFound: true,
		}
		seen["detail:"+classifyDNSFailure(err)] = struct{}{}
	}
	if len(seen) != 1 {
		t.Fatalf("200 failures for 200 distinct client-chosen hostnames produced %d distinct dedup keys, want 1 — the alert Detail is unbounded again", len(seen))
	}
	// And the reason must not leak the hostname.
	err := &net.DNSError{Err: "no such host", Name: "secret-internal-host.corp.invalid", IsNotFound: true}
	if reason := classifyDNSFailure(err); strings.Contains(reason, "secret-internal-host") {
		t.Fatalf("classifyDNSFailure leaked the queried hostname: %q", reason)
	}
}

func TestChaos57_ClassifyDNSFailureClasses(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"timeout", &net.DNSError{IsTimeout: true}, "timeout"},
		{"nxdomain", &net.DNSError{IsNotFound: true}, "nxdomain"},
		{"temporary", &net.DNSError{IsTemporary: true}, "temporary"},
		{"other-dns", &net.DNSError{Err: "server misbehaving"}, "resolver_error"},
		{"deadline", context.DeadlineExceeded, "timeout"},
		{"opaque", errors.New("boom"), "resolver_error"},
		{"nil", nil, "unknown"},
	}
	for _, tc := range cases {
		if got := classifyDNSFailure(tc.err); got != tc.want {
			t.Errorf("%s: classifyDNSFailure = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestChaos57_NXDOMAINAtTheDeadlineBoundaryStaysNXDOMAIN keeps an authoritative
// verdict authoritative even when the resolution's deadline has already passed.
//
// An authoritative NXDOMAIN that lands microseconds before the deadline leaves
// the context expired by the time the error is classified. A ctx-first reading
// would stamp it "timeout", which escalates toward the degradation page while
// "nxdomain" deliberately does not — and since the hostname is client-chosen,
// that inversion hands any client a way to fabricate the page by requesting
// nonexistent hosts under mild resolver latency. The resolver's own
// classification is authoritative.
func TestChaos57_NXDOMAINAtTheDeadlineBoundaryStaysNXDOMAIN(t *testing.T) {
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if expired.Err() == nil {
		t.Fatal("setup: context is not expired")
	}
	nx := &net.DNSError{Err: "no such host", Name: "typo.example.invalid", IsNotFound: true}

	// The deadline refinement must not touch an AUTHORITATIVE verdict, however
	// long the resolution actually took.
	if got := refineDNSFailureWithDeadline(expired, classifyDNSFailure(nx)); got != "nxdomain" {
		t.Fatalf("an NXDOMAIN classified against an expired deadline = %q, want \"nxdomain\" — the clock must never relabel an authoritative answer", got)
	}
	for _, authoritative := range []string{"nxdomain", "temporary", "timeout"} {
		if got := refineDNSFailureWithDeadline(expired, authoritative); got != authoritative {
			t.Fatalf("refineDNSFailureWithDeadline(%q) = %q, want it unchanged", authoritative, got)
		}
	}

	// It DOES upgrade an unclassified failure — that is the case it exists for.
	if got := refineDNSFailureWithDeadline(expired, "resolver_error"); got != "timeout" {
		t.Fatalf("an unclassified failure at an expired deadline = %q, want \"timeout\"", got)
	}
	live, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	if got := refineDNSFailureWithDeadline(live, "resolver_error"); got != "resolver_error" {
		t.Fatalf("an unclassified failure with a LIVE context = %q, want it unchanged", got)
	}

	// And the escalation consequence is what actually matters: the hostname is
	// client-chosen, so if a typo under mild resolver latency could read as a
	// timeout, any client could fabricate the degradation page on demand.
	resetDNSResolveHealthForTest()
	defer resetDNSResolveHealthForTest()
	start := time.Now()
	reason := refineDNSFailureWithDeadline(expired, classifyDNSFailure(nx))
	noteDNSResolveFailure(reason, start)
	noteDNSResolveFailure(reason, start.Add(dnsResolveDegradedAfter+time.Second))
	if snap := dnsResolveState(); snap.Degraded {
		t.Fatal("NXDOMAIN answers classified at an expired deadline drove the resolver to degraded")
	}
}

// TestChaos57_ContractRowReportsWarnNotFail pins the degraded contract row at
// warn rather than fail.
//
// A resolver outage is fleet-wide by construction — every node shares the
// customer's DNS. The gateway is still proxying every request; what has stopped
// is geo-scoped policy MATCHING. Reporting fail would be read as "this node is
// broken" and, on a strict readiness deployment, would eject a fleet that is
// serving.
func TestChaos57_ContractRowReportsWarnNotFail(t *testing.T) {
	resetDNSResolveHealthForTest()
	defer resetDNSResolveHealthForTest()

	if row := checkDNSResolution(); row.Status != diagOK {
		t.Fatalf("unused resolver reports %q, want ok — a permanent row would be noise on an appliance with no geo rules", row.Status)
	}

	driveResolverDegraded()
	row := checkDNSResolution()
	if row.Status != diagWarn {
		t.Fatalf("degraded resolver reports %q, want warn", row.Status)
	}
	if row.OperatorAction == "" {
		t.Fatal("degraded row carries no OperatorAction")
	}
	// The message must state what is not being enforced — that is the part an
	// operator cannot infer from "DNS is down".
	if !strings.Contains(strings.ToLower(row.Message), "not being enforced") {
		t.Fatalf("degraded row does not say what stopped being enforced: %q", row.Message)
	}
}

// TestChaos57_ContractRowNeverCarriesAHostname: /api/diagnostics is a
// viewer-role surface with a standing no-sensitive-values guardrail, and the
// hostnames flowing through this path are the customer's destinations.
func TestChaos57_ContractRowNeverCarriesAHostname(t *testing.T) {
	resetDNSResolveHealthForTest()
	defer resetDNSResolveHealthForTest()

	driveResolverDegraded()
	row := checkDNSResolution()
	for _, bad := range []string{"invalid", "example.com", "http"} {
		if strings.Contains(row.Message, bad) {
			t.Fatalf("contract row message leaks a destination (%q): %q", bad, row.Message)
		}
	}
}

// ─── CONTROLS ────────────────────────────────────────────────────────────────

// C1: the mechanism must still RESOLVE. A resolver that always shed, or always
// served stale, or never refreshed would pass every defect gate above while
// being far worse than the defect.
func TestChaos57_Control_HealthyResolutionStillWorks(t *testing.T) {
	calls, restore := stubResolver([]string{"192.0.2.1", "203.0.113.77"}, nil)
	defer restore()

	got := resolveHost("healthy.chaos57.invalid")
	if got == nil {
		t.Fatal("CONTROL FAILED: a healthy resolver produced no address")
	}
	// 192.0.2.1 is public (TEST-NET-1 is not in the private-range set), so the
	// first public answer wins — the pre-existing first-public-answer contract.
	if !got.Equal(net.ParseIP("192.0.2.1")) {
		t.Fatalf("CONTROL FAILED: resolveHost = %v, want the first public answer 192.0.2.1", got)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("CONTROL FAILED: resolver invoked %d times for one cold host, want 1", n)
	}
	if snap := dnsResolveState(); snap.Failures != 0 || snap.Shed != 0 {
		t.Fatalf("CONTROL FAILED: a healthy resolution was charged to a failure counter: %+v", snap)
	}
}

// C2: a genuinely unresolvable host must still fail, be counted, and be
// negative-cached. A change that "fixed" the outage case by serving something
// for everything would pass D3 and be a security regression.
func TestChaos57_Control_UnresolvableHostStillFailsAndIsCounted(t *testing.T) {
	calls, restore := stubResolver(nil, &net.DNSError{Err: "no such host", IsNotFound: true})
	defer restore()

	if ip := resolveHost("nxdomain.chaos57.invalid"); ip != nil {
		t.Fatalf("CONTROL FAILED: an NXDOMAIN host resolved to %v", ip)
	}
	if ip := resolveHost("nxdomain.chaos57.invalid"); ip != nil {
		t.Fatalf("CONTROL FAILED: second call resolved to %v", ip)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("CONTROL FAILED: resolver invoked %d times, want 1 — failures must still be negative-cached", n)
	}
	if snap := dnsResolveState(); snap.Failures != 1 || snap.LastReason != "nxdomain" {
		t.Fatalf("CONTROL FAILED: failure not counted/classified: %+v", snap)
	}
}

// TestChaos57_StaleServeIsCounted: the stale-served counter is the leading
// indicator that resolution has stopped completing — it moves before the
// degradation threshold does, which is the whole point of exporting it.
func TestChaos57_StaleServeIsCounted(t *testing.T) {
	calls, restore := stubResolver([]string{"203.0.113.88"}, nil)
	defer restore()

	if resolveHost("stale-counted.chaos57.invalid") == nil {
		t.Fatal("warm-up failed")
	}
	waitForResolverCalls(t, calls, 1)
	expireEntry("stale-counted.chaos57.invalid", time.Second)
	_ = resolveHost("stale-counted.chaos57.invalid")

	if snap := dnsResolveState(); snap.StaleServed == 0 {
		t.Fatalf("a stale serve was not counted: %+v", snap)
	}
}
