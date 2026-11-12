package secscan

// clam_status_probe_chaos116_test.go — CHAOS-116: the ClamAV status ping was an
// unauthenticated, uncapped, uncancellable dial on the caller's own goroutine.
//
// WHY THESE GATES EXIST. Scanner.ClamAVStatus is read by /health and /ready,
// which routeProxyListenerBuiltin dispatches on the PROXY listener ahead of
// handleRequest — so ahead of the IP filter, the rate limiter and the connection
// limiter. On a cache miss it called clam.Ping() inline: a dial with
// context.Background() under a budget of ~2x the 30 s scan timeout, with no
// single-flight and no concurrency cap. Three consequences, and the third is the
// security one:
//
//  1. the documented liveness endpoint could take a minute to answer, so an
//     orchestrator with a 1 s probe timeout restarts a HEALTHY gateway;
//  2. one goroutine and one socket were parked per request, and a client's
//     disconnect could not end them;
//  3. clamav.clamSem bounds concurrent SCANS "to prevent overwhelming the
//     daemon" and Ping takes no slot, so this was the one path that could open
//     unbounded connections to the daemon that semaphore protects. A daemon
//     whose connection queue is full fails real scans, which this package
//     classifies as an engine fault and forwards UNSCANNED (statClamScanError,
//     fail-open). An unauthenticated request flood could therefore suppress
//     malware scanning node-wide.
//
// The gates below hold the fix's four properties — one dial per flight, no
// caller waiting on the daemon, an honest answer when the probe is slower than
// the caller, and a probe budget of its own — plus the negative control that an
// ordinary daemon's behaviour is unchanged.

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/hashcache"
)

// gatedPingClam is a daemon that accepts the probe and does not answer until
// released — the blackholed/saturated shape, not the connection-refused one,
// which returns instantly and was never the problem.
type gatedPingClam struct {
	dials    atomic.Int64
	release  chan struct{}
	deadline atomic.Int64 // UnixNano of the ctx deadline the probe passed, 0 if none
	honorCtx bool         // true: end the ping when the ctx does (the shipped client's behaviour)
}

func newGatedPingClam() *gatedPingClam {
	return &gatedPingClam{release: make(chan struct{})}
}

func (g *gatedPingClam) Ping() error { return g.PingContext(context.Background()) }

func (g *gatedPingClam) PingContext(ctx context.Context) error {
	g.dials.Add(1)
	if d, ok := ctx.Deadline(); ok {
		g.deadline.Store(d.UnixNano())
	}
	if g.honorCtx {
		select {
		case <-g.release:
		case <-ctx.Done():
			return ctx.Err()
		}
		return nil
	}
	<-g.release
	return nil
}

func (g *gatedPingClam) Scan([]byte) (name string, found bool, err error) { return "", false, nil }

// fastPingClam answers at once, like any healthy daemon.
type fastPingClam struct {
	dials atomic.Int64
	err   error
}

func (f *fastPingClam) Ping() error { return f.PingContext(context.Background()) }
func (f *fastPingClam) PingContext(context.Context) error {
	f.dials.Add(1)
	return f.err
}
func (f *fastPingClam) Scan([]byte) (name string, found bool, err error) { return "", false, nil }

// panickingPingClam is the CHAOS-24 case: the probe is a DETACHED goroutine now,
// so an unrecovered panic in it would terminate an in-line security gateway.
type panickingPingClam struct{ dials atomic.Int64 }

func (p *panickingPingClam) Ping() error { return p.PingContext(context.Background()) }
func (p *panickingPingClam) PingContext(context.Context) error {
	p.dials.Add(1)
	panic("status probe exploded")
}
func (p *panickingPingClam) Scan([]byte) (name string, found bool, err error) { return "", false, nil }

func newStatusScanner(t *testing.T, clam ClamScanner) *Scanner {
	t.Helper()
	return New(Deps{Clam: clam, Cache: hashcache.New(16, time.Minute)})
}

// expireClamStatus ages out the cached observation without touching its VALUE,
// which is what a TTL expiry does and what stale-while-revalidate needs.
func expireClamStatus(ss *Scanner) {
	ss.mu.Lock()
	ss.clamStatusExpiry = time.Now().Add(-time.Second)
	ss.mu.Unlock()
}

// ── 1. The defect: one dial, however many readers ───────────────────────────

func TestChaos116_OneDialServesEveryConcurrentStatusReader(t *testing.T) {
	clam := newGatedPingClam()
	ss := newStatusScanner(t, clam)

	const readers = 64
	beforeCoalesced := atomic.LoadInt64(&statClamStatusCoalesced)

	var wg sync.WaitGroup
	done := make(chan struct{})
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = ss.ClamAVStatus()
		}()
	}
	go func() { wg.Wait(); close(done) }()

	select {
	case <-done:
	case <-time.After(10 * clamStatusWait):
		close(clam.release)
		t.Fatalf("%d status readers did not all return while the daemon was silent: before the fix each one dialed and waited on its own ping", readers)
	}
	close(clam.release)

	if got := clam.dials.Load(); got != 1 {
		t.Fatalf("dials = %d, want 1: %d concurrent readers must share ONE probe, not open %d connections to the daemon clamSem exists to protect", got, readers, readers)
	}
	// The coalesced counter is what an operator sees instead of that storm.
	if got := atomic.LoadInt64(&statClamStatusCoalesced) - beforeCoalesced; got < readers-1 {
		t.Errorf("coalesced delta = %d, want >= %d: the readers that dialed nothing must be counted", got, readers-1)
	}
}

// ── 2. No caller waits on the daemon's network path ─────────────────────────

func TestChaos116_NoCallerWaitsOnTheDaemonsNetworkPath(t *testing.T) {
	clam := newGatedPingClam()
	ss := newStatusScanner(t, clam)
	t.Cleanup(func() { close(clam.release) })

	start := time.Now()
	got := ss.ClamAVStatus()
	elapsed := time.Since(start)

	// The caller's bound is clamStatusWait, NOT the probe budget and certainly
	// not the client's 30 s scan timeout. Generous slack: this asserts the
	// ORDER OF MAGNITUDE (sub-second vs. tens of seconds), which is the
	// property, and stays quiet on a loaded CI host.
	if elapsed > clamStatusWait+2*time.Second {
		t.Fatalf("ClamAVStatus took %s with a silent daemon, want <= %s: a request must not wait on the AV daemon's network path", elapsed, clamStatusWait+2*time.Second)
	}
	if got == "connected" || got == "disabled" {
		t.Fatalf("status = %q while the daemon has never answered: an unobserved daemon must not read as healthy", got)
	}
}

// ── 3. Stale-while-revalidate, so a healthy row cannot flap ─────────────────

func TestChaos116_StaleObservationIsServedWhileRevalidating(t *testing.T) {
	fast := &fastPingClam{}
	ss := newStatusScanner(t, fast)
	if got := ss.ClamAVStatus(); got != "connected" {
		t.Fatalf("first status = %q, want connected", got)
	}

	// The daemon goes silent and the TTL expires. A row that reported "fail"
	// here would flap on every TTL expiry of a merely slow daemon, which is
	// noise rather than signal — the previous observation is at most one probe
	// behind and every surface re-reads it.
	gated := newGatedPingClam()
	ss.mu.Lock()
	ss.clam = gated
	ss.mu.Unlock()
	expireClamStatus(ss)
	t.Cleanup(func() { close(gated.release) })

	beforeStale := atomic.LoadInt64(&statClamStatusStale)
	if got := ss.ClamAVStatus(); got != "connected" {
		t.Fatalf("status = %q while revalidating, want the previous %q", got, "connected")
	}
	if got := atomic.LoadInt64(&statClamStatusStale) - beforeStale; got != 1 {
		t.Errorf("stale delta = %d, want 1: serving a previous observation must be counted, or an operator cannot tell it from a fresh one", got)
	}
}

func TestChaos116_AFreshObservationReplacesTheStaleOne(t *testing.T) {
	gated := newGatedPingClam()
	ss := newStatusScanner(t, gated)
	ss.mu.Lock()
	ss.clamStatusVal, ss.clamStatusExpiry = "connected", time.Now().Add(-time.Second)
	ss.mu.Unlock()

	if got := ss.ClamAVStatus(); got != "connected" {
		t.Fatalf("status = %q while revalidating, want the stale %q", got, "connected")
	}
	close(gated.release) // the probe lands

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, v, fresh := ss.clamStatusSnapshot(); fresh && v == "connected" {
			return // the probe stored its own observation and it is fresh again
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("the probe's observation never became the fresh cached value")
}

// ── 4. Nothing claims health before the first observation ───────────────────

func TestChaos116_NothingClaimsHealthBeforeTheFirstObservation(t *testing.T) {
	clam := newGatedPingClam()
	ss := newStatusScanner(t, clam)
	t.Cleanup(func() { close(clam.release) })

	got := ss.ClamAVStatus()
	if got != clamStatusUnknown {
		t.Fatalf("status = %q, want %q", got, clamStatusUnknown)
	}
	// The property that matters is not the string: it is that every consumer
	// treats it as NOT healthy. computeReadiness switches on exactly these two
	// values and takes its failing default branch for anything else, and
	// coarseClamAVStatus collapses anything else to "unreachable".
	if got == "connected" || got == "disabled" {
		t.Fatalf("status %q would pass readiness while the daemon has never been observed", got)
	}
}

// ── 5. The probe is independent of the caller that started it ───────────────

func TestChaos116_TheProbeOutlivesTheCallerThatStartedIt(t *testing.T) {
	clam := newGatedPingClam()
	ss := newStatusScanner(t, clam)

	// A caller that gives up must not cancel the probe: if it did, an
	// unauthenticated client could keep the status permanently unobserved by
	// disconnecting, which is the fail-open state this fix exists to close.
	_ = ss.ClamAVStatus() // returns on its own bound, probe still in flight
	close(clam.release)   // the daemon answers AFTER its starter walked away

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, v, _ := ss.clamStatusSnapshot(); v == "connected" {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("the probe's observation never landed: a caller's bound must not cancel the shared probe")
}

// ── 6. The probe carries its own budget ─────────────────────────────────────

func TestChaos116_ProbeCarriesItsOwnBudgetNotTheScanTimeout(t *testing.T) {
	clam := newGatedPingClam()
	clam.honorCtx = true
	ss := newStatusScanner(t, clam)
	t.Cleanup(func() { close(clam.release) })

	_ = ss.ClamAVStatus()

	deadline := time.Now().Add(5 * time.Second)
	var ns int64
	for time.Now().Before(deadline) {
		if ns = clam.deadline.Load(); ns != 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if ns == 0 {
		t.Fatal("the probe passed no deadline: an unbounded status dial is the defect")
	}
	budget := time.Until(time.Unix(0, ns))
	if budget <= 0 || budget > clamStatusProbeBudget {
		t.Fatalf("probe budget = %s, want (0, %s]", budget, clamStatusProbeBudget)
	}
	// The whole point of a separate constant: the status question must not
	// inherit the scan path's patience.
	if clamStatusProbeBudget >= ScanBodyTimeout {
		t.Fatalf("clamStatusProbeBudget (%s) must stay below ScanBodyTimeout (%s): a liveness probe answers sooner than a scan", clamStatusProbeBudget, ScanBodyTimeout)
	}
	if clamStatusWait >= clamStatusProbeBudget {
		t.Fatalf("clamStatusWait (%s) must stay below clamStatusProbeBudget (%s), or the caller's bound is the probe's bound and the dial rate follows the request rate again", clamStatusWait, clamStatusProbeBudget)
	}
}

// ── 7. Negative control: an ordinary daemon is unaffected ───────────────────

func TestChaos116_OrdinaryDaemonIsUnaffected(t *testing.T) {
	fast := &fastPingClam{}
	ss := newStatusScanner(t, fast)
	beforeStale := atomic.LoadInt64(&statClamStatusStale)

	if got := ss.ClamAVStatus(); got != "connected" {
		t.Fatalf("status = %q, want connected", got)
	}
	// Inside the TTL this is a pure memory read, exactly as before the fix.
	for i := 0; i < 20; i++ {
		if got := ss.ClamAVStatus(); got != "connected" {
			t.Fatalf("cached read %d = %q, want connected", i, got)
		}
	}
	if got := fast.dials.Load(); got != 1 {
		t.Fatalf("dials = %d, want 1: the TTL cache must still absorb repeat reads", got)
	}
	if got := atomic.LoadInt64(&statClamStatusStale) - beforeStale; got != 0 {
		t.Errorf("stale delta = %d, want 0: a healthy daemon must never be reported from a stale observation", got)
	}

	// A daemon that is genuinely down still reports the cause, unchanged, to
	// the role-gated surface that renders it.
	down := &fastPingClam{err: errors.New("connect failed: dial tcp 10.0.0.5:3310: connection refused")}
	ss2 := newStatusScanner(t, down)
	got := ss2.ClamAVStatus()
	if got == "connected" || got == clamStatusUnknown {
		t.Fatalf("status = %q, want the unreachable cause", got)
	}
	if !contains(got, "unreachable:") || !contains(got, "connection refused") {
		t.Fatalf("status = %q, want it to carry the dial cause for the operator surface", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// ── 8. The detached probe is panic-contained ────────────────────────────────

func TestChaos116_PanickingProbeIsContainedAndTheFlightIsReleased(t *testing.T) {
	clam := &panickingPingClam{}
	ss := newStatusScanner(t, clam)

	// Go terminates the process on an unrecovered panic in ANY goroutine, and
	// this one is started from an HTTP handler's goroutine. If the guard were
	// missing, this test would not fail — the test BINARY would die.
	if got := ss.ClamAVStatus(); got != clamStatusUnknown {
		t.Fatalf("status = %q, want %q after a panicking probe", got, clamStatusUnknown)
	}

	// And the flight must be released, or one panic would wedge the status
	// plane for the life of the process.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		ss.clamProbeMu.Lock()
		inFlight := ss.clamProbeDone != nil
		ss.clamProbeMu.Unlock()
		if !inFlight {
			if got := ss.ClamAVStatus(); got != clamStatusUnknown {
				t.Fatalf("second status = %q, want %q", got, clamStatusUnknown)
			}
			if got := clam.dials.Load(); got < 2 {
				t.Fatalf("dials = %d, want >= 2: a later read must be able to start a new probe", got)
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("the in-flight handle was never cleared after a panicking probe")
}

// ── 9. Init no longer stalls startup on a silent daemon ─────────────────────

func TestChaos116_InitDoesNotBlockOnABlackholedDaemon(t *testing.T) {
	// A daemon that ACCEPTS and never answers. Connection-refused returns
	// instantly and was never the problem; this is the shape that held Init's
	// write lock across a 30 s read deadline, delaying the proxy listener's
	// startup by that long and — per Init's own "after reconfiguration"
	// comment — freezing every in-flight scan for the same 30 s if it is ever
	// called at runtime.
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback listener: %v", err)
	}
	var mu sync.Mutex
	var accepted []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			accepted = append(accepted, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		for _, c := range accepted {
			_ = c.Close()
		}
		mu.Unlock()
	})

	ss := New(Deps{Cache: hashcache.New(16, time.Minute)})
	start := time.Now()
	ss.Init("tcp:"+ln.Addr().String(), 1<<20, nil)
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Fatalf("Init took %s against a silent daemon: startup must not wait on the AV daemon (the pre-fix path waited up to the 30 s scan timeout, holding the scanner's write lock)", elapsed)
	}
	if !ss.Enabled() {
		t.Fatal("Init must still enable the scanner")
	}
}
