package secscan

// Chaos gates for the body-scan pipeline under scanner slowness and
// saturation — the regime a real gateway reaches long before a scanner is
// actually "down": a signature reload, a burst of large downloads, memory
// pressure on the ClamAV host.
//
// Four coupled defects, all in and around ScanBody:
//
//  1. ClamAV's queue wait had its own 5 s deadline, which always fired before
//     the orchestrator's 10 s one and returned an ordinary error — classified
//     as an engine fault and handled fail-OPEN. Five concurrent scans on a
//     HEALTHY daemon admitted content unscanned, while the outer deadline that
//     is supposed to decide this fails CLOSED. (Gated in internal/clamav.)
//  2. The timeout path abandoned its scan goroutine but nothing stopped the
//     work: it held a ClamAV slot and the body buffer until the client's own
//     30 s timeout, so abandoned scans crowded out live ones and kept the
//     system in the failing regime.
//  3. The fail-closed refusal was cached under the CONTENT TTL (1 h), so
//     seconds of slowness blocked that object node-wide for an hour after
//     recovery — the neighbouring ClamAV-error branch already refuses to cache
//     for exactly this reason.
//  4. The abandoned goroutine still wrote to the cache when it eventually
//     finished, overwriting the fail-closed refusal with "clean" — so whether
//     an object was blocked or served came down to a race.

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/clamav"
	"github.com/KidCarmi/Culvert/internal/hashcache"
)

// withScanBudget shortens the scan deadline for the duration of a test so the
// timeout paths can be exercised without waiting out the production 10 s.
func withScanBudget(t *testing.T, d time.Duration) {
	t.Helper()
	scanBodyTimeoutOverride.Store(int64(d))
	t.Cleanup(func() { scanBodyTimeoutOverride.Store(0) })
}

func withCooldown(t *testing.T, d time.Duration) {
	t.Helper()
	prev := scanTimeoutCooldown
	scanTimeoutCooldown = d
	t.Cleanup(func() { scanTimeoutCooldown = prev })
}

// gatedClam is a ClamAV stand-in whose scan blocks until released, modelling a
// daemon that accepts work and takes longer than the scan budget to answer.
// Counters are atomic: an abandoned scan runs concurrently with the assertions.
type gatedClam struct {
	release  chan struct{}
	calls    atomic.Int64
	finished atomic.Int64

	mu    sync.Mutex
	name  string
	found bool
	err   error
}

func newGatedClam() *gatedClam { return &gatedClam{release: make(chan struct{})} }

func (g *gatedClam) Ping() error { return nil }

func (g *gatedClam) verdict() (string, bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.name, g.found, g.err
}

func (g *gatedClam) setVerdict(name string, found bool, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.name, g.found, g.err = name, found, err
}

func (g *gatedClam) Scan([]byte) (string, bool, error) {
	g.calls.Add(1)
	defer g.finished.Add(1)
	<-g.release
	return g.verdict()
}

// waitScanDrained waits for every started scan to return, so assertions about
// what the late goroutine did are made after it has actually run. Counting
// rather than a WaitGroup: the scans are started by ScanBody, so there is no
// point at which the test could Add before Wait.
func (g *gatedClam) waitScanDrained(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if g.finished.Load() >= g.calls.Load() && g.calls.Load() > 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("abandoned scan never unwound (started %d, finished %d)", g.calls.Load(), g.finished.Load())
}

func newSlowScanner(t *testing.T, clam ClamScanner, cacheTTL time.Duration) *Scanner {
	t.Helper()
	ss := New(Deps{Clam: clam, Yara: &fakeYARA{}, Excl: fakeExcl{}, Feed: fakeFeed{}})
	ss.Init("", 0, hashcache.New(64, cacheTTL))
	return ss
}

// TestChaos_TimeoutRefusalDoesNotOutliveTheFault proves the fail-closed
// scan-timeout verdict is remembered as a short COOLDOWN, not as a content
// verdict with the content TTL.
//
// Pre-fix the entry was written with the cache's own TTL — an hour by default —
// so a scanner that was slow for a few seconds kept refusing that exact object,
// for every user of the node, long after it recovered; the only recovery was an
// admin cache flush.
func TestChaos_TimeoutRefusalDoesNotOutliveTheFault(t *testing.T) {
	withScanBudget(t, 60*time.Millisecond)
	withCooldown(t, 120*time.Millisecond)

	clam := newGatedClam()
	// The content cache TTL is long — that is the point: the refusal must not
	// inherit it.
	ss := newSlowScanner(t, clam, time.Hour)
	data := []byte("a popular installer that happened to be scanned during a stall")

	res := ss.ScanBody(data)
	if res == nil || !res.Blocked || res.Source != "timeout" {
		t.Fatalf("a scan that exceeds its budget must fail closed, got %+v", res)
	}

	// The scanner recovers.
	close(clam.release)
	clam.waitScanDrained(t)

	// Inside the cooldown the refusal is still served — a burst of requests for
	// one hot object must not each start a doomed scan.
	if got := ss.ScanBody(data); got == nil || !got.Blocked {
		t.Fatalf("refusal must hold during the cooldown, got %+v", got)
	}

	time.Sleep(180 * time.Millisecond)

	// Past the cooldown the object is rescanned by the now-healthy engine.
	callsBefore := clam.calls.Load()
	if got := ss.ScanBody(data); got != nil {
		t.Fatalf("after the cooldown a healthy scanner must be consulted again, still blocked: %+v", got)
	}
	if clam.calls.Load() <= callsBefore {
		t.Fatal("the recovered engine was never consulted — the refusal outlived the fault")
	}
}

// TestChaos_AbandonedScanCannotOverturnTheFailClosedVerdict proves a scan whose
// caller already returned the fail-closed refusal cannot publish a CLEAN
// verdict when it eventually finishes.
//
// Pre-fix it could, and did: the refusal the user saw was silently replaced by
// a cached admission for the rest of the TTL, with no counter and no log —
// whether an object was blocked or served was decided by a race between the
// deadline and the scanner.
func TestChaos_AbandonedScanCannotOverturnTheFailClosedVerdict(t *testing.T) {
	withScanBudget(t, 60*time.Millisecond)
	withCooldown(t, 10*time.Second)

	clam := newGatedClam()
	ss := newSlowScanner(t, clam, time.Hour)
	data := []byte("content whose scan finishes after we stopped waiting")
	hash := hashcache.SHA256Hex(data)
	before := atomic.LoadInt64(&statScanLateDiscarded)

	res := ss.ScanBody(data)
	if res == nil || !res.Blocked {
		t.Fatalf("expected the fail-closed refusal, got %+v", res)
	}

	// The abandoned scan now completes, cleanly.
	close(clam.release)
	clam.waitScanDrained(t)
	// The late verdict is published (or discarded) by the abandoned goroutine
	// after Scan returns; give it a moment to attempt it.
	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt64(&statScanLateDiscarded) == before && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	cached, ok := ss.cache.Get(hash)
	if !ok {
		t.Fatal("the fail-closed refusal disappeared from the cache")
	}
	if cached.Clean {
		t.Fatalf("an abandoned scan overturned the fail-closed verdict: %+v", cached)
	}
	if atomic.LoadInt64(&statScanLateDiscarded) <= before {
		t.Fatal("a discarded late verdict must be counted — silent discard is its own blind spot")
	}
}

// TestChaos_AbandonedScanMayStillTighten proves the tighten-only rule is a rule
// about DIRECTION, not a blanket discard: a late scan that finds a threat still
// publishes it, upgrading the placeholder refusal to the real name.
func TestChaos_AbandonedScanMayStillTighten(t *testing.T) {
	withScanBudget(t, 60*time.Millisecond)
	withCooldown(t, 10*time.Second)

	clam := newGatedClam()
	clam.setVerdict("EICAR-Test-Signature", true, nil)
	ss := newSlowScanner(t, clam, time.Hour)
	data := []byte("malware whose scan ran long")
	hash := hashcache.SHA256Hex(data)

	if res := ss.ScanBody(data); res == nil || !res.Blocked {
		t.Fatalf("expected the fail-closed refusal, got %+v", res)
	}
	close(clam.release)
	clam.waitScanDrained(t)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cached, ok := ss.cache.Get(hash); ok && cached.Source == "clamav" {
			if cached.Clean || cached.Reason != "EICAR-Test-Signature" {
				t.Fatalf("late block published incorrectly: %+v", cached)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("a late BLOCKING verdict must still be published — it can only tighten")
}

// TestChaos_InnerScanNeverLaundersAnOverrunIntoClean pins the both-sides
// enforcement. ScanBody's select can see a finished scan and an expired
// deadline as simultaneously ready and pick either, so the inner path must
// return the same refusal rather than leaving the outcome to a coin flip.
func TestChaos_InnerScanNeverLaundersAnOverrunIntoClean(t *testing.T) {
	ss := newSlowScanner(t, &fakeClam{}, time.Hour)
	data := []byte("clean content, scanned past the budget")
	hash := hashcache.SHA256Hex(data)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // budget already gone when the scan reports

	res := ss.scanBodyInner(ctx, data, hash, nil)
	if res == nil || !res.Blocked || res.Source != "timeout" {
		t.Fatalf("a scan completing outside its budget must fail closed, got %+v", res)
	}
	if _, ok := ss.cache.Get(hash); ok {
		t.Fatal("an out-of-budget scan must not cache a verdict")
	}
}

// TestChaos_AbandonedScansAreCountedAndUnwind proves abandoned work is visible
// while it runs and returns to zero afterwards. The gauge is the operator's
// only leading indicator of the timeout-and-abandon regime: pre-fix, abandoned
// scans were invisible in every surface while they held the scarce resource.
func TestChaos_AbandonedScansAreCountedAndUnwind(t *testing.T) {
	withScanBudget(t, 50*time.Millisecond)
	withCooldown(t, 10*time.Second)

	if got := ScanInflight(); got != 0 {
		t.Fatalf("precondition: inflight = %d, want 0", got)
	}
	clam := newGatedClam()
	ss := newSlowScanner(t, clam, time.Hour)

	const n = 8
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Distinct content per caller so nothing is served from cache.
			if res := ss.ScanBody([]byte(strings.Repeat("x", i+1))); res == nil || !res.Blocked {
				t.Errorf("scan %d: expected fail-closed refusal, got %+v", i, res)
			}
		}(i)
	}
	wg.Wait()

	if got := ScanInflight(); got == 0 {
		t.Fatal("abandoned scans must be visible while they are still holding resources")
	}

	close(clam.release)
	clam.waitScanDrained(t)

	deadline := time.Now().Add(5 * time.Second)
	for ScanInflight() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := ScanInflight(); got != 0 {
		t.Fatalf("inflight did not return to zero after the scans unwound: %d", got)
	}
}

// saturatedClam reports the capacity sentinel without any context involvement,
// modelling a HEALTHY daemon at its concurrency limit.
type saturatedClam struct{ calls atomic.Int64 }

func (s *saturatedClam) Ping() error { return nil }
func (s *saturatedClam) Scan([]byte) (string, bool, error) {
	s.calls.Add(1)
	return "", false, clamav.ErrQueueFull
}

// TestChaos_ClamSaturationIsNotReportedAsAnEngineFault proves capacity
// exhaustion is counted on its own and does not fire the daemon-fault alert.
//
// The two need different operator responses — add capacity vs. fix the daemon —
// and conflating them meant one busy period produced a stream of alerts blaming
// a daemon that was working perfectly.
func TestChaos_ClamSaturationIsNotReportedAsAnEngineFault(t *testing.T) {
	rec := withAlertRecorder(t)
	clam := &saturatedClam{}
	ss := newSlowScanner(t, clam, time.Hour)

	satBefore := atomic.LoadInt64(&statClamSaturated)
	errBefore := atomic.LoadInt64(&statClamScanError)

	ss.ScanBody([]byte("content scanned while the daemon is at capacity"))

	if got := atomic.LoadInt64(&statClamSaturated) - satBefore; got != 1 {
		t.Fatalf("ClamSaturated delta = %d, want 1", got)
	}
	if got := atomic.LoadInt64(&statClamScanError) - errBefore; got != 0 {
		t.Fatalf("saturation must not be charged to the engine-error counter (delta %d)", got)
	}
	// Give any (incorrect) alert goroutine a chance to land before asserting.
	time.Sleep(50 * time.Millisecond)
	for _, ev := range rec.matching(clamav.ErrQueueFull.Error()) {
		if ev.event == "scan_clam_error" {
			t.Fatal("capacity exhaustion must not raise a daemon-fault alert")
		}
	}
}

// TestChaos_SaturationCounterIsExactWhileTheLogIsGated pins the
// count-everything / gate-the-noise split. The log line is rate-limited because
// every condition in this file recurs per request for as long as the fault
// lasts — logging each one would degrade the node hardest exactly when it is
// already saturated — but the COUNTER must carry the full magnitude, or the
// operator cannot tell a blip from a sustained outage.
func TestChaos_SaturationCounterIsExactWhileTheLogIsGated(t *testing.T) {
	withAlertRecorder(t)
	clam := &saturatedClam{}
	ss := newSlowScanner(t, clam, time.Hour)

	before := atomic.LoadInt64(&statClamSaturated)
	const n = 25
	for i := 0; i < n; i++ {
		ss.ScanBody([]byte(strings.Repeat("y", i+1)))
	}
	if got := atomic.LoadInt64(&statClamSaturated) - before; got != n {
		t.Fatalf("ClamSaturated delta = %d, want %d — the log gate must not suppress the counter", got, n)
	}
	if got := clam.calls.Load(); got != n {
		t.Fatalf("engine consulted %d times, want %d", got, n)
	}
}
