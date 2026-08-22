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
	"errors"
	"fmt"
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

func (g *gatedClam) verdict() (name string, found bool, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.name, g.found, g.err
}

func (g *gatedClam) setVerdict(name string, found bool, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.name, g.found, g.err = name, found, err
}

func (g *gatedClam) Scan([]byte) (name string, found bool, err error) {
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
func (s *saturatedClam) Scan([]byte) (name string, found bool, err error) {
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

// ── Review follow-up: two defects in the fix itself (PR #1192, Codex review) ──

// TestChaos_TimeoutFromTheWorkerIsAccountedLikeTheDeadlineArm pins that a
// timeout-sourced result arriving on the WORKER channel goes through the same
// accounting as the deadline arm of the select.
//
// With a budget-aware ClamAV client the connection deadline and ctx.Done()
// become ready at the same instant, so which arm wins is a coin flip. Routing
// only one of them through the accounting made statScanTimeout undercount
// nondeterministically and — the part that actually bites — skipped the
// cooldown write, so the next request for the same hot object immediately
// launched another doomed scan. The cooldown was unreliable in exactly the
// regime it exists for.
func TestChaos_TimeoutFromTheWorkerIsAccountedLikeTheDeadlineArm(t *testing.T) {
	withScanBudget(t, 10*time.Second)
	withCooldown(t, 10*time.Second)

	ss := newSlowScanner(t, &fakeClam{}, time.Hour)
	data := []byte("content whose worker reported the overrun itself")
	hash := hashcache.SHA256Hex(data)
	before := atomic.LoadInt64(&statScanTimeout)

	// Exactly what scanBodyInner delivers when it finds the budget gone.
	res := ss.completeScan(&Result{Blocked: true, Reason: "scan timeout", Source: "timeout", Hash: hash}, hash)

	if res == nil || !res.Blocked || res.Source != "timeout" {
		t.Fatalf("a worker-reported timeout must stay a fail-closed refusal, got %+v", res)
	}
	if got := atomic.LoadInt64(&statScanTimeout) - before; got != 1 {
		t.Fatalf("ScanTimeout delta = %d, want 1 — the worker arm skipped the counter", got)
	}
	cached, ok := ss.cache.Get(hash)
	if !ok || cached.Clean || cached.Source != "timeout" {
		t.Fatalf("the worker arm must write the cooldown too, got %+v (present=%v)", cached, ok)
	}
}

// TestChaos_WorkerVerdictsStillPassThroughUnchanged is the other half: only a
// timeout-sourced result is re-accounted. A real verdict must reach the caller
// untouched and must not be charged to the timeout counter.
func TestChaos_WorkerVerdictsStillPassThroughUnchanged(t *testing.T) {
	ss := newSlowScanner(t, &fakeClam{}, time.Hour)
	before := atomic.LoadInt64(&statScanTimeout)

	block := &Result{Blocked: true, Reason: "EICAR-Test", Source: "clamav", Hash: "h"}
	if got := ss.completeScan(block, "h"); got != block {
		t.Fatalf("a real block must pass through unchanged, got %+v", got)
	}
	if got := ss.completeScan(nil, "h"); got != nil {
		t.Fatalf("a clean verdict must pass through unchanged, got %+v", got)
	}
	if got := atomic.LoadInt64(&statScanTimeout) - before; got != 0 {
		t.Fatalf("real verdicts must not be charged to the timeout counter (delta %d)", got)
	}
}

// TestChaos_TimeoutCooldownNeverDowngradesAConfirmedBlock pins the direction
// rule on the cooldown write.
//
// A late block — from this scan's own abandoned goroutine, or from a concurrent
// scan of the same hash — can land between the deadline firing and the cooldown
// write. Overwriting it replaces a NAMED, full-TTL threat entry with a generic
// one that lapses in 30 s, after which the object depends on the next scan
// succeeding, and the engine-error path is fail-OPEN. Tighten-only applies here
// for the same reason it applies to publishVerdict.
func TestChaos_TimeoutCooldownNeverDowngradesAConfirmedBlock(t *testing.T) {
	withCooldown(t, 30*time.Second)
	ss := newSlowScanner(t, &fakeClam{}, time.Hour)
	hash := hashcache.SHA256Hex([]byte("known malware"))

	// A confirmed threat verdict is already cached.
	ss.cache.Set(hash, hashcache.ScanCacheResult{Clean: false, Reason: "EICAR-Test-Signature", Source: "clamav"})

	ss.cacheTimeoutCooldown(hash)

	cached, ok := ss.cache.Get(hash)
	if !ok {
		t.Fatal("the confirmed verdict disappeared")
	}
	if cached.Source != "clamav" || cached.Reason != "EICAR-Test-Signature" {
		t.Fatalf("a generic timeout entry downgraded a confirmed block: %+v", cached)
	}
}

// TestChaos_TimeoutCooldownStillReplacesWeakerEntries keeps the direction rule
// from becoming a blanket refusal to write: an absent entry, a clean one, and
// an earlier timeout entry must all be (re)written, or the cooldown would never
// refresh and the stampede guard would decay.
func TestChaos_TimeoutCooldownStillReplacesWeakerEntries(t *testing.T) {
	withCooldown(t, 30*time.Second)
	ss := newSlowScanner(t, &fakeClam{}, time.Hour)

	for _, tc := range []struct {
		name string
		seed *hashcache.ScanCacheResult
	}{
		{"absent", nil},
		{"clean", &hashcache.ScanCacheResult{Clean: true, Source: "clean"}},
		{"earlier timeout", &hashcache.ScanCacheResult{Clean: false, Reason: "scan timeout", Source: "timeout"}},
	} {
		hash := hashcache.SHA256Hex([]byte(tc.name))
		if tc.seed != nil {
			ss.cache.Set(hash, *tc.seed)
		}
		ss.cacheTimeoutCooldown(hash)
		cached, ok := ss.cache.Get(hash)
		if !ok || cached.Clean || cached.Source != "timeout" {
			t.Fatalf("%s: cooldown must be written, got %+v (present=%v)", tc.name, cached, ok)
		}
	}
}

// TestChaos_TimeoutAccountingIsExactWhicheverArmWins is the end-to-end
// invariant: N scans that all exceed the budget must produce exactly N timeout
// counts, regardless of which select arm happens to win each time.
// ctxGatedClam blocks until the scan budget is gone and then reports the
// context error — the production shape with a budget-aware client, where the
// worker's completion and the deadline become ready at the same instant.
type ctxGatedClam struct{ calls atomic.Int64 }

func (c *ctxGatedClam) Ping() error { return nil }
func (c *ctxGatedClam) Scan([]byte) (name string, found bool, err error) {
	return "", false, errors.New("clamav: no context")
}
func (c *ctxGatedClam) ScanContext(ctx context.Context, _ []byte) (name string, found bool, err error) {
	c.calls.Add(1)
	<-ctx.Done()
	return "", false, fmt.Errorf("clamav: scan aborted: %w", ctx.Err())
}

// TestChaos_TimeoutAccountingIsExactWhicheverArmWins is the end-to-end
// invariant: N scans that all exceed the budget must produce exactly N timeout
// counts and N cooldown entries, regardless of which select arm happens to win
// each time. The worker here finishes at the very instant the deadline fires,
// so over N iterations both arms win some of the time — which is the whole
// point, and was the source of the nondeterministic undercount.
func TestChaos_TimeoutAccountingIsExactWhicheverArmWins(t *testing.T) {
	withScanBudget(t, 30*time.Millisecond)
	withCooldown(t, 10*time.Second)

	clam := &ctxGatedClam{}
	ss := newSlowScanner(t, clam, time.Hour)

	before := atomic.LoadInt64(&statScanTimeout)
	const n = 12
	for i := 0; i < n; i++ {
		data := []byte(strings.Repeat("z", i+1))
		res := ss.ScanBody(data)
		if res == nil || !res.Blocked || res.Source != "timeout" {
			t.Fatalf("scan %d: expected the fail-closed refusal, got %+v", i, res)
		}
		// Every refused scan must also leave the stampede guard behind, or a
		// burst on one hot object keeps launching doomed scans.
		cached, ok := ss.cache.Get(hashcache.SHA256Hex(data))
		if !ok || cached.Clean || cached.Source != "timeout" {
			t.Fatalf("scan %d: cooldown missing, got %+v (present=%v)", i, cached, ok)
		}
	}
	if got := atomic.LoadInt64(&statScanTimeout) - before; got != n {
		t.Fatalf("ScanTimeout delta = %d, want %d — accounting depends on which arm won", got, n)
	}
	if got := clam.calls.Load(); got != n {
		t.Fatalf("engine consulted %d times, want %d", got, n)
	}
}
