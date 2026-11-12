package secscan

// clam_status_probe_reconfigure_test.go — the single-flight status probe
// (CHAOS-116) across a RECONFIGURE.
//
// CHAOS-116 made the ClamAV status ping a single-flight probe on its own
// goroutine, which is what removed the unauthenticated amplification into the
// daemon. Single-flight without a generation is wrong in one place, and it is
// the place where the answer changes meaning: Init.
//
// Init clears the status cache so "the next status read reflects the daemon
// configured now, never the previous one", then warms it with the same
// single-flight probe. A probe already dialing the PREVIOUS daemon is a flight
// in progress, so the warm-up JOINED it — the newly configured address was
// never probed at all — and when the old daemon answered, its observation was
// stored under the new configuration with a full clamStatusTTL and logged with
// the NEW address (runClamStatusProbe reads clamStatusAddr at store time).
//
// The direction that matters is "connected": coarseClamAVStatus passes it
// through to the unauthenticated /health, computeReadiness's `clamav` row takes
// its ok branch, and ClamAV scan failures are classified as engine faults that
// forward content UNSCANNED (statClamScanError, fail-open). A stale
// "connected" therefore keeps a node in rotation while malware scanning on it
// is down. clamStatusGen is the fix; these are its gates.

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/hashcache"
)

// waitCurrentFlight is WaitStatusProbe with a deadline, and the deadline is the
// point. If the generation guard regresses, the flight a reconfiguring Init
// waits on is the one dialing the PREVIOUS daemon, which these tests hold open
// deliberately — so an unbounded wait would hang the package to its timeout
// instead of naming the defect. Bounded, it fails with the reason.
func waitCurrentFlight(t *testing.T, ss *Scanner, what string) {
	t.Helper()
	ss.clamProbeMu.Lock()
	ch := ss.clamProbeDone
	ss.clamProbeMu.Unlock()
	if ch == nil {
		return
	}
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not land within 5s: the flight in progress is the one dialing the daemon that is no longer configured, so the configured daemon was never probed", what)
	}
}

// releaseOnce returns a function that lets a gated daemon answer, idempotent
// and also registered as cleanup — so a test that fails before its own release
// (which is how a regression in the generation guard surfaces) still frees the
// probe goroutine instead of leaking it for the rest of the run.
func releaseOnce(t *testing.T, g *gatedPingClam) func() {
	t.Helper()
	var once sync.Once
	rel := func() { once.Do(func() { close(g.release) }) }
	t.Cleanup(rel)
	return rel
}

// deadClamAddr is a loopback port nothing listens on, so the real
// *clamav.Client Init builds for it answers "connection refused" immediately.
// The point is that it is a DIFFERENT daemon from the one the in-flight probe
// is dialing, and an unreachable one.
const deadClamAddr = "127.0.0.1:1"

// ── 1. The regression: a superseded probe must not publish its observation ──

func TestChaos116_ReconfigureDiscardsThePreviousDaemonsObservation(t *testing.T) {
	old := newGatedPingClam()
	releaseOld := releaseOnce(t, old)
	ss := newStatusScanner(t, old)

	// A probe against the OLD daemon is in flight and has not answered.
	oldFlight := ss.startClamStatusProbe(old)

	// Reconfigure onto a daemon that cannot be reached. Init clears the cache
	// and warms it; its probe answers at once.
	ss.Init(deadClamAddr, 1<<20, hashcache.New(16, time.Minute))
	waitCurrentFlight(t, ss, "the warm-up probe for the reconfigured daemon")

	if got := ss.ClamAVStatus(); got == "connected" || got == clamStatusUnknown {
		t.Fatalf("status after reconfigure = %q, want an observation of %s: the warm-up probe must dial the newly configured daemon, not join the flight already dialing the previous one",
			got, deadClamAddr)
	}

	// Now the old daemon answers "connected". That answer describes a daemon
	// that is no longer configured and must not reach any surface.
	releaseOld()
	<-oldFlight

	if got := ss.ClamAVStatus(); got == "connected" {
		t.Fatalf("status = %q after the superseded probe landed: a healthy answer from the PREVIOUS daemon was published for %s, so /ready reports ok while this node's scans fail OPEN",
			got, deadClamAddr)
	}
	if got := old.dials.Load(); got != 1 {
		t.Errorf("dials against the old daemon = %d, want 1", got)
	}
}

// ── 2. The superseded probe must not be able to erase the current flight ────

func TestChaos116_SupersededProbeDoesNotClearTheCurrentFlight(t *testing.T) {
	old := newGatedPingClam()
	releaseOld := releaseOnce(t, old)
	ss := newStatusScanner(t, old)

	oldFlight := ss.startClamStatusProbe(old)

	// A reconfigure, then a fresh flight for the daemon configured now.
	ss.clamStatusGen.Add(1)
	current := newGatedPingClam()
	releaseCurrent := releaseOnce(t, current)
	curFlight := ss.startClamStatusProbe(current)
	if oldFlight == curFlight {
		t.Fatalf("the reconfigured caller joined the superseded flight instead of starting its own")
	}

	// The superseded probe finishes first. Its cleanup must leave the current
	// flight's handle in place, or the next caller would start a SECOND dial
	// against a daemon already being probed — the amplification CHAOS-116 removed.
	releaseOld()
	<-oldFlight

	beforeCoalesced := atomic.LoadInt64(&statClamStatusCoalesced)
	if ch := ss.startClamStatusProbe(current); ch != curFlight {
		t.Errorf("a caller after the superseded probe's cleanup got a new flight, want the one still in progress")
	}
	if got := atomic.LoadInt64(&statClamStatusCoalesced) - beforeCoalesced; got != 1 {
		t.Errorf("coalesced delta = %d, want 1", got)
	}

	releaseCurrent()
	<-curFlight
	if got := current.dials.Load(); got != 1 {
		t.Errorf("dials against the current daemon = %d, want 1", got)
	}
}

// ── 3. Negative control: no reconfigure, no behaviour change ────────────────
//
// The generation must not split the flight that CHAOS-116 exists to merge. One
// dial for many concurrent readers at a steady configuration is the property
// that keeps the unauthenticated surface off the daemon's connection queue.

func TestChaos116_SameGenerationReadersStillShareOneProbe(t *testing.T) {
	clam := newGatedPingClam()
	releaseClam := releaseOnce(t, clam)
	ss := newStatusScanner(t, clam)

	const readers = 32
	var wg sync.WaitGroup
	for range readers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = ss.ClamAVStatus()
		}()
	}
	wg.Wait()
	releaseClam()
	waitCurrentFlight(t, ss, "the shared probe")

	if got := clam.dials.Load(); got != 1 {
		t.Fatalf("dials = %d, want 1: %d readers at one configuration must share a single probe", got, readers)
	}
}

// ── 4. Concurrency: a reconfigure racing live status readers ────────────────
//
// Run under -race. The invariant is the same one §1 pins, asserted while
// readers are hammering the surface: once the configuration names an
// unreachable daemon, no reader may ever be told "connected" again.

func TestChaos116_ReconfigureUnderConcurrentReadersNeverPublishesStaleHealth(t *testing.T) {
	old := newGatedPingClam()
	releaseOld := releaseOnce(t, old)
	ss := newStatusScanner(t, old)
	oldFlight := ss.startClamStatusProbe(old)

	ss.Init(deadClamAddr, 1<<20, hashcache.New(16, time.Minute))
	waitCurrentFlight(t, ss, "the warm-up probe for the reconfigured daemon")

	stop := make(chan struct{})
	var bad atomic.Int64
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if ss.ClamAVStatus() == "connected" {
					bad.Add(1)
				}
			}
		}()
	}

	releaseOld() // the previous daemon answers "connected" mid-storm
	<-oldFlight
	expireClamStatus(ss) // force the readers through the probe path too
	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()

	if got := bad.Load(); got != 0 {
		t.Fatalf("%d status reads returned \"connected\" for %s: the superseded daemon's answer reached live readers", got, deadClamAddr)
	}
}
