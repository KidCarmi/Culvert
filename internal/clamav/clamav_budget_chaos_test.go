package clamav

// Chaos gates for the ClamAV client's deadline ownership.
//
// The defect these pin: the queue wait used to be governed by a PRIVATE 5 s
// constant. The scan orchestrator's own budget is 10 s and fails CLOSED on
// expiry, so the inner limit always fired first and returned an ordinary error
// — which the orchestrator classifies as an engine fault and handles fail-OPEN.
// Five concurrent large downloads on a perfectly healthy daemon therefore
// admitted content unscanned. Worse, an abandoned scan kept its slot for the
// client's full 30 s timeout, so a slow daemon filled all four slots with work
// nobody was waiting for and pushed every live request onto that fail-open
// path — a collapse that sustains itself for as long as load continues.
//
// Both halves are structural: an inner deadline must not preempt an outer one,
// and abandoned work must release its resources.

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// occupyAllSlots fills clamSem and returns a release func. Direct manipulation
// of the package semaphore keeps the test deterministic — no reliance on
// timing a real scan into place.
func occupyAllSlots(t *testing.T) (release func()) {
	t.Helper()
	for i := 0; i < clamMaxConcurrent; i++ {
		select {
		case clamSem <- struct{}{}:
		case <-time.After(2 * time.Second):
			t.Fatalf("could not occupy clamSem slot %d — a previous test leaked one", i)
		}
	}
	var released bool
	return func() {
		if released {
			return
		}
		released = true
		for i := 0; i < clamMaxConcurrent; i++ {
			<-clamSem
		}
	}
}

// TestChaos_QueueWaitIsChargedToTheCallersBudget proves the wait for a scan
// slot expires with the CALLER's deadline, not with a private constant, and
// that the outcome is classifiable as saturation rather than as a daemon fault.
//
// Pre-fix this call blocked for the full private 5 s and returned an
// unclassifiable error, so a caller with a shorter budget could not enforce it
// and a caller with a longer one had its fail-closed deadline preempted by a
// fail-open error.
func TestChaos_QueueWaitIsChargedToTheCallersBudget(t *testing.T) {
	release := occupyAllSlots(t)
	defer release()

	c := New("tcp:127.0.0.1:1") // never dialled: the wait ends first
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, _, err := c.ScanContext(ctx, []byte("payload"))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("scan must fail while every slot is occupied")
	}
	if !errors.Is(err, ErrQueueFull) {
		t.Fatalf("saturation must be distinguishable from a daemon fault, got %v", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("the caller's deadline must be the cause, got %v", err)
	}
	// Generous upper bound: the point is that it is nowhere near the old 5 s.
	if elapsed > 2*time.Second {
		t.Fatalf("queue wait took %s — the caller's 250ms budget did not govern it", elapsed)
	}
}

// TestChaos_QueueWaitOutlivesTheOldPrivateConstant proves the inverse: a caller
// whose budget EXCEEDS the old 5 s constant keeps waiting instead of being
// failed out at 5 s. This is the half that used to invert the posture — the
// orchestrator's 10 s fail-closed budget was cut short by a 5 s fail-open one.
func TestChaos_QueueWaitOutlivesTheOldPrivateConstant(t *testing.T) {
	if testing.Short() {
		t.Skip("timing gate")
	}
	release := occupyAllSlots(t)

	// Hold the slots for LONGER than the retired 5 s cap, so a client that
	// still enforced it would fail this caller out even though the caller's own
	// budget has seconds left. That is the exact inversion being pinned.
	freed := make(chan struct{})
	go func() {
		time.Sleep(clamQueueWaitFallback + 500*time.Millisecond)
		release()
		close(freed)
	}()

	addr, _ := fakeClamd(t, "stream: OK\x00")
	c := New(addr)
	// A budget far longer than the retired constant. If the private cap were
	// still in force the scan would fail regardless of this.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	_, malicious, err := c.ScanContext(ctx, []byte("payload"))
	<-freed
	if err != nil {
		t.Fatalf("a caller with budget remaining must wait for a slot, not be failed out: %v", err)
	}
	if malicious {
		t.Fatal("clean payload reported malicious")
	}
}

// stalledClamd accepts a connection and never replies, modelling a daemon that
// is up but wedged (signature reload, memory pressure, disk stall).
func stalledClamd(t *testing.T) string {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Hold the connection open, reading nothing back to the client.
			t.Cleanup(func() { conn.Close() })
		}
	}()
	return "tcp:" + ln.Addr().String()
}

// TestChaos_AbandonedScanReleasesItsSlotPromptly proves a cancelled scan gives
// its slot back at the caller's deadline rather than at the client's own
// 30 s timeout. This is the amplifier: pre-fix, four abandoned scans held every
// slot for 30 s, so live requests could not scan at all.
func TestChaos_AbandonedScanReleasesItsSlotPromptly(t *testing.T) {
	addr := stalledClamd(t)
	c := New(addr)
	if c.timeout < 10*time.Second {
		t.Fatalf("precondition: client timeout is %s, expected the long default", c.timeout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, _, err := c.ScanContext(ctx, []byte("payload")); err == nil {
		t.Fatal("a scan against a wedged daemon must not report success")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("abandoned scan took %s to unwind — it held its slot to the client timeout (%s)", elapsed, c.timeout)
	}

	// The slot must be back: acquire every slot without waiting.
	release := occupyAllSlots(t)
	release()
}

// TestChaos_LegacyScanKeepsItsOwnBudget pins that callers with no deadline of
// their own (the compatibility Scan entry point) still get a bounded wait
// rather than blocking forever.
func TestChaos_LegacyScanKeepsItsOwnBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("timing gate")
	}
	release := occupyAllSlots(t)
	defer release()

	c := New("tcp:127.0.0.1:1")
	start := time.Now()
	_, _, err := c.Scan([]byte("payload")) // no caller deadline
	elapsed := time.Since(start)

	if !errors.Is(err, ErrQueueFull) {
		t.Fatalf("want the saturation sentinel, got %v", err)
	}
	if elapsed < clamQueueWaitFallback {
		t.Fatalf("deadline-free caller gave up after %s, before the fallback budget %s", elapsed, clamQueueWaitFallback)
	}
	if elapsed > clamQueueWaitFallback+3*time.Second {
		t.Fatalf("deadline-free caller waited %s — the fallback budget is not bounding it", elapsed)
	}
}
