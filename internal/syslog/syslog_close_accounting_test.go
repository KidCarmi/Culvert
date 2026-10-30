package syslog

// Close/send accounting: every line a caller hands to send must end up either
// DELIVERED to the collector or COUNTED in Drops. A line that is neither is
// silent loss — invisible on Drops(), on the admin JSON readback and on every
// other surface — which is the one failure mode this engine's whole async
// design is meant to make impossible.
//
// CHAOS-78 (Codex round 1) found that Close could strand exactly such a line:
// a sender that had passed send's closed check could be preempted, Close could
// then stop drainLoop with an empty queue, and the sender's subsequent send
// would succeed into a queue nobody would ever read again (Close never closes
// the channel, by design, so the send does not even panic). Close now waits for
// in-flight senders before stopping the drain goroutine.
//
// The conservation test below IS a differential oracle: against the pre-fix
// ordering it fails 6 runs in 10, typically losing exactly one line
// ("delivered 2091 + dropped 5273 = 7364; want exactly 7365 sent").
//
// It did not start out that way, and why is worth recording. The first version
// of countingConn embedded a bare net.Conn, so writeLine's SetWriteDeadline
// nil-panicked on every line; deliverGuarded recovered each one and counted it
// as a drop. delivered was ZERO, the conservation law held trivially, and the
// test passed on fixed and broken code alike. On that evidence this finding was
// written up as "confirmed by construction, not reproduced" — the conclusion
// was wrong, and it was wrong because of a bug in the fake conn, not because
// the race is rare. A review comment rated "minor" is what surfaced it.
//
// Hence the two explicit guards in that test: delivered must be non-zero and
// Panics() must be zero. Either one failing means drops are standing in for
// deliveries and the law proves nothing.

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// countingConn counts delivered lines. The drain goroutine owns every write, so
// no lock is needed beyond the counter itself.
//
// It embeds deadlineRecordingConn rather than net.Conn, which matters: writeLine
// calls SetWriteDeadline BEFORE every write, so a bare embedded net.Conn
// (a nil interface) panics there, deliverGuarded recovers it, and the line is
// counted as a drop. The conservation law below would then hold trivially with
// ZERO lines delivered — a vacuous test that looks like coverage. Measured on
// the first version of this file: delivered=0, dropped=50, panics=50.
// deadlineRecordingConn implements the whole net.Conn surface, and
// discardConn/slowConn in the benchmarks embed it for the same reason.
type countingConn struct {
	deadlineRecordingConn
	lines atomic.Uint64 // unsigned to match Drops(), so the conservation check
	// below needs no conversion (gosec G115)
}

func (c *countingConn) Write(p []byte) (int, error) {
	c.lines.Add(1)
	return len(p), nil
}

// TestClose_EveryLineIsDeliveredOrDropped races senders against Close and
// asserts the conservation law: delivered + dropped == sent, exactly.
//
// delivered+dropped < sent means lines were enqueued onto the abandoned queue
// after drainLoop exited. Senders run across the Close, which is the shape of a
// runtime SIEM retarget under live traffic and the interleaving the finding
// describes. Pre-fix: 6 failures in 10 runs.
func TestClose_EveryLineIsDeliveredOrDropped(t *testing.T) {
	const senders = 8

	conn := &countingConn{}
	w := newAsyncTestWriter(conn)

	var wg sync.WaitGroup
	var sent atomic.Uint64
	stop := make(chan struct{})
	for i := 0; i < senders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				w.WriteRequest(map[string]string{"k": "v"})
				sent.Add(1)
			}
		}()
	}

	// Let delivery actually get going before Close lands, so the law is tested
	// against a mix of delivered and dropped lines rather than against an
	// all-dropped run (see countingConn on why an all-dropped run is vacuous).
	deadline := time.Now().Add(10 * time.Second)
	for conn.lines.Load() < 32 {
		if time.Now().After(deadline) {
			close(stop)
			wg.Wait()
			t.Fatalf("collector saw only %d lines in 10s; the delivery path is not running", conn.lines.Load())
		}
		time.Sleep(time.Millisecond)
	}

	// Close mid-flight: senders keep running across it, which is the shape of a
	// runtime SIEM retarget under live traffic.
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	close(stop)
	wg.Wait()

	delivered := conn.lines.Load()
	dropped := w.Drops()
	total := sent.Load()

	// Guard against the vacuous pass described on countingConn: if nothing was
	// delivered, or anything panicked, the conservation law below is satisfied
	// by construction and proves nothing.
	if delivered == 0 {
		t.Error("no line was delivered, so the conservation law below holds trivially; the fake conn is not exercising the delivery path")
	}
	if p := w.Panics(); p != 0 {
		t.Errorf("%d recovered delivery panic(s); the fake conn is rejecting a call the writer makes, so drops are standing in for deliveries", p)
	}
	if delivered+dropped != total {
		t.Errorf("delivered %d + dropped %d = %d; want exactly %d sent.\n"+
			"A line that is neither delivered nor counted is silent SIEM loss: it was enqueued onto a queue whose drain goroutine had already exited.",
			delivered, dropped, delivered+dropped, total)
	}
}

// TestClose_WaitsForAnInFlightSenderBeforeStoppingTheDrain tests the mechanism
// directly instead of trying to win a race: it parks a registration to stand in
// for a sender sitting between its closed check and its enqueue, releases it
// after a delay, and requires Close not to have returned before then.
//
// Unlike the conservation test above, this IS a differential — pre-fix, Close
// did not consult inFlight at all and returns in well under the delay.
//
// Note what is NOT asserted: that inFlight is zero once Close returns. It need
// not be. Senders arriving after waitForSenders finishes still register briefly
// before taking the closed branch, so that would be a false invariant; the
// property that matters is the ordering against close(stop), which is what the
// delay below measures.
func TestClose_WaitsForAnInFlightSenderBeforeStoppingTheDrain(t *testing.T) {
	const parked = 150 * time.Millisecond

	conn := &countingConn{}
	w := newAsyncTestWriter(conn)

	w.inFlight.Add(1) // stands in for a sender inside the window
	// start is taken BEFORE the release timer begins, so a Close that waited
	// for the release always measures at least parked. Taken after, the
	// goroutine's sleep could already be under way and a correct Close would
	// read as early on a preempted runner.
	start := time.Now()
	go func() {
		time.Sleep(parked)
		w.inFlight.Add(-1)
	}()

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if elapsed := time.Since(start); elapsed < parked {
		t.Errorf("Close returned after %v, before the in-flight sender cleared at %v.\n"+
			"Closing stop while a sender is between its closed check and its enqueue strands that line on a queue whose drain goroutine has exited: neither delivered nor counted.",
			elapsed, parked)
	}
}

// TestClose_SenderWaitIsBounded is the other half: the wait must never be able
// to hang shutdown. A registration that is never released must still let Close
// return, at the cost of the recorded residual (that line may go unaccounted).
func TestClose_SenderWaitIsBounded(t *testing.T) {
	conn := &countingConn{}
	w := newAsyncTestWriter(conn)

	w.inFlight.Add(1) // never released

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = w.Close()
	}()

	select {
	case <-done:
	case <-time.After(senderDrainTimeout + closeWait + 5*time.Second):
		t.Fatal("Close did not return: the in-flight sender wait must be bounded, never a shutdown hang")
	}
}
