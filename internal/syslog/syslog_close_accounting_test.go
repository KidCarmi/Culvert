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
// READ THESE AS INVARIANTS, NOT AS A DIFFERENTIAL ORACLE. Both tests pass on
// the pre-fix ordering too: reaching the lost-line case needs drainLoop's flush
// to observe an EMPTY queue at the one moment every sender sits between its
// closed check and its enqueue, and ~500 attempts across two strategies (a
// slow formatMsg via a large payload, and Close landing in steady-state
// traffic) never hit it here. Close's existing wait on done also lets inFlight
// drain on its own, which is why the ordering assertion below passes either
// way. The finding is confirmed BY CONSTRUCTION from the source — the
// interleaving the code permits — and is NOT reproduced, which is the same
// standard §42 of the chaos register sets for mixing measured and reasoned
// items. What these tests buy is regression protection for the invariant, not
// evidence of the bug.

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// countingConn counts delivered lines. The drain goroutine owns every write,
// so no lock is needed beyond the counter itself.
type countingConn struct {
	net.Conn
	lines atomic.Uint64 // unsigned to match Drops(), so the conservation check
	// below needs no conversion (gosec G115)
}

func (c *countingConn) Write(p []byte) (int, error) {
	c.lines.Add(1)
	return len(p), nil
}
func (c *countingConn) Close() error { return nil }

// TestClose_EveryLineIsDeliveredOrDropped races senders against Close and
// asserts the conservation law: delivered + dropped == sent, exactly.
//
// delivered+dropped < sent would mean lines were enqueued onto the abandoned
// queue after drainLoop exited. The senders start first and Close lands while
// they are still running, which is the shape of the interleaving the finding
// describes — though see the header: this did not fail pre-fix here.
func TestClose_EveryLineIsDeliveredOrDropped(t *testing.T) {
	const (
		senders        = 16
		linesPerSender = 64
		sent           = senders * linesPerSender
	)

	conn := &countingConn{}
	w := newAsyncTestWriter(conn)

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < senders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < linesPerSender; j++ {
				w.WriteRequest(map[string]int{"n": j})
			}
		}()
	}

	close(start)
	// Close concurrently with the senders: the point is to land inside the
	// window, not after it.
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	wg.Wait()

	// Any sender still running after Close now takes the closed branch and is
	// counted, so the law holds across the whole run, not just the pre-Close
	// part.
	delivered := conn.lines.Load()
	dropped := w.Drops()
	if delivered+dropped != sent {
		t.Errorf("delivered %d + dropped %d = %d; want exactly %d sent.\n"+
			"A line that is neither delivered nor counted is silent SIEM loss: it was enqueued onto a queue whose drain goroutine had already exited.",
			delivered, dropped, delivered+dropped, sent)
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
	go func() {
		time.Sleep(parked)
		w.inFlight.Add(-1)
	}()

	start := time.Now()
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
