package syslog

// CHAOS-66 engine gates: the counters and the observer that make the difference
// between a CONNECTED feed and a DELIVERING one observable.
//
// Before this, the package exposed only a cumulative Drops() total. A reader
// had to poll and difference it to learn anything, and nothing distinguished
// "the collector is unreachable" (a network path to fix) from "the queue
// overflowed" (capacity to add) — so package main could report a feed that was
// dropping every event as fully active.

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// stallingConn blocks every write until released, so the drain goroutine cannot
// keep up and the bounded queue overflows. That is the "SIEM accepted the
// connection and stopped reading" shape.
type stallingConn struct {
	release chan struct{}
}

func (c *stallingConn) Write(p []byte) (int, error) {
	<-c.release
	return len(p), nil
}
func (c *stallingConn) Read([]byte) (int, error) { return 0, nil }
func (c *stallingConn) Close() error             { return nil }

func (c *stallingConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *stallingConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *stallingConn) SetDeadline(time.Time) error        { return nil }
func (c *stallingConn) SetReadDeadline(time.Time) error    { return nil }
func (c *stallingConn) SetWriteDeadline(t time.Time) error { return nil }

func newAsyncWriterWithConn(conn net.Conn) *Writer {
	w := &Writer{
		network:  "tcp",
		addr:     "192.0.2.1:514", // TEST-NET-1: never dialled
		host:     "testhost",
		tag:      "culvert",
		format:   "rfc3164",
		conn:     conn,
		dialFunc: func() (net.Conn, error) { return conn, nil },
	}
	w.startAsync()
	return w
}

// A delivered line advances Delivered() and reports true to the observer; a
// failed one advances Drops() and reports false. Without this the only signal
// is a cumulative total that says nothing about the CURRENT state.
func TestChaos66_DeliveryOutcomeIsObservable(t *testing.T) {
	var ok, bad atomic.Int64
	good := &deadlineRecordingConn{}
	w := newAsyncWriterWithConn(good)
	w.SetDeliveryObserver(func(delivered bool) {
		if delivered {
			ok.Add(1)
		} else {
			bad.Add(1)
		}
	})
	defer w.Close() //nolint:errcheck // test teardown

	w.Write([]byte("hello")) //nolint:errcheck // io.Writer contract, never errors here
	waitFor(t, func() bool { return ok.Load() == 1 })
	if w.Delivered() != 1 {
		t.Errorf("Delivered() = %d; want 1", w.Delivered())
	}

	// The collector goes away. deliverLine tries the write, reconnects (the
	// dial seam hands back the same dead conn), retries and gives up.
	dead := &failingConn{}
	w.mu.Lock()
	w.conn = dead
	w.dialFunc = func() (net.Conn, error) { return dead, nil }
	w.lastReconnErr = time.Time{}
	w.mu.Unlock()

	w.Write([]byte("world")) //nolint:errcheck // as above
	waitFor(t, func() bool { return bad.Load() == 1 })
	if w.Drops() == 0 {
		t.Error("a failed delivery did not advance Drops()")
	}
	if w.Delivered() != 1 {
		t.Errorf("Delivered() = %d after a failed delivery; want 1 — a failed line must never count as delivered", w.Delivered())
	}
}

// Queue overflow is charged to QueueDrops as well as to the Drops total.
// Operator action differs — collector capacity, not a network path — so the two
// must be distinguishable.
func TestChaos66_QueueOverflowIsChargedToQueueDrops(t *testing.T) {
	stall := &stallingConn{release: make(chan struct{})}
	w := newAsyncWriterWithConn(stall)
	defer func() {
		close(stall.release)
		w.Close() //nolint:errcheck // test teardown
	}()

	// One line parks the drain goroutine inside Write; queueCap more fill the
	// channel; everything after that must shed.
	for i := 0; i < queueCap+64; i++ {
		w.Write([]byte("line")) //nolint:errcheck // io.Writer contract
	}
	if w.QueueDrops() == 0 {
		t.Fatalf("queue overflow was not charged to QueueDrops (Drops=%d)", w.Drops())
	}
	if w.QueueDrops() > w.Drops() {
		t.Errorf("QueueDrops()=%d exceeds Drops()=%d; the subset can never exceed the total", w.QueueDrops(), w.Drops())
	}
	if w.Delivered() != 0 {
		t.Errorf("Delivered()=%d against a collector that has not read a byte", w.Delivered())
	}
}

// The observer runs on the DRAIN goroutine, never on the caller's. A per-line
// callback on the request path is exactly the coupling the async design exists
// to remove, so queue-side drops are accounted by QueueDrops() instead.
func TestChaos66_ObserverNeverRunsOnTheCallerGoroutine(t *testing.T) {
	stall := &stallingConn{release: make(chan struct{})}
	w := newAsyncWriterWithConn(stall)
	defer func() {
		close(stall.release)
		w.Close() //nolint:errcheck // test teardown
	}()

	var calls atomic.Int64
	w.SetDeliveryObserver(func(bool) { calls.Add(1) })
	for i := 0; i < queueCap+64; i++ {
		w.Write([]byte("line")) //nolint:errcheck // io.Writer contract
	}
	// The drain goroutine is parked in Write, so at most the ONE line it is
	// delivering can have reached the observer. Every shed line must have gone
	// to QueueDrops without a callback.
	if got := calls.Load(); got > 1 {
		t.Errorf("observer called %d times while the drain goroutine was parked; queue-side drops must not invoke it", got)
	}
}

// A panicking observer must never take delivery down — the SetPanicObserver
// containment rule, applied to the second seam.
func TestChaos66_PanickingDeliveryObserverIsContained(t *testing.T) {
	good := &deadlineRecordingConn{}
	w := newAsyncWriterWithConn(good)
	defer w.Close() //nolint:errcheck // test teardown
	w.SetDeliveryObserver(func(bool) { panic("observer is broken") })

	for i := 0; i < 5; i++ {
		w.Write([]byte("line")) //nolint:errcheck // io.Writer contract
	}
	waitFor(t, func() bool { return w.Delivered() == 5 })
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("condition not met within the deadline")
}
