package syslog

// Async-delivery tests: the request path must never block on (or serialize
// behind) the collector socket. Delivery happens on the single drain
// goroutine; callers only format + enqueue, with overflow counted in Drops.

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"
)

// newAsyncTestWriter builds a Writer around an injected conn and arms the
// production async path (queue + drain goroutine), skipping the real dialer.
func newAsyncTestWriter(conn net.Conn) *Writer {
	w := &Writer{
		network: "tcp",
		addr:    "192.0.2.1:514", // TEST-NET-1, never dialed: conn is pre-injected
		host:    "testhost",
		tag:     "culvert",
		format:  "rfc3164",
		pid:     "1",
		conn:    conn,
	}
	w.startAsync()
	return w
}

func TestAsync_DeliversAndPreservesOrder(t *testing.T) {
	fake := &deadlineRecordingConn{}
	w := newAsyncTestWriter(fake)
	defer w.Close() //nolint:errcheck // test cleanup

	w.WriteRequest(map[string]string{"seq": "alpha"})
	w.WriteAudit(map[string]string{"seq": "bravo"})
	if _, err := w.Write([]byte("charlie")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		fake.mu.Lock()
		got := fake.buf.String()
		fake.mu.Unlock()
		a, b, c := strings.Index(got, "alpha"), strings.Index(got, "bravo"), strings.Index(got, "charlie")
		if a >= 0 && b >= 0 && c >= 0 {
			if a >= b || b >= c {
				t.Fatalf("delivery order violated (alpha@%d bravo@%d charlie@%d): %q", a, b, c, got)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("async delivery incomplete after 2s: %q", got)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// blockedConn wedges every Write until release is closed — a collector that
// accepted the TCP handshake but never drains, ignoring deadlines (worse than
// real kernels, which is the point: even then callers must not block).
type blockedConn struct {
	deadlineRecordingConn
	release chan struct{}
}

func (c *blockedConn) Write(p []byte) (int, error) {
	<-c.release
	return c.deadlineRecordingConn.Write(p)
}

// TestAsync_WedgedCollectorNeverBlocksCaller is THE regression gate for the
// decoupling: with the drain goroutine wedged in a socket write, every send —
// including queueCap-plus overflow — must return immediately, counting drops.
// On the pre-async synchronous path this test cannot finish: the first caller
// wedges on the socket under s.mu and every later caller queues on the mutex.
func TestAsync_WedgedCollectorNeverBlocksCaller(t *testing.T) {
	wedged := &blockedConn{release: make(chan struct{})}
	w := newAsyncTestWriter(wedged)

	const sends = queueCap + 100
	start := time.Now()
	for i := 0; i < sends; i++ {
		w.WriteRequest(map[string]string{"n": "x"})
	}
	elapsed := time.Since(start)

	// Generous CI bound: sends are pure format+enqueue (µs each); anything in
	// the seconds range means a caller touched the wedged socket path.
	if elapsed > 5*time.Second {
		t.Fatalf("%d sends against a wedged collector took %v; callers are blocking on delivery", sends, elapsed)
	}
	// One line may be in-flight in the drain goroutine and queueCap queued;
	// everything else must have dropped.
	if got, want := w.Drops(), uint64(sends-queueCap-2); got < want {
		t.Errorf("Drops() = %d, want >= %d (queue overflow must count as drops)", got, want)
	}

	close(wedged.release) // unwedge so Close's flush isn't pinned to the timeout
	_ = w.Close()
}

func TestAsync_CloseFlushesQueued(t *testing.T) {
	fake := &deadlineRecordingConn{}
	w := newAsyncTestWriter(fake)

	const n = 50
	for i := 0; i < n; i++ {
		w.WriteRequest(map[string]int{"i": i})
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	fake.mu.Lock()
	lines := bytes.Count(fake.buf.Bytes(), []byte("\n"))
	closed := fake.closed
	fake.mu.Unlock()
	if lines != n {
		t.Errorf("delivered %d lines by Close return, want %d (Close must flush the queue to a healthy collector)", lines, n)
	}
	if !closed {
		t.Error("conn not released after Close")
	}
	if got := w.Drops(); got != 0 {
		t.Errorf("Drops() = %d, want 0 (healthy collector, no overflow)", got)
	}
}

func TestAsync_CloseIdempotentAndSendAfterCloseDrops(t *testing.T) {
	fake := &deadlineRecordingConn{}
	w := newAsyncTestWriter(fake)

	if err := w.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	before := w.Drops()
	w.WriteRequest(map[string]string{"late": "entry"})
	if got := w.Drops(); got != before+1 {
		t.Errorf("Drops() after post-Close send = %d, want %d", got, before+1)
	}
}
