package syslog

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// stubConn is a net.Conn whose write behaviour the test drives.
type stubConn struct {
	mu      sync.Mutex
	writes  int
	failAll bool
}

func (c *stubConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failAll {
		return 0, errors.New("collector gone")
	}
	c.writes++
	return len(p), nil
}
func (c *stubConn) Read([]byte) (int, error)         { return 0, errors.New("no reads") }
func (c *stubConn) Close() error                     { return nil }
func (c *stubConn) LocalAddr() net.Addr              { return nil }
func (c *stubConn) RemoteAddr() net.Addr             { return nil }
func (c *stubConn) SetDeadline(time.Time) error      { return nil }
func (c *stubConn) SetReadDeadline(time.Time) error  { return nil }
func (c *stubConn) SetWriteDeadline(time.Time) error { return nil }

func newStubWriter(t *testing.T, c *stubConn, dialErr error) *Writer {
	t.Helper()
	w := &Writer{network: "tcp", addr: "collector:514", host: "h", tag: "culvert", format: "rfc3164", pid: "1"}
	w.dialFunc = func() (net.Conn, error) {
		if dialErr != nil {
			return nil, dialErr
		}
		return c, nil
	}
	if dialErr == nil {
		if err := w.connect(); err != nil {
			t.Fatalf("connect: %v", err)
		}
	}
	return w
}

// DEFECT GATE. Before CHAOS-72 the engine exposed only a cumulative Drops()
// counter: there was no way for any surface to answer "is the feed delivering
// RIGHT NOW?", which is why every health surface either had nothing to read or
// reported init-time state. Delivery must carry a timestamp.
func TestChaos72_DeliverySetsLastSuccess(t *testing.T) {
	c := &stubConn{}
	w := newStubWriter(t, c, nil)

	if st := w.Stats(); !st.LastSuccess.IsZero() {
		t.Fatalf("LastSuccess = %v before any delivery; want zero (never delivered is a DISTINCT state)", st.LastSuccess)
	}
	w.writeMsg(14, "hello")

	st := w.Stats()
	if st.Delivered != 1 {
		t.Errorf("Delivered = %d; want 1", st.Delivered)
	}
	if st.LastSuccess.IsZero() {
		t.Error("LastSuccess is zero after a successful delivery — the freshness axis is missing")
	}
	if st.Drops != 0 {
		t.Errorf("Drops = %d; want 0", st.Drops)
	}
}

// DEFECT GATE. Every drop site must move the reason and the timestamp, not
// only the counter — a drop that moves Drops() alone is invisible to a
// freshness surface, which is the shape that made the pre-fix counter useless.
func TestChaos72_EveryDropCarriesABoundedReason(t *testing.T) {
	cases := []struct {
		name string
		want string
		run  func(t *testing.T) *Writer
	}{
		{"connect_failed", ReasonConnectFail, func(t *testing.T) *Writer {
			w := newStubWriter(t, nil, errors.New("refused"))
			w.writeMsg(14, "x")
			return w
		}},
		{"write_failed", ReasonWriteFail, func(t *testing.T) *Writer {
			c := &stubConn{failAll: true}
			w := newStubWriter(t, c, nil)
			w.writeMsg(14, "x") // write fails, reconnect succeeds, write fails again
			return w
		}},
		{"backoff", ReasonBackoff, func(t *testing.T) *Writer {
			w := newStubWriter(t, nil, errors.New("refused"))
			w.writeMsg(14, "x") // arms lastReconnErr
			w.writeMsg(14, "y") // fast-drops inside the window
			return w
		}},
		{"queue_full", ReasonQueueFull, func(t *testing.T) *Writer {
			c := &stubConn{}
			w := newStubWriter(t, c, nil)
			w.queue = make(chan queuedLine, 1) // no drain goroutine: fills immediately
			w.send(14, "a")
			w.send(14, "b")
			return w
		}},
		{"closed", ReasonClosed, func(t *testing.T) *Writer {
			c := &stubConn{}
			w := newStubWriter(t, c, nil)
			w.queue = make(chan queuedLine, 1)
			w.closed.Store(true)
			w.send(14, "a")
			return w
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := tc.run(t)
			st := w.Stats()
			if st.Drops == 0 {
				t.Fatalf("Drops = 0; want >0 for the %s path", tc.name)
			}
			if st.LastFailureReason != tc.want {
				t.Errorf("LastFailureReason = %q; want %q", st.LastFailureReason, tc.want)
			}
			if st.LastFailure.IsZero() {
				t.Error("LastFailure is zero after a drop — the drop bypassed noteDrop")
			}
			for _, r := range []string{
				ReasonQueueFull, ReasonClosed, ReasonConnectFail,
				ReasonWriteFail, ReasonBackoff, ReasonPanic, ReasonFlushTimeout,
			} {
				if st.LastFailureReason == r {
					return
				}
			}
			t.Errorf("reason %q is outside the closed set — a raw error can reach an alert Detail and defeat dedup (WK-12/RS-5)", st.LastFailureReason)
		})
	}
}

// DEFECT GATE. ConsecutiveFailures must reset on delivery, otherwise the
// recovery edge never fires and the plane latches a healed feed as down.
func TestChaos72_ConsecutiveFailuresResetOnDelivery(t *testing.T) {
	c := &stubConn{failAll: true}
	w := newStubWriter(t, c, nil)
	w.writeMsg(14, "x")
	if st := w.Stats(); st.ConsecutiveFailures == 0 {
		t.Fatalf("ConsecutiveFailures = 0 after a failed write; want >0")
	}
	c.mu.Lock()
	c.failAll = false
	c.mu.Unlock()
	// The write path armed the backoff; clear it so the retry is attempted.
	w.mu.Lock()
	w.lastReconnErr = time.Time{}
	w.mu.Unlock()
	w.writeMsg(14, "y")
	if st := w.Stats(); st.ConsecutiveFailures != 0 {
		t.Errorf("ConsecutiveFailures = %d after recovery; want 0", st.ConsecutiveFailures)
	}
}

// DEFECT GATE. The observer is the seam the freshness plane is driven from
// (this package cannot log, alert or hold a timer). It must fire on every drop
// and exactly once on the recovery edge.
func TestChaos72_DeliveryObserverFiresOnDropAndOnRecoveryEdge(t *testing.T) {
	c := &stubConn{failAll: true}
	w := newStubWriter(t, c, nil)

	var mu sync.Mutex
	var events []bool
	w.SetDeliveryObserver(func(ok bool) {
		mu.Lock()
		events = append(events, ok)
		mu.Unlock()
	})

	w.writeMsg(14, "a")
	c.mu.Lock()
	c.failAll = false
	c.mu.Unlock()
	w.mu.Lock()
	w.lastReconnErr = time.Time{}
	w.mu.Unlock()
	w.writeMsg(14, "b") // recovery edge
	w.writeMsg(14, "c") // ordinary success — must NOT notify

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 2 {
		t.Fatalf("observer events = %v; want exactly [false true] (a drop, then one recovery edge; steady-state success must not notify)", events)
	}
	if events[0] != false || events[1] != true {
		t.Errorf("observer events = %v; want [false true]", events)
	}
}

// CONTROL. The cheapest way to pass every gate above is to stop delivering and
// report nothing, or to notify on every line. Pin the healthy steady state:
// a working collector produces deliveries, no drops, and no observer traffic.
func TestChaos72_HealthyFeedIsUnchangedAndSilent(t *testing.T) {
	c := &stubConn{}
	w := newStubWriter(t, c, nil)
	notified := 0
	w.SetDeliveryObserver(func(bool) { notified++ })

	for i := 0; i < 100; i++ {
		w.writeMsg(14, "line")
	}
	st := w.Stats()
	if st.Delivered != 100 || st.Drops != 0 {
		t.Errorf("Stats{Delivered:%d Drops:%d}; want 100/0", st.Delivered, st.Drops)
	}
	if notified != 0 {
		t.Errorf("observer fired %d times on a healthy feed; want 0 (the happy path must not pay for a callback)", notified)
	}
	c.mu.Lock()
	writes := c.writes
	c.mu.Unlock()
	if writes != 100 {
		t.Errorf("collector saw %d writes; want 100 — delivery accounting must not change what is sent", writes)
	}
}

// CONTROL. A panicking observer must never take down the drain goroutine: the
// SIEM plane is an observability surface and may not become a way to kill an
// in-line gateway (CHAOS-24's rule, already applied to SetPanicObserver).
func TestChaos72_PanickingObserverCannotKillDelivery(t *testing.T) {
	c := &stubConn{failAll: true}
	w := newStubWriter(t, c, nil)
	w.SetDeliveryObserver(func(bool) { panic("bad observer") })
	w.writeMsg(14, "x") // must not panic out of here
	if st := w.Stats(); st.Drops == 0 {
		t.Error("drop was not counted while the observer panicked")
	}
}

// Stats must be readable without contending with the drain goroutine's socket
// writes: /metrics, /healthz and the diagnostics row all reach it.
func TestChaos72_StatsIsReadableWhileTheWriteLockIsHeld(t *testing.T) {
	c := &stubConn{}
	w := newStubWriter(t, c, nil)
	w.mu.Lock()
	done := make(chan Stats, 1)
	go func() { done <- w.Stats() }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		w.mu.Unlock()
		t.Fatal("Stats blocked on the delivery mutex — a scrape must never contend with a socket write")
	}
	w.mu.Unlock()
}
