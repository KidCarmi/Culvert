package syslog

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// syslog_delivery_chaos_test.go — CHAOS-66 gates for the delivery-evidence
// half of the SIEM forwarding plane.
//
// Every DEFECT gate here was verified failing against the pre-fix tree, where
// the package exported exactly two numbers (Drops, Panics) and no notion of
// delivery at all. The CONTROLS matter as much: the cheapest way to pass a
// "loss must be visible" gate is to report everything as broken, which would
// page every healthy deployment — so a healthy feed must stay green, and a
// queue overflow must not be reported as a collector outage.

// failConn is a net.Conn whose writes fail, simulating a collector that
// accepted the connection and then stopped draining (SIEM overload, half-open
// peer after a reboot).
type failConn struct {
	net.Conn
	mu       sync.Mutex
	failing  bool
	written  []string
	deadline time.Time
}

func (c *failConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failing {
		return 0, errors.New("write: connection reset by peer")
	}
	c.written = append(c.written, string(p))
	return len(p), nil
}
func (c *failConn) Close() error                       { return nil }
func (c *failConn) SetWriteDeadline(t time.Time) error { c.deadline = t; return nil }

func (c *failConn) setFailing(v bool) {
	c.mu.Lock()
	c.failing = v
	c.mu.Unlock()
}

func (c *failConn) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.written)
}

// newTestWriter builds a synchronous (zero-queue) Writer over a controllable
// conn. The synchronous path runs the identical deliverLine state machine the
// drain goroutine uses, so the accounting under test is production code.
//
// dialFunc hands back the SAME conn, modelling a collector that stays
// reachable at the TCP level while its writes fail — the half-open /
// stopped-draining shape. A dialFunc that always failed would model a
// different fault (collector gone entirely) and would make the recovery
// gates unreachable.
func newTestWriter(network string, conn net.Conn) *Writer {
	return &Writer{
		network:  network,
		addr:     "collector.test:514",
		host:     "h",
		tag:      "culvert",
		format:   "rfc3164",
		pid:      "1",
		conn:     conn,
		dialFunc: func() (net.Conn, error) { return conn, nil },
	}
}

// clearBackoff drops deliverLine's 5s reconnect suppression so a test can
// exercise the NEXT delivery attempt without sleeping. The backoff itself is
// established behaviour with its own coverage in syslog_deadline_test.go;
// these gates are about what the attempt's OUTCOME is recorded as.
func clearBackoff(w *Writer) {
	w.mu.Lock()
	w.lastReconnErr = time.Time{}
	w.mu.Unlock()
}

// TestChaos66_DeliveryIsCountedAsEvidence — DEFECT gate. Before the fix the
// process had no record that anything had EVER been delivered, so no surface
// could distinguish "working" from "never tried".
func TestChaos66_DeliveryIsCountedAsEvidence(t *testing.T) {
	conn := &failConn{}
	w := newTestWriter("tcp", conn)

	if h := w.Health(); h.Delivered != 0 || !h.LastDelivery.IsZero() {
		t.Fatalf("fresh writer already claims delivery: %+v", h)
	}
	w.Write([]byte("one")) //nolint:errcheck // syslog Write never fails by contract (it enqueues); the delivery outcome is read through Health()
	w.Write([]byte("two")) //nolint:errcheck // syslog Write never fails by contract (it enqueues); the delivery outcome is read through Health()

	h := w.Health()
	if h.Delivered != 2 {
		t.Errorf("Delivered = %d, want 2", h.Delivered)
	}
	if h.LastDelivery.IsZero() {
		t.Error("LastDelivery is zero after two successful deliveries — no surface can report feed liveness")
	}
	if h.Drops != 0 {
		t.Errorf("Drops = %d on a healthy feed, want 0", h.Drops)
	}
	if conn.count() != 2 {
		t.Errorf("collector received %d lines, want 2", conn.count())
	}
}

// TestChaos66_CollectorLossIsAttributedAndBounded — DEFECT gate. Loss used to
// land in one undifferentiated counter with no reason, so an operator could
// not tell a dead collector from one that is merely too slow — different
// remedies, one number.
func TestChaos66_CollectorLossIsAttributedAndBounded(t *testing.T) {
	conn := &failConn{}
	w := newTestWriter("tcp", conn)
	w.Write([]byte("delivered")) //nolint:errcheck // syslog Write never fails by contract (it enqueues); the delivery outcome is read through Health()

	conn.setFailing(true)
	for i := 0; i < 3; i++ {
		w.Write([]byte("lost")) //nolint:errcheck // syslog Write never fails by contract (it enqueues); the delivery outcome is read through Health()
	}

	h := w.Health()
	if h.DropsCollectorDown == 0 {
		t.Fatal("collector-down losses were not attributed to the collector")
	}
	if h.DropsCollectorDown != h.Drops {
		t.Errorf("DropsCollectorDown=%d but Drops=%d — the per-reason counters must sum to the aggregate", h.DropsCollectorDown, h.Drops)
	}
	if h.ConsecutiveFailures == 0 {
		t.Error("ConsecutiveFailures did not advance — nothing can verdict on how long the feed has been failing")
	}
	// The reason must be a bounded class. A raw net error would embed the
	// collector address and the ephemeral local port, which defeats alert
	// dedup by construction (WK-12/RS-5).
	switch h.LastFailureReason {
	case "write_failed", "dial_failed":
	default:
		t.Errorf("LastFailureReason = %q, want a bounded class", h.LastFailureReason)
	}
	if h.Delivered != 1 {
		t.Errorf("Delivered = %d, want 1 (the pre-outage line)", h.Delivered)
	}
}

// TestChaos66_RecoveryIsObservedNeverAssumed — a failure run is cleared only
// by a line the socket accepted, never by elapsed time. This is the
// ca_health.go / storage_health.go discipline: a feed that stopped reporting
// failures because nothing is being logged looks identical to a healthy one.
func TestChaos66_RecoveryIsObservedNeverAssumed(t *testing.T) {
	conn := &failConn{}
	w := newTestWriter("tcp", conn)

	conn.setFailing(true)
	w.Write([]byte("lost")) //nolint:errcheck // syslog Write never fails by contract (it enqueues); the delivery outcome is read through Health()
	if w.Health().ConsecutiveFailures == 0 {
		t.Fatal("failure run did not start")
	}

	// Time passing must change nothing.
	time.Sleep(5 * time.Millisecond)
	if w.Health().ConsecutiveFailures == 0 {
		t.Fatal("failure run cleared by elapsed time alone")
	}

	conn.setFailing(false)
	clearBackoff(w)
	w.Write([]byte("recovered")) //nolint:errcheck // syslog Write never fails by contract (it enqueues); the delivery outcome is read through Health()
	h := w.Health()
	if h.ConsecutiveFailures != 0 {
		t.Errorf("ConsecutiveFailures = %d after an observed delivery, want 0", h.ConsecutiveFailures)
	}
	if h.LastFailureReason != "" {
		t.Errorf("LastFailureReason = %q after recovery, want empty", h.LastFailureReason)
	}
}

// TestChaos66_ObserverIsEdgeTriggered — the observer fires on every
// collector-attributable failure and exactly once on the recovery edge, and
// NOT per delivered line. That is what makes it safe to hang a mutex-taking
// health plane off it: it costs nothing in the healthy steady state.
func TestChaos66_ObserverIsEdgeTriggered(t *testing.T) {
	conn := &failConn{}
	w := newTestWriter("tcp", conn)

	var mu sync.Mutex
	var oks, fails int
	w.SetDeliveryObserver(func(ok bool, reason string, consecutive int64) {
		mu.Lock()
		defer mu.Unlock()
		if ok {
			oks++
			return
		}
		fails++
		if reason == "" {
			t.Error("failure notification carried no reason class")
		}
		if consecutive <= 0 {
			t.Errorf("failure notification carried consecutive=%d", consecutive)
		}
	})

	// Healthy steady state: no notifications at all.
	for i := 0; i < 5; i++ {
		w.Write([]byte("ok")) //nolint:errcheck // syslog Write never fails by contract (it enqueues); the delivery outcome is read through Health()
	}
	mu.Lock()
	if oks != 0 || fails != 0 {
		t.Errorf("healthy deliveries notified (%d ok, %d fail) — the observer must be free when nothing is wrong", oks, fails)
	}
	mu.Unlock()

	conn.setFailing(true)
	for i := 0; i < 3; i++ {
		w.Write([]byte("lost")) //nolint:errcheck // syslog Write never fails by contract (it enqueues); the delivery outcome is read through Health()
	}
	mu.Lock()
	if fails != 3 {
		t.Errorf("failure notifications = %d, want 3", fails)
	}
	mu.Unlock()

	conn.setFailing(false)
	clearBackoff(w)
	w.Write([]byte("back")) //nolint:errcheck // syslog Write never fails by contract (it enqueues); the delivery outcome is read through Health()
	w.Write([]byte("back")) //nolint:errcheck // syslog Write never fails by contract (it enqueues); the delivery outcome is read through Health()
	mu.Lock()
	if oks != 1 {
		t.Errorf("recovery notifications = %d, want exactly 1 (the edge, not one per line)", oks)
	}
	mu.Unlock()
}

// TestChaos66_ObserverPanicCannotStopDelivery — an observer must never take
// down the drain goroutine, the same rule SetPanicObserver carries.
func TestChaos66_ObserverPanicCannotStopDelivery(t *testing.T) {
	conn := &failConn{}
	w := newTestWriter("tcp", conn)
	w.SetDeliveryObserver(func(bool, string, int64) { panic("observer is broken") })

	conn.setFailing(true)
	w.Write([]byte("lost")) //nolint:errcheck // syslog Write never fails by contract (it enqueues); the delivery outcome is read through Health()
	conn.setFailing(false)
	clearBackoff(w)
	w.Write([]byte("delivered")) //nolint:errcheck // syslog Write never fails by contract (it enqueues); the delivery outcome is read through Health()

	if got := w.Health().Delivered; got != 1 {
		t.Fatalf("Delivered = %d after a panicking observer, want 1 — delivery must survive a bad observer", got)
	}
}

// TestChaos66_UDPDeliveryIsReportedUnverifiable — the load-bearing gate. UDP
// is the DEFAULT transport (InitSyslog picks it when the scheme is omitted)
// and a UDP write to a blackholed collector succeeds forever, so no counter
// this package keeps can distinguish a healthy collector from one that has not
// existed for a week. Reporting the absence of observed failures as success is
// the defect; Health must state the limit.
func TestChaos66_UDPDeliveryIsReportedUnverifiable(t *testing.T) {
	udp := newTestWriter("udp", &failConn{})
	udp.Write([]byte("into the void")) //nolint:errcheck // syslog Write never fails by contract (it enqueues); the delivery outcome is read through Health()
	h := udp.Health()
	if h.DeliveryVerifiable {
		t.Error("UDP reported as verifiable — a green reading on this transport is not evidence of receipt")
	}
	if h.Drops != 0 || h.Delivered != 1 {
		t.Errorf("unexpected UDP accounting: %+v", h)
	}

	tcp := newTestWriter("tcp", &failConn{})
	if !tcp.Health().DeliveryVerifiable {
		t.Error("TCP reported as unverifiable — loss IS observable there and must be alertable")
	}
}

// TestChaos66_QueueOverflowIsNotACollectorOutage — CONTROL. A full queue means
// the collector is too SLOW for this node's log rate, not that it is gone. The
// two have different remedies, so conflating them would send an operator down
// the wrong path, and a slow collector must not advance the run the outage
// alert verdicts on.
func TestChaos66_QueueOverflowIsNotACollectorOutage(t *testing.T) {
	w := newTestWriter("tcp", &failConn{})
	w.queue = make(chan string, 1) // no drain goroutine: overflow immediately
	w.stop = make(chan struct{})
	w.done = make(chan struct{})

	for i := 0; i < 5; i++ {
		w.Write([]byte("burst")) //nolint:errcheck // syslog Write never fails by contract (it enqueues); the delivery outcome is read through Health()
	}
	h := w.Health()
	if h.DropsQueueFull == 0 {
		t.Fatal("queue overflow was not counted under its own reason")
	}
	if h.DropsCollectorDown != 0 {
		t.Errorf("queue overflow attributed to the collector (%d) — different fault, different remedy", h.DropsCollectorDown)
	}
	if h.ConsecutiveFailures != 0 {
		t.Errorf("queue overflow advanced the collector failure run (%d) — it would page for an outage that is not happening", h.ConsecutiveFailures)
	}
}

// TestChaos66_HealthyFeedStaysGreen — CONTROL. The cheapest way to pass every
// loss-visibility gate above is to report everything as degraded, which would
// page every healthy deployment. A feed that is delivering must look like one.
func TestChaos66_HealthyFeedStaysGreen(t *testing.T) {
	conn := &failConn{}
	w := newTestWriter("tcp", conn)
	for i := 0; i < 20; i++ {
		w.Write([]byte("routine")) //nolint:errcheck // syslog Write never fails by contract (it enqueues); the delivery outcome is read through Health()
	}
	h := w.Health()
	if h.Drops != 0 || h.ConsecutiveFailures != 0 || h.LastFailureReason != "" {
		t.Errorf("healthy feed reported as failing: %+v", h)
	}
	if h.Delivered != 20 || !h.DeliveryVerifiable {
		t.Errorf("healthy TCP feed misreported: %+v", h)
	}
}

// TestChaos66_FormatAndNetworkAreLockFree — DEFECT gate. Format() used to take
// s.mu, which deliverLine holds across up to two dials and two writes (~15s
// against a wedged collector). Its callers are GET /api/syslog and, by way of
// the settings snapshot, adminSettingsSave() — which every mutating admin
// handler reaches, so the management plane could stall on a log sink.
//
// Structural, not timing-based: the test HOLDS the writer mutex and requires
// both accessors (and Health, which every surface reads) to answer anyway. A
// return to a lock-guarded accessor deadlocks the gate on any hardware, at any
// load, with or without -race.
func TestChaos66_FormatAndNetworkAreLockFree(t *testing.T) {
	w := newTestWriter("tcp", &failConn{})

	w.mu.Lock()
	defer w.mu.Unlock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = w.Format()
		_ = w.Network()
		_ = w.Health()
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Format/Network/Health blocked on the writer mutex — an admin read can stall behind a wedged SIEM collector")
	}
}
