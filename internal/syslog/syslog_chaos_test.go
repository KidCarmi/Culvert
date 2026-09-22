package syslog

// syslog_chaos_test.go — CHAOS-66 engine gates.
//
// The root-package gates (syslog_feed_chaos_test.go) cover what the SURFACES
// report. These cover the engine contracts those surfaces rest on, including
// the two that are only reachable from inside the package.

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// pipeConn is a net.Conn whose writes can be made to fail on demand.
type pipeConn struct {
	mu      sync.Mutex
	written []byte
	fail    error
	closed  bool
}

func (c *pipeConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail != nil {
		return 0, c.fail
	}
	c.written = append(c.written, p...)
	return len(p), nil
}
func (c *pipeConn) Read([]byte) (int, error) { return 0, errors.New("no reads") }
func (c *pipeConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}
func (c *pipeConn) LocalAddr() net.Addr              { return dummyAddr{} }
func (c *pipeConn) RemoteAddr() net.Addr             { return dummyAddr{} }
func (c *pipeConn) SetDeadline(time.Time) error      { return nil }
func (c *pipeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *pipeConn) SetWriteDeadline(time.Time) error { return nil }
func (c *pipeConn) setFail(err error)                { c.mu.Lock(); c.fail = err; c.mu.Unlock() }
func (c *pipeConn) bytes() int                       { c.mu.Lock(); defer c.mu.Unlock(); return len(c.written) }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "tcp" }
func (dummyAddr) String() string  { return "192.0.2.1:514" }

func newObservedWriter(t *testing.T, conn net.Conn, dial func() (net.Conn, error)) (*Writer, *stateLog) {
	t.Helper()
	w := &Writer{
		network: "tcp", addr: "192.0.2.1:514", host: "testhost",
		tag: "culvert", format: "rfc3164", pid: "1", conn: conn, dialFunc: dial,
	}
	w.up.Store(conn != nil)
	w.stateKnown.Store(conn != nil)
	sl := &stateLog{}
	w.SetStateObserver(sl.record)
	w.startAsync()
	t.Cleanup(func() { _ = w.Close() })
	return w, sl
}

type stateLog struct {
	mu       sync.Mutex
	changes  []bool   // one entry per changed=true call
	reasons  []string // reason on each down transition
	outcomes atomic.Int64
}

func (s *stateLog) record(up bool, reason string, changed bool) {
	s.outcomes.Add(1)
	if !changed {
		return
	}
	s.mu.Lock()
	s.changes = append(s.changes, up)
	if !up {
		s.reasons = append(s.reasons, reason)
	}
	s.mu.Unlock()
}

func (s *stateLog) transitions() []bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]bool(nil), s.changes...)
}

func waitFor(t *testing.T, budget time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return cond()
}

// TestChaos66_StateObserverFiresOnTransitionsOnly pins what keeps the log one
// line per outage rather than one per dropped line. A feed carrying one line
// per proxied request would otherwise make the mitigation for a
// write-amplification defect into one itself.
func TestChaos66_StateObserverFiresOnTransitionsOnly(t *testing.T) {
	conn := &pipeConn{}
	w, sl := newObservedWriter(t, conn, func() (net.Conn, error) {
		return nil, errors.New("collector refused")
	})

	for i := 0; i < 20; i++ {
		w.WriteAudit(map[string]string{"n": "healthy"})
	}
	if !waitFor(t, 2*time.Second, func() bool { return conn.bytes() > 0 }) {
		t.Fatal("no healthy delivery observed")
	}
	if got := sl.transitions(); len(got) != 0 {
		t.Fatalf("healthy steady state must produce no transitions, got %v", got)
	}

	conn.setFail(errors.New("connection reset by peer"))
	for i := 0; i < 50; i++ {
		w.WriteAudit(map[string]string{"n": "failing"})
	}
	if !waitFor(t, 3*time.Second, func() bool { return len(sl.transitions()) >= 1 }) {
		t.Fatal("a failing collector produced no down transition")
	}
	got := sl.transitions()
	if len(got) != 1 || got[0] {
		t.Fatalf("expected exactly one down transition across 50 failing lines, got %v", got)
	}
	// Per-OUTCOME, not per-transition — the property that makes a DURATION
	// evaluable at all. Expressed as "strictly more outcomes than
	// transitions", which is the invariant itself and holds no matter how
	// much of the flood has drained when the assertion runs.
	//
	// It previously asserted an absolute count (>= the 50 lines written) and
	// CI caught that as the flake it was: waitFor returns on the FIRST
	// transition, so only part of the flood has been drained by then — a
	// loaded runner had delivered 29. An absolute quantity that depends on
	// scheduling is not the invariant; the ratio is.
	outcomes := sl.outcomes.Load()
	if outcomes <= int64(len(got)) {
		t.Fatalf("observer fired %d time(s) for %d transition(s) — it is per-TRANSITION, so a degradation duration can never be evaluated", outcomes, len(got))
	}
	if outcomes < 5 {
		t.Fatalf("observer fired only %d time(s) across a flood of failing lines; too few to establish the per-outcome contract", outcomes)
	}
}

// TestChaos66_QueueDropsAreSeparableFromDeliveryDrops: the two causes point at
// different operator actions — an unreachable collector is a network fault, a
// full queue is a collector slower than this node's entry rate.
func TestChaos66_QueueDropsAreSeparableFromDeliveryDrops(t *testing.T) {
	conn := &pipeConn{fail: errors.New("collector gone")}
	release := make(chan struct{})
	w, _ := newObservedWriter(t, conn, func() (net.Conn, error) {
		// A collector that accepts the TCP connection and then never
		// completes — the half-open/wedged-SIEM shape. The drain parks here,
		// which is what lets the bounded queue actually fill.
		<-release
		return nil, errors.New("collector refused")
	})

	if !waitFor(t, 3*time.Second, func() bool {
		w.WriteAudit(map[string]string{"n": "x"})
		return w.Drops() > 0 || len(w.queue) > 0
	}) {
		t.Fatal("nothing was enqueued")
	}
	deliveryDropsBefore := w.Drops() - w.QueueDrops()

	for i := 0; i < queueCap*2; i++ {
		w.WriteAudit(map[string]string{"n": "flood"})
	}
	if w.QueueDrops() == 0 {
		t.Fatalf("a full queue must be charged to QueueDrops (drops=%d, queued=%d)", w.Drops(), len(w.queue))
	}
	if w.QueueDrops() > w.Drops() {
		t.Fatalf("QueueDrops (%d) must be a SUBSET of Drops (%d)", w.QueueDrops(), w.Drops())
	}
	close(release)

	// And the reverse direction: delivery failures are NOT charged as queue
	// drops, so an operator can tell an unreachable collector (fix the
	// network) from a slow one (fix capacity).
	if !waitFor(t, 5*time.Second, func() bool {
		w.WriteAudit(map[string]string{"n": "y"})
		return w.Drops()-w.QueueDrops() > deliveryDropsBefore
	}) {
		t.Fatal("delivery failures were never counted separately from queue drops")
	}
}

// TestChaos66_DeferredWriterSelfHealsWithoutReconstruction is the recovery
// contract. NewWriter fails closed on the first dial and nothing in the
// process ever built a second one, so a collector down at boot meant no SIEM
// forwarding for the life of the process.
func TestChaos66_DeferredWriterSelfHealsWithoutReconstruction(t *testing.T) {
	var dials atomic.Int64
	conn := &pipeConn{}
	var refuse atomic.Bool
	refuse.Store(true)

	w := &Writer{
		network: "tcp", addr: "192.0.2.1:514", host: "h", tag: "culvert",
		format: "rfc3164", pid: "1",
		dialFunc: func() (net.Conn, error) {
			dials.Add(1)
			if refuse.Load() {
				return nil, errors.New("connection refused")
			}
			return conn, nil
		},
	}
	// Mirror NewWriterDeferred's failed-first-dial state.
	w.lastReconnErr = time.Now().Add(-reconnectBackoff) // allow an immediate retry
	w.up.Store(false)
	w.stateKnown.Store(true)
	w.startAsync()
	t.Cleanup(func() { _ = w.Close() })

	w.WriteAudit(map[string]string{"n": "while-down"})
	if !waitFor(t, 2*time.Second, func() bool { return w.Drops() > 0 }) {
		t.Fatal("expected a drop while the collector was refusing")
	}

	// The collector comes back. No reconstruction, no operator action.
	refuse.Store(false)
	if !waitFor(t, 15*time.Second, func() bool {
		w.WriteAudit(map[string]string{"n": "after-recovery"})
		return conn.bytes() > 0
	}) {
		t.Fatal("the writer never recovered after the collector returned")
	}
	if !w.Up() {
		t.Fatal("Up() must report the recovery it just observed")
	}
}

// TestChaos66_ProbeTargetReportsTheTruth: an operator-triggered connectivity
// check must be able to FAIL. Before CHAOS-66 the admin endpoint behind it
// called Write, which only enqueues.
func TestChaos66_ProbeTargetReportsTheTruth(t *testing.T) {
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = c.Read(make([]byte, 256)); _ = c.Close() }()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	verified, perr := ProbeTarget(ctx, "tcp", addr, "rfc3164")
	if !verified || perr != nil {
		t.Fatalf("probe against a live TCP collector: verified=%v err=%v", verified, perr)
	}

	_ = ln.Close()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel2()
	if _, perr = ProbeTarget(ctx2, "tcp", addr, "rfc3164"); perr == nil {
		t.Fatal("DEFECT: probe reported success against a collector that is gone")
	}

	// UDP can never be verified — a connected socket's write succeeds locally.
	ctx3, cancel3 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel3()
	verified, perr = ProbeTarget(ctx3, "udp", "192.0.2.77:514", "rfc3164")
	if verified {
		t.Fatal("DEFECT: a UDP probe must never report itself as verified")
	}
	if perr != nil {
		t.Fatalf("a UDP probe should still send: %v", perr)
	}
}

// TestChaos66_ObserverPanicNeverStopsDelivery: the observer runs arbitrary
// caller code on the single drain goroutine that owns every network write.
func TestChaos66_ObserverPanicNeverStopsDelivery(t *testing.T) {
	conn := &pipeConn{}
	w := &Writer{
		network: "tcp", addr: "192.0.2.1:514", host: "h", tag: "culvert",
		format: "rfc3164", pid: "1", conn: conn,
	}
	w.SetStateObserver(func(bool, string, bool) { panic("observer is hostile") })
	w.startAsync()
	t.Cleanup(func() { _ = w.Close() })

	for i := 0; i < 10; i++ {
		w.WriteAudit(map[string]string{"n": "x"})
	}
	if !waitFor(t, 2*time.Second, func() bool { return conn.bytes() > 0 }) {
		t.Fatal("a panicking observer stopped delivery")
	}
}

// TestChaos66_DeliveryVerifiableIsTransportDerived pins the honesty gauge to
// the transport, not to whatever the last write happened to return.
func TestChaos66_DeliveryVerifiableIsTransportDerived(t *testing.T) {
	for _, tc := range []struct {
		network string
		want    bool
	}{{"udp", false}, {"tcp", true}} {
		w := &Writer{network: tc.network}
		if got := w.DeliveryVerifiable(); got != tc.want {
			t.Errorf("%s: DeliveryVerifiable() = %v, want %v", tc.network, got, tc.want)
		}
	}
}

// TestChaos66_QueueSaturationIsObservableWhileDeliverySucceeds pins the fault
// Codex found in review (PR #1461): delivery succeeding is not the same as
// entries arriving.
//
// A collector that stays writable but drains slower than producers sheds lines
// in send()'s queue-full branch while every drain outcome is a success. Before
// the fix that was counted and nothing else: Up() stayed true, so the health
// record stayed clean, the contract row read "delivering" and described the
// loss as having happened "earlier", and neither the degradation gauge nor the
// alert fired. Same reporting error as SL-2, for the commoner fault.
func TestChaos66_QueueSaturationIsObservableWhileDeliverySucceeds(t *testing.T) {
	// slowConn (syslog_bench_test.go) models a congested collector: every
	// write SUCCEEDS, each taking ~200µs to drain. Reused rather than
	// redefined — it already models exactly this fault.
	conn := &slowConn{}
	w, sl := newObservedWriter(t, conn, func() (net.Conn, error) { return conn, nil })

	// Outrun the drain until the bounded queue sheds.
	for i := 0; i < queueCap*3 && w.QueueDrops() == 0; i++ {
		w.WriteAudit(map[string]string{"n": "flood"})
	}
	if w.QueueDrops() == 0 {
		t.Fatalf("the queue never shed (drops=%d) — the flood did not outrun the drain", w.Drops())
	}

	// The contract the fix rests on: delivery is UP and entries are being lost.
	if !w.Up() {
		t.Skip("the drain fell over rather than merely lagging; this gate needs a SUCCEEDING drain")
	}
	if !w.QueueSaturatedSince(time.Now().Add(-syslogTestSaturationWindow)) {
		t.Fatal("DEFECT: the writer is shedding entries but reports no recent queue saturation")
	}
	// The observer must still be seeing SUCCESSES — that is what made this
	// invisible, and the gate is worthless if the drain is actually failing.
	if n := sl.outcomes.Load(); n == 0 {
		t.Fatal("no delivery outcomes observed")
	}

	// And it must clear on its own once the flood stops: saturation is a RATE
	// condition, so it needs no clearing path that could be forgotten.
	if w.QueueSaturatedSince(time.Now().Add(time.Second)) {
		t.Fatal("saturation must be scoped to a window, not latched")
	}
}

// syslogTestSaturationWindow mirrors the root package's
// syslogQueueSaturationWindow; this package cannot import it.
const syslogTestSaturationWindow = 10 * time.Second
