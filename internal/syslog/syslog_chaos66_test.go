package syslog

// CHAOS-66 — the delivery half of the SIEM forwarding sweep.
//
// Every DEFECT gate here was verified FAILING against the pre-fix tree before
// the fix was written; the shape each one targets is named in its comment. The
// CONTROLS exist because the cheapest way to pass most of these gates is to
// make the Writer permanently pessimistic — report failure, back off forever,
// never claim delivery — which would be far worse than the defect.

import (
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── fakes ───────────────────────────────────────────────────────────────────

type baseConn struct{}

func (baseConn) Read([]byte) (int, error)         { return 0, nil }
func (baseConn) Close() error                     { return nil }
func (baseConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (baseConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (baseConn) SetDeadline(time.Time) error      { return nil }
func (baseConn) SetReadDeadline(time.Time) error  { return nil }
func (baseConn) SetWriteDeadline(time.Time) error { return nil }

// okConn accepts every write.
type okConn struct {
	baseConn
	mu sync.Mutex
	n  int
}

func (c *okConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	return len(p), nil
}

// rejectConn fails every write with a timeout, i.e. a collector that accepts
// connections and then stops draining.
type rejectConn struct{ baseConn }

func (rejectConn) Write([]byte) (int, error) { return 0, errWouldBlock }

// blockingConn parks in Write until released — the wedged collector.
type blockingConn struct {
	baseConn
	release chan struct{}
	entered chan struct{}
	once    sync.Once
}

func (c *blockingConn) Write([]byte) (int, error) {
	c.once.Do(func() { close(c.entered) })
	<-c.release
	return 0, errWouldBlock
}

// newTestWriter builds a synchronous (zero-queue) Writer so the delivery state
// machine is driven directly, without racing a drain goroutine.
func newTestWriter(conn net.Conn, dial func() (net.Conn, error)) *Writer {
	return &Writer{
		network: "tcp", addr: "192.0.2.1:514",
		host: "h", tag: "culvert", format: "rfc3164", pid: "1",
		conn: conn, dialFunc: dial,
	}
}

func dialFails() (net.Conn, error) { return nil, errors.New("connection refused") }

// ── defect gates ────────────────────────────────────────────────────────────

// DEFECT: Format() took s.mu, which the drain goroutine holds across dial +
// write + write (~15 s worst case). GET /api/syslog — the page an operator
// opens BECAUSE the SIEM looks wrong — therefore hung for the whole cycle.
func TestChaos66_FormatDoesNotBlockBehindAStalledDelivery(t *testing.T) {
	block := &blockingConn{release: make(chan struct{}), entered: make(chan struct{})}
	w := newTestWriter(block, dialFails)
	w.startAsync()
	t.Cleanup(func() { close(block.release) })

	w.Write([]byte("wedged"))
	select {
	case <-block.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("setup: the drain goroutine never entered the stalled write")
	}

	done := make(chan string, 1)
	go func() { done <- w.Format() }()
	select {
	case got := <-done:
		if got != "rfc3164" {
			t.Errorf("Format() = %q, want rfc3164", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Format() blocked behind a stalled collector write; the admin surface hangs for the whole SIEM outage")
	}
}

// Same property for Stats(), which every new reporting surface calls. A health
// plane that stalls on the fault it is reporting is worse than none.
func TestChaos66_StatsDoesNotBlockBehindAStalledDelivery(t *testing.T) {
	block := &blockingConn{release: make(chan struct{}), entered: make(chan struct{})}
	w := newTestWriter(block, dialFails)
	w.startAsync()
	t.Cleanup(func() { close(block.release) })

	w.Write([]byte("wedged"))
	select {
	case <-block.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("setup: the drain goroutine never entered the stalled write")
	}

	done := make(chan Stats, 1)
	go func() { done <- w.Stats() }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stats() blocked behind a stalled collector write; /metrics and /api/diagnostics would hang during a SIEM outage")
	}
}

// DEFECT: the reconnect window was a FLAT 5 s that never grew, so a fleet
// re-dialled a down collector in lockstep for the whole outage.
func TestChaos66_ReconnectBackoffGrowsAndIsBounded(t *testing.T) {
	w := newTestWriter(nil, dialFails)

	var seen []time.Duration
	for i := 0; i < 12; i++ {
		w.retryAfter = time.Time{} // let every attempt through; we are measuring growth
		w.writeMsg(14, "line")
		seen = append(seen, w.backoff)
	}
	if seen[0] != reconnectBackoffInitial {
		t.Errorf("first backoff = %v, want %v", seen[0], reconnectBackoffInitial)
	}
	if seen[1] <= seen[0] {
		t.Errorf("backoff did not grow: %v then %v — a flat window is the pre-fix defect", seen[0], seen[1])
	}
	for i, d := range seen {
		if d > reconnectBackoffMax {
			t.Fatalf("attempt %d backoff %v exceeds the ceiling %v", i, d, reconnectBackoffMax)
		}
	}
	if last := seen[len(seen)-1]; last != reconnectBackoffMax {
		t.Errorf("backoff did not reach the ceiling after %d failures: %v", len(seen), last)
	}
}

// The jitter is what de-synchronises a fleet, so it must actually vary. A fixed
// schedule passes every "backoff grows" assertion while leaving the reconnect
// storm exactly as it was.
func TestChaos66_ReconnectBackoffIsJittered(t *testing.T) {
	const base = 10 * time.Second
	distinct := map[time.Duration]struct{}{}
	for i := 0; i < 200; i++ {
		d := jitterBackoff(base)
		if d < time.Duration(float64(base)*(1-reconnectBackoffJitter))-time.Millisecond ||
			d > time.Duration(float64(base)*(1+reconnectBackoffJitter))+time.Millisecond {
			t.Fatalf("jittered backoff %v outside ±%.0f%% of %v", d, reconnectBackoffJitter*100, base)
		}
		distinct[d] = struct{}{}
	}
	if len(distinct) < 50 {
		t.Errorf("only %d distinct delays in 200 draws; a fleet would stay in phase", len(distinct))
	}
}

// The Close-race sweep. Unlike the other gates in this file this is NOT a
// reproduced defect, and saying so is the point: the window it closes is a
// sender that passed its s.closed check before Close set it and whose buffered
// send lands AFTER the flush loop has already seen an empty queue. That
// ordering cannot be scheduled from a test — every line that arrives before the
// flush loop's default branch is drained and accounted for, which is why
// removing the sweep leaves the end-to-end accounting gate below green.
//
// So this pins the MECHANISM directly. The loss it prevents is small and rare;
// it is worth closing because it is the one place in this package where a line
// disappears without moving Drops(), and shutdown is when the last audit lines
// matter most.
func TestChaos66_SweepQueueCountsBufferedLines(t *testing.T) {
	w := newTestWriter(nil, dialFails)
	w.queue = make(chan string, queueCap)
	for i := 0; i < 7; i++ {
		w.queue <- "stranded"
	}
	w.sweepQueue()
	if got := w.Drops(); got != 7 {
		t.Errorf("Drops() = %d after sweeping 7 stranded lines, want 7", got)
	}
	if n := len(w.queue); n != 0 {
		t.Errorf("%d lines still buffered after the sweep", n)
	}
}

// The accounting invariant Close must uphold: every line handed to the Writer
// is either delivered or counted as a drop. Nothing vanishes.
func TestChaos66_CloseAccountsForEveryQueuedLine(t *testing.T) {
	const sent = 64
	ok := &okConn{}
	w := newTestWriter(ok, func() (net.Conn, error) { return ok, nil })
	w.startAsync()
	for i := 0; i < sent; i++ {
		w.Write([]byte("line"))
	}
	_ = w.Close()

	st := w.Stats()
	if got := st.Delivered + st.Drops; got != sent {
		t.Errorf("delivered(%d) + drops(%d) = %d, want %d — %d lines vanished without being counted",
			st.Delivered, st.Drops, got, sent, sent-int(got))
	}
	if n := len(w.queue); n != 0 {
		t.Errorf("%d lines still buffered after Close", n)
	}
}

// DEFECT: nothing recorded whether anything had EVER been delivered, so "the
// dial worked at boot" was the only evidence available and the health plane
// could not tell a working feed from a dead one.
func TestChaos66_DeliveryEvidenceIsRecorded(t *testing.T) {
	ok := &okConn{}
	w := newTestWriter(ok, nil)

	if st := w.Stats(); st.Delivered != 0 || !st.LastSuccess.IsZero() {
		t.Fatalf("fresh writer already claims delivery: %+v", st)
	}
	w.writeMsg(14, "one")
	st := w.Stats()
	if st.Delivered != 1 {
		t.Errorf("Delivered = %d, want 1", st.Delivered)
	}
	if st.LastSuccess.IsZero() {
		t.Error("LastSuccess is zero after a delivered line; the health plane has no evidence to report")
	}
	if st.Consecutive != 0 || !st.FirstFail.IsZero() {
		t.Errorf("healthy writer reports a failing run: %+v", st)
	}
}

// A failing run must be attributed and timed, and the reason must be one of the
// BOUNDED classes — never a raw error, which embeds the collector address and
// would give the alert dedup key one value per failure (WK-12/RS-5).
func TestChaos66_FailureEvidenceIsBoundedAndTimed(t *testing.T) {
	w := newTestWriter(&rejectConn{}, func() (net.Conn, error) { return &rejectConn{}, nil })

	w.writeMsg(14, "one")
	st := w.Stats()
	if st.Consecutive == 0 {
		t.Fatal("a failed delivery did not register as a failure")
	}
	if st.FirstFail.IsZero() {
		t.Error("FirstFail is zero during a failing run; degradation cannot be measured as a duration")
	}
	switch st.LastReason {
	case ReasonDNS, ReasonConnectTimeout, ReasonConnectFailed, ReasonWriteTimeout, ReasonWriteFailed:
	default:
		t.Errorf("LastReason = %q, which is not one of the bounded classes", st.LastReason)
	}
	if strings.Contains(st.LastReason, "192.0.2.1") {
		t.Error("the reported reason carries the collector address")
	}
}

// DEFECT: nothing distinguished "the collector is unreachable" from "the
// collector is slower than we generate events". They need different actions.
func TestChaos66_QueueOverflowIsCountedSeparately(t *testing.T) {
	block := &blockingConn{release: make(chan struct{}), entered: make(chan struct{})}
	w := newTestWriter(block, dialFails)
	w.startAsync()
	t.Cleanup(func() { close(block.release) })

	select {
	case <-block.entered:
	case <-time.After(3 * time.Second):
	}
	for i := 0; i < queueCap+64; i++ {
		w.Write([]byte("flood"))
	}
	st := w.Stats()
	if st.QueueFull == 0 {
		t.Error("queue overflow was not counted separately from a delivery failure")
	}
	if st.QueueFull > st.Drops {
		t.Errorf("QueueFull (%d) exceeds Drops (%d); overflow must be a subset of loss", st.QueueFull, st.Drops)
	}
}

// The observer is the seam the health plane learns through. It must report a
// failure and the FIRST success after one — and nothing else, because the
// healthy path runs once per proxied request.
func TestChaos66_ObserverReportsTransitionsOnly(t *testing.T) {
	ok := &okConn{}
	w := newTestWriter(ok, nil)

	var mu sync.Mutex
	var events []DeliveryOutcome
	w.SetDeliveryObserver(func(o DeliveryOutcome) {
		mu.Lock()
		events = append(events, o)
		mu.Unlock()
	})

	for i := 0; i < 5; i++ { // healthy: must produce NO events
		w.writeMsg(14, "healthy")
	}
	mu.Lock()
	n := len(events)
	mu.Unlock()
	if n != 0 {
		t.Fatalf("%d observer calls on a healthy feed; the per-request path must cost nothing", n)
	}

	w.conn = &rejectConn{}
	w.dialFunc = dialFails
	w.writeMsg(14, "fails")
	mu.Lock()
	n = len(events)
	failed := n > 0 && !events[n-1].OK
	mu.Unlock()
	if !failed {
		t.Fatalf("a delivery failure produced no observer event (events=%d)", n)
	}

	w.conn = ok
	w.retryAfter = time.Time{}
	w.dialFunc = func() (net.Conn, error) { return ok, nil }
	w.writeMsg(14, "recovers")
	mu.Lock()
	last := events[len(events)-1]
	mu.Unlock()
	if !last.OK || !last.Recovered {
		t.Errorf("the first delivery after a failing run did not report recovery: %+v", last)
	}
}

// A recovered panic in delivery must keep being contained AND counted. This is
// the CHAOS-24 contract; it is re-pinned here because the delivery path was
// restructured around it.
func TestChaos66_ObserverPanicCannotBreakDelivery(t *testing.T) {
	ok := &okConn{}
	w := newTestWriter(&rejectConn{}, func() (net.Conn, error) { return &rejectConn{}, nil })
	w.SetDeliveryObserver(func(DeliveryOutcome) { panic("observer is broken") })

	w.writeMsg(14, "one") // must not panic out of here

	w.conn = ok
	w.dialFunc = func() (net.Conn, error) { return ok, nil }
	w.retryAfter = time.Time{}
	w.writeMsg(14, "two")
	if got := w.Stats().Delivered; got != 1 {
		t.Errorf("Delivered = %d after a panicking observer; delivery must survive it", got)
	}
}

// ── controls ────────────────────────────────────────────────────────────────

// CONTROL: the cheapest way to pass every gate above is a Writer that reports
// failure unconditionally. A healthy collector must stay clean — no drops, no
// backoff, no failing run — or the health plane pages on every appliance.
func TestChaos66_Control_HealthyFeedNeverReportsFailure(t *testing.T) {
	ok := &okConn{}
	w := newTestWriter(ok, nil)
	for i := 0; i < 50; i++ {
		w.writeMsg(14, "healthy")
	}
	st := w.Stats()
	if st.Drops != 0 || st.Consecutive != 0 || st.Backoff != 0 || !st.FirstFail.IsZero() {
		t.Errorf("healthy feed reports a fault: %+v", st)
	}
	if st.Delivered != 50 {
		t.Errorf("Delivered = %d, want 50", st.Delivered)
	}
	if ok.n != 50 {
		t.Errorf("collector received %d lines, want 50", ok.n)
	}
}

// CONTROL: backoff must be cleared by OBSERVED delivery, not by elapsed time.
// A schedule that decays on its own would report a feed as recovered because
// nobody was logging to it.
func TestChaos66_Control_BackoffClearsOnlyOnObservedDelivery(t *testing.T) {
	ok := &okConn{}
	w := newTestWriter(nil, dialFails)

	w.writeMsg(14, "fails")
	if w.backoff == 0 {
		t.Fatal("setup: backoff not armed")
	}
	time.Sleep(20 * time.Millisecond) // elapsed time alone must change nothing
	if w.backoff == 0 {
		t.Error("backoff decayed on elapsed time; recovery must require evidence")
	}

	w.retryAfter = time.Time{}
	w.dialFunc = func() (net.Conn, error) { return ok, nil }
	w.writeMsg(14, "lands")
	if w.backoff != 0 {
		t.Errorf("backoff = %v after an observed delivery, want 0", w.backoff)
	}
	if got := w.Stats().Backoff; got != 0 {
		t.Errorf("Stats().Backoff = %v after recovery, want 0", got)
	}
}

// CONTROL: a fast-drop inside the backoff window must not overwrite the real
// cause with "we are backing off" — the operator needs to know WHY the feed is
// dark, and the window is a consequence, not a cause.
func TestChaos66_Control_BackoffWindowPreservesTheRealReason(t *testing.T) {
	w := newTestWriter(nil, func() (net.Conn, error) { return nil, &net.DNSError{Err: "no such host", Name: "collector.invalid"} })

	w.writeMsg(14, "one")
	first := w.Stats().LastReason
	if first != ReasonDNS {
		t.Fatalf("LastReason = %q, want %q", first, ReasonDNS)
	}
	w.writeMsg(14, "two") // inside the window: fast drop
	if got := w.Stats().LastReason; got != first {
		t.Errorf("LastReason changed to %q during the backoff window; the real cause was overwritten", got)
	}
	if got := w.Stats().Drops; got != 2 {
		t.Errorf("Drops = %d, want 2 (a fast drop is still a lost event)", got)
	}
}

// A collector that ACCEPTS connections and then stops draining dials
// successfully on every cycle. The backoff must still GROW across those cycles:
// clearing it on a successful dial pins the schedule at its first step forever,
// against exactly the overloaded collector the backoff exists to spare.
//
// This gate exists because the first draft of the CHAOS-66 fix did clear on
// dial, which made the wedged-collector case MORE aggressive than the flat 5 s
// window it replaced — found on an adversarial re-read of the diff, not by any
// other gate here.
func TestChaos66_BackoffGrowsAgainstACollectorThatAcceptsAndStalls(t *testing.T) {
	dials := 0
	w := newTestWriter(&rejectConn{}, func() (net.Conn, error) {
		dials++
		return &rejectConn{}, nil // handshake accepted, writes always fail
	})

	var seen []time.Duration
	for i := 0; i < 8; i++ {
		w.retryAfter = time.Time{} // let every cycle through; we are measuring growth
		w.writeMsg(14, "line")
		seen = append(seen, w.backoff)
	}
	if dials == 0 {
		t.Fatal("setup: the wedged-collector path never re-dialled")
	}
	if seen[len(seen)-1] <= seen[0] {
		t.Errorf("backoff did not grow across %d wedged cycles (%v … %v); a successful dial must not reset the schedule",
			len(seen), seen[0], seen[len(seen)-1])
	}
	if got := w.Stats().Delivered; got != 0 {
		t.Errorf("Delivered = %d against a collector that never accepted a line", got)
	}
}
