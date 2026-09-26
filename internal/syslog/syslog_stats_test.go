package syslog

import (
	"errors"
	"io"
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

// An episode whose start has NOT been published yet is reported as undated,
// never dated from the previous episode's end (Codex P1, PR #1494).
//
// noteDrop runs on the CALLER's goroutine for a queue-full drop, so several
// request goroutines reach it at once. The one whose `consecutiveFail.Add(1)`
// returns 1 can be descheduled before `failSinceNano.Store(t)` while another
// increments to 2 and invokes the observer — which reads Stats and sees a
// non-zero failure count beside a `failSince` left over from an episode that a
// delivery already ended.
//
// Stats used to CLAMP that stale value up to lastSuccess, so on a node that
// had been quiet since its last delivery the brand-new episode was dated from
// that delivery. Past the degradation window that is an immediate false DOWN
// page on the FIRST drop of a fresh episode.
//
// The window is a couple of instructions wide and cannot be scheduled from a
// test, so the invariant is driven directly through the atomics: `Stats` is a
// pure function of them, and this is the state the race produces.
func TestStats_UnpublishedEpisodeStartIsNotDatedFromTheLastDelivery(t *testing.T) {
	base := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	w := &Writer{}

	oldEpisode := base.Add(-30 * time.Minute) // an episode that has since healed
	lastSuccess := base.Add(-10 * time.Minute)

	w.failSinceNano.Store(oldEpisode.UnixNano())
	w.lastSuccessNano.Store(lastSuccess.UnixNano())
	w.delivered.Store(41)
	// The racing shape: the count is already 2 while the 0->1 goroutine has not
	// yet stored the new episode's start.
	w.consecutiveFail.Store(2)
	w.drops.Store(2)
	w.lastFailureNano.Store(base.UnixNano())

	st := w.Stats()
	if !st.FailingSince.IsZero() {
		t.Fatalf("FailingSince = %s; want the zero time — the episode start has not been published, and dating it from the last delivery (%s) makes a brand-new episode look %s old and pages immediately",
			st.FailingSince, lastSuccess, base.Sub(lastSuccess))
	}
	if st.ConsecutiveFailures != 2 {
		t.Errorf("ConsecutiveFailures = %d; want 2 — the failure itself must still be reported", st.ConsecutiveFailures)
	}

	// CONTROL: once the start IS published, the episode is dated normally.
	// Refusing to date every episode would satisfy the assertion above while
	// deleting the degradation predicate's only time axis.
	realStart := base.Add(-1 * time.Second)
	w.failSinceNano.Store(realStart.UnixNano())
	if st := w.Stats(); !st.FailingSince.Equal(realStart) {
		t.Fatalf("FailingSince = %s; want %s once the start is published", st.FailingSince, realStart)
	}

	// CONTROL: a genuinely long episode that began after the last delivery is
	// still dated from its own start, not truncated.
	longStart := lastSuccess.Add(time.Second)
	w.failSinceNano.Store(longStart.UnixNano())
	if st := w.Stats(); !st.FailingSince.Equal(longStart) {
		t.Fatalf("FailingSince = %s; want %s — a long real episode must keep its own start", st.FailingSince, longStart)
	}
}

// A failure recorded while a delivery is in flight SURVIVES that delivery
// (Codex P1, PR #1494).
//
// Queue-full drops run noteDrop on the CALLER's goroutine (tryEnqueue holds
// only sendMu), so one can land between a successful write and the clear that
// follows it. An unconditional Swap(0) discarded that loss and emitted a
// recovery notification for an episode that had not ended; if traffic then
// stopped, the watchdog saw zero consecutive failures forever and the lost
// event could never degrade the feed.
//
// The interleaving cannot be scheduled from a test, so the invariant is driven
// through the two primitives directly in the order the race produces.
func TestNoteDelivered_DoesNotClearAFailureThatRacedTheWrite(t *testing.T) {
	w := &Writer{}
	var recoveries int
	w.SetDeliveryObserver(func(delivered bool) {
		if delivered {
			recoveries++
		}
	})

	// The delivery observed a clean writer and stamped its success at the
	// instant the write was ATTEMPTED...
	failuresBefore := w.consecutiveFail.Load()
	successAt := now().UnixNano()
	// ...and a queue-full drop landed while that write was in flight.
	w.noteDrop(&reasonQueueFull)
	w.noteDelivered(failuresBefore, successAt)

	if n := w.consecutiveFail.Load(); n != 1 {
		t.Fatalf("ConsecutiveFailures = %d after a drop raced the write; want 1 — the delivery erased a loss that happened after it, so the feed can never degrade for that event", n)
	}
	if recoveries != 0 {
		t.Errorf("fired %d recovery notifications for an episode that never ended", recoveries)
	}

	// And the surviving episode is DATABLE **immediately**, with no further
	// drop to correct it. This is the half round 6 left open (Codex P1, round
	// 7): retaining the failure is worth nothing if its start cannot be
	// dated, because Stats refuses a start older than the last success and no
	// later drop takes the 0->1 edge. A node that goes quiet right here would
	// otherwise carry an unresolved failure that can never reach the
	// degradation window, while the contract row printed "FAILING NOW ...
	// failing for 0s" for as long as the silence lasted.
	st := w.Stats()
	if st.FailingSince.IsZero() {
		t.Fatalf("the surviving episode is undatable (FailingSince zero, ConsecutiveFailures %d) — it can never reach the degradation window, and no later drop will correct it", st.ConsecutiveFailures)
	}
	if st.FailingSince.Before(st.LastSuccess) {
		t.Errorf("FailingSince %v predates LastSuccess %v — Stats will refuse to date this episode", st.FailingSince, st.LastSuccess)
	}

	// A later drop keeps it datable rather than un-dating it.
	w.noteDrop(&reasonConnectFail)
	if st := w.Stats(); st.FailingSince.IsZero() {
		t.Errorf("a later drop left the episode undatable (ConsecutiveFailures %d)", st.ConsecutiveFailures)
	}

	// CONTROL: an ordinary delivery that ends a real episode still clears it
	// and still reports recovery exactly once. The cheapest way to pass the
	// assertions above is to stop clearing at all, which would latch the feed
	// as failing forever after one transient drop.
	before := w.consecutiveFail.Load()
	w.noteDelivered(before, now().UnixNano())
	if n := w.consecutiveFail.Load(); n != 0 {
		t.Fatalf("ConsecutiveFailures = %d after a clean delivery; want 0", n)
	}
	if recoveries != 1 {
		t.Errorf("fired %d recovery notifications; want exactly 1 for the episode that genuinely ended", recoveries)
	}
}

// TestNoteDelivered_ReDatesAnEpisodeThatOutlivedTheDeliveryItRacedWith is the
// OTHER interleaving that leaves an undatable start, and it does not need the
// 0->1 edge at all: an episode is already running with N failures, a delivery
// succeeds (so that episode has ENDED), and a concurrent queue-full drop makes
// the compare-and-swap fail. The survivor belongs to a NEW episode beginning at
// the delivery, but it carries the OLD episode's start — which now predates the
// last success, so Stats refuses to date it and the feed can never degrade.
//
// Driven through the primitives in the order the race produces, since the
// interleaving cannot be scheduled.
func TestNoteDelivered_ReDatesAnEpisodeThatOutlivedTheDeliveryItRacedWith(t *testing.T) {
	base := time.Date(2026, 3, 4, 10, 0, 0, 0, time.UTC)
	cur := base
	defer SetNowForTest(func() time.Time { return cur })()

	w := &Writer{}

	// An episode is running: two failures, starting at base.
	w.noteDrop(&reasonWriteFail)
	cur = base.Add(time.Second)
	w.noteDrop(&reasonWriteFail)
	failuresBefore := w.consecutiveFail.Load()
	if failuresBefore != 2 {
		t.Fatalf("setup: ConsecutiveFailures = %d, want 2", failuresBefore)
	}

	// A delivery succeeds — its success is stamped at the write, ten seconds
	// in — and a third drop lands while it is in flight, so the CAS fails.
	cur = base.Add(10 * time.Second)
	successAt := now().UnixNano()
	cur = base.Add(11 * time.Second)
	w.noteDrop(&reasonQueueFull)
	w.noteDelivered(failuresBefore, successAt)

	st := w.Stats()
	if st.ConsecutiveFailures != 3 {
		t.Fatalf("ConsecutiveFailures = %d; want 3 — the raced drop must survive the failed CAS", st.ConsecutiveFailures)
	}
	if st.FailingSince.IsZero() {
		t.Fatalf("the surviving episode is undatable — Stats refuses a start older than the last success, and no later drop takes the 0->1 edge to correct it")
	}
	if st.FailingSince.Before(st.LastSuccess) {
		t.Errorf("FailingSince %v still carries the ENDED episode's start and predates LastSuccess %v", st.FailingSince, st.LastSuccess)
	}
	// It is dated from the delivery, not from the episode the delivery ended.
	if got := st.FailingSince.UTC(); got.Before(base.Add(10 * time.Second)) {
		t.Errorf("FailingSince = %v; want no earlier than the success at %v — the old episode ended when the delivery succeeded", got, base.Add(10*time.Second))
	}
}

// TestNoteDelivered_RecordsTheWriteInstantNotTheBookkeepingInstant pins the
// half of the round-7 fix the re-date cannot cover.
//
// A delivery's success must be dated when the write was ATTEMPTED, not when
// noteDelivered happens to run. The two differ by the duration of the write,
// and in that gap a queue-full drop can be stamped on the CALLER's goroutine.
// Dating the success at the later instant makes it NEWER than that drop, which
// is the state Stats refuses to date.
//
// The re-date below it repairs the common orderings, but it cannot repair the
// one where the drop's own Store lands AFTER the re-date: there, the only
// thing that keeps the episode datable is that the drop's timestamp is
// necessarily later than the success it raced — which is true if and only if
// the success was stamped before the write. That interleaving cannot be
// scheduled from a test, so this gate pins the property it rests on instead:
// noteDelivered records the instant its CALLER supplies and never invents one.
func TestNoteDelivered_RecordsTheWriteInstantNotTheBookkeepingInstant(t *testing.T) {
	base := time.Date(2026, 3, 4, 10, 0, 0, 0, time.UTC)
	cur := base
	defer SetNowForTest(func() time.Time { return cur })()

	w := &Writer{}
	writeAt := now().UnixNano()
	// The write takes a second; bookkeeping runs after it.
	cur = base.Add(time.Second)
	w.noteDelivered(w.consecutiveFail.Load(), writeAt)

	if got, want := w.Stats().LastSuccess.UTC(), base; !got.Equal(want) {
		t.Errorf("LastSuccess = %v, want %v — the success was dated from the bookkeeping, not from the write, so any drop stamped during the write looks OLDER than it and becomes undatable", got, want)
	}
}

// TestNoteDelivered_ADropDuringASuccessfulWriteIsResolvedByIt pins which
// losses a delivery is allowed to clear, and it is decided by the CAPTURE
// POINT of the failure count.
//
// A queue-full drop runs on the CALLER's goroutine and can land while
// writeLine is blocked. That drop happened while the collector was
// demonstrably still accepting bytes — the write went on to succeed — so it is
// a real compliance loss but NOT evidence the feed is down. Reading the count
// at function ENTRY excluded it from the clear, and once round 7 made a
// surviving failure DATABLE, a node that then went idle reported DOWN five
// minutes later off the back of a delivery that had SUCCEEDED (Codex P1,
// PR #1494).
//
// Reading it after the write COMPLETED resolves it. The round-6 property is
// untouched: a drop recorded after completion still fails the compare-and-swap
// and still survives — proved by the sibling gate above.
func TestNoteDelivered_ADropDuringASuccessfulWriteIsResolvedByIt(t *testing.T) {
	base := time.Date(2026, 3, 4, 10, 0, 0, 0, time.UTC)
	cur := base
	defer SetNowForTest(func() time.Time { return cur })()

	w := &Writer{}
	var recoveries int
	w.SetDeliveryObserver(func(delivered bool) {
		if delivered {
			recoveries++
		}
	})

	// The write is attempted...
	successAt := now().UnixNano()
	// ...a queue-full drop lands WHILE it is in flight...
	cur = base.Add(10 * time.Millisecond)
	w.noteDrop(&reasonQueueFull)
	// ...and the write then completes successfully, so the count is read here.
	cur = base.Add(20 * time.Millisecond)
	w.noteDelivered(w.consecutiveFail.Load(), successAt)

	st := w.Stats()
	if st.ConsecutiveFailures != 0 {
		t.Errorf("ConsecutiveFailures = %d after a drop that PRECEDED a completed write; want 0 — the collector accepted bytes after that loss, so it is not evidence the feed is down, and an idle node would page DOWN on it", st.ConsecutiveFailures)
	}
	if !st.FailingSince.IsZero() {
		t.Errorf("FailingSince = %v; a resolved episode must carry no start", st.FailingSince)
	}
	if recoveries != 1 {
		t.Errorf("fired %d recovery notifications; want exactly 1 — the delivery did end that episode", recoveries)
	}

	// CONTROL: the loss is still COUNTED. Resolving the episode must not make
	// the compliance record forget the event — that would trade a false page
	// for a silent loss, which is the defect this whole sweep exists to remove.
	if st.Drops != 1 {
		t.Errorf("Drops = %d, want 1 — the event was lost and must stay counted", st.Drops)
	}
}

// TestDeliverLine_ResolvesADropRecordedBeforeTheWriteCompleted drives the REAL
// deliverLine, because the capture POINT is what this fix changed and the
// sibling gate above cannot see it.
//
// That gate calls noteDelivered with a count the test supplies, so it pins the
// contract ("clear exactly this count") and says nothing about which count
// deliverLine chooses to pass — which is the entire defect. Restoring the
// entry capture leaves it green. This section has had to record "walling the
// function is not walling the path" four times; this is the fifth.
//
// The drop is injected through the clock seam, which deliverLine calls exactly
// once on the happy path — to stamp successAt, immediately before the write.
// That places the loss after entry and before completion: the window an entry
// capture excludes and a completion capture includes.
func TestDeliverLine_ResolvesADropRecordedBeforeTheWriteCompleted(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close() //nolint:errcheck // test listener
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(io.Discard, c) }()
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close() //nolint:errcheck // test conn

	w := &Writer{format: "rfc3164", host: "h", tag: "culvert", pid: "1", conn: conn}

	base := time.Date(2026, 3, 4, 10, 0, 0, 0, time.UTC)
	var injected bool
	defer SetNowForTest(func() time.Time {
		// The first call is deliverLine stamping successAt, just before the
		// write. Record a queue-full drop there — exactly as a caller
		// goroutine would while the write is in flight. The guard stops
		// noteDrop's own clock read from recursing.
		if !injected {
			injected = true
			w.noteDrop(&reasonQueueFull)
		}
		return base
	})()

	w.deliverLine("<13>Sep 26 01:02:03 h culvert: probe\n")

	if !injected {
		t.Fatal("the clock seam was never reached, so no drop was injected — this gate would prove nothing")
	}
	st := w.Stats()
	if st.ConsecutiveFailures != 0 {
		t.Errorf("ConsecutiveFailures = %d after a drop recorded before the write COMPLETED; want 0.\n"+
			"deliverLine read the failure count at function ENTRY, so the delivery could not resolve it — "+
			"and once a surviving failure became datable, an idle node paged DOWN off a delivery that succeeded.",
			st.ConsecutiveFailures)
	}
	if st.Delivered != 1 {
		t.Errorf("Delivered = %d, want 1", st.Delivered)
	}
	// CONTROL: the loss is still counted. Resolving the episode must never
	// make the compliance record forget the event.
	if st.Drops != 1 {
		t.Errorf("Drops = %d, want 1 — the event was lost and must stay counted", st.Drops)
	}
}
