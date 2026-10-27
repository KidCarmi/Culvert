package syslog

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
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

// DEFECT GATE. Before CHAOS-81 the engine exposed only a cumulative Drops()
// counter: there was no way for any surface to answer "is the feed delivering
// RIGHT NOW?", which is why every health surface either had nothing to read or
// reported init-time state. Delivery must carry a timestamp.
func TestChaos81_DeliverySetsLastSuccess(t *testing.T) {
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
func TestChaos81_EveryDropCarriesABoundedReason(t *testing.T) {
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
func TestChaos81_ConsecutiveFailuresResetOnDelivery(t *testing.T) {
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
func TestChaos81_DeliveryObserverFiresOnDropAndOnRecoveryEdge(t *testing.T) {
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
func TestChaos81_HealthyFeedIsUnchangedAndSilent(t *testing.T) {
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
func TestChaos81_PanickingObserverCannotKillDelivery(t *testing.T) {
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
func TestChaos81_StatsIsReadableWhileTheWriteLockIsHeld(t *testing.T) {
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
	// ONE, not three. The raced drop must survive — that is round 6's
	// property and the reason this interleaving matters — but the two
	// failures the delivery OBSERVED preceded its completion and are
	// resolved by it. This assertion read `want 3` until Codex round 15,
	// which is the all-or-nothing CAS's arithmetic rather than the rule:
	// note that the prose above this function already says "the survivor
	// belongs to a NEW episode beginning at the delivery" — singular — so
	// the test documented the correct model and pinned the wrong number.
	if st.ConsecutiveFailures != 1 {
		t.Fatalf("ConsecutiveFailures = %d; want 1 — the raced drop survives, the two the delivery resolved do not", st.ConsecutiveFailures)
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
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
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

	conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", ln.Addr().String())
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

// TestNoteDelivered_ResolvesOnlyTheFailuresItObserved is the DEFECT gate for
// Codex round 15: a delivery resolves every loss that preceded its completion
// (round 8), and the all-or-nothing CompareAndSwap implemented that rule only
// when nothing raced it. When a queue-full drop landed between the count being
// read and the swap, the swap failed and kept EVERY failure — including the
// prefix the delivery had just proved resolved — so every later snapshot
// reported those as losses since the delivery and inflated the current
// episode on the contract row and the admin surface.
//
// The degradation predicate is a boolean over this count, so the page was
// never wrong; the number an operator acts on was.
func TestNoteDelivered_ResolvesOnlyTheFailuresItObserved(t *testing.T) {
	base := time.Date(2026, 3, 4, 10, 0, 0, 0, time.UTC)
	cur := base
	defer SetNowForTest(func() time.Time { return cur })()

	for _, tc := range []struct {
		name      string
		before    int // failures already unresolved when the delivery reads the count
		racing    int // queue-full drops landing between that read and the resolve
		wantAfter uint64
	}{
		{"nothing races, the episode ends", 4, 0, 0},
		{"one drop races a long episode", 7, 1, 1},
		{"several race", 3, 2, 2},
		{"a single failure, nothing races", 1, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := &Writer{}
			for i := 0; i < tc.before; i++ {
				w.noteDrop(&reasonWriteFail)
			}
			failuresBefore := w.consecutiveFail.Load()

			cur = base.Add(10 * time.Second)
			successAt := now().UnixNano()
			cur = base.Add(11 * time.Second)
			for i := 0; i < tc.racing; i++ {
				w.noteDrop(&reasonQueueFull)
			}
			w.noteDelivered(failuresBefore, successAt)

			if got := w.Stats().ConsecutiveFailures; got != tc.wantAfter {
				t.Fatalf("ConsecutiveFailures = %d, want %d: a delivery resolves exactly the "+
					"failures that preceded it and leaves exactly those recorded after", got, tc.wantAfter)
			}
		})
	}
}

// TestNoteDelivered_CannotUnderflowTheFailureCount is the CONTROL on the clamp.
// A wrapped uint64 is not a smaller error than an inflated count: it is a
// permanently non-zero failure count, i.e. a feed reported as failing for the
// life of the process. Today only the single drain goroutine decreases the
// counter so this cannot arise, but that is an argument about a CALLER, and
// the standing lesson of this file is that such arguments get invalidated
// silently.
func TestNoteDelivered_CannotUnderflowTheFailureCount(t *testing.T) {
	w := &Writer{}
	w.noteDrop(&reasonWriteFail)
	// Claim to have observed far more failures than were ever recorded.
	w.noteDelivered(50, now().UnixNano())
	if got := w.Stats().ConsecutiveFailures; got != 0 {
		t.Fatalf("ConsecutiveFailures = %d, want 0: the resolve must clamp, never wrap", got)
	}
}

// ── A folding consumer reads one cumulative value, not two ───────────────────
//
// A Writer carries TWO cumulative values: the live counters and the sealed
// finals. The live ones deliberately keep moving after the seal, and every
// post-seal loss is ALSO charged to lateDrops. So the two diverge by exactly
// the losses lateDrops already holds, and a consumer that folds the live value
// after the seal counts them twice — then has the next fold reversed by the
// smaller sealed snapshot, making an exported counter DECREASE (Codex P2,
// PR #1494).

// The divergence itself, which is what makes a two-read consumer unsafe.
func TestSealedAndLiveCumulativeValuesDiverge(t *testing.T) {
	ResetLateDropsForTest()
	t.Cleanup(ResetLateDropsForTest)

	w := &Writer{network: "udp", format: "rfc3164", host: "h", tag: "culvert", pid: "1", queue: make(chan queuedLine, 1)}
	w.MarkRetired()
	w.noteDrop(&reasonQueueFull) // before the seal

	// Seal exactly as the drain does: finals published under sendMu.
	w.sendMu.Lock()
	final := w.Stats()
	w.finalStats.Store(&final)
	w.sendMu.Unlock()

	// A stale handle charges a loss after the seal. The engine routes it to
	// lateDrops, and the Writer's own counters move too.
	// Exactly as send/handOffQueued do it: chargeTerminalDrop REPORTS that the
	// loss belongs to the process-lifetime counter, and the caller charges it.
	if late := w.chargeTerminalDrop(&reasonClosed); late {
		noteLateDrop()
	} else {
		t.Fatal("precondition: a post-seal loss on a retired writer must be routed to lateDrops")
	}

	sealed, ok := w.FinalStats()
	if !ok {
		t.Fatal("precondition: the writer must report sealed")
	}
	live := w.Stats()
	if live.Drops <= sealed.Drops {
		t.Fatalf("precondition: the live counters must exceed the sealed finals after a post-seal loss (live=%d sealed=%d)", live.Drops, sealed.Drops)
	}
	if got := LateDrops(); got != 1 {
		t.Fatalf("lateDrops = %d, want 1 — the post-seal loss is already held there, so folding the live value counts it twice", got)
	}
}

// CumulativeStats answers with ONE of the two, so a folded value is never
// succeeded by a smaller one.
func TestCumulativeStatsPrefersTheSealedFinals(t *testing.T) {
	ResetLateDropsForTest()
	t.Cleanup(ResetLateDropsForTest)

	w := &Writer{network: "udp", format: "rfc3164", host: "h", tag: "culvert", pid: "1", queue: make(chan queuedLine, 1)}
	w.MarkRetired()
	w.noteDrop(&reasonQueueFull)
	w.sendMu.Lock()
	final := w.Stats()
	w.finalStats.Store(&final)
	w.sendMu.Unlock()
	if late := w.chargeTerminalDrop(&reasonClosed); late {
		noteLateDrop()
	}

	cur, sealed := w.CumulativeStats()
	if !sealed {
		t.Fatal("CumulativeStats did not report a sealed writer as sealed")
	}
	if cur.Drops != final.Drops {
		t.Fatalf("CumulativeStats returned Drops=%d for a sealed writer, want the finals' %d — folding the live value double-counts the loss lateDrops already holds",
			cur.Drops, final.Drops)
	}
}

// CONTROL: before the seal it must report the LIVE counters, or a displaced
// writer's losses stop being folded at all while its drain is still flushing —
// which is the loss-history erasure the sealing boundary exists to prevent.
func TestCumulativeStatsReportsLiveCountersBeforeSealing(t *testing.T) {
	w := &Writer{network: "udp", format: "rfc3164", host: "h", tag: "culvert", pid: "1", queue: make(chan queuedLine, 1)}
	w.noteDrop(&reasonQueueFull)
	w.noteDrop(&reasonQueueFull)

	cur, sealed := w.CumulativeStats()
	if sealed {
		t.Fatal("reported an unsealed writer as sealed")
	}
	if cur.Drops != 2 {
		t.Fatalf("CumulativeStats returned Drops=%d before sealing, want the live 2", cur.Drops)
	}
}

// ── CumulativeStats takes no lock, and reads the live value FIRST ────────────
//
// The first shape of CumulativeStats read the seal flag and the counters under
// sendMu.RLock. That is exact, and it DEADLOCKS. Both folding consumers
// (retireSyslogWriterLocked, settleRetiredSyslogWritersLocked) run with the
// health plane's mutex held, while a line this Writer refuses charges its drop
// from tryEnqueue — holding sendMu.RLock — and notifies the delivery observer
// from there, which takes that same health mutex. Two read locks coexist, so
// the inversion looks harmless until a Close() is waiting on sendMu.Lock: Go's
// RWMutex then stops new readers barging in, and the three edges close a
// cycle. Measured, not reasoned: the concurrent re-point gate hung to the test
// timeout, and the dump named all three edges on one Writer.
//
// Walled structurally because the alternative gate is a hang — the most
// expensive failure a suite can have (it costs the whole package's timeout and
// reports no test name without reading a stack dump), and the cycle needs a
// Close() parked between a reader and the fold to appear at all. The property
// is also exactly a source property: this function may take no lock, however
// briefly, because it is called from under the very mutex this Writer's
// delivery observer goes on to take.
//
// The ordering half is pinned here too, and it is the reason the lock is not
// needed: reading the live counters BEFORE loading the seal means an absent
// seal proves the Writer had not sealed at the earlier read either, so the
// live value predates the finals and can never exceed them. The reverse order
// is the original defect (Codex P2, PR #1494).
func TestCumulativeStatsTakesNoLockAndReadsLiveFirst(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "syslog.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse syslog.go: %v", err)
	}
	var fd *ast.FuncDecl
	for _, d := range f.Decls {
		if d, ok := d.(*ast.FuncDecl); ok && d.Name.Name == "CumulativeStats" {
			fd = d
			break
		}
	}
	if fd == nil {
		t.Fatal("CumulativeStats is gone; this wall names a function that no longer exists")
	}

	liveAt, sealAt := -1, -1
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch sel.Sel.Name {
		case "Lock", "RLock", "TryLock", "TryRLock":
			t.Errorf("CumulativeStats calls %s() at %s\n\t"+
				"it runs with syslogHealth.mu held, and this package's own drop path takes that mutex "+
				"while holding sendMu — any lock here closes a three-way cycle with a parked Close() "+
				"(Codex P2, PR #1494)",
				sel.Sel.Name, fset.Position(call.Pos()).String())
		case "Stats":
			if liveAt < 0 {
				liveAt = int(call.Pos())
			}
		case "Load":
			// s.finalStats.Load(); any other Load in here would be a new
			// field this wall has not been taught about, and ordering it
			// against the live read is the conservative answer anyway.
			if sealAt < 0 {
				sealAt = int(call.Pos())
			}
		}
		return true
	})
	if liveAt < 0 {
		t.Fatal("CumulativeStats no longer reads the live counters; the unsealed answer cannot be correct")
	}
	if sealAt < 0 {
		t.Fatal("CumulativeStats no longer loads the seal; it cannot report whether the writer sealed")
	}
	if liveAt > sealAt {
		t.Errorf("CumulativeStats loads the seal (%s) BEFORE reading the live counters (%s)\n\t"+
			"that is the original defect: a seal landing between the two makes the fallback return a "+
			"post-seal live value, already counted in lateDrops and larger than the finals the next "+
			"settle reads — so culvert_syslog_drops_total decreases",
			fset.Position(token.Pos(sealAt)).String(), fset.Position(token.Pos(liveAt)).String())
	}
}

// CONTROL: the matcher must be able to SEE the locks it forbids, or a broken
// AST walk passes forever. tryEnqueue takes sendMu.RLock on purpose — that is
// what makes "check closed, then enqueue" atomic against Close.
func TestLockMatcherSeesTheLocksItForbids(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "syslog.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse syslog.go: %v", err)
	}
	var fd *ast.FuncDecl
	for _, d := range f.Decls {
		if d, ok := d.(*ast.FuncDecl); ok && d.Name.Name == "tryEnqueue" {
			fd = d
			break
		}
	}
	if fd == nil {
		t.Fatal("tryEnqueue is gone; pick another positive sample whose job IS to hold sendMu")
	}
	found := false
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "RLock" {
			found = true
		}
		return true
	})
	if !found {
		t.Fatal("control: the walk cannot find RLock in tryEnqueue, so the wall above proves nothing")
	}
}

// ── A failure start is published only while its episode is still current ─────
//
// noteDrop runs on the CALLER's goroutine for a queue-full drop, so its two
// halves can be split by the scheduler: claimEpisodeStart records the failure
// and reports the 0->1 edge, publishEpisodeStart publishes the start. A caller
// descheduled between them resumes after a delivery has ENDED its episode and
// a later drop has correctly dated a NEW one.
//
// Publishing unconditionally there overwrites the good start with a stale,
// pre-success value. Stats refuses it (its `fs >= ls` test fails), so an
// outage with ConsecutiveFailures > 0 has NO datable start — and because
// noteDrop's re-dating branch only runs on a SUBSEQUENT drop, a node that goes
// quiet never recovers the date. FailingFor stays 0, the degradation window
// can never elapse, and that outage is never paged (Codex P2, PR #1494).
//
// The reader was already hardened for the opposite order (it refuses a stale
// start rather than clamping it up — Codex P1, earlier in this sweep). This is
// the writer half of the same window: the reader cannot help once the good
// value is gone.
//
// No structural wall accompanies this one, and that is a measured decision
// rather than an omission. Round 19's fix was a PLACEMENT, which its
// behavioural gate could not pin; this fix is a VALUE the interleaving reads,
// so the gate below catches every way of getting it wrong — verified by
// mutation: ignoring the witness, never publishing, and loading the witness
// inside publishEpisodeStart (the tautology) each turn it red.
func TestNoteDrop_StaleEdgePublicationCannotOrphanTheEpisode(t *testing.T) {
	var clock time.Time
	restore := SetNowForTest(func() time.Time { return clock })
	t.Cleanup(restore)

	w := &Writer{network: "udp", format: "rfc3164", host: "h", tag: "culvert", pid: "1", queue: make(chan queuedLine, 1)}
	base := time.Unix(1_700_000_000, 0)

	// A reaches noteDrop, takes the 0->1 edge, and is descheduled before it
	// publishes.
	clock = base
	witnessA, edgeA := w.claimEpisodeStart()
	staleStart := clock.UnixNano()
	if !edgeA {
		t.Fatal("precondition: A must take the 0->1 edge")
	}

	// The drain delivers a line. A's episode is resolved.
	clock = base.Add(1 * time.Second)
	w.noteDelivered(1, clock.UnixNano())
	if cf := w.consecutiveFail.Load(); cf != 0 {
		t.Fatalf("precondition: the delivery must end A's episode, consecutiveFail = %d", cf)
	}

	// A NEW outage begins and dates itself correctly.
	clock = base.Add(2 * time.Second)
	realStart := clock
	w.noteDrop(&reasonQueueFull)
	if st := w.Stats(); !st.FailingSince.Equal(realStart) {
		t.Fatalf("precondition: the new episode must be dated %s before A resumes, got %s", realStart, st.FailingSince)
	}

	// A resumes and runs the second half with the timestamp it computed before
	// the delivery. Traffic then stops: nothing else will re-date the episode.
	w.publishEpisodeStart(staleStart, witnessA)

	st := w.Stats()
	if st.ConsecutiveFailures == 0 {
		t.Fatal("precondition: the outage must still be unresolved")
	}
	if st.FailingSince.IsZero() {
		t.Fatalf("an ongoing outage (ConsecutiveFailures = %d) has no datable start: FailingFor stays 0, so the degradation window can never elapse and the outage is never paged",
			st.ConsecutiveFailures)
	}
	if !st.FailingSince.Equal(realStart) {
		t.Errorf("FailingSince = %s; want %s — A's stale start must not displace the episode that is actually running", st.FailingSince, realStart)
	}
}

// CONTROL: an ordinary drop, with nothing racing it, must still publish and
// date its episode. Refusing to publish at all satisfies the gate above while
// deleting the degradation predicate's only time axis — and the reader-side
// controls in TestStats_UnpublishedEpisodeStartIsNotDatedFromTheLastDelivery do NOT cover it,
// because they store failSinceNano directly rather than going through noteDrop
// (measured before this control existed: with publication removed, every
// reader-side gate stayed green and only the gate above went red).
func TestNoteDrop_AnUnracedEdgeDatesItsEpisode(t *testing.T) {
	var clock time.Time
	restore := SetNowForTest(func() time.Time { return clock })
	t.Cleanup(restore)

	w := &Writer{network: "udp", format: "rfc3164", host: "h", tag: "culvert", pid: "1", queue: make(chan queuedLine, 1)}
	clock = time.Unix(1_700_000_000, 0)

	w.noteDrop(&reasonQueueFull)
	st := w.Stats()
	if st.FailingSince.IsZero() {
		t.Fatal("a plain first drop published no episode start; the feed can never become degradable")
	}
	if !st.FailingSince.Equal(clock) {
		t.Errorf("FailingSince = %s; want %s", st.FailingSince, clock)
	}
}

// CONTROL, the other direction: a drop that follows a delivery must date the
// NEW episode. A witness keyed too broadly — one that never matches — would
// refuse every publication after the first delivery, which is the same
// undatable outage by a different route.
func TestNoteDrop_ADropAfterADeliveryDatesTheNewEpisode(t *testing.T) {
	var clock time.Time
	restore := SetNowForTest(func() time.Time { return clock })
	t.Cleanup(restore)

	w := &Writer{network: "udp", format: "rfc3164", host: "h", tag: "culvert", pid: "1", queue: make(chan queuedLine, 1)}
	base := time.Unix(1_700_000_000, 0)

	clock = base
	w.noteDrop(&reasonQueueFull)
	clock = base.Add(1 * time.Second)
	w.noteDelivered(1, clock.UnixNano())

	clock = base.Add(2 * time.Second)
	w.noteDrop(&reasonQueueFull)
	st := w.Stats()
	if st.FailingSince.IsZero() {
		t.Fatal("the episode after a delivery was never dated; the witness refuses legitimate publications")
	}
	if !st.FailingSince.Equal(clock) {
		t.Errorf("FailingSince = %s; want %s — the new episode starts at its own first drop", st.FailingSince, clock)
	}
}
