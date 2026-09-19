package syslog

// CHAOS-66 engine-side gates: loss classification, delivery evidence, and the
// one structural property the whole health plane rests on (the accessors must
// never take the delivery mutex).

import (
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// failingConn (a collector that accepts the handshake and then never drains)
// is defined in syslog_deadline_test.go and reused here rather than
// duplicated — one fake, one behaviour.

// newTestWriter builds a Writer with an injected dialer, bypassing the network.
func newTestWriter(t *testing.T, dial func() (net.Conn, error)) *Writer {
	t.Helper()
	return &Writer{
		network:  "tcp",
		addr:     "collector.test:514",
		host:     "node",
		tag:      "culvert",
		format:   "rfc5424",
		pid:      "1",
		dialFunc: dial,
	}
}

// TestDropReasons_AreExhaustive pins that every exported DropReason has a
// counter slot.
//
// A reason declared but absent from dropReasons would be counted into the
// total and never reported per-class — this sweep's own finding (loss the
// operator cannot see), reproduced one level down inside the mechanism that
// exists to prevent it.
func TestDropReasons_AreExhaustive(t *testing.T) {
	declared := []DropReason{
		DropCollectorUnreachable,
		DropWriteFailed,
		DropQueueFull,
		DropWriterClosed,
		DropDeliveryPanic,
	}
	for _, r := range declared {
		if dropIndex(r) < 0 {
			t.Errorf("DropReason %q has no counter slot in dropReasons — it would be counted in the total and never reported by class", r)
		}
	}
	if len(declared) != len(dropReasons) {
		t.Errorf("dropReasons has %d slots but %d reasons are declared; a mismatch means a class is unreported or a slot is dead", len(dropReasons), len(declared))
	}
}

// TestNoteDrop_ChargesTotalAndReason pins that the per-class counters
// reconcile with the total. A breakdown that does not sum to the total is
// worse than no breakdown: it invites an operator to conclude that the
// unaccounted difference went somewhere benign.
func TestNoteDrop_ChargesTotalAndReason(t *testing.T) {
	var w Writer
	for i := 0; i < 3; i++ {
		w.noteDrop(DropCollectorUnreachable)
	}
	w.noteDrop(DropQueueFull)
	w.noteDrop(DropWriterClosed)

	if got := w.Drops(); got != 5 {
		t.Fatalf("Drops() = %d, want 5", got)
	}
	by := w.DropsByReason()
	var sum uint64
	for _, n := range by {
		sum += n
	}
	if sum != w.Drops() {
		t.Errorf("per-reason counters sum to %d but Drops() = %d", sum, w.Drops())
	}
	if by[DropCollectorUnreachable] != 3 || by[DropQueueFull] != 1 || by[DropWriterClosed] != 1 {
		t.Errorf("wrong per-reason breakdown: %+v", by)
	}
}

// TestDeliveryEpisode_ArmsOnceAndClearsOnObservedSuccess pins the episode
// lifecycle and, with it, the once-per-episode observer contract.
func TestDeliveryEpisode_ArmsOnceAndClearsOnObservedSuccess(t *testing.T) {
	var w Writer
	var mu sync.Mutex
	var events []DeliveryEvent
	w.SetDeliveryObserver(func(ev DeliveryEvent) {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
	})

	if !w.FailingSince().IsZero() {
		t.Fatal("a fresh Writer must not be in a failure episode")
	}
	for i := 0; i < 10; i++ {
		w.noteDrop(DropCollectorUnreachable)
	}
	// In production the transition is STAGED under s.mu and flushed by
	// deliverLine after it unlocks (see stageDelivery). These direct calls are
	// not inside that lock, so the flush is explicit here.
	w.flushPendingDelivery()
	if w.FailingSince().IsZero() {
		t.Fatal("ten reachability drops did not open a failure episode")
	}
	if w.LastFailureReason() != DropCollectorUnreachable {
		t.Errorf("LastFailureReason() = %q, want %q", w.LastFailureReason(), DropCollectorUnreachable)
	}

	mu.Lock()
	n := len(events)
	mu.Unlock()
	if n != 1 {
		t.Fatalf("observer fired %d times for one episode; it must fire once per TRANSITION, not per line (an observer that logs or alerts would otherwise run at request rate)", n)
	}

	w.noteDeliverySuccess()
	w.flushPendingDelivery()
	if !w.FailingSince().IsZero() {
		t.Error("an observed delivery did not clear the episode")
	}
	if w.LastDelivery().IsZero() {
		t.Error("an observed delivery did not stamp LastDelivery — the health plane has no evidence to recover on")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2 (failing, recovered)", len(events))
	}
	if events[1].State != DeliveryRecovered {
		t.Errorf("second event state = %v, want DeliveryRecovered", events[1].State)
	}
	if events[1].Drops != 10 {
		t.Errorf("recovery event reported %d drops, want 10 — the episode's magnitude must reach the observer", events[1].Drops)
	}
}

// TestQueueFullDoesNotArmADeliveryEpisode is a CONTROL.
//
// The cheapest way to make a SIEM-outage detector look sensitive is to arm it
// on every kind of loss. A full queue is NOT evidence about the collector — it
// says the drain could not keep up, which on a healthy but under-provisioned
// link is a capacity fact, and during a shutdown race is nothing at all.
// Arming on it would page for an ordinary burst and would misattribute the
// cause in the alert Detail an operator acts on.
func TestQueueFullDoesNotArmADeliveryEpisode(t *testing.T) {
	for _, reason := range []DropReason{DropQueueFull, DropWriterClosed, DropDeliveryPanic} {
		var w Writer
		fired := false
		w.SetDeliveryObserver(func(DeliveryEvent) { fired = true })
		w.noteDrop(reason)
		w.flushPendingDelivery()
		if !w.FailingSince().IsZero() {
			t.Errorf("%s opened a delivery episode; it is not evidence about the collector", reason)
		}
		if fired {
			t.Errorf("%s notified the delivery observer; it would page as a SIEM outage", reason)
		}
		if w.Drops() != 1 {
			t.Errorf("%s was not counted at all (Drops()=%d) — not arming an episode must not mean not counting", reason, w.Drops())
		}
	}
}

// TestObservability_AccessorsDoNotTakeTheDeliveryMutex is the STRUCTURAL gate
// the entire health plane rests on.
//
// s.mu is held by the drain goroutine across the whole reconnect/backoff state
// machine — writeTimeout + dial + writeTimeout, about 15 seconds against a
// collector that accepts and never drains. If any accessor the health plane
// reads took that mutex, a /metrics scrape or a /healthz probe would BLOCK for
// fifteen seconds on precisely the fault it exists to report, turning a SIEM
// outage into a monitoring outage.
//
// Structural rather than timing-based on purpose: it holds the lock and
// requires the accessors to answer anyway, so a return to mutex-guarded state
// fails deterministically on any hardware, at any load, with or without -race.
// A ratio gate was rejected for the reason connlimit's and the histogram's
// were — a gate that can flake gets muted.
func TestObservability_AccessorsDoNotTakeTheDeliveryMutex(t *testing.T) {
	var w Writer
	w.noteDrop(DropCollectorUnreachable)
	w.noteDeliverySuccess()

	w.mu.Lock()
	defer w.mu.Unlock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = w.Drops()
		_ = w.Panics()
		_ = w.DropsByReason()
		_ = w.LastDelivery()
		_ = w.FailingSince()
		_ = w.LastFailureReason()
		_ = w.DeliveryConfirmable()
		_ = w.Network()
		_ = w.QueueCap()
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("a health accessor blocked on s.mu — a /metrics scrape would stall for the length of a wedged collector's write+dial cycle, turning a SIEM outage into a monitoring outage")
	}
}

// TestDeliveryConfirmable_IsFalseOnUDP pins the honesty signal.
//
// UDP is the DEFAULT transport. A connected UDP socket to a collector that
// does not exist accepts every write, so no counter in this package can ever
// see that loss. Reporting `up` for such a feed is only defensible while the
// surfaces also say that "up" means the socket is open, and this accessor is
// what lets them. Do not make this return true for UDP to tidy a dashboard.
func TestDeliveryConfirmable_IsFalseOnUDP(t *testing.T) {
	if (&Writer{network: "udp"}).DeliveryConfirmable() {
		t.Error("UDP reported as delivery-confirmable; nothing in this package can observe a UDP delivery failure")
	}
	if !(&Writer{network: "tcp"}).DeliveryConfirmable() {
		t.Error("TCP reported as NOT delivery-confirmable; a refused connect and a failed write are real signals")
	}
}

// TestJitteredReconnectWindow_StaysWithinBand pins that the reconnect
// suppression window is spread but still bounded.
//
// A SIEM outage is a FLEET event: every node's collector goes away at the same
// instant, so an unjittered fixed window has the whole estate retrying in
// lockstep and hitting the recovering collector in one burst. Jitter must
// spread the attempts WITHOUT changing the direction of the bound.
func TestJitteredReconnectWindow_StaysWithinBand(t *testing.T) {
	lo := time.Duration(float64(reconnectWindow) * (1 - jitterFraction))
	hi := time.Duration(float64(reconnectWindow) * (1 + jitterFraction))
	distinct := map[time.Duration]struct{}{}
	for i := 0; i < 500; i++ {
		d := jitteredReconnectWindow()
		if d < lo || d > hi {
			t.Fatalf("jitteredReconnectWindow() = %v, outside [%v, %v]", d, lo, hi)
		}
		distinct[d] = struct{}{}
	}
	if len(distinct) < 100 {
		t.Errorf("only %d distinct windows in 500 draws — the jitter is degenerate and the fleet would still retry in lockstep", len(distinct))
	}
}

// TestDeliveryObserver_PanicIsContained pins that a bad observer cannot take
// down the drain goroutine, which owns the collector socket for the process.
func TestDeliveryObserver_PanicIsContained(t *testing.T) {
	var w Writer
	w.SetDeliveryObserver(func(DeliveryEvent) { panic("observer is broken") })
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("a panicking delivery observer escaped containment: %v", r)
		}
	}()
	w.noteDrop(DropCollectorUnreachable)
	w.flushPendingDelivery()
	if w.FailingSince().IsZero() {
		t.Error("the episode was not recorded when the observer panicked; containment must not lose the state")
	}
}

// TestDeliverLine_ClassifiesRealFailures drives the REAL delivery state
// machine against a collector that accepts and then refuses every write, and
// pins that the loss is classified rather than lumped into one number.
func TestDeliverLine_ClassifiesRealFailures(t *testing.T) {
	w := newTestWriter(t, func() (net.Conn, error) { return &failingConn{}, nil })
	w.deliverLine("<13>1 line\n")

	by := w.DropsByReason()
	if by[DropWriteFailed] == 0 {
		t.Errorf("a failed write was not charged to write_failed: %+v", by)
	}
	if w.FailingSince().IsZero() {
		t.Error("a failed write did not open a delivery episode — the health plane would report the feed as active")
	}
}

// TestDeliverLine_RecordsSuccessAsEvidence pins the positive half: a delivered
// line must stamp the evidence the health plane recovers on.
func TestDeliverLine_RecordsSuccessAsEvidence(t *testing.T) {
	var sink deadlineRecordingConn
	w := newTestWriter(t, func() (net.Conn, error) { return &sink, nil })
	w.deliverLine("<13>1 line\n")

	if w.LastDelivery().IsZero() {
		t.Fatal("a successful delivery stamped no evidence; recovery would have nothing to key on")
	}
	if w.Drops() != 0 {
		t.Errorf("a successful delivery counted %d drops", w.Drops())
	}
	sink.mu.Lock()
	got := sink.buf.String()
	sink.mu.Unlock()
	if !strings.Contains(got, "line") {
		t.Errorf("the line did not reach the conn: %q", got)
	}
}

// TestDropReasonSlotsAreStable pins the reason ORDER, which every operator
// surface renders in. Reordering silently reshuffles a dashboard's columns.
func TestDropReasonSlotsAreStable(t *testing.T) {
	want := []DropReason{
		DropCollectorUnreachable,
		DropWriteFailed,
		DropQueueFull,
		DropWriterClosed,
		DropDeliveryPanic,
	}
	if !reflect.DeepEqual(dropReasons[:], want) {
		t.Errorf("dropReasons order changed: got %v, want %v", dropReasons, want)
	}
}

// TestDeliveryObserver_NeverRunsUnderTheDeliveryMutex pins the invariant that
// a self-review of this file's FIRST version found it breaking.
//
// noteDeliverySuccess and the reachability branches of noteDrop are reached
// from deliverLine, which holds s.mu across the entire reconnect/backoff state
// machine. The first version invoked the observer inline from there, so an
// observer doing something entirely ordinary — asking the Writer what format
// it is using, to put in the log line it is building — deadlocked on the
// recovery transition and would have wedged the drain goroutine permanently,
// taking down all SIEM delivery for the life of the process.
//
// The SetPanicObserver comment had already written this invariant down for the
// OTHER observer on this path ("runs AFTER deliverLine's own deferred mutex
// unlock has already fired during unwind, so it never needs s.mu"). It held
// there because a panic unwinds through the unlock, and was quietly broken
// here because a normal return does not.
//
// Verified failing against the inline-notify shape.
func TestDeliveryObserver_NeverRunsUnderTheDeliveryMutex(t *testing.T) {
	var sink deadlineRecordingConn
	w := newTestWriter(t, func() (net.Conn, error) { return &sink, nil })

	var calls int
	w.SetDeliveryObserver(func(ev DeliveryEvent) {
		calls++
		done := make(chan struct{}) // fresh per invocation: a shared one is
		// already closed on the second call and hides the deadlock
		go func() { _ = w.Format(); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Errorf("observer invocation %d (state=%v) ran while s.mu was held — an observer that touches any mutex-guarded API deadlocks the drain goroutine permanently", calls, ev.State)
		}
	})

	// Open an episode through the real delivery path, then recover through it.
	w.conn = nil
	w.dialFunc = func() (net.Conn, error) { return nil, errDialRefused }
	w.deliverLine("<13>1 down\n")

	w.dialFunc = func() (net.Conn, error) { return &sink, nil }
	w.lastReconnErr = time.Time{}
	w.deliverLine("<13>1 up\n")

	if calls < 2 {
		t.Fatalf("observer fired %d times; the gate needs both a failing and a recovered transition to prove anything", calls)
	}
}

var errDialRefused = &net.OpError{Op: "dial", Err: errRefused{}}

type errRefused struct{}

func (errRefused) Error() string { return "connection refused" }
