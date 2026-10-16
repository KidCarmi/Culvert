package syslog

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// A runtime re-point may change the wire format as well as the collector. A
// line still queued on the displaced writer was encoded in ITS format; handing
// it to the successor verbatim would deliver RFC 3164 records to a collector
// configured for RFC 5424 (or vice versa) while the successor counted them
// delivered (Codex review, PR #1494). The handoff must re-encode the line for
// the accepting writer, keeping the priority, the body and the event time.
func TestHandOffQueued_ReencodesForTheSuccessorsFormat(t *testing.T) {
	old := &Writer{format: "rfc3164", host: "h1", tag: "culvert", pid: "1", queue: make(chan queuedLine, 4)}
	next := &Writer{format: "rfc5424", host: "h2", tag: "culvert", pid: "2", queue: make(chan queuedLine, 4)}
	old.HandOffTo(next)

	at := time.Date(2026, 9, 26, 1, 2, 3, 0, time.UTC)
	item := old.formatLine(13, `{"evt":"policy.change"}`, at)
	if !strings.HasPrefix(item.line, "<13>Sep 26 01:02:03 h1 culvert: ") {
		t.Fatalf("precondition: rfc3164 encoding, got %q", item.line)
	}
	if !old.handOffQueued(item) {
		t.Fatal("successor did not accept the handed-off line")
	}
	got := <-next.queue
	want := "<13>1 " + at.Format(time.RFC3339Nano) + ` h2 culvert 2 - - {"evt":"policy.change"}` + "\n"
	if got.line != want {
		t.Fatalf("handed-off line = %q, want it re-encoded for the successor as %q", got.line, want)
	}
	if got.format != "rfc5424" {
		t.Fatalf("handed-off line format = %q, want rfc5424", got.format)
	}
}

// CONTROL: a successor with the SAME format receives the line byte-identical
// (no gratuitous re-encode, which would change the event time's precision or
// the host field for an ordinary same-format re-point).
func TestHandOffQueued_SameFormatIsForwardedVerbatim(t *testing.T) {
	old := &Writer{format: "rfc5424", host: "h1", tag: "culvert", pid: "1", queue: make(chan queuedLine, 4)}
	next := &Writer{format: "rfc5424", host: "h2", tag: "culvert", pid: "2", queue: make(chan queuedLine, 4)}
	old.HandOffTo(next)
	item := old.formatLine(14, "hello", time.Now())
	if !old.handOffQueued(item) {
		t.Fatal("successor did not accept the handed-off line")
	}
	if got := <-next.queue; got.line != item.line {
		t.Fatalf("same-format handoff changed the line: %q -> %q", item.line, got.line)
	}
}

// Once HandOffTo has named a successor, a line the drain goroutine dequeues
// through its ordinary (non-stop) branch must go to the successor, never to
// the collector being replaced. Close closes `stop` while lines are still
// queued, and Go picks uniformly between two ready select cases, so without
// this the drain loop could keep delivering queued security events to the
// displaced collector after the re-point (Codex review, PR #1494). The stop
// channel is deliberately left open here so the ordinary branch is the ONLY
// one that can fire — the test is deterministic, not a race.
func TestDrainLoop_DequeuedLineAfterHandOffGoesToSuccessor(t *testing.T) {
	oldConn := &deadlineRecordingConn{}
	old := &Writer{network: "tcp", addr: "192.0.2.1:514", host: "h1", tag: "culvert",
		format: "rfc3164", pid: "1", conn: oldConn,
		queue: make(chan queuedLine, 4), stop: make(chan struct{}), done: make(chan struct{})}
	next := &Writer{format: "rfc3164", host: "h2", tag: "culvert", pid: "2", queue: make(chan queuedLine, 4)}
	old.HandOffTo(next)
	old.queue <- old.formatLine(13, "after-handoff", time.Now())

	go old.drainLoop()
	defer func() {
		close(old.stop)
		<-old.done
	}()

	select {
	case got := <-next.queue:
		if !strings.Contains(got.line, "after-handoff") {
			t.Fatalf("successor received %q", got.line)
		}
	case <-time.After(2 * time.Second):
		oldConn.mu.Lock()
		sent := oldConn.buf.String()
		oldConn.mu.Unlock()
		t.Fatalf("line was not handed to the successor; displaced collector received %q", sent)
	}
	oldConn.mu.Lock()
	defer oldConn.mu.Unlock()
	if oldConn.buf.Len() != 0 {
		t.Fatalf("displaced collector still received %q after the handoff", oldConn.buf.String())
	}
}

// TestHandOffQueued_ExhaustedHopBoundDropsRatherThanFallingBack pins that the
// walk bound never sends a queued event BACKWARDS to the displaced collector.
//
// handOffQueued reports false to mean "no successor — this line is still
// yours"; both drainLoop callers then deliver it through the writer's own
// connection. The hop bound used to exit that way as well, so a queue that
// survived more than maxHandoffHops rapid re-points had its security events
// written to the collector the operator had already replaced, while the
// bound's stated contract was to drop and count them (Codex P2, PR #1494).
//
// Exhausting the bound is a LOSS. It is recorded on this writer, acknowledged
// to any waiting prober as not-delivered, and reported as handled so no caller
// can fall back.
func TestHandOffQueued_ExhaustedHopBoundDropsRatherThanFallingBack(t *testing.T) {
	// A chain longer than the bound. Every link is itself CLOSED — which is
	// what a run of rapid re-points produces, since each displaced writer is
	// closed as its successor is installed — so the walk keeps following
	// successor links and reaches the bound with a live writer still ahead.
	head := &Writer{format: "rfc3164", host: "h", tag: "culvert", pid: "1", queue: make(chan queuedLine, 4)}
	prev := head
	for i := 0; i < maxHandoffHops+2; i++ {
		w := &Writer{format: "rfc3164", host: "h", tag: "culvert", pid: "1", queue: make(chan queuedLine, 4)}
		w.closed.Store(true)
		prev.HandOffTo(w)
		prev = w
	}
	// ...and the far end is live, so the line was never unreachable in
	// principle; only the bound stopped us getting to it.
	live := &Writer{format: "rfc3164", host: "h", tag: "culvert", pid: "1", queue: make(chan queuedLine, 4)}
	prev.HandOffTo(live)

	ack := make(chan ProbeOutcome, 1)
	item := head.formatLine(13, `{"evt":"auth.login"}`, time.Now())
	item.ack = ack

	beforeDrops := head.Stats().Drops
	if !head.handOffQueued(item) {
		t.Fatal("handOffQueued reported the line as unhandled after exhausting the hop bound — both drainLoop callers read that as \"no successor\" and deliver it through the DISPLACED collector")
	}
	if got := head.Stats().Drops; got != beforeDrops+1 {
		t.Errorf("drops = %d, want %d — a line lost to the hop bound must be counted, not silently redirected", got, beforeDrops+1)
	}
	select {
	case out := <-ack:
		if out.Delivered {
			t.Error("the prober was told the line was delivered; it was not")
		}
	default:
		t.Error("the prober was never acknowledged and would wait out its own deadline")
	}
	// Nothing reached the displaced writer's own queue either.
	if len(head.queue) != 0 {
		t.Errorf("the displaced writer queued %d line(s) for its own collector", len(head.queue))
	}

	if len(live.queue) != 0 {
		t.Errorf("the far end received %d line(s); the bound was not actually reached, so this gate proves nothing", len(live.queue))
	}

	// CONTROL: a chain INSIDE the bound still hands off normally. The cheapest
	// way to pass everything above is to drop every handoff, which would
	// delete the P1-E fix that preserves events across a re-point.
	short := &Writer{format: "rfc3164", host: "h", tag: "culvert", pid: "1", queue: make(chan queuedLine, 4)}
	target := &Writer{format: "rfc3164", host: "h", tag: "culvert", pid: "1", queue: make(chan queuedLine, 4)}
	short.HandOffTo(target)
	if !short.handOffQueued(short.formatLine(13, "ok", time.Now())) {
		t.Fatal("a one-hop handoff was not handled")
	}
	if len(target.queue) != 1 {
		t.Errorf("the live successor received %d line(s), want 1", len(target.queue))
	}
	if short.Stats().Drops != 0 {
		t.Errorf("a successful handoff counted %d drop(s)", short.Stats().Drops)
	}
}

// A probe's acknowledgement must carry the transport of the writer that
// ACTUALLY SENT the line (CHAOS-72, Codex P2 round 11).
//
// handOffQueued moves a queued line — its ack channel included — to a
// successor, which may speak a different transport. The probe endpoint binds
// its "delivered" vs "sent" wording to that flag, so a probe queued on a TCP
// writer and handed off to a UDP one was reported as "the collector accepted
// the test event" for a datagram nothing may have received.
//
// The previous round bound the claim to the writer the CALLER held, which was
// right one hop short: only the sender knows how it sent.
func TestProbeAckCarriesTheSendingTransport(t *testing.T) {
	// A closed TCP head that hands off to a live UDP successor.
	head := &Writer{network: "tcp", format: "rfc3164", host: "h", tag: "culvert", pid: "1", queue: make(chan queuedLine, 4)}
	head.closed.Store(true)
	live := &Writer{network: "udp", format: "rfc3164", host: "h", tag: "culvert", pid: "1", queue: make(chan queuedLine, 4)}
	head.HandOffTo(live)

	ack := make(chan ProbeOutcome, 1)
	item := head.formatLine(13, "probe", time.Now())
	item.ack = ack

	if !head.handOffQueued(item) {
		t.Fatal("handOffQueued did not take the line")
	}
	// The successor accepted it; its drain goroutine is not running in this
	// unit, so acknowledge it exactly as deliverTracked would.
	queued := <-live.queue
	ackQueued(queued, live, true, nil)

	select {
	case out := <-ack:
		if !out.Delivered {
			t.Fatal("precondition: the handed-off line was not reported delivered")
		}
		if out.Provable {
			t.Error("the acknowledgement claims provable delivery, but a UDP successor sent the line — " +
				"POST /api/syslog/test would answer \"the collector accepted the test event\" for a datagram " +
				"nothing may have received")
		}
	default:
		t.Fatal("the prober was never acknowledged")
	}

	// CONTROL: the inverse must still be provable. Hardwiring Provable false
	// would pass the assertion above while deleting the only affirmative
	// delivery evidence this endpoint can give.
	tcpLive := &Writer{network: "tcp", format: "rfc3164", host: "h", tag: "culvert", pid: "1", queue: make(chan queuedLine, 4)}
	ack2 := make(chan ProbeOutcome, 1)
	item2 := tcpLive.formatLine(13, "probe", time.Now())
	item2.ack = ack2
	ackQueued(item2, tcpLive, true, nil)
	if out := <-ack2; !out.Provable {
		t.Error("control: a TCP sender's acknowledgement must report provable delivery")
	}
}

// A loss at the end of a bounded successor walk must be countable, and the
// walk must not charge a writer it never tried (CHAOS-72, Codex P2 round 11).
//
// The exported drop total is each displaced writer's finals (folded when it is
// displaced) plus the LIVE writer's own counters. A drop recorded against an
// intermediate writer after its finals were folded therefore lands nowhere.
// `send` also used to check its bound at the top of the loop, so on exhaustion
// it charged a writer that had been assigned and never asked.
// retiredAndSealed puts a hand-built Writer into the state a late drop is
// DEFINED against: its owner has folded its cumulative counters and stopped
// reading them (MarkRetired), and its drain has published its finals
// (sealing). A closed Writer that is neither is still read live by the health
// plane, so charging its losses late would count them twice — which is why
// the predicate needs both and why a chain built without this models a shape
// production never produces.
func retiredAndSealed(w *Writer) {
	w.MarkRetired()
	st := w.Stats()
	w.finalStats.Store(&st)
}

func TestSendExhaustedWalkIsCountableAndTriesItsLastWriter(t *testing.T) {
	head := &Writer{network: "udp", format: "rfc3164", host: "h", tag: "culvert", pid: "1", queue: make(chan queuedLine, 4)}
	head.closed.Store(true)
	retiredAndSealed(head)
	prev := head
	chain := []*Writer{head}
	for i := 0; i < maxHandoffHops+2; i++ {
		w := &Writer{network: "udp", format: "rfc3164", host: "h", tag: "culvert", pid: "1", queue: make(chan queuedLine, 4)}
		w.closed.Store(true)
		retiredAndSealed(w)
		prev.HandOffTo(w)
		prev = w
		chain = append(chain, w)
	}
	// The far end is LIVE, so only the bound stops the line reaching it.
	live := &Writer{network: "udp", format: "rfc3164", host: "h", tag: "culvert", pid: "1", queue: make(chan queuedLine, 4)}
	prev.HandOffTo(live)

	beforeLate := LateDrops()
	head.send(13, "payload")

	if got := LateDrops() - beforeLate; got != 1 {
		t.Errorf("late drops = %d, want 1 — a loss charged to a writer whose totals were already retired "+
			"is absent from culvert_syslog_drops_total and /healthz, which is the one series this plane exists to keep honest", got)
	}
	// Every writer the walk charged must be one it actually asked. A writer
	// with zero attempts and a drop against it is the off-by-one.
	charged := 0
	for _, w := range chain {
		if w.Stats().Drops > 0 {
			charged++
		}
	}
	if charged != 1 {
		t.Errorf("%d writers in the chain were charged; want exactly 1", charged)
	}
	if live.Stats().Drops != 0 {
		t.Error("the LIVE writer was charged for a line the walk never offered it")
	}

	// The off-by-one, made observable: with the LIVE writer sitting exactly at
	// the exhaustion point, the pre-fix loop checked its bound at the TOP, so
	// it assigned that writer to `w` without ever asking it and then charged
	// the drop there. Neither shape delivers the line — the bound is spent
	// either way — but blaming a healthy collector for a loss it never saw
	// also stamps `closed` on its LastFailureReason, which is the health
	// plane's input. The charge must land on the last writer that actually
	// refused.
	oh := &Writer{network: "udp", format: "rfc3164", host: "h", tag: "culvert", pid: "1", queue: make(chan queuedLine, 4)}
	oh.closed.Store(true)
	retiredAndSealed(oh)
	p := oh
	for i := 0; i < maxHandoffHops-1; i++ {
		w := &Writer{network: "udp", format: "rfc3164", host: "h", tag: "culvert", pid: "1", queue: make(chan queuedLine, 4)}
		w.closed.Store(true)
		retiredAndSealed(w)
		p.HandOffTo(w)
		p = w
	}
	edge := &Writer{network: "udp", format: "rfc3164", host: "h", tag: "culvert", pid: "1", queue: make(chan queuedLine, 4)}
	p.HandOffTo(edge)
	oh.send(13, "payload")
	if edge.Stats().Drops != 0 {
		t.Error("the writer sitting at the exhaustion point was charged for a line the walk never asked it for — " +
			"a healthy collector is blamed, and its LastFailureReason becomes \"closed\", which the health plane reads")
	}
	if edge.Stats().LastFailureReason != "" {
		t.Errorf("an unasked writer's failure reason was set to %q", edge.Stats().LastFailureReason)
	}
	// With exactly maxHandoffHops successor links the walk must reach the
	// LAST one: the bound is maxHandoffHops links followed, the same budget
	// handOffQueued spends. Stopping one short dropped a line the live
	// writer at the end of the chain would have accepted.
	if len(edge.queue) != 1 {
		t.Errorf("the writer %d links down the chain received %d lines; want 1 — the walk stopped one link short of its bound",
			maxHandoffHops, len(edge.queue))
	}

	// CONTROL: a walk that reaches a live writer within the bound delivers and
	// counts nothing. The cheapest way to pass the assertions above is to
	// charge a late drop unconditionally.
	h2 := &Writer{network: "udp", format: "rfc3164", host: "h", tag: "culvert", pid: "1", queue: make(chan queuedLine, 4)}
	h2.closed.Store(true)
	ok := &Writer{network: "udp", format: "rfc3164", host: "h", tag: "culvert", pid: "1", queue: make(chan queuedLine, 4)}
	h2.HandOffTo(ok)
	beforeLate = LateDrops()
	h2.send(13, "payload")
	if LateDrops() != beforeLate {
		t.Error("control: a line that reached a live writer within the bound was counted as a late drop")
	}
	if len(ok.queue) != 1 {
		t.Errorf("control: the live writer received %d lines; want 1", len(ok.queue))
	}
}

// TestAckCarriesTheSendersFailureReason is the DEFECT gate for Codex round 15.
//
// A queued probe is handed to a successor along with its ack channel. When the
// successor is the one that drops it, the failure class belongs to THAT
// writer — but POST /api/syslog/test read `sw.Stats().LastFailureReason`, i.e.
// the writer the probe was CALLED on, which never attempted the send. It
// reports `unknown` on a fresh chain, or an unrelated stale class on a busy
// one, in the endpoint whose entire job is to be believed. This is the same
// one-hop-short error the transport had (fixed the round before), one field
// later.
//
// Driven at the ack level because the interleaving is what matters, not the
// HTTP plumbing: the handler's own use of outcome.Reason is pinned in the root
// package where that handler lives.
func TestAckCarriesTheSendersFailureReason(t *testing.T) {
	head := &Writer{network: "tcp", format: "rfc3164", host: "h", tag: "culvert", pid: "1", queue: make(chan queuedLine, 1)}
	head.closed.Store(true)

	// A successor whose queue is already FULL, so it refuses the handoff and
	// the loss is charged there — not on head.
	full := &Writer{network: "tcp", format: "rfc3164", host: "h", tag: "culvert", pid: "1", queue: make(chan queuedLine, 1)}
	full.queue <- full.formatLine(13, "occupies the slot", time.Now())
	head.HandOffTo(full)

	// head must look "clean": pre-fix the handler read ITS reason, and the
	// whole point is that head knows nothing about this line's fate.
	if r := head.Stats().LastFailureReason; r != "" {
		t.Fatalf("precondition: head already carries reason %q; the gate cannot distinguish", r)
	}

	ack := make(chan ProbeOutcome, 1)
	item := head.formatLine(13, "probe", time.Now())
	item.ack = ack
	if !head.handOffQueued(item) {
		t.Fatal("handOffQueued did not take the line")
	}

	select {
	case out := <-ack:
		if out.Delivered {
			t.Fatal("precondition: the probe was reported delivered by a full successor")
		}
		if out.Reason != ReasonQueueFull {
			t.Fatalf("acknowledged reason = %q, want %q: the reason must come from the writer that "+
				"actually refused the send. Pre-fix the endpoint read it off the writer the probe was "+
				"handed, which never attempted it and reports %q",
				out.Reason, ReasonQueueFull, head.Stats().LastFailureReason)
		}
	default:
		t.Fatal("the prober was never acknowledged")
	}
}

// TestAckReasonIsEmptyOnDelivery is the CONTROL. The cheapest way to pass the
// gate above is to stamp a reason unconditionally, which would have the test
// endpoint report a failure class alongside a successful delivery.
func TestAckReasonIsEmptyOnDelivery(t *testing.T) {
	w := &Writer{network: "tcp", format: "rfc3164", host: "h", tag: "culvert", pid: "1", queue: make(chan queuedLine, 1)}
	ack := make(chan ProbeOutcome, 1)
	item := w.formatLine(13, "probe", time.Now())
	item.ack = ack

	ackQueued(item, w, true, &reasonWriteFail)

	out := <-ack
	if !out.Delivered {
		t.Fatal("precondition: not reported delivered")
	}
	if out.Reason != "" {
		t.Fatalf("a delivered probe carries reason %q, want empty: a success has no failure class", out.Reason)
	}
}

// TestWriteProbeFollowsTheSuccessorOfAClosedWriter: POST /api/syslog/test
// captures a writer and a concurrent re-point can close it before the probe
// is enqueued. The probe must then reach the REPLACEMENT collector, like any
// other line, instead of being dropped against the displaced writer (which
// reported a healthy replacement as "dropped").
func TestWriteProbeFollowsTheSuccessorOfAClosedWriter(t *testing.T) {
	old := &Writer{network: "udp", format: "rfc3164", host: "h", tag: "culvert", pid: "1", queue: make(chan queuedLine, 4)}
	old.closed.Store(true)
	live := &Writer{network: "udp", format: "rfc5424", host: "h", tag: "culvert", pid: "1", queue: make(chan queuedLine, 4)}
	old.HandOffTo(live)

	ack, ok := old.WriteProbe("probe")
	if !ok || ack == nil {
		t.Fatal("a probe on a displaced writer with a live successor was refused instead of handed off")
	}
	if len(live.queue) != 1 {
		t.Fatalf("the replacement writer received %d probe lines; want 1", len(live.queue))
	}
	if d := old.Stats().Drops; d != 0 {
		t.Errorf("the displaced writer was charged %d drops for a probe its successor accepted", d)
	}

	// CONTROL: with no successor the probe is still refused and counted.
	lone := &Writer{network: "udp", format: "rfc3164", host: "h", tag: "culvert", pid: "1", queue: make(chan queuedLine, 4)}
	lone.closed.Store(true)
	if _, ok := lone.WriteProbe("probe"); ok {
		t.Error("control: a probe on a closed writer with no successor was reported as queued")
	}
	if lone.Stats().Drops != 1 {
		t.Errorf("control: the closed writer counted %d drops; want 1", lone.Stats().Drops)
	}
}

// chainTo builds head -> n closed writers -> one LIVE writer, linked exactly as
// releaseReplacedSyslogWriter does it (retire, hand off, close), and returns the
// head and the live tail. Every writer in between is closed, so a line sent
// through the head must walk the whole chain to be delivered.
func chainTo(t *testing.T, closedLinks int) (head, live *Writer) {
	t.Helper()
	mk := func() *Writer {
		return &Writer{network: "udp", format: "rfc3164", host: "h", tag: "culvert", pid: "1", queue: make(chan queuedLine, 4)}
	}
	head = mk()
	prev := head
	for i := 0; i < closedLinks; i++ {
		nx := mk()
		prev.MarkRetired()
		prev.HandOffTo(nx)
		prev.closed.Store(true)
		prev = nx
	}
	return head, prev
}

// TestSendAndHandOffAgreeOnChainDepth pins the PROPERTY behind the hop-bound
// finding rather than the depth it happened to have.
//
// The defect was not that one number was better than the other: it was that two
// walks over ONE chain disagreed about how deep it goes, so the same line was
// delivered or lost depending only on which path it took. The exhaustion test
// above asserts the fixed depth and so catches this instance; this asserts the
// agreement, and so catches a future divergence in either direction — including
// one introduced by changing maxHandoffHops or by touching only one walk.
func TestSendAndHandOffAgreeOnChainDepth(t *testing.T) {
	for _, depth := range []int{1, maxHandoffHops - 1, maxHandoffHops, maxHandoffHops + 1} {
		t.Run(fmt.Sprintf("depth=%d", depth), func(t *testing.T) {
			sendHead, sendLive := chainTo(t, depth)
			sendHead.send(13, "via send")
			sendReached := len(sendLive.queue) == 1

			hoHead, hoLive := chainTo(t, depth)
			if !hoHead.handOffQueued(hoHead.formatLine(13, "via handoff", time.Now())) {
				t.Fatal("handOffQueued declined to take the line")
			}
			hoReached := len(hoLive.queue) == 1

			if sendReached != hoReached {
				t.Fatalf("at %d successor links send reached the live writer = %v but handOffQueued = %v: "+
					"one chain walked by two functions must drop at the SAME depth",
					depth, sendReached, hoReached)
			}
		})
	}
}

// TestProbeRefusalOnASealedWriterReachesTheExportedTotal closes the accounting
// half of the probe finding at the SURFACE rather than at the counter.
//
// A displaced writer's own counters stop being read once its finals are folded,
// which is exactly why lateDrops exists. The no-successor control above asserts
// Stats().Drops on a writer that was never retired or sealed — the case where
// the writer's own counter IS still read — so it cannot see a loss charged to a
// sealed one. That is the shape this plane has recorded repeatedly: when a fix
// routes a loss to a counter, the deliverable is the exported total, not the
// counter.
func TestProbeRefusalOnASealedWriterReachesTheExportedTotal(t *testing.T) {
	ResetLateDropsForTest()
	t.Cleanup(ResetLateDropsForTest)

	// Retired AND sealed, closed, with no successor: the chain ends here and
	// this writer's own counters are no longer folded by the health plane.
	w := &Writer{network: "udp", format: "rfc3164", host: "h", tag: "culvert", pid: "1", queue: make(chan queuedLine, 1)}
	w.closed.Store(true)
	w.MarkRetired()
	final := Stats{}
	w.finalStats.Store(&final)

	before := LateDrops()
	if ack, ok := w.WriteProbe("refused at the end of the chain"); ok || ack != nil {
		t.Fatalf("a probe no writer can take was reported queued (ok=%v, ack!=nil=%v)", ok, ack != nil)
	}
	if got := LateDrops(); got == before {
		t.Fatalf("a probe refused on a retired+sealed writer left the late-drop total at %d: "+
			"that writer's own counters are not read any more, so the loss is absent from "+
			"culvert_syslog_drops_total and /healthz", got)
	}
}

// TestProbeOnAnOpenWriterWithASuccessorStaysPut is the CONTROL for walking.
// The cheapest way to pass a "the probe reaches the replacement" gate is to walk
// unconditionally, which would hand a probe past a perfectly healthy collector
// and report on the wrong one.
func TestProbeOnAnOpenWriterWithASuccessorStaysPut(t *testing.T) {
	w := &Writer{network: "udp", format: "rfc3164", host: "h", tag: "culvert", pid: "1", queue: make(chan queuedLine, 4)}
	nx := &Writer{network: "udp", format: "rfc3164", host: "h", tag: "culvert", pid: "1", queue: make(chan queuedLine, 4)}
	w.HandOffTo(nx) // a successor exists, but w is OPEN and must keep the line

	ack, ok := w.WriteProbe("stays on the healthy writer")
	if !ok || ack == nil {
		t.Fatal("a probe on a healthy writer was refused")
	}
	if len(w.queue) != 1 {
		t.Fatalf("the healthy writer holds %d queued lines, want 1", len(w.queue))
	}
	if len(nx.queue) != 0 {
		t.Fatal("the probe was handed to a successor although the writer it was submitted to was " +
			"open and accepted it")
	}
	select {
	case out := <-ack:
		t.Fatalf("an accepted probe was acknowledged %+v before the drain delivered it", out)
	default:
	}
}

// ── A displaced writer's full queue is not a loss ────────────────────────────
//
// releaseReplacedSyslogWriter names the successor BEFORE it closes the
// predecessor, and that close is ASYNCHRONOUS, so `successor != nil &&
// !closed` is the ordinary state of a just-displaced writer. Its queue being
// full is the ordinary REASON for the re-point. Treating that as terminal
// destroyed the event on a collector the operator had already moved off, with
// a healthy replacement sitting idle — and charged a compliance drop for it
// (Codex P2, PR #1494).

// A new line reaching a displaced, backed-up writer must follow the successor.
func TestSend_DisplacedWriterWithAFullQueueFollowsItsSuccessor(t *testing.T) {
	old := &Writer{network: "udp", format: "rfc3164", host: "h1", tag: "culvert", pid: "1", queue: make(chan queuedLine, 1)}
	next := &Writer{network: "udp", format: "rfc3164", host: "h2", tag: "culvert", pid: "2", queue: make(chan queuedLine, 4)}
	old.queue <- old.formatLine(14, "backlog", time.Now())
	old.MarkRetired()
	old.HandOffTo(next)
	if old.closed.Load() {
		t.Fatal("precondition: the displaced writer must still be open — the close is asynchronous")
	}

	old.send(14, "late-audit-event")

	select {
	case got := <-next.queue:
		if !strings.Contains(got.line, "late-audit-event") {
			t.Fatalf("successor received %q, want the late event", got.line)
		}
	default:
		t.Fatal("the line was lost on the displaced writer instead of being offered to its replacement")
	}
}

// ...and it must not be ACCUSED as a drop. The counter means "events that did
// not reach the SIEM"; charging one for an event the replacement accepted
// inflates the only series that measures compliance loss. Both halves of the
// finding need their own assertion: following the successor without this is
// still a false accusation, and this without the one above is still a loss.
func TestSend_FollowingTheSuccessorChargesNoDrop(t *testing.T) {
	// A DELTA, never the absolute total: lateDrops is process-lifetime by
	// design, so any earlier gate that charges one shifts it for every gate
	// after. Asserting `== 0` passed only because another test in this file
	// happens to reset the counter just above this one in source order — under
	// -shuffle=on it fails the moment the exhausted-walk gate lands in
	// between (reproduced deterministically with a two-test -run).
	//
	// This is the trap round 11's postscript already recorded, in the gate
	// added one round later: when a counter survives what used to reset it,
	// every assertion about it has to be relative (CodeRabbit, PR #1494).
	beforeLate := LateDrops()
	old := &Writer{network: "udp", format: "rfc3164", host: "h1", tag: "culvert", pid: "1", queue: make(chan queuedLine, 1)}
	next := &Writer{network: "udp", format: "rfc3164", host: "h2", tag: "culvert", pid: "2", queue: make(chan queuedLine, 4)}
	old.queue <- old.formatLine(14, "backlog", time.Now())
	old.HandOffTo(next)

	old.send(14, "late-audit-event")

	if got := old.Drops(); got != 0 {
		t.Fatalf("displaced writer charged %d drop(s) for a line its replacement accepted, want 0", got)
	}
	if got := next.Drops(); got != 0 {
		t.Fatalf("replacement charged %d drop(s) for a line it accepted, want 0", got)
	}
	if got := LateDrops() - beforeLate; got != 0 {
		t.Fatalf("late-drop total moved by %d for a delivered line, want 0", got)
	}
}

// CONTROL: a full queue on the writer that is still IN SERVICE stays a counted
// drop. The cheapest way to pass the two gates above is to stop charging
// queue-full drops at all, which would delete the backpressure signal that
// tells an operator their collector cannot keep up.
func TestSend_FullQueueOnTheLiveWriterIsStillACountedDrop(t *testing.T) {
	live := &Writer{network: "udp", format: "rfc3164", host: "h", tag: "culvert", pid: "1", queue: make(chan queuedLine, 1)}
	live.queue <- live.formatLine(14, "backlog", time.Now())
	if live.successor.Load() != nil {
		t.Fatal("precondition: the live writer names no successor")
	}

	live.send(14, "shed-me")

	if got := live.Drops(); got != 1 {
		t.Fatalf("live writer charged %d drop(s) for a shed line, want 1", got)
	}
	// The CLASS matters as much as the count, and asserting only the count
	// made this control vacuous against the cheapest wrong fix: reporting
	// every full queue as displaced still charges one drop, at the end of the
	// walk, under `closed` — so an operator chasing a collector that cannot
	// keep up is told the writer was replaced instead (verified by mutation).
	if got := live.Stats().LastFailureReason; got != reasonQueueFull {
		t.Fatalf("live writer charged the shed line as %q, want %q", got, reasonQueueFull)
	}
}

// CONTROL: a displaced writer whose queue still has ROOM keeps taking the
// line. The drain loop hands it on from there, so skipping a displaced writer
// wholesale would both change the ordinary re-point path and make the drain's
// own handoff — which four gates above pin — unreachable from `send`.
func TestSend_DisplacedWriterWithRoomStillTakesTheLine(t *testing.T) {
	old := &Writer{network: "udp", format: "rfc3164", host: "h1", tag: "culvert", pid: "1", queue: make(chan queuedLine, 4)}
	next := &Writer{network: "udp", format: "rfc3164", host: "h2", tag: "culvert", pid: "2", queue: make(chan queuedLine, 4)}
	old.HandOffTo(next)

	old.send(14, "still-mine")

	select {
	case got := <-old.queue:
		if !strings.Contains(got.line, "still-mine") {
			t.Fatalf("displaced writer queued %q, want the line", got.line)
		}
	default:
		t.Fatal("a displaced writer with room must still accept the line; its own drain hands it on")
	}
	if l := len(next.queue); l != 0 {
		t.Fatalf("successor received %d line(s) it should not have been offered", l)
	}
}

// The same rule inside handOffQueued: a run of rapid re-points can leave an
// INTERMEDIATE writer both replaced and backed up, and that writer is no more
// the one to use than a closed one. Walking past it is what delivers the line.
func TestHandOffQueued_WalksPastADisplacedBackedUpIntermediate(t *testing.T) {
	head := &Writer{network: "udp", format: "rfc3164", host: "h0", tag: "culvert", pid: "0", queue: make(chan queuedLine, 4)}
	mid := &Writer{network: "udp", format: "rfc3164", host: "h1", tag: "culvert", pid: "1", queue: make(chan queuedLine, 1)}
	live := &Writer{network: "udp", format: "rfc3164", host: "h2", tag: "culvert", pid: "2", queue: make(chan queuedLine, 4)}
	mid.queue <- mid.formatLine(14, "backlog", time.Now())
	head.HandOffTo(mid)
	mid.HandOffTo(live)

	item := head.formatLine(14, "queued-at-the-re-point", time.Now())
	if !head.handOffQueued(item) {
		t.Fatal("handOffQueued reported the line as still the caller's")
	}
	select {
	case got := <-live.queue:
		if !strings.Contains(got.line, "queued-at-the-re-point") {
			t.Fatalf("live writer received %q, want the queued line", got.line)
		}
	default:
		t.Fatal("the line stopped at a displaced, backed-up intermediate instead of reaching the live writer")
	}
	if got := mid.Drops(); got != 0 {
		t.Fatalf("intermediate charged %d drop(s) for a line the live writer accepted, want 0", got)
	}
}
