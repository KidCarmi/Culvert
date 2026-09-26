package syslog

import (
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
	ackQueued(queued, live, true)

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
	ackQueued(item2, tcpLive, true)
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
func TestSendExhaustedWalkIsCountableAndTriesItsLastWriter(t *testing.T) {
	head := &Writer{network: "udp", format: "rfc3164", host: "h", tag: "culvert", pid: "1", queue: make(chan queuedLine, 4)}
	head.closed.Store(true)
	prev := head
	chain := []*Writer{head}
	for i := 0; i < maxHandoffHops+2; i++ {
		w := &Writer{network: "udp", format: "rfc3164", host: "h", tag: "culvert", pid: "1", queue: make(chan queuedLine, 4)}
		w.closed.Store(true)
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
	p := oh
	for i := 0; i < maxHandoffHops-1; i++ {
		w := &Writer{network: "udp", format: "rfc3164", host: "h", tag: "culvert", pid: "1", queue: make(chan queuedLine, 4)}
		w.closed.Store(true)
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
