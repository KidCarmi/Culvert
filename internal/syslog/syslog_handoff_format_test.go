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
