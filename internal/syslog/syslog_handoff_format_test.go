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
