package main

import (
	"strings"
	"testing"
)

// TestH1BlockResponder_BlockBeforeResponse locks the exact wire format so the
// H2 responder (later PR) and any future edit cannot silently drift the H1 bytes.
func TestH1BlockResponder_BlockBeforeResponse(t *testing.T) {
	var b strings.Builder
	h1BlockResponder{w: &b}.blockBeforeResponse("text/plain; charset=utf-8", "nope\r\n")
	got := b.String()
	want := "HTTP/1.1 403 Forbidden\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Content-Length: 6\r\n" +
		"Connection: close\r\n" +
		"\r\nnope\r\n"
	if got != want {
		t.Fatalf("h1 block bytes mismatch:\n got: %q\nwant: %q", got, want)
	}
}

// TestBlockResponderInterface_H1Satisfies is a compile-time guard that
// h1BlockResponder implements blockResponder (the seam the H2 impl also fills).
func TestBlockResponderInterface_H1Satisfies(t *testing.T) {
	var _ blockResponder = h1BlockResponder{w: &strings.Builder{}}
}

// spyResponder records blockResponder calls for the C5 choke-point assertion.
type spyResponder struct {
	calls          int
	lastCT, lastBd string
}

func (s *spyResponder) blockBeforeResponse(ct, body string) {
	s.calls++
	s.lastCT, s.lastBd = ct, body
}

// TestC5_AllBlockEmittersRouteThroughResponder is the invariant-C5 structural
// guarantee: every tunnel block emitter (scan/DPI/CDR-via-scanBlockConn, and the
// file-block path) routes through the single blockResponder choke point — no
// emitter writes a conn directly. This is what makes "one inspection pipeline for
// H1 and H2" a structural fact: the H2 responder plugs into the same choke point.
func TestC5_AllBlockEmittersRouteThroughResponder(t *testing.T) {
	t.Run("scanBlockConn", func(t *testing.T) {
		s := &spyResponder{}
		scanBlockConn(s, "h", "reason", "clamav")
		if s.calls != 1 {
			t.Fatalf("scanBlockConn routed through responder %d times, want 1", s.calls)
		}
	})
	t.Run("dpiBlock", func(t *testing.T) {
		s := &spyResponder{}
		dpiBlock(s, "h", "pattern")
		if s.calls != 1 {
			t.Fatalf("dpiBlock routed through responder %d times, want 1", s.calls)
		}
	})
	t.Run("emitFileBlock", func(t *testing.T) {
		s := &spyResponder{}
		emitFileBlock(s, "h", "/p/x.exe", "exe", "global ext")
		if s.calls != 1 {
			t.Fatalf("emitFileBlock routed through responder %d times, want 1", s.calls)
		}
		if s.lastBd != "Blocked: file type exe is not allowed (global ext)\r\n" {
			t.Fatalf("emitFileBlock body = %q", s.lastBd)
		}
	})
}

// TestH1BlockResponder_DoesNotCloseConn locks the anti-bypass contract: the
// pre-commit responder must NOT close the tunnel conn (the H1 loop owns teardown
// via break + clientTLS.Close, and pipelined-retry bypass is prevented by
// Connection: close in the emitted response). This is the property the H2 path
// depends on — an H2 per-stream block must never close the shared conn (which
// would kill sibling streams). Reviewer R1 missing-test #3.
func TestH1BlockResponder_DoesNotCloseConn(t *testing.T) {
	w := &writeCloseBuf{}
	h1BlockResponder{w: w}.blockBeforeResponse("text/plain; charset=utf-8", "blocked\r\n")
	if w.closed {
		t.Fatal("blockBeforeResponse must NOT close the conn (loop owns teardown; anti-bypass is the Connection: close header)")
	}
}
