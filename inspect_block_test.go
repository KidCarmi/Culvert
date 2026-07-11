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
