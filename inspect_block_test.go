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
