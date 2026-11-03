package threatfeed

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

// chunksThenEOF returns each chunk with a nil error and reports io.EOF only on
// the NEXT call — the shape of a valid chunked response that flushes its final
// payload before sending the terminating chunk.
type chunksThenEOF struct{ chunks []string }

func (r *chunksThenEOF) Read(p []byte) (int, error) {
	if len(r.chunks) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.chunks[0])
	r.chunks[0] = r.chunks[0][n:]
	if r.chunks[0] == "" {
		r.chunks = r.chunks[1:]
	}
	return n, nil
}

// scanBounded runs bufio.Scanner, as the fetch loop does, over body split into
// two chunks under a byte budget of limit.
func scanBounded(body string, limit int64) (lines int, err error) {
	half := len(body) / 2
	sc := bufio.NewScanner(&boundedReader{
		r: &chunksThenEOF{chunks: []string{body[:half], body[half:]}}, what: "feed body", limit: limit,
	})
	for sc.Scan() {
		lines++
	}
	return lines, sc.Err()
}

// BodyOfExactlyTheBudgetIsAccepted pins Codex P2 4448735208 on PR #1796: a
// body of exactly the budget whose final read does not also return io.EOF was
// rejected on the next read without checking that any byte actually exceeded
// the budget, so a valid feed at the production boundary failed every round.
func TestBodyOfExactlyTheBudgetIsAccepted(t *testing.T) {
	var b strings.Builder
	for i := range 256 {
		fmt.Fprintf(&b, "h%04d.example.com\n", i) // 18 bytes each: 4,608 in all
	}
	body := b.String()

	lines, err := scanBounded(body, int64(len(body)))
	if err != nil {
		t.Fatalf("a %d-byte body against a %d-byte budget was rejected: %v", len(body), len(body), err)
	}
	if lines != 256 {
		t.Errorf("scanned %d lines, want 256", lines)
	}

	// Negative control: one real byte past the budget is still an overrun.
	if _, err := scanBounded(body+"x", int64(len(body))); !errors.Is(err, errBudgetExceeded) {
		t.Fatalf("one byte past the budget must fail with errBudgetExceeded, got %v", err)
	}
}
