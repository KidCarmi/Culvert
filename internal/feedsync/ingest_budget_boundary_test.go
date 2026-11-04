// ingest_budget_boundary_test.go — the boundary gate for this package's
// boundedReader.
//
// PR #1796 corrected the blocklistfeed and threatfeed copies of boundedReader
// (Codex P2 4448735208): a body of EXACTLY the budget was rejected on the read
// after the budget was reached, without checking that any byte had actually
// exceeded it. This third copy — the one on the category-feed ingest path, with
// a budget on the compressed body AND a second on the decompressed archive —
// was not corrected in that PR. These gates pin both ends of the decision for
// it, so the three readers cannot drift apart again.
package feedsync

import (
	"errors"
	"io"
	"strings"
	"testing"
)

// chunksThenEOF returns each chunk with a nil error and reports io.EOF only on
// the NEXT call. That is the shape of a valid chunked response that flushes its
// final payload before the terminating chunk, and it is the shape that made the
// off-by-one reachable: a reader whose last data-bearing read also carried
// io.EOF never asked for the byte after the budget.
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

// readBounded drains body through boundedReader under a budget of limit, with
// the body split across two chunks so the budget is reached mid-stream rather
// than on the first read.
func readBounded(body string, limit int64) (int, error) {
	half := len(body) / 2
	br := &boundedReader{
		r:     &chunksThenEOF{chunks: []string{body[:half], body[half:]}},
		what:  "compressed feed body",
		limit: limit,
	}
	got, err := io.ReadAll(br)
	return len(got), err
}

// TestBodyOfExactlyTheBudgetIsAccepted is the positive boundary: a body of
// exactly the budget is WITHIN it and must complete the round. Before the fix
// this returned errBudgetExceeded, which fails the whole sync round on this
// path (parseTarball returns the error, syncRound charges failDownload) and
// would have done so on every round for as long as the feed stayed that size.
func TestBodyOfExactlyTheBudgetIsAccepted(t *testing.T) {
	body := strings.Repeat("x", 4096)

	n, err := readBounded(body, int64(len(body)))
	if err != nil {
		t.Fatalf("a %d-byte body against a %d-byte budget was rejected: %v", len(body), len(body), err)
	}
	if n != len(body) {
		t.Errorf("read %d bytes, want %d", n, len(body))
	}
}

// TestOneBytePastTheBudgetIsAnOverrun is the negative control that keeps the
// fix from degenerating into "never enforce the budget". One real byte past the
// limit must still fail, and must fail with the sentinel — parseTarball routes
// errBudgetExceeded to a FAILED round rather than to the log-and-continue arm
// that a corrupt member takes, so losing the sentinel would report an origin
// overrun to the operator as a benign "skipping <member>" line.
func TestOneBytePastTheBudgetIsAnOverrun(t *testing.T) {
	body := strings.Repeat("x", 4096)

	if _, err := readBounded(body+"y", int64(len(body))); !errors.Is(err, errBudgetExceeded) {
		t.Fatalf("one byte past the budget must fail with errBudgetExceeded, got %v", err)
	}
}

// TestShortBodyNeverProbesPastEOF covers the arm below the boundary: a body
// well under budget must report a clean EOF and never surface the sentinel.
func TestShortBodyNeverProbesPastEOF(t *testing.T) {
	body := strings.Repeat("x", 100)

	n, err := readBounded(body, 4096)
	if err != nil {
		t.Fatalf("a %d-byte body against a 4096-byte budget was rejected: %v", len(body), err)
	}
	if n != len(body) {
		t.Errorf("read %d bytes, want %d", n, len(body))
	}
}

// TestBoundaryProbePassesThroughTransportErrors pins the third outcome of the
// probe. At exactly the budget the reader asks for one more byte; if that read
// returns a transport error rather than io.EOF or a byte, the error must reach
// the caller AS a transport error. Reporting it as errBudgetExceeded would
// blame the origin for overrunning a budget it did not overrun, and on this
// path the two outcomes are charged differently.
func TestBoundaryProbePassesThroughTransportErrors(t *testing.T) {
	wantErr := errors.New("connection reset by peer")
	body := strings.Repeat("x", 64)

	br := &boundedReader{
		r:     &errAfter{data: body, err: wantErr},
		what:  "compressed feed body",
		limit: int64(len(body)),
	}
	if _, err := io.ReadAll(br); !errors.Is(err, wantErr) {
		t.Fatalf("transport error at the boundary must pass through, got %v", err)
	}
}

// errAfter returns data in one read, then err — a transport that cut out
// exactly as the budget was reached.
type errAfter struct {
	data string
	err  error
	done bool
}

func (r *errAfter) Read(p []byte) (int, error) {
	if r.done {
		return 0, r.err
	}
	r.done = true
	return copy(p, r.data), nil
}
