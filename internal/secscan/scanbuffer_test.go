package secscan

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"testing"
)

// bodyShape describes one response-body/hint combination to exercise.
type bodyShape struct {
	name  string
	size  int   // bytes the reader actually produces
	limit int64 // scan-buffer limit
	hint  int64 // declared Content-Length (<=0 = chunked / not declared)
}

// scanBufferShapes covers every way a declaration can relate to the body and
// the limit — the whole point of the hint being advisory.
func scanBufferShapes() []bodyShape {
	const limit = 5 << 20
	return []bodyShape{
		{"empty/declared-zero", 0, limit, 0},
		{"empty/chunked", 0, limit, -1},
		{"small/truthful", 1024, limit, 1024},
		{"small/chunked", 1024, limit, -1},
		{"small/over-declared", 1024, limit, 64 << 10},
		{"small/under-declared", 64 << 10, limit, 1024},
		{"exact-seed-boundary", 512, limit, 512},
		{"one-past-seed", 513, limit, 513},
		{"at-presize-cap", maxScanPresizeBytes, limit, maxScanPresizeBytes},
		{"past-presize-cap", maxScanPresizeBytes + 1, limit, maxScanPresizeBytes + 1},
		{"body-over-limit/truthful", 4096, 1024, 4096},
		{"body-over-limit/chunked", 4096, 1024, -1},
		{"hint-over-limit", 4096, 1024, 1 << 30},
		{"limit-zero", 4096, 0, 4096},
	}
}

func makeBody(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte('a' + i%26)
	}
	return b
}

// TestReadScanBuffer_MatchesReadAll is the equivalence wall: ReadScanBuffer is
// a COST change only, so for every body/hint shape it must return byte-for-byte
// what io.ReadAll(io.LimitReader(...)) returns. A future edit that lets the
// hint govern how much is read — which would forward the tail of an
// under-declared body unscanned — fails here.
func TestReadScanBuffer_MatchesReadAll(t *testing.T) {
	for _, s := range scanBufferShapes() {
		t.Run(s.name, func(t *testing.T) {
			body := makeBody(s.size)

			want, wantErr := io.ReadAll(io.LimitReader(bytes.NewReader(body), s.limit))
			got, gotErr := ReadScanBuffer(bytes.NewReader(body), s.limit, s.hint)

			if !errors.Is(gotErr, wantErr) {
				t.Fatalf("err = %v, io.ReadAll = %v", gotErr, wantErr)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("bytes differ: got %d bytes, io.ReadAll %d bytes", len(got), len(want))
			}
		})
	}
}

// errAfterN yields n bytes and then fails, modelling an origin that resets
// mid-body. The scan pipeline fails CLOSED on a read error, so the error must
// survive — a swallowed one would deliver a truncated body as a clean scan.
type errAfterN struct {
	data []byte
	n    int
	err  error
}

func (e *errAfterN) Read(p []byte) (int, error) {
	if e.n <= 0 {
		return 0, e.err
	}
	n := copy(p, e.data[:min(len(e.data), e.n)])
	e.n -= n
	e.data = e.data[n:]
	return n, nil
}

func TestReadScanBuffer_PropagatesReadError(t *testing.T) {
	boom := errors.New("origin reset")
	body := makeBody(8192)

	for _, hint := range []int64{-1, 8192, 1 << 30} {
		t.Run(fmt.Sprintf("hint=%d", hint), func(t *testing.T) {
			want, wantErr := io.ReadAll(io.LimitReader(
				&errAfterN{data: body, n: 4096, err: boom}, 5<<20))
			got, gotErr := ReadScanBuffer(
				&errAfterN{data: body, n: 4096, err: boom}, 5<<20, hint)

			if !errors.Is(gotErr, boom) {
				t.Fatalf("error not propagated: %v", gotErr)
			}
			if !errors.Is(wantErr, boom) {
				t.Fatalf("baseline lost the error: %v", wantErr)
			}
			// The partial prefix must match io.ReadAll's too — the caller may
			// log or account it.
			if !bytes.Equal(got, want) {
				t.Fatalf("partial bytes differ: got %d, io.ReadAll %d", len(got), len(want))
			}
		})
	}
}

// oneByteReader forces the many-small-reads shape a real TLS conn produces, so
// the loop is exercised with partial fills rather than one satisfying read.
type oneByteReader struct{ data []byte }

func (o *oneByteReader) Read(p []byte) (int, error) {
	if len(o.data) == 0 {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = o.data[0]
	o.data = o.data[1:]
	return 1, nil
}

func TestReadScanBuffer_PartialReads(t *testing.T) {
	body := makeBody(4096)
	got, err := ReadScanBuffer(&oneByteReader{data: append([]byte(nil), body...)}, 5<<20, 4096)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("got %d bytes, want %d", len(got), len(body))
	}
}

// TestReadScanBuffer_HintDoesNotCapReading pins the security half of the
// contract explicitly: a body LARGER than its declaration is still buffered up
// to the scan limit, so the undeclared tail reaches the scanners.
func TestReadScanBuffer_HintDoesNotCapReading(t *testing.T) {
	body := makeBody(64 << 10)
	got, err := ReadScanBuffer(bytes.NewReader(body), 5<<20, 1024) // declares 1 KB, sends 64 KB
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(got) != len(body) {
		t.Fatalf("read %d bytes, want the full %d — the tail would be forwarded unscanned", len(got), len(body))
	}
}

// TestReadScanBuffer_PresizeIsBounded pins the amplification guard: an origin
// that declares far more than it sends must not make the proxy commit an
// arbitrarily large buffer.
func TestReadScanBuffer_PresizeIsBounded(t *testing.T) {
	got, err := ReadScanBuffer(bytes.NewReader(nil), 512<<20, 512<<20)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if cap(got) > maxScanPresizeBytes+512 {
		t.Fatalf("pre-sized %d bytes from an empty body; cap is %d", cap(got), maxScanPresizeBytes)
	}
}

// TestReadScanBuffer_AllocationsConstant is the regression gate: the whole point
// is that the allocation count no longer scales with body size. io.ReadAll pays
// one growth per doubling (15 allocs at 16 KB, 22 at 256 KB, 26 at 1 MB); the
// pre-sized path must stay flat.
func TestReadScanBuffer_AllocationsConstant(t *testing.T) {
	const maxAllocs = 3 // LimitReader + the buffer + slack for the runtime
	for _, size := range []int{16 << 10, 256 << 10, maxScanPresizeBytes} {
		body := makeBody(size)
		got := testing.AllocsPerRun(50, func() {
			out, err := ReadScanBuffer(bytes.NewReader(body), 5<<20, int64(size))
			if err != nil || len(out) != size {
				t.Fatalf("size=%d: err=%v len=%d", size, err, len(out))
			}
		})
		// bytes.NewReader is one more allocation inside the closure.
		if got > maxAllocs+1 {
			t.Fatalf("size=%d: %.0f allocs/op, want <= %d", size, got, maxAllocs+1)
		}
	}
}

// stallReader yields a few bytes, then fails — the shape of a hostile origin
// that declares a large Content-Length and then never delivers it.
type stallReader struct {
	payload []byte
	err     error
}

func (s *stallReader) Read(p []byte) (int, error) {
	if len(s.payload) == 0 {
		return 0, s.err
	}
	n := copy(p, s.payload)
	s.payload = s.payload[n:]
	return n, nil
}

// TestReadScanBuffer_StalledDeclarationDoesNotCommitHint pins the deferred
// allocation: an origin that declares a body inside the presize cap but stalls
// before delivering it must cost this proxy the io.ReadAll seed size it always
// cost, not a hint-sized buffer per in-flight response (an amplification where
// N parallel declare-and-stall responses commit N x maxScanPresizeBytes of
// live heap for zero attacker bandwidth).
func TestReadScanBuffer_StalledDeclarationDoesNotCommitHint(t *testing.T) {
	stallErr := errors.New("origin stalled")
	src := &stallReader{payload: []byte("abc"), err: stallErr}

	got, err := ReadScanBuffer(src, 5<<20, maxScanPresizeBytes)
	if !errors.Is(err, stallErr) {
		t.Fatalf("err = %v, want the stall error", err)
	}
	if string(got) != "abc" {
		t.Fatalf("bytes = %q, want the delivered prefix", got)
	}
	if cap(got) >= maxScanPresizeBytes {
		t.Fatalf("returned buffer capacity %d — the declared hint was allocated before the origin produced the body", cap(got))
	}
	if cap(got) > 512 {
		t.Fatalf("returned buffer capacity %d, want <= the 512-byte io.ReadAll seed", cap(got))
	}
}
