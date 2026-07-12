package main

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"testing"
)

// flushCountRW is an http.ResponseWriter + http.Flusher that counts Flush calls
// and (optionally) collects the body, for asserting h2CopyBody's adaptive-flush
// behavior without a live h2 server.
type flushCountRW struct {
	hdr     http.Header
	status  int
	flushes int
	body    *bytes.Buffer // nil ⇒ discard (throughput benchmarks)
	written int64
}

func (r *flushCountRW) Header() http.Header {
	if r.hdr == nil {
		r.hdr = http.Header{}
	}
	return r.hdr
}

func (r *flushCountRW) Write(p []byte) (int, error) {
	r.written += int64(len(p))
	if r.body != nil {
		return r.body.Write(p)
	}
	return len(p), nil
}

func (r *flushCountRW) WriteHeader(s int) { r.status = s }
func (r *flushCountRW) Flush()            { r.flushes++ }

// chunkReader returns a caller-specified sequence of chunk sizes, one per Read,
// drawn from an underlying byte source. It models an origin that hands the proxy
// data in specific burst sizes (full-buffer bursts vs short trickle reads) so the
// adaptive-flush decision (flush iff nr < len(buf)) can be exercised deterministically.
type chunkReader struct {
	data   []byte
	chunks []int // bytes to return on each successive Read
	off    int
	idx    int
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if c.idx >= len(c.chunks) {
		return 0, io.EOF
	}
	n := c.chunks[c.idx]
	c.idx++
	if n > len(p) {
		n = len(p)
	}
	if c.off+n > len(c.data) {
		n = len(c.data) - c.off
	}
	copy(p, c.data[c.off:c.off+n])
	c.off += n
	if c.idx >= len(c.chunks) || c.off >= len(c.data) {
		return n, io.EOF
	}
	return n, nil
}

// TestH2CopyBody_AdaptiveFlush proves the flush-on-short-read contract:
//   - a full-buffer read (nr == len(buf)) does NOT flush (bulk coalescing),
//   - a short read (nr < len(buf)) DOES flush (trickle/pause latency),
//   - the delivered bytes are byte-exact regardless.
func TestH2CopyBody_AdaptiveFlush(t *testing.T) {
	full := relayBufSize
	// Two full-buffer bursts (no flush) followed by a short tail (one flush).
	data := bytes.Repeat([]byte("x"), full*2+1234)
	rw := &flushCountRW{body: &bytes.Buffer{}}
	src := &chunkReader{data: data, chunks: []int{full, full, 1234}}

	if err := h2CopyBody(rw, src); err != nil {
		t.Fatalf("h2CopyBody: %v", err)
	}
	if !bytes.Equal(rw.body.Bytes(), data) {
		t.Fatalf("body mismatch: got %d bytes, want %d", rw.body.Len(), len(data))
	}
	// Exactly one flush — only the final short (1234-byte) read triggers it; the two
	// full-buffer bursts coalesce.
	if rw.flushes != 1 {
		t.Fatalf("flushes = %d, want 1 (only the short tail read flushes)", rw.flushes)
	}
}

// TestH2CopyBody_FullReadsNeverFlushButDeliverAll pins the coalescing invariant:
// a stream whose reads all fill the buffer emits ZERO explicit flushes yet delivers
// every byte. This guards against a future x/net change to the h2 handler's write
// buffer size — the whole "no explicit flush needed on full writes" reasoning
// depends on a full 128 KB write bypassing that ~4 KB bufio straight to the frame
// scheduler; the stream still egresses because a completed handler flushes on
// END_STREAM.
func TestH2CopyBody_FullReadsNeverFlushButDeliverAll(t *testing.T) {
	full := relayBufSize
	data := bytes.Repeat([]byte("f"), full*3)
	rw := &flushCountRW{body: &bytes.Buffer{}}
	src := &chunkReader{data: data, chunks: []int{full, full, full}}

	if err := h2CopyBody(rw, src); err != nil {
		t.Fatalf("h2CopyBody: %v", err)
	}
	if !bytes.Equal(rw.body.Bytes(), data) {
		t.Fatalf("body mismatch: got %d, want %d", rw.body.Len(), len(data))
	}
	if rw.flushes != 0 {
		t.Fatalf("flushes = %d, want 0 (full-buffer reads coalesce; no explicit flush)", rw.flushes)
	}
}

// TestH2CopyBody_TrickleFlushesEveryChunk proves a pure trickle stream (every read
// short) is flushed on every chunk — SSE / gRPC-server-streaming latency is
// preserved, unchanged from the old unconditional per-write flush.
func TestH2CopyBody_TrickleFlushesEveryChunk(t *testing.T) {
	data := bytes.Repeat([]byte("y"), 300)
	rw := &flushCountRW{body: &bytes.Buffer{}}
	src := &chunkReader{data: data, chunks: []int{100, 100, 100}}

	if err := h2CopyBody(rw, src); err != nil {
		t.Fatalf("h2CopyBody: %v", err)
	}
	if !bytes.Equal(rw.body.Bytes(), data) {
		t.Fatalf("body mismatch")
	}
	if rw.flushes != 3 {
		t.Fatalf("flushes = %d, want 3 (each short trickle chunk flushes)", rw.flushes)
	}
}

// TestH2CopyBody_ReadErrorPropagates ensures a mid-body read error is surfaced (so
// the caller resets the stream via exDeliverError) rather than being swallowed.
func TestH2CopyBody_ReadErrorPropagates(t *testing.T) {
	rw := &flushCountRW{body: &bytes.Buffer{}}
	src := io.MultiReader(bytes.NewReader([]byte("partial")), &errReader{})
	err := h2CopyBody(rw, src)
	if err == nil || err.Error() != "boom" {
		t.Fatalf("err = %v, want boom", err)
	}
}

type errReader struct{}

func (e *errReader) Read([]byte) (int, error) { return 0, errBoom }

var errBoom = errors.New("boom")

// TestH2CopyBody_NilFlusherSafe pins that the flusher != nil guard is load-bearing:
// a writer that does NOT implement http.Flusher (recordingRW) must copy byte-exact
// without panicking. In production the h2 responseWriter is always a Flusher, so
// this path only occurs in tests — but the guard must never be removed.
func TestH2CopyBody_NilFlusherSafe(t *testing.T) {
	data := bytes.Repeat([]byte("n"), relayBufSize+777) // one full + one short read
	rw := &recordingRW{}                                // no Flush method
	src := &chunkReader{data: data, chunks: []int{relayBufSize, 777}}
	if err := h2CopyBody(rw, src); err != nil {
		t.Fatalf("h2CopyBody: %v", err)
	}
	if !bytes.Equal(rw.body.Bytes(), data) {
		t.Fatalf("body mismatch: got %d, want %d", rw.body.Len(), len(data))
	}
}

// BenchmarkH2CopyBody_Bulk measures the byte-moving hot path on an IDEALISED bulk
// transfer where every read fills the 128 KiB buffer. rw/src are hoisted out of the
// timed loop (only their cursors reset) so ReportAllocs isolates the copy path — it
// evidences the pooled-buffer win: ZERO per-response allocation (vs io.Copy's 32 KB)
// and, in this best case, zero flush churn. Real upstreams rarely return full 128
// KiB reads (see _BulkFlowControlled for the realistic flush cadence).
func BenchmarkH2CopyBody_Bulk(b *testing.B) {
	const total = 8 << 20 // 8 MiB body
	data := bytes.Repeat([]byte("z"), total)
	chunks := make([]int, 0, total/relayBufSize+1)
	for remaining := total; remaining > 0; remaining -= relayBufSize {
		chunks = append(chunks, relayBufSize)
	}
	rw := &flushCountRW{} // discard body
	src := &chunkReader{data: data, chunks: chunks}
	b.SetBytes(total)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		src.idx, src.off = 0, 0
		rw.flushes, rw.written = 0, 0
		if err := h2CopyBody(rw, src); err != nil {
			b.Fatalf("copy: %v", err)
		}
		if rw.flushes != 0 {
			b.Fatalf("full-read bulk flushed %d times, want 0", rw.flushes)
		}
	}
}

// BenchmarkH2CopyBody_BulkFlowControlled measures the REALISTIC bulk path: a real
// http2.Transport body is flow-control bounded and typically returns sub-buffer
// reads, so nr < 128 KiB is usually true and the adaptive path flushes ~per read —
// i.e. the coalescing win is opportunistic. This still evidences the guaranteed
// win: zero per-response allocation regardless of read size.
func BenchmarkH2CopyBody_BulkFlowControlled(b *testing.B) {
	const total = 8 << 20
	const readSize = 24 << 10 // 24 KiB — a typical coalesced h2 read under flow control
	data := bytes.Repeat([]byte("z"), total)
	chunks := make([]int, 0, total/readSize+1)
	for remaining := total; remaining > 0; remaining -= readSize {
		chunks = append(chunks, readSize)
	}
	rw := &flushCountRW{}
	src := &chunkReader{data: data, chunks: chunks}
	b.SetBytes(total)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		src.idx, src.off = 0, 0
		rw.flushes, rw.written = 0, 0
		if err := h2CopyBody(rw, src); err != nil {
			b.Fatalf("copy: %v", err)
		}
	}
}

// BenchmarkH2CopyBody_Trickle measures the streaming path (many small reads, flush
// each) to confirm the adaptive path adds no overhead beyond the necessary flushes.
func BenchmarkH2CopyBody_Trickle(b *testing.B) {
	const chunk = 512
	const nChunks = 256
	data := bytes.Repeat([]byte("s"), chunk*nChunks)
	chunks := make([]int, nChunks)
	for i := range chunks {
		chunks[i] = chunk
	}
	rw := &flushCountRW{}
	src := &chunkReader{data: data, chunks: chunks}
	b.SetBytes(int64(chunk * nChunks))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		src.idx, src.off = 0, 0
		rw.flushes, rw.written = 0, 0
		if err := h2CopyBody(rw, src); err != nil {
			b.Fatalf("copy: %v", err)
		}
	}
}
