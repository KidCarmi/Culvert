package secscan

import "io"

// ── Scan-buffer fill ─────────────────────────────────────────────────────────
//
// Every response body that reaches the scanners is first buffered whole, so
// that a match can block the response instead of racing bytes already on their
// way to the client. That buffering ran through io.ReadAll, which seeds a
// 512-byte slice and grows it by append: an N-byte body costs O(log N)
// reallocations and pushes roughly 2N bytes through the allocator, of which
// ~N is pure copying of bytes that were already in the right place.
//
// Origins almost always declare Content-Length, and the proxy is holding the
// parsed *http.Response when it fills the buffer — so the final size is known
// before the first read. ReadScanBuffer takes that hint and allocates once.
//
// Measured by BenchmarkScanBuffer{Grown,Presized}* below (Go 1.26, 4-core
// amd64, bytes.Reader source, 5 MiB scan limit — the shipped max_scan_mb
// default), best of two runs at -benchtime=2s:
//
//	body size │ io.ReadAll (grown)           │ pre-sized                   │
//	   16 KB  │  13.3us   37.8 KB  15 allocs │   4.6us   18.5 KB  3 allocs │
//	  256 KB  │ 202.6us  629.7 KB  22 allocs │  88.2us  270.4 KB  3 allocs │
//	    1 MB  │ 729.4us    2.2 MB  26 allocs │ 609.2us    1.1 MB  3 allocs │
//
// So the allocator sees roughly half the bytes and a small constant number of
// allocations instead of one per doubling. Wall-clock falls 19-66%; the halved
// allocation volume is the part that matters most, because this path runs on
// every scanned response of every inspected tunnel and its garbage lands in the
// heap the proxy's latency-critical goroutines share.
//
// This is a COST change, not a POLICY change. The read loop below is io.ReadAll's
// own loop with a different starting capacity, so the bytes returned, the
// treatment of a short or over-long body, and the error semantics are identical
// — see TestReadScanBuffer_MatchesReadAll, which asserts that equivalence
// against the real io.ReadAll across every body/hint shape.

// maxScanPresizeBytes bounds how much the Content-Length hint may pre-allocate.
//
// Content-Length is declared by the ORIGIN, which for a forward proxy is
// attacker-choosable: a hostile origin can advertise a large body and then send
// nothing, so an unbounded hint would let one cheap response commit the full
// scan limit. Capping the hint keeps that bounded at 1 MiB per in-flight
// response while still covering the body sizes ordinary web traffic is made of.
// Past the cap the growth path takes over — where its doublings are few and
// already amortized over a large body — so the guard costs the tail of the win,
// not its bulk.
const maxScanPresizeBytes = 1 << 20

// ReadScanBuffer reads from r until EOF or limit bytes, whichever comes first,
// and returns the bytes read. It is a drop-in replacement for
// io.ReadAll(io.LimitReader(r, limit)) that uses contentLength — the origin's
// declared body size, or a value <= 0 when it declared none (chunked) — to
// allocate the destination buffer once instead of growing it.
//
// contentLength is a HINT ONLY and is never trusted for correctness: the read
// still runs to EOF or to limit, so an origin that under-declares its body does
// not get the tail past its declaration forwarded unscanned, and one that
// over-declares simply yields a shorter buffer.
func ReadScanBuffer(r io.Reader, limit, contentLength int64) ([]byte, error) {
	lr := io.LimitReader(r, limit)

	hint := contentLength
	if hint > limit {
		hint = limit // the limit governs; nothing past it will ever be read
	}
	if hint <= 0 || hint > maxScanPresizeBytes {
		// No usable declaration, or one too large to trust with an allocation.
		return io.ReadAll(lr)
	}

	// hint+512 rather than hint: the read that observes EOF still needs a free
	// slot to read into, and 512 is io.ReadAll's own seed size. Without the
	// slack a truthful Content-Length would pay one final grow-and-copy of the
	// whole buffer — exactly the cost this function exists to remove.
	buf := make([]byte, 0, hint+512)
	for {
		if len(buf) == cap(buf) {
			buf = append(buf, 0)[:len(buf)]
		}
		n, err := lr.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return buf, err
		}
	}
}
