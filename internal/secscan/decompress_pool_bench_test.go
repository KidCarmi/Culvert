package secscan

// decompress_pool_bench_test.go — before/after evidence for the scan-path
// gzip and deflate decompressors (secscan.go), which used to construct a
// decoder per response and now Reset a pooled one.
//
// Run:
//
//	go test -run '^$' -bench 'BenchmarkExpand' -benchmem -count=6 ./internal/secscan/
//
// legacyExpandGzipForScan / legacyExpandDeflateForScan are the FROZEN
// pre-change shapes, kept so the comparison stays reproducible in-tree rather
// than living only in a commit message. They are deliberately verbatim copies
// of the code that was replaced; they are not called by production and must
// NOT be "kept in sync" with the shipped arms — their whole value is that they
// do not move. The one unavoidable difference is that they call the shared
// expansionVerdict tail instead of repeating its four branches, which decides
// nothing about allocations: it is called identically by both arms, takes only
// already-materialised values, and never touches a decoder.
//
// Measured on this machine (go1.27.3, linux/amd64, 4 vCPU, Xeon @ 2.10GHz,
// medians of n=6) — see the gate in decompress_pool_benchgate_test.go for the
// assertion that actually holds this. B/op includes readCapped's 32 KiB output
// buffer, which both arms pay identically; everything else is decoder state:
//
//	                        legacy                        pooled
//	gzip 16 KiB      35.2 us  74 000 B  7 allocs   24.3 us  32 775 B  1 alloc
//	gzip 16 KiB 4x   25.9 us  74 000 B  7 allocs   14.3 us  32 780 B  1 alloc
//	deflate 16 KiB   33.3 us  73 296 B  6 allocs   22.8 us  32 775 B  1 alloc
//	deflate 16 KiB 4x 27.9 us 73 296 B  6 allocs   13.5 us  32 780 B  1 alloc
//	gzip 256 KiB      ~470 us 1 057 666 B 27 allocs ~462 us 1 016 622 B 21 allocs
//
// The removed bytes are all decoder STATE, not content: compress/flate's
// fixed 32 KiB history window plus its Huffman tables, and gzip's 512-byte
// header scratch on top. Because that cost is FIXED per response, the 256 KiB
// row is the honest limit of the change — the decode dominates there and ns/op
// is inside the noise. The 16 KiB rows are the common case, and the parallel
// rows are the ones a gateway actually runs: the gap widens with concurrency
// because what is removed is allocator and GC work every core was doing at
// once.
//
// The decompressed output is byte-identical — that is what
// TestExpandPooled_MatchesLegacy pins, over repeated reuse of the same pooled
// reader, which is the shape a stale-state bug would show up in.

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"testing"
)

// ── Frozen pre-change shapes ─────────────────────────────────────────────────

// legacyExpandGzipForScan is the gzip arm as it stood before pooling. Frozen.
func legacyExpandGzipForScan(data []byte, ce string) (out []byte, bomb bool) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		// gzip.NewReader failed (malformed header) — scan raw bytes.
		return data, false
	}
	defer reader.Close() //nolint:errcheck // frozen pre-change shape; Close reports only the terminal read error
	decompressed, readErr, isBomb := expandForScan(reader, data, ce)
	return expansionVerdict(data, decompressed, readErr, isBomb)
}

// legacyExpandDeflateForScan is the deflate arm as it stood before pooling.
// Frozen.
func legacyExpandDeflateForScan(data []byte, ce string) (out []byte, bomb bool) {
	reader := flate.NewReader(bytes.NewReader(data))
	defer reader.Close() //nolint:errcheck // frozen pre-change shape; Close reports only the terminal read error
	decompressed, readErr, isBomb := expandForScan(reader, data, ce)
	return expansionVerdict(data, decompressed, readErr, isBomb)
}

// ── Payloads ─────────────────────────────────────────────────────────────────

// benchMarkupBody returns roughly n bytes of markup-shaped text. Shape matters:
// a run of identical bytes compresses to almost nothing and would make the
// decode itself free, hiding the construction cost this benchmark is about.
func benchMarkupBody(n int) []byte {
	var b bytes.Buffer
	i := 0
	for b.Len() < n {
		b.WriteString(`<div class="row" id="r`)
		b.WriteString(string(rune('a' + i%26)))
		b.WriteString(`"><span>item `)
		b.WriteString(string(rune('0' + i%10)))
		b.WriteString(`</span><a href="/p/`)
		b.WriteString(string(rune('A' + i%26)))
		b.WriteString(`">link</a></div>` + "\n")
		i++
	}
	return b.Bytes()[:n]
}

func benchGzipPayload(tb testing.TB, n int) []byte {
	tb.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(benchMarkupBody(n)); err != nil {
		tb.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		tb.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func benchDeflatePayload(tb testing.TB, n int) []byte {
	tb.Helper()
	var buf bytes.Buffer
	fw, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		tb.Fatalf("flate writer: %v", err)
	}
	if _, err := fw.Write(benchMarkupBody(n)); err != nil {
		tb.Fatalf("flate write: %v", err)
	}
	if err := fw.Close(); err != nil {
		tb.Fatalf("flate close: %v", err)
	}
	return buf.Bytes()
}

// ── Benchmarks ───────────────────────────────────────────────────────────────

func benchExpand(b *testing.B, data []byte, ce string, fn func([]byte, string) ([]byte, bool)) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, bomb := fn(data, ce)
		if bomb || len(out) == 0 {
			b.Fatalf("expansion failed: bomb=%v len=%d", bomb, len(out))
		}
	}
}

func BenchmarkExpandGzip_Legacy16KB(b *testing.B) {
	benchExpand(b, benchGzipPayload(b, 16<<10), "gzip", legacyExpandGzipForScan)
}

func BenchmarkExpandGzip_Pooled16KB(b *testing.B) {
	benchExpand(b, benchGzipPayload(b, 16<<10), "gzip", expandGzipForScan)
}

func BenchmarkExpandGzip_Legacy256KB(b *testing.B) {
	benchExpand(b, benchGzipPayload(b, 256<<10), "gzip", legacyExpandGzipForScan)
}

func BenchmarkExpandGzip_Pooled256KB(b *testing.B) {
	benchExpand(b, benchGzipPayload(b, 256<<10), "gzip", expandGzipForScan)
}

func BenchmarkExpandDeflate_Legacy16KB(b *testing.B) {
	benchExpand(b, benchDeflatePayload(b, 16<<10), "deflate", legacyExpandDeflateForScan)
}

func BenchmarkExpandDeflate_Pooled16KB(b *testing.B) {
	benchExpand(b, benchDeflatePayload(b, 16<<10), "deflate", expandDeflateForScan)
}

// The parallel pair is the one that matters for a gateway: the scan path runs
// one expansion per response on the request goroutine, so the interesting
// question is whether the saving survives contention on the pool rather than
// whether it exists on one core. A sync.Pool is per-P, so it should.
func benchExpandParallel(b *testing.B, data []byte, ce string, fn func([]byte, string) ([]byte, bool)) {
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			out, bomb := fn(data, ce)
			if bomb || len(out) == 0 {
				b.Fatalf("expansion failed: bomb=%v len=%d", bomb, len(out))
			}
		}
	})
}

func BenchmarkExpandGzip_LegacyParallel(b *testing.B) {
	benchExpandParallel(b, benchGzipPayload(b, 16<<10), "gzip", legacyExpandGzipForScan)
}

func BenchmarkExpandGzip_PooledParallel(b *testing.B) {
	benchExpandParallel(b, benchGzipPayload(b, 16<<10), "gzip", expandGzipForScan)
}

func BenchmarkExpandDeflate_LegacyParallel(b *testing.B) {
	benchExpandParallel(b, benchDeflatePayload(b, 16<<10), "deflate", legacyExpandDeflateForScan)
}

func BenchmarkExpandDeflate_PooledParallel(b *testing.B) {
	benchExpandParallel(b, benchDeflatePayload(b, 16<<10), "deflate", expandDeflateForScan)
}

// BenchmarkExpandBrotli_Unpooled is the CONTROL for the arm this change
// deliberately leaves alone (see "WHY BROTLI IS NOT POOLED" in secscan.go). It
// exists so the cost of that decision is a number in the tree rather than an
// assumption, for whoever revisits it with a retention bound in hand.
func BenchmarkExpandBrotli_Unpooled(b *testing.B) {
	benchExpand(b, benchBrotliPayload(b, 16<<10), "br", expandBrotliForScan)
}
