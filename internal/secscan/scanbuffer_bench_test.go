package secscan

// scanbuffer_bench_test.go — evidence for pre-sizing the scan buffer from the
// origin's declared Content-Length instead of growing it with io.ReadAll.
//
// Measured on linux/amd64, Intel Xeon @ 2.10GHz, go1.26, -benchtime=2s
// -count=2 (best of two), 5 MiB scan limit — the shipped max_scan_mb default.
// "Grown" passes contentLength=-1, which is exactly the io.ReadAll path this
// change replaces; "Presized" passes the true size, the shape ~all real
// responses have.
//
//	                      BEFORE (grown)              AFTER (pre-sized)
//	16 KB body     13321 ns/op   37832 B  15 allocs    4628 ns/op   18504 B  3 allocs
//	256 KB body   202589 ns/op  629706 B  22 allocs   88226 ns/op  270409 B  3 allocs
//	1 MB body     729380 ns/op 2228046 B  26 allocs  609214 ns/op 1056846 B  3 allocs
//
// Two things to read out of that, in order of importance:
//
//   - The BYTES roughly halve at every size, and the allocation count stops
//     scaling with the body: 15/22/26 becomes a flat 3. This path runs on every
//     scanned response body of every inspected tunnel, and its garbage lands in
//     the same heap the latency-critical relay goroutines share, so halving the
//     volume is the durable win — the one that shows up as GC pressure rather
//     than as a number in this table.
//
//   - Wall-clock falls 19-66%, biggest at the small sizes that dominate real
//     web traffic. The 1 MB row narrows because a big body spends proportionally
//     more time in the copy that both paths must do; the allocator work being
//     removed is a fixed share, not a growing one.
//
// The parallel benchmark is the shape that actually matters for a gateway —
// many tunnels buffering at once, contending for the allocator — and is kept as
// a floor against a future change that reintroduces per-body growth.

import (
	"bytes"
	"testing"
)

func benchScanBuffer(b *testing.B, size int, presized bool) {
	body := makeBody(size)
	const limit = 5 << 20
	hint := int64(size)
	if !presized {
		hint = -1 // no declaration → the io.ReadAll growth path
	}
	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, err := ReadScanBuffer(bytes.NewReader(body), limit, hint)
		if err != nil || len(out) != size {
			b.Fatalf("err=%v len=%d", err, len(out))
		}
	}
}

func BenchmarkScanBufferGrown16KB(b *testing.B)     { benchScanBuffer(b, 16<<10, false) }
func BenchmarkScanBufferPresized16KB(b *testing.B)  { benchScanBuffer(b, 16<<10, true) }
func BenchmarkScanBufferGrown256KB(b *testing.B)    { benchScanBuffer(b, 256<<10, false) }
func BenchmarkScanBufferPresized256KB(b *testing.B) { benchScanBuffer(b, 256<<10, true) }
func BenchmarkScanBufferGrown1MB(b *testing.B)      { benchScanBuffer(b, 1<<20, false) }
func BenchmarkScanBufferPresized1MB(b *testing.B)   { benchScanBuffer(b, 1<<20, true) }

// BenchmarkScanBufferParallel4KB is the concurrency shape: many inspected
// tunnels filling scan buffers at once, all contending for the same heap.
func BenchmarkScanBufferParallel4KB(b *testing.B) {
	body := makeBody(4096)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := ReadScanBuffer(bytes.NewReader(body), 5<<20, 4096); err != nil {
				b.Fatal(err)
			}
		}
	})
}
