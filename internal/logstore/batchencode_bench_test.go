package logstore

import (
	"encoding/json"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	badger "github.com/dgraph-io/badger/v4"
)

// batchencode_bench_test.go — the before/after for the flush-path serializer.
//
// The LEGACY arm (one json.Marshal per entry) is kept in-tree for the same
// reason BenchmarkHTTPForward_LegacyClientPerRequest and the reqlog
// BenchmarkRingOrderPrim* arms are: a claim about cost is only maintainable if
// the comparison can be re-run on the hardware in front of you. It keeps its
// own state and never touches batchEncoder, so no arm can perturb the shipped
// path.
//
// Measured on a 4-core Xeon @ 2.10GHz, go1.27.3, -benchtime 500x, n=5 medians.
// Per 256-entry batch (flushBatchSize, the full-batch case):
//
//	                        │ ns/op   │ B/op    │ allocs/op
//	Legacy (Marshal/entry)  │ 382,893 │ 271,447 │ 768
//	Shipped (shared buffer) │ 257,023 │     793 │ 0
//	                        │ -33%    │ -99.7%  │ -768
//
// Per entry that is ~1,500 ns → ~1,000 ns, ~1,060 B → ~3 B, and 3 allocations
// → 0. The store takes one entry per proxied request, so the garbage line is
// the one that matters: it was scaling with request rate.
//
// Through a live Badger store (BenchmarkFlushBatchThroughStore*, n=3 medians),
// which is the honest end-to-end share — Badger's own write dominates what is
// left: 863,955 → 629,234 ns/op (-27%), 399,669 → 129,875 B/op (-67%),
// 4,476 → 3,708 allocs/op, i.e. exactly the 768 this change removes.
//
// BenchmarkFlushEncode_BySize shows the win does not depend on a full batch
// (legacy → shared, n=3 medians): n=1 2,539 → 1,504 ns; n=16 24,301 → 20,622;
// n=64 104,744 → 74,080; n=256 421,494 → 247,806 — 0 allocations at every size.

// ── legacy arm ──────────────────────────────────────────────────────────────

// encodeLegacy is the replaced encode step verbatim: a fresh heap allocation
// per entry from json.Marshal.
func encodeLegacy(batch []Entry, out [][]byte) [][]byte {
	out = out[:0]
	for i := range batch {
		b, err := json.Marshal(batch[i])
		if err != nil {
			continue
		}
		out = append(out, b)
	}
	return out
}

// flushBatchLegacy is Store.flushBatch's replaced body, for the whole-flush
// arm below (encode + Badger write together).
func (s *Store) flushBatchLegacy(batch []Entry) []Entry {
	if len(batch) == 0 {
		return batch
	}
	wb := s.db.NewWriteBatch()
	var added int64
	for i := range batch {
		b, err := json.Marshal(batch[i])
		if err != nil {
			continue
		}
		key := storeKey(batch[i].TS, atomic.AddUint32(&s.seq, 1))
		ent := badger.NewEntry(key, b)
		if ttl := time.Duration(atomic.LoadInt64(&s.ttlNanos)); ttl > 0 {
			ent = ent.WithTTL(ttl)
		}
		_ = wb.SetEntry(ent)
		added += int64(len(key) + len(b))
	}
	if err := wb.Flush(); err != nil {
		return batch[:0]
	}
	atomic.AddInt64(&s.bytesUsed, added)
	return batch[:0]
}

var encodeSink []byte

// ── encode step: before vs after, at the shipped batch size ─────────────────

func BenchmarkFlushEncode_LegacyMarshalPerEntry(b *testing.B) {
	batch := encodeBatchFixture(flushBatchSize)
	out := make([][]byte, 0, flushBatchSize)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out = encodeLegacy(batch, out)
		encodeSink = out[len(out)-1]
	}
}

func BenchmarkFlushEncode(b *testing.B) {
	batch := encodeBatchFixture(flushBatchSize)
	enc := newBatchEncoder()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enc.reset()
		for j := range batch {
			enc.add(j, &batch[j])
		}
		for j := range enc.recs {
			encodeSink = enc.at(j)
		}
	}
}

// ── regression arms: the win must hold across batch sizes, not just at 256 ──
//
// The 500ms ticker flushes partial batches, so a lightly loaded gateway
// flushes 1–16 entries at a time and a loaded one flushes 256. Both ends are
// measured so a future change cannot trade the small-batch case away: the
// shared buffer must not be slower than the legacy shape at ANY size.

func BenchmarkFlushEncode_BySize(b *testing.B) {
	for _, n := range []int{1, 16, 64, flushBatchSize} {
		batch := encodeBatchFixture(n)
		b.Run(fmt.Sprintf("legacy/n=%d", n), func(b *testing.B) {
			out := make([][]byte, 0, n)
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				out = encodeLegacy(batch, out)
				encodeSink = out[len(out)-1]
			}
		})
		b.Run(fmt.Sprintf("shared/n=%d", n), func(b *testing.B) {
			enc := newBatchEncoder()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				enc.reset()
				for j := range batch {
					enc.add(j, &batch[j])
				}
				for j := range enc.recs {
					encodeSink = enc.at(j)
				}
			}
		})
	}
}

// ── whole flush, through a live Badger store ────────────────────────────────
//
// The encode arms above isolate the change; this one states its share of the
// real flush, Badger write included, so the gain is not overclaimed.

func benchFlushThroughStore(b *testing.B, legacy bool) {
	b.Helper()
	s, err := OpenTTL(b.TempDir(), 0, 0, nil, nil)
	if err != nil {
		b.Fatalf("OpenTTL: %v", err)
	}
	b.Cleanup(func() { _ = s.Close() })
	enc := newBatchEncoder()
	fixture := encodeBatchFixture(flushBatchSize)
	batch := make([]Entry, 0, flushBatchSize)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		batch = append(batch[:0], fixture...)
		if legacy {
			batch = s.flushBatchLegacy(batch)
		} else {
			batch = s.flushBatch(enc, batch)
		}
	}
}

func BenchmarkFlushBatchThroughStore_Legacy(b *testing.B) { benchFlushThroughStore(b, true) }
func BenchmarkFlushBatchThroughStore(b *testing.B)        { benchFlushThroughStore(b, false) }

// ── the producer hot path, contended ────────────────────────────────────────
//
// flushBatch itself runs on ONE goroutine (the write loop), so a parallel
// encode arm would measure a shape production never takes. The contended
// measurement that does matter is Add — the call the proxy makes per request —
// so it is here as the concurrency arm, confirming this change does not move
// the enqueue cost it sits behind.

func BenchmarkStoreAddParallel(b *testing.B) {
	s, err := OpenTTL(b.TempDir(), 0, 0, nil, nil)
	if err != nil {
		b.Fatalf("OpenTTL: %v", err)
	}
	b.Cleanup(func() { _ = s.Close() })
	e := entryRich()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			s.Add(e)
		}
	})
}

// BenchmarkStoreAddBurst is the stress arm: a burst larger than the write
// queue, which is the shape that exercises the flush loop at its batch cap
// (and Add's deliberate drop path) rather than at the ticker's partial batches.
func BenchmarkStoreAddBurst(b *testing.B) {
	s, err := OpenTTL(b.TempDir(), 0, 0, nil, nil)
	if err != nil {
		b.Fatalf("OpenTTL: %v", err)
	}
	b.Cleanup(func() { _ = s.Close() })
	burst := encodeBatchFixture(8192) // > the 4096-deep queue
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := range burst {
			s.Add(burst[j])
		}
	}
}
