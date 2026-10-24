package reqlog

// ring_order_bench_test.go — the measured answer to the question
// BenchmarkAddParallel's comment left open: can ringMu, the one process-wide
// exclusive lock every logged request takes, be removed?
//
// Measured answer: NO. Three alternatives were built and measured; the best of
// them ties the shipped mutex at four cores while costing 36% more at one, and
// the obvious one is three times WORSE. The shipped lock stands, and the
// remaining ceiling is recorded with its headroom instead of acted on.
//
// Everything here is benchmark-only (no production code changes), and it is
// in-tree rather than in a commit message for the same reason
// BenchmarkHTTPForward_LegacyClientPerRequest is: the comparison has to stay
// reproducible. The rejected alternative keeps its OWN state, so no arm can
// perturb Add, Get or SwapRingForTest, and
// TestTicketRing_OrderMatchesShippedRing proves it reproduces Get()'s window
// byte for byte — so the rejection rests on its cost, not on a broken
// prototype. It must not be "kept in sync" with Add; its value is that it
// does not move.
//
// WHY ORDER IS THE CONSTRAINT. Get() returns the newest MaxRing entries in
// arrival order, newest first, and the admin request feed renders them in that
// order. Establishing a total order over concurrent writers costs at least one
// read-modify-write on one shared word per entry, and that word is the whole
// game: every arm below either pays it or gives up the order.
//
// Measured on this tree (go1.27.3, linux/amd64, 4-vCPU Xeon @2.30GHz,
// -count=5 medians, all arms in ONE invocation so machine drift hits them
// equally). These are RunParallel arms, so ns/op is wall time per op across
// ALL workers — lower is more throughput, a genuinely parallel cost FALLS as
// cores are added and one that serialises rises:
//
//	                                     │ P=1  │ P=2   │ P=4   │ 1→4 throughput
//	ringMu ring write (SHIPPED)          │ 26.8 │  58.7 │ 110.9 │ 0.24x
//	ticket ring, per-slot mutex          │ 28.1 │ 178.8 │ 123.7 │ 0.23x  (1.1-3.0x WORSE)
//	sharded + global seq, sticky key     │ 32.4 │  95.2 │  86.2 │ 0.38x  (unreachable, see below)
//	sharded + global seq, realistic key  │ 36.5 │ 126.7 │ 111.5 │ 0.33x  (a tie at P=4)
//	─ primitives that bound any design ─ │      │       │       │
//	global atomic.Uint64.Add             │  8.2 │  32.1 │  27.1 │ 0.30x
//	time.Now() (unshared ordering key)   │ 46.4 │  23.4 │  11.6 │ 4.0x
//	unordered core-local ring write      │  7.9 │   3.4 │   1.9 │ 4.1x   (the floor)
//
// Run-to-run spread on this shared VM is roughly ±20% at P=4 (the shipped arm
// measured 110.9 here and 131.8 in an earlier identical run), so only the
// large gaps below are claims; the tie is reported as a tie.
//
// FIRST, the ticket ring is not merely no better, it is ~3x worse at two
// cores. The mutex serialises writers, which means one core at a time owns the
// head region and writes several consecutive 352-byte slots while its lines
// stay exclusive to it — the lock buys BATCHING. Direct-mapped tickets
// interleave the cores slot by slot, so every write pulls ~6 lines away from
// whichever core wrote them one ring-cycle ago. One contended lock was traded
// for six contended cache lines.
//
// SECOND, sharding does not pay here, and it fails for the reason store.go
// already recorded rather than a new one. Core-local shards do fix the line
// migration — the sticky-key arm is the fastest ordered shape at four cores —
// but a proxied request is a FRESH GOROUTINE, so the request path has no
// stickiness to offer. The only key available is tsShardIndex()'s per-P
// rand.Uint64, redrawn per entry, and against a 352-byte Entry that lands
// every write on a shard whose lines are cold or owned elsewhere. The
// realistic arm is therefore a dead heat with the shipped mutex at four cores
// and 36%/116% worse at one and two. That is the same verdict store.go
// reaches for the 60-bucket time-series ring — "against an object that size
// its cost ate the gain" — and the same contrast with the current-minute
// counter that DOES shard: a counter needs only its sum, so its shards never
// have to be put back in order. This ring cannot give that up, which is why
// the tsLiveShard shape does not transfer.
//
// THIRD, the floor, and the one shape that genuinely scales: an unordered
// core-local write runs at 1.9 ns and IMPROVES with cores. Note also that
// time.Now() is not the obstacle an earlier reading of these numbers made it
// out to be — it needs no shared word and so falls 46.4 → 11.6 as cores are
// added. A timestamp-keyed, core-local ring is thus the fast design, and it is
// fast precisely because ns timestamps are an APPROXIMATE order (ties, and
// cross-core read skew) rather than a total one. Adopting it would change what
// the admin request feed shows. That is a product decision about an
// admin-visible surface, not a performance fix, and it is not taken here.
//
// WHAT THE SHIPPED LOCK COSTS, in the units that decide whether to act:
// ~37M entries/s at one core falling to ~9M at four. Negative scaling is an
// unattractive shape on the 16- and 32-core hardware this appliance ships
// onto, and it is why the question was asked. It is also one to two orders of
// magnitude above the request rate of the gateways this serves, and every
// ordered alternative measured above is a tie or a regression. So: recorded,
// not acted on. Re-open it if a profile ever shows ringMu as a real
// bottleneck, and re-run these arms first if it does.
//
// One incidental correction carried in this change: the ring comments in
// reqlog.go and persist.go sized an Entry at 328 bytes, which the schema has
// since outgrown. unsafe.Sizeof(Entry{}) is 352 on linux/amd64 at this
// revision, and those comments now say so.

import (
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ── The rejected alternative, frozen ────────────────────────────────────────
//
// A direct-mapped ring: ticket s always lands in slot (s-1)%MaxRing, so slot
// order IS ticket order and no head pointer is shared between writers. The
// per-slot mutex is what keeps it race-free (a torn read of an Entry's string
// headers would hand a reader a pointer from one entry with a length from
// another). Ticket s and ticket s+MaxRing collide on one slot, so a lagging
// writer must never clobber a newer entry — hence the s > sl.seq guard, which
// drops an entry that was already due for eviction.
//
// It keeps its OWN state. Production's ring is untouched by these arms, so
// nothing here can perturb Add, Get, or SwapRingForTest.

type ticketSlot struct {
	mu  sync.Mutex
	seq uint64 // 1-based ticket occupying this slot; 0 = never written
	e   Entry
}

var (
	ticketSeq   atomic.Uint64
	ticketSlots []ticketSlot
	ticketOnce  sync.Once
)

func ticketInit() { ticketSlots = make([]ticketSlot, MaxRing) }

func addTicketRing(e Entry) {
	ticketOnce.Do(ticketInit)
	s := ticketSeq.Add(1)
	sl := &ticketSlots[(s-1)%MaxRing]
	sl.mu.Lock()
	if s > sl.seq {
		sl.seq = s
		sl.e = e
	}
	sl.mu.Unlock()
}

// getTicketRing is Get()'s shape for the ticket ring: newest-first over the
// newest MaxRing tickets, skipping a slot whose occupant is not the ticket
// asked for (not yet committed, or already evicted).
func getTicketRing() []Entry {
	ticketOnce.Do(ticketInit)
	end := ticketSeq.Load()
	if end == 0 {
		return nil
	}
	first := uint64(1)
	if end > MaxRing {
		first = end - MaxRing + 1
	}
	out := make([]Entry, 0, end-first+1)
	for s := end; ; s-- {
		sl := &ticketSlots[(s-1)%MaxRing]
		sl.mu.Lock()
		if sl.seq == s {
			out = append(out, sl.e)
		}
		sl.mu.Unlock()
		if s == first {
			break
		}
	}
	return out
}

// resetTicketRing clears the alternative's state between arms. It takes no
// slot locks: it is only ever called with no concurrent writer, which is the
// only context it is correct in.
func resetTicketRing() {
	ticketOnce.Do(ticketInit)
	for i := range ticketSlots {
		ticketSlots[i].seq = 0
		ticketSlots[i].e = Entry{}
	}
	ticketSeq.Store(0)
}

// TestTicketRing_OrderMatchesShippedRing is what makes the rejection above a
// statement about cost. The alternative must produce the SAME newest-first
// window as the shipped ring — including the wrap and the MaxRing truncation —
// or its benchmark would be measuring something cheaper than the real job.
func TestTicketRing_OrderMatchesShippedRing(t *testing.T) {
	restore := SwapRingForTest()
	defer restore()
	restoreW := SwapPersistenceForTest()
	defer restoreW()
	oldHistory := history
	history = nil
	defer func() { history = oldHistory }()
	resetTicketRing()
	defer resetTicketRing()

	for i := 0; i < MaxRing+137; i++ { // past the wrap, not on a boundary
		e := benchEntry(i)
		Add(e)
		addTicketRing(e)
	}

	shipped, alt := Get(), getTicketRing()
	if len(shipped) != MaxRing {
		t.Fatalf("precondition: shipped ring returned %d entries, want MaxRing=%d", len(shipped), MaxRing)
	}
	if len(alt) != len(shipped) {
		t.Fatalf("ticket ring returned %d entries, shipped ring %d", len(alt), len(shipped))
	}
	for i := range shipped {
		// Entry carries a []string field, so this is DeepEqual rather than ==.
		if !reflect.DeepEqual(alt[i], shipped[i]) {
			t.Fatalf("entry %d differs:\n ticket: %+v\nshipped: %+v", i, alt[i], shipped[i])
		}
	}
}

// BenchmarkAddTicketRingParallel is the alternative's arm. Read it against
// BenchmarkAddParallel (reqlog_bench_test.go) at matched GOMAXPROCS.
func BenchmarkAddTicketRingParallel(b *testing.B) {
	resetTicketRing()
	defer resetTicketRing()
	for i := 0; i < MaxRing; i++ { // steady state: at capacity, as production is
		addTicketRing(benchEntry(i))
	}
	e := benchEntry(0)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			addTicketRing(e)
		}
	})
}

// ── The primitives that bound every design ──────────────────────────────────

var ringOrderSeq atomic.Uint64

// BenchmarkRingOrderPrimTicket is the ordering primitive in isolation: ONE
// read-modify-write on one shared word, which is the irreducible cost of a
// total order over concurrent writers. Compare it against the whole of
// BenchmarkAddParallel — it is the same order of magnitude, which is the
// finding.
func BenchmarkRingOrderPrimTicket(b *testing.B) {
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ringOrderSeq.Add(1)
		}
	})
}

// BenchmarkRingOrderPrimClock measures time.Now() as an alternative ordering
// key — the one that needs no shared word, and so the one that SCALES: 46.4 →
// 23.4 → 11.6 ns as cores are added. Read it with the single-core figure in
// view, because that figure alone is misleading: at P=1 the clock looks more
// expensive than the whole lock it would replace, and at P=4 it costs a tenth
// of it. What it buys is only an APPROXIMATE order (ties, and cross-core read
// skew), which is why it is a product question and not a drop-in.
func BenchmarkRingOrderPrimClock(b *testing.B) {
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		// Consumed through a branch rather than a shared sink: a benchmark that
		// writes shared state per iteration measures its own instrument (the
		// lesson persist.go records). A worker may legitimately get zero
		// iterations, so the assertion is inside the loop, not after it.
		for pb.Next() {
			if time.Now().UnixNano() == 0 {
				b.Fatal("clock returned zero")
			}
		}
	})
}

// ringOrderLocal is one writer's private ring, padded so neighbouring workers
// never share a cache line.
type ringOrderLocal struct {
	buf  []Entry
	head int
	_    [64]byte
}

// BenchmarkRingOrderPrimCoreLocal is the FLOOR: the same 352-byte entry copy
// with no shared word of any kind, because each worker owns its own ring and
// nothing is ever put back in order. It is the only shape here that improves
// with core count, and it is reachable only by giving up Get()'s total order.
func BenchmarkRingOrderPrimCoreLocal(b *testing.B) {
	const workers = 64
	rings := make([]*ringOrderLocal, workers)
	for i := range rings {
		rings[i] = &ringOrderLocal{buf: make([]Entry, MaxRing/workers)}
	}
	var pick atomic.Int64
	e := benchEntry(0)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		r := rings[pick.Add(1)%workers] // sticky for this worker's whole run
		for pb.Next() {
			r.buf[r.head] = e
			r.head = (r.head + 1) % len(r.buf)
		}
	})
}

// ringOrderShard is a cache-line-local shard carrying the global sequence
// number a merge would need — the tsLiveShard shape applied to this ring.
type ringOrderShard struct {
	mu   sync.Mutex
	buf  []ringOrderShardSlot
	head int
	_    [40]byte
}

type ringOrderShardSlot struct {
	seq uint64
	e   Entry
}

// BenchmarkRingOrderPrimShardedOrdered is the sharded design measured whole:
// core-local shards (which is why it beats the ticket ring) plus the global
// sequence stamp that putting the shards back in arrival order requires. It
// is the FLATTERING version: picking the shard once per RunParallel worker
// makes every shard permanently core-local, which no request goroutine can
// arrange. Read it as the unreachable upper bound and
// BenchmarkRingOrderPrimShardedOrderedRandomKey as the reachable one.
func BenchmarkRingOrderPrimShardedOrdered(b *testing.B) {
	const shards = 64
	sh := make([]*ringOrderShard, shards)
	for i := range sh {
		sh[i] = &ringOrderShard{buf: make([]ringOrderShardSlot, MaxRing/shards)}
	}
	var pick atomic.Int64
	var seq atomic.Uint64
	e := benchEntry(0)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		s := sh[pick.Add(1)%shards]
		for pb.Next() {
			s.mu.Lock()
			s.buf[s.head] = ringOrderShardSlot{seq: seq.Add(1), e: e}
			s.head = (s.head + 1) % len(s.buf)
			s.mu.Unlock()
		}
	})
}

// BenchmarkRingOrderPrimShardedOrderedRandomKey is the sharded design measured
// with the shard key a REQUEST path actually has, and it is the arm that
// settles the question: 36.5 / 126.7 / 111.5 ns, i.e. a dead heat with the
// shipped mutex at four cores after costing 36% and 116% more at one and two.
//
// A proxied request is a fresh goroutine, so there is no stickiness to inherit
// — the only key available is tsShardIndex()'s per-P rand.Uint64 (store.go),
// redrawn per entry. Against a 352-byte Entry that lands each write on a shard
// whose lines are cold or owned by another core, which is exactly the effect
// store.go records when it explains why the 60-bucket time-series ring was NOT
// sharded while the 2-word current-minute counter was: "against an object that
// size its cost ate the gain".
//
// The random key is modelled here with a cheap xorshift rather than importing
// math/rand/v2, so the arm measures the sharding and not a particular
// generator; tsShardIndex's real draw costs ~7 ns on top.
func BenchmarkRingOrderPrimShardedOrderedRandomKey(b *testing.B) {
	const shards = 64
	sh := make([]*ringOrderShard, shards)
	for i := range sh {
		sh[i] = &ringOrderShard{buf: make([]ringOrderShardSlot, MaxRing/shards)}
	}
	var pick atomic.Int64
	var seq atomic.Uint64
	e := benchEntry(0)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		x := uint64(pick.Add(1)) * 0x9E3779B97F4A7C15 // per-worker seed
		for pb.Next() {
			x ^= x << 13
			x ^= x >> 7
			x ^= x << 17
			s := sh[x&(shards-1)]
			s.mu.Lock()
			s.buf[s.head] = ringOrderShardSlot{seq: seq.Add(1), e: e}
			s.head = (s.head + 1) % len(s.buf)
			s.mu.Unlock()
		}
	})
}
