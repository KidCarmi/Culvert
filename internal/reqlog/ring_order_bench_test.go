package reqlog

// ring_order_bench_test.go — the measured answer to the question
// BenchmarkAddParallel's comment left open: can ringMu, the one process-wide
// exclusive lock every logged request takes, be removed?
//
// Short answer: ringMu is NOT simply removable — a totally ordered ring pays
// one shared read-modify-write per entry however it is built, and that floor
// is measured below. But the longer answer is a CROSSOVER rather than a
// closed question, and that is the finding: core-local shards carrying a
// global sequence stamp are slower than the shipped mutex at one and two
// cores and 1.3-2.3x FASTER at four. On 4 vCPUs that is not enough to justify
// rewriting a durable admin-visible surface. It is enough to make the sharded
// design a candidate worth qualifying on real 16-/32-core appliance hardware,
// which is what these arms are for.
//
// Everything here is benchmark-only (no production code changes), in-tree for
// the same reason BenchmarkHTTPForward_LegacyClientPerRequest is: the
// comparison has to stay reproducible. The rejected alternative keeps its OWN
// state, so no arm can perturb Add, Get or SwapRingForTest, and
// TestTicketRing_OrderMatchesShippedRing proves it reproduces Get()'s window
// byte for byte — so its rejection rests on cost, not on a broken prototype.
// It must not be "kept in sync" with Add; its value is that it does not move.
//
// WHY ORDER IS THE CONSTRAINT. Get() returns the newest MaxRing entries in
// arrival order, newest first, and the admin request feed renders them in that
// order. Establishing a total order over concurrent writers costs at least one
// read-modify-write on one shared word per entry, and that word is the whole
// game: every arm below either pays it or gives up the order.
//
// HOW TO READ THESE NUMBERS, because it is easy to get wrong and an earlier
// revision of this comment did. All arms are RunParallel, so ns/op is wall
// time per op across ALL workers: lower is more throughput, a genuinely
// parallel cost FALLS as cores are added and one that serialises rises.
// Absolute ns/op on a shared 4-vCPU VM is NOT comparable between invocations —
// the shipped arm's own P=4 median moved 110.9 -> 158.4 ns between two runs of
// this same file, a 43% drift, which is larger than most gaps worth claiming.
// Within one invocation the spread is tight (shipped arm, n=7: 32.8-40.8 at
// P=1, 71.3-74.2 at P=2, 135.4-164.4 at P=4), so the honest unit is the RATIO
// to the shipped arm measured in the SAME interleaved invocation. That is what
// the table reports. Re-measure the whole set in one go; never compare a new
// arm against a number quoted here.
//
// go1.27.3, linux/amd64, 4-vCPU Xeon @2.30GHz, all arms in ONE invocation,
// -count=7, medians. Ratio <1.00x means faster than the shipped ringMu write:
//
//	                                     │  P=1  │  P=2  │  P=4  │
//	ringMu ring write (SHIPPED)           │ 1.00x │ 1.00x │ 1.00x │  35.0/73.3/158.4 ns
//	ticket ring, per-slot mutex           │ 1.07x │ 1.91x │ 0.76x │
//	shards + global seq, sticky key       │ 1.19x │ 1.02x │ 0.43x │
//	shards + global seq, realistic key    │ 1.55x │ 1.58x │ 0.75x │
//	─ primitives that bound any design ─  │       │       │       │
//	global atomic.Uint64.Add              │ 0.25x │ 0.34x │ 0.16x │   8.7/24.6/25.6 ns
//	time.Now() (unshared ordering key)    │ 1.53x │ 0.40x │ 0.09x │  53.5/29.5/14.8 ns
//	unordered core-local ring write       │ 0.31x │ 0.07x │ 0.01x │  10.7/5.0/2.3 ns
//
// WHAT IS ROBUST — held across two independent interleaved runs:
//
//  1. The floor is real. One global atomic add costs 25.6 ns at four cores,
//     ~16% of the entire shipped write and more than the whole write costs
//     serially. No totally ordered design gets under it.
//  2. The direct-mapped ticket ring is the WRONG design: 1.91x worse at two
//     cores (3.05x in the other run), and never consistently better anywhere.
//     The mutex serialises writers, so one core at a time owns the head region
//     and writes consecutive 352-byte slots with its lines exclusive to it —
//     the lock buys BATCHING. Tickets interleave the cores slot by slot and
//     trade one contended lock for six contended cache lines.
//  3. Sharding CROSSES OVER rather than winning outright: slower at one core
//     (1.19x), level at two, and 0.43x at four. Both runs agree on the
//     direction at four cores.
//  4. The shard key matters as much as the sharding. A proxied request is a
//     fresh goroutine with no stickiness to inherit, so production's only key
//     is tsShardIndex()'s per-entry rand.Uint64; against a 352-byte Entry that
//     lands every write on a shard whose lines are cold or owned elsewhere.
//     It costs most of the gain (1.55x vs 1.19x at P=1; 0.75x vs 0.43x at
//     P=4) — the same effect store.go records for the 60-bucket time-series
//     ring, "against an object that size its cost ate the gain". Note the
//     contrast with the current-minute counter that DOES shard: a counter
//     needs only its sum, so its shards never have to be put back in order.
//     That is exactly what this ring cannot give up, and why tsLiveShard's
//     shape does not transfer unchanged.
//  5. Only the UNORDERED core-local write scales (0.31x -> 0.01x, improving
//     with every core). time.Now() scales too — it needs no shared word, so
//     it goes 1.53x -> 0.09x. So a timestamp-keyed core-local ring is the fast
//     design, and it is fast precisely because ns timestamps are an
//     APPROXIMATE order (ties, cross-core read skew) rather than a total one.
//     Adopting it would change what the admin request feed shows: a product
//     decision about an admin-visible surface, not a performance fix.
//
// WHAT THIS HARDWARE CANNOT RESOLVE. The ticket ring's P=4 ratio flipped
// between runs (1.12x then 0.76x), so its four-core standing is unknown — it
// is rejected on P=2 and on mechanism, not on P=4. More importantly, four
// vCPUs is the widest measurement available here, and both sharded arms are
// still improving at the edge of it while the mutex degrades. The crossover is
// established; where it lands on 16 and 32 cores is not.
//
// RECOMMENDATION. Keep ringMu for now: on the only hardware measured, the
// ordered alternative that wins does so at the core count where this product
// is least latency-sensitive, and it costs 19-55% at one and two cores. Do not
// ship a rewrite of the request-feed ring on 4-vCPU evidence. The sharded
// design IS the candidate to qualify if ringMu ever shows up in a real
// profile: re-run this whole set on the target appliance, in one invocation,
// and read the ratios. ~9M entries/s at four cores (the shipped arm's own
// ceiling) still carries one to two orders of magnitude of headroom over the
// request rates these gateways serve, which is why this is recorded rather
// than acted on.
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

// ringOrderLocalDepth is one worker's private ring depth, held CONSTANT rather
// than derived from the worker count: the measurement is about where the
// written cache lines live, so the per-worker working set must not move with
// GOMAXPROCS or the figures stop being comparable across core counts. It is
// the depth the published numbers were taken at (MaxRing split 64 ways).
const ringOrderLocalDepth = MaxRing / 64

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
	e := benchEntry(0)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		// Allocated INSIDE the worker, so "private" is structural: there is no
		// pool to run out of and no modulo to wrap, at any GOMAXPROCS. A fixed
		// pool of 64 indexed by `pick.Add(1)%64` looked equivalent and was not
		// — above 64 workers two of them shared a ring and raced on head/buf,
		// which the race detector confirms at GOMAXPROCS=128 (Codex P2,
		// PR #1710). That is the wrong bug to ship in THIS arm in particular:
		// it is the one asserting an unshared write is the floor, and it broke
		// precisely on the many-core hardware this file asks people to
		// re-measure on. The one allocation per worker is amortized over that
		// worker's whole share of b.N.
		r := &ringOrderLocal{buf: make([]Entry, ringOrderLocalDepth)}
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
	var seq atomic.Uint64
	e := benchEntry(0)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		// One shard per worker, allocated per worker for the same reason as the
		// core-local arm above: a fixed pool wrapped at 64 workers, which here
		// silently broke the STICKINESS this arm exists to model (the mutex
		// meant it was contention, not a race). "Sticky" now means one shard
		// per worker by construction, at any GOMAXPROCS. The global seq stamp
		// below stays shared — that is the cost being measured.
		s := &ringOrderShard{buf: make([]ringOrderShardSlot, ringOrderLocalDepth)}
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
	// This arm KEEPS the fixed 64-shard pool, deliberately: a shared shard
	// array addressed by a per-entry key is exactly the production shape being
	// modelled, so workers sharing shards is the point rather than a defect,
	// and every access is under the shard's mutex (contention, never a race).
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
