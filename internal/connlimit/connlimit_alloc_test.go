package connlimit

import (
	"runtime"
	"strconv"
	"sync"
	"testing"
	"unsafe"
)

// Allocation gates + evidence for the per-request Acquire/Release pair.
//
// WHY THIS IS A GATE AND NOT JUST A BENCHMARK
//
// Acquire and Release run on EVERY proxied request (proxy.go's handleRequest,
// socks5.go) — not once per TCP connection, so a keep-alive connection pays the
// pair per request. While the counters were held behind a *int64, Acquire
// heap-allocated an 8-byte counter on every first connection for an IP, and
// because Release deletes the entry when the count returns to zero, the
// overwhelmingly common production shape — one request in flight at a time per
// client — allocated and discarded one counter PER REQUEST:
//
//	BenchmarkAcquireRelease_SingleIP   125.3 ns/op   8 B/op   1 allocs/op
//
// That made Acquire the largest Culvert-owned allocation site in the end-to-end
// proxy allocation profile (2.4% of every allocation the proxy made, as its own
// flat cost). Holding the counter by value removed it. Measured here, n=12,
// 2.8GHz Xeon, Go 1.26, benchstat against the pointer-map parent:
//
//	                            before      after    delta
//	SingleIP                  125.3ns      85.3ns   -32.0%  (p=0.000)
//	SingleIPParallel          287.6ns     214.3ns   -25.5%  (p=0.000)
//	DistinctIPsParallel       174.7ns     149.0ns   -14.7%  (p=0.000)
//	EnabledParallel           167.2ns     148.8ns   -11.0%  (p=0.002)
//	geomean                   180.1ns     141.9ns   -21.2%
//	allocs/op (every shape)         1           0    -100%
//
// The ns/op win is larger than removing one 8-byte allocation can account for,
// and the reason is the second half of the change: with the count no longer
// mutable from outside the shard lock, every mutation moved under the single
// lock the map operation already needed. Release used to take the lock TWICE
// (lookup, then a re-check-and-delete after an unlocked atomic decrement), so
// the pair went from three lock acquisitions per request to two. That is why
// SingleIPParallel — all traffic from one NAT egress, every operation on ONE
// shard, the shape sharding deliberately does not help — improves the second
// most of any benchmark here rather than regressing, which is what holding a
// lock across a map write instead of an atomic would otherwise risk.
//
// The gates below are structural (exact allocation counts via AllocsPerRun),
// not timing-based, for the reason recorded on the sharding gates in
// connlimit_shard_test.go: a gate that can flake on a loaded CI runner gets
// muted, and a muted gate protects nothing. Allocation counts do not flake.

// errCounterAllocates is the diagnosis every gate below reports. It is shared so
// whichever gate notices first says the same thing.
const errCounterAllocates = "the per-IP connection counter allocates again. " +
	"The most likely cause is the counter moving back behind a pointer " +
	"(map[string]*int64), which heap-allocates once per tracked IP — and because " +
	"Release deletes the entry at zero, that is once per REQUEST for any client " +
	"with one request in flight at a time, which is most of them. See the shard " +
	"type's doc in connlimit.go."

// TestBenchGate_AcquireReleasePairIsAllocationFree is the primary gate: the
// per-request pair, on the shape production actually runs (an IP whose count
// returns to zero between requests, so the map entry is created and deleted
// every time), must not allocate at all.
func TestBenchGate_AcquireReleasePairIsAllocationFree(t *testing.T) {
	cl := New()
	cl.Enable(1024)

	// AllocsPerRun warms up once before measuring, which is what settles the
	// shard's map buckets; the steady-state create/delete cycle below reuses
	// them. Any allocation left is the counter itself.
	got := testing.AllocsPerRun(200, func() {
		cl.Acquire("203.0.113.7")
		cl.Release("203.0.113.7")
	})
	if got != 0 {
		t.Fatalf("Acquire+Release allocated %.2f objects/op, want 0: %s", got, errCounterAllocates)
	}
}

// TestBenchGate_AcquireIsAllocationFreeWhileDisabled covers the default
// deployment posture. A limiter that was never Enable()d still COUNTS every
// connection (Acquire's doc explains why that is required for the #503
// fail-closed contract), so the disabled path runs the same map work on every
// request and must be just as free of allocation as the enabled one.
func TestBenchGate_AcquireIsAllocationFreeWhileDisabled(t *testing.T) {
	cl := New() // disabled by default
	got := testing.AllocsPerRun(200, func() {
		cl.Acquire("203.0.113.9")
		cl.Release("203.0.113.9")
	})
	if got != 0 {
		t.Fatalf("Acquire+Release while disabled allocated %.2f objects/op, want 0: %s",
			got, errCounterAllocates)
	}
}

// TestBenchGate_RejectedAcquireIsAllocationFree covers the over-cap branch. It
// is the path a flood actually takes — under attack it is the HOT path, so an
// allocation here would be an allocation per rejected request, exactly when the
// process can least afford one.
//
// Unlike the three gates around it, this one is NOT a before/after control: it
// passes on the pointer map too, because a rejection could only happen on an IP
// whose entry already existed, so the counter was already allocated. It is kept
// as a forward guard on a path no benchmark in this package covers.
func TestBenchGate_RejectedAcquireIsAllocationFree(t *testing.T) {
	cl := New()
	cl.Enable(1)
	if !cl.Acquire("198.51.100.4") { // occupies the single slot for the whole test
		t.Fatal("first acquire at cap 1 should be admitted")
	}
	defer cl.Release("198.51.100.4")

	got := testing.AllocsPerRun(200, func() {
		if cl.Acquire("198.51.100.4") {
			t.Fatal("acquire over cap 1 should be rejected")
		}
	})
	if got != 0 {
		t.Fatalf("a rejected Acquire allocated %.2f objects/op, want 0: %s", got, errCounterAllocates)
	}
}

// TestBenchGate_TrackedIPCostsNoHeapObject is the memory-footprint gate, and it
// is about the GC rather than about one request. A pointer map put one tiny heap
// object per tracked IP into the scan set, so a gateway holding 50k live client
// IPs handed the GC 50k extra objects to trace on every cycle, and allocated
// every one of them. With the count held inline there is no such object.
//
// The reading is MemStats.Mallocs — the process's CUMULATIVE allocation count —
// and not HeapObjects. HeapObjects is a live-set gauge: it moves when unrelated
// test garbage is collected between the two reads, which made this gate swing by
// far more than the signal it is measuring (it can even read lower after, and
// the unsigned subtraction then wraps). Mallocs is monotonic, so the delta is
// attributable to the loop between the reads and nothing else, with no GC timing
// to depend on.
//
// The bound is deliberately generous (well under one allocation per IP rather
// than exactly zero): the shard maps themselves must still grow their buckets as
// they fill, and this gate is here to catch the per-entry object coming back —
// which costs 1.0 per IP on top of that growth — not to freeze Go's map growth
// policy. Each shard is warmed to its final capacity first so that even the
// bucket growth is mostly out of the measured window.
func TestBenchGate_TrackedIPCostsNoHeapObject(t *testing.T) {
	const ips = 20000

	cl := New()
	// Build the keys and warm the shard maps to their final capacity BEFORE the
	// measurement, so neither key construction nor bucket growth lands in it.
	keys := make([]string, ips)
	for i := range keys {
		keys[i] = "203.0.113." + strconv.Itoa(i&0xff) + "-" + strconv.Itoa(i)
		cl.Acquire(keys[i])
	}
	for _, k := range keys {
		cl.Release(k)
	}

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for _, k := range keys {
		cl.Acquire(k)
	}
	runtime.ReadMemStats(&after)

	if got := cl.ActiveIPs(); got != ips {
		t.Fatalf("ActiveIPs = %d, want %d", got, ips)
	}
	for _, k := range keys {
		cl.Release(k)
	}

	perIP := float64(after.Mallocs-before.Mallocs) / float64(ips)
	if perIP > 0.5 {
		t.Fatalf("tracking an IP costs %.2f allocations, want < 0.5: %s", perIP, errCounterAllocates)
	}
}

// TestBenchGate_ShardIsExactlyOneCacheLine pins the padding arithmetic that the
// counter-representation change had to keep intact. shard's padding is written
// as [cacheLine - 16]byte, where 16 is the size of the mutex plus the map header
// ahead of it — a literal, so changing either field's size silently either
// under-pads (re-introducing the false sharing that cost a measured 21%, see the
// shard doc) or over-pads past the line.
//
// Measured on this toolchain: sync.Mutex is 8 bytes and a map header is 8,
// whatever the map's value type, so moving the counter from *int64 to int64 left
// the prefix at 16 and the struct at exactly 64. This gate is the standing
// check on that, rather than a comment asserting it.
func TestBenchGate_ShardIsExactlyOneCacheLine(t *testing.T) {
	if got := unsafe.Sizeof(shard{}); got != cacheLine {
		t.Fatalf("sizeof(shard) = %d, want exactly %d (one cache line). The padding literal "+
			"[cacheLine - 16]byte no longer matches the mutex + map header ahead of it; "+
			"recompute it rather than deleting it — under-padding puts four shards back on "+
			"one line and hands back most of what splitting the lock bought.", got, cacheLine)
	}
}

// BenchmarkAcquireRelease_EntryChurn is the production shape stated plainly, and
// the one the pointer map was worst at: many distinct clients, each with ONE
// request in flight, so every single pair creates the map entry and deletes it
// again. The pointer map allocated a counter on every iteration here; this is
// the benchmark that reads zero.
func BenchmarkAcquireRelease_EntryChurn(b *testing.B) {
	cl := New()
	cl.Enable(1024)
	ips := benchIPs(1024)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip := ips[i&1023]
		cl.Acquire(ip)
		cl.Release(ip)
	}
}

// BenchmarkAcquireRelease_EntryChurnParallel is the same churn across all cores:
// allocation pressure is cheapest to measure serially and most expensive in
// production when every core is allocating at once, which is the shape that
// actually ships.
func BenchmarkAcquireRelease_EntryChurnParallel(b *testing.B) {
	cl := New()
	cl.Enable(1024)
	ips := benchIPs(1024)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			ip := ips[i&1023]
			cl.Acquire(ip)
			cl.Release(ip)
			i++
		}
	})
}

// BenchmarkAcquireRelease_DeepCountParallel holds a sustained per-IP count
// instead of churning the entry, so the map entry persists and the measurement
// isolates the lock path from the create/delete path. This is the shape a
// browser with many parallel connections, or an aggressive HTTP/2 client,
// presents — and the one where the old unlocked atomic decrement was supposed
// to pay off, so it is the honest control on moving that work under the lock.
func BenchmarkAcquireRelease_DeepCountParallel(b *testing.B) {
	cl := New()
	cl.Enable(1 << 20) // high enough that the held depth never rejects
	ips := benchIPs(64)

	// Pin a standing count on every key so no iteration deletes an entry.
	const depth = 32
	for _, ip := range ips {
		for i := 0; i < depth; i++ {
			cl.Acquire(ip)
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			ip := ips[i&63]
			cl.Acquire(ip)
			cl.Release(ip)
			i++
		}
	})
	b.StopTimer()
	for _, ip := range ips {
		for i := 0; i < depth; i++ {
			cl.Release(ip)
		}
	}
}

// TestStress_ChurnUnderConcurrentReconfigure races the churn shape against live
// Enable/Disable reconfigures and the admin gauges, with every Acquire paired to
// its Release, and requires the limiter to come back to exactly zero tracked
// IPs. Run under -race it is the correctness counterpart to the benchmarks
// above: moving the counter inline moved the decrement under the shard lock, and
// a mistake there would show up as a leaked entry or a lost decrement rather
// than as a slowdown.
func TestStress_ChurnUnderConcurrentReconfigure(t *testing.T) {
	cl := New()
	cl.Enable(64)

	const workers = 8
	const iters = 2000
	ips := benchIPs(128)

	stop := make(chan struct{})
	var reconf sync.WaitGroup
	reconf.Add(1)
	go func() {
		defer reconf.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if i%2 == 0 {
				cl.Enable(64)
			} else {
				cl.Disable()
			}
			cl.ActiveIPs() // the admin gauge touches every shard lock
		}
	}()

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				ip := ips[(w*iters+i)&127]
				// Release only what was admitted — releasing a rejected
				// acquire is what the #503 bug did, and it would mask a leak.
				if cl.Acquire(ip) {
					cl.Release(ip)
				}
			}
		}(w)
	}
	wg.Wait()
	close(stop)
	reconf.Wait()

	if got := cl.ActiveIPs(); got != 0 {
		t.Fatalf("ActiveIPs after every admitted acquire was released = %d, want 0 "+
			"(a leaked entry means a decrement was lost)", got)
	}
	for _, ip := range ips {
		if got := cl.ActiveConns(ip); got != 0 {
			t.Fatalf("ActiveConns(%q) = %d, want 0", ip, got)
		}
	}
}
