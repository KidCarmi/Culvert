package blocklist

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/KidCarmi/Culvert/internal/hostutil"
)

// Gates and benchmarks for the sharded blocklist read lock (hotread.go).
//
//	go test -run 'TestHotRW|TestBenchGate_IsBlocked' -race ./internal/blocklist/
//	go test -run XXX -bench 'BenchmarkIsBlockedScaling' -cpu 1,2,4 ./internal/blocklist/
//
// Three things are being pinned, in descending order of how much they matter:
//
//  1. CORRECTNESS. A writer must still exclude every reader. This is the whole
//     safety argument for the change, and it is proved twice — once directly
//     (TestHotRW_WriteLockExcludesHotReaders) and once by running the real
//     mutators against the real hot path under the race detector
//     (TestHotRW_ConcurrentReadersAndMutators), which is what would catch a
//     concurrent map read/write if the exclusion were ever broken.
//  2. The SHARDING ACTUALLY HAPPENS. TestBenchGate_HotReadsSpreadAcrossShards
//     is structural, not timing-based: it counts the distinct shards real draws
//     land on, so a collapse back to one shared lock fails deterministically on
//     any hardware, under any load, with or without -race. The repo has twice
//     rejected scaling-RATIO gates for this path class (internal/connlimit,
//     metrics.go) because their margin narrows under -race until they flake, and
//     a gate that flakes gets muted.
//  3. The COST. BenchmarkIsBlockedScaling reports the aggregate throughput of
//     the real IsBlocked, and BenchmarkIsBlockedScaling_Baseline runs the
//     verbatim pre-fix lock shape in the SAME binary, so the before/after
//     comparison stays reproducible in-tree without checking out the parent
//     commit — the convention BenchmarkIsBlocked_Baseline already set here.

// ── 1. Correctness ────────────────────────────────────────────────────────────

// TestHotRW_WriteLockExcludesHotReaders is the mutual-exclusion contract: a
// writer holds EVERY shard, so it does not matter which shard the reader draws.
// That makes this deterministic rather than a 1-in-readShardCount coin flip.
func TestHotRW_WriteLockExcludesHotReaders(t *testing.T) {
	st := New()
	st.Add("blocked.example.com")

	entered := make(chan bool, 1)
	st.mu.Lock()
	go func() { entered <- st.IsBlocked("blocked.example.com") }()

	select {
	case <-entered:
		st.mu.Unlock()
		t.Fatal("IsBlocked completed while the write lock was held: a writer no longer excludes the hot read path")
	case <-time.After(100 * time.Millisecond):
	}

	st.mu.Unlock()
	select {
	case got := <-entered:
		if !got {
			t.Fatal("IsBlocked returned false for a listed host")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("IsBlocked never completed after the write lock was released")
	}
}

// TestHotRW_ColdReadLockUsesShardZero pins the cold-reader contract: the admin
// and persistence surfaces share shard 0 rather than paying for shard
// selection. TryLock is the proof — a shard held for reading cannot be
// write-locked, and an untouched one can.
func TestHotRW_ColdReadLockUsesShardZero(t *testing.T) {
	var h hotRW
	h.RLock()
	defer h.RUnlock()

	if h.shards[0].TryLock() {
		h.shards[0].Unlock()
		t.Fatal("RLock did not take shard 0")
	}
	for i := 1; i < readShardCount; i++ {
		if !h.shards[i].TryLock() {
			t.Fatalf("RLock took shard %d as well as shard 0; cold readers must take exactly one", i)
		}
		h.shards[i].Unlock()
	}
}

// TestHotRW_ConcurrentReadersAndMutators is the safety net that matters: it runs
// the real IsBlocked against every mutator that touches a map it reads. Under
// -race, any break in the exclusion shows up as a concurrent map read/write,
// which is precisely the failure a sharded lock would introduce if a writer ever
// stopped taking all the shards.
func TestHotRW_ConcurrentReadersAndMutators(t *testing.T) {
	st := New()
	for i := 0; i < 500; i++ {
		st.Add(fmt.Sprintf("seed%d.example.net", i))
	}

	var stop atomic.Bool
	var wg sync.WaitGroup

	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				st.IsBlocked("seed7.example.net")
				st.IsBlocked("nothing.here.example.org")
				st.IsBlocked("host.evil.example.org")
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; !stop.Load(); i++ {
			h := fmt.Sprintf("churn%d.example.net", i%64)
			st.Add(h)
			st.AddManual("*.evil.example.org")
			st.Remove(h)
			st.AddException("*.allowed.example.org")
			st.RemoveException("*.allowed.example.org")
			st.ApplyDelta([]string{"d1.example.net", "*.d2.example.net"}, []string{"d1.example.net"})
			st.ReplaceFeedEntries([]string{"feed1.example.net", "*.feed2.example.net"})
			if i%2 == 0 {
				st.SetMode("allow")
			} else {
				st.SetMode("block")
			}
		}
	}()

	time.Sleep(250 * time.Millisecond)
	stop.Store(true)
	wg.Wait()
}

// TestHotRW_VerdictsAreUnchangedAcrossShards is the behavioural half: the shard
// a request happens to draw must never influence the answer. Each case is run
// many times so it is decided on many different shards.
func TestHotRW_VerdictsAreUnchangedAcrossShards(t *testing.T) {
	st := New()
	st.Add("evil.test")
	st.Add("*.badexample.com")
	st.AddException("*.allowed.badexample.com")

	cases := []struct {
		host string
		want bool
	}{
		{"evil.test", true},
		{"sub.badexample.com", true},
		{"badexample.com", true},
		{"deep.allowed.badexample.com", false},
		{"allowed.badexample.com", false},
		{"good.example.org", false},
		{"", false},
	}
	for _, c := range cases {
		for i := 0; i < readShardCount*8; i++ {
			if got := st.IsBlocked(c.host); got != c.want {
				t.Fatalf("IsBlocked(%q) = %v, want %v (draw %d)", c.host, got, c.want, i)
			}
		}
	}
}

// ── 2. The sharding actually happens ──────────────────────────────────────────

// TestBenchGate_HotReadsSpreadAcrossShards fails deterministically if the read
// path collapses back to a single shared lock.
//
// With 64 shards and 64*64 draws, the chance of landing on fewer than half the
// shards is far below any threshold that could make this flake (missing even one
// specific shard is ~64*(63/64)^4096, on the order of 1e-26); a collapse yields
// exactly 1. The bound is set at half the shards rather than all of them so the
// gate stays about the property, not about the quality of the RNG.
func TestBenchGate_HotReadsSpreadAcrossShards(t *testing.T) {
	var h hotRW
	seen := make(map[*readShard]struct{}, readShardCount)
	for i := 0; i < readShardCount*readShardCount; i++ {
		sh := h.rlockHot()
		seen[sh] = struct{}{}
		sh.RUnlock()
	}
	if len(seen) < readShardCount/2 {
		t.Fatalf("hot reads landed on %d distinct shards out of %d: the read path is sharing one lock again", len(seen), readShardCount)
	}
}

// TestHotRW_ShardsAreCacheLineIsolated pins the padding. Without it two shards
// share a cache line and taking one lock invalidates its neighbour — false
// sharing that hands back most of what splitting the lock just bought.
//
// It also pins rwMutexSize, which hotread.go states as a constant so that a
// security-critical package does not import unsafe for a padding figure. A
// future Go release that changes sync.RWMutex fails here rather than silently
// unpadding the shards.
func TestHotRW_ShardsAreCacheLineIsolated(t *testing.T) {
	if got := unsafe.Sizeof(sync.RWMutex{}); got != rwMutexSize {
		t.Fatalf("sync.RWMutex is %d bytes, but hotread.go's rwMutexSize says %d; update the constant and re-check the padding", got, rwMutexSize)
	}
	if got := unsafe.Sizeof(readShard{}); got != cacheLine {
		t.Fatalf("readShard is %d bytes, want exactly one %d-byte cache line", got, cacheLine)
	}
	if readShardCount&(readShardCount-1) != 0 {
		t.Fatalf("readShardCount = %d must be a power of two: rlockHot indexes with a mask", readShardCount)
	}
}

// The allocation contract — shard selection must not have reintroduced one — is
// already pinned across every host shape and both postures by
// TestIsBlocked_AllocRegression and TestIsBlocked_MaxLengthHostStaysAllocFree in
// blocklist_bench_test.go, which run this same IsBlocked. It is deliberately not
// restated here.

// ── 3. The cost ───────────────────────────────────────────────────────────────

// scalingStore is a feed-backed blocklist of a realistic size with one wildcard.
//
// Both postures are measured, for the same reason BenchmarkIsBlocked splits on
// them. NoExceptions is the DEFAULT posture and the one that isolates the lock:
// isExcepted short-circuits on an empty map, so almost all of what remains is
// the lock itself. WithExceptions adds ~170 ns of parent-walk probing per call,
// which does not contend and therefore DILUTES the contention as a share of the
// total — it is reported so the win is not quoted from its most flattering case.
func scalingStore(tb testing.TB, exceptions []string) *Store {
	tb.Helper()
	st := New()
	for i := 0; i < 100000; i++ {
		st.Add(fmt.Sprintf("bad%d.example.net", i))
	}
	st.Add("*.evil.example.org")
	for _, e := range exceptions {
		st.AddException(e)
	}
	return st
}

// scalingHost is an ordinary CDN destination that matches nothing: a miss is
// what every ALLOWED request pays, and allowed requests are the overwhelming
// majority of a gateway's traffic.
const scalingHost = "assets.cdn.example-corporation.com"

// legacyStore reproduces the PRE-FIX lock shape — one process-wide
// sync.RWMutex around the identical probe sequence — so the baseline below
// measures only the lock, not a different matcher. It delegates to the real
// isExcepted/isListed, which take no locks of their own.
type legacyStore struct {
	mu sync.RWMutex
	s  *Store
}

func (l *legacyStore) IsBlocked(host string) bool {
	host = hostutil.NormalizeHost(host)
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.s.isExcepted(host) {
		return false
	}
	listed := l.s.isListed(host)
	if l.s.mode == "allow" {
		return !listed
	}
	return listed
}

// BenchmarkIsBlockedScaling reports the AGGREGATE throughput of the real hot
// path. Run it as:
//
//	go test -run XXX -bench 'BenchmarkIsBlockedScaling' -cpu 1,2,4 -count=5 ./internal/blocklist/
//
// RunParallel reports wall-clock time per operation across all workers, so a
// FALLING ns/op as -cpu rises means the store is scaling and a RISING one means
// it is contending. That is the whole finding: before this change the number
// rose.
func BenchmarkIsBlockedScaling(b *testing.B) {
	for _, p := range scalingPostures {
		b.Run(p.name, func(b *testing.B) {
			st := scalingStore(b, p.exceptions)
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				local := false
				for pb.Next() {
					local = st.IsBlocked(scalingHost)
				}
				keepAlive(local)
			})
		})
	}
}

// BenchmarkIsBlockedScaling_Baseline is the same measurement against the
// single-RWMutex shape this change replaced.
func BenchmarkIsBlockedScaling_Baseline(b *testing.B) {
	for _, p := range scalingPostures {
		b.Run(p.name, func(b *testing.B) {
			l := &legacyStore{s: scalingStore(b, p.exceptions)}
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				local := false
				for pb.Next() {
					local = l.IsBlocked(scalingHost)
				}
				keepAlive(local)
			})
		})
	}
}

// keepAliveSink is written ONCE PER WORKER, after its loop, purely to stop the
// compiler eliding the calls.
//
// The obvious form — assigning the result to a package-level sink inside the
// loop, which is exactly what the serial BenchmarkIsBlocked above does and what
// the first draft of this file did — is CORRECT in a serial benchmark and
// RUINOUS in a parallel one: every worker then writes the same cache line on
// every iteration, and that false sharing becomes the bottleneck being measured.
// It flattened the sharded store to the baseline's throughput and hid the entire
// finding. Pinned in prose because there is nothing for a test to assert on: the
// numbers simply come out wrong.
var keepAliveSink atomic.Bool

func keepAlive(v bool) {
	if v {
		keepAliveSink.Store(v)
	}
}

// keepAliveIntSink is the same guard for a counted loop: written once, after the
// loop, so the compiler cannot discard the work but no iteration pays for it.
var keepAliveIntSink atomic.Int64

func keepAliveInt(v int) { keepAliveIntSink.Store(int64(v)) }

var scalingPostures = []struct {
	name       string
	exceptions []string
}{
	{"NoExceptions", nil},
	{"WithExceptions", benchExceptions},
}

// BenchmarkHotRWWriteLock prices the other side of the trade: a writer now takes
// readShardCount locks instead of one. Both shapes are measured so the multiple
// is a number in the tree rather than an assertion in a comment.
//
// Each critical section increments a guarded counter rather than being empty.
// That is not decoration: a lock around nothing is an "empty critical section"
// (staticcheck SA2001), and it is also not what a writer does — every real
// caller mutates something under the lock. The increment costs about a
// nanosecond against a 22 ns floor, far too little to move the comparison, and
// it keeps the benchmark free of any linter directive.
func BenchmarkHotRWWriteLock(b *testing.B) {
	b.Run("Sharded", func(b *testing.B) {
		var h hotRW
		guarded := 0
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			h.Lock()
			guarded++
			h.Unlock()
		}
		keepAliveInt(guarded)
	})
	b.Run("SingleRWMutex", func(b *testing.B) {
		var mu sync.RWMutex
		guarded := 0
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			mu.Lock()
			guarded++
			mu.Unlock()
		}
		keepAliveInt(guarded)
	})
}
