package urlcat

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/KidCarmi/Culvert/internal/hostutil"
)

// Gates for the sharded forward-index read lock (hotread.go).
//
// Three classes, and the split matters:
//
//   - DEFECT gates fail against the pre-change shape (a single process-wide
//     RWMutex read lock on the per-rule path). Each one is noted with what it
//     catches.
//   - CONTROLS fail against the cheapest wrong "fixes". The cheapest way to pass
//     every defect gate here is to stop taking a read lock at all, or to stop
//     excluding writers — both of which would be far worse than the defect,
//     because this index decides whether a Deny rule matches.
//   - The STRUCTURAL gates are deliberately not timing-based. A scaling-ratio
//     gate on a shared runner flakes, and a gate that can flake gets muted —
//     the standing rule recorded for internal/connlimit and the latency
//     histogram.

// ── 1. The mechanism ──────────────────────────────────────────────────────────

// DEFECT GATE (STRUCTURAL). The two per-rule readers must reach their host set
// through the SHARDED path and must not take the single process-wide read lock.
//
// This is an AST assertion and not a behavioural one, deliberately. A
// behavioural probe here cannot be made deterministic: holding shard 0 to prove
// the hot path avoids it also blocks the ~1-in-64 calls that legitimately draw
// shard 0, so the gate hangs rather than failing cleanly (measured — the first
// draft of this gate timed out ~99.8% of the time on a CORRECT tree). A scaling
// ratio is the other option and flakes on a shared runner. The structural form
// is deterministic under any load, under -race, on any hardware, and it pins the
// thing that actually matters: WHICH lock the hot path takes.
//
// It carries its own CONTROL below, so a selector that stops matching cannot
// pass forever (the sanitizeLog scan-count precedent).
func TestHotRW_WallHotReadersUseTheShardedPath(t *testing.T) {
	for _, fn := range []string{"MatchesHost", "MatchesHostAdmin"} {
		body := storeMethodSource(t, "urlcat.go", fn)
		if !strings.Contains(body, "s.mu.rlockHot()") {
			t.Errorf("%s does not call s.mu.rlockHot(): the per-rule read path is not sharded", fn)
		}
		if strings.Contains(body, "s.mu.RLock()") {
			t.Errorf("%s still takes the process-wide read lock (s.mu.RLock); that is the throughput ceiling hotread.go removes", fn)
		}
	}
}

// CONTROL for the wall above. The same predicate, run against the VERBATIM
// pre-change body kept in this file, must REJECT it. Without this, a renamed
// method or a changed file path would make the wall match nothing and pass
// vacuously forever.
func TestHotRW_WallRejectsThePreChangeShape(t *testing.T) {
	body := storeMethodSource(t, "hotread_test.go", "legacyMatchesHost")
	if strings.Contains(body, "s.mu.rlockHot()") {
		t.Fatal("the frozen legacy baseline has been edited to use the sharded path; it must stay a verbatim copy of the defect")
	}
	if !strings.Contains(body, "s.mu.RLock()") {
		t.Fatal("the frozen legacy baseline no longer takes the process-wide read lock, so the wall above is not proven to be able to fail")
	}
}

// storeMethodSource returns the source text of a *Store method in the named
// file of this package.
func storeMethodSource(t *testing.T, file, name string) string {
	t.Helper()
	src, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Recv == nil || fd.Name.Name != name || fd.Body == nil {
			continue
		}
		return string(src[fset.Position(fd.Body.Pos()).Offset:fset.Position(fd.Body.End()).Offset])
	}
	t.Fatalf("method %s not found in %s", name, file)
	return ""
}

// DEFECT GATE. rlockHot must actually spread across shards. A sharded lock that
// always returned the same shard would pass the gate above only by luck and
// would buy nothing. Fully deterministic: rlockHot returns the shard it took.
func TestHotRW_HotReadsSpreadAcrossShards(t *testing.T) {
	var h hotRW
	seen := make(map[*readShard]struct{})
	for i := 0; i < 4096; i++ {
		sh := h.rlockHot()
		seen[sh] = struct{}{}
		sh.RUnlock()
	}
	// 4096 draws over 64 shards: every shard is overwhelmingly likely. Require a
	// clear majority rather than all of them so the gate cannot flake, while
	// still failing hard for any collapse toward a single lock.
	if len(seen) < readShardCount/2 {
		t.Fatalf("rlockHot reached only %d of %d shards; reads are not spread across cache lines",
			len(seen), readShardCount)
	}
}

// CONTROL. Cold readers must share shard 0 — the admin/list/persist/lookup
// surfaces are not on the per-rule path and must not pay for shard selection.
// TryLock is the proof: a shard held for reading cannot be write-locked.
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

// CONTROL. A writer must still exclude EVERY reader. Removing the read lock
// entirely is the cheapest way to pass every cost gate in this file, and it
// would make a category mutation racy against the policy hot path. Fully
// deterministic: with the write lock held, no shard may be read-lockable.
func TestHotRW_WriteLockTakesEveryShard(t *testing.T) {
	var h hotRW
	h.Lock()
	for i := range h.shards {
		if h.shards[i].TryRLock() {
			h.shards[i].RUnlock()
			h.Unlock()
			t.Fatalf("shard %d was still read-lockable while the write lock was held: "+
				"a writer no longer excludes the hot read path", i)
		}
	}
	h.Unlock()
	for i := range h.shards {
		if !h.shards[i].TryRLock() {
			t.Fatalf("shard %d stayed locked after Unlock", i)
		}
		h.shards[i].RUnlock()
	}
}

// CONTROL. The store-level form of the above: a real write lock must block a
// real MatchesHost.
func TestHotRW_StoreWriteLockExcludesMatchesHost(t *testing.T) {
	s := New(DefaultEntries())
	cat := benchCategoryName(t)

	entered := make(chan bool, 1)
	s.mu.Lock()
	go func() { entered <- s.MatchesHost(cat, "uncategorized.example.net") }()

	select {
	case <-entered:
		s.mu.Unlock()
		t.Fatal("MatchesHost completed while the write lock was held: a writer no longer excludes the hot read path")
	case <-time.After(100 * time.Millisecond):
	}

	s.mu.Unlock()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("MatchesHost never completed after the write lock was released")
	}
}

// TestHotRW_ShardsAreCacheLineIsolated pins the padding arithmetic. Without it,
// two 24-byte mutexes share a 64-byte line and taking one shard invalidates its
// neighbour, handing back most of what splitting the lock bought.
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

// ── 2. The verdict is unchanged ───────────────────────────────────────────────

// CONTROL. This is a COST change: the shard a reader happens to draw must never
// influence the answer. Drives both entry points across every shipped category
// and a set of host shapes, repeatedly, so many different shards serve the same
// question.
func TestHotRW_VerdictIsIndependentOfTheShardDrawn(t *testing.T) {
	s := New(DefaultEntries())
	hosts := []string{
		"uncategorized.example.net",
		"linkedin.com",
		"www.linkedin.com",
		"deep.sub.linkedin.com",
		"LINKEDIN.COM",
		"",
		".",
		"linkedin.com.",
	}
	for _, e := range DefaultEntries() {
		cat := Category(e.Name)
		for _, h := range hosts {
			// First answer is the oracle; every repeat draws a fresh shard.
			wantAll := s.MatchesHost(cat, h)
			wantAdmin := s.MatchesHostAdmin(cat, h)
			for i := 0; i < 128; i++ {
				if got := s.MatchesHost(cat, h); got != wantAll {
					t.Fatalf("MatchesHost(%q, %q) returned %v then %v across shards", cat, h, wantAll, got)
				}
				if got := s.MatchesHostAdmin(cat, h); got != wantAdmin {
					t.Fatalf("MatchesHostAdmin(%q, %q) returned %v then %v across shards", cat, h, wantAdmin, got)
				}
			}
		}
	}
}

// The safety net that matters: the real hot readers against every writer that
// touches the index they read. Under -race, any break in the exclusion shows up
// as a concurrent map read/write — precisely the failure a sharded lock would
// introduce if a writer ever stopped taking all the shards.
func TestHotRW_ConcurrentReadersAndMutators(t *testing.T) {
	s := New(DefaultEntries())
	cat := benchCategoryName(t)

	var stop atomic.Bool
	// SEPARATE waitgroups: the readers spin until stop is set, so waiting on a
	// single shared group waits for goroutines that are waiting to be told to
	// finish — a self-deadlock.
	var readers, writer sync.WaitGroup

	for r := 0; r < 4; r++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for !stop.Load() {
				_ = s.MatchesHost(cat, "uncategorized.example.net")
				_ = s.MatchesHostAdmin(cat, "deep.sub.example.net")
			}
		}()
	}

	// AddHost patches one category in place (addHostToIndexes); Set and
	// ReplaceAll go through rebuildIndex. Between them they cover both writers
	// of the forward index.
	writer.Add(1)
	go func() {
		defer writer.Done()
		for i := 0; i < 300; i++ {
			_ = s.AddHost(string(cat), fmt.Sprintf("h%d.churn.example", i))
			if i%25 == 0 {
				_ = s.Set("Churn", []string{fmt.Sprintf("s%d.example", i)}, false)
			}
			if i%100 == 0 {
				s.ReplaceAll(defaultEntryValues())
			}
		}
	}()

	writer.Wait() // every mutation has landed
	stop.Store(true)
	readers.Wait()
}

// defaultEntryValues adapts DefaultEntries() to ReplaceAll's value slice.
func defaultEntryValues() []Entry {
	src := DefaultEntries()
	out := make([]Entry, 0, len(src))
	for _, e := range src {
		out = append(out, *e)
	}
	return out
}

// ── 3. The cost ───────────────────────────────────────────────────────────────

// BenchmarkMatchesHostScaling vs _Baseline: the whole finding, measured in ONE
// run so the comparison is machine-independent (the convention established by
// security_ratelimit_window_bench_test.go's _Legacy arms). The baseline freezes
// the PRE-CHANGE shape — one process-wide RWMutex read lock around the same map
// probe — so the before/after stays reproducible in-tree.
//
//	go test -run '^$' -bench 'MatchesHostScaling' -cpu 1,2,4 ./internal/urlcat/
//
// Read it as throughput against core count, not as ns/op at one core: the defect
// is that the pre-change curve INVERTS (four cores deliver less than one).
func BenchmarkMatchesHostScaling(b *testing.B) {
	s := benchMatchStore()
	cat := benchCategoryName(b)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		// Each worker keeps its OWN sink: a shared package-level sink turns
		// false sharing into the thing being measured (the trap recorded on
		// internal/blocklist's hot-read benchmarks).
		var sink bool
		for pb.Next() {
			sink = s.MatchesHost(cat, "uncategorized.example.net")
		}
		_ = sink
	})
}

// legacyMatchesHost is a VERBATIM copy of the pre-change read path: the single
// process-wide read lock. Kept only as the benchmark baseline above.
func (s *Store) legacyMatchesHost(cat Category, host string) bool {
	host = hostutil.NormalizeHost(host)
	var keyBuf [maxInlineCategoryKey]byte
	inlineKey, strKey, inlineOK := categoryKey(keyBuf[:], string(cat))

	s.mu.RLock() // the defect: ONE shared word, written by every core
	var hostSet map[string]bool
	if inlineOK {
		hostSet = s.index[string(inlineKey)]
	} else {
		hostSet = s.index[strKey]
	}
	s.mu.RUnlock()

	if hostSet == nil {
		return false
	}
	if hostSet[host] {
		return true
	}
	for i, ch := range host {
		if ch == '.' && hostSet[host[i+1:]] {
			return true
		}
	}
	return false
}

func BenchmarkMatchesHostScaling_Baseline(b *testing.B) {
	s := benchMatchStore()
	cat := benchCategoryName(b)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var sink bool
		for pb.Next() {
			sink = s.legacyMatchesHost(cat, "uncategorized.example.net")
		}
		_ = sink
	})
}

// BenchmarkHotRWWriteLock measures the trade: a writer takes every shard
// instead of one lock. Both shapes in one run.
func BenchmarkHotRWWriteLock(b *testing.B) {
	b.Run("sharded", func(b *testing.B) {
		var h hotRW
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			h.Lock()
			h.Unlock()
		}
	})
	b.Run("single", func(b *testing.B) {
		var m sync.RWMutex
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			m.Lock()
			m.Unlock()
		}
	})
}
