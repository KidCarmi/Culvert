package urlcat

// Before/after benchmarks for the lock-free forward read view.
//
// BOTH arms are timed in ONE run — the `_Legacy` arms call the verbatim
// pre-change body frozen in urlcat_matcheshost_view_test.go — because this
// repo has already been burned twice by cross-run readings of exactly this
// question (the internal/urlcat categoryKey note records a cross-run figure
// that "was wrong by an order of magnitude"). A same-run ratio cancels the
// machine; quote the RATIO and the SHAPE across core counts, never the
// absolutes.
//
// Run:
//
//	go test -run '^$' -bench 'BenchmarkMatchesHostView' -benchmem \
//	    -cpu 1,2,4 -count=5 ./internal/urlcat/
//
// The MISS case is the one to read: an uncategorized destination cannot
// short-circuit, so it is what every ALLOWED request pays per category rule.

import (
	"strings"
	"testing"
)

func lowerTrimDot(h string) string { return strings.ToLower(strings.TrimSuffix(h, ".")) }
func lowerOnly(h string) string    { return strings.ToLower(h) }

// viewBenchStore is the shipped default taxonomy — real category names, so the
// inline key fold is representative.
func viewBenchStore() *Store { return New(DefaultEntries()) }

const viewBenchHost = "uncategorized.example.net"

var viewBenchSink bool

// BenchmarkMatchesHostView_Parallel is the finding's instrument: the per-rule
// probe under concurrency. Before the view this got SLOWER as cores were
// added (RLock/RUnlock are two atomic read-modify-writes on one shared word);
// after it, it scales.
func BenchmarkMatchesHostView_Parallel(b *testing.B) {
	s := viewBenchStore()
	cat := benchCategoryName(b)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		// Each worker owns its sink: a shared package-level sink would make
		// every worker write one cache line per iteration, and that false
		// sharing becomes the thing being measured (the internal/blocklist
		// lesson, where it hid the entire finding).
		var local bool
		for pb.Next() {
			local = s.MatchesHost(cat, viewBenchHost)
		}
		viewBenchSink = local
	})
}

// BenchmarkMatchesHostView_ParallelLegacy is the same measurement against the
// lock-based body, in the same run.
func BenchmarkMatchesHostView_ParallelLegacy(b *testing.B) {
	s := viewBenchStore()
	cat := benchCategoryName(b)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var local bool
		for pb.Next() {
			local = legacyMatchesHost(s, cat, viewBenchHost)
		}
		viewBenchSink = local
	})
}

// BenchmarkMatchesHostView_Serial / _SerialLegacy are the CONTROL pair: they
// show the single-goroutine cost, so the parallel gain cannot be confused with
// a plain per-call speedup, and any low-concurrency price is visible rather
// than hidden.
func BenchmarkMatchesHostView_Serial(b *testing.B) {
	s := viewBenchStore()
	cat := benchCategoryName(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		viewBenchSink = s.MatchesHost(cat, viewBenchHost)
	}
}

func BenchmarkMatchesHostView_SerialLegacy(b *testing.B) {
	s := viewBenchStore()
	cat := benchCategoryName(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		viewBenchSink = legacyMatchesHost(s, cat, viewBenchHost)
	}
}

// BenchmarkMatchesHostView_AdminParallel covers the second entry point — the
// signed-feed path calls MatchesHostAdmin once per category-scoped rule, so it
// carries the identical per-rule lock traffic.
func BenchmarkMatchesHostView_AdminParallel(b *testing.B) {
	s := viewBenchStore()
	cat := benchCategoryName(b)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var local bool
		for pb.Next() {
			local = s.MatchesHostAdmin(cat, viewBenchHost)
		}
		viewBenchSink = local
	})
}

func BenchmarkMatchesHostView_AdminParallelLegacy(b *testing.B) {
	s := viewBenchStore()
	cat := benchCategoryName(b)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var local bool
		for pb.Next() {
			local = legacyMatchesHostAdmin(s, cat, viewBenchHost)
		}
		viewBenchSink = local
	})
}

// BenchmarkMatchesHostView_WriterCost is the TRADE: the incremental
// single-host fold now clones the outer category map and publishes, so a
// writer pays O(categories) it did not pay before. It is measured on the
// shipped taxonomy and on a 2 000-category store (the upper end of the
// "hundreds to low-thousands" realistic range controlplane_snapshot.go
// records) so the cost is a number, not an assertion.
//
// addHostToIndexes is measured directly rather than through AddHost: AddHost
// APPENDS, so repeated calls grow the target category and the inner-set clone
// grows with it — a benchmark of AddHost measures its own fixture drifting.
func BenchmarkMatchesHostView_WriterCost(b *testing.B) {
	for _, cats := range []int{27, 200, 2000} {
		b.Run(benchCategoriesLabel(cats), func(b *testing.B) {
			s := writerCostStore(cats, 25)
			e := s.entries[0]
			key := "category 0"
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s.mu.Lock()
				s.addHostToIndexes(0, e, key, "probe.example.net")
				s.mu.Unlock()
			}
		})
	}
}

func benchCategoriesLabel(n int) string {
	switch n {
	case 27:
		return "categories=27"
	case 200:
		return "categories=200"
	default:
		return "categories=2000"
	}
}

func writerCostStore(categories, hostsPer int) *Store {
	entries := make([]*Entry, 0, categories)
	for c := 0; c < categories; c++ {
		hosts := make([]string, 0, hostsPer)
		for h := 0; h < hostsPer; h++ {
			hosts = append(hosts, hostNameFor(c, h))
		}
		entries = append(entries, &Entry{Name: categoryNameFor(c), Hosts: hosts})
	}
	s := New(entries)
	s.SetPathForTest("")
	return s
}

func categoryNameFor(c int) string { return "Category " + itoaSmall(c) }
func hostNameFor(c, h int) string {
	return "h-" + itoaSmall(c) + "-" + itoaSmall(h) + ".example.com"
}

// itoaSmall avoids pulling fmt into a benchmark fixture builder.
func itoaSmall(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [8]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// legacyAddHostToIndexes is the VERBATIM pre-view fold: it assigns into the
// live outer maps instead of cloning them, and publishes nothing. It is the
// writer-side baseline so the trade is a same-run ratio rather than a pair of
// numbers from different commits. It is NOT safe to run concurrently with the
// readers — which is the whole point of the change — so it exists only here.
func legacyAddHostToIndexes(s *Store, ei int, e *Entry, key, host string) {
	set := make(map[string]bool, len(s.index[key])+1)
	for h := range s.index[key] {
		set[h] = true
	}
	set[lowerTrimDot(host)] = true
	s.index[key] = set
	if !e.BuiltIn {
		s.adminIndex[key] = set
	}

	// #nosec G115 -- slice indices: non-negative and bounded by len
	ref := patternRef{entry: int32(ei), host: int32(len(e.Hosts) - 1)}
	pk := lowerOnly(host)
	if cur, dup := s.hostIndex[pk]; !dup || ref.less(cur) {
		s.hostIndex[pk] = ref
	}
	if !e.BuiltIn {
		if cur, dup := s.adminHostIndex[pk]; !dup || ref.less(cur) {
			s.adminHostIndex[pk] = ref
		}
	}
}

func BenchmarkMatchesHostView_WriterCostLegacy(b *testing.B) {
	for _, cats := range []int{27, 200, 2000} {
		b.Run(benchCategoriesLabel(cats), func(b *testing.B) {
			s := writerCostStore(cats, 25)
			e := s.entries[0]
			key := "category 0"
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s.mu.Lock()
				legacyAddHostToIndexes(s, 0, e, key, "probe.example.net")
				s.mu.Unlock()
			}
		})
	}
}

// BenchmarkMatchesHostView_AddHostWithPersistence is the DENOMINATOR: the
// writer delta above only matters relative to what AddHost already does, and
// AddHost persists — it marshals the whole taxonomy to JSON and fsyncs an
// atomic rename on every call. Setup is excluded from the timer; the target
// category grows across iterations, so read this as an order of magnitude for
// the denominator, not as a precise per-call cost.
func BenchmarkMatchesHostView_AddHostWithPersistence(b *testing.B) {
	for _, cats := range []int{27, 2000} {
		b.Run(benchCategoriesLabel(cats), func(b *testing.B) {
			s := writerCostStore(cats, 25)
			s.SetPathForTest(b.TempDir() + "/categories.json")
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = s.AddHost("Category 1", "p"+itoaSmall(i)+".example.net")
			}
		})
	}
}
