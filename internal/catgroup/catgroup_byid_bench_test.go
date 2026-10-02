package catgroup

import (
	"fmt"
	"testing"
)

// Category-group membership benchmarks.
//
// MatchesCategoryByID is the per-RULE half of category-group matching:
// categoryGroupMatchesHostScratch (categorygroup.go) calls it once per
// category-group access rule per proxied request, for every rule carrying a
// DestCategoryGroupID — which is every rule the admin API has ever saved
// against an existing group (stampObjectRefIDs, ui_policy.go).
//
// It resolved that id by ranging the whole groups map, with mu held for reading
// across the walk, because groups is keyed by NAME. So the AUTHORITATIVE,
// rename-safe link was O(#groups) while the denormalized-name fallback it
// supersedes was already an O(1) probe. maxSnapCategoryGroups caps the store at
// 1000 groups.
//
// WHY THIS WENT UNMEASURED: every pre-existing policy benchmark
// (buildCategoryGroupPolicyStore, policy_bench_test.go) sets DestCategoryGroup
// — the NAME — and never DestCategoryGroupID, so 100% of benchmark traffic took
// the O(1) fallback while ~100% of production traffic took the walk. The blind
// spot sat exactly over the authoritative path.
//
// Run:
//
//	go test -run '^$' -bench 'BenchmarkMatchesCategoryByID' -benchmem ./internal/catgroup/
//
// Read the RATIO between the arms, never the absolutes: both are timed in one
// run precisely so the comparison survives a box whose clock drifts between
// rounds (the urlcat categoryKey lesson).

func benchStore(n int) (*Store, string, string) {
	s := New()
	var lastID, lastName string
	for i := 0; i < n; i++ {
		lastName = fmt.Sprintf("group-%d", i)
		g, err := s.Add(lastName, []string{fmt.Sprintf("Category %d", i), "Social Media"})
		if err != nil {
			panic(err)
		}
		lastID = g.ID
	}
	return s, lastID, lastName
}

var benchGroupCounts = []int{4, 16, 64, 256, 1000}

// BenchmarkMatchesCategoryByID is the indexed resolve: expected flat in group
// count.
func BenchmarkMatchesCategoryByID(b *testing.B) {
	for _, n := range benchGroupCounts {
		s, id, _ := benchStore(n)
		b.Run(fmt.Sprintf("groups=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if m, ok := s.MatchesCategoryByID(id, "Social Media"); !ok || !m {
					b.Fatal("expected a resolved match")
				}
			}
		})
	}
}

// BenchmarkMatchesCategoryByID_Legacy is the frozen pre-index walk — the
// before-arm of the comparison.
func BenchmarkMatchesCategoryByID_Legacy(b *testing.B) {
	for _, n := range benchGroupCounts {
		s, id, _ := benchStore(n)
		b.Run(fmt.Sprintf("groups=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if m, ok := linearResolveLegacy(s, id, "Social Media"); !ok || !m {
					b.Fatal("expected a resolved match")
				}
			}
		})
	}
}

// BenchmarkMatchesCategory_ByName is the O(1) name fallback, unchanged in
// complexity by this work and included as the reference the indexed path should
// now sit beside. It also measures the second change: the catSet probe moved
// inside the read lock, which removes the old shape's second lock round trip.
func BenchmarkMatchesCategory_ByName(b *testing.B) {
	for _, n := range benchGroupCounts {
		s, _, name := benchStore(n)
		b.Run(fmt.Sprintf("groups=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if !s.MatchesCategory(name, "Social Media") {
					b.Fatal("expected a match")
				}
			}
		})
	}
}

// BenchmarkMatchesCategoryByID_Parallel measures the resolve under concurrency.
// Both arms are here because the walk's cost is paid with mu held for reading,
// so shortening it shortens the critical section every core serving traffic
// contends on: what matters is not ns/op at one core but how ns/op MOVES with
// core count.
//
//	go test -run '^$' -bench 'ByID_Parallel' -benchmem -cpu 1,2,4 ./internal/catgroup/
func BenchmarkMatchesCategoryByID_Parallel(b *testing.B) {
	const n = 256
	s, id, _ := benchStore(n)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		// Each worker keeps its OWN sink: a shared package-level sink turns
		// false sharing into the thing being measured (the trap recorded on
		// internal/blocklist's hot-read benchmarks).
		var sink bool
		for pb.Next() {
			sink, _ = s.MatchesCategoryByID(id, "Social Media")
		}
		_ = sink
	})
}

func BenchmarkMatchesCategoryByID_LegacyParallel(b *testing.B) {
	const n = 256
	s, id, _ := benchStore(n)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var sink bool
		for pb.Next() {
			sink, _ = linearResolveLegacy(s, id, "Social Media")
		}
		_ = sink
	})
}

// BenchmarkReindexByID measures what the fix COSTS: every content mutation
// rebuilds the index wholesale. This is the admin-rate side of the trade and is
// here so the cost is evidenced rather than asserted.
func BenchmarkReindexByID(b *testing.B) {
	for _, n := range benchGroupCounts {
		s, _, _ := benchStore(n)
		b.Run(fmt.Sprintf("groups=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s.mu.Lock()
				s.reindexByIDLocked()
				s.mu.Unlock()
			}
		})
	}
}

// BenchmarkAdd_BulkLoad guards the composite: Add routes through the
// chokepoint, so seeding N groups is now N index rebuilds. It must stay
// tractable at the store cap — pinned as a ratio by
// TestBenchGate_MutationCostStaysTractable.
func BenchmarkAdd_BulkLoad(b *testing.B) {
	for _, n := range []int{100, 400} {
		b.Run(fmt.Sprintf("groups=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchStore(n)
			}
		})
	}
}
