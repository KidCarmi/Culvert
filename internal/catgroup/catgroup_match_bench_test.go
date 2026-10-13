package catgroup

import (
	"fmt"
	"testing"
)

// Benchmarks for the per-request group-membership match.
//
// categoryGroupMatchesHostScratch (package main, called from matchDestNorm)
// runs ONE of these per category-group-scoped policy rule, per request. Its
// doc comment describes the membership check as "the engine's O(1) catSet
// lookup", which is true of the NAME path (GetByName is a map lookup) and was
// NOT true of the ID path: Store.groups is keyed by lowercase NAME only, so
// resolving a group by its stable ID iterated the whole map.
//
// The ID path is the one production rules take — DestCategoryGroupID is the
// authoritative, rename-safe link and is stamped name→id on every write — so
// the scan cost applied to essentially every category-group rule on every
// request, and grew with the number of configured GROUPS.
//
// The existing policy-engine benchmarks could not see this: their fixtures set
// DestCategoryGroup (the name) and never DestCategoryGroupID, and they
// evaluate an UNCATEGORIZED host, which returns from MatchesCategoryByID
// before the lookup runs at all.
//
// Run:
//
//	go test -run '^$' -bench 'BenchmarkMatchesCategory' -benchmem ./internal/catgroup/

// benchGroups installs n groups of production shape and returns the store plus
// the ID and name of a group in the MIDDLE of the insertion order, so neither
// an early-exit nor a worst-case scan is reported as the typical cost.
func benchGroups(tb testing.TB, n int) (store *Store, groupID, groupName string) {
	tb.Helper()
	groups := make([]Group, n)
	for i := 0; i < n; i++ {
		groups[i] = Group{
			ID:   fmt.Sprintf("grp-%08d", i),
			Name: fmt.Sprintf("group-%d", i),
			// Mixed case, as the shipped taxonomy names are.
			Categories: []string{"Streaming", "Gambling", "Social Media"},
		}
	}
	s := New()
	s.ReplaceAll(groups)
	mid := n / 2
	return s, fmt.Sprintf("grp-%08d", mid), fmt.Sprintf("group-%d", mid)
}

// BenchmarkMatchesCategoryByID is the hot path: resolve a group by its
// authoritative ID, then test membership of an already-resolved category.
func BenchmarkMatchesCategoryByID(b *testing.B) {
	for _, n := range []int{1, 8, 32, 128} {
		s, id, _ := benchGroups(b, n)
		b.Run(fmt.Sprintf("groups=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if matched, resolved := s.MatchesCategoryByID(id, "Streaming"); !matched || !resolved {
					b.Fatalf("expected a resolved match, got matched=%v resolved=%v", matched, resolved)
				}
			}
		})
	}
}

// BenchmarkMatchesCategoryByID_Miss is the same lookup for an ID that resolves
// to no group — the un-migrated / dangling case, which ran the scan to
// completion before falling back to the name path.
func BenchmarkMatchesCategoryByID_Miss(b *testing.B) {
	for _, n := range []int{1, 8, 32, 128} {
		s, _, _ := benchGroups(b, n)
		b.Run(fmt.Sprintf("groups=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, resolved := s.MatchesCategoryByID("grp-nonexistent", "Streaming"); resolved {
					b.Fatal("expected no resolution")
				}
			}
		})
	}
}

// BenchmarkMatchesCategoryByName is the name fallback, already a map lookup.
// It is the reference the ID path should match once indexed.
func BenchmarkMatchesCategoryByName(b *testing.B) {
	for _, n := range []int{1, 8, 32, 128} {
		s, _, name := benchGroups(b, n)
		b.Run(fmt.Sprintf("groups=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if !s.MatchesCategory(name, "Streaming") {
					b.Fatal("expected a match")
				}
			}
		})
	}
}

// BenchmarkMatchesCategoryByIDParallel is the concurrency shape: the match is
// per-rule per-request on every core serving traffic, and it takes the store's
// read lock each time.
func BenchmarkMatchesCategoryByIDParallel(b *testing.B) {
	s, id, _ := benchGroups(b, 32)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if matched, _ := s.MatchesCategoryByID(id, "Streaming"); !matched {
				b.Fatal("expected a match")
			}
		}
	})
}
