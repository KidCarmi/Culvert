package catgroup

// Hot-path benchmarks for the per-request group match.
//
// MatchesCategoryByID and MatchesCategory are called from package main's
// matchDestNorm ONCE PER RULE that carries a destination category group, inside
// the policy scan that every proxied request walks. The per-request cost is
// therefore (rules with a category group) x (the cost measured here), and the
// LOCK TRAFFIC is that product too — which is why the parallel rows, not the
// serial ones, are the ones to read.
//
// Run locally:
//
//	go test -run '^$' -bench 'BenchmarkMatches' -benchmem -cpu 1,2,4 ./internal/catgroup/

import (
	"fmt"
	"testing"
)

// benchStore builds a store of n groups, each holding catsPerGroup categories,
// and returns it with the ID and name of a group in the MIDDLE of the set (so
// an ID lookup that scans pays about half the set, the average case rather than
// the best or the worst).
func benchStore(tb testing.TB, n, catsPerGroup int) (s *Store, midID, midName string) {
	tb.Helper()
	s = New()
	groups := make([]Group, n)
	for i := 0; i < n; i++ {
		cats := make([]string, 0, catsPerGroup)
		for c := 0; c < catsPerGroup; c++ {
			cats = append(cats, fmt.Sprintf("category-%d-%d", i, c))
		}
		groups[i] = Group{
			ID:         fmt.Sprintf("gid-%08d", i),
			Name:       fmt.Sprintf("group-%d", i),
			Categories: cats,
		}
	}
	s.ReplaceAll(groups)
	mid := n / 2
	return s, fmt.Sprintf("gid-%08d", mid), fmt.Sprintf("group-%d", mid)
}

// benchGroupCounts is the admin-set sizing swept below. 8 is a small posture,
// 64 a large one, 256 the ceiling a big multi-tenant deployment reaches.
var benchGroupCounts = []int{8, 64, 256}

// BenchmarkMatchesCategoryByID_Hit measures the production path: a rule whose
// DestCategoryGroupID resolves. The host category is the group's FIRST
// category, so a set probe hits.
func BenchmarkMatchesCategoryByID_Hit(b *testing.B) {
	for _, n := range benchGroupCounts {
		s, id, _ := benchStore(b, n, 12)
		cat := fmt.Sprintf("category-%d-0", n/2)
		b.Run(fmt.Sprintf("groups=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if matched, resolved := s.MatchesCategoryByID(id, cat); !matched || !resolved {
					b.Fatalf("matched=%v resolved=%v, want both true", matched, resolved)
				}
			}
		})
	}
}

// BenchmarkMatchesCategoryByID_HitParallel is the row that matters: it puts the
// same op on every core, the shape a gateway under load is in.
func BenchmarkMatchesCategoryByID_HitParallel(b *testing.B) {
	for _, n := range benchGroupCounts {
		s, id, _ := benchStore(b, n, 12)
		cat := fmt.Sprintf("category-%d-0", n/2)
		b.Run(fmt.Sprintf("groups=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if matched, resolved := s.MatchesCategoryByID(id, cat); !matched || !resolved {
						b.Fatalf("matched=%v resolved=%v, want both true", matched, resolved)
					}
				}
			})
		})
	}
}

// BenchmarkMatchesCategoryByID_Miss is the un-migrated / dangling-reference
// case, which is also the ID path's WORST case: no group carries the id, so a
// scan cannot stop early and the caller then falls back to the name path.
func BenchmarkMatchesCategoryByID_Miss(b *testing.B) {
	for _, n := range benchGroupCounts {
		s, _, _ := benchStore(b, n, 12)
		b.Run(fmt.Sprintf("groups=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, resolved := s.MatchesCategoryByID("gid-no-such", "category-0-0"); resolved {
					b.Fatal("resolved a group id that does not exist")
				}
			}
		})
	}
}

// BenchmarkMatchesCategory_NameParallel measures the name fallback, which is
// what a rule with no DestCategoryGroupID reaches and what package main's
// BenchmarkPolicyEvaluate_CategoryGroupRulesParallel exercises today.
func BenchmarkMatchesCategory_NameParallel(b *testing.B) {
	s, _, name := benchStore(b, 64, 12)
	cat := "category-32-0"
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if !s.MatchesCategory(name, cat) {
				b.Fatal("expected the group to contain the category")
			}
		}
	})
}

// BenchmarkMatchesCategory_UnknownNameParallel is the fail-closed miss — the
// shape a rule referencing a deleted group has, and the one the empty-store
// policy benchmark in package main measures.
func BenchmarkMatchesCategory_UnknownNameParallel(b *testing.B) {
	s, _, _ := benchStore(b, 64, 12)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if s.MatchesCategory("no-such-group", "category-0-0") {
				b.Fatal("unknown group must not match")
			}
		}
	})
}
