package catgroup

// catgroup_matchkey_bench_test.go — before/after evidence for the pre-keyed
// hot-path matchers, kept in-tree so the comparison stays reproducible rather
// than living only in a commit message.
//
// The _StringArg arms are NOT a frozen copy of removed code: the string form is
// still shipped and still correct for every caller that holds a display-cased
// category name. What changed is which form the POLICY SCAN calls. So the pair
// below measures exactly the choice the scan makes once per category-group
// rule — derive the catSet key here, or accept the one the per-request scratch
// already derived.
//
//	go test -run '^$' -bench 'MatchesCategoryKey|MatchesCategoryStringArg' -benchmem ./internal/catgroup/
//
// allocs/op is the honest signal and the one the gates assert on: it is
// deterministic and hardware-independent, while the ns/op share depends
// entirely on how expensive one small malloc is relative to two map probes on
// the box doing the measuring.

import (
	"fmt"
	"testing"
)

// benchKeyStore installs groups spelled the way the shipped taxonomy spells
// categories. The display casing is load-bearing: strings.ToLower returns its
// input unchanged for an all-lowercase string, so a benchmark using lowercase
// category names would measure a fast path no real taxonomy ever takes.
func benchKeyStore(groups int) (store *Store, ids []string) {
	s := New()
	gs := make([]Group, 0, groups)
	ids = make([]string, 0, groups)
	for i := 0; i < groups; i++ {
		id := fmt.Sprintf("grpid%07d", i)
		gs = append(gs, Group{
			ID:         id,
			Name:       fmt.Sprintf("Group %d", i), // display-cased, like an operator types
			Categories: []string{"Social Media", "Streaming"},
		})
		ids = append(ids, id)
	}
	s.ReplaceAll(gs)
	return s, ids
}

const benchKeyCategory = "Social Media" // as the shipped taxonomy spells it

// BenchmarkMatchesCategoryKeyByID is the shape the policy scan now runs: the
// catSet key arrives from the per-request scratch, so the probe is two map
// lookups and nothing else.
func BenchmarkMatchesCategoryKeyByID(b *testing.B) {
	s, ids := benchKeyStore(64)
	key := CategoryKey(benchKeyCategory)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if m, ok := s.MatchesCategoryKeyByID(ids[i%len(ids)], key); !ok || !m {
			b.Fatalf("expected a resolved member match")
		}
	}
}

// BenchmarkMatchesCategoryByID_StringArg is the same probe when the caller
// hands over the display-cased name and the store lowers it — what the scan did
// once per category-group rule per request.
func BenchmarkMatchesCategoryByID_StringArg(b *testing.B) {
	s, ids := benchKeyStore(64)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if m, ok := s.MatchesCategoryByID(ids[i%len(ids)], benchKeyCategory); !ok || !m {
			b.Fatalf("expected a resolved member match")
		}
	}
}

// BenchmarkMatchesCategoryKeyByID_Parallel / _StringArgParallel are the rows
// that matter for an appliance: the removed allocation is per-call, so the
// string form's cost is paid by every core at once and lands on the shared
// allocator rather than on one goroutine's critical path.
//
// Each worker checks its own result, as the serial arms do, rather than writing
// a shared package-level sink: concurrent writes to one variable are a data
// race under -race and add cache-line contention the read-only production
// lookup never has. b.Error, not b.Fatal, because FailNow must not be called
// from a RunParallel worker goroutine.
func BenchmarkMatchesCategoryKeyByID_Parallel(b *testing.B) {
	s, ids := benchKeyStore(64)
	key := CategoryKey(benchKeyCategory)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if m, ok := s.MatchesCategoryKeyByID(ids[i%len(ids)], key); !ok || !m {
				b.Error("expected a resolved member match")
				return
			}
			i++
		}
	})
}

func BenchmarkMatchesCategoryByID_StringArgParallel(b *testing.B) {
	s, ids := benchKeyStore(64)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if m, ok := s.MatchesCategoryByID(ids[i%len(ids)], benchKeyCategory); !ok || !m {
				b.Error("expected a resolved member match")
				return
			}
			i++
		}
	})
}

// BenchmarkMatchesCategoryKey_NameLeg / _StringArgNameLeg cover the
// denormalized-NAME fallback an un-migrated rule still takes. The keyed form
// retires the CATEGORY allocation there too; the group-name lowering remains,
// which is why this arm does not reach zero for a display-cased group name —
// see MatchesCategoryKey's note on why that one is a separate change.
func BenchmarkMatchesCategoryKey_NameLeg(b *testing.B) {
	s, _ := benchKeyStore(64)
	key := CategoryKey(benchKeyCategory)
	// Names are built BEFORE the timer: formatting one inside the loop would
	// charge this arm an allocation the matcher never makes, which is exactly
	// the measurement error that would make the remaining group-name lowering
	// look twice as expensive as it is.
	names := make([]string, 64)
	for i := range names {
		names[i] = fmt.Sprintf("Group %d", i)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !s.MatchesCategoryKey(names[i%len(names)], key) {
			b.Fatal("expected a member match")
		}
	}
}

func BenchmarkMatchesCategoryKey_NameLegLowercaseGroup(b *testing.B) {
	s := New()
	s.ReplaceAll([]Group{{ID: "grpid0000000", Name: "lower-named", Categories: []string{"Social Media"}}})
	key := CategoryKey(benchKeyCategory)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !s.MatchesCategoryKey("lower-named", key) {
			b.Fatal("expected a member match")
		}
	}
}
