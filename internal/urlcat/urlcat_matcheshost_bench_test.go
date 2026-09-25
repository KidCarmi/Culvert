package urlcat

import (
	"strings"
	"testing"
)

// MatchesHost / MatchesHostAdmin benchmarks.
//
// These are the per-RULE half of destination-category resolution: package
// main's hostCatScratch.matchesCategory (policy_hostcat.go) calls one of them
// once per category-scoped access rule per proxied request, and deliberately
// does NOT memoize the result — its comment records the reason as "they depend
// on the rule's category and are O(labels) index probes, not scans, so
// memoizing them would trade a cheap map probe for a map allocation".
//
// That claim is what these benchmarks measure. The probe resolves the
// category's host set through a map keyed by the LOWERCASED category name, and
// the pre-fix body materialised that key with strings.ToLower on every call —
// so the "cheap map probe" allocated a string per rule per request, for a value
// that is pure CONFIGURATION (the rule's category name never changes between
// requests). Every one of the 21 shipped SaaS category names carries an
// uppercase letter, so the allocation fired on 100% of the shipped taxonomy.
//
// Run:
//
//	go test -run '^$' -bench 'BenchmarkStoreMatchesHost' -benchmem ./internal/urlcat/
//
// The MISS case is the one to read: clean traffic to an uncategorized
// destination cannot short-circuit, so it is what an allowed request pays.

// benchMatchStore returns the shipped default taxonomy — the real category
// names, which is what makes the key-lowering cost representative.
func benchMatchStore() *Store { return New(DefaultEntries()) }

// benchCategoryName picks a real shipped category name (mixed case).
func benchCategoryName(tb testing.TB) Category {
	tb.Helper()
	for _, e := range DefaultEntries() {
		if e.Name != strings.ToLower(e.Name) {
			return Category(e.Name)
		}
	}
	tb.Fatal("no mixed-case category in the shipped taxonomy")
	return ""
}

func BenchmarkStoreMatchesHost_Miss(b *testing.B) {
	s := benchMatchStore()
	cat := benchCategoryName(b)
	const host = "uncategorized.example.net"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if s.MatchesHost(cat, host) {
			b.Fatal("unexpected match")
		}
	}
}

func BenchmarkStoreMatchesHost_Hit(b *testing.B) {
	s := New([]*Entry{{Name: "Social Media", Hosts: []string{"example.com"}}})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !s.MatchesHost("Social Media", "a.b.example.com") {
			b.Fatal("expected match")
		}
	}
}

func BenchmarkStoreMatchesHostAdmin_Miss(b *testing.B) {
	s := New([]*Entry{{Name: "Corp Internal", Hosts: []string{"intranet.corp.invalid"}}})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if s.MatchesHostAdmin("Corp Internal", "uncategorized.example.net") {
			b.Fatal("unexpected match")
		}
	}
}

// BenchmarkStoreMatchesHost_Parallel measures the same probe under
// concurrency. It is here for two reasons.
//
// First, it is the honest reading of the allocation fix: removing a per-call
// allocation removes per-call GC pressure, which only shows up as throughput
// once several cores are allocating at once.
//
// Second, it is the instrument for what this change deliberately does NOT
// touch. Both entry points still take s.mu.RLock once per call, i.e. once per
// category-scoped access rule per proxied request — and RLock/RUnlock are two
// atomic read-modify-writes on one shared word, so a category rulebase
// multiplies read-lock traffic by the rule count on every core serving
// traffic. That is the throughput-ceiling shape this repo has already closed
// in internal/threatfeed, internal/connlimit, internal/blocklist and the IP
// filter, and this benchmark is what a future change closing it here should
// be read against: what matters is not ns/op at one core but how ns/op MOVES
// with core count.
//
//	go test -run '^$' -bench 'BenchmarkStoreMatchesHost_Parallel' -benchmem -cpu 1,2,4 ./internal/urlcat/
func BenchmarkStoreMatchesHost_Parallel(b *testing.B) {
	s := benchMatchStore()
	cat := benchCategoryName(b)
	const host = "uncategorized.example.net"
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		// Each worker keeps its OWN sink: a shared package-level sink turns
		// false sharing into the thing being measured (the trap recorded on
		// internal/blocklist's hot-read benchmarks).
		var sink bool
		for pb.Next() {
			sink = s.MatchesHost(cat, host)
		}
		_ = sink
	})
}
