package urlcat

import (
	"fmt"
	"testing"
)

// Host→category resolution benchmarks.
//
// LookupHost / LookupHostAdmin are NOT admin-API-only. package main's
// lookupHostCategory (policy.go) calls them, and categoryGroupMatchesHostRule
// (categorygroup.go) calls THAT for every enabled access rule carrying a
// DestCategoryGroup — i.e. once per such rule per proxied request. The
// clean-traffic case is a MISS (the destination is in no admin category), and a
// miss is the worst case: it scans every pattern of every category.
//
// Run:
//
//	go test -run '^$' -bench 'BenchmarkStoreLookupHost' -benchmem ./internal/urlcat/
//
// Sizes: 657 patterns is the SHIPPED default taxonomy (DefaultEntries — 6
// hardcoded built-ins plus the 21 embedded SaaS categories). The larger sizes
// stand in for a deployment that has added its own categories.

// benchStore returns a store with the shipped defaults plus n synthetic
// admin-created host patterns spread over 10 extra categories.
func benchStore(extra int) *Store {
	entries := DefaultEntries()
	if extra > 0 {
		const cats = 10
		per := extra / cats
		for c := 0; c < cats; c++ {
			hosts := make([]string, 0, per)
			for i := 0; i < per; i++ {
				hosts = append(hosts, fmt.Sprintf("host-%d-%d.corp.invalid", c, i))
			}
			entries = append(entries, &Entry{Name: fmt.Sprintf("Custom %d", c), Hosts: hosts})
		}
	}
	return New(entries)
}

func benchPatternCount(s *Store) int {
	n := 0
	for _, e := range s.entries {
		n += len(e.Hosts)
	}
	return n
}

// BenchmarkStoreLookupHost_Miss is the clean-traffic per-rule cost.
func BenchmarkStoreLookupHost_Miss(b *testing.B) {
	for _, extra := range []int{0, 1000, 5000} {
		s := benchStore(extra)
		b.Run(fmt.Sprintf("patterns=%d", benchPatternCount(s)), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, _, ok := s.LookupHost("www.example.com"); ok {
					b.Fatal("unexpected hit")
				}
			}
		})
	}
}

// BenchmarkStoreLookupHost_Hit resolves a host in the FIRST built-in category,
// i.e. the cheapest possible hit — it bounds how much of the miss cost is the
// scan rather than the fixed normalization.
func BenchmarkStoreLookupHost_Hit(b *testing.B) {
	s := benchStore(0)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, ok := s.LookupHost("cdn.facebook.com"); !ok {
			b.Fatal("expected hit")
		}
	}
}

// BenchmarkStoreLookupHostAdmin_Miss is the same probe on the F3b-4
// signed-feed path, where only admin-created (BuiltIn=false) categories are
// scanned here and the SaaS taxonomy is served by the effective view.
func BenchmarkStoreLookupHostAdmin_Miss(b *testing.B) {
	for _, extra := range []int{0, 1000, 5000} {
		s := benchStore(extra)
		b.Run(fmt.Sprintf("patterns=%d", benchPatternCount(s)), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, _, ok := s.LookupHostAdmin("www.example.com"); ok {
					b.Fatal("unexpected hit")
				}
			}
		})
	}
}

// BenchmarkStoreLookupHost_MissParallel is the contention measure: the scan is
// held under s.mu.RLock for its whole duration, so this reports whether the
// per-request lookup scales across cores.
func BenchmarkStoreLookupHost_MissParallel(b *testing.B) {
	s := benchStore(0)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, _, ok := s.LookupHost("www.example.com"); ok {
				b.Fatal("unexpected hit")
			}
		}
	})
}
