package urlcat

import "testing"

// benchStore builds a store over the shipped default taxonomy (built-in
// categories + the embedded SaaS seed) — the shape a stock appliance runs with.
//
// The reverse index is built lazily on first lookup, so the store is warmed
// here; leaving that one-time build inside the timed loop showed up as a
// phantom 3 B/op that has nothing to do with steady-state cost.
func benchStore() *Store {
	s := New(DefaultEntries())
	s.LookupHost("warm.example")
	s.LookupHostAdmin("warm.example")
	return s
}

func BenchmarkLookupHost_Miss(b *testing.B) {
	s := benchStore()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, ok := s.LookupHost("customer-intranet.example.corp"); ok {
			b.Fatal("unexpected match")
		}
	}
}

func BenchmarkLookupHost_HitLate(b *testing.B) {
	s := benchStore()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, ok := s.LookupHost("cdn.zoom.us"); !ok {
			_ = ok
		}
	}
}

func BenchmarkLookupHost_HitEarly(b *testing.B) {
	s := benchStore()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, ok := s.LookupHost("openai.com"); !ok {
			b.Fatal("expected match")
		}
	}
}

func BenchmarkLookupHostAdmin_Miss(b *testing.B) {
	s := benchStore()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.LookupHostAdmin("customer-intranet.example.corp")
	}
}

// MatchesHost is the indexed sibling — the baseline LookupHost should be able
// to reach.
func BenchmarkMatchesHost_Miss(b *testing.B) {
	s := benchStore()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.MatchesHost("AI", "customer-intranet.example.corp")
	}
}

func BenchmarkLookupHost_MissParallel(b *testing.B) {
	s := benchStore()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			s.LookupHost("customer-intranet.example.corp")
		}
	})
}
