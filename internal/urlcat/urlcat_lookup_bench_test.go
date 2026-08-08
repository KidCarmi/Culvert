package urlcat

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

// Benchmarks for the LookupHost reverse index.
//
// The headline number is _Miss: a host in NO category cannot short-circuit, so
// the scan this index replaced had to walk every configured pattern. Misses are
// also the common case for a gateway, since most traffic is uncategorized.
//
// Run:
//   go test -run '^$' -bench 'BenchmarkLookupHost' -benchmem ./internal/urlcat/

// benchEntries returns a taxonomy of nCats categories x hostsPer hosts, on top
// of the shipped defaults, to measure scaling in total configured hosts.
func benchEntries(nCats, hostsPer int) []*Entry {
	entries := DefaultEntries()
	for c := 0; c < nCats; c++ {
		hosts := make([]string, hostsPer)
		for h := 0; h < hostsPer; h++ {
			hosts[h] = fmt.Sprintf("host%d-%d.synthetic%d.test", c, h, c)
		}
		entries = append(entries, &Entry{Name: fmt.Sprintf("Synthetic-%d", c), Hosts: hosts})
	}
	return entries
}

func countHosts(entries []*Entry) int {
	n := 0
	for _, e := range entries {
		n += len(e.Hosts)
	}
	return n
}

// BenchmarkLookupHost_Miss is the scaling test: cost must stay flat as the
// configured taxonomy grows, because the probe count depends on the LABELS in
// the queried host, not on how many patterns are configured.
func BenchmarkLookupHost_Miss(b *testing.B) {
	for _, sz := range []struct{ cats, per int }{{0, 0}, {10, 50}, {50, 100}, {200, 250}} {
		entries := benchEntries(sz.cats, sz.per)
		s := New(entries)
		b.Run(fmt.Sprintf("patterns=%d", countHosts(entries)), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, _, ok := s.LookupHost("api.internal.corp.example.com"); ok {
					b.Fatal("expected miss")
				}
			}
		})
	}
}

// BenchmarkLookupHost_Hit covers the categorized-host path.
func BenchmarkLookupHost_Hit(b *testing.B) {
	s := New(benchEntries(50, 100))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, ok := s.LookupHost("cdn.edge.netflix.com"); !ok {
			b.Fatal("expected hit")
		}
	}
}

// BenchmarkLookupHost_DeepHost varies the LABEL count, which is what the probe
// count is actually proportional to.
func BenchmarkLookupHost_DeepHost(b *testing.B) {
	s := New(benchEntries(50, 100))
	for _, depth := range []int{1, 4, 8, 16} {
		parts := make([]string, depth)
		for i := range parts {
			parts[i] = fmt.Sprintf("l%d", i)
		}
		host := strings.Join(parts, ".") + ".uncategorized.test"
		b.Run(fmt.Sprintf("labels=%d", depth+2), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s.LookupHost(host)
			}
		})
	}
}

// BenchmarkLookupHost_Parallel checks the read path scales across cores. The
// lock is held only long enough to copy a map header, so contention should be
// negligible.
func BenchmarkLookupHost_Parallel(b *testing.B) {
	s := New(benchEntries(50, 100))
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			s.LookupHost("api.internal.corp.example.com")
		}
	})
}

// BenchmarkLookupHost_UnderMutation measures readers while an admin is editing
// categories — the case that motivated copy-on-write publication.
func BenchmarkLookupHost_UnderMutation(b *testing.B) {
	s := New(benchEntries(10, 50))
	s.SetPathForTest("")
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			_ = s.Set("Churn", []string{fmt.Sprintf("c%d.test", i)}, false)
		}
	}()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.LookupHost("api.internal.corp.example.com")
	}
	b.StopTimer()
	close(stop)
	wg.Wait()
}

// BenchmarkRebuildIndex prices the write side. Mutators now rebuild every index
// instead of patching one in place, so this is the cost that was added — it must
// stay small next to the Save() that follows it on every mutation.
func BenchmarkRebuildIndex(b *testing.B) {
	for _, sz := range []struct{ cats, per int }{{10, 50}, {50, 100}, {200, 250}} {
		entries := benchEntries(sz.cats, sz.per)
		s := New(entries)
		b.Run(fmt.Sprintf("patterns=%d", countHosts(entries)), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s.rebuildIndex()
			}
		})
	}
}
